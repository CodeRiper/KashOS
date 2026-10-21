# B4 blocked-task idle handoff — 2026-10-21

## Finding

The scheduler returned no context-switch plan when the current task became
Blocked and no task was runnable. `task::on_timer_tick` treated that result as
“no switch” and returned the interrupted RSP to `_isr32`, so `iretq` resumed the
blocked task even though the scheduler had cleared its current slot. A
terminated current task with no successor had a related stale-context problem.

## Change

- `ContextSwitchTarget` distinguishes a task context from an idle context.
  Blocking the last runnable current task now produces an explicit idle plan;
  waking from idle produces a task plan with no previous task.
- x86 reserves one 16 KiB idle stack plus a 4 KiB guard page per scheduler CPU
  slot. The initialized CPU's idle frame enters an `sti; hlt` loop.
- The timer path saves the outgoing blocked thread's RSP and FPU image before
  returning the idle RSP, changes TSS.RSP0 to that idle stack, and clears its
  current TID. An interrupt from idle can later dispatch a newly-ready task.
- If there is no scheduler current task but the CPU still has a nonzero current
  TID (for example after termination), the timer switches to idle instead of
  returning to the stale task. A selected scheduler task without a live kernel
  thread record now halts instead of returning to the incoming context.
- Every reserved idle-stack guard is included in the page-table unmap list.
  QEMU self-test deliberately wrote to the first idle-stack guard and observed
  the expected non-present supervisor write fault.
- A BSP QEMU self-test now blocks the only boot task, waits for the idle loop
  to consume a one-shot synthetic wake, and verifies that a later timer tick
  resumes the same task in `Running` state. This exercises the live timer to
  idle to task stack handoff; it is not an IPC syscall continuation test.
- Scheduler tests cover blocked-last-task to idle and wake-from-idle to task.
  A CI source guard checks that the x86 timer consumes the explicit idle plan.

## Research

- Intel, *64 and IA-32 Architectures Software Developer's Manual*, Volume 1,
  interrupt/exception return behavior; official manual landing page reports
  version 093, reviewed 2026-10-21:
  https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- Linux kernel Driver Basics documentation, wait-event state and wake ordering,
  reviewed 2026-10-21: https://docs.kernel.org/driver-api/basics.html

The Intel manual specifies the architectural `iretq` stack behavior; it does
not validate KashOS's constructed frame. Linux docs provide design context for
sleep/wake coordination, not a claim of feature parity.

## Failure-first check

Before the scheduler decision change, the new test target failed to compile:

```text
cargo test -p kscheduler --test scheduler_tests
FAIL as expected: ContextSwitchPlan had no explicit target and
ContextSwitchTarget did not exist
```

The tests pass after adding explicit `Task` and `Idle` targets.

## Verification

```text
cargo test --workspace --exclude kernel --features kvault/test-fast-kdf PASS
cargo check --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
python tools/test_blocked_task_idle_handoff.py PASS
python tools/test_unmapped_thread_stack_guards.py --verify-baseline PASS
python tools/test_*.py PASS (all repository source guards)
python tools/claims_lint.py PASS
python tools/verify_findings.py PASS (F8 and F10 remain present)
python -u tests/test_qemu_boot.py PASS (T0, one CPU; thread and idle guard faults recovered; locked shell reached)
```

The live test covers the BSP timer/context transition using a synthetic wake
probe. It does not cover a blocked IPC syscall, syscall result delivery,
wake-versus-exit races, AP execution, SMP safety, or hardware behavior. APs
remain parked, and shared scheduler state is not SMP-safe. Unmatched IPC still
returns `WouldBlock`; this change does not add a saved IPC syscall continuation
or make B4 complete.
