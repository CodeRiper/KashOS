# B4 supervisor blocked-context handoff — 2026-10-21

## Finding

`SYS_YIELD` uses vector `0xF0`, whose scheduler transition requires the current
task to be Running and requeues it. A syscall that marks its TCB Blocked cannot
use that transition: it would be rejected as a scheduling error. The timer
path knows how to switch away from a blocked task, but a syscall needs a
supervisor handoff that saves its current kernel continuation immediately.

## Change

- Added a host-testable scheduler plan for the current task already marked
  Blocked. It switches to the next ready task or to idle and does not requeue
  the blocked task.
- A wake that arrives before the software handoff changes the still-current
  task back to Running; the handoff then returns without queueing or switching
  that current context.
- Added supervisor-only IDT vector `0xF1`. Its assembly frame saves general
  registers and FPU state, and the task handler stores the interrupt frame and
  selects the incoming task's CR3, TSS stack, syscall stack, and TID.
- Added `block_current_task` to mark only the scheduler's actual current,
  Running task as Blocked. The caller must publish its wait state while holding
  the relevant object lock, release all locks, then call
  `handoff_blocked_current`.
- Reworked the existing blocked-to-idle boot self-test to use vector `0xF1`;
  the saved kernel call resumes after the synthetic wake.

This does not yet connect `SYS_IPC_SEND` or `SYS_IPC_RECV` to the blocking
path. IPC unmatched calls still return `WouldBlock`. No per-thread IPC result
record, endpoint/PCB/TCB transaction, mapped-page validation, or SMP IPC test
is implemented. APs stay parked. The QEMU runtime check is T0, one CPU, and
does not establish syscall ABI or seL4 parity for blocked IPC.

## Research

- seL4, [IPC Tutorial](https://docs.sel4.systems/Tutorials/ipc), reviewed
  2026-10-21. Endpoint calls may block until rendezvous; endpoints queue
  waiting senders and receivers. KashOS currently only adds a scheduler-side
  handoff and retains `WouldBlock` for unmatched endpoint calls.
- seL4, [Threads Tutorial](https://docs.sel4.systems/Tutorials/threads.html),
  reviewed 2026-10-21. The scheduler selects runnable threads that are not
  blocked on IPC. This is design context, not a verification of KashOS.
- Intel, [64 and IA-32 Architectures Software Developer's Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html),
  reviewed 2026-10-21. Software-generated interrupt gates enforce the IDT
  descriptor privilege level; vector `0xF1` is installed at DPL 0 and is
  invoked only by supervisor code. Runtime QEMU checks the current handler path.

## Failure-first regression

The new host tests were added before the scheduler API. The initial focused run
failed to compile because `plan_blocked_current_handoff_on_cpu` did not exist.
After implementing the API:

```text
cargo test -p kscheduler --test scheduler_tests handoff -- --nocapture PASS (4 tests)
cargo test -p kscheduler --test scheduler_tests PASS (28 tests)
```

## Verification

```text
python tools/test_syscall_block_handoff.py PASS
python tools/test_blocked_task_idle_handoff.py PASS
python tools/test_smp_aps_fail_closed.py PASS
cargo test --workspace --exclude kernel --features kvault/test-fast-kdf PASS
cargo check --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
all 31 tools/test_*.py source guards PASS
python tools/claims_lint.py PASS
python tools/verify_findings.py PASS (F8 and F10 remain present)
python -u tests/test_qemu_boot.py PASS (fresh release image; T0 one CPU; blocked-to-idle wake returned and shell reached)
git diff --check PASS
```

The repository requires an `rtk` shell prefix, but `rtk` is not installed in
this environment; commands ran directly in PowerShell.
