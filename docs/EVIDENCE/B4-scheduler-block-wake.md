# B4 scheduler block/wake policy groundwork — 2026-10-21

## Question and scope

Does the scheduler remove blocked tasks from dispatch, avoid requeueing a
blocked current task on timer expiry, and handle wake-before-switch without
putting the same task in both `current` and a ready queue?

This task implements scheduler-policy transitions only. It does not implement
blocking IPC syscalls, saved syscall continuations, atomic endpoint/PCB/TCB
transactions, architecture idle contexts, or SMP-safe context switching.

## Research

The official Linux kernel driver basics documentation describes wait operations
as setting a sleep state until a condition holds, and requires wakeup after a
change that can satisfy that condition. This supports treating the state/wakeup
ordering as one coordinated scheduler transition; it is design context, not a
claim of Linux or seL4 parity.

- Linux kernel documentation, Driver Basics, wait-event APIs; reviewed
  2026-10-21: https://docs.kernel.org/driver-api/basics.html

## Change

- Added `block_task`: validates a live task, removes it from ready queues,
  marks it Blocked, and clears consumed slice time. Repeated block returns
  `AlreadyBlocked`.
- Added `wake_task`: rejects non-blocked tasks; if the task is still current on
  a CPU, restores Running in place; otherwise enqueues it as Ready. This avoids
  duplicate dispatch during the interval before the timer switches away.
- Updated the timer scheduler path to clear a Blocked/Terminated current slot
  and select another task without charging or requeueing the blocked task.
- Added host regressions for queued block/wake, switching away then waking,
  and wake-before-switch.

The current-task wake case assumes scheduler callers serialize access to the
scheduler (the existing kernel `SCHEDULER` lock). This API alone does not
establish multi-CPU execution safety.

## Failure-first check

Before implementing the API, the new scheduler test target was run:

```text
cargo test -p kscheduler --test scheduler_tests
FAIL as expected: compiler reported missing block_task and wake_task methods
```

After implementation the same tests pass.

## Verification

```text
cargo test -p kscheduler --test scheduler_tests PASS (20 tests)
cargo test --workspace --exclude kernel --features kvault/test-fast-kdf PASS
cargo check --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
python tools/claims_lint.py PASS
python tools/verify_findings.py PASS (F8 and F10 remain present)
python tools/test_*.py PASS (all repository source guards)
python -u tests/test_qemu_boot.py PASS (T0, 1 CPU; locked shell and required markers)
```

QEMU T0 is the existing system smoke test. It does not directly exercise the
new `block_task`/`wake_task` API from a running kernel IPC syscall. Kernel IPC
continues to return `WouldBlock` for unmatched calls. If a blocked task leaves
no runnable task, the policy returns `None`; the architecture timer path has no
idle context to switch to, so real syscall suspension remains unimplemented.
`F8` (hardware DMA/IOMMU path) and `F10` (normal boot session remains Ring 0)
remain present.
