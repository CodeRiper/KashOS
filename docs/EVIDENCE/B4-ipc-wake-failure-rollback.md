# B4 IPC wake-failure state preservation — 2026-10-21

## Finding

Both direct IPC rendezvous paths mutated endpoint and PCB state before asking
the scheduler to wake the waiting peer. If the waiter was stale, terminated,
or no longer Blocked, `wake_task_by_tid` returned an error after the endpoint
had already discarded its waiter/message. A transferred capability could also
remain installed after the failed operation.

## Change

- Direct send and receive now ask the scheduler to wake the peer before
  consuming endpoint state or marking its PCB Ready.
- If wake fails after a transferred capability was installed, the receiver's
  destination slot is deleted and the endpoint rendezvous is left available.
- Added a CI source regression guard that checks both directions and rejects
  early endpoint/PCB mutation or missing transfer rollback.
- Unmatched IPC remains `WouldBlock`; this does not add a syscall continuation.

The scheduler wake and endpoint commit are still separate lock transactions.
AP startup remains disabled. Before APs or SMP user tasks are enabled, the
endpoint, scheduler, PCB, and capability-space changes need a single
cross-object transition with a documented lock order. This change is bounded
to preventing state loss when wake itself rejects the peer on the supported
single-CPU path.

## Research

- seL4, [IPC Tutorial](https://docs.sel4.systems/Tutorials/ipc), reviewed
  2026-10-21. The tutorial describes endpoints as queues of blocked senders or
  receivers and says synchronous send/receive rendezvous wakes the paired
  thread. KashOS's direct-only path is not equivalent: unmatched operations
  continue to return `WouldBlock` and no seL4 parity is claimed.
- seL4, [Threads Tutorial](https://docs.sel4.systems/Tutorials/threads.html),
  reviewed 2026-10-21. It describes runnable threads as resumed and not blocked
  on IPC, supporting the requirement that IPC and scheduler state agree; it is
  reference material, not a verification of KashOS.

## Failure-first regression

The regression guard was run against the pre-change `HEAD` source copied to a
temporary file. It failed as expected:

```text
AssertionError: send consumes waiter before scheduler wake succeeds
```

It passes against the changed source:

```text
python tools/test_ipc_wake_failure_preserves_state.py
PASS: IPC endpoint/PCB state is retained when scheduler wake fails
```

## Verification

Commands run from PowerShell because the repository-required `rtk` wrapper is
not installed in this environment:

```text
python tools/test_ipc_wake_failure_preserves_state.py PASS
cargo test --workspace --exclude kernel --features kvault/test-fast-kdf PASS
cargo check --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
all 30 tools/test_*.py source guards PASS
python tools/claims_lint.py PASS
python tools/verify_findings.py PASS (F8 and F10 remain present)
python -u tests/test_qemu_boot.py PASS (QEMU T0, one CPU, shell reached)
git diff --check PASS
```

All existing runtime honesty limits remain: QEMU T0 is single CPU, APs are
parked, unmatched IPC cannot suspend/resume, and mapped writable user-buffer
validation is incomplete.
