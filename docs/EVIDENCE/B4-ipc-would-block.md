# B4 IPC unmatched-call behavior — 2026-10-21

## Finding

The endpoint send and receive paths returned success when no peer was present.
They recorded a waiter and changed only `ProcessControlBlock.state` to
`Blocked`. The scheduler's TCB stayed runnable, and receive returned an empty
message to user code. The syscall dispatcher has no resumable blocked-syscall
continuation, so this did not implement blocking rendezvous semantics.

## Correction

Unmatched send and receive now return the stable syscall error
`SyscallError::WouldBlock` (`-9`) without changing endpoint or process state.
Direct delivery still handles an endpoint that already has a waiter, including
capability transfer and the atomic TID-to-scheduler-slot wake added in PR #30.
The module documentation now states that unmatched syscall suspension and
resumption are not implemented.

The boot self-test checks both empty-endpoint calls return `WouldBlock`, leave
the endpoint idle, and leave the caller's PCB Ready. It separately stages an
internal waiter to exercise direct transfer delivery. That staged test does
not establish the missing user-facing blocking/wake lifecycle.

## Verification (2026-10-21)

```text
python tools/test_ipc_would_block_fail_closed.py PASS
python tools/test_ipc_task_wakeup_atomic.py PASS
cargo test --workspace --exclude kernel --features kvault/test-fast-kdf PASS
cargo check --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
all 25 tools/test_*.py source guards PASS
python tools/claims_lint.py PASS
python tools/verify_findings.py PASS (F8 and F10 remain present)
python -u tests/test_qemu_boot.py PASS (T0 reached shell; T16 WouldBlock/direct-delivery marker observed)
git diff --check PASS
```

The QEMU T0 run has one CPU. It does not exercise true blocking or concurrent
IPC wakeup. PR and main CI are pending.

The repository's `rtk` command wrapper is not installed in this environment;
verification commands were run directly in PowerShell.
