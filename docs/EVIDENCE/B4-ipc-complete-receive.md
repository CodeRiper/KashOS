# B4 complete-message receive evidence — 2026-10-21

Reviewed branch: `codex/ipc-reject-truncated-receive`, based on `main` at
`3e766aa39e7548e1f642c04a8d04845335e46abc` (PR #39 sync).

## Source review and research

- `kernel/src/arch/x86_64/syscall.rs`: receive capacity was bounded before
  endpoint lookup, but the syscall copied `min(capacity, message length)` after
  consuming the message. A too-small buffer silently lost the tail.
- `kernel/src/ipc.rs`: wake and endpoint updates are still a single-CPU
  rollback design; APs remain parked.
- seL4 [IPC tutorial](https://docs.sel4.systems/Tutorials/ipc), reviewed
  2026-10-21: IPC is synchronous transmission of small amounts of data and
  capability transfer. Used as behavior context, not a parity claim.
- Rust [slice documentation](https://doc.rust-lang.org/core/primitive.slice.html),
  Rust core 1.99.1 (2026-10-13), reviewed 2026-10-21: slice operations require
  the relevant elements to be valid. This reinforces that canonical-address
  checks alone cannot prove user-page writability.

## Regression and change

The T16 boot self-test now stages a two-word message, attempts receive with
capacity one, checks `InvalidArgument` and unchanged endpoint/sender state, then
retries with capacity two and checks complete delivery and sender wake. The x86
syscall passes its prevalidated capacity to this bounded receive API and copies
the full message only after success. A CI source guard checks that the size
rejection precedes capability installation, task wake, and endpoint clearing.

The first broad source-guard run exposed three existing guards that inspected
the old receive function body rather than the new bounded implementation.
Those guards were updated to inspect the implementation that owns the state
transition; no checks were removed or weakened.

## Verification

- `python tools/test_syscall_ipc_user_buffers.py` — PASS.
- `cargo test --workspace --exclude kernel --features kvault/test-fast-kdf` — PASS.
- `cargo check --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none` — PASS.
- `cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none` — PASS.
- `python -u tests/test_qemu_boot.py` — PASS; T0 single CPU reached the shell
  and T16 observed too-small rejection plus complete retry.
- Claims lint and findings verification — PASS (F8 and F10 remain present).
- `Get-ChildItem tools/test_*.py | ForEach-Object { python $_.FullName }` — PASS,
  all 31 source guards.
- `git diff --check` — PASS.
- GitHub PR #40: Workspace Subsystem Tests, Build Microkernel (x86-64), and
  Build Guide v2 Claims & Honesty Gate — PASS; merged to `main` at
  `d11213354d4376833a922b8737aede3ab2171bee` on 2026-10-21. Local `main` was
  fast-forwarded to that commit.

The repository instructions require the `rtk` command prefix. `rtk --version`
previously showed it is not installed in this environment; commands ran
directly in PowerShell.

## Limits

This does not validate user page mappings or write permissions. A bad but
canonical user pointer can still fault after a message has been consumed.
Unmatched IPC remains `WouldBlock`; this does not implement blocked IPC, a
per-thread result, lock-atomic endpoint/scheduler/PCB/CSpace transitions, SMP,
or seL4 equivalence.
