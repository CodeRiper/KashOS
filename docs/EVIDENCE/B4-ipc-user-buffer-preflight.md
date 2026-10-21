# B4 IPC user-buffer preflight evidence — 2026-10-21

Base reviewed: `main` at `e306a0f` (PR #35 and its handoff sync).

## Source research

- Rust core 1.98.1, `core::ptr::copy_nonoverlapping`, reviewed 2026-10-21:
  https://doc.rust-lang.org/stable/core/ptr/fn.copy_nonoverlapping.html
  The API requires the source and destination to be valid for the copied byte
  count. KashOS's current helper only verifies canonical user-range bounds; it
  does not verify page mappings or write permissions. Therefore preflight is a
  boundary check only; the later memory copy can still fault.
- Intel SDM Version 093 (landing page updated 2026-10-09):
  https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
  Used for the existing syscall entry boundary; no new hardware behavior claim
  is made by this task.

## Failure-first regression

`python tools/test_syscall_ipc_user_buffers.py` was run before the fix and failed
because `validate_ipc_user_buffer` did not exist. The dispatcher also had no
preflight call before `sys_ipc_recv`, and ignored user-copy results.

## Verification

- `python tools/test_syscall_ipc_user_buffers.py` — PASS.
- `cargo test --workspace --exclude kernel --features kvault/test-fast-kdf` — PASS.
- `cargo check --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none` — PASS.
- `cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none` — PASS.
- `Get-ChildItem tools/test_*.py | ForEach-Object { python $_.FullName }` — PASS, all source guards.
- `python tools/claims_lint.py` — PASS after revising evidence wording.
- `python tools/verify_findings.py` — PASS; F8 and F10 remain present.
- `python -u tests/test_qemu_boot.py` — PASS, T0 single CPU reached shell and observed T42 IPC preflight marker.
- `git diff --check` — PASS after all source and documentation changes.

The repository requests command prefix `rtk`, but `rtk --version` reported that
`rtk` is not installed in this environment; commands ran directly in PowerShell.

## Limits and next work

Canonical-range validation does not validate page presence/write permission.
Direct message consumption can still precede a user-page fault; solving that
requires a transactional delivery design or fault-safe copy staging. Unmatched
IPC remains `WouldBlock`; saved continuation, atomic endpoint/PCB/TCB/scheduler
transitions, SMP scheduling, and AP startup are not implemented. A11 remains
in progress and B4 remains partial.
