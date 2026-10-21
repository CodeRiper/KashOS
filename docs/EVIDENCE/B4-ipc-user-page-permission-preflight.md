# B4 IPC user-page permission preflight evidence

Date: 2026-10-21

## Source review and research

- Reviewed `kernel/src/arch/x86_64/syscall.rs`, the ELF mapping path in
  `kernel/src/elf.rs`, and the T11/T42 checks in `kernel/src/selftest.rs`.
- Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 3A,
  §6.11.1, page protection: U/S and R/W permissions are checked across paging
  structure entries. Official document:
  https://cdrdv2-public.intel.com/874249/253668-090-sdm-vol-3a.pdf
- The current KashOS loader constructs 4 KiB leaves, with page-table frames
  directly addressable under the current frame allocator contract. The
  implementation rejects large-page entries and checks every paging level.

## Failure-first regression

Before implementation, `python tools/test_syscall_user_page_permissions.py`
failed because `validate_user_page_range` was absent. The regression now checks
that syscall copy helpers validate page mappings and appropriate permissions,
IPC receive output is checked before endpoint mutation, and the CI workflow
runs this source guard.

## Verification

- `python tools/test_syscall_user_page_permissions.py` — PASS.
- `cargo test --workspace --exclude kernel --features kvault/test-fast-kdf` —
  PASS.
- `cargo check --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none` — PASS.
- `cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none` — PASS.
- All 32 `tools/test_*.py` source guards — PASS.
- `python tools/claims_lint.py` — PASS.
- `python tools/verify_findings.py` — PASS; F8 and F10 remain present.
- `python tests/test_qemu_boot.py` — PASS after explicitly building the release
  kernel first. The script itself uses an existing release binary and does not
  rebuild it. T0 ran with one QEMU CPU and checked user RX, stack RW, read-only
  rejection, an unmapped cross-page range, an unmapped adjacent page, and
  successful boot through the locked shell.
- `git diff --check` — PASS.

The repository requires shell commands to start with `rtk`, but `rtk --version`
reported that the command is not installed. Commands were run directly in
PowerShell.

## Limits

This check supports current x86-64 four-level paging and kernel-created,
identity-addressable page tables. It does not make the subsequent memory copy
fault-recoverable, support concurrent address-space mutation, make scheduler or
IPC state SMP-safe, or add AArch64 syscall-copy validation. APs remain parked.
This narrow change does not establish seL4 equivalence or production readiness.
