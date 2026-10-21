# A11 syscall voluntary-yield evidence — 2026-10-21

Base reviewed: `main` at `07c32d88ea9c3c968677d4b694346bae1501037a`.

## Source research

- Intel, *64 and IA-32 Architectures Software Developer's Manual*, Volume 2A,
  Version 089, `INT n` privilege check; and Volume 3A, Version 089, IDT gate
  behavior. Official manual landing page:
  https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
  Volume 2A PDF (Version 089):
  https://cdrdv2-public.intel.com/868140/253666-089-sdm-vol-2a.pdf
  The INT instruction checks gate DPL against CPL for software-generated
  interrupts. KashOS keeps vector 0xF0 at DPL 0 and invokes it only from the
  Ring 0 SYS_YIELD dispatcher. This reference supports gate selection; runtime
  QEMU evidence checks the actual path.
- Intel, *64 and IA-32 Architectures Software Developer's Manual*, Volume 2B,
  SYSCALL instruction, current Version 093 manual search result:
  https://cdrdv2-public.intel.com/774492/325383-sdm-vol-2abcd.pdf
  SYSCALL saves the next RIP to RCX and flags to R11 and masks flags using
  IA32_FMASK. It does not itself provide a task context switch. The new
  software interrupt runs after the syscall entry has already switched to the
  task-owned kernel stack.
- seL4, *IPC Tutorial*, reviewed 2026-10-21:
  https://docs.sel4.systems/Tutorials/ipc
  Blocking endpoint calls and reply capabilities are separate IPC semantics;
  this SYS_YIELD work does not implement them.

## Failure-first regression

The new scheduler host tests were added before the scheduler method. The first
run of
`cargo test -p kscheduler --test scheduler_tests voluntary_yield -- --nocapture`
failed to compile because `plan_voluntary_yield_on_cpu` was absent. Both tests
pass after implementation.

## Verification

- `cargo test -p kscheduler --test scheduler_tests voluntary_yield -- --nocapture` — PASS (2 tests).
- `cargo test --workspace --exclude kernel --features kvault/test-fast-kdf` — PASS.
- `cargo check --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none` — PASS.
- `cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none` — PASS.
- `python tools/test_syscall_voluntary_yield.py` — PASS.
- `Get-ChildItem tools/test_*.py | ForEach-Object { python $_.FullName }` — PASS, all source guards.
- `python -u tests/test_qemu_boot.py` — PASS; T0 single CPU reached shell and saw `SYS_YIELD resumed Ring 3`.
- `python tools/claims_lint.py` — PASS after replacing a claims-linter trigger phrase.
- `python tools/verify_findings.py` — PASS; F8 and F10 remain present.
- `git diff --check` — PASS after final source and documentation changes.

The repository instructs using `rtk` for shell commands, but `rtk --version`
reports that `rtk` is not installed. Commands ran directly in PowerShell.

## Limits

This demonstrates a voluntary Ring 3 syscall switching away and resuming on the
BSP under QEMU. It does not demonstrate blocking IPC, result continuation,
SMP, AP startup, fault-safe page copy, or production readiness. Unmatched IPC
still returns `WouldBlock`.
