# A11 timer-interrupt FPU save boundary — 2026-10-21

## Finding

`_isr32` saved GPRs and then called `x86_timer_handler`; `task::on_timer_tick`
only saved FPU state later after entering Rust. The scheduler's FXSAVE buffer
was 16-byte aligned, but this ordering could capture handler-clobbered XMM/x87
state. A regression guard was added first and failed because no `FXSAVE64`
instruction existed in the timer entry stub.

## Research (2026-10-21)

- Intel SDM latest page, updated 2026-10-09, version 093:
  <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>
- Intel SDM Volume 1, section 10.5: FXSAVE/FXRSTOR operate on a 512-byte area
  whose base must be 16-byte aligned; the saved state includes x87, XMM, and
  MXCSR: <https://cdrdv2-public.intel.com/843827/253665-sdm-vol-1-dec-24.pdf>
- Intel SDM Volume 3A, section 6.14: 64-bit interrupt stack frames are
  16-byte-aligned before the CPU pushes the frame, and save the prior RSP;
  interrupt handling stack semantics are documented there:
  <https://cdrdv2-public.intel.com/812386/253668-sdm-vol-3a.pdf>
- The repo's `.cargo/config.toml` uses the `x86_64-unknown-none` target, whose
  red zone is disabled per the checked-in comment.

## Commands and results

- Failure-first regression: `python tools/test_timer_fpu_preservation.py` —
  failed as expected before implementation (`fxsave64` absent from `_isr32`).
- `python tools/test_timer_fpu_preservation.py` — passed.
- `cargo test --workspace --exclude kernel --features kvault/test-fast-kdf` —
  passed.
- `cargo check --release --manifest-path kernel/Cargo.toml --target
  x86_64-unknown-none` — passed.
- `cargo build --release --manifest-path kernel/Cargo.toml --target
  x86_64-unknown-none` — passed.
- All `tools/test_*.py` source guards — passed.
- `python tools/claims_lint.py` — passed.
- `python tools/verify_findings.py` — passed; F8 (VT-d hardware unavailable)
  and F10 (normal desktop in Ring 0) remain present.
- `python -u tests/test_qemu_boot.py` — passed T0 through the shell. The boot
  self-test executed software interrupt `int 0x20` with a sentinel in XMM15 and
  verified it after the same-task timer path returned. This checks the exact
  timer gate and no-switch restore path in QEMU; it does not exercise a task
  switch or concurrent CPUs.
- `git diff --check` — passed.
- The `rtk` command is unavailable in this environment; commands ran directly.

## Limits

The scheduler/TCB storage remains shared and AP startup remains disabled. The
temporary area adds 528 bytes to the active task stack during a timer interrupt;
no worst-case kernel stack-depth analysis is included. The source guard and QEMU
smoke run do not establish SMP correctness or formal isolation. CI status for
the current task branch: pending.
