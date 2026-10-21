# A11 FPU initial state — 2026-10-21

## Finding and correction

Source audit found `FpuState::empty()` produced 512 zero bytes. The scheduler
restores this state for new kernel threads and user processes using `FXRSTOR64`.
The zero image therefore configured x87/SSE execution differently from the
architectural reset defaults. A failure-first source guard was added and run
against the old implementation; it failed because `FpuState::initial()` did
not exist. The implementation now initializes x87 FCW to `0x037f` and MXCSR
to `0x1f80` and uses that constructor for every fresh thread/process state.

The guard is `tools/test_fpu_initial_state.py`. It checks the documented byte
offsets/values and the TCB/process construction sites. This is a source-level
regression check; it does not establish hardware behavior or context-switch
correctness.

## Research (2026-10-21)

- Intel, *64 and IA-32 Architectures Software Developer's Manual*, current
  combined set shown as version 093 on the Intel manuals page (updated
  2026-10-09): <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>
- Volume 2A, `FXSAVE` defines the 512-byte state layout, including x87 control
  word and MXCSR fields: <https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf>
- Volume 2A, `FNINIT` specifies the x87 control word default `0x037f`, masks
  all exceptions, rounds to nearest, and empties the x87 stack:
  <https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf>
- Volume 1, section 11.6.4 specifies MXCSR reset value `0x1f80` and the reset
  state of XMM registers:
  <https://cdrdv2-public.intel.com/671436/253665-sdm-vol-1.pdf>

## Commands and results

- Baseline regression: `python tools/test_fpu_initial_state.py` — failed as
  expected before the implementation (`FpuState::initial()` absent).
- `python tools/test_fpu_initial_state.py` — passed.
- `cargo test --workspace --exclude kernel --features kvault/test-fast-kdf` —
  passed (full workspace host suite).
- `cargo check --release --manifest-path kernel/Cargo.toml --target
  x86_64-unknown-none` — passed.
- `cargo build --release --manifest-path kernel/Cargo.toml --target
  x86_64-unknown-none` — passed.
- All `tools/test_*.py` source guards — passed.
- `python tools/claims_lint.py` — passed.
- `python tools/verify_findings.py` — passed; the known F8 and F10 findings
  remain present.
- `python -u tests/test_qemu_boot.py` — passed T0 smoke markers through the
  shell using QEMU's Conroe profile (1 CPU, 1 GiB). This does not exercise FPU
  switching or multi-CPU execution.
- `git diff --check` — passed.
- `cargo fmt --all -- --check` and targeted `rustfmt --check` — failed on
  pre-existing formatting differences across unrelated repository code. No
  broad formatting rewrite was applied.
- The requested `rtk` command prefix could not be used because `rtk` is not
  installed in this environment; the listed commands were run directly.

## Limits

The timer interrupt currently enters Rust before saving the interrupted FPU
state. Rust/ABI code may use caller-saved XMM registers, so the correctness of
that save boundary is not established by this change and requires a separate
interrupt-entry design and test. The scheduler, TCB/FPU storage, and timer
ownership are still shared; APs remain parked and A11 is incomplete.
