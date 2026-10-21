# A11 switched-task FPU regression — 2026-10-21

## Finding

The timer FPU regression added in PR #26 injected vector 32 while only the boot
task was runnable. It checked the no-switch path, but not saving one TCB's XMM
state, running another task, and restoring the first task later. Audit also
found the existing worker test's floating-point arithmetic was unused and its
local-versus-constant comparisons could be optimized away. The old output
overstated those checks; it now reports counter iterations and the dedicated
XMM test separately.

## Research (2026-10-21)

- Intel SDM current set (version 093, page updated 2026-10-09):
  <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>
- Intel SDM Volume 1, section 10.5, defines the 512-byte FXSAVE area and its
  x87/SSE contents:
  <https://cdrdv2-public.intel.com/843827/253665-sdm-vol-1-dec-24.pdf>
- The current kernel uses a 16-byte-aligned `FpuState` per TCB and schedules
  tasks on 2 ms UserInteractive slices; the periodic BSP timer reports 10 ms
  elapsed per tick. The regression explicitly waits until the boot task runs
  after the worker publishes its XMM sentinel before asking it to stop.

## Commands and results

- Failure-first guard: `python tools/test_switched_fpu_state.py` — failed before
  implementation because the switched-context worker did not exist.
- First QEMU probe attempt timed out because `lateout("rax")` allowed the
  compiler to alias an input pointer with AL, which the probe sets before its
  XCHG. Changed it to a non-overlapping `out("rax")`; the probe then passed.
- `python tools/test_switched_fpu_state.py` — passed.
- `cargo test --workspace --exclude kernel --features kvault/test-fast-kdf` —
  passed.
- `cargo check --release --manifest-path kernel/Cargo.toml --target
  x86_64-unknown-none` — passed.
- `cargo build --release --manifest-path kernel/Cargo.toml --target
  x86_64-unknown-none` — passed.
- All `tools/test_*.py` guards — passed.
- `python tools/claims_lint.py` and `python tools/verify_findings.py` — passed;
  F8 and F10 remain present.
- `python -u tests/test_qemu_boot.py` — passed T0 to the shell and observed
  both same-task and switched-task XMM15 markers. The worker published its
  sentinel before the boot task was scheduled again, then verified it after a
  later timer handoff.
- `git diff --check` — passed.
- `rtk` is unavailable in this environment; verification commands ran directly.

## Limits

PR #27 passed the required GitHub Actions gates and merged to `main` at
`7c3a92c815f651b9a8a17f2356b0bc0ec379e9fa` on 2026-10-21. Both triggered runs
reported success for Workspace Subsystem Tests, Build Microkernel (x86-64),
and Build Guide v2 Claims & Honesty Gate.

This regression covers a timer-driven switch between tasks on the BSP only. It
does not test AP concurrency, per-CPU run queues, worst-case interrupt stack
usage, hardware other than QEMU T0, or formal isolation.
