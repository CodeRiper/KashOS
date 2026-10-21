# A11 per-thread stack guard pages — 2026-10-21

## Change

The x86-64 W^X page-table setup now removes every `ThreadStack.guard_page`
after mapping `.data`/`.bss`; failed unmaps stop boot. It also treats failure
to remove the existing boot-stack guard as fatal. Expected page-fault recovery
now checks the exact error code as well as vector and fault RIP. A BSP
self-test writes to the first reserved thread guard and verifies the exact
non-present supervisor-write fault is recovered. T0 requires its pass marker.

The design and limits are recorded in
[`../design/a11-thread-stack-guards.md`](../design/a11-thread-stack-guards.md).
Research reference: Intel SDM Vol. 3A §4.7,
<https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-system-programming-manual-325384.pdf>.
The manual defines P=0 as non-present, W/R=1 as write, and U/S=0 as supervisor;
the expected ordinary page-fault code is therefore `0b010`.

## Verification (2026-10-21)

```text
python tools/test_unmapped_thread_stack_guards.py --verify-baseline PASS
python tools/test_idt_per_cpu_state.py PASS
cargo test --workspace --exclude kernel --features kvault/test-fast-kdf PASS
cargo check --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
all tools/test_*.py guards PASS
python tools/claims_lint.py PASS
python tools/verify_findings.py PASS (F8 and F10 remain present)
python -u tests/test_qemu_boot.py PASS (T0 reached locked shell; observed exact #PF err=0x2 and stack guard marker)
git diff --check PASS
```

`rtk` is not installed in this environment, so commands ran directly. QEMU
T0 used one Conroe CPU under emulation. It verifies one deliberate guard
write on the BSP, not all stack sizes, AP execution, arbitrary fault-handler
stack exhaustion, or physical hardware. A11 remains incomplete; APs remain
parked, and findings F8 (hardware IOMMU/DMA path unavailable) and F10 (normal
GUI/session in Ring 0) remain present. No readiness or formal verification
claim is made.
