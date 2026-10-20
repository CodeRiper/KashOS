#!/usr/bin/env python3
"""Guard the Linux DDE prototype against fabricated physical/DMA addresses."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
DDE = (ROOT / "kernel/src/dde.rs").read_text(encoding="utf-8")


def body(start: str, end: str) -> str:
    first = DDE.index(start)
    return DDE[first:DDE.index(end, first)]


def main() -> int:
    checks = [
        ("DDE does not allocate fabricated physical addresses", "next_alloc_paddr" not in DDE and "0x2000_0000" not in DDE),
        ("DDE kmalloc reports unavailable", 'Err("DDE memory allocation is unavailable")' in body("pub fn kmalloc(", "    /// DMA allocation")),
        ("DDE DMA allocator reports unavailable", 'Err("DDE DMA allocation is unavailable' in body("pub fn dma_alloc_coherent(", "    /// Registers a Linux-derived")),
        ("DDE registry does not claim a running driver", "driver execution and DMA are unavailable" in body("pub fn register_driver(", "}\n\n// ── 2.")),
        ("DDE listing labels entries as a model registry", "MODEL REGISTRY (NO DRIVERS RUNNING)" in DDE),
    ]
    failed = [name for name, passed in checks if not passed]
    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'}: {name}")
    if failed:
        print(f"{len(failed)} DDE DMA fail-closed regression(s) detected.", file=sys.stderr)
        return 1
    print(f"All {len(checks)} DDE DMA fail-closed checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
