#!/usr/bin/env python3
"""Regression guard: the unverified installer must not write to storage."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SHELL = (ROOT / "kernel/src/shell.rs").read_text(encoding="utf-8")


def main() -> int:
    start = SHELL.index("pub fn run_kash_installer(")
    end = SHELL.index("/// Run an interactive REPL terminal", start)
    installer = SHELL[start:end]
    forbidden = (
        "write_sectors(",
        "flush_cache(",
        "deterministic_zero(",
        "format_root(",
    )
    checks = [
        ("Installer reports itself disabled", "[installer] Disabled:" in installer),
        ("Installer explains no disk sectors were changed", "No disk sectors were changed" in installer),
        *[(f"Installer excludes {call}", call not in installer) for call in forbidden],
    ]
    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'}: {name}")
    failures = [name for name, passed in checks if not passed]
    if failures:
        print(f"{len(failures)} installer write regression(s) detected.", file=sys.stderr)
        return 1
    print(f"All {len(checks)} installer safety checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
