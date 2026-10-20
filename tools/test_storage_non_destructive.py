#!/usr/bin/env python3
"""Guard boot-time storage checks against destructive persistent-disk writes."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
VFS = (ROOT / "kernel/src/vfs.rs").read_text(encoding="utf-8")
SELFTEST = (ROOT / "kernel/src/selftest.rs").read_text(encoding="utf-8")


def body(source: str, start: str, end: str) -> str:
    left = source.index(start)
    right = source.index(end, left)
    return source[left:right]


def main() -> int:
    mount = body(VFS, "pub fn mount_root(", "/// Explicitly formats a new kvault filesystem")
    test = body(SELFTEST, "fn test_kvault_root_mount_readonly()", "/// Test 26:")

    checks = [
        ("Mount never formats on open failure", "Vault::format" not in mount),
        ("Mount does not provision folders or files", "create_folder(" not in mount and "write_file(" not in mount),
        ("Boot self-test never formats the persistent root", "format_root(" not in test),
        ("Boot self-test never writes filesystem data", "vfs::write(" not in test),
        ("Boot self-test never raw-writes disk sectors", "write_sectors(" not in test),
        ("Unmounted root vault is skipped safely", "if !vfs::is_root_mounted()" in test and "return;" in test),
    ]
    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'}: {name}")
    failures = [name for name, passed in checks if not passed]
    if failures:
        print(f"{len(failures)} destructive-storage regression(s) detected.", file=sys.stderr)
        return 1
    print(f"All {len(checks)} storage safety regression checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
