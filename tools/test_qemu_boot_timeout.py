#!/usr/bin/env python3
"""Guard the T0 QEMU smoke test against blocking past its timeout."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
TEST_PATH = "tests/test_qemu_boot.py"


def check(source: str) -> None:
    required = (
        "output_lines = queue.Queue()",
        "def collect_output():",
        "threading.Thread(target=collect_output, daemon=True)",
        "output_lines.get(timeout=0.2)",
        "while time.time() - start_time < timeout_sec:",
        '"[security] PASS: deliberate NX/WP violation verified"',
        '"T13 Ring 3 process mechanism test passed"',
        '"T22 "',
        "Vault is locked. Use 'unlock'; passphrase input is hidden.",
    )
    for fragment in required:
        assert fragment in source, f"QEMU timeout invariant missing: {fragment}"
    assert "line_bytes = proc.stdout.readline()" not in source, (
        "the timeout loop must not block on serial output"
    )
    assert 'sys.stdout.reconfigure(errors="replace")' in source, (
        "boot output may contain characters unavailable in the host console encoding"
    )


def main() -> None:
    source = (ROOT / TEST_PATH).read_text(encoding="utf-8")
    check(source)
    print("PASS: QEMU serial output cannot block the T0 smoke-test timeout")

    old_source = subprocess.run(
        ["git", "show", f"HEAD:{TEST_PATH}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    try:
        check(old_source)
    except AssertionError:
        print("PASS: regression guard rejects the old blocking reader")
    else:
        raise AssertionError("regression guard accepted the blocking QEMU reader")


if __name__ == "__main__":
    main()
