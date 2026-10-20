#!/usr/bin/env python3
"""Compatibility entry point for the retired, destructive installer test.

The old version booted a potentially stale kernel and issued a disk-writing
install command. Keep this script safe by running only the current source guard.
"""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "tools" / "test_installer_fail_closed.py"
raise SystemExit(subprocess.call([sys.executable, str(GUARD)], cwd=ROOT))
