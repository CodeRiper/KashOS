#!/usr/bin/env python3
"""Prevent prototype Ring 3 mechanisms from being presented as user services."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")
    print(f"PASS: {message}")


session = read("kernel/src/session.rs")
main = read("kernel/src/main.rs")
selftest = read("kernel/src/selftest.rs")
status = read("kernel/src/status.rs")
shell = read("kernel/src/shell.rs")
verifier = read("tools/verify_findings.py")
evidence = read("docs/EVIDENCE/A10.md")

require("launch_kernel_resident_session" in session, "session entry point identifies kernel-resident execution")
require("gui::run_desktop_session" in session and "shell.run_interactive_terminal" in session,
        "both prototype UI paths are visible in the reviewed session module")
require("setup_capabilities" not in session and "Rights::ALL" not in session,
        "session setup does not fabricate process capability spaces")
require("launch_kernel_resident_session" in main and "kernel-resident UI" in main,
        "normal boot labels its UI as kernel-resident")
require("user_mode_ring3 = crate::status::ComponentStatus::Partial" in selftest,
        "self-test does not report production user-service isolation as Real")
require("T13 test only; UI remains in Ring 0" in status,
        "status registry distinguishes process tests from the Ring 0 UI")
require("currently run in Ring 0" in shell and "[VERIFIED NOMINAL]" not in shell,
        "shell does not claim user-mode service isolation")
require('"F10"' in verifier and '"kernel/src/session.rs"' in verifier,
        "ground-truth verifier checks the real session source path")
require("Needs revalidation" in evidence and "A10 remains open" in evidence,
        "A10 evidence records the incomplete service migration")

print("All userland honesty regression checks passed.")
