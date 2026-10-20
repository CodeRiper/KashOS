#!/usr/bin/env python3
"""
tools/verify_findings.py — Verify Ground Truth Findings F1 to F12
Section 1.3 of KashOS Master Engineering Plan
"""
import os
import sys
import subprocess

def run_check(finding_id, command):
    try:
        res = subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def check_file_contains(finding_id, filepath, pattern, invert=False):
    if not os.path.exists(filepath):
        return False if not invert else True
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            found = pattern in content
            return (not found) if invert else found
    except Exception:
        return False

def check_cargo_contains(pattern):
    for root, dirs, files in os.walk("."):
        if "target" in dirs:
            dirs.remove("target")
        for f in files:
            if f == "Cargo.toml":
                with open(os.path.join(root, f), "r", encoding="utf-8", errors="ignore") as c:
                    if pattern in c.read():
                        return True
    return False

def main():
    checks = [
        ("F1", check_file_contains("F1", "kernel/src/net.rs", "Congratulations")),
        ("F2", check_file_contains("F2", "kernel/src/net.rs", "Default Tor Exit")),
        ("F3", check_file_contains("F3", "knet/src/lib.rs", "TcpState::Established")),
        ("F4", not check_cargo_contains("smoltcp")),
        ("F5", check_file_contains("F5", "kernel/src/arch/x86_64/tpm.rs", "pcr_bank")),
        ("F6", check_file_contains("F6", "kernel/src/kms.rs", "generating fresh master key")),
        ("F7", check_file_contains("F7", "kernel/src/vfs.rs", "Err(open_fail)")),
        ("F8", check_file_contains("F8", "khal/src/vtd.rs", "next_phys_frame: 0x4000_0000")),
        ("F9", check_file_contains("F9", "kernel/src/selftest.rs", "s.tpm2_crtm = crate::status::ComponentStatus::Real")),
        ("F10", (
            check_file_contains("F10", "kernel/src/session.rs", "gui::run_desktop_session")
            and check_file_contains("F10", "kernel/src/session.rs", "shell.run_interactive_terminal")
        )),
        ("F11", check_file_contains("F11", "kash-ui/crates/kash-ui/src/apps/files.rs", "todo.txt")),
        ("F12", check_file_contains("F12", "kernel/src/browser.rs", "about:privacy")),
    ]

    print("======================================================================")
    print("  KASHOS GROUND TRUTH FINDINGS VERIFICATION (Master Plan v2.0)")
    print("======================================================================")
    present_count = 0
    for fid, is_present in checks:
        status = "PRESENT (finding still true)" if is_present else "ABSENT (finding fixed or wrong)"
        if is_present:
            present_count += 1
        print(f"  {fid:<4} {status}")
    print("======================================================================")
    print(f"  Summary: {present_count}/{len(checks)} findings PRESENT.")
    print("======================================================================")

if __name__ == "__main__":
    main()
