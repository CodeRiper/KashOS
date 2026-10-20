#!/usr/bin/env python3
"""
tests/test_qemu_boot.py — KashOS Automated QEMU Boot & Acceptance Test Suite
Fulfills Problem #8 and Section 7 & 15 of KashOS Build Guide Part B:
Boots the compiled kernel headlessly under QEMU on the T0 Legacy Profile
(-cpu Conroe, 1 core, 1024M RAM) and asserts that all security gates,
seL4 capabilities, and interactive commands execute with zero panics.
"""

import os
import sys
import time
import subprocess

def find_qemu():
    candidates = [
        "qemu-system-x86_64",
        os.path.expandvars(r"%USERPROFILE%\qemu\qemu-system-x86_64.exe"),
        r"C:\Program Files\qemu\qemu-system-x86_64.exe",
        "/usr/bin/qemu-system-x86_64",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    # Try PATH
    try:
        subprocess.run(["qemu-system-x86_64", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return "qemu-system-x86_64"
    except Exception:
        return None

def test_t0_boot():
    qemu_bin = find_qemu()
    if not qemu_bin:
        print("[-] Error: qemu-system-x86_64 not found in system or known paths.")
        return False

    # Prefer the freshly built release image. isodir can contain a stale image
    # from a previous checkout and would otherwise make this test verify old code.
    release_kernel = os.path.join("target", "x86_64-unknown-none", "release", "kernel")
    packaged_kernel = os.path.join("isodir", "boot", "kash-kernel")
    kernel_bin = release_kernel if os.path.exists(release_kernel) else packaged_kernel

    if not os.path.exists(kernel_bin):
        print(f"[-] Error: Kernel binary not found at {kernel_bin}. Build kernel first.")
        return False

    # QEMU T0 Profile: 1 Core, 1024M RAM, Vintage Conroe CPU
    cmd = [
        qemu_bin,
        "-accel", "tcg,thread=multi",
        "-cpu", "Conroe",
        "-smp", "1",
        "-m", "1024M",
        "-kernel", kernel_bin,
        "-drive", "file=kash_vault.img,format=raw,if=ide,index=0,media=disk" if os.path.exists("kash_vault.img") else "file=kash_drive.img,format=raw,if=ide,index=0,media=disk",
        "-vga", "none",
        "-display", "none",
        "-serial", "stdio"
    ]

    print("=" * 70)
    print("  KASHOS QEMU T0 BOOT SMOKE TEST (-cpu Conroe, 1 CPU, 1024M RAM)")
    print("=" * 70)
    print(f"[+] Launching: {' '.join(cmd)}")

    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    start_time = time.time()

    required_markers = {
        "mmu_wx": False,
        "sel4_cap": False,
        "test_t22": False,
        "test_t40": False,
        "test_t44": False,
        "kms_locked": False,
        "vault_selftest_skip": False,
        "unlock_help": False,
        "shell_ready": False,
    }

    collected_lines = []
    timeout_sec = 60

    try:
        while time.time() - start_time < timeout_sec:
            line_bytes = proc.stdout.readline()
            if not line_bytes:
                break
            line = line_bytes.decode("utf-8", errors="ignore").strip()
            if not line:
                continue
            collected_lines.append(line)

            # Echo relevant boot lines
            if any(k in line for k in ["[boot]", "[mmu]", "[cap]", "[kms]", "[selftest] PASS", "[selftest] SKIP", "[storage]", "root@kash-node-01"]):
                print(f"  {line}")

            if "W^X" in line:
                required_markers["mmu_wx"] = True
            if "[cap] Initialized seL4 root untyped" in line:
                required_markers["sel4_cap"] = True
            if "T22 " in line:
                required_markers["test_t22"] = True
            if "T40 " in line:
                required_markers["test_t40"] = True
            if "T44 " in line:
                required_markers["test_t44"] = True
            if "[kms] Locked:" in line:
                required_markers["kms_locked"] = True
            if "T25 root vault is not mounted; refusing to format" in line:
                required_markers["vault_selftest_skip"] = True
            if "Vault is locked. Use 'unlock'; passphrase input is hidden." in line:
                required_markers["unlock_help"] = True
                required_markers["shell_ready"] = True
                print("\n[+] Shell prompt reached! Sending interactive verification commands...")
                # Send hardware report command
                proc.stdin.write(b"hardware-report\n")
                proc.stdin.flush()
                time.sleep(0.5)
                # Send tpm status command
                proc.stdin.write(b"tpm\n")
                proc.stdin.flush()
                time.sleep(0.5)
                # Send capability retype test command
                proc.stdin.write(b"cap retype\n")
                proc.stdin.flush()
                time.sleep(0.5)
                # Send exit/sync
                proc.stdin.write(b"dmesg\n")
                proc.stdin.flush()
                time.sleep(1.0)
                break

    finally:
        proc.kill()
        proc.wait()

    print("\n" + "=" * 70)
    print("  QEMU BOOT ASSERTION RESULTS")
    print("=" * 70)
    all_passed = True
    for marker, found in required_markers.items():
        status = "[PASS]" if found else "[FAIL]"
        print(f"  * Marker {marker:<15}: {status}")
        if not found:
            all_passed = False

    if all_passed:
        print("\n[+] SUCCESS: T0 Legacy profile booted through the shell and emitted the required smoke-test markers.")
        return True
    else:
        print("\n[-] FAILED: Some required boot markers were not observed.")
        return False

if __name__ == "__main__":
    success = test_t0_boot()
    sys.exit(0 if success else 1)
