#!/usr/bin/env python3
"""
tools/harness/runner.py — External Test Harness for KashOS
Implements Section 7 of KashOS Build Guide v2:
Drives QEMU across CPU tiers, collects structured KASH-EVT JSON lines,
and validates isolation/security events from outside the guest.
"""

import subprocess
import json
import time
import os
import sys

TIER_PROFILES = {
    "T0": ["-cpu", "Conroe", "-smp", "1", "-m", "1024M"],
    "T0-lowmem": ["-cpu", "Conroe", "-smp", "1", "-m", "256M"],
    "T2": ["-cpu", "max", "-smp", "4", "-m", "1024M"],
}

def find_qemu():
    if "QEMU_PATH" in os.environ and os.path.exists(os.environ["QEMU_PATH"]):
        return os.environ["QEMU_PATH"]
    import shutil
    which_qemu = shutil.which("qemu-system-x86_64")
    if which_qemu:
        return which_qemu
    # Common fallback install locations
    for c in [
        r"C:\Program Files\qemu\qemu-system-x86_64.exe",
        os.path.expanduser(r"~\qemu\qemu-system-x86_64.exe"),
    ]:
        if os.path.exists(c):
            return c
    return "qemu-system-x86_64"

class QemuHarness:
    def __init__(self, kernel_path="isodir/boot/kash-kernel", profile="T0", timeout_secs=10):
        self.kernel_path = kernel_path
        self.profile = profile
        self.timeout_secs = timeout_secs
        self.events = []
        self.raw_logs = []

    def run(self):
        import threading
        import queue

        qemu_bin = find_qemu()
        tier_args = TIER_PROFILES.get(self.profile, TIER_PROFILES["T0"])

        cmd = [
            qemu_bin,
            "-accel", "tcg,thread=multi",
            *tier_args,
            "-vga", "none",
            "-display", "none",
            "-kernel", self.kernel_path,
            "-serial", "stdio",
        ]

        print(f"[harness] Launching QEMU profile '{self.profile}' with command: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except Exception as e:
            print(f"[harness] Failed to start QEMU: {e}")
            return self.events

        q = queue.Queue()

        def reader():
            try:
                for line in iter(proc.stdout.readline, ''):
                    q.put(line)
            except Exception:
                pass
            finally:
                proc.stdout.close()

        t = threading.Thread(target=reader, daemon=True)
        t.start()

        start_time = time.time()
        try:
            while time.time() - start_time < self.timeout_secs:
                try:
                    line = q.get(timeout=0.2)
                    self.raw_logs.append(line.rstrip())
                    if line.startswith("KASH-EVT "):
                        json_str = line[len("KASH-EVT "):].strip()
                        try:
                            evt = json.loads(json_str)
                            self.events.append(evt)
                            print(f"[harness] Event: {evt.get('src')}/{evt.get('ev')}")
                        except json.JSONDecodeError as err:
                            print(f"[harness] Malformed KASH-EVT line: {err}")
                except queue.Empty:
                    if proc.poll() is not None:
                        break
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()

        return self.events

def main():
    profile = sys.argv[1] if len(sys.argv) > 1 else "T0"
    harness = QemuHarness(profile=profile)
    events = harness.run()
    print(f"\n[harness] Completed. Captured {len(events)} structured KASH-EVT events.")
    print(f"[harness] Total raw console lines logged: {len(harness.raw_logs)}")

if __name__ == "__main__":
    main()
