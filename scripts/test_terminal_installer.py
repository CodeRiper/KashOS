import subprocess
import time
import sys

def main():
    cmd = [
        "qemu-system-x86_64",
        "-accel", "tcg,thread=multi",
        "-cpu", "max",
        "-kernel", "isodir/boot/kash-kernel",
        "-drive", "file=kash_drive.img,format=raw,if=ide,index=0,media=disk",
        "-m", "512M",
        "-vga", "none",
        "-display", "none",
        "-serial", "stdio"
    ]

    print("Starting QEMU without VGA to test serial interactive shell & kash installer...")
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    collected_output = []
    t0 = time.time()
    shell_ready = False

    print("Streaming kernel boot logs until shell prompt...")
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        text = line.decode('utf-8', errors='ignore')
        collected_output.append(text)
        safe_print = text.strip().encode('ascii', errors='replace').decode('ascii')
        if any(tag in safe_print for tag in ["[boot]", "[selftest]", "[kblock]", "[stage", "kash-root", "KASH-OS", "MBR"]):
            print(f"[{time.time()-t0:5.1f}s] {safe_print}")

        if "kash-root@kash-node-01" in text or "Launching interactive root shell" in text:
            shell_ready = True
            print(f"\n[+] Shell prompt reached at {time.time()-t0:.1f}s! Executing 'kash install'...")
            proc.stdin.write(b"kash install\n")
            proc.stdin.flush()
            break

        if time.time() - t0 > 90:
            print("[-] Timeout waiting for shell prompt!")
            break

    if not shell_ready:
        print("[-] Shell failed to initialize.")
        proc.kill()
        sys.exit(1)

    # Now read installer stages
    print("Capturing installer execution...")
    t_inst = time.time()
    installer_complete = False
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        text = line.decode('utf-8', errors='ignore')
        collected_output.append(text)
        safe_print = text.strip().encode('ascii', errors='replace').decode('ascii')
        print(safe_print)

        if "KASH-OS INSTALLATION COMPLETE" in text:
            installer_complete = True
            print("\n[+] Installer finished! Sending 'kash status'...")
            proc.stdin.write(b"kash status\n")
            proc.stdin.flush()
            break

        if time.time() - t_inst > 30:
            print("[-] Timeout waiting for installer completion!")
            break

    # Read status output
    time.sleep(2)
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except Exception:
        proc.kill()

    full_text = "".join(collected_output)
    if "[stage-1]" in full_text and "[stage-7]" in full_text and "KASH-OS INSTALLATION COMPLETE" in full_text:
        print("\n======================================================================")
        print("  [TEST-PASS] 7-Stage Bare-Metal Installer Verified Successfully!    ")
        print("======================================================================")
        sys.exit(0)
    else:
        print("\n[TEST-FAIL] Incomplete installer execution.")
        sys.exit(1)

if __name__ == "__main__":
    main()
