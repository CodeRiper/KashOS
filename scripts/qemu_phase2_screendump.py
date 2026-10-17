import subprocess
import time
import socket
import os
import sys

def main():
    port = 44446
    bios_ppm = "qemu_phase2_bios.ppm"
    bios_png = "qemu_phase2_bios.png"
    lock_ppm = "qemu_phase2_lock.ppm"
    lock_png = "qemu_phase2_lock.png"
    log_path = "qemu_phase2.log"

    for p in [bios_ppm, bios_png, lock_ppm, lock_png, log_path]:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass

    cmd = [
        "qemu-system-x86_64",
        "-kernel", "isodir/boot/kash-kernel",
        "-m", "512M",
        "-vga", "std",
        "-display", "none",
        "-serial", f"file:{log_path}",
        "-monitor", f"tcp:127.0.0.1:{port},server,nowait"
    ]

    print(f"Starting QEMU for Phase 2 UI test (monitor on 127.0.0.1:{port})...")
    proc = subprocess.Popen(cmd)

    # Connect to QEMU monitor
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connected = False
    for _ in range(50):
        try:
            s.connect(("127.0.0.1", port))
            connected = True
            break
        except Exception:
            time.sleep(0.1)

    if not connected:
        print("Failed to connect to QEMU monitor")
        proc.kill()
        return

    s.settimeout(5.0)
    try:
        s.recv(1024)
    except Exception:
        pass

    # Wait until the kernel enters the Liquid-Glass compositor main render loop
    print("Waiting for kernel to initialize and enter Liquid-Glass render loop...")
    started = False
    for _ in range(250):
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                if "Entering Liquid-Glass compositor main render loop" in content:
                    started = True
                    break
        time.sleep(0.1)

    if not started:
        print("Failed: render loop not entered in time")
        s.close()
        proc.kill()
        return

    print("Compositor is actively rendering!")
    
    # Capture BIOS POST screen (first 1.5 seconds of compositor run)
    time.sleep(1.2)
    print(f"Capturing BIOS screen: {bios_ppm}...")
    s.sendall(f"screendump {bios_ppm}\n".encode('ascii'))
    time.sleep(1.0)

    # Wait 5.5 seconds for BIOS to finish and transition to Logo / Lock screen
    print("Waiting for transition to Logo / Lock screen...")
    time.sleep(5.5)
    print(f"Capturing Lock screen: {lock_ppm}...")
    s.sendall(f"screendump {lock_ppm}\n".encode('ascii'))
    time.sleep(1.0)

    s.sendall(b"quit\n")
    time.sleep(0.5)
    s.close()
    proc.wait(timeout=5)

    print("QEMU session ended.")

    # Convert PPMs to PNGs
    from PIL import Image
    for ppm, png in [(bios_ppm, bios_png), (lock_ppm, lock_png)]:
        if os.path.exists(ppm):
            size = os.path.getsize(ppm)
            print(f"Captured {ppm} ({size} bytes)")
            try:
                img = Image.open(ppm)
                img.save(png)
                print(f"  Converted to {png} ({img.size[0]}x{img.size[1]})")
            except Exception as e:
                print(f"  Conversion error for {ppm}: {e}")
        else:
            print(f"FAILED to find {ppm}")

if __name__ == "__main__":
    main()
