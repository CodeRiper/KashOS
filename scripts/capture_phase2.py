import subprocess
import time
import socket
import os
import sys

def main():
    port = 44452
    bios_ppm = "qemu_phase2_bios.ppm"
    bios_png = "qemu_phase2_bios.png"
    lock_ppm = "qemu_phase2_lock.ppm"
    lock_png = "qemu_phase2_lock.png"

    for p in [bios_ppm, bios_png, lock_ppm, lock_png]:
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
        "-serial", "stdio",
        "-monitor", f"tcp:127.0.0.1:{port},server,nowait"
    ]

    print(f"Starting QEMU (monitor on 127.0.0.1:{port})...")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

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

    # Read serial output line by line until render loop
    print("Waiting for kernel to enter Liquid-Glass compositor render loop...")
    t0 = time.time()
    entered = False
    for line in iter(proc.stdout.readline, b''):
        text = line.decode('utf-8', errors='ignore').strip()
        if "[gui]" in text or "[boot]" in text or "PANIC" in text:
            print(f"[{time.time()-t0:6.2f}s] {text}", flush=True)
        if "Entering Liquid-Glass compositor main render loop" in text:
            entered = True
            break
        if time.time() - t0 > 450:
            print("Timeout waiting for render loop!")
            break

    if not entered:
        print("Failed: render loop not entered!")
        s.close()
        proc.kill()
        return

    print("SUCCESS: Compositor is actively rendering!")
    
    # Capture BIOS screen (1.0 second into render loop)
    time.sleep(1.2)
    print(f"Capturing BIOS screen: {bios_ppm}...")
    s.sendall(f"screendump {bios_ppm}\n".encode('ascii'))
    time.sleep(1.0)

    # Wait 15 seconds for transition through BIOS (3.9s) -> Golden Gate Logo (2.6s) -> Lock screen
    print("Waiting 15s for transition to Lock screen...")
    time.sleep(15.0)
    print(f"Capturing Lock screen: {lock_ppm}...")
    s.sendall(f"screendump {lock_ppm}\n".encode('ascii'))
    time.sleep(1.0)

    s.sendall(b"quit\n")
    time.sleep(0.5)
    s.close()
    proc.kill()

    print("QEMU session finished.")

    from PIL import Image
    for ppm, png in [(bios_ppm, bios_png), (lock_ppm, lock_png)]:
        if os.path.exists(ppm):
            img = Image.open(ppm)
            img.save(png)
            print(f"Saved {png} ({img.size[0]}x{img.size[1]})")
        else:
            print(f"Error: missing {ppm}")

if __name__ == "__main__":
    main()
