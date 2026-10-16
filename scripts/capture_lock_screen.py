import subprocess
import time
import socket
import os
import sys

def main():
    port = 44455
    lock_ppm = "qemu_phase2_lock.ppm"
    lock_png = "qemu_phase2_lock.png"

    for p in [lock_ppm, lock_png]:
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
    
    # Wait 8 seconds to allow Logo animation to run, then send Enter key to advance to Lock screen
    print("Waiting 8s in render loop...")
    time.sleep(8.0)
    print("Sending Enter key via QEMU monitor to transition to Lock screen...")
    s.sendall(b"sendkey ret\n")
    time.sleep(3.0)

    print(f"Capturing Lock screen: {lock_ppm}...")
    s.sendall(f"screendump {lock_ppm}\n".encode('ascii'))
    time.sleep(1.0)

    s.sendall(b"quit\n")
    time.sleep(0.5)
    s.close()
    proc.kill()

    from PIL import Image
    if os.path.exists(lock_ppm):
        img = Image.open(lock_ppm)
        img.save(lock_png)
        print(f"Saved {lock_png} ({img.size[0]}x{img.size[1]})")

if __name__ == "__main__":
    main()
