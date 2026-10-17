import subprocess
import time
import socket
import os
import sys

def main():
    port = 44458
    ppm_path = "qemu_phase7_screen.ppm"
    png_path = "qemu_phase7_screen.png"
    log_path = "qemu_phase7.log"

    for p in [ppm_path, png_path, log_path]:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass

    cmd = [
        "qemu-system-x86_64",
        "-accel", "tcg,thread=multi",
        "-cpu", "max",
        "-kernel", "isodir/boot/kash-kernel",
        "-m", "512M",
        "-vga", "std",
        "-display", "none",
        "-serial", f"file:{log_path}",
        "-monitor", f"tcp:127.0.0.1:{port},server,nowait"
    ]

    print(f"Starting QEMU for Phase 7 live capture (monitor on 127.0.0.1:{port})...")
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
            time.sleep(0.2)

    if not connected:
        print("Failed to connect to QEMU monitor")
        proc.kill()
        return

    s.settimeout(5.0)
    try:
        s.recv(1024)
    except Exception:
        pass

    # Monitor serial log until frame blit complete
    print("Waiting for boot, Phase 7 selftests (T28-T31), and GUI frame blit...")
    t0 = time.time()
    entered = False
    while time.time() - t0 < 120:
        if os.path.exists(log_path):
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if "blit complete" in content:
                    print(f"[{time.time()-t0:.1f}s] Frame blit complete detected!")
                    entered = True
                    break
        time.sleep(0.5)

    if not entered:
        print("Warning: blit complete marker not found within 120s, proceeding anyway...")
    else:
        time.sleep(1.0)

    print(f"Sending screendump {ppm_path} to QEMU monitor...")
    s.sendall(f"screendump {ppm_path}\n".encode('ascii'))
    time.sleep(1.5)
    s.sendall(b"quit\n")
    time.sleep(0.5)
    s.close()
    proc.wait(timeout=5)

    if os.path.exists(ppm_path):
        from PIL import Image
        img = Image.open(ppm_path)
        img.save(png_path)
        print(f"Captured {png_path} ({img.size[0]}x{img.size[1]})")
    else:
        print("Error: screendump ppm not generated")

if __name__ == "__main__":
    main()
