import subprocess
import time
import socket
import os
import sys

def main():
    port = 44445
    ppm_path = sys.argv[1] if len(sys.argv) > 1 else "qemu_phase1_screen.ppm"
    png_path = sys.argv[2] if len(sys.argv) > 2 else "qemu_phase1_screen.png"
    log_path = sys.argv[3] if len(sys.argv) > 3 else "qemu_phase1.log"

    if os.path.exists(ppm_path):
        os.remove(ppm_path)
    if os.path.exists(png_path):
        os.remove(png_path)

    cmd = [
        "qemu-system-x86_64",
        "-smp", "4",
        "-kernel", "isodir/boot/kash-kernel",
        "-m", "512M",
        "-vga", "std",
        "-display", "none",
        "-serial", f"file:{log_path}",
        "-monitor", f"tcp:127.0.0.1:{port},server,nowait"
    ]
    
    print(f"Starting QEMU with monitor on 127.0.0.1:{port}...")
    proc = subprocess.Popen(cmd)
    
    # Wait for kernel to boot and render
    time.sleep(12)
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connected = False
        for _ in range(30):
            try:
                s.connect(("127.0.0.1", port))
                connected = True
                break
            except Exception:
                time.sleep(0.2)
        
        if not connected:
            raise RuntimeError("Could not connect to QEMU monitor TCP socket")

        s.settimeout(3.0)
        try:
            s.recv(1024)
        except Exception:
            pass
            
        print(f"Sending screendump {ppm_path} to QEMU monitor...")
        s.sendall(f"screendump {ppm_path}\n".encode('ascii'))
        time.sleep(1.5)
        s.sendall(b"quit\n")
        time.sleep(0.5)
        s.close()
        proc.wait(timeout=5)
    except Exception as e:
        print(f"Monitor communication error: {e}")
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            pass
        
    if os.path.exists(ppm_path):
        size = os.path.getsize(ppm_path)
        print(f"PPM screendump captured successfully! Size: {size} bytes")
        try:
            from PIL import Image
            img = Image.open(ppm_path)
            img.save(png_path)
            print(f"Converted to PNG: {png_path} ({img.size[0]}x{img.size[1]})")
        except Exception as e:
            print(f"Pillow conversion error: {e}")
    else:
        print("Failed to capture PPM screendump")

if __name__ == "__main__":
    main()
