import zipfile
import os
import sys

def create_release_zip():
    zip_name = "KashOS_v0.1.0_Complete_Release.zip"
    print(f"[+] Creating release bundle: {zip_name}...")
    
    if os.path.exists(zip_name):
        os.remove(zip_name)

    # Key files to explicitly include
    critical_files = [
        "kash-os.iso",
        "README.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "TESTING.md",
        "ARCHITECTURAL_SECURITY_REPORT.md",
        "CRITIQUE_AND_VERIFICATION_REPORT.md",
        "LOW_HARDWARE_VM_TEST.md",
        "VIRTUALBOX_GUIDE.md",
        "VIRTUALBOX_OPTIMIZATION_GUIDE.md",
        "docs/CLAIMS.md",
        "docs/THREAT_MODEL.md",
        "docs/KASHOS_BUILD_GUIDE.md",
        "docs/ARCHITECTURAL_SECURITY_REPORT.md",
        "desktop.png",
        "vbox_kashos_desktop.png",
        "qemu_phase10_screen.png",
        "qemu_phase9_screen.png",
        "run_kashos_interactive.bat",
        "run_kashos_interactive.ps1",
        "Launch_KashOS.bat",
        "Run-KashOS-QEMU-LowMemory.bat",
        "launch_virtualbox.bat",
        "rust-toolchain.toml",
        "build_iso.sh",
        "isodir/boot/kash-kernel",
        "target/x86_64-unknown-none/release/kernel",
    ]

    # Directories to recursively include (all 12 workspace crates + tooling)
    code_dirs = [
        "docs",
        "kernel",
        "kcore",
        "kpaging",
        "kscheduler",
        "kipc",
        "kvault",
        "knet",
        "kblock",
        "kboot",
        "khal",
        "kheap",
        "kash-ui",
        "scripts",
        "isodir",
        ".cargo",
        ".github",
    ]

    # Files/extensions to ignore
    ignored_extensions = {".ppm", ".log", ".tmp", ".img"}
    ignored_dirs = {"target", ".git", ".gemini", ".system_generated"}

    seen = set()
    count = 0
    with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        # Add root project files
        for root_file in ["Cargo.toml", "Cargo.lock", "Makefile", ".gitignore"]:
            if os.path.exists(root_file) and root_file not in seen:
                zf.write(root_file, root_file)
                seen.add(root_file)
                count += 1

        for f in critical_files:
            if os.path.exists(f) and f not in seen:
                zf.write(f, f)
                seen.add(f)
                count += 1
                print(f"  [+] Added: {f}")

        for d in code_dirs:
            if not os.path.exists(d):
                continue
            for root, dirs, files in os.walk(d):
                dirs[:] = [sub for sub in dirs if sub not in ignored_dirs]
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext in ignored_extensions:
                        continue
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, ".").replace("\\", "/")
                    if arcname in seen:
                        continue
                    try:
                        zf.write(full_path, arcname)
                        seen.add(arcname)
                        count += 1
                    except Exception as e:
                        print(f"  [-] Skipped {full_path}: {e}")

    file_size_mb = os.path.getsize(zip_name) / (1024 * 1024)
    print(f"[OK] Successfully packaged {count} files into '{zip_name}' ({file_size_mb:.2f} MB)")

if __name__ == "__main__":
    create_release_zip()
