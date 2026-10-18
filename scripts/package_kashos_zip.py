import os
import zipfile
import sys

def package_zip(output_zip="kash os.zip"):
    print(f"Creating clean complete source code zip: {output_zip}...")
    
    # Files/directories to exclude
    exclude_dirs = {
        'target', '.git', '.gemini', '__pycache__', '.tempmediaStorage', '.system_generated'
    }
    exclude_files = {
        'kash os.zip', 'KashOS_Complete_Source.zip', 'KashOS_Source_Release.zip',
        'KashOS_v0.1.0_Complete_Release.zip', 'kash_drive.img', 'bios_test.ppm', 'test_screen.ppm'
    }

    base_dir = os.path.abspath(".")
    file_count = 0
    total_bytes = 0

    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, dirs, files in os.walk(base_dir):
            # Modify dirs in-place to avoid traversing excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]

            for file in files:
                if file in exclude_files or file.endswith('.ppm') or file.endswith('.tmp'):
                    continue
                
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, base_dir)

                # Skip any target directory accidental match
                if any(part in exclude_dirs for part in rel_path.split(os.sep)):
                    continue

                zf.write(full_path, rel_path)
                file_count += 1
                total_bytes += os.path.getsize(full_path)

    zip_size = os.path.getsize(output_zip)
    print(f"[+] Zip successfully created: {output_zip}")
    print(f"[+] Packaged {file_count} files ({total_bytes:,} raw bytes -> {zip_size:,} compressed bytes)")

if __name__ == "__main__":
    out_name = sys.argv[1] if len(sys.argv) > 1 else "kash os.zip"
    package_zip(out_name)
