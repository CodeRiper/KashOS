#!/usr/bin/env bash
set -e
mkdir -p isodir/boot/grub
cp target/x86_64-unknown-none/release/kernel isodir/boot/kash-kernel
cat > isodir/boot/grub/grub.cfg << 'EOF'
set default=0
set timeout=1

menuentry "KashOS v0.2.0 (High-Assurance Hardened Microkernel)" {
    multiboot2 /boot/kash-kernel
    boot
}
EOF
grub-mkrescue -o kash-os.iso isodir
ls -lh kash-os.iso
