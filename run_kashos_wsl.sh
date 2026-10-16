#!/bin/bash
cd "$(dirname "$0")"
echo "========================================================"
echo "  Launching KashOS Desktop in QEMU via WSL (WSLg Display)"
echo "========================================================"
qemu-system-x86_64 -kernel isodir/boot/kash-kernel -m 512M -vga std -name "KashOS 27 Liquid-Glass Desktop"
