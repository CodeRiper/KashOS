#!/bin/bash
export DISPLAY=:0
export WAYLAND_DISPLAY=wayland-0
export XDG_RUNTIME_DIR=/mnt/wslg/runtime-dir
export PULSE_SERVER=/mnt/wslg/PulseServer

cd "/mnt/c/Users/Akash.J/Documents/KashOS Kernal/kash-kernel"

echo "=========================================================="
echo "  Starting KashOS 27 Liquid-Glass Desktop in QEMU (WSLg)  "
echo "=========================================================="

qemu-system-x86_64 \
    -accel kvm \
    -accel tcg \
    -kernel isodir/boot/kash-kernel \
    -m 512M \
    -vga std \
    -display gtk \
    -name "KashOS 27 Liquid-Glass Desktop"
