@echo off
title KashOS v0.1.0 Interactive Workstation Launcher
cls
echo ======================================================================
echo           KASH-OS v0.1.0 HIGH-ASSURANCE WORKSTATION LAUNCHER
echo ======================================================================
echo.
echo [*] Checking KashOS kernel and ISO images...
if not exist "isodir\boot\kash-kernel" (
    echo [-] Error: isodir\boot\kash-kernel not found. Run 'cargo build --release -p kernel' first.
    pause
    exit /b 1
)

echo [+] Kernel Binary: isodir\boot\kash-kernel
echo [+] ISO Image:     kash-os.iso
echo.
echo [*] System Configuration:
echo     - CPU:          4 vCPUs (Multi-core SMP)
echo     - Memory:       1024 MiB (1 GiB) High-Speed RAM
echo     - Display:      Standard VGA 1024x768 @ 60 FPS
echo     - Network:      Intel e1000 Gigabit NIC + User Netdev
echo     - Acceleration: WHPX (Windows Hypervisor Platform) with fallback to Multi-Threaded TCG
echo.
echo [*] Navigation ^& Controls:
echo     - Mouse:             Move cursor and click dock apps / window headers
echo     - Release Mouse:     Press [Ctrl + Alt + G] or [Ctrl + Alt]
echo     - F12:               Toggle Nitpicker X-Ray security border inspection
echo     - Secure Input:      Click window to switch focus; keystrokes route strictly to focused domain
echo.
echo [!] Starting KashOS Workstation in QEMU...
echo.

qemu-system-x86_64 ^
    -accel whpx,kernel-irqchip=off ^
    -accel tcg,thread=multi ^
    -cpu max ^
    -smp 4 ^
    -m 1024M ^
    -vga std ^
    -kernel isodir/boot/kash-kernel ^
    -device e1000,netdev=net0 ^
    -netdev user,id=net0 ^
    -serial file:kash_serial.log

echo.
echo [!] KashOS session ended. Serial log saved to 'kash_serial.log'.
pause
