@echo off
title KashOS v0.1.0 Interactive Workstation Launcher
cd /d "%~dp0"
cls
echo ======================================================================
echo           KASH-OS v0.1.0 HIGH-ASSURANCE WORKSTATION LAUNCHER
echo ======================================================================
echo.
echo [*] Checking KashOS kernel and ISO images...
if not exist "isodir\boot\kash-kernel" (
    echo [-] Error: isodir\boot\kash-kernel not found. Run 'cargo build --release -p kernel --target x86_64-unknown-none' first.
    pause
    exit /b 1
)

set "QEMU_BIN=qemu-system-x86_64"
if defined QEMU_PATH if exist "%QEMU_PATH%" set "QEMU_BIN=%QEMU_PATH%"
if not defined QEMU_PATH if exist "%USERPROFILE%\qemu\qemu-system-x86_64.exe" set "QEMU_BIN=%USERPROFILE%\qemu\qemu-system-x86_64.exe"
if not defined QEMU_PATH if exist "C:\Program Files\qemu\qemu-system-x86_64.exe" set "QEMU_BIN=C:\Program Files\qemu\qemu-system-x86_64.exe"

echo [+] Kernel Binary: %~dp0isodir\boot\kash-kernel
echo [+] ISO Image:     %~dp0kash-os.iso
echo [+] QEMU Binary:   %QEMU_BIN%
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

"%QEMU_BIN%" ^
    -accel whpx,kernel-irqchip=off ^
    -accel tcg,thread=multi ^
    -cpu max ^
    -smp 4 ^
    -m 1024M ^
    -vga std ^
    -kernel "%~dp0isodir\boot\kash-kernel" ^
    -drive file="%~dp0kash_vault.img",format=raw,if=ide,index=0,media=disk ^
    -device e1000,netdev=net0 ^
    -netdev user,id=net0 ^
    -serial file:"%~dp0kash_serial.log"

echo.
echo [!] KashOS session ended. Serial log saved to 'kash_serial.log'.
pause
