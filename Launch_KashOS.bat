@echo off
title KashOS 27 Liquid-Glass Desktop
cd /d "%~dp0"
if not exist "isodir\boot\kash-kernel" cd /d "c:\Users\Akash.J\Documents\KashOS Kernal\kash-kernel"
cls
echo ===================================================================
echo   KashOS 27 Liquid-Glass Desktop - Interactive Session
echo   Hardened Microkernel v0.2.0 (seL4 capability model + CDT)
echo ===================================================================
echo.
echo  [SYSTEM PROFILE]
echo    * Resolution: 1024x768 32bpp TrueColor Linear Framebuffer
echo    * Compositor: Liquid-Glass Direct Framebuffer GPU/CPU Compositor
echo    * Trackpad:   Ballistic Acceleration Curve (High-Speed Gliding)
echo    * Memory:     512 MiB RAM
echo    * Processor:  Multi-threaded TCG Core
echo    * Disk:       10 GiB Persistent Disk (kash_drive.img)
echo.
echo  [SHORTCUTS]
echo    * Click inside window : Grab mouse/trackpad focus
echo    * Ctrl+Alt+G          : Release mouse back to Windows
echo    * Ctrl+T              : Open Terminal (commands: neofetch, selftest, install, help)
echo    * Ctrl+S / Ctrl+,     : Open Settings (Security ^& Anti-Forensics)
echo    * Ctrl+Space          : Spotlight Search
echo    * Ctrl+F              : Files (kvault-fs)
echo    * Ctrl+B              : Firefox Browser (Default Browser, All Permissions Denied)
echo    * Ctrl+L              : Launchpad Grid
echo.
echo  Starting KashOS GUI window...
echo.

set "QEMU_EXE=C:\Users\Akash.J\qemu\qemu-system-x86_64.exe"
if not exist "%QEMU_EXE%" set "QEMU_EXE=qemu-system-x86_64.exe"

REM Try SDL display first for instant DirectInput mouse responsiveness without queue lag
"%QEMU_EXE%" -accel tcg,thread=multi -cpu max -smp 1 -m 512M -vga std -display sdl -drive file=kash_drive.img,format=raw,if=ide,index=0,media=disk -kernel isodir\boot\kash-kernel -name "KashOS 27 Liquid-Glass Desktop" -serial file:qemu_serial.log

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Fallback to GTK display...
    "%QEMU_EXE%" -accel tcg,thread=multi -cpu max -smp 1 -m 512M -vga std -display gtk -drive file=kash_drive.img,format=raw,if=ide,index=0,media=disk -kernel isodir\boot\kash-kernel -name "KashOS 27 Liquid-Glass Desktop" -serial file:qemu_serial.log
)

echo.
echo KashOS session closed. Press any key to exit...
pause >nul
