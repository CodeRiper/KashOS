@echo off
title KashOS Liquid-Glass Desktop
echo ========================================================
echo   Launching KashOS Desktop in QEMU (1024x768 True Color)
echo ========================================================
echo.
cd /d "%~dp0"
qemu-system-x86_64.exe -kernel isodir\boot\kash-kernel -m 512M -vga std -name "KashOS 27 Liquid-Glass Desktop"
pause
