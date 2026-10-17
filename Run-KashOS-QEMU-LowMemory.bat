@echo off
setlocal
set "KASHOS_QEMU=C:\Users\Akash.J\qemu\qemu-system-x86_64.exe"
set "KASHOS_ISO=%~dp0target\KashOS-LowHW-responsive.iso"

if not exist "%KASHOS_QEMU%" (
    echo QEMU was not found at "%KASHOS_QEMU%".
    pause
    exit /b 1
)
if not exist "%KASHOS_ISO%" (
    echo The tested ISO was not found at "%KASHOS_ISO%".
    pause
    exit /b 1
)

start "KashOS QEMU - 1 CPU, 100 MiB" "%KASHOS_QEMU%" -name "KashOS low-memory test" -machine q35 -cpu core2duo -m 100M -smp 1 -nic none -vga std -cdrom "%KASHOS_ISO%" -boot d -display gtk,zoom-to-fit=on
