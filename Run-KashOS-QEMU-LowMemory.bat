@echo off
setlocal
set "KASHOS_QEMU=qemu-system-x86_64"
if exist "C:\Users\Akash.J\qemu\qemu-system-x86_64.exe" set "KASHOS_QEMU=C:\Users\Akash.J\qemu\qemu-system-x86_64.exe"
set "KASHOS_ISO=%~dp0kash-os.iso"

if not exist "%KASHOS_ISO%" (
    echo [-] Error: kash-os.iso not found at "%KASHOS_ISO%".
    pause
    exit /b 1
)

start "KashOS QEMU - Low Memory (1 CPU, 256 MiB)" "%KASHOS_QEMU%" -name "KashOS Low-Memory Test" -machine q35 -cpu max -m 256M -smp 1 -nic none -vga std -cdrom "%KASHOS_ISO%" -boot d -display gtk,zoom-to-fit=on

