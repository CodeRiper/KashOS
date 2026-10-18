@echo off
setlocal
if exist "%USERPROFILE%\qemu\qemu-system-x86_64.exe" set "KASHOS_QEMU=%USERPROFILE%\qemu\qemu-system-x86_64.exe"
if exist "C:\Program Files\qemu\qemu-system-x86_64.exe" set "KASHOS_QEMU=C:\Program Files\qemu\qemu-system-x86_64.exe"
set "KASHOS_ISO=%~dp0kash-os.iso"

if not exist "%KASHOS_ISO%" (
    echo [-] Error: kash-os.iso not found at "%KASHOS_ISO%".
    pause
    exit /b 1
)

start "KashOS QEMU - Low Memory (1 CPU, 256 MiB)" "%KASHOS_QEMU%" -name "KashOS Low-Memory Test" -machine q35 -cpu max -m 256M -smp 1 -drive file="%~dp0kash_vault.img",format=raw,if=ide,index=0,media=disk -nic none -vga std -cdrom "%KASHOS_ISO%" -boot d -display gtk,zoom-to-fit=on

