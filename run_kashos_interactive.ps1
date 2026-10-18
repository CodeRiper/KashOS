# KashOS v0.1.0 High-Assurance Workstation Launcher (PowerShell)
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "          KASH-OS v0.1.0 HIGH-ASSURANCE WORKSTATION LAUNCHER" -ForegroundColor White
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path "isodir\boot\kash-kernel")) {
    Write-Host "[-] Error: isodir\boot\kash-kernel not found. Build kernel first." -ForegroundColor Red
    exit 1
}

Write-Host "[+] Kernel Binary: isodir\boot\kash-kernel" -ForegroundColor Green
Write-Host "[+] ISO Image:     kash-os.iso" -ForegroundColor Green
Write-Host ""
Write-Host "[*] Configuration: 4 vCPUs, 1024 MiB RAM, 1024x768 60 FPS, Intel e1000 NIC" -ForegroundColor Yellow
Write-Host "[*] Mouse Release: [Ctrl + Alt + G] or [Ctrl + Alt]" -ForegroundColor Yellow
Write-Host "[*] Security:      Press [F12] for Nitpicker X-Ray border inspection" -ForegroundColor Yellow
Write-Host ""
Write-Host "[!] Launching KashOS GUI window..." -ForegroundColor Cyan

& qemu-system-x86_64 `
    -accel whpx,kernel-irqchip=off `
    -accel tcg,thread=multi `
    -cpu max `
    -smp 4 `
    -m 1024M `
    -vga std `
    -kernel isodir/boot/kash-kernel `
    -drive file=kash_vault.img,format=raw,if=ide,index=0,media=disk `
    -device e1000,netdev=net0 `
    -netdev user,id=net0 `
    -serial file:kash_serial.log

Write-Host ""
Write-Host "[!] KashOS session completed. Serial log written to 'kash_serial.log'." -ForegroundColor Green
