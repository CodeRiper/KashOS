@echo off
title KashOS VirtualBox Launcher
cd /d "%~dp0"

echo ===================================================================
echo   KashOS 27 Liquid-Glass Desktop - Native VirtualBox Launcher
echo ===================================================================
echo.
set VBOX="C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
if not exist %VBOX% (
    echo [ERROR] VirtualBox not found at %VBOX%
    pause
    exit /b 1
)

echo [INFO] Starting VirtualBox VM 'KashOS' with native hardware acceleration...
start "" "C:\Program Files\Oracle\VirtualBox\VirtualBoxVM.exe" --startvm "KashOS"

echo.
echo VirtualBox VM launched! Look for the VirtualBox window on your taskbar.
