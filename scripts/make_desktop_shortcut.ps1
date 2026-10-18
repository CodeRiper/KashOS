$WshShell = New-Object -ComObject WScript.Shell
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$RootDir = Split-Path -Parent $PSScriptRoot
$Shortcut = $WshShell.CreateShortcut("$DesktopPath\KashOS 27 Desktop.lnk")
$Shortcut.TargetPath = "$RootDir\Launch_KashOS.bat"
$Shortcut.WorkingDirectory = "$RootDir"
$Shortcut.Description = "Launch KashOS 27 Liquid-Glass Desktop"
$Shortcut.Save()
Write-Output "Shortcut created on Desktop successfully."
