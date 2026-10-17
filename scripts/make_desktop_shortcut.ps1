$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\Users\Akash.J\Desktop\KashOS 27 Desktop.lnk")
$Shortcut.TargetPath = "c:\Users\Akash.J\Documents\KashOS Kernal\kash-kernel\Launch_KashOS.bat"
$Shortcut.WorkingDirectory = "c:\Users\Akash.J\Documents\KashOS Kernal\kash-kernel"
$Shortcut.Description = "Launch KashOS 27 Liquid-Glass Desktop"
$Shortcut.Save()
Write-Output "Shortcut created on Desktop successfully."
