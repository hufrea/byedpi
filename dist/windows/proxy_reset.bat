@echo off

rem Run as administrator
reg query "HKU\S-1-5-19\Environment" >nul 2>&1
if not %errorlevel% equ 0 (
powershell.exe -windowstyle hidden -noprofile "Start-Process '%~dpnx0' -Verb RunAs"
exit /b 0
)

reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyEnable" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyServer" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MigrateProxy" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "AutoDetect" /f