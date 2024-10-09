@echo off
title ByeDPI - Delete Service

rem Run as administrator
reg query "HKU\S-1-5-19\Environment" >nul 2>&1
if not %errorlevel% equ 0 (
powershell.exe -windowstyle hidden -noprofile "Start-Process '%~dpnx0' -Verb RunAs"
exit /b 0
)

set svc_name="ByeDPI"

sc stop %svc_name%
sc delete %svc_name%