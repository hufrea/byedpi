@echo off
title ByeDPI - Install Service

rem Run as administrator
reg query "HKU\S-1-5-19\Environment" >nul 2>&1
if not %errorlevel% equ 0 (
powershell.exe -windowstyle hidden -noprofile "Start-Process '%~dpnx0' -Verb RunAs"
exit /b 0
)

set svc_name="ByeDPI"
set svc_desc="Local SOCKS proxy server to bypass DPI (Deep Packet Inspection)."

set svc_bin="\"%~dp0ciadpi.exe\" --ip 127.0.0.1 --split 1+s --disorder 3+s --mod-http=h,d --auto --tlsrec 1+s"

sc stop %svc_name%
sc delete %svc_name%
sc create %svc_name% binPath= %svc_bin% start= "auto"
sc description %svc_name% %svc_desc%
sc start %svc_name%