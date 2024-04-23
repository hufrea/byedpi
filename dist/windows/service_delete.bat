@echo off
title ByeDPI - Delete Service

echo This script should be run with administrator privileges.
echo Right click - run as administrator.
echo Press any key if you're running it as administrator.
pause

set svc_name="ByeDPI"

sc stop %svc_name%
sc delete %svc_name%
pause