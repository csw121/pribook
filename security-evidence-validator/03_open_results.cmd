@echo off
setlocal
call "%~dp0windows.cmd" results %*
set "sev_exit=%errorlevel%"
echo.
pause
exit /b %sev_exit%
