@echo off
setlocal
call "%~dp0windows.cmd" analyze %*
set "sev_exit=%errorlevel%"
echo.
pause
exit /b %sev_exit%
