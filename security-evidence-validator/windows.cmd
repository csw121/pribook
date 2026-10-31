@echo off
setlocal
chcp 65001 >nul
set "PYTHONUTF8=1"
pushd "%~dp0"
if errorlevel 1 exit /b 2
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -c "import sys; raise SystemExit(sys.version_info < (3,13))" >nul 2>&1
  if not errorlevel 1 goto use_venv
)
py -3 -c "import sys; raise SystemExit(sys.version_info < (3,13))" >nul 2>&1
if not errorlevel 1 goto use_py
python -c "import sys; raise SystemExit(sys.version_info < (3,13))" >nul 2>&1
if not errorlevel 1 goto use_python
echo Python 3.13 or newer is required on this PC.
echo Install: https://www.python.org/downloads/windows/
echo Or run: winget install --exact --id Python.Python.3.13
echo Reopen this window after installation.
popd
exit /b 2
:use_venv
".venv\Scripts\python.exe" "tools\windows_launcher.py" %*
goto finish
:use_py
py -3 "tools\windows_launcher.py" %*
goto finish
:use_python
python "tools\windows_launcher.py" %*
:finish
set "sev_exit=%errorlevel%"
popd
exit /b %sev_exit%
