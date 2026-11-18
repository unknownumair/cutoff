@echo off
REM CUTOFF Windows launcher.
REM First run installs the app machine-wide (%ProgramData%\CUTOFF) so the
REM "cutoff" command works in any prompt; later runs just start it.
setlocal EnableExtensions
cd /d "%~dp0"

fltmc >nul 2>&1
if errorlevel 1 (
  echo [*] Administrator rights are required for Npcap and firewall rules.
  echo [*] Re-launching elevated...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY (
  where python >nul 2>&1 && set "PY=python"
)
if not defined PY (
  echo [!] Python 3 was not found.
  echo     Install it from https://www.python.org/downloads/windows/ and tick
  echo     "Add python.exe to PATH", then run run.bat again.
  pause
  exit /b 1
)

REM ---------------------------------------------------------------- install
if not exist "%ProgramData%\CUTOFF\VERSION" (
  if "%CUTOFF_NO_INSTALL%"=="1" goto local
  echo [*] First run - installing CUTOFF into %ProgramData%\CUTOFF
  call "%~dp0tools\install-global.bat"
  if errorlevel 1 (
    echo [!] Global install failed - continuing from this folder instead.
    goto local
  )
)

if exist "%ProgramData%\CUTOFF\bin\cutoff.cmd" (
  echo [*] Starting the installed copy on http://127.0.0.1:8848
  call "%ProgramData%\CUTOFF\bin\cutoff.cmd"
  echo.
  echo [i] CUTOFF stopped. The "cutoff" command stays available in new terminals.
  pause
  exit /b 0
)

:local
if not exist ".venv\Scripts\python.exe" (
  echo [*] Creating virtual environment...
  %PY% -m venv .venv
  if errorlevel 1 (
    echo [!] Could not create .venv
    pause
    exit /b 1
  )
)

call ".venv\Scripts\activate.bat"
echo [*] Installing Python dependencies...
python -m pip install --disable-pip-version-check -q -r backend\requirements.txt
if errorlevel 1 (
  echo [!] pip install failed
  pause
  exit /b 1
)

echo [*] Checking Npcap and portable tools (first run downloads them)...
python backend\platform_ops.py
if errorlevel 1 (
  echo [!] Driver/tool setup failed - see the messages above.
  pause
  exit /b 1
)

echo [*] Starting CUTOFF on http://127.0.0.1:8848
python backend\app.py
echo.
echo [i] CUTOFF stopped.
pause
