@echo off
REM CUTOFF global installer for Windows.
REM Copies the app to %ProgramData%\CUTOFF, builds its venv, writes a
REM "cutoff" shim and appends its bin dir to the machine PATH.
REM Run from an elevated prompt (run.bat already is).
setlocal EnableExtensions
cd /d "%~dp0.."

fltmc >nul 2>&1
if errorlevel 1 (
  echo [!] Administrator rights are required for a machine-wide install.
  pause
  exit /b 1
)

set "PREFIX=%ProgramData%\CUTOFF"
set "SRC=%CD%"

echo [*] Installing CUTOFF to "%PREFIX%"
if not exist "%PREFIX%" mkdir "%PREFIX%"
robocopy "%SRC%" "%PREFIX%" /E /XD .venv .git __pycache__ "backend\data" /XF *.pyc *.log /NFL /NDL /NJH /NJS /NP >nul
if errorlevel 8 (
  echo [!] Could not copy the application files.
  exit /b 1
)

set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY ( where python >nul 2>&1 && set "PY=python" )
if not defined PY (
  echo [!] Python 3 was not found. Install it from python.org and tick "Add python.exe to PATH".
  exit /b 1
)

if not exist "%PREFIX%\.venv\Scripts\python.exe" (
  echo [*] Creating virtual environment in "%PREFIX%\.venv"
  %PY% -m venv "%PREFIX%\.venv"
)
echo [*] Installing Python dependencies
"%PREFIX%\.venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r "%PREFIX%\backend\requirements.txt"
if errorlevel 1 (
  echo [!] pip install failed - the machine needs network access once.
  exit /b 1
)

if not exist "%PREFIX%\data" mkdir "%PREFIX%\data"
if not exist "%PREFIX%\bin" mkdir "%PREFIX%\bin"

(
  echo @echo off
  echo set "CUTOFF_PREFIX=%PREFIX%"
  echo set "CUTOFF_DATA_DIR=%PREFIX%\data"
  echo "%%CUTOFF_PREFIX%%\.venv\Scripts\python.exe" "%%CUTOFF_PREFIX%%\backend\app.py" %%*
) > "%PREFIX%\bin\cutoff.cmd"

(
  echo @echo off
  echo set "CUTOFF_PREFIX=%PREFIX%"
  echo set "CUTOFF_DATA_DIR=%PREFIX%\data"
  echo "%%CUTOFF_PREFIX%%\.venv\Scripts\python.exe" "%%CUTOFF_PREFIX%%\backend\doctor.py" %%*
) > "%PREFIX%\bin\cutoff-doctor.cmd"

REM Append the shim directory to the machine PATH (once).
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$d='%PREFIX%\bin'; $p=[Environment]::GetEnvironmentVariable('Path','Machine');" ^
  "if (($p -split ';') -notcontains $d) { if ($p.Length -lt 900) { [Environment]::SetEnvironmentVariable('Path', ($p.TrimEnd(';') + ';' + $d), 'Machine'); Write-Host '[*] Added' $d 'to the machine PATH' } else { Write-Host '[!] PATH is too long - add' $d 'manually' -ForegroundColor Yellow } } else { Write-Host '[*] PATH already contains' $d }"

if exist "%PREFIX%\VERSION" (
  set /p VER=<"%PREFIX%\VERSION"
) else (
  set "VER=unknown"
)

echo.
echo CUTOFF %VER% installed
echo   run      : cutoff          (new terminals; this one needs PATH refreshed)
echo   doctor   : cutoff-doctor
echo   open     : http://127.0.0.1:8848/
echo   token    : %PREFIX%\data\api_token
echo   uninstall: rmdir /s /q "%PREFIX%"  ^(and remove the bin dir from PATH^)
echo.
exit /b 0
