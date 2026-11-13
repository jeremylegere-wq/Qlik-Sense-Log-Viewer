@echo off
setlocal
cd /d "%~dp0"
title Qlik Server Event Manager

rem --- find Python 3 ---
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY (
  echo Python 3 was not found on this PC.
  echo Install it from the Software Centre or python.org, then run this again.
  pause
  exit /b 1
)

rem --- one-time setup into a private .venv folder next to this file ---
if not exist ".venv\Scripts\python.exe" (
  echo First run: setting up. This takes a few minutes and only happens once.
  %PY% -m venv .venv
  if errorlevel 1 (
    echo Could not create the Python environment.
    pause
    exit /b 1
  )
  ".venv\Scripts\python.exe" -m pip install --upgrade pip >nul 2>&1
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  if not errorlevel 1 ".venv\Scripts\python.exe" -c "import hashlib,sys,pathlib;pathlib.Path(sys.prefix,'requirements.sha1').write_text(hashlib.sha1(open('requirements.txt','rb').read()).hexdigest())"
  if errorlevel 1 (
    echo.
    echo Install failed. Check this PC can reach pypi.org, or ask IT to allow it.
    rmdir /s /q ".venv"
    pause
    exit /b 1
  )
)

rem --- stop Streamlit asking for an email address on first launch ---
if not exist "%USERPROFILE%\.streamlit\credentials.toml" (
  mkdir "%USERPROFILE%\.streamlit" >nul 2>&1
  > "%USERPROFILE%\.streamlit\credentials.toml" echo [general]
  >> "%USERPROFILE%\.streamlit\credentials.toml" echo email = ""
)

echo.
echo Starting the Qlik Server Event Manager. Your browser will open in a moment.
echo It uses its own port, so your other Streamlit apps can stay open.
echo Leave this window open while you use it. Close it to stop the app.
echo.
".venv\Scripts\python.exe" launch.py
if errorlevel 1 pause
endlocal
