@echo off
title Fetch latest Qlik logs
cd /d "%~dp0"
echo Copies the newest Qlik logs from the ArchivedLogs share to %USERPROFILE%\QlikLogs\latest
echo.
set "DAYS=2"
set /p DAYS=How many days back? [2] 
set "S="
set /p S=Also sample one audit file per day for the last 90 days (slower)? [y/N] 
set "EXTRA="
if /i "%S%"=="y" set "EXTRA=-Sample"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Fetch latest Qlik logs.ps1" -Days %DAYS% %EXTRA%
echo.
pause
