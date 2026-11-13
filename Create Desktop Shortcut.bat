@echo off
setlocal
set "TARGET=%~dp0Start Qlik Log Analyzer.bat"
if not exist "%TARGET%" (
  echo Could not find "Start Qlik Log Analyzer.bat" next to this file.
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=[Environment]::GetFolderPath('Desktop'); $s=(New-Object -ComObject WScript.Shell).CreateShortcut($d+'\Qlik Log Analyzer.lnk'); $s.TargetPath='%TARGET%'; $s.WorkingDirectory='%~dp0'; $s.IconLocation='shell32.dll,13'; $s.Description='Qlik engine log analyzer'; $s.Save(); Write-Host ('Shortcut created on your desktop: ' + $d)"
if errorlevel 1 (
  echo Could not create the shortcut. You can right-click "Start Qlik Log Analyzer.bat" and choose Send to, then Desktop.
)
pause
endlocal
