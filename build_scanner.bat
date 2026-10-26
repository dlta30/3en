@echo off
setlocal
cd /d "%~dp0"
py -m pip install --upgrade pip
py -m pip install -r requirements-scanner.txt
py -m PyInstaller --noconfirm --clean --onefile --windowed --name 3eN-Fight-Scanner-PRO scanner.py
if errorlevel 1 (
  echo.
  echo Build failed. Check the error above.
  pause
  exit /b 1
)
echo.
echo Finished. EXE path: dist\3eN-Fight-Scanner-PRO.exe
pause
