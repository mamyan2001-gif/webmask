@echo off
setlocal
cd /d "%~dp0\.."

echo.
echo WebMask - install dependencies
echo.

where node >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Node.js 18+ is required. Install from https://nodejs.org
  exit /b 1
)

echo Installing server packages...
cd server
call npm install --no-audit --no-fund
if errorlevel 1 exit /b 1
cd ..

echo Installing client packages...
cd client
call npm install --no-audit --no-fund
if errorlevel 1 exit /b 1
cd ..

echo Installing Playwright Chromium...
cd server
call npx --yes playwright install chromium
cd ..

echo.
echo Setup complete.
echo Next: double-click "Start WebMask.bat" or run npm run start:app
echo.
pause
