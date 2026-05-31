@echo off
setlocal
cd /d "%~dp0\.."

set APP_URL=http://localhost:5173
set RUN_DIR=.webmask

echo.
echo WebMask - starting app
echo.

if not exist "server\node_modules" (
  echo [ERROR] Dependencies not installed. Run "Install WebMask.bat" first.
  pause
  exit /b 1
)
if not exist "client\node_modules" (
  echo [ERROR] Dependencies not installed. Run "Install WebMask.bat" first.
  pause
  exit /b 1
)

if not exist "%RUN_DIR%" mkdir "%RUN_DIR%"

echo Starting API server on :4000...
start "WebMask API" /min cmd /c "cd /d %CD%\server && npm run dev >> ..\%RUN_DIR%\server.log 2>&1"

echo Starting UI on :5173...
start "WebMask UI" /min cmd /c "cd /d %CD%\client && npm run dev >> ..\%RUN_DIR%\client.log 2>&1"

echo Waiting for servers...
set /a tries=0
:wait_api
set /a tries+=1
curl -fsS http://localhost:4000/api/health >nul 2>&1 && goto api_ready
if %tries% GEQ 90 goto fail
timeout /t 1 /nobreak >nul
goto wait_api

:api_ready
set /a tries=0
:wait_ui
set /a tries+=1
curl -fsS %APP_URL% >nul 2>&1 && goto ui_ready
if %tries% GEQ 90 goto fail
timeout /t 1 /nobreak >nul
goto wait_ui

:ui_ready
start "" %APP_URL%
echo.
echo WebMask is running at %APP_URL%
echo Close the "WebMask API" and "WebMask UI" terminal windows to stop.
echo.
pause
exit /b 0

:fail
echo [ERROR] Servers did not start in time. Check %RUN_DIR%\*.log
pause
exit /b 1
