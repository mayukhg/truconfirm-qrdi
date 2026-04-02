@echo off
title TruConfirm QRDI — Startup
color 0A

echo.
echo  ===============================================
echo   TruConfirm QRDI — Starting Services
echo  ===============================================
echo.

REM ── Check Node.js ──────────────────────────────
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Node.js not found. Install from https://nodejs.org
    pause
    exit /b 1
)

REM ── Check Python ───────────────────────────────
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Python not found. Install from https://python.org
    pause
    exit /b 1
)

REM ── Install backend dependencies if needed ─────
if not exist "%~dp0backend\node_modules" (
    echo  [INFO] Installing backend dependencies...
    cd /d "%~dp0backend"
    call npm install --silent
    cd /d "%~dp0"
    echo  [OK] Dependencies installed
)

REM ── Start backend on port 3001 ──────────────────
echo  [1/2] Starting backend server on port 3001...
start "TruConfirm QRDI Backend" /min cmd /c "cd /d "%~dp0backend" && node server.js"
timeout /t 2 /nobreak >nul

REM ── Start frontend on port 8080 ─────────────────
echo  [2/2] Starting frontend server on port 8080...
start "TruConfirm QRDI Frontend" /min cmd /c "cd /d "%~dp0" && python -m http.server 8080"
timeout /t 2 /nobreak >nul

REM ── Open browser ────────────────────────────────
echo.
echo  ===============================================
echo   Both servers are running!
echo.
echo   App     →  http://localhost:8080
echo   API     →  http://localhost:3001/api
echo.
echo   Close this window or run stop.bat to stop.
echo  ===============================================
echo.

start "" "http://localhost:8080"

REM Keep window open so user can see status
pause
