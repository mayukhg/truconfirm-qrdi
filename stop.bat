@echo off
title TruConfirm QRDI — Shutdown
color 0C

echo.
echo  ===============================================
echo   TruConfirm QRDI — Stopping Services
echo  ===============================================
echo.

REM ── Kill backend (node server.js on port 3001) ──
echo  [1/2] Stopping backend server (port 3001)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":3001 " ^| findstr "LISTENING"') do (
    taskkill /PID %%a /F >nul 2>&1
)

REM Also close the named terminal window
taskkill /FI "WINDOWTITLE eq TruConfirm QRDI Backend" /F >nul 2>&1
echo  [OK] Backend stopped

REM ── Kill frontend (serve.py on port 8888) ──────────
echo  [2/2] Stopping frontend server (port 8888)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8888 " ^| findstr "LISTENING"') do (
    taskkill /PID %%a /F >nul 2>&1
)

taskkill /FI "WINDOWTITLE eq TruConfirm QRDI Frontend" /F >nul 2>&1
echo  [OK] Frontend stopped

echo.
echo  ===============================================
echo   All services stopped.
echo  ===============================================
echo.
timeout /t 2 /nobreak >nul
