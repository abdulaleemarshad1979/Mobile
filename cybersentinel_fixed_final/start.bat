@echo off
title CyberSentinel v3
echo ============================================
echo  CyberSentinel v3 - Starting...
echo ============================================

REM --- Kill and restart ADB server to re-detect all devices ---
echo [ADB] Restarting ADB server to detect connected devices...
where adb >nul 2>&1
if %errorlevel%==0 (
    adb kill-server
    adb start-server
    adb devices -l
    echo [ADB] ADB server ready.
) else (
    echo [WARN] ADB not found in PATH.
    echo [WARN] Install from: https://developer.android.com/tools/releases/platform-tools
    echo [WARN] Then add platform-tools folder to your PATH environment variable.
    echo [WARN] CyberSentinel will still start but device scanning requires ADB.
)

echo.
echo [PKG] Installing Python dependencies...
pip install -r requirements.txt --quiet

echo.
echo [SRV] Starting CyberSentinel backend on http://localhost:8000
echo [SRV] Open your browser to: http://localhost:8000
echo.
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
pause
