#!/bin/bash
echo "Starting CyberSentinel v3..."

# Detect WSL — if inside WSL, use Windows python to access host USB devices
if grep -qi microsoft /proc/version 2>/dev/null; then
    echo "[WSL] Detected Windows Subsystem for Linux — launching via Windows Python for USB access"
    # Use cmd.exe to run the Windows start.bat which uses native Windows Python + ADB
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    # Convert WSL path to Windows path
    WIN_DIR="$(wslpath -w "$SCRIPT_DIR" 2>/dev/null || echo "$SCRIPT_DIR")"
    cmd.exe /c "cd /d $WIN_DIR && start.bat"
else
    echo "[LINUX] Running natively on Linux"
    pip install -r requirements.txt --break-system-packages -q 2>/dev/null || pip install -r requirements.txt -q
    python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
fi
