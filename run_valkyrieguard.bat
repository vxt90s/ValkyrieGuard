@echo off
:: Double-click launcher for ValkyrieGuard (Windows). Needs Python 3.9+ with Tk (default installer).
cd /d "%~dp0"
where py >nul 2>&1
if %errorlevel%==0 (
    py -3 main.py
) else (
    python main.py
)
if %errorlevel% neq 0 (
    echo.
    echo ValkyrieGuard could not start. Make sure Python 3 is installed.
    pause
)
