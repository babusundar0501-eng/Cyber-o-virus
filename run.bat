@echo off
setlocal
cd /d "%~dp0"
title NO.0 AntiVirus
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 main.py
) else (
    where python >nul 2>nul
    if %errorlevel%==0 (
        python main.py
    ) else (
        echo Python was not found.
        echo Install Python 3.10 or newer from https://www.python.org/downloads/windows/
        echo During setup, check "Add Python to PATH".
        pause
        exit /b 1
    )
)
if errorlevel 1 (
    echo.
    echo NO.0 stopped with an error. Read the message above.
    pause
)
endlocal
