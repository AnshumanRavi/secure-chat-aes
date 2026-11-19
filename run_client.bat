@echo off
rem SecureChat APP - double-click to start. Start it twice to chat as two users on one PC.
rem Options are passed on, e.g.   run_client.bat --host 192.168.1.20   (pre-fills the server address)
rem If the window doesn't appear, run   run_client.bat --console   to see the error messages.
setlocal
cd /d "%~dp0"
call "%~dp0setup_env.bat" || goto :failed
call "%~dp0.venv\Scripts\activate.bat"

if /i "%~1"=="--console" (
    rem %2 onwards = the options after --console
    python -m client.gui.main %2 %3 %4 %5 %6 %7 %8 %9
    pause
    exit /b 0
)
rem pythonw = no black console window behind the app
start "SecureChat" pythonw -m client.gui.main %*
exit /b 0

:failed
pause
exit /b 1
