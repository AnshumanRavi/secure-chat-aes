@echo off
rem SecureChat SERVER - double-click to start (on the PC that hosts the chat).
rem Options are passed on, e.g.   run_server.bat --port 6000   or   run_server.bat --quiet
setlocal
cd /d "%~dp0"
title SecureChat Server
call "%~dp0setup_env.bat" || goto :failed
call "%~dp0.venv\Scripts\activate.bat"

python -m server.server %*
echo.
echo The server has stopped.
pause
exit /b 0

:failed
pause
exit /b 1
