@echo off
rem Creates the Python environment (.venv) on the first run and installs the requirements.
rem Called by run_server.bat and run_client.bat - you don't need to run it yourself.
if exist "%~dp0.venv\Scripts\python.exe" exit /b 0

echo First run: setting up the Python environment in .venv (needs internet, about 2-3 minutes)...
where py >nul 2>&1
if %errorlevel%==0 (
    py -3 -m venv "%~dp0.venv"
) else (
    python -m venv "%~dp0.venv"
)
if not exist "%~dp0.venv\Scripts\python.exe" (
    echo.
    echo Python was not found. Install Python 3.11 or newer from https://www.python.org/downloads/
    echo and tick "Add python.exe to PATH" in the installer, then run this again.
    exit /b 1
)
"%~dp0.venv\Scripts\python.exe" -m pip install --upgrade pip --quiet
"%~dp0.venv\Scripts\python.exe" -m pip install -r "%~dp0requirements.txt"
if errorlevel 1 (
    echo.
    echo Installing the requirements failed - check the internet connection and try again.
    rmdir /s /q "%~dp0.venv"
    exit /b 1
)
echo Setup complete.
exit /b 0
