@echo off
rem Let the other PC reach the SecureChat server through Windows Firewall.
rem Run ONCE on the SERVER PC: right-click -> "Run as administrator".
rem   allow_firewall.bat          add the rules: TCP 5555 (chat), UDP 5555 ("Find server on LAN") and
rem                               TCP 5600-5602 (performance\benchmark_network.py --serve)
rem   allow_firewall.bat remove   delete them again (e.g. after the demo)
net session >nul 2>&1
if errorlevel 1 (
    echo This needs administrator rights: right-click allow_firewall.bat and choose "Run as administrator".
    pause
    exit /b 1
)

if /i "%~1"=="remove" (
    netsh advfirewall firewall delete rule name="SecureChat server (TCP 5555)"
    netsh advfirewall firewall delete rule name="SecureChat discovery (UDP 5555)"
    netsh advfirewall firewall delete rule name="SecureChat benchmark (TCP 5600-5602)"
    echo SecureChat firewall rules removed.
    pause
    exit /b 0
)

netsh advfirewall firewall delete rule name="SecureChat server (TCP 5555)" >nul 2>&1
netsh advfirewall firewall delete rule name="SecureChat discovery (UDP 5555)" >nul 2>&1
netsh advfirewall firewall delete rule name="SecureChat benchmark (TCP 5600-5602)" >nul 2>&1
netsh advfirewall firewall add rule name="SecureChat server (TCP 5555)" dir=in action=allow protocol=TCP localport=5555 profile=any
netsh advfirewall firewall add rule name="SecureChat discovery (UDP 5555)" dir=in action=allow protocol=UDP localport=5555 profile=any
netsh advfirewall firewall add rule name="SecureChat benchmark (TCP 5600-5602)" dir=in action=allow protocol=TCP localport=5600-5602 profile=any
echo.
echo Done: other PCs can now reach SecureChat (and the network benchmark) on this PC.
echo Remove the rules later with:  allow_firewall.bat remove   (as administrator)
pause
exit /b 0
