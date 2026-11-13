@echo off
rem Installs KeySeal for this user: copies it to %LOCALAPPDATA%\keyseal and
rem registers keyseal:// links under HKCU. No administrator rights needed.
rem With /quiet it doesn't wait for a key, for scripted installs.
"%~dp0keyseal.exe" install
set status=%errorlevel%
if /i not "%~1"=="/quiet" pause
exit /b %status%
