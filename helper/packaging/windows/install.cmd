@echo off
rem Installs KeySeal for this user: copies it to %LOCALAPPDATA%\keyseal and
rem registers keyseal:// links under HKCU. No administrator rights needed.
"%~dp0keyseal.exe" install
pause
