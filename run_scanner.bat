@echo off
cd /d "%~dp0"
python scanner.py --target 127.0.0.1 --start 1 --end 1024
pause
