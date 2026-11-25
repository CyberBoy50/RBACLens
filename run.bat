@echo off
REM RBACLens - one click to open the menu (Windows)
cd /d "%~dp0"
python run.py scan %*
pause
