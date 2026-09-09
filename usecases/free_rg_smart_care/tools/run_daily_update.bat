@echo off
REM Free RGs Smart Care — Daily Update Runner
REM Schedule via Windows Task Scheduler to run every morning.

cd /d "%~dp0.."
call .venv\Scripts\activate.bat
python tools\daily_update.py %*
deactivate
