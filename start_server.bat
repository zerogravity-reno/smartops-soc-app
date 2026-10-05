@echo off
rem Secrets and endpoints come from .env (git-ignored), which webapp/main.py loads at startup.
echo Starting SmartOps SOC Server...
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PYTHONPATH=%~dp0;%~dp0engine\src;%~dp0engine\contracts\src
echo Server running at http://localhost:8001
python -m uvicorn webapp.main:app --host 0.0.0.0 --port 8001 --timeout-keep-alive 600
pause
