@echo off
REM Starts the Flask API on http://127.0.0.1:5000  (run setup steps in README first)
cd /d "%~dp0backend"
if exist .venv\Scripts\activate.bat call .venv\Scripts\activate.bat
python app.py
