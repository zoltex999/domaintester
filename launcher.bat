@echo off
:loop
cls
python main.py
if errorlevel 10 goto loop
pause