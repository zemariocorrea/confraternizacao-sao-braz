
@echo off
cd /d "%~dp0"

where node >nul 2>&1

if errorlevel 1 (
  echo Node.js nao encontrado.
  echo Instale pelo site https://nodejs.org/
  pause
  exit /b 1
)

node server.js
pause
