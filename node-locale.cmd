@echo off
set "ROOT=%~dp0"
set "PATH=%ROOT%.node\node-v24.15.0-win-x64;%PATH%"
cd /d "%ROOT%"

echo Node locale attivo:
node -v
npm -v

cmd /k