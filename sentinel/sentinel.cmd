@echo off
rem Runs the sentinel daemon from its private Python copy (sentinel\runtime), never the shared python.exe.
rem Hodometer trusts a client by executable path and SHA-256, so this is the program the user allows.
if not exist "%~dp0runtime\python.exe" (
    echo sentinel\runtime\python.exe is missing. Run setup_runtime.ps1 first.
    exit /b 1
)
"%~dp0runtime\python.exe" -I -X utf8 -m sentineld %*
