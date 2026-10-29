# Builds Hodometer.exe with MinGW-w64 (WinLibs). Run from any PowerShell:  .\build.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$gcc = (Get-Command gcc -ErrorAction SilentlyContinue).Source
if (-not $gcc) { $gcc = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Recurse -Filter gcc.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName }
if (-not $gcc) { throw 'gcc not found (install WinLibs via winget: BrechtSanders.WinLibs.POSIX.MSVCRT)' }
$bin = Split-Path -Parent $gcc
$windres = Join-Path $bin 'windres.exe'
Push-Location $here
try {
    if (Test-Path $windres) { & $windres app.rc -O coff -o app_res.o; if ($LASTEXITCODE) { throw "windres failed" } } else { Write-Warning 'windres not found: building without manifest (app will self-elevate, classic controls)'; Remove-Item app_res.o -ErrorAction SilentlyContinue }
    $objs = @('main.c'); if (Test-Path app_res.o) { $objs += 'app_res.o' }
    & $gcc -O2 -Wall -Wno-unused-function -o Hodometer.exe $objs -lws2_32 -liphlpapi -ldnsapi -ladvapi32 -lshell32 -luser32 -lgdi32 -lcomctl32 -lole32 '-Wl,--subsystem,windows'
    if ($LASTEXITCODE) { throw "gcc failed ($LASTEXITCODE)" }
    $f = Get-Item Hodometer.exe
    Write-Host "built $($f.FullName) ($([math]::Round($f.Length/1KB)) KB)"
} finally { Pop-Location }
