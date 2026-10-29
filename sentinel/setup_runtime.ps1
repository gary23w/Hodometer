<#
.SYNOPSIS
  Creates sentinel\runtime: a private copy of a standalone CPython with the Anthropic SDK, used only by the daemon.

  Hodometer trusts a client by executable path and SHA-256. A venv's python.exe is only a launcher (the socket would
  belong to the shared base interpreter), so the daemon needs a real python.exe of its own. This script copies one:

    -Source <dir>   a standalone CPython folder (python.exe + python3xx.dll + Lib), e.g. a python-build-standalone
                    or uv-managed install, or the unzipped python.org "embeddable package"
    (no -Source)    looks for a uv-managed CPython under %APPDATA%\uv\python and copies the newest 3.x

  Then it installs requirements.txt into the copy and registers the sentinel folder on its sys.path.

.EXAMPLE
  .\setup_runtime.ps1
  .\setup_runtime.ps1 -Source C:\tools\python-3.13.9-embed-amd64
#>
param(
    [string]$Source = "",
    [switch]$Force
)
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$rt = Join-Path $here "runtime"

if ((Test-Path (Join-Path $rt "python.exe")) -and -not $Force) {
    Write-Host "runtime already exists at $rt (use -Force to rebuild)"
} else {
    if (-not $Source) {
        $uv = Join-Path $env:APPDATA "uv\python"
        if (Test-Path $uv) {
            $cand = Get-ChildItem $uv -Directory -Filter "cpython-3.1*-windows-x86_64-none" | Sort-Object Name -Descending | Select-Object -First 1
            if ($cand) { $Source = $cand.FullName }
        }
    }
    if (-not $Source -or -not (Test-Path (Join-Path $Source "python.exe"))) {
        Write-Host "No standalone Python found. Either install one with 'uv python install 3.13' and rerun, or download the"
        Write-Host "Windows embeddable package (python-3.13.x-embed-amd64.zip) from https://www.python.org/downloads/windows/,"
        Write-Host "unzip it, and run: .\setup_runtime.ps1 -Source <that folder>"
        exit 1
    }
    Write-Host "copying $Source -> $rt"
    if (Test-Path $rt) { Remove-Item -Recurse -Force $rt }
    New-Item -ItemType Directory -Force $rt | Out-Null
    robocopy $Source $rt /E /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -gt 7) { throw "robocopy failed with $LASTEXITCODE" }
    # the copy is ours now, not uv's
    Remove-Item -Force (Join-Path $rt "Lib\EXTERNALLY-MANAGED") -ErrorAction SilentlyContinue
}

$py = Join-Path $rt "python.exe"

# embeddable package: its ._pth file must let site-packages and our .pth file load
Get-ChildItem $rt -Filter "python3*._pth" | ForEach-Object {
    $lines = Get-Content $_.FullName
    $changed = $false
    if ($lines -notcontains "Lib\site-packages") { $lines += "Lib\site-packages"; $changed = $true }
    $lines = $lines | ForEach-Object { if ($_ -eq "#import site") { $changed = $true; "import site" } else { $_ } }
    if ($changed) { Set-Content -Encoding ascii $_.FullName $lines }
}

$site = Join-Path $rt "Lib\site-packages"
New-Item -ItemType Directory -Force $site | Out-Null

& $py -I -m pip --version *> $null
if ($LASTEXITCODE -ne 0) {
    & $py -I -m ensurepip --upgrade *> $null
}
& $py -I -m pip --version *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "This Python has no pip (the embeddable package ships without it). Download https://bootstrap.pypa.io/get-pip.py"
    Write-Host "and run:  $py -I get-pip.py   then rerun this script."
    exit 1
}
& $py -I -m pip install --disable-pip-version-check --no-warn-script-location -r (Join-Path $here "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

# make 'python -I -m sentineld' find the package without touching PYTHONPATH (-I ignores it)
Set-Content -Encoding ascii (Join-Path $site "sentineld.pth") $here

& $py -I -c "import sys, anthropic, sentineld; print('runtime ok:', sys.version.split()[0], 'anthropic', anthropic.__version__, 'sentineld', sentineld.__version__)"
if ($LASTEXITCODE -ne 0) { throw "runtime check failed" }
Write-Host "Done. Start the daemon with .\sentinel.cmd (dry-run by default)."
