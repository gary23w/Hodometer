#Requires -RunAsAdministrator
# Installs Hodometer: logon task (elevated, no UAC prompt), Desktop shortcut, and retires the script-based
# network watcher it replaces. Run once from an elevated PowerShell, or let the app's installer launch it.
$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $here 'Hodometer.exe'
$log = Join-Path $here 'install.log'
function Note([string]$m) { "$(Get-Date -Format s) $m" | Out-File $log -Append -Encoding utf8; Write-Host $m }
Note "=== install start: $exe"

Note '--- retire the script-based network watcher (replaced by this app)'
foreach ($t in 'Claude - network spike recorder') {
    $task = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    if ($task) { Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue; Disable-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue | Out-Null; Note "  task '$t' stopped and disabled" }
}
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*netspikes.ps1*' -or $_.CommandLine -like '*spike_capture.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; Note "  stopped script process $($_.ProcessId)" }
& logman stop spikecap -ets 2>&1 | Out-Null; Note '  rolling ETW trace session "spikecap" stopped'
Remove-Item "$env:USERPROFILE\.onedrive-watchdog\rolling.etl", "$env:USERPROFILE\.onedrive-watchdog\capture.lock" -Force -ErrorAction SilentlyContinue

Note '--- logon task "Hodometer" (highest privileges, this user, starts hidden in the tray)'
Get-Process Hodometer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute $exe -WorkingDirectory $here
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'Hodometer' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Hodometer tray network monitor (per-process bytes, audit keeper, AI socket 127.0.0.1:48201). Remove: Unregister-ScheduledTask -TaskName Hodometer' -Force | Out-Null
Note "  registered: $((Get-ScheduledTask -TaskName 'Hodometer').State)"

Note '--- Desktop shortcut (launches the elevated task, so no UAC prompt)'
try {
    $ws = New-Object -ComObject WScript.Shell
    $lnkPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Hodometer.lnk'
    $lnk = $ws.CreateShortcut($lnkPath)
    $lnk.TargetPath = "$env:SystemRoot\System32\schtasks.exe"; $lnk.Arguments = '/run /tn Hodometer'; $lnk.WorkingDirectory = $here
    $lnk.IconLocation = "$env:SystemRoot\System32\shell32.dll,13"; $lnk.Description = 'Start Hodometer (tray network monitor)'; $lnk.WindowStyle = 7
    $lnk.Save(); Note "  shortcut: $lnkPath"
} catch { Note "  shortcut failed: $($_.Exception.Message)" }

Note '--- start it'
Start-ScheduledTask -TaskName 'Hodometer'
Start-Sleep -Seconds 4
$p = Get-Process Hodometer -ErrorAction SilentlyContinue
Note "  running: $(if ($p) { "pid $($p.Id)" } else { 'NO' })"
Note "  socket listening: $((Get-NetTCPConnection -LocalPort 48201 -State Listen -ErrorAction SilentlyContinue) -ne $null)"
Note 'DONE'
Start-Sleep -Seconds 2
