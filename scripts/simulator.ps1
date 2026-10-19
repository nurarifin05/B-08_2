#requires -Version 5.1
[CmdletBinding()]param([string]$Root='C:\CTF-Lab-AV02')
$ErrorActionPreference='Stop'
$art=Join-Path $Root 'Artifacts';$ev=Join-Path $Root 'Evidence';$log=Join-Path $Root 'Logs'
[void](New-Item -Path $log -ItemType Directory -Force)
$trace=[ordered]@{timestamp_utc=(Get-Date).ToUniversalTime().ToString('o');simulator_pid=$PID;parent_label='powershell.exe (setup.ps1 launches simulator.ps1)';child='cmd.exe';grandchild='whoami.exe';persistence_type='HKCU Registry Run Key';persistence_name='AV02LabUpdater';persistence_path='HKCU\Software\Microsoft\Windows\CurrentVersion\Run';note='EDR process lineage may also include PowerShell launchers.'}
$child=Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/d','/c','whoami.exe' -PassThru -Wait -WindowStyle Hidden
$trace.child_pid=$child.Id;$trace.child_exit_code=$child.ExitCode
# Lab-only, non-privileged HKCU Run value. Target script only appends a harmless marker if a future interactive sign-in occurs.
$rk='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
[void](New-Item -Path $rk -Force)
$script=Join-Path $art 'startup-marker.ps1'
$value='"'+"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"+'" -NoProfile -File "'+$script+'"'
New-ItemProperty -Path $rk -Name 'AV02LabUpdater' -PropertyType String -Value $value -Force | Out-Null
$trace.actual_run_value=$value
$trace | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $ev 'process_trace.json') -Encoding UTF8
Add-Content -LiteralPath (Join-Path $log 'simulator_activity.log') -Value "$(Get-Date -Format o) simulator launched cmd.exe -> whoami.exe; HKCU Run value created" -Encoding UTF8
