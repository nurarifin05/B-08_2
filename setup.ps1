#requires -Version 5.1
<# AV-02 – Windows 11 benign suspicious-process simulation.
Actions: Install, Status, Preflight, Trigger, Reset.
EDRVendor is metadata only; never installs or alters EDR software.
#>
[CmdletBinding()]
param(
 [ValidateSet('Install','Status','Preflight','Trigger','Reset')][string]$Action='Status',
 [ValidateSet('SentinelOne','ESET','Generic')][string]$EDRVendor='SentinelOne',
 [string]$Root='C:\CTF-Lab-AV02'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Case=Join-Path $Root 'Case'; $Artifacts=Join-Path $Root 'Artifacts'
$Evidence=Join-Path $Root 'Evidence'; $Logs=Join-Path $Root 'Logs'
$Source=Join-Path $PSScriptRoot 'scripts'
$RunPath='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$RunName='AV02LabUpdater'
$EventLogName='Application'; $EventSource='AV02-CTF-Lab'
$ExpectedPath=Join-Path $Artifacts 'startup-marker.ps1'
function Say([string]$s){Write-Host "[AV02] $s"}
function NeedAdmin { $id=[Security.Principal.WindowsIdentity]::GetCurrent();$p=New-Object Security.Principal.WindowsPrincipal($id);if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Jalankan Windows PowerShell as Administrator.'} }
function PutJson($Object,[string]$Path){$Object | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8}
function InitFolders {foreach($p in @($Root,$Case,$Artifacts,$Evidence,$Logs)){[void](New-Item -Path $p -ItemType Directory -Force)}}
function CheckOS { $os=Get-CimInstance Win32_OperatingSystem; Say "OS: $($os.Caption), build $($os.BuildNumber)"; if([int]$os.BuildNumber -lt 22000){Write-Warning 'Disarankan Windows 11; OS sekarang bukan Windows 11.'}}
function InitEventSource { if(-not [System.Diagnostics.EventLog]::SourceExists($EventSource)){New-EventLog -LogName $EventLogName -Source $EventSource} }
function Event([string]$Text,[int]$Id=4100){try {Write-EventLog -LogName $EventLogName -Source $EventSource -EntryType Information -EventId $Id -Message $Text} catch {Write-Warning "Tidak dapat menulis Event Log: $($_.Exception.Message)"}}
function ExistingRun {try {$k=Get-ItemProperty -LiteralPath $RunPath -Name $RunName -ErrorAction Stop;return [string]$k.$RunName}catch{return $null}}
function CheckCollision { $cur=ExistingRun; if($null -ne $cur -and $cur -notlike '*CTF-Lab-AV02*' -and $cur -notlike "*$Root*"){throw "HKCU Run value '$RunName' sudah dipakai aplikasi lain. Tidak akan ditimpa: $cur"}}
function InstallLab {
 NeedAdmin;CheckOS;InitFolders;CheckCollision
 foreach($f in @('simulator.ps1','startup-marker.ps1')){ $s=Join-Path $Source $f; if(-not(Test-Path -LiteralPath $s)){throw "Dependensi tidak ditemukan: $s"};Copy-Item -LiteralPath $s -Destination (Join-Path $Artifacts $f) -Force }
 $ticket=@"
INCIDENT AV02-WKS11-2026
Kategori: Suspicious Process Execution
Workstation: $env:COMPUTERNAME
Cerita: Aplikasi simulasi benign dijalankan dari lokasi artefak lab. SOC diminta menyelidiki parent-child process, command line, dan registry startup Run Key menggunakan konsol EDR. Trigger belum dilakukan saat instalasi.
Peringatan: Jangan menyimpulkan 'malware' dari nama proses; seluruh konten latihan benign.
"@
 Set-Content -LiteralPath (Join-Path $Case 'incident_ticket.txt') -Value $ticket -Encoding UTF8
 PutJson ([ordered]@{case_id='AV02-WKS11-2026';host=$env:COMPUTERNAME;vendor=$EDRVendor;installed_utc=(Get-Date).ToUniversalTime().ToString('o');trigger='not-started';edr_verification='not-performed'}) (Join-Path $Evidence 'case_manifest.json')
 InitEventSource;Event 'AV02 baseline installed; no suspicious process has been launched.' 4100
 Say "Baseline siap: $Root";Say 'JANGAN jalankan Trigger sampai EDR online/policy siap dan snapshot VM tersedia.'
}
function Status {
 CheckOS; Say "Root: $Root (exists=$(Test-Path -LiteralPath $Root))"
 $r=ExistingRun;Say "HKCU Run ${RunName}: $(if($r){$r}else{'NOT PRESENT'})"
 foreach($p in @('Case\incident_ticket.txt','Evidence\case_manifest.json','Evidence\trigger_evidence.json','Artifacts\simulator.ps1','Artifacts\startup-marker.ps1')) {Say "${p}: $(Test-Path -LiteralPath (Join-Path $Root $p))"}
 Say "Current user: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
 if(Test-Path -LiteralPath (Join-Path $Evidence 'trigger_evidence.json')) {Get-Content -LiteralPath (Join-Path $Evidence 'trigger_evidence.json') | Write-Host}
}
function Preflight {
 CheckOS;Say "User/HKCU: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)";Say "EDR target: $EDRVendor"
 Get-Service | Where-Object { $_.DisplayName -match 'Sentinel|ESET' -or $_.Name -match 'Sentinel|ESET' } | Select-Object Name,DisplayName,Status | Format-Table -AutoSize
 Say 'Output service BUKAN bukti agent online. Periksa endpoint, policy, dan izin telemetry di konsol EDR.'
 Say 'Perlu event Process Creation + Command Line + Registry modification. Jika produk tidak merekam Run Key, gunakan evidence Windows dan catat keterbatasannya.'
}
function Trigger {
 NeedAdmin; if(-not(Test-Path -LiteralPath (Join-Path $Artifacts 'simulator.ps1'))){throw 'Jalankan -Action Install terlebih dahulu.'}; CheckCollision
 if(Test-Path -LiteralPath (Join-Path $Evidence 'trigger_evidence.json')) {throw 'Trigger sudah dilakukan. Simpan evidence, lalu gunakan -Action Reset sebelum pengulangan.'}
 $time=(Get-Date).ToUniversalTime().ToString('o');$id='AV02-WKS11-2026'
 # Metadata dibuat sebelum aktivitas proses agar jejak tidak hanya bergantung pada ketersediaan EDR.
 PutJson ([ordered]@{case_id=$id;host=$env:COMPUTERNAME;actor_user=[Security.Principal.WindowsIdentity]::GetCurrent().Name;trigger_started_utc=$time;simulation='benign';edr_vendor=$EDRVendor;edr_action='UNVERIFIED';expected_activity=@('powershell.exe runs simulator.ps1','simulator.ps1 spawns cmd.exe','cmd.exe runs whoami.exe','HKCU Run key AV02LabUpdater');actual_completion='pending'}) (Join-Path $Evidence 'trigger_evidence.json')
 Event "AV02 trigger initiated case=$id at=$time" 4101
 $exe="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
 $script=Join-Path $Artifacts 'simulator.ps1'
 $proc=Start-Process -FilePath $exe -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$script+'"'),'-Root',('"'+$Root+'"')) -Wait -PassThru -WindowStyle Hidden
 $reg=ExistingRun
 $out=[ordered]@{case_id=$id;host=$env:COMPUTERNAME;trigger_started_utc=$time;trigger_finished_utc=(Get-Date).ToUniversalTime().ToString('o');launcher_process_id=$proc.Id;launcher_exit_code=$proc.ExitCode;run_key_name=$RunName;run_key_value=$reg;edr_detection_status='NOT_ASSESSED';edr_action='NOT_ASSESSED';note='Periksa konsol EDR untuk parent process, child process, command line dan Registry Run modification.'}
 PutJson $out (Join-Path $Evidence 'trigger_evidence.json')
 Event "AV02 trigger completed case=$id launcherPID=$($proc.Id) exitCode=$($proc.ExitCode)" 4102
 if($proc.ExitCode -ne 0 -or -not $reg){throw "Simulator gagal (exit code $($proc.ExitCode)). Periksa $Logs"}
 Say 'Simulasi selesai. Periksa Threat/Activity/Storyline/Process telemetry di konsol EDR (jika didukung).';Say "Evidence: $(Join-Path $Evidence 'trigger_evidence.json')"
}
function Reset {
 NeedAdmin;CheckCollision
 $cur=ExistingRun;if($cur){Remove-ItemProperty -LiteralPath $RunPath -Name $RunName}
 foreach($p in @('trigger_evidence.json','process_trace.json')){ $f=Join-Path $Evidence $p;if(Test-Path -LiteralPath $f){Remove-Item -LiteralPath $f -Force}}
 Say 'Artefak Run Key latihan dan trigger evidence lokal direset. Event Log/EDR histories tidak dihapus.'
 Event 'AV02 simulation reset completed' 4103
}
switch($Action){ 'Install'{InstallLab} 'Status'{Status} 'Preflight'{Preflight} 'Trigger'{Trigger} 'Reset'{Reset}}
