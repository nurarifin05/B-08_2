#requires -Version 5.1
[CmdletBinding()]param([string]$Root='C:\CTF-Lab-AV02')
$ErrorActionPreference='Stop'
$ep=Join-Path $Root 'Evidence\trigger_evidence.json'
$tp=Join-Path $Root 'Evidence\process_trace.json'
Write-Host '[AV02] Validator lokal (TIDAK memvalidasi event EDR secara otomatis)'
$checks=[ordered]@{'Incident ticket'=(Test-Path "$Root\Case\incident_ticket.txt");'Trigger evidence'=(Test-Path $ep);'Process trace'=(Test-Path $tp)}
try{$r=(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name AV02LabUpdater -ErrorAction Stop).AV02LabUpdater;$checks['HKCU Run key present']=[bool]$r}catch{$checks['HKCU Run key present']=$false}
$checks.GetEnumerator() | ForEach-Object {"{0}: {1}" -f $_.Key,$_.Value}
if($checks.Values -contains $false){Write-Warning 'Artefak belum lengkap.';exit 1}
$e=Get-Content -Raw -LiteralPath $ep | ConvertFrom-Json
$t=Get-Content -Raw -LiteralPath $tp | ConvertFrom-Json
"Case ID: $($e.case_id)";"Child observed by simulator: $($t.child)";"Persistence: $($t.persistence_type)"
Write-Host 'PENDING: Konfirmasikan proses/registry dari SentinelOne atau ESET secara manual.'
Write-Host 'Empat checkpoint dinilai terhadap bukti EDR dan evidence Windows; hasil lokal saja bukan kelulusan CTF.'
