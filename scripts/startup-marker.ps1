# AV02 benign startup marker: no network calls, downloads, or additional processes.
$root='C:\CTF-Lab-AV02\Logs'
if(Test-Path -LiteralPath 'C:\CTF-Lab-AV02'){
 [void](New-Item -ItemType Directory -Path $root -Force)
 Add-Content -LiteralPath (Join-Path $root 'startup_marker.log') -Value "$(Get-Date -Format o) AV02 harmless startup marker executed." -Encoding UTF8
}
