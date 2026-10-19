# AV-02 — Suspicious Process Execution (Windows 11, EDR-centric)

**Lingkungan:** Windows 11 Desktop (disarankan snapshot VM), SentinelOne selama development, ESET setelah pengadaan. Tidak ada installer EDR dalam paket; gunakan paket resmi dan konsol manajemen vendor.

## Persiapan dan keselamatan
- Lab terisolasi, akun administrator untuk setup, akun konsol EDR dengan hak read-only untuk investigasi.
- Simulator **benign**: `powershell.exe` menjalankan `simulator.ps1`, simulator memanggil `cmd.exe /c whoami.exe`, lalu membuat `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\AV02LabUpdater`. Target Run Key hanya menulis satu baris marker lokal saat login; tidak mengunduh atau mengirim data.
- Windows 11 EDR harus menerima telemetri *process creation + command line* dan *registry modifications*. Produk/policy tertentu mungkin tidak menampilkan semuanya; jangan mengarang alert.
- Run Key dibuat pada HKCU **akun yang menjalankan Trigger** (jika elevasi memakai akun administrator lain, HKCU mengarah ke akun tersebut). Jangan memakai VM produksi.
- Jangan memberi peserta file instruktur yang memuat jawaban final sebelum ujian.

## 1. Deploy baseline
Ekstrak ZIP, lalu buka **Windows PowerShell 5.1 as Administrator** di folder `AV02_CTF_Windows11`:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\setup.ps1 -Action Install -EDRVendor SentinelOne
.\setup.ps1 -Action Status -EDRVendor SentinelOne
```

## 2. Pasang dan verifikasi agent EDR
Instal SentinelOne secara terpisah dengan installer resmi dari tenant Anda. Di masa mendatang gunakan agent/produk proteksi ESET beserta ESET PROTECT. Pastikan endpoint online, policy aktif, dan kemampuan melihat proses, command-line, registry events di console. Jalankan preflight lokal:

```powershell
.\setup.ps1 -Action Preflight -EDRVendor SentinelOne
```

## 3. Trigger sekali
```powershell
.\setup.ps1 -Action Trigger -EDRVendor SentinelOne
```

Kumpulkan bukti dari konsol EDR: process tree (PowerShell → cmd.exe → whoami.exe), command line, registry Run Key, waktu/identitas host. Ini bukan malware dan tidak selalu menghasilkan alert malware; gunakan telemetry/activity hunting sesuai lisensi dan policy.

## 4. Periksa artefak Windows
```powershell
Get-Content C:\CTF-Lab-AV02\Case\incident_ticket.txt
Get-Content C:\CTF-Lab-AV02\Evidence\trigger_evidence.json
Get-Content C:\CTF-Lab-AV02\Evidence\process_trace.json
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name AV02LabUpdater
Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='AV02-CTF-Lab'} -MaxEvents 10
.\verify_av02.ps1
```

Jika audit process creation Windows sudah diaktifkan oleh kebijakan organisasi, Event ID 4688 di Security dapat membantu, tetapi tidak diaktifkan otomatis oleh installer. Sysmon opsional apabila telah diinstal dan disetujui. Telemetry event ID 1 (process creation) dan 13 (registry value set) bergantung pada konfigurasi Sysmon; tidak dijanjikan tersedia.

## 5. Reset untuk peserta berikutnya
```powershell
.\setup.ps1 -Action Reset -EDRVendor SentinelOne
```

Reset menghapus **hanya** Run Key lab dan berkas trigger lokal; tidak menghapus log Event Viewer atau histori konsol EDR. Untuk pengulangan sesi ujian yang bersih, gunakan snapshot VM dan waktu/Case ID baru.

## 6. Validasi kompetensi
Empat checkpoint utama (20/25/25/30 poin): proses launcher, child process, persistence mechanism, dan lokasi persistence. Pembobotan 15 tugas pada Word adalah rubrik praktikum terpisah. Pemeriksaan EDR selalu mensyaratkan evidence aktual. Tidak ada 'auto-flag' karena telemetry vendor tidak disediakan melalui API di lab ini.

## Troubleshooting
- **Run Key tidak terlihat:** cek akun/hive HKCU yang dipakai ketika menjalankan Trigger; `whoami` dan `Get-ItemProperty` harus memakai akun tersebut.
- **Tidak ada event EDR:** pastikan agent online, periksa filter waktu, lisensi telemetry dan policy. Jangan menyimpulkan instalasi gagal hanya karena tidak ada alert signature.
- **Process tree sudah hilang dari Task Manager:** perilaku normal karena proses singkat; cari riwayat EDR/Sysmon/4688 atau gunakan `process_trace.json` sebagai bukti pelengkap, bukan pengganti EDR.
- **Trigger menolak pengulangan:** gunakan Reset setelah menyimpan screenshot dan evidence, atau restore snapshot.
