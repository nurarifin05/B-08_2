#!/bin/bash
# ==============================================================================
# Script Generator Lab CTF: VM 2 - Persistence & Account Anomaly (Ubuntu 24.04)
# EDR Target: SentinelOne Telemetry
# ==============================================================================

set -e

echo "[*] Menginisialisasi direktori laboratorium dan bukti forensik..."
mkdir -p /srv/lab/evidence
mkdir -p /etc/cron.d
mkdir -p /etc/systemd/system
mkdir -p /var/log/sentinelone

# 1. Membuat Baseline dan Bukti File /etc/passwd
cat << 'EOF' > /srv/lab/evidence/passwd.baseline
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/spool/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
syslog:x:104:108::/home/syslog:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
soc_admin:x:1001:1001:SOC Admin:/home/soc_admin:/bin/bash
EOF

cat << 'EOF' > /srv/lab/evidence/passwd.simulated
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/spool/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
syslog:x:104:108::/home/syslog:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
soc_admin:x:1001:1001:SOC Admin:/home/soc_admin:/bin/bash
sysadmin_backdoor:x:1002:1002:System Maintenance Account:/home/sysadmin_backdoor:/bin/bash
EOF

# 2. Membuat Simulasi Log Otentikasi (/var/log/auth.log)
cat << 'EOF' > /var/log/auth.log
Oct  9 14:00:10 web-app-train-01 sshd[1020]: Server listening on 0.0.0.0 port 22.
Oct  9 14:05:22 web-app-train-01 sudo: soc_admin : TTY=pts/0 ; PWD=/home/soc_admin ; USER=root ; COMMAND=/usr/bin/apt update
Oct  9 15:10:00 web-app-train-01 useradd[2104]: new user: name=sysadmin_backdoor, UID=1002, GID=1002, home=/home/sysadmin_backdoor, shell=/bin/bash
Oct  9 15:10:05 web-app-train-01 usermod[2110]: add 'sysadmin_backdoor' to group 'sudo'
Oct  9 15:10:12 web-app-train-01 chpasswd[2115]: password changed for 'sysadmin_backdoor'
Oct  9 15:12:30 web-app-train-01 sudo: sysadmin_backdoor : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/tee /etc/cron.d/lab-maintenance
Oct  9 15:14:22 web-app-train-01 sudo: sysadmin_backdoor : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/cp /tmp/lab-update.service /etc/systemd/system/lab-update.service
Oct  9 15:14:25 web-app-train-01 systemd[1]: Reloading System Manager Configuration...
EOF

# 3. Membuat Persistence Unit Service (Inert / Tidak Aktif Berbahaya)
cat << 'EOF' > /etc/systemd/system/lab-update.service
[Unit]
Description=Simulated System Update Persistence Service
After=network.target

[Service]
Type=simple
User=sysadmin_backdoor
ExecStart=/usr/local/bin/update-agent.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 4. Membuat Persistence Cron Job (Inert)
cat << 'EOF' > /etc/cron.d/lab-maintenance
# Simulated Scheduled Maintenance Task
*/15 * * * * root /usr/local/bin/check-health.sh >/dev/null 2>&1
EOF

# 5. Membuat Telemetri SentinelOne (/var/log/sentinelone/telemetry.json)
cat << 'EOF' > /var/log/sentinelone/telemetry.json
[
  {
    "agent_id": "S1-LNX-88291",
    "timestamp": "2026-10-09T15:10:00Z",
    "event_type": "USER_CREATION",
    "threat_class": "Persistence / Account Manipulation",
    "process_name": "useradd",
    "pid": 2104,
    "user_affected": "sysadmin_backdoor",
    "initiated_by_user": "root",
    "cmdline": "useradd -m -s /bin/bash sysadmin_backdoor",
    "indicator": "Unscheduled Local Account Creation"
  },
  {
    "agent_id": "S1-LNX-88291",
    "timestamp": "2026-10-09T15:12:30Z",
    "event_type": "FILE_CREATION",
    "threat_class": "Persistence / Scheduled Task",
    "process_name": "tee",
    "pid": 2120,
    "file_path": "/etc/cron.d/lab-maintenance",
    "initiated_by_user": "sysadmin_backdoor",
    "indicator": "Cron Job Creation in System Directory"
  },
  {
    "agent_id": "S1-LNX-88291",
    "timestamp": "2026-10-09T15:14:22Z",
    "event_type": "FILE_CREATION",
    "threat_class": "Persistence / Systemd Service Modification",
    "process_name": "cp",
    "pid": 2135,
    "file_path": "/etc/systemd/system/lab-update.service",
    "initiated_by_user": "sysadmin_backdoor",
    "indicator": "New Systemd Service Unit Installed"
  }
]
EOF

# 6. Membuat Timeline CSV
cat << 'EOF' > /srv/lab/evidence/timeline.csv
Timestamp_UTC,Source_Log,Event_Type,Details,User
2026-10-09 15:10:00,/var/log/auth.log,Account Creation,Created user sysadmin_backdoor (UID 1002),root
2026-10-09 15:10:05,/var/log/auth.log,Group Modification,Added sysadmin_backdoor to group sudo,root
2026-10-09 15:12:30,SentinelOne Telemetry,Cron Modification,Created /etc/cron.d/lab-maintenance,sysadmin_backdoor
2026-10-09 15:14:22,SentinelOne Telemetry,Service Modification,Created /etc/systemd/system/lab-update.service,sysadmin_backdoor
2026-10-09 15:14:25,/var/log/auth.log,Systemd Event,Systemd daemon-reload executed,root
EOF

# 7. Membuat Catatan Forensik Instruktur
cat << 'EOF' > /srv/lab/evidence/forensic_notes.txt
===============================================================================
FORENSIC INVESTIGATION NOTES - CASE #UBU02-PERSISTENCE
===============================================================================
Instruksi Analis:
Lakukan verifikasi silang antara berkas konfigurasi systemd, cron job, dan log 
otentikasi untuk mengonfirmasi teknik persistence yang diterapkan.

Setelah memvalidasi path berkas systemd (/etc/systemd/system/lab-update.service) 
serta nama akun anomali (sysadmin_backdoor), gunakan string kunci gabungan tersebut 
untuk mengonfirmasi keabsahan temuan.

TOKEN CTF: FLAG{UBU02_SENTINELONE_PERSISTENCE_89412X}
===============================================================================
EOF

# Atur Izin Akses Artefak
chmod 644 /var/log/auth.log
chmod 644 /etc/systemd/system/lab-update.service
chmod 644 /etc/cron.d/lab-maintenance
chmod 644 /var/log/sentinelone/telemetry.json
chmod -R 644 /srv/lab/evidence/*

echo "[+] Setup Lab Skenario 2 Berhasil!"
