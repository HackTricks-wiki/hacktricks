# Linux-Forensik

{{#include ../../banners/hacktricks-training.md}}

## Erste Informationsbeschaffung

### Grundlegende Informationen

Zunächst wird empfohlen, einen **USB**-Datenträger mit **bekannten, vertrauenswürdigen Binaries und Libraries darauf** bereitzuhalten (du kannst einfach Ubuntu verwenden und die Verzeichnisse _/bin_, _/sbin_, _/lib,_ und _/lib64_ kopieren), anschließend den USB-Datenträger einzubinden und die Umgebungsvariablen so anzupassen, dass diese Binaries verwendet werden:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Sobald du das System für die Verwendung guter und bekannter Binaries konfiguriert hast, kannst du mit dem **Extrahieren einiger grundlegender Informationen** beginnen:
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### Verdächtige Informationen

Beim Abrufen der grundlegenden Informationen solltest du auf ungewöhnliche Dinge achten, zum Beispiel:

- **Root-Prozesse** laufen normalerweise mit niedrigen PIDs. Wenn du also einen Root-Prozess mit einer hohen PID findest, solltest du misstrauisch werden.
- Überprüfe **registrierte Logins** von Benutzern ohne eine Shell in `/etc/passwd`
- Überprüfe **Passwort-Hashes** in `/etc/shadow` für Benutzer ohne eine Shell

### Memory Dump

Um den Speicher des laufenden Systems zu erfassen, wird empfohlen, [**LiME**](https://github.com/504ensicsLabs/LiME) zu verwenden.\
Zum **Kompilieren** musst du denselben **Kernel** verwenden, den auch die Opfermaschine nutzt.

> [!TIP]
> Denke daran, dass du **LiME oder irgendetwas anderes nicht auf der Opfermaschine installieren kannst**, da dies mehrere Änderungen daran vornehmen würde.

Wenn du also über eine identische Ubuntu-Version verfügst, kannst du `apt-get install lime-forensics-dkms` verwenden.\
In anderen Fällen musst du [**LiME**](https://github.com/504ensicsLabs/LiME) von github herunterladen und mit den korrekten Kernel-Headern kompilieren. Um die **exakten Kernel-Header** der Opfermaschine zu **erhalten**, kannst du einfach das Verzeichnis `/lib/modules/<kernel version>` auf deine Maschine **kopieren** und anschließend LiME damit **kompilieren**:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME unterstützt 3 **Formate**:

- Raw (jedes Segment miteinander verkettet)
- Padded (wie Raw, jedoch mit Nullen in den rechten Bits)
- Lime (empfohlenes Format mit Metadaten

LiME kann auch verwendet werden, um den **Dump über das Netzwerk zu senden**, anstatt ihn auf dem System zu speichern, beispielsweise mit: `path=tcp:4444`

### Datenträger-Imaging

#### Herunterfahren

Zunächst müssen Sie das **System herunterfahren**. Dies ist nicht immer möglich, da es sich manchmal um einen Produktionsserver handelt, den sich das Unternehmen nicht leisten kann herunterzufahren.\
Es gibt **2 Möglichkeiten**, das System herunterzufahren: ein **normales Herunterfahren** und das **Herunterfahren durch Ziehen des Netzsteckers**. Die erste Möglichkeit erlaubt es den **Prozessen, wie gewohnt zu terminieren**, und das **Dateisystem** wird **synchronisiert**. Sie ermöglicht es jedoch auch der möglichen **Malware**, **Beweise zu zerstören**. Das Vorgehen durch **Ziehen des Netzsteckers** kann zu **etwas Informationsverlust** führen (es wird nicht viel Information verloren gehen, da wir bereits ein Abbild des Arbeitsspeichers erstellt haben), und die **Malware hat keine Möglichkeit**, etwas dagegen zu unternehmen. Wenn Sie daher **vermuten**, dass sich **Malware** auf dem System befinden könnte, führen Sie einfach den **Befehl** **`sync`** auf dem System aus und ziehen Sie den Netzstecker.

#### Erstellen eines Abbilds des Datenträgers

Es ist wichtig zu beachten, dass Sie **vor dem Verbinden Ihres Computers mit irgendetwas, das mit dem Fall zusammenhängt**, sicherstellen müssen, dass er **nur lesbar eingehängt** wird, um eine Änderung von Informationen zu vermeiden.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Vorab-Analyse eines Disk-Images

Erstellung eines Images eines Datenträgers ohne weitere Daten.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
## Nach bekannter Malware suchen

### Geänderte Systemdateien

Linux bietet Tools zur Überprüfung der Integrität von Systemkomponenten, was entscheidend ist, um potenziell problematische Dateien zu erkennen.<sup>[[1]](#references)</sup>

- **RedHat-basierte Systeme**: Verwende `rpm -Va` für eine umfassende Überprüfung.
- **Debian-basierte Systeme**: Verwende zunächst `dpkg --verify` zur Verifizierung und anschließend `debsums | grep -v "OK$"` (nach der Installation von `debsums` mit `apt-get install debsums`), um Probleme zu identifizieren.

### Malware-/Rootkit-Detektoren

Lies die folgende Seite, um mehr über Tools zu erfahren, die beim Auffinden von Malware hilfreich sein können:


{{#ref}}
malware-analysis.md
{{#endref}}

## Installierte Programme suchen

Um effektiv nach installierten Programmen auf Debian- und RedHat-Systemen zu suchen, solltest du neben manuellen Prüfungen in gängigen Verzeichnissen auch Systemprotokolle und Datenbanken nutzen.<sup>[[1]](#references)</sup>

- Überprüfe bei Debian _**`/var/lib/dpkg/status`**_ und _**`/var/log/dpkg.log`**_, um Details zu Paketinstallationen abzurufen, und verwende `grep`, um nach bestimmten Informationen zu filtern.
- RedHat-Benutzer können die RPM-Datenbank mit `rpm -qa --root=/mntpath/var/lib/rpm` abfragen, um installierte Pakete aufzulisten.

Um Software zu finden, die manuell oder außerhalb dieser Paketmanager installiert wurde, untersuche Verzeichnisse wie _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ und _**`/sbin`**_. Kombiniere Verzeichnisauflistungen mit systemspezifischen Befehlen, um ausführbare Dateien zu identifizieren, die keinen bekannten Paketen zugeordnet sind, und erweitere so deine Suche nach allen installierten Programmen.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
## Gelöschte laufende Binärdateien wiederherstellen

Stell dir einen Prozess vor, der aus `/tmp/exec` ausgeführt und anschließend gelöscht wurde. Es ist möglich, ihn zu extrahieren.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Syscall Trace Triage mit SQLite und FTS5

Wenn ein Prozess noch läuft oder in einem Lab erneut ausgeführt werden kann, kann **`strace`** einen schnellen Verhaltens-Trace liefern, ohne Kernel-Module oder vollständige EDR-Telemetrie zu benötigen. Bei großen Traces sollte das Raw-Log nicht direkt gelesen oder in ein **SQLite**-Database eingefügt werden: Speichere es stattdessen in einer **SQLite**-Datenbank und frage nur die minimale benötigte Teilmenge ab.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> Das Anhängen von `strace` verändert das Timing des Prozesses und kann Race Conditions oder andere fragile Bugs beeinflussen. Wenn möglich, sollte die Reproduktion auf einem Copy-/Lab-System erfolgen.

### Erfassung

Für einen neuen Prozess:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Für einen laufenden Prozess:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Nützliche Optionen:

- `-ff`: Forks/Threads folgen und Ausgaben pro Prozess beibehalten
- `-ttt`: Epoch-Zeitstempel für eine einfache Timeline-Korrelation
- `-yy`: Dateideskriptoren nach Möglichkeit in zugrunde liegende Pfade/Sockets auflösen
- `-s 4096`: Verhindert, dass lange Pfad- und Buffer-Argumente abgeschnitten werden

### Normalisieren

Ein praktikables Schema umfasst eine Zeile pro Syscall und eine Zeile pro Argument:
```sql
CREATE TABLE syscalls (
id        INTEGER PRIMARY KEY,
pid       INTEGER NOT NULL,
timestamp REAL    NOT NULL,
name      TEXT    NOT NULL,
ret_val   INTEGER,
errno     TEXT
);

CREATE TABLE syscall_args (
id         INTEGER PRIMARY KEY,
syscall_id INTEGER NOT NULL REFERENCES syscalls(id),
position   INTEGER NOT NULL,
raw        TEXT    NOT NULL,
type       INTEGER NOT NULL
);
```
Dies verhindert, dass heterogene Syscall-Zeilen in eine einzige breite Tabelle abgeflacht werden müssen, und sorgt dafür, dass Joins während der Triage vorhersehbar bleiben.

### Textlastige Argumente mit FTS5 indizieren

Die naive Pfadsuche mit `LIKE "%...%"` wird bei großen Traces sehr langsam. Erstelle einen FTS5-Index für Argumenttext und durchsuche stattdessen diesen:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Beispiel: Dateiaktivitäten unter `/tmp` rekonstruieren, ohne jede Zeile zu durchsuchen:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Untersuchungen mit hoher Aussagekraft

- **PATH hijacking / fake sudo**: Suche nach Schreibvorgängen sowie `chmod`-/`rename`-Aktivitäten unter `~/.local/bin/` und korreliere diese anschließend mit `execve`-Aufrufen privilegiert wirkender Namen wie `sudo`.
- **TOCTOU bei temporären Dateien**: Verfolge denselben `/tmp/...`-Pfad über `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` und `execve`, um Lücken zwischen Prüfung und Verwendung zu identifizieren.
- **Ursache eines Absturzes**: Korreliere `mmap` einer Datei mit Schreibvorgängen oder einer Kürzung desselben Inodes/Pfads durch einen anderen Prozess und untersuche anschließend die Signal-/Exit-Sequenz auf `SIGBUS`.
- **Wiederherstellung von Netzwerkzielen**: Filtere `connect`, `sendto`, `sendmsg`, `recvfrom` und socketbezogene Argumente, um Peer-IP-Adressen und Ports zu extrahieren.

### LLM-gestützte Trace-Analyse

Wenn du ein LLM unterstützen lassen möchtest, stelle einen **read-only**-SQLite-Handle bereit und gib ihm das vollständige Schema. Lass es direktes SQL ausführen, anstatt die Datenbank hinter engen Hilfsfunktionen zu kapseln. Das funktioniert gewöhnlich besser für Joins, zeitliche Korrelationen und FTS-Lookups.

Praktische Regeln:

- Halte die Datenbank schreibgeschützt, zum Beispiel mit `sqlite3 'file:trace.db?mode=ro'`.
- Gib dem Modell Beispiele für gültige `JOIN`- und `FTS5 MATCH`-Abfragen.
- Füge keine rohen Multi-GB-`strace`-Logs in den Prompt ein.
- Stelle fokussierte Fragen wie:
- "Liste die persistenten Dateien auf, die von diesem Programm geschrieben wurden."
- "Hat das Programm ausführbare Dateien in benutzerkontrollierten PATH-Verzeichnissen erstellt oder ersetzt?"
- "Erkläre, warum dieser Trace mit SIGBUS endet."

## Autostart-Speicherorte untersuchen

### Geplante Tasks
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
#### Suche: Cron/Anacron-Missbrauch über 0anacron und verdächtige Stubs
Angreifer bearbeiten häufig den unter jedem Verzeichnis `/etc/cron.*/` vorhandenen 0anacron-Stub, um eine regelmäßige Ausführung sicherzustellen.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH-Hardening-Rücknahme und Backdoor-Shells
Änderungen an sshd_config und den Shells von Systemkonten sind häufige post-exploitation-Maßnahmen, um den Zugriff aufrechtzuerhalten.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud-C2-Marker (Dropbox/Cloudflare Tunnel)
- Dropbox-API-Beacons verwenden typischerweise api.dropboxapi.com oder content.dropboxapi.com über HTTPS mit Authorization: Bearer-Tokens.
- Suche in Proxy/Zeek/NetFlow nach unerwartetem Dropbox-Egress von Servern.
- Cloudflare Tunnel (`cloudflared`) stellt ein Backup-C2 über ausgehendes 443 bereit.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Dienste

Pfade, unter denen Malware als Dienst installiert sein könnte:

- **/etc/inittab**: Ruft Initialisierungsskripte wie rc.sysinit auf, die anschließend an Startup-Skripte weiterleiten.
- **/etc/rc.d/** und **/etc/rc.boot/**: Enthalten Skripte für den Dienststart; letzteres ist in älteren Linux-Versionen zu finden.
- **/etc/init.d/**: Wird in bestimmten Linux-Versionen wie Debian zum Speichern von Startup-Skripten verwendet.
- Dienste können je nach Linux-Variante auch über **/etc/inetd.conf** oder **/etc/xinetd/** aktiviert werden.
- **/etc/systemd/system**: Ein Verzeichnis für Skripte des System- und Dienstmanagers.
- **/etc/systemd/system/multi-user.target.wants/**: Enthält Links zu Diensten, die in einem Multi-User-Runlevel gestartet werden sollen.
- **/usr/local/etc/rc.d/**: Für benutzerdefinierte Dienste oder Dienste von Drittanbietern.
- **\~/.config/autostart/**: Für benutzerspezifische Anwendungen mit automatischem Start; kann als Versteck für auf Benutzer abzielende Malware dienen.
- **/lib/systemd/system/**: Systemweite Standard-Unit-Dateien, die von installierten Paketen bereitgestellt werden.

#### Suche: systemd-Timer und transiente Units

Die systemd-Persistenz ist nicht auf `.service`-Dateien beschränkt. Untersuche `.timer`-Units, Units auf Benutzerebene und **transiente Units**, die zur Laufzeit erstellt werden.
```bash
# Enumerate timers and inspect referenced services
systemctl list-timers --all
systemctl cat <name>.timer
systemctl cat <name>.service

# Search common system and user paths
find /etc/systemd/system /run/systemd/system /usr/lib/systemd/system -maxdepth 3 \( -name '*.service' -o -name '*.timer' \) -ls
find /home -path '*/.config/systemd/user/*' -type f \( -name '*.service' -o -name '*.timer' \) -ls

# Transient units created via systemd-run often land here
find /run/systemd/transient -maxdepth 2 -type f -ls 2>/dev/null

# Pull execution history for a suspicious unit
journalctl -u <name>.service
journalctl _SYSTEMD_UNIT=<name>.service
```
Transient units sind leicht zu übersehen, da `/run/systemd/transient/` **nicht persistent** ist. Wenn Sie ein Live-Image erfassen, sichern Sie es vor dem Herunterfahren.

### Kernel Modules

Linux-Kernelmodule, die von Malware häufig als rootkit-Komponenten verwendet werden, werden beim Systemstart geladen. Zu den für diese Module wichtigen Verzeichnissen und Dateien gehören:

- **/lib/modules/$(uname -r)**: Enthält Module für die laufende Kernelversion.
- **/etc/modprobe.d**: Enthält Konfigurationsdateien zur Steuerung des Ladens von Modulen.
- **/etc/modprobe** und **/etc/modprobe.conf**: Dateien für globale Moduleinstellungen.

### Other Autostart Locations

Linux verwendet verschiedene Dateien, um Programme automatisch bei der Benutzeranmeldung auszuführen, in denen sich möglicherweise Malware befinden kann:

- **/etc/profile.d/**\*, **/etc/profile** und **/etc/bash.bashrc**: Werden bei der Anmeldung jedes Benutzers ausgeführt.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** und **\~/.config/autostart**: Benutzerspezifische Dateien, die bei dessen Anmeldung ausgeführt werden.
- **/etc/rc.local**: Wird ausgeführt, nachdem alle Systemdienste gestartet wurden, und markiert das Ende des Übergangs zu einer Multiuser-Umgebung.

## Examine Logs

Linux-Systeme protokollieren Benutzeraktivitäten und Systemereignisse in verschiedenen Logdateien. Diese Logs sind entscheidend, um unbefugten Zugriff, Malware-Infektionen und andere Sicherheitsvorfälle zu identifizieren.<sup>[[2]](#references)</sup> Zu den wichtigsten Logdateien gehören:

- **/var/log/syslog** (Debian) oder **/var/log/messages** (RedHat): Erfassen systemweite Meldungen und Aktivitäten.
- **/var/log/auth.log** (Debian) oder **/var/log/secure** (RedHat): Zeichnen Authentifizierungsversuche sowie erfolgreiche und fehlgeschlagene Anmeldungen auf.
- Verwenden Sie `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`, um relevante Authentifizierungsereignisse zu filtern.
- **/var/log/boot.log**: Enthält Meldungen zum Systemstart.
- **/var/log/maillog** oder **/var/log/mail.log**: Protokollieren Aktivitäten des E-Mail-Servers und sind nützlich, um E-Mail-bezogene Dienste nachzuverfolgen.
- **/var/log/kern.log**: Speichert Kernelmeldungen, einschließlich Fehlern und Warnungen.
- **/var/log/dmesg**: Enthält Meldungen von Gerätetreibern.
- **/var/log/faillog**: Zeichnet fehlgeschlagene Anmeldeversuche auf und unterstützt Untersuchungen von Sicherheitsverletzungen.
- **/var/log/cron**: Protokolliert die Ausführung von Cron-Jobs.
- **/var/log/daemon.log**: Verfolgt Aktivitäten von Hintergrunddiensten.
- **/var/log/btmp**: Dokumentiert fehlgeschlagene Anmeldeversuche.
- **/var/log/httpd/**: Enthält Apache-HTTPD-Fehler- und Zugriffslogs.
- **/var/log/mysqld.log** oder **/var/log/mysql.log**: Protokollieren Aktivitäten der MySQL-Datenbank.
- **/var/log/xferlog**: Zeichnet FTP-Dateiübertragungen auf.
- **/var/log/**: Überprüfen Sie diesen Pfad immer auf unerwartete Logs.

> [!TIP]
> Linux-Systemlogs und Audit-Subsysteme können bei einem Einbruch oder Malware-Vorfall deaktiviert oder gelöscht worden sein. Da Logs auf Linux-Systemen im Allgemeinen einige der nützlichsten Informationen über schädliche Aktivitäten enthalten, löschen Angreifer sie routinemäßig. Achten Sie daher bei der Untersuchung verfügbarer Logdateien auf Lücken oder Einträge in falscher Reihenfolge, da dies auf eine Löschung oder Manipulation hindeuten kann.

### Journald triage (`journalctl`)

Auf modernen Linux-Hosts ist das **systemd journal** in der Regel die wertvollste Quelle für **service execution**, **auth events**, **package operations** sowie **kernel/user-space messages**. Versuchen Sie bei einer Live-Response, sowohl das **persistente** Journal (`/var/log/journal/`) als auch das **Runtime**-Journal (`/run/log/journal/`) zu sichern, da kurzlebige Aktivitäten von Angreifern möglicherweise nur im letzteren vorhanden sind.<sup>[[5]](#references)</sup>
```bash
# List available boots and pivot around the suspicious one
journalctl --list-boots
journalctl -b -1

# Review a mounted image or copied journal directory offline
journalctl --directory /mnt/image/var/log/journal --list-boots
journalctl --directory /mnt/image/var/log/journal -b -1

# Inspect a single journal file and check integrity/corruption
journalctl --file system.journal --header
journalctl --file system.journal --verify

# High-signal filters
journalctl -u ssh.service
journalctl _SYSTEMD_UNIT=cron.service
journalctl _UID=0
journalctl _EXE=/usr/sbin/useradd
```
Nützliche Journal-Felder für die Triage umfassen `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` und `MESSAGE`. Wenn journald ohne persistenten Speicher konfiguriert wurde, sind unter `/run/log/journal/` nur aktuelle Daten zu erwarten.

### Triage des Audit-Frameworks (`auditd`)

Wenn `auditd` aktiviert ist, sollte es bevorzugt verwendet werden, wenn die **Zuordnung von Prozessen** zu Dateiänderungen, Befehlsausführung, Login-Aktivitäten oder der Installation von Paketen erforderlich ist.<sup>[[6]](#references)</sup>
```bash
# Fast summaries
aureport --start today --summary -i
aureport --start today --login --failed -i
aureport --start today --executable -i

# Search raw events
ausearch --start today -m EXECVE -i
ausearch --start today -ua 1000 -m USER_CMD,EXECVE -i
ausearch --start today -m SERVICE_START,SERVICE_STOP -i

# Software installation/update events (especially useful on RHEL-like systems)
ausearch -m SOFTWARE_UPDATE -i
```
Wenn Regeln mit Schlüsseln bereitgestellt wurden, pivotiere von ihnen aus, statt rohe Logs zu durchsuchen:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux führt für jeden Benutzer einen Befehlsverlauf**, der gespeichert wird unter:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Außerdem liefert der Befehl `last -Faiwx` eine Liste der Benutzeranmeldungen. Überprüfe sie auf unbekannte oder unerwartete Anmeldungen.

Überprüfe Dateien, die zusätzliche Berechtigungen gewähren können:

- Überprüfe `/etc/sudoers` auf unerwartete Benutzerberechtigungen, die gewährt worden sein könnten.
- Überprüfe `/etc/sudoers.d/` auf unerwartete Benutzerberechtigungen, die gewährt worden sein könnten.
- Untersuche `/etc/groups`, um ungewöhnliche Gruppenmitgliedschaften oder Berechtigungen zu identifizieren.
- Untersuche `/etc/passwd`, um ungewöhnliche Gruppenmitgliedschaften oder Berechtigungen zu identifizieren.

Einige Anwendungen erzeugen außerdem eigene Logs:

- **SSH**: Untersuche _\~/.ssh/authorized_keys_ und _\~/.ssh/known_hosts_ auf nicht autorisierte Remote-Verbindungen.
- **Gnome Desktop**: Sieh in _\~/.recently-used.xbel_ nach, um kürzlich über Gnome-Anwendungen aufgerufene Dateien zu identifizieren.
- **Firefox/Chrome**: Überprüfe den Browserverlauf und Downloads in _\~/.mozilla/firefox_ oder _\~/.config/google-chrome_ auf verdächtige Aktivitäten.
- **VIM**: Überprüfe _\~/.viminfo_ auf Nutzungsdetails, beispielsweise aufgerufene Dateipfade und den Suchverlauf.
- **Open Office**: Überprüfe den Zugriff auf kürzlich verwendete Dokumente, der auf kompromittierte Dateien hindeuten kann.
- **FTP/SFTP**: Überprüfe Logs in _\~/.ftp_history_ oder _\~/.sftp_history_ auf möglicherweise nicht autorisierte Dateiübertragungen.
- **MySQL**: Untersuche _\~/.mysql_history_ auf ausgeführte MySQL-Abfragen, die möglicherweise nicht autorisierte Datenbankaktivitäten offenlegen.
- **Less**: Analysiere _\~/.lesshst_ auf den Nutzungsverlauf, einschließlich angezeigter Dateien und ausgeführter Befehle.
- **Git**: Untersuche _\~/.gitconfig_ und _.git/logs_ des Projekts auf Änderungen an Repositories.

### USB-Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) ist eine kleine, vollständig in Python 3 geschriebene Software, die Linux-Logdateien (`/var/log/syslog*` oder `/var/log/messages*`, abhängig von der Distribution) analysiert, um Tabellen mit dem USB-Ereignisverlauf zu erstellen.

Es ist interessant zu **wissen, welche USBs verwendet wurden**. Noch nützlicher ist dies, wenn du über eine autorisierte Liste von USBs verfügst, um „Verstoßereignisse“ zu identifizieren (die Verwendung von USBs, die nicht in dieser Liste enthalten sind).

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Beispiele
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Weitere Beispiele und Informationen im github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Benutzerkonten und Logon-Aktivitäten überprüfen

Untersuchen Sie _**/etc/passwd**_, _**/etc/shadow**_ und **Sicherheitsprotokolle** auf ungewöhnliche Namen oder Konten, die zeitnah zu bekannten unautorisierten Ereignissen erstellt und/oder verwendet wurden. Überprüfen Sie außerdem mögliche sudo-Brute-Force-Angriffe.\
Überprüfen Sie zudem Dateien wie _**/etc/sudoers**_ und _**/etc/groups**_ auf unerwartete Privilegien, die Benutzern gewährt wurden.\
Suchen Sie schließlich nach Konten mit **keinen Passwörtern** oder **leicht zu erratenden** Passwörtern.<sup>[[1]](#references)</sup>

## Dateisystem untersuchen

### Analyse von Dateisystemstrukturen bei der Malware-Untersuchung

Bei der Untersuchung von Malware-Vorfällen ist die Struktur des Dateisystems eine wichtige Informationsquelle, die sowohl die Abfolge der Ereignisse als auch den Inhalt der Malware offenlegt. Malware-Autoren entwickeln jedoch Techniken, um diese Analyse zu behindern, beispielsweise durch das Ändern von Dateizeitstempeln oder das Umgehen des Dateisystems zur Datenspeicherung.<sup>[[1]](#references)</sup>

Um diesen Anti-Forensik-Methoden entgegenzuwirken, ist es wichtig:

- **Eine gründliche Zeitleistenanalyse durchzuführen**, beispielsweise mit Tools wie **Autopsy** zur Visualisierung von Ereigniszeitleisten oder `mactime` aus dem **Sleuth Kit** für detaillierte Zeitleistendaten.
- **Unerwartete Skripte** im $PATH des Systems zu untersuchen, die Shell- oder PHP-Skripte enthalten könnten, die von Angreifern verwendet werden.
- **`/dev` auf atypische Dateien zu untersuchen**, da dieses Verzeichnis traditionell spezielle Dateien enthält, aber auch Malware-bezogene Dateien beherbergen kann.
- **Nach versteckten Dateien oder Verzeichnissen** mit Namen wie ".. " (Punkt Punkt Leerzeichen) oder "..^G" (Punkt Punkt Control-G) zu suchen, die schädliche Inhalte verbergen könnten.
- **Setuid-root-Dateien zu identifizieren**, indem der Befehl verwendet wird: `find / -user root -perm -04000 -print` Dieser findet Dateien mit erweiterten Berechtigungen, die von Angreifern missbraucht werden könnten.
- **Löschzeitstempel zu überprüfen**, die in Inode-Tabellen enthalten sind, um massenhafte Dateilöschungen zu erkennen, die möglicherweise auf das Vorhandensein von Rootkits oder Trojanern hindeuten.
- **Aufeinanderfolgende Inodes zu untersuchen**, um nach der Identifizierung einer schädlichen Datei benachbarte schädliche Dateien zu finden, da diese möglicherweise gemeinsam platziert wurden.
- **Übliche Binärverzeichnisse** (_/bin_, _/sbin_) auf kürzlich geänderte Dateien zu überprüfen, da diese durch Malware verändert worden sein könnten.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Beachte, dass ein **Angreifer** die **Zeit** **ändern** kann, damit **Dateien** **legitim erscheinen**, aber er kann den **Inode** nicht **ändern**. Wenn du feststellst, dass eine **Datei** angibt, dass sie zur **gleichen Zeit** wie die übrigen Dateien im selben Ordner erstellt und geändert wurde, der **Inode** jedoch **unerwartet größer** ist, wurden die **Zeitstempel dieser Datei geändert**.

### Schnelle, auf den Inode fokussierte Triage

Wenn du anti-forensics vermutest, führe frühzeitig diese auf den Inode fokussierten Prüfungen durch:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Wenn sich ein verdächtiger Inode auf einem EXT-Dateisystem-Image/-Gerät befindet, überprüfen Sie die Inode-Metadaten direkt:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Nützliche Felder:
- **Links**: Wenn `0`, referenziert derzeit kein Verzeichniseintrag den inode.
- **dtime**: Löschzeitstempel, der gesetzt wird, wenn der inode entfernt wurde.
- **ctime/mtime**: Hilft dabei, Änderungen an Metadaten und Inhalten mit der Incident-Zeitlinie zu korrelieren.

### Capabilities, xattrs und preload-basierte Userland-Rootkits

Moderne Linux-Persistence vermeidet häufig offensichtliche **setuid**-Binaries und missbraucht stattdessen **file capabilities**, **extended attributes** und den dynamic loader.
```bash
# Enumerate file capabilities (think cap_setuid, cap_sys_admin, cap_dac_override)
getcap -r / 2>/dev/null

# Inspect extended attributes on suspicious binaries and libraries
getfattr -d -m - /path/to/suspicious/file 2>/dev/null

# Global preload hook affecting every dynamically linked binary
cat /etc/ld.so.preload 2>/dev/null
stat /etc/ld.so.preload 2>/dev/null

# If a suspicious library is referenced, inspect its metadata and links
ls -lah /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib 2>/dev/null | grep -E '\\.so(\\.|$)'
ldd /bin/ls
```
Achten Sie besonders auf Libraries, die aus **beschreibbaren** Pfaden wie `/tmp`, `/dev/shm`, `/var/tmp` oder ungewöhnlichen Speicherorten unter `/usr/local/lib` referenziert werden. Prüfen Sie außerdem Binärdateien mit Capabilities außerhalb der normalen Paketverwaltung und gleichen Sie diese mit den Ergebnissen der Paketüberprüfung ab (`rpm -Va`, `dpkg --verify`, `debsums`).

## Dateien verschiedener Dateisystemversionen vergleichen

### Zusammenfassung des Dateisystemversionsvergleichs

Um Dateisystemversionen zu vergleichen und Änderungen zu ermitteln, verwenden wir vereinfachte `git diff`-Befehle:<sup>[[3]](#references)</sup>

- **Um neue Dateien zu finden**, vergleichen Sie zwei Verzeichnisse:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Für geänderte Inhalte** Änderungen unter Auslassung bestimmter Zeilen auflisten:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Gelöschte Dateien erkennen**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) helfen dabei, die Ausgabe auf bestimmte Änderungen wie hinzugefügte (`A`), gelöschte (`D`) oder geänderte (`M`) Dateien zu beschränken.
- `A`: Hinzugefügte Dateien
- `C`: Kopierte Dateien
- `D`: Gelöschte Dateien
- `M`: Geänderte Dateien
- `R`: Umbenannte Dateien
- `T`: Typänderungen (z. B. Datei zu Symlink)
- `U`: Nicht zusammengeführte Dateien
- `X`: Unbekannte Dateien
- `B`: Beschädigte Dateien

## Referenzen

- [1] [Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides – Kapitel 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Linux-Logs erklärt](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [git diff-Dokumentation – Option --diff-filter](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Forensische Analyse von Linux-Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 – Überwachung des Systems](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Say hi to Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
