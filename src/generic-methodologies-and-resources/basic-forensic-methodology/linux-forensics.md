# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Erste Informationsgewinnung

### Grundlegende Informationen

Zunächst wird empfohlen, einen **USB** mit **gut bekannten Binaries und Libraries darauf** zu haben (du kannst einfach Ubuntu nehmen und die Ordner _/bin_, _/sbin_, _/lib,_ und _/lib64_ kopieren), dann den USB mounten und die env-Variablen so anpassen, dass diese Binaries verwendet werden:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Sobald Sie das System so konfiguriert haben, dass es gute und bekannte Binaries verwendet, können Sie damit beginnen, **einige grundlegende Informationen zu extrahieren**:
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

Während du die grundlegenden Informationen sammelst, solltest du auf seltsame Dinge achten wie:

- **Root-Prozesse** laufen normalerweise mit niedrigen PIDs, also kannst du verdächtig werden, wenn du einen Root-Prozess mit einer großen PID findest
- Prüfe **registrierte Logins** von Benutzern ohne Shell in `/etc/passwd`
- Prüfe auf **password hashes** in `/etc/shadow` für Benutzer ohne Shell

### Memory Dump

Um den Speicher des laufenden Systems zu erhalten, wird empfohlen, [**LiME**](https://github.com/504ensicsLabs/LiME) zu verwenden.\
Zum **Kompilieren** musst du denselben **Kernel** verwenden, den die Zielmaschine benutzt.

> [!TIP]
> Denk daran, dass du **LiME oder irgendetwas anderes nicht auf der Zielmaschine installieren kannst**, da dies mehrere Änderungen daran verursachen würde

Wenn du also eine identische Version von Ubuntu hast, kannst du `apt-get install lime-forensics-dkms` verwenden\
In anderen Fällen musst du [**LiME**](https://github.com/504ensicsLabs/LiME) von github herunterladen und mit den korrekten Kernel-Headern kompilieren. Um die exakten **Kernel-Header** der Zielmaschine zu erhalten, kannst du einfach das Verzeichnis `/lib/modules/<kernel version>` auf deine Maschine **kopieren** und dann LiME damit **kompilieren**:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME unterstützt 3 **Formate**:

- Raw (jedes Segment zusammengefügt)
- Padded (wie raw, aber mit Nullen in den rechten Bits)
- Lime (empfohlenes Format mit Metadaten)

LiME kann auch verwendet werden, um den Dump **über das Netzwerk zu senden** statt ihn auf dem System zu speichern, z. B. mit: `path=tcp:4444`

### Disk Imaging

#### Shutting down

Zuerst musst du das System **herunterfahren**. Das ist nicht immer eine Option, da es sich manchmal um einen Produktionsserver handelt, den das Unternehmen nicht herunterfahren kann.\
Es gibt **2 Wege**, das System herunterzufahren: ein **normales Herunterfahren** und ein **"plug the plug" shutdown**. Die erste Variante erlaubt es den **Prozessen**, sich wie üblich zu beenden, und dem **filesystem**, sich zu **synchronisieren**, aber sie gibt auch möglicher **malware** die Chance, **Beweise zu zerstören**. Die "pull the plug"-Methode kann zu **einem gewissen Informationsverlust** führen (nicht viel Information geht verloren, da wir bereits ein Image des Speichers erstellt haben) und die **malware** hat **keine Gelegenheit**, etwas dagegen zu tun. Wenn du also **vermutest**, dass **malware** vorhanden sein könnte, führe einfach den **`sync`**-**command** auf dem System aus und ziehe den Stecker.

#### Taking an image of the disk

Es ist wichtig zu beachten, dass du **bevor du deinen Computer mit etwas verbindest, das mit dem Fall zu tun hat**, sicherstellen musst, dass es **nur lesend eingebunden** wird, um zu vermeiden, dass irgendwelche Informationen verändert werden.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk-Image Voranalyse

Erstellen eines Disk-Images ohne weitere Daten.
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
## Suche nach bekannter Malware

### Geänderte Systemdateien

Linux bietet Werkzeuge zur Sicherstellung der Integrität von Systemkomponenten, die entscheidend sind, um potenziell problematische Dateien zu erkennen.

- **RedHat-based systems**: Verwende `rpm -Va` für eine umfassende Prüfung.
- **Debian-based systems**: `dpkg --verify` für die erste Überprüfung, gefolgt von `debsums | grep -v "OK$"` (nach Installation von `debsums` mit `apt-get install debsums`), um Probleme zu identifizieren.

### Malware/Rootkit Detectors

Lies die folgende Seite, um mehr über Werkzeuge zu erfahren, die nützlich sein können, um Malware zu finden:


{{#ref}}
malware-analysis.md
{{#endref}}

## Installierte Programme suchen

Um installierte Programme auf Debian- und RedHat-Systemen effektiv zu suchen, solltest du System-Logs und Datenbanken zusammen mit manuellen Prüfungen in gängigen Verzeichnissen nutzen.

- Für Debian prüfe _**`/var/lib/dpkg/status`**_ und _**`/var/log/dpkg.log`**_, um Details zu Paketinstallationen abzurufen, und verwende `grep`, um nach spezifischen Informationen zu filtern.
- RedHat-Benutzer können die RPM-Datenbank mit `rpm -qa --root=/mntpath/var/lib/rpm` abfragen, um installierte Pakete aufzulisten.

Um Software zu entdecken, die manuell oder außerhalb dieser Package Manager installiert wurde, erkunde Verzeichnisse wie _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ und _**`/sbin`**_. Kombiniere Verzeichnisauflistungen mit systemspezifischen Befehlen, um ausführbare Dateien zu identifizieren, die nicht mit bekannten Paketen verbunden sind, und verbessere so deine Suche nach allen installierten Programmen.
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

Stell dir einen Prozess vor, der von /tmp/exec ausgeführt und dann gelöscht wurde. Es ist möglich, ihn zu extrahieren
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Syscall Trace Triage mit SQLite und FTS5

Wenn ein Prozess noch läuft oder in einem Lab erneut ausgeführt werden kann, kann **`strace`** einen schnellen Verhaltens-Trace liefern, ohne Kernel-Module oder vollständige EDR-Telemetrie zu benötigen. Bei großen Traces solltest du das rohe Log nicht direkt lesen oder in ein LLM einfügen: Speichere es in einer **SQLite**-Datenbank und frage nur die minimale Teilmenge ab, die du brauchst.

> [!WARNING]
> Das Anhängen von `strace` verändert das Timing des Prozesses und kann Race Conditions oder andere fragile Bugs beeinflussen. Wenn möglich, reproduziere auf einer Kopie oder einem Lab-System.

### Capture

Für einen neuen Prozess:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Für einen Live-Prozess:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Nützliche Optionen:

- `-ff`: Forks/Threads verfolgen und pro Prozess eigene Ausgaben behalten
- `-ttt`: Epoch-Zeitstempel für einfache Timeline-Korrelation
- `-yy`: File Descriptors nach Möglichkeit auf zugrunde liegende Pfade/Sockets auflösen
- `-s 4096`: lange Pfad- und Buffer-Argumente nicht abschneiden

### Normalisieren

Ein praktisches Schema ist eine Zeile pro Syscall und eine Zeile pro Argument:
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
Dies vermeidet es, heterogene syscall-Zeilen in eine einzige breite Tabelle zu überführen, und hält Joins während der Triage vorhersehbar.

### Index textlastige Argumente mit FTS5

Naives Path Hunting mit `LIKE "%...%"` wird bei großen Traces sehr langsam. Erstelle stattdessen einen FTS5-Index für den Argumenttext und suche darüber:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Beispiel: Dateiaktivität unter `/tmp` wiederherstellen, ohne jede Zeile zu scannen:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### High-signal investigations

- **PATH hijacking / fake sudo**: Suche nach Writes und `chmod`/`rename`-Aktivität unter `~/.local/bin/`, und korreliere dann mit späterem `execve` von privilegiert wirkenden Namen wie `sudo`.
- **TOCTOU on temporary files**: Pivot auf denselben `/tmp/...`-Pfad über `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` und `execve`, um Check/Use-Lücken zu identifizieren.
- **Crash root cause**: Korreliere `mmap` einer Datei mit Writes oder Truncation desselben Inodes/Pfads durch einen anderen Prozess, und prüfe dann die Signal-/Exit-Sequenz auf `SIGBUS`.
- **Network destination recovery**: Filtere `connect`, `sendto`, `sendmsg`, `recvfrom` und socket-bezogene Argumente, um Peer-IPs und Ports zu extrahieren.

### LLM-assisted trace analysis

If you want an LLM to assist, expose a **read-only** SQLite handle and give it the full schema. Let it issue raw SQL instead of wrapping the database behind narrow helper functions. This usually works better for joins, temporal correlation, and FTS lookups.

Practical rules:

- Keep the database read-only, for example with `sqlite3 'file:trace.db?mode=ro'`.
- Give the model examples of valid `JOIN` and `FTS5 MATCH` queries.
- Do **not** paste raw multi-GB `strace` logs into the prompt.
- Ask focused questions such as:
- "List persistent files written by this program."
- "Did it create or replace executables in user-controlled PATH directories?"
- "Explain why this trace ends in SIGBUS."

## Inspect Autostart locations

### Scheduled Tasks
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
#### Hunt: Cron/Anacron abuse via 0anacron and suspicious stubs
Angreifer bearbeiten oft den 0anacron-Stub, der in jedem /etc/cron.*/-Verzeichnis vorhanden ist, um eine periodische Ausführung sicherzustellen.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH hardening rollback and backdoor shells
Änderungen an sshd_config und System-Account-Shells sind nach einer Kompromittierung üblich, um den Zugriff aufrechtzuerhalten.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API-Beacons verwenden typischerweise api.dropboxapi.com oder content.dropboxapi.com über HTTPS mit Authorization: Bearer tokens.
- Suche in proxy/Zeek/NetFlow nach unerwartetem Dropbox-Egress von Servern.
- Cloudflare Tunnel (`cloudflared`) bietet Backup-C2 über ausgehendes 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Pfade, in denen Malware als Service installiert werden könnte:

- **/etc/inittab**: Ruft Initialisierungsskripte wie rc.sysinit auf und leitet weiter zu Startup-Skripten.
- **/etc/rc.d/** und **/etc/rc.boot/**: Enthalten Skripte für den Service-Start; letzteres findet man in älteren Linux-Versionen.
- **/etc/init.d/**: Wird in bestimmten Linux-Versionen wie Debian zum Speichern von Startup-Skripten verwendet.
- Services können je nach Linux-Variante auch über **/etc/inetd.conf** oder **/etc/xinetd/** aktiviert werden.
- **/etc/systemd/system**: Ein Verzeichnis für System- und Service-Manager-Skripte.
- **/etc/systemd/system/multi-user.target.wants/**: Enthält Links zu Services, die in einem Multi-User-Runlevel gestartet werden sollen.
- **/usr/local/etc/rc.d/**: Für benutzerdefinierte oder Drittanbieter-Services.
- **\~/.config/autostart/**: Für anwendungsspezifische automatische Startanwendungen; kann ein Versteck für auf den Benutzer zielende Malware sein.
- **/lib/systemd/system/**: Systemweite Standard-Unit-Dateien, die von installierten Paketen bereitgestellt werden.

#### Hunt: systemd timers and transient units

Systemd-Persistenz ist nicht auf `.service`-Dateien beschränkt. Untersuche `.timer`-Units, User-Level-Units und zur Laufzeit erstellte **transient units**.
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
Transient Units sind leicht zu übersehen, weil `/run/systemd/transient/` **nicht persistent** ist. Wenn du ein Live-Image erfasst, sichere es vor dem Herunterfahren.

### Kernel Modules

Linux kernel modules, die oft von malware als rootkit components genutzt werden, werden beim Systemstart geladen. Die für diese modules kritischen Verzeichnisse und Dateien sind:

- **/lib/modules/$(uname -r)**: Enthält modules für die laufende kernel version.
- **/etc/modprobe.d**: Enthält Konfigurationsdateien zur Steuerung des module loading.
- **/etc/modprobe** und **/etc/modprobe.conf**: Dateien für globale module settings.

### Other Autostart Locations

Linux verwendet verschiedene Dateien, um Programme beim Login eines Users automatisch auszuführen, was malware enthalten kann:

- **/etc/profile.d/**\*, **/etc/profile**, und **/etc/bash.bashrc**: Werden für jeden user login ausgeführt.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, und **\~/.config/autostart**: User-spezifische Dateien, die beim Login ausgeführt werden.
- **/etc/rc.local**: Wird ausgeführt, nachdem alle system services gestartet wurden, und markiert das Ende des Übergangs zu einer multiuser environment.

## Examine Logs

Linux systems protokollieren user activities und system events über verschiedene log files. Diese logs sind entscheidend, um unauthorized access, malware infections und andere security incidents zu identifizieren. Wichtige log files sind:

- **/var/log/syslog** (Debian) oder **/var/log/messages** (RedHat): Erfassen systemweite Nachrichten und Aktivitäten.
- **/var/log/auth.log** (Debian) oder **/var/log/secure** (RedHat): Protokollieren authentication attempts sowie erfolgreiche und fehlgeschlagene logins.
- Verwende `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`, um relevante authentication events zu filtern.
- **/var/log/boot.log**: Enthält system startup messages.
- **/var/log/maillog** oder **/var/log/mail.log**: Protokolliert email server activities, nützlich zum Nachverfolgen email-bezogener services.
- **/var/log/kern.log**: Speichert kernel messages, einschließlich errors und warnings.
- **/var/log/dmesg**: Enthält device driver messages.
- **/var/log/faillog**: Protokolliert fehlgeschlagene login attempts und hilft bei security breach investigations.
- **/var/log/cron**: Protokolliert cron job executions.
- **/var/log/daemon.log**: Verfolgt background service activities.
- **/var/log/btmp**: Dokumentiert fehlgeschlagene login attempts.
- **/var/log/httpd/**: Enthält Apache HTTPD error und access logs.
- **/var/log/mysqld.log** oder **/var/log/mysql.log**: Protokolliert MySQL database activities.
- **/var/log/xferlog**: Protokolliert FTP file transfers.
- **/var/log/**: Immer auf unerwartete logs hier prüfen.

> [!TIP]
> Linux system logs und audit subsystems können bei einem intrusion oder malware incident deaktiviert oder gelöscht sein. Da logs auf Linux systems in der Regel einige der nützlichsten Informationen über malicious activities enthalten, löschen intruders sie routinemäßig. Daher ist es beim Untersuchen verfügbarer log files wichtig, nach Lücken oder Einträgen in falscher Reihenfolge zu suchen, die auf deletion oder tampering hindeuten könnten.

### Journald triage (`journalctl`)

Auf modernen Linux hosts ist das **systemd journal** normalerweise die wertvollste Quelle für **service execution**, **auth events**, **package operations** und **kernel/user-space messages**. Bei der Live Response solltest du sowohl das **persistente** Journal (`/var/log/journal/`) als auch das **runtime** Journal (`/run/log/journal/`) sichern, da kurzlebige attacker activity nur im letzteren vorhanden sein kann.
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
Nützliche journal-Felder für das Triage umfassen `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` und `MESSAGE`. Wenn `journald` ohne persistenten Speicher konfiguriert war, erwarte nur aktuelle Daten unter `/run/log/journal/`.

### Audit-Framework-Triage (`auditd`)

Wenn `auditd` aktiviert ist, nutze es immer dann bevorzugt, wenn du **process attribution** für Dateiänderungen, Befehlsausführung, Login-Aktivität oder Paketinstallation benötigst.
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
Wenn Regeln mit keys ausgerollt wurden, pivotiere von ihnen statt rohe logs zu greppen:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux hält für jeden Benutzer einen Befehlsverlauf vor**, gespeichert in:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Außerdem liefert der Befehl `last -Faiwx` eine Liste der Benutzer-Logins. Prüfe ihn auf unbekannte oder unerwartete Logins.

Prüfe Dateien, die zusätzliche rprivileges gewähren können:

- Überprüfe `/etc/sudoers` auf unerwartete Benutzerrechte, die möglicherweise gewährt wurden.
- Überprüfe `/etc/sudoers.d/` auf unerwartete Benutzerrechte, die möglicherweise gewährt wurden.
- Untersuche `/etc/groups`, um ungewöhnliche Gruppenmitgliedschaften oder Berechtigungen zu identifizieren.
- Untersuche `/etc/passwd`, um ungewöhnliche Gruppenmitgliedschaften oder Berechtigungen zu identifizieren.

Einige Apps erzeugen auch eigene Logs:

- **SSH**: Untersuche _\~/.ssh/authorized_keys_ und _\~/.ssh/known_hosts_ auf nicht autorisierte Remote-Verbindungen.
- **Gnome Desktop**: Sieh in _\~/.recently-used.xbel_ nach zuletzt über Gnome-Anwendungen aufgerufenen Dateien.
- **Firefox/Chrome**: Prüfe den Browser-Verlauf und Downloads in _\~/.mozilla/firefox_ oder _\~/.config/google-chrome_ auf verdächtige Aktivitäten.
- **VIM**: Prüfe _\~/.viminfo_ auf Nutzungsdetails, wie aufgerufene Dateipfade und Suchverlauf.
- **Open Office**: Prüfe den Zugriff auf zuletzt geöffnete Dokumente, was auf kompromittierte Dateien hinweisen kann.
- **FTP/SFTP**: Prüfe Logs in _\~/.ftp_history_ oder _\~/.sftp_history_ auf möglicherweise nicht autorisierte Dateiübertragungen.
- **MySQL**: Untersuche _\~/.mysql_history_ auf ausgeführte MySQL-Abfragen, die möglicherweise nicht autorisierte Datenbankaktivitäten offenbaren.
- **Less**: Analysiere _\~/.lesshst_ auf Nutzungsverlauf, einschließlich angezeigter Dateien und ausgeführter Befehle.
- **Git**: Untersuche _\~/.gitconfig_ und projektbezogene _.git/logs_ auf Änderungen an Repositories.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) ist eine kleine Software, die in reinem Python 3 geschrieben wurde und Linux-Logdateien (`/var/log/syslog*` oder `/var/log/messages*` je nach Distro) parst, um USB-Ereignisverlaufs-Tabellen zu erstellen.

Es ist interessant, **alle verwendeten USBs zu kennen**, und noch nützlicher ist es, wenn du eine autorisierte Liste von USBs hast, um "violation events" zu finden (die Nutzung von USBs, die nicht in dieser Liste enthalten sind).

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
Weitere Beispiele und Infos gibt es auf github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Benutzerkonten und Anmeldeaktivitäten überprüfen

Untersuche _**/etc/passwd**_, _**/etc/shadow**_ und **security logs** auf ungewöhnliche Namen oder Konten, die in zeitlicher Nähe zu bekannten unbefugten Ereignissen erstellt und/oder verwendet wurden. Prüfe außerdem auf mögliche sudo brute-force attacks.\
Außerdem solltest du Dateien wie _**/etc/sudoers**_ und _**/etc/groups**_ auf unerwartete Privilegien überprüfen, die Benutzern gewährt wurden.\
Suche schließlich nach Konten mit **keinen Passwörtern** oder **leicht zu erratenden** Passwörtern.

## Dateisystem untersuchen

### Analyse von Dateisystemstrukturen bei Malware-Untersuchungen

Bei der Untersuchung von Malware-Vorfällen ist die Struktur des Dateisystems eine entscheidende Informationsquelle, da sie sowohl die Abfolge der Ereignisse als auch den Inhalt der Malware offenlegt. Allerdings entwickeln Malware-Autoren Techniken, um diese Analyse zu erschweren, etwa durch das Ändern von Dateizeitstempeln oder dadurch, dass sie das Dateisystem zur Datenspeicherung vermeiden.

Um diesen anti-forensischen Methoden entgegenzuwirken, ist es wichtig:

- **Eine gründliche Timeline-Analyse durchzuführen** mit Tools wie **Autopsy** zur Visualisierung von Ereignis-Zeitachsen oder **Sleuth Kit's** `mactime` für detaillierte Timeline-Daten.
- **Unerwartete Skripte** im $PATH des Systems zu untersuchen, darunter möglicherweise Shell- oder PHP-Skripte, die von Angreifern verwendet wurden.
- **`/dev` auf atypische Dateien zu prüfen**, da es traditionell spezielle Dateien enthält, aber auch malware-bezogene Dateien beherbergen kann.
- **Nach versteckten Dateien oder Verzeichnissen** mit Namen wie ".. " (dot dot space) oder "..^G" (dot dot control-G) zu suchen, die schädlichen Inhalt verbergen könnten.
- **setuid root-Dateien zu identifizieren** mit dem Befehl: `find / -user root -perm -04000 -print` Dies findet Dateien mit erhöhten Berechtigungen, die von Angreifern missbraucht werden könnten.
- **Löschzeitstempel** in Inode-Tabellen zu überprüfen, um massenhafte Dateilöschungen zu erkennen, was auf Rootkits oder trojans hindeuten könnte.
- **Aufeinanderfolgende Inodes zu inspizieren**, um nach der Identifizierung einer schädlichen Datei nahegelegene weitere zu finden, da sie zusammen platziert worden sein könnten.
- **Gemeinsame Binärverzeichnisse** (_/bin_, _/sbin_) auf kürzlich geänderte Dateien zu prüfen, da diese durch Malware verändert worden sein könnten.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Beachte, dass ein **attacker** die **time** **ändern** kann, um **files appear** **legitim** wirken zu lassen, aber er kann das **inode** nicht ändern. Wenn du feststellst, dass eine **file** darauf hinweist, dass sie zur **gleichen Zeit** erstellt und geändert wurde wie der Rest der files im selben Ordner, das **inode** aber **unerwartet größer** ist, dann wurden die **timestamps** dieser **file** geändert.

### Inode-focused quick triage

Wenn du Anti-Forensics vermutest, führe diese inode-focused checks früh aus:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Wenn sich ein verdächtiger Inode auf einem EXT-Dateisystem-Image/Device befindet, prüfe die Inode-Metadaten direkt:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Nützliche Felder:
- **Links**: wenn `0`, verweist aktuell kein Verzeichniseintrag auf den Inode.
- **dtime**: Löschzeitstempel, gesetzt, wenn der Inode unlinked wurde.
- **ctime/mtime**: hilft, Metadaten-/Inhaltsänderungen mit der Incident-Timeline abzugleichen.

### Capabilities, xattrs, and preload-based userland rootkits

Moderne Linux-Persistenz vermeidet oft offensichtliche `setuid`-Binaries und missbraucht stattdessen **file capabilities**, **extended attributes** und den Dynamic Loader.
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
Achte besonders auf Bibliotheken, die aus **schreibbaren** Pfaden wie `/tmp`, `/dev/shm`, `/var/tmp` oder ungewöhnlichen Orten unter `/usr/local/lib` referenziert werden. Prüfe auch Binaries mit Capabilities außerhalb der normalen Paketzuordnung und korreliere sie mit den Ergebnissen der Paketverifikation (`rpm -Va`, `dpkg --verify`, `debsums`).

## Dateien verschiedener Dateisystemversionen vergleichen

### Zusammenfassung des Vergleichs von Dateisystemversionen

Um Dateisystemversionen zu vergleichen und Änderungen genau zu erkennen, verwenden wir vereinfachte `git diff`-Befehle:

- **Um neue Dateien zu finden**, vergleiche zwei Verzeichnisse:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Für geänderten Inhalt**, liste die Änderungen auf und ignoriere dabei bestimmte Zeilen:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Um gelöschte Dateien zu erkennen**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) helfen dabei, die Ergebnisse auf bestimmte Änderungen einzugrenzen, z. B. hinzugefügte (`A`), gelöschte (`D`) oder geänderte (`M`) Dateien.
- `A`: Hinzugefügte Dateien
- `C`: Kopierte Dateien
- `D`: Gelöschte Dateien
- `M`: Geänderte Dateien
- `R`: Umbenannte Dateien
- `T`: Typänderungen (z. B. Datei zu Symlink)
- `U`: Nicht zusammengeführte Dateien
- `X`: Unbekannte Dateien
- `B`: Defekte Dateien

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [Say hi to Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [strace](https://strace.io/)
- [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
