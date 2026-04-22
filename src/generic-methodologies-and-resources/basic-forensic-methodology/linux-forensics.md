# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Erste Informationssammlung

### Grundlegende Informationen

Zunächst wird empfohlen, einen **USB-Stick** mit **bekannt guten Binaries und Libraries** darauf zu haben (du kannst einfach Ubuntu nehmen und die Ordner _/bin_, _/sbin_, _/lib,_ und _/lib64_ kopieren), dann den USB-Stick einhängen und die env-Variablen so anpassen, dass diese Binaries verwendet werden:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Sobald du das System so konfiguriert hast, dass es gute und bekannte Binaries verwendet, kannst du damit beginnen, **einige grundlegende Informationen zu extrahieren**:
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

- **Root processes** laufen normalerweise mit niedrigen PIDS, wenn du also einen root process mit einer hohen PID findest, kannst du etwas vermuten
- Prüfe **registrierte Logins** von Benutzern ohne shell in `/etc/passwd`
- Prüfe auf **password hashes** in `/etc/shadow` für Benutzer ohne shell

### Memory Dump

Um den Speicher des laufenden Systems zu erhalten, wird empfohlen, [**LiME**](https://github.com/504ensicsLabs/LiME) zu verwenden.\
Um es zu **kompilieren**, musst du denselben **kernel** verwenden, den die Opfermaschine nutzt.

> [!TIP]
> Denk daran, dass du **LiME oder irgendetwas anderes nicht auf der Opfermaschine installieren kannst**, da dies mehrere Änderungen daran verursachen würde

Wenn du also eine identische Version von Ubuntu hast, kannst du `apt-get install lime-forensics-dkms` verwenden\
In anderen Fällen musst du [**LiME**](https://github.com/504ensicsLabs/LiME) von github herunterladen und mit den korrekten kernel headers kompilieren. Um die **exakten kernel headers** der Opfermaschine zu erhalten, kannst du einfach das Verzeichnis `/lib/modules/<kernel version>` auf deine Maschine **kopieren** und dann LiME damit **kompilieren**:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME supports 3 **formats**:

- Raw (every segment concatenated together)
- Padded (same as raw, but with zeroes in right bits)
- Lime (recommended format with metadata

LiME can also be used to **send the dump via network** instead of storing it on the system using something like: `path=tcp:4444`

### Disk Imaging

#### Shutting down

First of all, you will need to **shut down the system**. This isn't always an option as some times system will be a production server that the company cannot afford to shut down.\
Es gibt **2 Wege**, das System herunterzufahren: ein **normales Herunterfahren** und ein **"plug the plug" Herunterfahren**. Die erste Variante ermöglicht es, dass die **Prozesse** wie gewohnt beendet werden und das **Filesystem** synchronisiert wird, aber sie gibt auch möglicher **malware** die Chance, **Beweise zu zerstören**. Der "pull the plug" Ansatz kann mit **einigen Informationsverlusten** einhergehen (nicht viel von den Informationen wird verloren gehen, da wir bereits ein Image des Speichers erstellt haben) und die **malware** bekommt **keine Gelegenheit**, etwas dagegen zu tun. Wenn du daher **vermutest**, dass **malware** vorhanden sein könnte, führe einfach den **`sync`**-**Befehl** auf dem System aus und zieh den Stecker.

#### Taking an image of the disk

Es ist wichtig zu beachten, dass **bevor du deinen Computer mit irgendetwas verbindest, das mit dem Fall zusammenhängt**, du sicherstellen musst, dass es **als read only eingehängt** wird, um zu vermeiden, dass irgendwelche Informationen verändert werden.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk-Image Voranalyse

Ein Disk-Image erstellen, wenn keine weiteren Daten vorhanden sind.
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

### Veränderte Systemdateien

Linux bietet Tools zur Sicherstellung der Integrität von Systemkomponenten, was entscheidend ist, um potenziell problematische Dateien zu erkennen.

- **RedHat-basierte Systeme**: Verwende `rpm -Va` für eine umfassende Prüfung.
- **Debian-basierte Systeme**: `dpkg --verify` für die erste Verifikation, danach `debsums | grep -v "OK$"` (nach der Installation von `debsums` mit `apt-get install debsums`), um etwaige Probleme zu identifizieren.

### Malware/Rootkit-Detektoren

Lies die folgende Seite, um mehr über Tools zu erfahren, die beim Finden von Malware nützlich sein können:


{{#ref}}
malware-analysis.md
{{#endref}}

## Installierte Programme suchen

Um installierte Programme auf Debian- und RedHat-Systemen effektiv zu suchen, solltest du Systemlogs und Datenbanken zusammen mit manuellen Prüfungen in gängigen Verzeichnissen nutzen.

- Für Debian prüfe _**`/var/lib/dpkg/status`**_ und _**`/var/log/dpkg.log`**_, um Details zu Paketinstallationen zu erhalten, und verwende `grep`, um nach spezifischen Informationen zu filtern.
- RedHat-Nutzer können die RPM-Datenbank mit `rpm -qa --root=/mntpath/var/lib/rpm` abfragen, um installierte Pakete aufzulisten.

Um Software aufzudecken, die manuell oder außerhalb dieser Package Manager installiert wurde, untersuche Verzeichnisse wie _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ und _**`/sbin`**_. Kombiniere Verzeichnisauflistungen mit systemspezifischen Befehlen, um ausführbare Dateien zu identifizieren, die nicht mit bekannten Paketen verbunden sind, und verbessere so deine Suche nach allen installierten Programmen.
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
## Autostart-Positionen überprüfen

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
#### Hunt: Cron/Anacron abuse via 0anacron and suspicious stubs
Angreifer bearbeiten oft den unter jedem /etc/cron.*/-Verzeichnis vorhandenen 0anacron-Stub, um die periodische Ausführung sicherzustellen.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Jagd: SSH-Härtungs-Rollback und Backdoor-Shells
Änderungen an sshd_config und den Shells von Systemkonten sind nach einer Kompromittierung üblich, um den Zugriff zu erhalten.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API-Beacons verwenden typischerweise api.dropboxapi.com oder content.dropboxapi.com über HTTPS mit Authorization: Bearer tokens.
- Suche in Proxy/Zeek/NetFlow nach unerwartetem Dropbox-Egress von Servern.
- Cloudflare Tunnel (`cloudflared`) bietet Backup-C2 über ausgehendes 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Pfade, an denen Malware als Service installiert werden könnte:

- **/etc/inittab**: Ruft Initialisierungsskripte wie rc.sysinit auf und leitet weiter zu Startup-Skripten.
- **/etc/rc.d/** und **/etc/rc.boot/**: Enthalten Skripte für den Service-Start, wobei letzteres in älteren Linux-Versionen zu finden ist.
- **/etc/init.d/**: Wird in bestimmten Linux-Versionen wie Debian zum Speichern von Startup-Skripten verwendet.
- Services können je nach Linux-Variante auch über **/etc/inetd.conf** oder **/etc/xinetd/** aktiviert werden.
- **/etc/systemd/system**: Ein Verzeichnis für System- und Service-Manager-Skripte.
- **/etc/systemd/system/multi-user.target.wants/**: Enthält Links zu Services, die in einem Multi-User-Runlevel gestartet werden sollen.
- **/usr/local/etc/rc.d/**: Für benutzerdefinierte oder Third-Party-Services.
- **\~/.config/autostart/**: Für benutzerspezifische automatische Startup-Anwendungen, die ein Versteck für auf Benutzer ausgerichtete Malware sein können.
- **/lib/systemd/system/**: Systemweite Standard-Unit-Dateien, die von installierten Paketen bereitgestellt werden.

#### Hunt: systemd timers and transient units

Systemd-Persistenz ist nicht auf `.service`-Dateien beschränkt. Untersuche `.timer`-Units, User-Level-Units und **transient units**, die zur Laufzeit erstellt werden.
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
Transient units sind leicht zu übersehen, weil `/run/systemd/transient/` **nicht persistent** ist. Wenn du ein Live-Image sammelst, sichere es vor dem Herunterfahren.

### Kernel Modules

Linux kernel modules, die oft von Malware als rootkit components genutzt werden, werden beim Systemstart geladen. Zu diesen Modulen wichtige Verzeichnisse und Dateien sind:

- **/lib/modules/$(uname -r)**: Enthält Module für die laufende Kernel-Version.
- **/etc/modprobe.d**: Enthält Konfigurationsdateien zur Steuerung des Modul-Ladens.
- **/etc/modprobe** und **/etc/modprobe.conf**: Dateien für globale Moduleinstellungen.

### Other Autostart Locations

Linux verwendet verschiedene Dateien zum automatischen Ausführen von Programmen beim Login eines Benutzers, die Malware enthalten können:

- **/etc/profile.d/**\*, **/etc/profile**, und **/etc/bash.bashrc**: Werden bei jedem Benutzer-Login ausgeführt.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, und **\~/.config/autostart**: Benutzerbezogene Dateien, die beim Login ausgeführt werden.
- **/etc/rc.local**: Wird nach dem Start aller Systemdienste ausgeführt und markiert das Ende der Umstellung auf eine Multiuser-Umgebung.

## Examine Logs

Linux-Systeme protokollieren Benutzeraktivitäten und Systemereignisse in verschiedenen Logdateien. Diese Logs sind entscheidend, um unbefugten Zugriff, Malware-Infektionen und andere Sicherheitsvorfälle zu erkennen. Wichtige Logdateien sind:

- **/var/log/syslog** (Debian) oder **/var/log/messages** (RedHat): Erfassen systemweite Nachrichten und Aktivitäten.
- **/var/log/auth.log** (Debian) oder **/var/log/secure** (RedHat): Zeichnen Authentifizierungsversuche sowie erfolgreiche und fehlgeschlagene Logins auf.
- Verwende `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`, um relevante Authentifizierungsereignisse zu filtern.
- **/var/log/boot.log**: Enthält Meldungen zum Systemstart.
- **/var/log/maillog** oder **/var/log/mail.log**: Protokolliert Aktivitäten des Mail-Servers, nützlich zum Nachverfolgen von E-Mail-bezogenen Diensten.
- **/var/log/kern.log**: Speichert Kernel-Meldungen, einschließlich Fehlern und Warnungen.
- **/var/log/dmesg**: Enthält Meldungen von Gerätetreibern.
- **/var/log/faillog**: Zeichnet fehlgeschlagene Login-Versuche auf und hilft bei der Untersuchung von Sicherheitsvorfällen.
- **/var/log/cron**: Protokolliert cron job Ausführungen.
- **/var/log/daemon.log**: Verfolgt Aktivitäten von Hintergrunddiensten.
- **/var/log/btmp**: Dokumentiert fehlgeschlagene Login-Versuche.
- **/var/log/httpd/**: Enthält Apache HTTPD error und access logs.
- **/var/log/mysqld.log** oder **/var/log/mysql.log**: Protokolliert MySQL-Datenbankaktivitäten.
- **/var/log/xferlog**: Zeichnet FTP-Dateiübertragungen auf.
- **/var/log/**: Immer nach unerwarteten Logs hier suchen.

> [!TIP]
> Linux system logs und audit subsystems können bei einem Einbruch oder Malware-Vorfall deaktiviert oder gelöscht worden sein. Da Logs auf Linux-Systemen im Allgemeinen einige der nützlichsten Informationen über bösartige Aktivitäten enthalten, löschen Eindringlinge sie routinemäßig. Deshalb ist es bei der Untersuchung verfügbarer Logdateien wichtig, auf Lücken oder Einträge außerhalb der Reihenfolge zu achten, die auf Löschung oder Manipulation hinweisen könnten.

### Journald triage (`journalctl`)

Auf modernen Linux-Hosts ist das **systemd journal** normalerweise die ergiebigste Quelle für **service execution**, **auth events**, **package operations** und **kernel/user-space messages**. Bei einer Live Response solltest du versuchen, sowohl das **persistente** Journal (`/var/log/journal/`) als auch das **runtime** Journal (`/run/log/journal/`) zu sichern, da kurzlebige Angreiferaktivitäten möglicherweise nur im letzteren vorhanden sind.
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
Nützliche Journal-Felder für das Triage umfassen `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` und `MESSAGE`. Wenn `journald` ohne persistenten Speicher konfiguriert war, erwarte nur aktuelle Daten unter `/run/log/journal/`.

### Triage des Audit-Frameworks (`auditd`)

Wenn `auditd` aktiviert ist, bevorzuge es immer dann, wenn du **Prozesszuordnung** für Dateiänderungen, Befehlsausführung, Login-Aktivität oder Paketinstallation benötigst.
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
Wenn Regeln mit Keys bereitgestellt wurden, pivotiere von ihnen statt rohe Logs zu greppen:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux führt für jeden Benutzer einen Befehlsverlauf**, gespeichert in:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Außerdem liefert der Befehl `last -Faiwx` eine Liste der Benutzer-Logins. Prüfe sie auf unbekannte oder unerwartete Logins.

Prüfe Dateien, die zusätzliche rprivileges gewähren können:

- Prüfe `/etc/sudoers` auf unerwartete Benutzerrechte, die möglicherweise vergeben wurden.
- Prüfe `/etc/sudoers.d/` auf unerwartete Benutzerrechte, die möglicherweise vergeben wurden.
- Untersuche `/etc/groups`, um ungewöhnliche Gruppenmitgliedschaften oder Berechtigungen zu identifizieren.
- Untersuche `/etc/passwd`, um ungewöhnliche Gruppenmitgliedschaften oder Berechtigungen zu identifizieren.

Einige Apps erzeugen ebenfalls eigene Logs:

- **SSH**: Untersuche _\~/.ssh/authorized_keys_ und _\~/.ssh/known_hosts_ auf unautorisierte Remote-Verbindungen.
- **Gnome Desktop**: Schaue in _\~/.recently-used.xbel_ nach kürzlich geöffneten Dateien über Gnome-Anwendungen.
- **Firefox/Chrome**: Prüfe den Browserverlauf und Downloads in _\~/.mozilla/firefox_ oder _\~/.config/google-chrome_ auf verdächtige Aktivitäten.
- **VIM**: Prüfe _\~/.viminfo_ auf Nutzungsdetails, wie aufgerufene Dateipfade und Suchverlauf.
- **Open Office**: Prüfe den Zugriff auf kürzlich verwendete Dokumente, der auf kompromittierte Dateien hinweisen kann.
- **FTP/SFTP**: Prüfe Logs in _\~/.ftp_history_ oder _\~/.sftp_history_ auf Dateiübertragungen, die unautorisiert sein könnten.
- **MySQL**: Untersuche _\~/.mysql_history_ auf ausgeführte MySQL-Abfragen, die möglicherweise unautorisierte Datenbankaktivitäten offenlegen.
- **Less**: Analysiere _\~/.lesshst_ auf Nutzungsverlauf, einschließlich angezeigter Dateien und ausgeführter Befehle.
- **Git**: Untersuche _\~/.gitconfig_ und das Projektverzeichnis _.git/logs_ auf Änderungen an Repositories.

### USB-Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) ist eine kleine Software, geschrieben in reinem Python 3, die Linux-Logdateien (`/var/log/syslog*` oder `/var/log/messages*` je nach Distribution) parst, um Tabellen mit USB-Ereignisverläufen zu erstellen.

Es ist interessant, **alle verwendeten USBs zu kennen**, und es ist noch nützlicher, wenn du eine autorisierte Liste von USBs hast, um „Verletzungsereignisse“ zu finden (die Verwendung von USBs, die nicht in dieser Liste enthalten sind).

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
Mehr Beispiele und Informationen im github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Review User Accounts and Logon Activities

Untersuche die _**/etc/passwd**_, _**/etc/shadow**_ und **security logs** auf ungewöhnliche Namen oder Konten, die in zeitlicher Nähe zu bekannten unautorisierten Ereignissen erstellt und/oder verwendet wurden. Außerdem mögliche sudo brute-force attacks prüfen.\
Prüfe außerdem Dateien wie _**/etc/sudoers**_ und _**/etc/groups**_ auf unerwartete Privilegien, die Benutzern gewährt wurden.\
Suche schließlich nach Konten mit **keinen Passwörtern** oder **leicht erratbaren** Passwörtern.

## Examine File System

### Analyzing File System Structures in Malware Investigation

Bei der Untersuchung von malware-Vorfällen ist die Struktur des file system eine entscheidende Informationsquelle, da sie sowohl die Abfolge der Ereignisse als auch den Inhalt der malware offenbart. Allerdings entwickeln malware-Autoren Techniken, um diese Analyse zu erschweren, etwa durch das Ändern von file timestamps oder indem sie das file system zur Datenspeicherung vermeiden.

Um diesen anti-forensic Methoden entgegenzuwirken, ist es wichtig:

- **Eine gründliche timeline analysis durchzuführen** mithilfe von Tools wie **Autopsy** zur Visualisierung von Ereignis-Timelines oder **Sleuth Kit's** `mactime` für detaillierte timeline-Daten.
- **Unerwartete scripts** im $PATH des Systems zu untersuchen, die shell- oder PHP-scripts enthalten könnten, die von Angreifern verwendet werden.
- **`/dev` auf atypische Dateien zu prüfen**, da es traditionell spezielle Dateien enthält, aber auch malware-bezogene Dateien beherbergen kann.
- **Nach versteckten Dateien oder Verzeichnissen** mit Namen wie ".. " (dot dot space) oder "..^G" (dot dot control-G) zu suchen, die bösartigen Inhalt verbergen könnten.
- **setuid root files** mit dem Befehl zu identifizieren: `find / -user root -perm -04000 -print` Dieser findet Dateien mit erhöhten Berechtigungen, die von Angreifern missbraucht werden könnten.
- **Lösch-Zeitstempel** in inode tables zu überprüfen, um massenhafte Dateilöschungen zu erkennen, was möglicherweise auf die Präsenz von rootkits oder trojans hinweist.
- **Aufeinanderfolgende inodes** zu inspizieren, um benachbarte bösartige Dateien zu finden, nachdem eine identifiziert wurde, da sie möglicherweise zusammen abgelegt wurden.
- **Gemeinsame binary directories** (_/bin_, _/sbin_) auf kürzlich geänderte Dateien zu prüfen, da diese durch malware verändert worden sein könnten.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Beachte, dass ein **Angreifer** die **Zeit** **ändern** kann, um **Dateien** **legitim erscheinen** zu lassen, aber er **kann** den **inode** **nicht** ändern. Wenn du feststellst, dass eine **Datei** angibt, dass sie zur **gleichen Zeit** wie der Rest der Dateien im selben Ordner erstellt und geändert wurde, der **inode** aber **unerwartet größer** ist, dann wurden die **Zeitstempel dieser Datei geändert**.

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
Wenn sich eine verdächtige Inode auf einem EXT-Dateisystem-Image/Device befindet, prüfe die Inode-Metadaten direkt:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Nützliche Felder:
- **Links**: wenn `0`, verweist aktuell kein Verzeichniseintrag auf den inode.
- **dtime**: Löschzeitstempel, der gesetzt wird, wenn der inode unlinked wurde.
- **ctime/mtime**: hilft, Metadaten-/Inhaltsänderungen mit der Incident-Zeitleiste zu korrelieren.

### Capabilities, xattrs und preload-basierte userland rootkits

Moderne Linux-Persistenz vermeidet oft offensichtliche `setuid`-Binaries und missbraucht stattdessen **file capabilities**, **extended attributes** und den dynamischen Loader.
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
Achte besonders auf Bibliotheken, die aus **beschreibbaren** Pfaden wie `/tmp`, `/dev/shm`, `/var/tmp` oder ungewöhnlichen Speicherorten unter `/usr/local/lib` referenziert werden. Prüfe außerdem Binaries mit Capabilities außerhalb der normalen Paketzuordnung und korreliere sie mit den Ergebnissen der Paketprüfung (`rpm -Va`, `dpkg --verify`, `debsums`).

## Dateien verschiedener Filesystem-Versionen vergleichen

### Zusammenfassung des Vergleichs von Filesystem-Versionen

Um Filesystem-Versionen zu vergleichen und Änderungen zu identifizieren, verwenden wir vereinfachte `git diff`-Befehle:

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
- **Filter-Optionen** (`--diff-filter`) helfen dabei, auf bestimmte Änderungen einzugrenzen, wie hinzugefügte (`A`), gelöschte (`D`) oder modifizierte (`M`) Dateien.
- `A`: Hinzugefügte Dateien
- `C`: Kopierte Dateien
- `D`: Gelöschte Dateien
- `M`: Modifizierte Dateien
- `R`: Umbenannte Dateien
- `T`: Typänderungen (z. B. Datei zu Symlink)
- `U`: Nicht zusammengeführte Dateien
- `X`: Unbekannte Dateien
- `B`: Beschädigte Dateien

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)

{{#include ../../banners/hacktricks-training.md}}
