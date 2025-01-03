# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Erste Informationssammlung

### Grundlegende Informationen

Zunächst wird empfohlen, ein **USB** mit **gut bekannten Binärdateien und Bibliotheken** darauf zu haben (Sie können einfach Ubuntu herunterladen und die Ordner _/bin_, _/sbin_, _/lib,_ und _/lib64_ kopieren), dann das USB-Laufwerk einbinden und die Umgebungsvariablen so ändern, dass diese Binärdateien verwendet werden:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Sobald Sie das System so konfiguriert haben, dass es gute und bekannte Binaries verwendet, können Sie **einige grundlegende Informationen extrahieren**:
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

Während Sie die grundlegenden Informationen abrufen, sollten Sie nach seltsamen Dingen suchen wie:

- **Root-Prozesse** laufen normalerweise mit niedrigen PIDs, also wenn Sie einen Root-Prozess mit einer großen PID finden, können Sie Verdacht schöpfen
- Überprüfen Sie die **registrierten Logins** von Benutzern ohne eine Shell in `/etc/passwd`
- Überprüfen Sie auf **Passworthashes** in `/etc/shadow` für Benutzer ohne eine Shell

### Speicherabbild

Um den Speicher des laufenden Systems zu erhalten, wird empfohlen, [**LiME**](https://github.com/504ensicsLabs/LiME) zu verwenden.\
Um es zu **kompilieren**, müssen Sie den **gleichen Kernel** verwenden, den die Zielmaschine verwendet.

> [!NOTE]
> Denken Sie daran, dass Sie **LiME oder irgendetwas anderes** nicht auf der Zielmaschine installieren können, da dies mehrere Änderungen daran vornehmen würde

Wenn Sie also eine identische Version von Ubuntu haben, können Sie `apt-get install lime-forensics-dkms` verwenden.\
In anderen Fällen müssen Sie [**LiME**](https://github.com/504ensicsLabs/LiME) von GitHub herunterladen und es mit den richtigen Kernel-Headern kompilieren. Um die **genauen Kernel-Header** der Zielmaschine zu erhalten, können Sie einfach das **Verzeichnis** `/lib/modules/<kernel version>` auf Ihre Maschine kopieren und dann LiME mit ihnen **kompilieren**:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME unterstützt 3 **Formate**:

- Raw (jeder Abschnitt zusammengefügt)
- Padded (gleich wie raw, aber mit Nullen in den rechten Bits)
- Lime (empfohlenes Format mit Metadaten)

LiME kann auch verwendet werden, um den **Dump über das Netzwerk zu senden**, anstatt ihn auf dem System zu speichern, indem man etwas wie: `path=tcp:4444` verwendet.

### Festplattenabbildung

#### Herunterfahren

Zunächst müssen Sie das **System herunterfahren**. Dies ist nicht immer eine Option, da das System manchmal ein Produktionsserver ist, den sich das Unternehmen nicht leisten kann, herunterzufahren.\
Es gibt **2 Möglichkeiten**, das System herunterzufahren: ein **normales Herunterfahren** und ein **"Stecker ziehen" Herunterfahren**. Das erste ermöglicht es den **Prozessen, wie gewohnt zu beenden** und das **Dateisystem** zu **synchronisieren**, aber es ermöglicht auch, dass mögliche **Malware** **Beweise zerstört**. Der "Stecker ziehen"-Ansatz kann **einige Informationsverluste** mit sich bringen (nicht viele Informationen werden verloren gehen, da wir bereits ein Abbild des Speichers erstellt haben) und die **Malware wird keine Gelegenheit haben**, etwas dagegen zu unternehmen. Daher, wenn Sie **verdächtigen**, dass es **Malware** geben könnte, führen Sie einfach den **`sync`** **Befehl** auf dem System aus und ziehen Sie den Stecker.

#### Erstellen eines Abbilds der Festplatte

Es ist wichtig zu beachten, dass Sie **bevor Sie Ihren Computer mit etwas, das mit dem Fall zu tun hat, verbinden**, sicherstellen müssen, dass er als **schreibgeschützt** **gemountet** wird, um zu vermeiden, dass Informationen verändert werden.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Image Voranalyse

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
## Suche nach bekanntem Malware

### Modifizierte Systemdateien

Linux bietet Werkzeuge zur Sicherstellung der Integrität von Systemkomponenten, die entscheidend sind, um potenziell problematische Dateien zu erkennen.

- **RedHat-basierte Systeme**: Verwenden Sie `rpm -Va` für eine umfassende Überprüfung.
- **Debian-basierte Systeme**: `dpkg --verify` für die erste Überprüfung, gefolgt von `debsums | grep -v "OK$"` (nach der Installation von `debsums` mit `apt-get install debsums`), um etwaige Probleme zu identifizieren.

### Malware/Rootkit-Detektoren

Lesen Sie die folgende Seite, um mehr über Werkzeuge zu erfahren, die nützlich sein können, um Malware zu finden:

{{#ref}}
malware-analysis.md
{{#endref}}

## Suche nach installierten Programmen

Um effektiv nach installierten Programmen auf sowohl Debian- als auch RedHat-Systemen zu suchen, sollten Sie Systemprotokolle und Datenbanken zusammen mit manuellen Überprüfungen in gängigen Verzeichnissen nutzen.

- Für Debian überprüfen Sie _**`/var/lib/dpkg/status`**_ und _**`/var/log/dpkg.log`**_, um Details zu Paketinstallationen abzurufen, und verwenden Sie `grep`, um spezifische Informationen herauszufiltern.
- RedHat-Benutzer können die RPM-Datenbank mit `rpm -qa --root=/mntpath/var/lib/rpm` abfragen, um installierte Pakete aufzulisten.

Um Software zu entdecken, die manuell oder außerhalb dieser Paketmanager installiert wurde, erkunden Sie Verzeichnisse wie _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ und _**`/sbin`**_. Kombinieren Sie Verzeichnisauflistungen mit systemspezifischen Befehlen, um ausführbare Dateien zu identifizieren, die nicht mit bekannten Paketen verbunden sind, und verbessern Sie Ihre Suche nach allen installierten Programmen.
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
## Wiederherstellung gelöschter laufender Binärdateien

Stellen Sie sich einen Prozess vor, der von /tmp/exec ausgeführt und dann gelöscht wurde. Es ist möglich, ihn zu extrahieren.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Autostart-Standorte überprüfen

### Geplante Aufgaben
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
### Dienste

Pfad, wo Malware als Dienst installiert werden könnte:

- **/etc/inittab**: Ruft Initialisierungsskripte wie rc.sysinit auf und leitet weiter zu Startskripten.
- **/etc/rc.d/** und **/etc/rc.boot/**: Enthalten Skripte für den Dienststart, wobei letzteres in älteren Linux-Versionen zu finden ist.
- **/etc/init.d/**: Wird in bestimmten Linux-Versionen wie Debian zum Speichern von Startskripten verwendet.
- Dienste können auch über **/etc/inetd.conf** oder **/etc/xinetd/** aktiviert werden, abhängig von der Linux-Variante.
- **/etc/systemd/system**: Ein Verzeichnis für System- und Dienstmanager-Skripte.
- **/etc/systemd/system/multi-user.target.wants/**: Enthält Links zu Diensten, die in einem Multi-User-Runlevel gestartet werden sollen.
- **/usr/local/etc/rc.d/**: Für benutzerdefinierte oder Drittanbieter-Dienste.
- **\~/.config/autostart/**: Für benutzerspezifische automatische Startanwendungen, die ein Versteck für benutzergerichtete Malware sein können.
- **/lib/systemd/system/**: Systemweite Standard-Einheitendateien, die von installierten Paketen bereitgestellt werden.

### Kernel-Module

Linux-Kernel-Module, die oft von Malware als Rootkit-Komponenten verwendet werden, werden beim Systemstart geladen. Die für diese Module kritischen Verzeichnisse und Dateien umfassen:

- **/lib/modules/$(uname -r)**: Enthält Module für die laufende Kernel-Version.
- **/etc/modprobe.d**: Enthält Konfigurationsdateien zur Steuerung des Modul-Ladens.
- **/etc/modprobe** und **/etc/modprobe.conf**: Dateien für globale Moduleinstellungen.

### Weitere Autostart-Standorte

Linux verwendet verschiedene Dateien, um Programme automatisch beim Benutzer-Login auszuführen, die möglicherweise Malware beherbergen:

- **/etc/profile.d/**\*, **/etc/profile** und **/etc/bash.bashrc**: Werden bei jedem Benutzer-Login ausgeführt.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** und **\~/.config/autostart**: Benutzerspezifische Dateien, die beim Login ausgeführt werden.
- **/etc/rc.local**: Wird ausgeführt, nachdem alle Systemdienste gestartet wurden, und markiert das Ende des Übergangs zu einer Multiuser-Umgebung.

## Protokolle überprüfen

Linux-Systeme verfolgen Benutzeraktivitäten und Systemereignisse durch verschiedene Protokolldateien. Diese Protokolle sind entscheidend für die Identifizierung von unbefugtem Zugriff, Malware-Infektionen und anderen Sicherheitsvorfällen. Wichtige Protokolldateien umfassen:

- **/var/log/syslog** (Debian) oder **/var/log/messages** (RedHat): Erfassen systemweite Nachrichten und Aktivitäten.
- **/var/log/auth.log** (Debian) oder **/var/log/secure** (RedHat): Protokollieren Authentifizierungsversuche, erfolgreiche und fehlgeschlagene Anmeldungen.
- Verwenden Sie `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`, um relevante Authentifizierungsereignisse zu filtern.
- **/var/log/boot.log**: Enthält Systemstartnachrichten.
- **/var/log/maillog** oder **/var/log/mail.log**: Protokolliert Aktivitäten des E-Mail-Servers, nützlich zur Verfolgung von E-Mail-bezogenen Diensten.
- **/var/log/kern.log**: Speichert Kernel-Nachrichten, einschließlich Fehlern und Warnungen.
- **/var/log/dmesg**: Enthält Nachrichten von Gerätetreibern.
- **/var/log/faillog**: Protokolliert fehlgeschlagene Anmeldeversuche, was bei der Untersuchung von Sicherheitsverletzungen hilft.
- **/var/log/cron**: Protokolliert die Ausführung von Cron-Jobs.
- **/var/log/daemon.log**: Verfolgt Aktivitäten von Hintergrunddiensten.
- **/var/log/btmp**: Dokumentiert fehlgeschlagene Anmeldeversuche.
- **/var/log/httpd/**: Enthält Apache HTTPD-Fehler- und Zugriffsprotokolle.
- **/var/log/mysqld.log** oder **/var/log/mysql.log**: Protokolliert Aktivitäten der MySQL-Datenbank.
- **/var/log/xferlog**: Protokolliert FTP-Dateiübertragungen.
- **/var/log/**: Überprüfen Sie hier immer auf unerwartete Protokolle.

> [!NOTE]
> Linux-Systemprotokolle und Auditsysteme können bei einem Eindringen oder Malware-Vorfall deaktiviert oder gelöscht werden. Da Protokolle auf Linux-Systemen im Allgemeinen einige der nützlichsten Informationen über böswillige Aktivitäten enthalten, löschen Eindringlinge sie routinemäßig. Daher ist es wichtig, beim Überprüfen der verfügbaren Protokolldateien nach Lücken oder nicht in der Reihenfolge befindlichen Einträgen zu suchen, die auf Löschungen oder Manipulationen hinweisen könnten.

**Linux führt eine Befehlsverlaufshistorie für jeden Benutzer**, die gespeichert wird in:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Darüber hinaus bietet der Befehl `last -Faiwx` eine Liste der Benutzeranmeldungen. Überprüfen Sie ihn auf unbekannte oder unerwartete Anmeldungen.

Überprüfen Sie Dateien, die zusätzliche Berechtigungen gewähren können:

- Überprüfen Sie `/etc/sudoers` auf unvorhergesehene Benutzerberechtigungen, die möglicherweise gewährt wurden.
- Überprüfen Sie `/etc/sudoers.d/` auf unvorhergesehene Benutzerberechtigungen, die möglicherweise gewährt wurden.
- Untersuchen Sie `/etc/groups`, um ungewöhnliche Gruppenmitgliedschaften oder Berechtigungen zu identifizieren.
- Untersuchen Sie `/etc/passwd`, um ungewöhnliche Gruppenmitgliedschaften oder Berechtigungen zu identifizieren.

Einige Apps generieren auch ihre eigenen Protokolle:

- **SSH**: Überprüfen Sie _\~/.ssh/authorized_keys_ und _\~/.ssh/known_hosts_ auf unbefugte Remote-Verbindungen.
- **Gnome Desktop**: Überprüfen Sie _\~/.recently-used.xbel_ auf kürzlich verwendete Dateien über Gnome-Anwendungen.
- **Firefox/Chrome**: Überprüfen Sie den Browserverlauf und Downloads in _\~/.mozilla/firefox_ oder _\~/.config/google-chrome_ auf verdächtige Aktivitäten.
- **VIM**: Überprüfen Sie _\~/.viminfo_ auf Nutzungsdetails, wie z.B. aufgerufene Dateipfade und Suchverlauf.
- **Open Office**: Überprüfen Sie den Zugriff auf kürzlich verwendete Dokumente, die auf kompromittierte Dateien hinweisen könnten.
- **FTP/SFTP**: Überprüfen Sie Protokolle in _\~/.ftp_history_ oder _\~/.sftp_history_ auf Dateiübertragungen, die möglicherweise unbefugt sind.
- **MySQL**: Untersuchen Sie _\~/.mysql_history_ auf ausgeführte MySQL-Abfragen, die möglicherweise unbefugte Datenbankaktivitäten offenbaren.
- **Less**: Analysieren Sie _\~/.lesshst_ auf Nutzungshistorie, einschließlich angezeigter Dateien und ausgeführter Befehle.
- **Git**: Überprüfen Sie _\~/.gitconfig_ und Projekt _.git/logs_ auf Änderungen an Repositories.

### USB-Protokolle

[**usbrip**](https://github.com/snovvcrash/usbrip) ist ein kleines Stück Software, das in reinem Python 3 geschrieben ist und Linux-Protokolldateien (`/var/log/syslog*` oder `/var/log/messages*`, abhängig von der Distribution) analysiert, um USB-Ereignisverlaufstabellen zu erstellen.

Es ist interessant zu **wissen, welche USBs verwendet wurden**, und es wird nützlicher sein, wenn Sie eine autorisierte Liste von USBs haben, um "Verstoßereignisse" (die Verwendung von USBs, die nicht in dieser Liste enthalten sind) zu finden.

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
Mehr Beispiele und Informationen finden Sie im GitHub: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Überprüfen von Benutzerkonten und Anmeldeaktivitäten

Untersuchen Sie die _**/etc/passwd**_, _**/etc/shadow**_ und **Sicherheitsprotokolle** auf ungewöhnliche Namen oder Konten, die in unmittelbarem Zusammenhang mit bekannten unbefugten Ereignissen erstellt oder verwendet wurden. Überprüfen Sie auch mögliche sudo-Brute-Force-Angriffe.\
Darüber hinaus sollten Sie Dateien wie _**/etc/sudoers**_ und _**/etc/groups**_ auf unerwartete Berechtigungen für Benutzer überprüfen.\
Schließlich suchen Sie nach Konten mit **keinen Passwörtern** oder **leicht zu erratenden** Passwörtern.

## Untersuchen des Dateisystems

### Analyse der Dateisystemstrukturen bei Malware-Untersuchungen

Bei der Untersuchung von Malware-Vorfällen ist die Struktur des Dateisystems eine entscheidende Informationsquelle, die sowohl die Reihenfolge der Ereignisse als auch den Inhalt der Malware offenbart. Malware-Autoren entwickeln jedoch Techniken, um diese Analyse zu erschweren, wie z.B. das Ändern von Dateistempeln oder das Vermeiden des Dateisystems zur Datenspeicherung.

Um diesen anti-forensischen Methoden entgegenzuwirken, ist es wichtig:

- **Eine gründliche Zeitlinienanalyse durchzuführen** mit Tools wie **Autopsy** zur Visualisierung von Ereigniszeitlinien oder **Sleuth Kit's** `mactime` für detaillierte Zeitliniendaten.
- **Unerwartete Skripte** im $PATH des Systems zu untersuchen, die Shell- oder PHP-Skripte enthalten könnten, die von Angreifern verwendet werden.
- **`/dev` auf atypische Dateien zu überprüfen**, da es traditionell spezielle Dateien enthält, aber möglicherweise malwarebezogene Dateien beherbergt.
- **Nach versteckten Dateien oder Verzeichnissen** mit Namen wie ".. " (Punkt Punkt Leerzeichen) oder "..^G" (Punkt Punkt Steuerung-G) zu suchen, die bösartigen Inhalt verbergen könnten.
- **Setuid-Root-Dateien zu identifizieren** mit dem Befehl: `find / -user root -perm -04000 -print` Dies findet Dateien mit erhöhten Berechtigungen, die von Angreifern missbraucht werden könnten.
- **Löschzeitstempel** in Inode-Tabellen zu überprüfen, um massenhafte Dateilöschungen zu erkennen, die möglicherweise auf die Anwesenheit von Rootkits oder Trojanern hinweisen.
- **Konsekutive Inodes** auf nahegelegene bösartige Dateien zu überprüfen, nachdem eine identifiziert wurde, da sie möglicherweise zusammen platziert wurden.
- **Häufige Binärverzeichnisse** (_/bin_, _/sbin_) auf kürzlich geänderte Dateien zu überprüfen, da diese möglicherweise von Malware verändert wurden.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!NOTE]
> Beachten Sie, dass ein **Angreifer** die **Zeit** **ändern** kann, um **Dateien legitim erscheinen** zu lassen, aber er **kann** die **inode** **nicht** ändern. Wenn Sie feststellen, dass eine **Datei** angibt, dass sie zur **gleichen Zeit** wie die anderen Dateien im selben Ordner erstellt und geändert wurde, aber die **inode** **unerwartet größer** ist, dann wurden die **Zeitstempel dieser Datei geändert**.

## Vergleichen von Dateien verschiedener Dateisystemversionen

### Zusammenfassung des Dateisystemversionsvergleichs

Um Dateisystemversionen zu vergleichen und Änderungen zu identifizieren, verwenden wir vereinfachte `git diff`-Befehle:

- **Um neue Dateien zu finden**, vergleichen Sie zwei Verzeichnisse:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Für modifizierte Inhalte**: Änderungen auflisten, während spezifische Zeilen ignoriert werden:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Um gelöschte Dateien zu erkennen**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filteroptionen** (`--diff-filter`) helfen dabei, spezifische Änderungen wie hinzugefügte (`A`), gelöschte (`D`) oder modifizierte (`M`) Dateien einzugrenzen.
- `A`: Hinzugefügte Dateien
- `C`: Kopierte Dateien
- `D`: Gelöschte Dateien
- `M`: Modifizierte Dateien
- `R`: Umbenannte Dateien
- `T`: Typänderungen (z.B. Datei zu Symlink)
- `U`: Nicht zusammengeführte Dateien
- `X`: Unbekannte Dateien
- `B`: Beschädigte Dateien

## Referenzen

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Buch: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

{{#include ../../banners/hacktricks-training.md}}
