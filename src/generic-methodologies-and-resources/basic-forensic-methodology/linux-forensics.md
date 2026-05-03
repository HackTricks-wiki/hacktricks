# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Aanvanklike Inligtingversameling

### Basiese Inligting

Eerstens word dit aanbeveel om 'n paar **USB** met **goed bekende binaries en libraries daarop** te hê (jy kan net ubuntu kry en die vouers _/bin_, _/sbin_, _/lib,_ en _/lib64_ kopieer), dan die USB te mount, en die env variables te wysig om daardie binaries te gebruik:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Sodra jy die stelsel gekonfigureer het om goeie en bekende binaries te gebruik, kan jy begin om **sommige basiese inligting te onttrek**:
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
#### Suspicious information

Terwyl jy die basiese inligting bekom, moet jy na vreemde dinge kyk soos:

- **Root processes** loop gewoonlik met lae PIDS, so as jy ’n root process met ’n groot PID vind, kan jy vermoed
- Kontroleer **registered logins** van users sonder ’n shell binne `/etc/passwd`
- Kontroleer vir **password hashes** binne `/etc/shadow` vir users sonder ’n shell

### Memory Dump

Om die memory van die lopende system te bekom, word dit aanbeveel om [**LiME**](https://github.com/504ensicsLabs/LiME) te gebruik.\
Om dit te **compile**, moet jy dieselfde **kernel** gebruik wat die victim machine gebruik.

> [!TIP]
> Onthou dat jy **cannot install LiME or any other thing** in the victim machine nie, aangesien dit verskeie changes daaraan sal maak

Dus, as jy ’n identiese weergawe van Ubuntu het, kan jy `apt-get install lime-forensics-dkms` gebruik\
In ander gevalle moet jy [**LiME**](https://github.com/504ensicsLabs/LiME) van github aflaai en dit met die korrekte kernel headers compile. Om die presiese kernel headers van die victim machine te **obtain**, kan jy eenvoudig die directory `/lib/modules/<kernel version>` na jou machine **copy**, en dan LiME daarmee **compile**:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME ondersteun 3 **formate**:

- Raw (elke segment saamgevoeg)
- Padded (dieselfde as raw, maar met nulle in regter bisse)
- Lime (aanbevole formaat met metadata

LiME kan ook gebruik word om die dump via netwerk te **stuur** in plaas daarvan om dit op die stelsel te stoor met iets soos: `path=tcp:4444`

### Disk Imaging

#### Afskakel

Eerstens sal jy die stelsel moet **afskakel**. Dit is nie altyd ’n opsie nie, aangesien die stelsel soms ’n produksiebediener kan wees wat die maatskappy dit nie kan bekostig om af te skakel nie.\
Daar is **2 maniere** om die stelsel af te skakel, ’n **normale afskakeling** en ’n **"plug the plug" afskakeling**. Die eerste een sal toelaat dat die **prosesse** soos gewoonlik **beëindig** en die **filesystem** **gesinchroniseer** word, maar dit sal ook die moontlike **malware** toelaat om **bewyse te vernietig**. Die "pull the plug" benadering kan **’n mate van inligtingsverlies** meebring (nie veel van die inligting gaan verlore raak nie aangesien ons reeds ’n beeld van die geheue geneem het ) en die **malware sal geen geleentheid hê** om iets daaromtrent te doen nie. Daarom, as jy **vermoed** dat daar **malware** mag wees, voer net die **`sync`** **command** op die stelsel uit en trek die prop.

#### Neem ’n beeld van die skyf

Dit is belangrik om daarop te let dat **voordat jy jou rekenaar aan enigiets koppel wat met die saak verband hou**, jy seker moet wees dat dit **as read only gemonteer** gaan word om te verhoed dat enige inligting gewysig word.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Diskbeeld voor-analise

Beeldvorming van 'n skyfbeeld met geen meer data.
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
## Soek vir bekende Malware

### Gewysigde Stelsellêers

Linux bied gereedskap om die integriteit van stelselkomponente te verseker, noodsaaklik om potensieel problematiese lêers raak te sien.

- **RedHat-gebaseerde stelsels**: Gebruik `rpm -Va` vir ’n omvattende kontrole.
- **Debian-gebaseerde stelsels**: `dpkg --verify` vir aanvanklike verifikasie, gevolg deur `debsums | grep -v "OK$"` (nadat `debsums` met `apt-get install debsums` geïnstalleer is) om enige probleme te identifiseer.

### Malware/Rootkit-Detectors

Lees die volgende bladsy om meer te leer oor tools wat nuttig kan wees om malware te vind:


{{#ref}}
malware-analysis.md
{{#endref}}

## Soek geïnstalleerde programme

Om geïnstalleerde programme doeltreffend op beide Debian- en RedHat-stelsels te soek, oorweeg dit om stelsellogboeke en databasisse saam met handmatige kontroles in algemene gidse te gebruik.

- Vir Debian, inspekteer _**`/var/lib/dpkg/status`**_ en _**`/var/log/dpkg.log`**_ om besonderhede oor pakketinstallasies te haal, deur `grep` te gebruik om vir spesifieke inligting te filter.
- RedHat-gebruikers kan die RPM-databasis met `rpm -qa --root=/mntpath/var/lib/rpm` navraag doen om geïnstalleerde pakkette te lys.

Om sagteware te ontdek wat handmatig of buite hierdie package managers geïnstalleer is, verken gidse soos _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, en _**`/sbin`**_. Kombineer gidslyste met stelselspesifieke commands om uitvoerbare lêers te identifiseer wat nie met bekende pakkette geassosieer word nie, en verbeter so jou soektog na alle geïnstalleerde programme.
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
## Herstel Verwyderde Lopende Binaries

Stel jou ’n proses voor wat vanaf /tmp/exec uitgevoer is en toe verwyder is. Dit is moontlik om dit uit te haal
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Syscall Trace Triage with SQLite and FTS5

Wanneer ’n proses nog loop of in ’n lab weer uitgevoer kan word, kan **`strace`** ’n vinnige gedrags-trace verskaf sonder om kernel modules of volledige EDR telemetry nodig te hê. Vir groot traces, vermy om die rou log direk te lees of dit in ’n LLM te plak: stoor dit in ’n **SQLite** database en vra slegs die minimale subset op wat jy nodig het.

> [!WARNING]
> Die aanheg van `strace` verander proses-timings en kan race conditions of ander brose bugs beïnvloed. Verkies om dit op ’n kopie/lab-stelsel te reproduseer wanneer moontlik.

### Capture

Vir ’n nuwe proses:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Vir 'n lewende proses:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Nuttige opsies:

- `-ff`: volg forks/threads en hou per-proses uitsette
- `-ttt`: epoch-tydstempels vir maklike tydlyn-korrelasie
- `-yy`: los file descriptors op na onderliggende paths/sockets wanneer moontlik
- `-s 4096`: keer dat lang path- en buffer-argumente afgekort word

### Normaliseer

’n Praktiese skema is een ry per syscall en een ry per argument:
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
Dit vermy die poging om heterogene syscall-lyne in een breë tabel te plat te maak en hou joins voorspelbaar tydens triage.

### Index teks-swaar arguments met FTS5

Naïewe path hunting met `LIKE "%...%"` raak baie stadig op groot traces. Skep eerder ’n FTS5-index vir argument teks en search dit:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Voorbeeld: herstel lêeraktiwiteit onder `/tmp` sonder om elke ry te skandeer:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Hoë-sein ondersoeke

- **PATH hijacking / fake sudo**: soek vir writes en `chmod`/`rename`-aktiwiteit onder `~/.local/bin/`, en korreleer dit dan met latere `execve` van voorregte-agtige name soos `sudo`.
- **TOCTOU op tydelike files**: pivot op dieselfde `/tmp/...` path oor `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink`, en `execve` om check/use-gapings te identifiseer.
- **Crash root cause**: korreleer `mmap` van ’n file met writes of truncation van dieselfde inode/path deur ’n ander process, en inspekteer dan die signal/exit-volgorde vir `SIGBUS`.
- **Network destination recovery**: filter `connect`, `sendto`, `sendmsg`, `recvfrom`, en socket-related arguments om peer IPs en ports uit te trek.

### LLM-assisted trace analysis

As jy wil hê ’n LLM moet help, stel ’n **read-only** SQLite handle bloot en gee dit die volle schema. Laat dit raw SQL uitreik in plaas daarvan om die database agter nou helper functions te verskuil. Dit werk gewoonlik beter vir joins, temporal correlation, en FTS lookups.

Praktiese reëls:

- Hou die database read-only, byvoorbeeld met `sqlite3 'file:trace.db?mode=ro'`.
- Gee die model voorbeelde van geldige `JOIN`- en `FTS5 MATCH` queries.
- Plak **nie** raw multi-GB `strace` logs in die prompt nie.
- Stel gefokusde vrae soos:
- "List persistent files written by this program."
- "Did it create or replace executables in user-controlled PATH directories?"
- "Explain why this trace ends in SIGBUS."

## Inspekteer Autostart locations

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
#### Jag: Cron/Anacron-misbruik via 0anacron en verdagte stubs
Aanvallers redigeer dikwels die 0anacron-stub wat onder elke /etc/cron.*/ directory teenwoordig is om periodieke uitvoering te verseker.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Jag: SSH-verharding-terugrol en agterdeur-doppe
Veranderings aan sshd_config en stelselrekening-doppe is algemeen na uitbuiting om toegang te behou.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons gebruik tipies api.dropboxapi.com of content.dropboxapi.com oor HTTPS met Authorization: Bearer tokens.
- Hunt in proxy/Zeek/NetFlow vir onverwachte Dropbox egress vanaf servers.
- Cloudflare Tunnel (`cloudflared`) bied backup C2 oor outbound 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Paaie waar 'n malware as 'n service geïnstalleer kan word:

- **/etc/inittab**: Roep initialisasie-skripte soos rc.sysinit aan, wat verder na startup-skripte lei.
- **/etc/rc.d/** en **/etc/rc.boot/**: Bevat skripte vir service-aanvang, laasgenoemde word in ouer Linux-weergawes gevind.
- **/etc/init.d/**: Word in sekere Linux-weergawes soos Debian gebruik vir die stoor van startup-skripte.
- Services kan ook geaktiveer word via **/etc/inetd.conf** of **/etc/xinetd/**, afhangend van die Linux-variant.
- **/etc/systemd/system**: ’n Gids vir system- en service manager-skripte.
- **/etc/systemd/system/multi-user.target.wants/**: Bevat skakels na services wat in ’n multi-user runlevel begin moet word.
- **/usr/local/etc/rc.d/**: Vir pasgemaakte of derdeparty services.
- **\~/.config/autostart/**: Vir gebruiker-spesifieke outomatiese startup-toepassings, wat ’n wegkruipplek vir user-targeted malware kan wees.
- **/lib/systemd/system/**: System-wide verstek unit-lêers wat deur geïnstalleerde packages voorsien word.

#### Hunt: systemd timers and transient units

Systemd persistence is nie beperk tot `.service`-lêers nie. Ondersoek `.timer` units, user-level units, en **transient units** wat tydens runtime geskep word.
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
Transient units is maklik om te mis omdat `/run/systemd/transient/` **nie-persistent** is. As jy ’n live image versamel, gryp dit voor shutdown.

### Kernel Modules

Linux kernel modules, wat dikwels deur malware as rootkit-komponente gebruik word, word by system boot gelaai. Die directories en files wat krities vir hierdie modules is, sluit in:

- **/lib/modules/$(uname -r)**: Bevat modules vir die lopende kernel weergawe.
- **/etc/modprobe.d**: Bevat configuration files om module loading te beheer.
- **/etc/modprobe** en **/etc/modprobe.conf**: Files vir globale module settings.

### Other Autostart Locations

Linux gebruik verskeie files om programmes outomaties uit te voer wanneer ’n user aanmeld, wat moontlik malware kan huisves:

- **/etc/profile.d/**\*, **/etc/profile**, en **/etc/bash.bashrc**: Word uitgevoer vir enige user login.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, en **\~/.config/autostart**: User-spesifieke files wat loop wanneer hulle aanmeld.
- **/etc/rc.local**: Loop nadat alle system services begin het, en merk die einde van die oorgang na ’n multiuser environment.

## Examine Logs

Linux systems hou user activities en system events dop deur verskeie log files. Hierdie logs is deurslaggewend om unauthorized access, malware infections, en ander security incidents te identifiseer. Belangrike log files sluit in:

- **/var/log/syslog** (Debian) of **/var/log/messages** (RedHat): Vang system-wide messages en activities vas.
- **/var/log/auth.log** (Debian) of **/var/log/secure** (RedHat): Neem authentication attempts, suksesvolle en mislukte logins op.
- Gebruik `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` om relevante authentication events te filter.
- **/var/log/boot.log**: Bevat system startup messages.
- **/var/log/maillog** of **/var/log/mail.log**: Log email server activities, nuttig om email-related services te volg.
- **/var/log/kern.log**: Stoor kernel messages, insluitend errors en warnings.
- **/var/log/dmesg**: Bevat device driver messages.
- **/var/log/faillog**: Teken failed login attempts aan, wat help met security breach investigations.
- **/var/log/cron**: Log cron job executions.
- **/var/log/daemon.log**: Volg background service activities.
- **/var/log/btmp**: Dokumenteer failed login attempts.
- **/var/log/httpd/**: Bevat Apache HTTPD error en access logs.
- **/var/log/mysqld.log** of **/var/log/mysql.log**: Log MySQL database activities.
- **/var/log/xferlog**: Teken FTP file transfers aan.
- **/var/log/**: Kyk altyd vir onverwante logs hier.

> [!TIP]
> Linux system logs en audit subsystems kan gedeaktiveer of uitgevee word in ’n intrusion of malware incident. Omdat logs op Linux systems gewoonlik van die nuttigste inligting oor malicious activities bevat, vee intruders dit gereeld uit. Daarom, wanneer beskikbare log files ondersoek word, is dit belangrik om na gaps of entries wat uit volgorde is te kyk, wat ’n aanduiding van deletion of tampering kan wees.

### Journald triage (`journalctl`)

Op moderne Linux hosts is die **systemd journal** gewoonlik die bron met die hoogste waarde vir **service execution**, **auth events**, **package operations**, en **kernel/user-space messages**. Tydens live response, probeer om beide die **persistent** journal (`/var/log/journal/`) en die **runtime** journal (`/run/log/journal/`) te bewaar, want kortstondige attacker activity mag net in laasgenoemde bestaan.
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
Nuttige journal-velde vir triage sluit `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, en `MESSAGE` in. As journald gekonfigureer was sonder persistente berging, verwag slegs onlangse data onder `/run/log/journal/`.

### Audit framework triage (`auditd`)

As `auditd` geaktiveer is, verkies dit wanneer jy **process attribution** nodig het vir lêerwysigings, cmd-uitvoering, aanmeldaktiwiteit, of pakkie-installasie.
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
Wanneer rules met keys ontplooi is, pivot vanaf hulle in plaas daarvan om raw logs te grep:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux handhaaf ’n command history vir elke gebruiker**, gestoor in:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Verder verskaf die `last -Faiwx` command ’n lys van gebruiker-aanmeldings. Kontroleer dit vir onbekende of onverwagte aanmeldings.

Kontroleer files wat ekstra rprivileges kan verleen:

- Hersien `/etc/sudoers` vir onverwagte user privileges wat moontlik verleen is.
- Hersien `/etc/sudoers.d/` vir onverwagte user privileges wat moontlik verleen is.
- Ondersoek `/etc/groups` om enige ongewone group membership of permissions te identifiseer.
- Ondersoek `/etc/passwd` om enige ongewone group membership of permissions te identifiseer.

Sommige apps genereer ook hul eie logs:

- **SSH**: Ondersoek _\~/.ssh/authorized_keys_ en _\~/.ssh/known_hosts_ vir ongemagtigde remote connections.
- **Gnome Desktop**: Kyk in _\~/.recently-used.xbel_ vir onlangs toeganklike files via Gnome applications.
- **Firefox/Chrome**: Kontroleer browser history en downloads in _\~/.mozilla/firefox_ of _\~/.config/google-chrome_ vir verdagte aktiwiteite.
- **VIM**: Hersien _\~/.viminfo_ vir usage details, soos toeganklike file paths en search history.
- **Open Office**: Kontroleer vir onlangse document access wat moontlik compromised files aandui.
- **FTP/SFTP**: Hersien logs in _\~/.ftp_history_ of _\~/.sftp_history_ vir file transfers wat moontlik ongemagtig was.
- **MySQL**: Ondersoek _\~/.mysql_history_ vir uitgevoerde MySQL queries, wat moontlik ongemagtigde database activities kan openbaar.
- **Less**: Ontleed _\~/.lesshst_ vir usage history, insluitend beskoude files en commands uitgevoer.
- **Git**: Ondersoek _\~/.gitconfig_ en project _.git/logs_ vir changes aan repositories.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) is ’n klein piece of software geskryf in suiwer Python 3 wat Linux log files (`/var/log/syslog*` or `/var/log/messages*` depending on the distro) parse om USB event history tables te bou.

Dit is interessant om **al die USBs te ken wat gebruik is** en dit sal meer nuttig wees as jy ’n gemagtigde lys van USBs het om "violation events" te vind (die gebruik van USBs wat nie binne daardie lys is nie).

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Voorbeelde
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Meer voorbeelde en inligting binne die github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Hersien Gebruikersrekeninge en Aanmeldaktiwiteite

Ondersoek die _**/etc/passwd**_, _**/etc/shadow**_ en **security logs** vir ongewone name of rekeninge wat geskep is en/of gebruik is naby bekende ongemagtigde gebeure. Kontroleer ook moontlike sudo brute-force attacks.\
Kontroleer verder lêers soos _**/etc/sudoers**_ en _**/etc/groups**_ vir onverwagte privileges wat aan users gegee is.\
Laastens, kyk vir rekeninge met **geen passwords** of **maklik raaibare** passwords.

## Ondersoek File System

### Ontleding van File System Structures in Malware Investigation

Wanneer malware-insidente ondersoek word, is die struktuur van die file system ’n kritieke bron van inligting wat beide die volgorde van gebeure en die malware se inhoud openbaar. Malware outeurs ontwikkel egter tegnieke om hierdie ontleding te belemmer, soos om file timestamps te wysig of die file system te vermy vir data storage.

Om hierdie anti-forensic methods teen te werk, is dit noodsaaklik om:

- **Voer ’n deeglike timeline analysis uit** met tools soos **Autopsy** vir die visualisering van event timelines of **Sleuth Kit's** `mactime` vir gedetailleerde timeline data.
- **Ondersoek onverwagte scripts** in die system se $PATH, wat shell- of PHP scripts kan insluit wat deur attackers gebruik word.
- **Ondersoek `/dev` vir atipiese files**, aangesien dit tradisioneel special files bevat, maar malware-related files kan huisves.
- **Soek vir hidden files of directories** met name soos ".. " (dot dot space) of "..^G" (dot dot control-G), wat malicious content kan verberg.
- **Identifiseer setuid root files** met die command: `find / -user root -perm -04000 -print` Dit vind files met verhoogde permissions, wat deur attackers misbruik kan word.
- **Hersien deletion timestamps** in inode tables om mass file deletions raak te sien, moontlik ’n aanduiding van die presence van rootkits of trojans.
- **Inspekteer consecutive inodes** vir nabygeleë malicious files nadat een geïdentifiseer is, aangesien hulle moontlik saam geplaas is.
- **Kontroleer algemene binary directories** (_/bin_, _/sbin_) vir onlangs gewysigde files, aangesien hierdie deur malware verander kon wees.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Let daarop dat 'n **aanvaller** die **tyd** kan **verander** om **lêers** **legitiem** te laat **lyk**, maar hy **kan nie** die **inode** verander nie. As jy vind dat 'n **lêer** aandui dat dit op dieselfde **tyd** geskep en gewysig is as die res van die lêers in dieselfde vouer, maar die **inode** onverwags groter is, dan is die **tydstempels van daardie lêer gewysig**.

### Inode-gerigte vinnige triage

As jy anti-forensics vermoed, voer hierdie inode-gerigte kontroles vroeg uit:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Wanneer ’n verdagte inode op ’n EXT filesystem image/device is, inspekteer inode metadata direk:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Useful fields:
- **Links**: if `0`, no directory entry currently references the inode.
- **dtime**: deletion timestamp set when the inode was unlinked.
- **ctime/mtime**: helps correlate metadata/content changes with incident timeline.

### Capabilities, xattrs, and preload-based userland rootkits

Moderne Linux-persistensie vermy dikwels ooglopende `setuid` binaries en misbruik eerder **file capabilities**, **extended attributes**, en die dynamic loader.
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
Gee spesiale aandag aan libraries waarna verwys word vanaf **writable** paths soos `/tmp`, `/dev/shm`, `/var/tmp`, of vreemde liggings onder `/usr/local/lib`. Kontroleer ook vir binaries met capabilities buite normale package ownership en korreleer dit met package verification resultate (`rpm -Va`, `dpkg --verify`, `debsums`).

## Vergelyk files van verskillende filesystem weergawes

### Opsomming van Filesystem Weergawe Vergelyking

Om filesystem weergawes te vergelyk en veranderinge te identifiseer, gebruik ons vereenvoudigde `git diff` commands:

- **Om nuwe files te vind**, vergelyk twee directories:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Vir gewysigde inhoud**, lys veranderinge terwyl spesifieke reëls geïgnoreer word:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Om geskrapte lêers op te spoor**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) help om af te baken tot spesifieke veranderinge soos bygevoegde (`A`), geskrapte (`D`), of gewysigde (`M`) files.
- `A`: Bygevoegde files
- `C`: Gekopieerde files
- `D`: Geskrapte files
- `M`: Gewysigde files
- `R`: Hernoemde files
- `T`: Tipeveranderinge (bv. file na symlink)
- `U`: Nie-saamgevoegde files
- `X`: Onbekende files
- `B`: Gebreekte files

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
