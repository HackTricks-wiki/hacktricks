# Linux-forensika

{{#include ../../banners/hacktricks-training.md}}

## Aanvanklike inligtingversameling

### Basiese inligting

Eerstens word dit aanbeveel om ’n **USB** met **betroubare, bekende binaries en libraries daarop** te hê (jy kan eenvoudig Ubuntu kry en die vouers _/bin_, _/sbin_, _/lib,_ en _/lib64_ kopieer), dan die USB te mount en die env variables te wysig om daardie binaries te gebruik:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Sodra jy die stelsel ingestel het om goeie en bekende binaries te gebruik, kan jy begin om **basiese inligting te onttrek**:
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
#### Verdagte inligting

Terwyl jy die basiese inligting verkry, moet jy kyk vir vreemde dinge soos:

- **Root processes** loop gewoonlik met lae PIDS, so as jy ’n root process met ’n groot PID vind, kan jy dit verdag vind
- Gaan **registered logins** van gebruikers sonder ’n shell binne `/etc/passwd` na
- Gaan na **password hashes** binne `/etc/shadow` vir gebruikers sonder ’n shell

### Memory Dump

Om die memory van die lopende stelsel te verkry, word dit aanbeveel om [**LiME**](https://github.com/504ensicsLabs/LiME) te gebruik.\
Om dit te **compile**, moet jy dieselfde **kernel** gebruik as wat die victim machine gebruik.

> [!TIP]
> Onthou dat jy **nie LiME of enigiets anders op die victim machine kan installeer nie**, aangesien dit verskeie veranderinge daaraan sal aanbring

As jy dus ’n identiese weergawe van Ubuntu het, kan jy `apt-get install lime-forensics-dkms` gebruik\
In ander gevalle moet jy [**LiME**](https://github.com/504ensicsLabs/LiME) vanaf github aflaai en dit met die korrekte **kernel headers** compile. Om die **presiese kernel headers** van die victim machine te **verkry**, kan jy eenvoudig die directory `/lib/modules/<kernel version>` na jou machine **kopieer**, en dan LiME daarmee compile:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME ondersteun 3 **formate**:

- Raw (elke segment aaneengeskakel)
- Padded (dieselfde as raw, maar met nulle in die regte bisse)
- Lime (aanbevole formaat met metadata

LiME kan ook gebruik word om die **dump via die netwerk te stuur** in plaas daarvan om dit op die stelsel te stoor, deur iets soos: `path=tcp:4444`

### Skyfbeeldvorming

#### Afskakeling

Eerstens sal jy die **stelsel moet afskakel**. Dit is nie altyd 'n opsie nie, aangesien die stelsel soms 'n produksiebediener sal wees wat die maatskappy nie kan bekostig om af te skakel nie.\
Daar is **2 maniere** om die stelsel af te skakel: 'n **normale afskakeling** en 'n **afskakeling deur die prop uit te trek**. Die eerste een sal die **prosesse toelaat om soos gewoonlik te termineer** en die **lêerstelsel** te **sinchroniseer**, maar dit sal ook moontlike **malware** toelaat om **bewyse te vernietig**. Die benadering om die **prop uit te trek** kan **'n mate van inligtingsverlies** veroorsaak (nie veel van die inligting sal verlore gaan nie, aangesien ons reeds 'n beeld van die geheue geneem het), en die **malware sal geen geleentheid hê** om enigiets daaraan te doen nie. Daarom, as jy **vermoed** dat daar moontlik **malware** is, voer eenvoudig die **`sync`** **command** op die stelsel uit en trek die prop uit.

#### Neem 'n beeld van die skyf

Dit is belangrik om daarop te let dat **voordat jy jou rekenaar aan enigiets koppel wat met die saak verband hou**, jy seker moet wees dat dit as **slegs-lees** gemonteer gaan word, om te voorkom dat enige inligting gewysig word.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Vooranalise van skyfbeeld

Die skep van 'n beeld van 'n skyfbeeld met geen verdere data nie.
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

### Gewysigde stelsellêers

Linux bied nutsprogramme om die integriteit van stelselkomponente te verseker, wat noodsaaklik is om moontlik problematiese lêers op te spoor.<sup>[[1]](#references)</sup>

- **RedHat-gebaseerde stelsels**: Gebruik `rpm -Va` vir ’n omvattende kontrole.
- **Debian-gebaseerde stelsels**: Gebruik `dpkg --verify` vir aanvanklike verifikasie, gevolg deur `debsums | grep -v "OK$"` (nadat `debsums` met `apt-get install debsums` geïnstalleer is) om enige probleme te identifiseer.

### Malware/Rootkit-detektors

Lees die volgende bladsy om meer te leer oor nutsprogramme wat nuttig kan wees om malware te vind:


{{#ref}}
malware-analysis.md
{{#endref}}

## Soek geïnstalleerde programme

Om doeltreffend na geïnstalleerde programme op beide Debian- en RedHat-stelsels te soek, oorweeg dit om stelsellogboeke en databasisse saam met handmatige kontroles in algemene gidse te gebruik.<sup>[[1]](#references)</sup>

- Vir Debian, inspekteer _**`/var/lib/dpkg/status`**_ en _**`/var/log/dpkg.log`**_ om besonderhede oor pakketinstallasies te verkry, en gebruik `grep` om vir spesifieke inligting te filter.
- RedHat-gebruikers kan die RPM-databasis met `rpm -qa --root=/mntpath/var/lib/rpm` navraag doen om geïnstalleerde pakkette te lys.

Om sagteware te ontdek wat handmatig of buite hierdie pakketbestuurders geïnstalleer is, ondersoek gidse soos _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, en _**`/sbin`**_. Kombineer gidslyste met stelselspesifieke opdragte om uitvoerbare lêers te identifiseer wat nie met bekende pakkette geassosieer word nie, en verbeter sodoende jou soektog na alle geïnstalleerde programme.
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
## Herwin Verwyderde Lopende Binaries

Stel jou ’n proses voor wat vanaf /tmp/exec uitgevoer en daarna verwyder is. Dit is moontlik om dit te onttrek.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Syscall Trace Triage met SQLite en FTS5

Wanneer ’n proses steeds loop of weer in ’n lab uitgevoer kan word, kan **`strace`** ’n vinnige gedrags-spoor verskaf sonder dat kernel modules of volledige EDR-telemetrie nodig is. Vir groot traces, vermy dit om die raw log direk te lees of dit in ’n LLM te plak: stoor dit in ’n **SQLite**-databasis en query slegs die minimale subset wat jy nodig het.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> Om **`strace`** aan ’n proses te attach, verander die prosestydsberekening en kan dit race conditions of ander sensitiewe bugs beïnvloed. Verkies reproduksie op ’n kopie/lab-stelsel waar moontlik.

### Vaslegging

Vir ’n nuwe proses:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Vir ’n lopende proses:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Nuttige opsies:

- `-ff`: volg forks/threads en behou afsonderlike uitvoer per proses
- `-ttt`: epoch-tydstempels vir maklike tydlynkorrelasie
- `-yy`: los lêerbeskrywers op na ondersteunende paaie/sockets waar moontlik
- `-s 4096`: voorkom dat lang pad- en bufferargumente afgekap word

### Normaliseer

'n Praktiese skema is een ry per syscall en een ry per argument:
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
Dit vermy pogings om heterogene syscall-reëls in ’n enkele breë tabel plat te slaan en hou joins voorspelbaar tydens triage.

### Indekseer teks-swaar argumente met FTS5

Naïewe padsoektogte met `LIKE "%...%"` word baie stadig op groot traces. Skep ’n FTS5-indeks vir argumentteks en soek eerder daarin:
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
### High-signal investigations

- **PATH hijacking / fake sudo**: soek na skryfaksies en `chmod`/`rename`-aktiwiteit onder `~/.local/bin/`, en korreleer dit dan met latere `execve` van name wat bevoorreg lyk, soos `sudo`.
- **TOCTOU on temporary files**: volg dieselfde `/tmp/...`-pad oor `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` en `execve` om gapings tussen kontrole en gebruik te identifiseer.
- **Crash root cause**: korreleer `mmap` van ’n lêer met skryfaksies of afkapping van dieselfde inode/pad deur ’n ander proses, en ondersoek dan die sein-/afsluitvolgorde vir `SIGBUS`.
- **Network destination recovery**: filtreer `connect`, `sendto`, `sendmsg`, `recvfrom` en socket-verwante argumente om peer-IP’s en poorte te onttrek.

### LLM-assisted trace analysis

As jy ’n LLM wil gebruik, stel ’n **read-only** SQLite-handle bloot en gee dit die volledige skema. Laat dit rou SQL uitreik in plaas daarvan om die databasis agter beperkte helper-funksies te verberg. Dit werk gewoonlik beter vir joins, temporale korrelasie en FTS-opsoeke.

Praktiese reëls:

- Hou die databasis read-only, byvoorbeeld met `sqlite3 'file:trace.db?mode=ro'`.
- Gee die model voorbeelde van geldige `JOIN`- en `FTS5 MATCH`-navrae.
- Moet **nie** rou multi-GB `strace`-logs in die prompt plak nie.
- Vra gefokusde vrae soos:
- "Lys volgehoue lêers wat deur hierdie program geskryf is."
- "Het dit uitvoerbare lêers in gebruiker-beheerde PATH-gidse geskep of vervang?"
- "Verduidelik waarom hierdie trace met SIGBUS eindig."

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
#### Soektog: Cron/Anacron-misbruik via 0anacron en verdagte stubs
Aanvallers wysig dikwels die 0anacron-stub wat in elke /etc/cron.*/-gids voorkom om periodieke uitvoering te verseker.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH-hardening-terugrol en backdoor-shells
Veranderinge aan sshd_config en stels elrekening se shells is algemene post-exploitation-tegnieke om toegang te behou.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Soektog: Cloud C2-merkers (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons gebruik tipies api.dropboxapi.com of content.dropboxapi.com oor HTTPS met Authorization: Bearer-tokens.
- Soek in proxy/Zeek/NetFlow vir onverwagte Dropbox-egress vanaf bedieners.
- Cloudflare Tunnel (`cloudflared`) verskaf rugsteun-C2 oor uitgaande 443.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Dienste

Paaie waar malware as ’n diens geïnstalleer kan word:

- **/etc/inittab**: Roep initialiseringsskripte soos rc.sysinit aan en verwys verder na opstartscripte.
- **/etc/rc.d/** en **/etc/rc.boot/**: Bevat skripte vir diensopstart; laasgenoemde word in ouer Linux-weergawes gevind.
- **/etc/init.d/**: Word in sekere Linux-weergawes, soos Debian, gebruik om opstartscripte te stoor.
- Dienste kan ook via **/etc/inetd.conf** of **/etc/xinetd/** geaktiveer word, afhangend van die Linux-variant.
- **/etc/systemd/system**: ’n Gids vir system- en diensbestuurderskripte.
- **/etc/systemd/system/multi-user.target.wants/**: Bevat skakels na dienste wat in ’n multi-user runlevel begin moet word.
- **/usr/local/etc/rc.d/**: Vir pasgemaakte of derdeparty-dienste.
- **\~/.config/autostart/**: Vir gebruiker-spesifieke outomatiese opstarttoepassings, wat ’n wegsteekplek vir gebruikergeteikende malware kan wees.
- **/lib/systemd/system/**: Stelselwye verstek-unit-lêers wat deur geïnstalleerde pakkette verskaf word.

#### Hunt: systemd timers and transient units

Systemd-persistentie is nie beperk tot `.service`-lêers nie. Ondersoek `.timer`-units, gebruiker-vlak-units en **transient units** wat tydens runtime geskep word.
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
Transient-eenhede is maklik om mis te kyk omdat `/run/systemd/transient/` **nie-persistent** is nie. As jy ’n lewendige image versamel, kopieer dit voordat die stelsel afskakel.

### Kernel Modules

Linux-kernelmodules, wat dikwels deur malware as rootkit-komponente gebruik word, word tydens stelselselflaai gelaai. Die gidse en lêers wat belangrik is vir hierdie modules, sluit in:

- **/lib/modules/$(uname -r)**: Bevat modules vir die lopende kernelweergawe.
- **/etc/modprobe.d**: Bevat konfigurasielêers om modulelaaiing te beheer.
- **/etc/modprobe** en **/etc/modprobe.conf**: Lêers vir globale module-instellings.

### Ander outomatiese opstart-liggings

Linux gebruik verskeie lêers om programme outomaties uit te voer wanneer ’n gebruiker aanmeld, wat moontlik malware kan bevat:

- **/etc/profile.d/**\*, **/etc/profile**, en **/etc/bash.bashrc**: Word vir enige gebruiker se aanmelding uitgevoer.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, en **~/.config/autostart**: Gebruikerspesifieke lêers wat tydens hul aanmelding uitgevoer word.
- **/etc/rc.local**: Loop nadat alle stelseldienste begin het, wat die einde van die oorgang na ’n multiuser-omgewing aandui.

## Ondersoek logs

Linux-stelsels hou gebruikersaktiwiteite en stelselgebeure deur verskeie loglêers dop. Hierdie logs is belangrik om ongemagtigde toegang, malware-infeksies en ander sekuriteitsinsidente te identifiseer.<sup>[[2]](#references)</sup> Belangrike loglêers sluit in:

- **/var/log/syslog** (Debian) of **/var/log/messages** (RedHat): Leg stelselwye boodskappe en aktiwiteite vas.
- **/var/log/auth.log** (Debian) of **/var/log/secure** (RedHat): Teken authentication-pogings en suksesvolle en mislukte aanmeldings aan.
- Gebruik `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` om relevante authentication-gebeure te filter.
- **/var/log/boot.log**: Bevat stelselselflaaiboodskappe.
- **/var/log/maillog** of **/var/log/mail.log**: Teken e-posbedieneraktiwiteite aan en is nuttig om e-posverwante dienste op te spoor.
- **/var/log/kern.log**: Stoor kernelboodskappe, insluitend foute en waarskuwings.
- **/var/log/dmesg**: Bevat toestelbestuurderboodskappe.
- **/var/log/faillog**: Teken mislukte aanmeldpogings aan en help met ondersoeke na sekuriteitsbreuke.
- **/var/log/cron**: Teken cron-taakuitvoerings aan.
- **/var/log/daemon.log**: Volg agtergronddiensaktiwiteite.
- **/var/log/btmp**: Dokumenteer mislukte aanmeldpogings.
- **/var/log/httpd/**: Bevat Apache HTTPD-fout- en toegangslogs.
- **/var/log/mysqld.log** of **/var/log/mysql.log**: Teken MySQL-databasisaktiwiteite aan.
- **/var/log/xferlog**: Teken FTP-lêeroordragte aan.
- **/var/log/**: Kontroleer altyd vir onverwagte logs hier.

> [!TIP]
> Linux-stelsellogs en audit-substelsels kan tydens ’n indringing of malware-insident gedeaktiveer of verwyder word. Omdat logs op Linux-stelsels oor die algemeen van die nuttigste inligting oor kwaadwillige aktiwiteite bevat, verwyder indringers dit gereeld. Wanneer beskikbare loglêers dus ondersoek word, is dit belangrik om te kyk vir gapings of inskrywings wat buite volgorde is, aangesien dit op verwydering of peutering kan dui.

### Journald-triage (`journalctl`)

Op moderne Linux-gashere is die **systemd journal** gewoonlik die waardevolste bron vir **diensuitvoering**, **auth-gebeure**, **pakketbewerkings** en **kernel-/gebruikersruimteboodskappe**. Probeer tydens live response om beide die **persistente** journal (`/var/log/journal/`) en die **runtime** journal (`/run/log/journal/`) te bewaar, omdat kortstondige aanvalleraktiwiteit moontlik net in laasgenoemde bestaan.<sup>[[5]](#references)</sup>
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
Nuttige journal-velde vir triage sluit `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` en `MESSAGE` in. Indien journald sonder persistente berging opgestel is, verwag slegs onlangse data onder `/run/log/journal/`.

### Triage van die ouditraamwerk (`auditd`)

Indien `auditd` geaktiveer is, verkies dit wanneer jy **proses-toewysing** benodig vir lêerwysigings, opdraguitvoering, aanmeldaktiwiteit of pakketinstallasie.<sup>[[6]](#references)</sup>
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
Wanneer rules met keys deployed is, pivot vanaf hulle eerder as om raw logs te grep:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux hou 'n opdraggeskiedenis vir elke gebruiker by**, wat gestoor word in:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Verder verskaf die `last -Faiwx`-opdrag 'n lys van gebruiker-aanmeldings. Gaan dit na vir onbekende of onverwagte aanmeldings.

Gaan lêers na wat ekstra voorregte kan verleen:

- Hersien `/etc/sudoers` vir onverwagte gebruikervoorregte wat toegestaan kon wees.
- Hersien `/etc/sudoers.d/` vir onverwagte gebruikervoorregte wat toegestaan kon wees.
- Ondersoek `/etc/groups` om enige ongewone groepslidmaatskappe of toestemmings te identifiseer.
- Ondersoek `/etc/passwd` om enige ongewone groepslidmaatskappe of toestemmings te identifiseer.

Sommige toepassings genereer ook hul eie logs:

- **SSH**: Ondersoek _\~/.ssh/authorized_keys_ en _\~/.ssh/known_hosts_ vir ongemagtigde afgeleë verbindings.
- **Gnome Desktop**: Kyk in _\~/.recently-used.xbel_ vir lêers wat onlangs deur Gnome-toepassings verkry is.
- **Firefox/Chrome**: Gaan blaaiergeskiedenis en downloads in _\~/.mozilla/firefox_ of _\~/.config/google-chrome_ na vir verdagte aktiwiteite.
- **VIM**: Hersien _\~/.viminfo_ vir gebruiksbesonderhede, soos verkrygde lêerpaaie en soekgeskiedenis.
- **Open Office**: Gaan na onlangse dokumenttoegang wat op gekompromitteerde lêers kan dui.
- **FTP/SFTP**: Hersien logs in _\~/.ftp_history_ of _\~/.sftp_history_ vir lêeroordragte wat moontlik ongemagtig was.
- **MySQL**: Ondersoek _\~/.mysql_history_ vir uitgevoerde MySQL-navrae, wat moontlik ongemagtigde databasisaktiwiteite kan onthul.
- **Less**: Ontleed _\~/.lesshst_ vir gebruiksgeskiedenis, insluitend bekykte lêers en uitgevoerde opdragte.
- **Git**: Ondersoek _\~/.gitconfig_ en projek se _.git/logs_ vir veranderinge aan repositories.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) is 'n klein stuk sagteware wat in suiwer Python 3 geskryf is en Linux-loglêers (`/var/log/syslog*` of `/var/log/messages*`, afhangend van die distro) ontleed om USB-gebeurtenisgeskiedenistabelle saam te stel.

Dit is interessant om **te weet watter USB-toestelle gebruik is**, en dit sal nuttiger wees as jy 'n gemagtigde lys van USB-toestelle het om "oortredingsgebeurtenisse" te vind (die gebruik van USB-toestelle wat nie in daardie lys voorkom nie).

### Installasie
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

Ondersoek die _**/etc/passwd**_, _**/etc/shadow**_ en **sekuriteitslogboeke** vir ongewone name of rekeninge wat geskep en/of gebruik is kort ná bekende ongemagtigde gebeurtenisse. Kontroleer ook moontlike sudo brute-force-aanvalle.\
Kontroleer verder lêers soos _**/etc/sudoers**_ en _**/etc/groups**_ vir onverwagte voorregte wat aan gebruikers toegeken is.\
Soek laastens rekeninge met **geen wagwoorde** of **maklik raaibare** wagwoorde.<sup>[[1]](#references)</sup>

## Ondersoek Lêerstelsel

### Ontleding van Lêerstelselstrukture in Malware-ondersoeke

Wanneer malware-insidente ondersoek word, is die struktuur van die lêerstelsel ’n belangrike bron van inligting wat beide die volgorde van gebeure en die malware se inhoud onthul. Malware-outeurs ontwikkel egter tegnieke om hierdie ontleding te bemoeilik, soos om lêertydstempels te wysig of die lêerstelsel vir databerging te vermy.<sup>[[1]](#references)</sup>

Om hierdie anti-forensiese metodes teen te werk, is dit noodsaaklik om:

- **’n Deeglike tydlynontleding uit te voer** met nutsmiddels soos **Autopsy** om gebeurtenistydlyne te visualiseer, of **Sleuth Kit** se `mactime` vir gedetailleerde tydlyndata.
- **Onverwagte skripte** in die stelsel se $PATH te ondersoek, wat shell- of PHP-skripte kan insluit wat deur aanvallers gebruik word.
- **`/dev` vir atipiese lêers te ondersoek**, aangesien dit tradisioneel spesiale lêers bevat, maar ook malware-verwante lêers kan huisves.
- **Na versteekte lêers of gidse te soek** met name soos ".. " (kolletjie kolletjie spasie) of "..^G" (kolletjie kolletjie control-G), wat kwaadwillige inhoud kan verberg.
- **setuid root-lêers te identifiseer** deur die opdrag te gebruik: `find / -user root -perm -04000 -print` Dit vind lêers met verhoogde toestemmings, wat deur aanvallers misbruik kan word.
- **Vee-tydstempels** in inode-tabelle te hersien om massiewe lêerskrapings raak te sien, wat moontlik op die teenwoordigheid van rootkits of trojans dui.
- **Opeenvolgende inodes te inspekteer** vir nabygeleë kwaadwillige lêers nadat een geïdentifiseer is, aangesien hulle moontlik saam geplaas is.
- **Algemene binêre gidse** (_/bin_, _/sbin_) vir onlangs gewysigde lêers te kontroleer, aangesien dit deur malware verander kon wees.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Let daarop dat ’n **aanvaller** die **tyd** kan **wysig** om **lêers wettig** te laat **voorkom**, maar hy kan nie die **inode** wysig nie. As jy vind dat ’n **lêer** aandui dat dit op **dieselfde tyd** as die res van die lêers in dieselfde vouer geskep en gewysig is, maar die **inode** **onverwags groter** is, is die **tydstempels van daardie lêer gewysig**.

### Vinnige triage gefokus op inodes

As jy anti-forensics vermoed, voer hierdie inode-gefokusde kontroles vroeg uit:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Wanneer ’n verdagte inode op ’n EXT-lêerstelselbeeld/-toestel is, ondersoek die inode-metadata direk:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Nuttige velde:
- **Links**: indien `0`, verwys geen directory entry tans na die inode nie.
- **dtime**: deletion timestamp wat gestel word wanneer die inode unlinked word.
- **ctime/mtime**: help om metadata/content changes met die incident timeline te korreleer.

### Capabilities, xattrs en preload-based userland rootkits

Moderne Linux persistence vermy dikwels ooglopende **setuid** binaries en misbruik eerder **file capabilities**, **extended attributes** en die dynamic loader.
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
Gee veral aandag aan libraries waarna verwys word vanaf **skryfbare** paths soos `/tmp`, `/dev/shm`, `/var/tmp`, of ongewone liggings onder `/usr/local/lib`. Kontroleer ook binaries met capabilities buite normale package-eienaarskap en korreleer dit met package-verifikasieresultate (`rpm -Va`, `dpkg --verify`, `debsums`).

## Vergelyk files van verskillende filesystem-weergawes

### Opsomming van filesystem-weergawes se vergelyking

Om filesystem-weergawes te vergelyk en veranderinge vas te stel, gebruik ons vereenvoudigde `git diff`-commands:<sup>[[3]](#references)</sup>

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
- **Filteropsies** (`--diff-filter`) help om na spesifieke veranderinge te beperk, soos bygevoegde (`A`), verwyderde (`D`) of gewysigde (`M`) lêers.
- `A`: Bygevoegde lêers
- `C`: Gekopieerde lêers
- `D`: Verwyderde lêers
- `M`: Gewysigde lêers
- `R`: Hernoemde lêers
- `T`: Tipeveranderings (bv. lêer na symlink)
- `U`: Onsaamgevoegde lêers
- `X`: Onbekende lêers
- `B`: Gebroke lêers

## Verwysings

- [1] [Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides – Chapter 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Linux Logs Explained](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [git diff Documentation – --diff-filter option](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Say hi to Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
