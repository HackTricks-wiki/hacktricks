# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Aanvanklike Inligtinginsameling

### Basiese Inligting

In die eerste plek word dit aanbeveel om 'n paar **USB** met **goed bekende binaries en libraries daarop** te hê (jy kan net ubuntu kry en die vouers _/bin_, _/sbin_, _/lib,_ en _/lib64_ kopieer), monteer dan die USB, en wysig die omgewingsveranderlikes om daardie binaries te gebruik:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Sodra jy die stelsel gekonfigureer het om goeie en bekende binaries te gebruik, kan jy begin om **’n paar basiese inligting te onttrek**:
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

Terwyl jy die basiese inligting verkry, moet jy kyk vir vreemde dinge soos:

- **Root processes** loop gewoonlik met lae PIDS, so as jy ’n root process met ’n groot PID vind, kan jy vermoed
- Kontroleer **registered logins** van users sonder ’n shell binne `/etc/passwd`
- Kontroleer vir **password hashes** binne `/etc/shadow` vir users sonder ’n shell

### Memory Dump

Om die memory van die lopende system te verkry, word aanbeveel om [**LiME**](https://github.com/504ensicsLabs/LiME) te gebruik.\
Om dit te **compile**, moet jy dieselfde **kernel** gebruik as wat die victim machine gebruik.

> [!TIP]
> Onthou dat jy **nie LiME of enige ander thing** op die victim machine kan install nie, aangesien dit baie changes daaraan sal maak

So, as jy ’n identiese version van Ubuntu het, kan jy `apt-get install lime-forensics-dkms` gebruik\
In ander cases moet jy [**LiME**](https://github.com/504ensicsLabs/LiME) van github aflaai en dit met die korrekte kernel headers compile. Om die presiese kernel headers van die victim machine te **obtain**, kan jy eenvoudig die directory `/lib/modules/<kernel version>` na jou machine **copy**, en dan LiME daarmee **compile**:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME ondersteun 3 **formats**:

- Raw (every segment concatenated together)
- Padded (same as raw, but with zeroes in right bits)
- Lime (recommended format with metadata

LiME can also be used to **send the dump via network** instead of storing it on the system using something like: `path=tcp:4444`

### Disk Imaging

#### Shutting down

First of all, you will need to **shut down the system**. This isn't always an option as some times system will be a production server that the company cannot afford to shut down.\
There are **2 ways** of shutting down the system, a **normal shutdown** and a **"plug the plug" shutdown**. The first one will allow the **processes to terminate as usual** and the **filesystem** to be **synchronized**, but it will also allow the possible **malware** to **destroy evidence**. The "pull the plug" approach may carry **some information loss** (not much of the info is going to be lost as we already took an image of the memory ) and the **malware won't have any opportunity** to do anything about it. Therefore, if you **suspect** that there may be a **malware**, just execute the **`sync`** **command** on the system and pull the plug.

#### Taking an image of the disk

It's important to note that **before connecting your computer to anything related to the case**, you need to be sure that it's going to be **mounted as read only** to avoid modifying any information.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Skyfprent-voorontleding

Beeldvorming van ’n skyfprent met geen verdere data.
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

### Gewysigde Stelsel Lêers

Linux bied gereedskap vir die versekering van die integriteit van stelselkomponente, wat van kritieke belang is vir die opspoor van moontlik problematiese lêers.

- **RedHat-based systems**: Gebruik `rpm -Va` vir ’n omvattende kontrole.
- **Debian-based systems**: `dpkg --verify` vir aanvanklike verifikasie, gevolg deur `debsums | grep -v "OK$"` (na installering van `debsums` met `apt-get install debsums`) om enige probleme te identifiseer.

### Malware/Rootkit Detectors

Lees die volgende bladsy om meer te leer oor gereedskap wat nuttig kan wees om Malware te vind:


{{#ref}}
malware-analysis.md
{{#endref}}

## Soek geïnstalleerde programme

Om doeltreffend te soek na geïnstalleerde programme op beide Debian en RedHat systems, oorweeg dit om stelsellogboeke en databasisse te gebruik, saam met handmatige kontroles in algemene gidse.

- Vir Debian, inspekteer _**`/var/lib/dpkg/status`**_ en _**`/var/log/dpkg.log`**_ om besonderhede oor pakketinstallasies te kry, deur `grep` te gebruik om vir spesifieke inligting te filter.
- RedHat-gebruikers kan die RPM-databasis navraag doen met `rpm -qa --root=/mntpath/var/lib/rpm` om geïnstalleerde pakkette te lys.

Om sagteware te ontdek wat handmatig of buite hierdie pakketbestuurders geïnstalleer is, verken gidse soos _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, en _**`/sbin`**_. Kombineer gidslyste met stelselspesifieke opdragte om uitvoerbare lêers te identifiseer wat nie met bekende pakkette geassosieer word nie, wat jou soektog na alle geïnstalleerde programme verbeter.
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
## Herstel Verwyderde Lopende Binêre Lêers

Stel jou ’n proses voor wat vanaf /tmp/exec uitgevoer is en toe verwyder is. Dit is moontlik om dit te onttrek
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Inspekteer Autostart-liggings

### Geskeduleerde Take
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
#### Soek: Cron/Anacron-misbruik via 0anacron en verdagte stubs
Aanvallers wysig dikwels die 0anacron-stub wat onder elke /etc/cron.*/ directory voorkom om periodieke uitvoering te verseker.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Jag: SSH-verharding terugrol en agterdeur-skille
Veranderings aan sshd_config en stelselrekening-skille is algemeen ná uitbuiting om toegang te behou.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Jag: Cloud C2-merkers (Dropbox/Cloudflare Tunnel)
- Dropbox API-beacons gebruik tipies api.dropboxapi.com of content.dropboxapi.com oor HTTPS met Authorization: Bearer tokens.
- Jag in proxy/Zeek/NetFlow vir onverwagte Dropbox-egress vanaf servers.
- Cloudflare Tunnel (`cloudflared`) bied backup C2 oor uitgaande 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Paths where a malware could be installed as a service:

- **/etc/inittab**: Roep initialisering-skripte soos rc.sysinit aan, wat verder na startup-skripte lei.
- **/etc/rc.d/** en **/etc/rc.boot/**: Bevat skripte vir service-startup, met laasgenoemde wat in ouer Linux-weergawes voorkom.
- **/etc/init.d/**: Gebruik in sekere Linux-weergawes soos Debian vir die stoor van startup-skripte.
- Services kan ook geaktiveer word via **/etc/inetd.conf** of **/etc/xinetd/**, afhangend van die Linux-variant.
- **/etc/systemd/system**: 'n Gids vir system- en service manager-skripte.
- **/etc/systemd/system/multi-user.target.wants/**: Bevat skakels na services wat in 'n multi-user runlevel begin moet word.
- **/usr/local/etc/rc.d/**: Vir custom of third-party services.
- **\~/.config/autostart/**: Vir gebruiker-spesifieke outomatiese opstart-toepassings, wat 'n wegkruipplek vir user-targeted malware kan wees.
- **/lib/systemd/system/**: Stelselwye verstek unit-lêers wat deur geïnstalleerde packages verskaf word.

#### Hunt: systemd timers and transient units

Systemd persistence is not limited to `.service` files. Investigate `.timer` units, user-level units, and **transient units** created at runtime.
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
Transient units is maklik om te mis omdat `/run/systemd/transient/` **nie-volhoubaar** is. As jy ’n lewendige image insamel, gryp dit voor shutdown.

### Kernel Modules

Linux kernel modules, wat dikwels deur malware as rootkit-komponente gebruik word, word by stelsel-boot gelaai. Die directories en files wat krities is vir hierdie modules sluit in:

- **/lib/modules/$(uname -r)**: Hou modules vir die lopende kernel version.
- **/etc/modprobe.d**: Bevat configuration files om module loading te beheer.
- **/etc/modprobe** and **/etc/modprobe.conf**: Files vir globale module settings.

### Other Autostart Locations

Linux gebruik verskeie files om programmes outomaties uit te voer wanneer ’n user aanmeld, wat moontlik malware kan bevat:

- **/etc/profile.d/**\*, **/etc/profile**, and **/etc/bash.bashrc**: Word uitgevoer vir enige user login.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, and **\~/.config/autostart**: User-spesifieke files wat loop wanneer hulle aanmeld.
- **/etc/rc.local**: Loop nadat alle system services begin het, wat die einde van die oorgang na ’n multiuser environment merk.

## Examine Logs

Linux systems hou user activities en system events dop deur verskeie log files. Hierdie logs is deurslaggewend vir die identifisering van unauthorized access, malware infections, en ander security incidents. Belangrike log files sluit in:

- **/var/log/syslog** (Debian) or **/var/log/messages** (RedHat): Vang system-wide messages en activities vas.
- **/var/log/auth.log** (Debian) or **/var/log/secure** (RedHat): Rekord authentication attempts, suksesvolle en mislukte logins.
- Gebruik `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` om relevante authentication events te filter.
- **/var/log/boot.log**: Bevat system startup messages.
- **/var/log/maillog** or **/var/log/mail.log**: Log email server activities, nuttig om email-related services te volg.
- **/var/log/kern.log**: Stoor kernel messages, insluitend errors en warnings.
- **/var/log/dmesg**: Hou device driver messages.
- **/var/log/faillog**: Rekord failed login attempts, wat help met security breach investigations.
- **/var/log/cron**: Log cron job executions.
- **/var/log/daemon.log**: Volg background service activities.
- **/var/log/btmp**: Dokumenteer failed login attempts.
- **/var/log/httpd/**: Bevat Apache HTTPD error en access logs.
- **/var/log/mysqld.log** or **/var/log/mysql.log**: Log MySQL database activities.
- **/var/log/xferlog**: Rekord FTP file transfers.
- **/var/log/**: Kyk altyd hier vir onverwante logs.

> [!TIP]
> Linux system logs en audit subsystems mag gedeaktiveer of uitgevee wees in ’n intrusion of malware incident. Omdat logs op Linux systems oor die algemeen van die nuttigste inligting oor malicious activities bevat, vee intruders dit gereeld uit. Daarom, wanneer jy beskikbare log files ondersoek, is dit belangrik om te kyk vir gapings of entries wat uit volgorde is, wat ’n aanduiding van deletion of tampering kan wees.

### Journald triage (`journalctl`)

Op moderne Linux hosts is die **systemd journal** gewoonlik die bron met die hoogste waarde vir **service execution**, **auth events**, **package operations**, en **kernel/user-space messages**. Tydens live response, probeer beide die **persistent** journal (`/var/log/journal/`) en die **runtime** journal (`/run/log/journal/`) bewaar omdat kortstondige attacker activity dalk net in laasgenoemde bestaan.
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
Nuttige journal-velde vir triage sluit `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, en `MESSAGE` in. As journald gekonfigureer was sonder volgehoue berging, verwag slegs onlangse data onder `/run/log/journal/`.

### Audit framework triage (`auditd`)

As `auditd` geaktiveer is, gebruik dit verkieslik wanneer jy **process attribution** vir lêerwysigings, command execution, login activity, of package installation nodig het.
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
Wanneer reëls met keys ontplooi is, pivot van hulle af eerder as om rou logs te grep:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux handhaaf ’n opdraggeskiedenis vir elke gebruiker**, gestoor in:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Verder verskaf die `last -Faiwx` opdrag ’n lys van gebruiker-aanmeldings. Gaan dit na vir onbekende of onverwagte aanmeldings.

Gaan lêers na wat ekstra rprivileges kan gee:

- Hersien `/etc/sudoers` vir onverwagte gebruikerregte wat moontlik verleen is.
- Hersien `/etc/sudoers.d/` vir onverwagte gebruikerregte wat moontlik verleen is.
- Ondersoek `/etc/groups` om ongewone groep-lidmaatskappe of regte te identifiseer.
- Ondersoek `/etc/passwd` om ongewone groep-lidmaatskappe of regte te identifiseer.

Sommige apps genereer ook hul eie logs:

- **SSH**: Ondersoek _\~/.ssh/authorized_keys_ en _\~/.ssh/known_hosts_ vir ongemagtigde afgeleë verbindings.
- **Gnome Desktop**: Kyk in _\~/.recently-used.xbel_ vir onlangs toeganklike lêers via Gnome-toepassings.
- **Firefox/Chrome**: Gaan blaaiergeskiedenis en aflaaie in _\~/.mozilla/firefox_ of _\~/.config/google-chrome_ na vir verdagte aktiwiteite.
- **VIM**: Hersien _\~/.viminfo_ vir gebruiksbesonderhede, soos toeganklike lêerpaaie en soekgeskiedenis.
- **Open Office**: Gaan onlangse dokumenttoegang na wat gekompromitteerde lêers kan aandui.
- **FTP/SFTP**: Hersien logs in _\~/.ftp_history_ of _\~/.sftp_history_ vir lêeroordragte wat ongemagtig mag wees.
- **MySQL**: Ondersoek _\~/.mysql_history_ vir uitgevoerde MySQL-navrae, wat moontlik ongemagtigde databasisaktiwiteite kan openbaar.
- **Less**: Analiseer _\~/.lesshst_ vir gebruiksgeskiedenis, insluitend besigtigede lêers en opdragte wat uitgevoer is.
- **Git**: Ondersoek _\~/.gitconfig_ en project _.git/logs_ vir veranderinge aan repositories.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) is ’n klein stuk sagteware geskryf in suiwer Python 3 wat Linux-loglêers (`/var/log/syslog*` of `/var/log/messages*` afhangend van die distro) ontleed om USB-gebeurtenisgeskiedenis-tabelle saam te stel.

Dit is interessant om **al die USBs te ken wat gebruik is** en dit sal nuttiger wees as jy ’n gemagtigde lys van USBs het om "violation events" te vind (die gebruik van USBs wat nie in daardie lys is nie).

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
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Hersien Gebruikersrekeninge en Aanmeldaktiwiteite

Ondersoek die _**/etc/passwd**_, _**/etc/shadow**_ en **security logs** vir ongewone name of rekeninge wat geskep is en/of gebruik is naby aan bekende ongemagtigde gebeurtenisse. Kontroleer ook moontlike sudo brute-force attacks.\
Verder, kontroleer lêers soos _**/etc/sudoers**_ en _**/etc/groups**_ vir onverwagte privileges wat aan gebruikers gegee is.\
Kyk ten slotte vir rekeninge met **geen passwords** of **maklik geraaide** passwords.

## Ondersoek File System

### Ontleding van File System-strukture in Malware Investigation

Wanneer malware-voorvalle ondersoek word, is die struktuur van die file system ’n belangrike bron van inligting, wat beide die volgorde van gebeure en die malware se inhoud openbaar. Malware skrywers ontwikkel egter tegnieke om hierdie ontleding te belemmer, soos om file timestamps te verander of die file system te vermy vir data storage.

Om hierdie anti-forensic metodes teë te werk, is dit noodsaaklik om:

- **Voer ’n deeglike tydlyn-ontleding uit** met tools soos **Autopsy** vir die visualisering van gebeurtenis-tydlyne of **Sleuth Kit's** `mactime` vir gedetailleerde tydlyn-data.
- **Ondersoek onverwagte scripts** in die stelsel se $PATH, wat shell- of PHP scripts deur aanvallers kan insluit.
- **Ondersoek `/dev` vir atipiese files**, aangesien dit tradisioneel spesiale files bevat, maar moontlik malware-verwante files kan huisves.
- **Soek vir versteekte files of directories** met name soos ".. " (dot dot space) of "..^G" (dot dot control-G), wat kwaadwillige inhoud kan verberg.
- **Identifiseer setuid root files** met die command: `find / -user root -perm -04000 -print` Dit vind files met verhoogde permissions, wat deur aanvallers misbruik kan word.
- **Hersien deletion timestamps** in inode tables om massa file deletions raak te sien, wat moontlik die teenwoordigheid van rootkits of trojans aandui.
- **Inspekteer opeenvolgende inodes** vir nabygeleë kwaadwillige files nadat een geïdentifiseer is, aangesien hulle saam geplaas kon wees.
- **Kontroleer algemene binary directories** (_/bin_, _/sbin_) vir onlangs gewysigde files, aangesien hierdie deur malware verander kon word.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Let daarop dat ’n **aanvaller** die **tyd** kan **wysig** om **lêers** **legitiem** te laat lyk, maar hy **kan nie** die **inode** wysig nie. As jy vind dat ’n **lêer** aandui dat dit op dieselfde **tyd** geskep en gewysig is as die res van die lêers in dieselfde vouer, maar die **inode** onverwags groter is, dan is die **tydstempels van daardie lêer gewysig**.

### Inode-gefokusde vinnige triage

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
Wanneer ’n verdagte inode op ’n EXT-filesystem image/device is, inspekteer inode metadata direk:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Nuttige velde:
- **Links**: as `0`, verwys geen gidsinskrywing tans na die inode nie.
- **dtime**: uitvee-tydstempel wat gestel word wanneer die inode ontkoppel is.
- **ctime/mtime**: help om metadata/inhoud-veranderings met die voorvaltydlyn te korreleer.

### Capabilities, xattrs, and preload-based userland rootkits

Moderne Linux-persistensie vermy dikwels ooglopende `setuid` binaries en misbruik eerder **file capabilities**, **extended attributes**, en die dinamiese loader.
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
Gee spesiale aandag aan libraries waarna verwys word vanaf **writable** paaie soos `/tmp`, `/dev/shm`, `/var/tmp`, of vreemde liggings onder `/usr/local/lib`. Kontroleer ook capability-draende binaries buite normale package-eienaarskap en korreleer hulle met package-verifikasie-resultate (`rpm -Va`, `dpkg --verify`, `debsums`).

## Vergelyk files van verskillende filesystem-weergawes

### Filesystem Weergawe Vergelyking Opsomming

Om filesystem-weergawes te vergelyk en veranderinge presies vas te stel, gebruik ons vereenvoudigde `git diff`-commands:

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
- **Filter options** (`--diff-filter`) help narrow down to specific changes like added (`A`), deleted (`D`), or modified (`M`) files.
- `A`: Added files
- `C`: Gekopieerde files
- `D`: Deleted files
- `M`: Gewysigde files
- `R`: Hernoemde files
- `T`: Type changes (e.g., file to symlink)
- `U`: Saamgevoegde files
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

{{#include ../../banners/hacktricks-training.md}}
