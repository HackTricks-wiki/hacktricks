# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Ukusanyaji wa Taarifa za Awali

### Taarifa za Msingi

Kwanza kabisa, inapendekezwa kuwa na baadhi ya **USB** zenye **binary na libraries nzuri zinazojulikana humo** (unaweza tu kupata ubuntu na kunakili folda _/bin_, _/sbin_, _/lib,_ na _/lib64_), kisha mount USB, na kurekebisha env variables ili kutumia hizo binaries:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Mara tu umesanidi mfumo utumie binary nzuri na zinazojulikana unaweza kuanza **kutoa taarifa za msingi**:
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

Wakati wa kupata taarifa za msingi unapaswa kuangalia mambo ya ajabu kama vile:

- **Root processes** kawaida huendeshwa na PID ndogo, kwa hiyo ukipata root process yenye PID kubwa unaweza kushuku
- Angalia **registered logins** za watumiaji wasio na shell ndani ya `/etc/passwd`
- Angalia **password hashes** ndani ya `/etc/shadow` kwa watumiaji wasio na shell

### Memory Dump

Ili kupata memory ya system inayoendelea, inapendekezwa kutumia [**LiME**](https://github.com/504ensicsLabs/LiME).\
Ili ku**compile** hiyo, unahitaji kutumia **same kernel** ambayo machine ya muathirika inatumia.

> [!TIP]
> Kumbuka kwamba huwezi kusakinisha LiME au kitu kingine chochote kwenye machine ya muathirika kwa sababu itafanya mabadiliko mengi kwake

Kwa hiyo, ikiwa una toleo sawia la Ubuntu unaweza kutumia `apt-get install lime-forensics-dkms`\
Katika hali nyingine, unahitaji kupakua [**LiME**](https://github.com/504ensicsLabs/LiME) kutoka github na kucompile kwa kutumia correct kernel headers. Ili ku**obtain the exact kernel headers** za machine ya muathirika, unaweza tu **kunakili directory** `/lib/modules/<kernel version>` kwenda kwenye machine yako, kisha **compile** LiME ukizitumia:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME inasaidia **formats** 3:

- Raw (kila segment imeunganishwa pamoja)
- Padded (kama raw, lakini kwa zeroes katika right bits)
- Lime (recommended format with metadata)

LiME pia inaweza kutumika **kutuma dump kupitia network** badala ya kuihifadhi kwenye system kwa kutumia kitu kama: `path=tcp:4444`

### Disk Imaging

#### Shutting down

Kwanza kabisa, utahitaji **kuzima system**. Hii si mara zote inawezekana kwani wakati mwingine system inaweza kuwa production server ambayo kampuni haiwezi kumudu kuizima.\
Kuna **njia 2** za kuzima system, **normal shutdown** na **"plug the plug" shutdown**. Ya kwanza itaruhusu **processes kumalizika kama kawaida** na **filesystem** kuwa **synchronized**, lakini pia itaruhusu **malware** inayowezekana **kuharibu evidence**. Njia ya "pull the plug" inaweza kuleta **upotevu fulani wa information** (si sana, kwani tayari tulichukua image ya memory) na **malware haitapata nafasi yoyote** ya kufanya kitu kuhusu hilo. Hivyo, ukihisi kwamba huenda kuna **malware**, tekeleza tu **`sync`** **command** kwenye system na uvue plug.

#### Taking an image of the disk

Ni muhimu kutambua kwamba **kabla ya kuunganisha computer yako kwenye chochote kinachohusiana na case**, unahitaji kuwa na uhakika kwamba itakuwa **mounted as read only** ili kuepuka kurekebisha taarifa yoyote.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Uchanganuzi wa awali wa Disk Image

Kutengeneza disk image bila data zaidi.
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
## Tafuta Malware inayojulikana

### Modified System Files

Linux inatoa tools za kuhakikisha integrity ya system components, muhimu kwa kutambua faili zinazoweza kuwa na shida.

- **RedHat-based systems**: Tumia `rpm -Va` kwa ukaguzi wa kina.
- **Debian-based systems**: `dpkg --verify` kwa uthibitisho wa awali, kisha `debsums | grep -v "OK$"` (baada ya kusakinisha `debsums` kwa `apt-get install debsums`) kutambua issues zozote.

### Malware/Rootkit Detectors

Soma ukurasa ufuatao ili kujifunza kuhusu tools zinazoweza kusaidia kupata malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Tafuta installed programs

Ili kutafuta kwa ufanisi installed programs kwenye Debian na RedHat systems, zingatia kutumia system logs na databases pamoja na ukaguzi wa mikono kwenye common directories.

- Kwa Debian, kagua _**`/var/lib/dpkg/status`**_ na _**`/var/log/dpkg.log`**_ ili kupata details kuhusu package installations, ukitumia `grep` kuchuja taarifa mahususi.
- Watumiaji wa RedHat wanaweza kuuliza RPM database kwa `rpm -qa --root=/mntpath/var/lib/rpm` ili kuorodhesha installed packages.

Ili kugundua software iliyosakinishwa manually au nje ya package managers hizi, chunguza directories kama _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, na _**`/sbin`**_. Changanya directory listings na system-specific commands ili kutambua executables zisizo na uhusiano na known packages, ukiimarisha utafutaji wako wa installed programs zote.
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
## Rejesha Binaries Zinazoendeshwa Zilizofutwa

Fikiria mchakato uliotekelezwa kutoka /tmp/exec kisha ukafutwa. Inawezekana kuutoa
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Kagua maeneo ya Autostart

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
Washambuliaji mara nyingi huhariri stub ya 0anacron iliyopo chini ya kila saraka ya /etc/cron.*/ ili kuhakikisha utekelezaji wa mara kwa mara.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Uwindaji: kurejesha SSH hardening na backdoor shells
Mabadiliko kwenye sshd_config na shell za akaunti za mfumo ni ya kawaida baada ya exploitation ili kuhifadhi access.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Alama za Cloud C2 (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons kawaida hutumia api.dropboxapi.com au content.dropboxapi.com kupitia HTTPS na Authorization: Bearer tokens.
- Hunt katika proxy/Zeek/NetFlow kwa unexpected Dropbox egress kutoka kwa servers.
- Cloudflare Tunnel (`cloudflared`) hutoa backup C2 kupitia outbound 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Paths ambapo malware inaweza kusanikishwa kama service:

- **/etc/inittab**: Huita initialization scripts kama rc.sysinit, na kuelekeza zaidi kwenye startup scripts.
- **/etc/rc.d/** and **/etc/rc.boot/**: Zina scripts za service startup, ya mwisho ikipatikana katika matoleo ya zamani ya Linux.
- **/etc/init.d/**: Hutumika katika baadhi ya matoleo ya Linux kama Debian kwa kuhifadhi startup scripts.
- Services pia zinaweza kuanzishwa kupitia **/etc/inetd.conf** au **/etc/xinetd/**, kutegemea aina ya Linux.
- **/etc/systemd/system**: Directory ya system na service manager scripts.
- **/etc/systemd/system/multi-user.target.wants/**: Ina links kwa services ambazo zinapaswa kuanzishwa katika multi-user runlevel.
- **/usr/local/etc/rc.d/**: Kwa custom au third-party services.
- **\~/.config/autostart/**: Kwa applications za automatic startup za mtumiaji mahususi, ambazo zinaweza kuwa mahali pa kujificha pa malware inayolenga mtumiaji.
- **/lib/systemd/system/**: System-wide default unit files zinazotolewa na packages zilizowekwa.

#### Hunt: systemd timers and transient units

Systemd persistence si kwa `.service` files pekee. Chunguza `.timer` units, user-level units, na **transient units** zilizoundwa wakati wa runtime.
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
Transient units ni rahisi kukosa kwa sababu `/run/systemd/transient/` ni **non-persistent**. Ukiwa unakusanya live image, ichukue kabla ya shutdown.

### Kernel Modules

Linux kernel modules, mara nyingi hutumiwa na malware kama rootkit components, hupakiwa wakati wa system boot. Directories na files muhimu kwa modules hizi ni pamoja na:

- **/lib/modules/$(uname -r)**: Huhifadhi modules za toleo la kernel linaloendesha.
- **/etc/modprobe.d**: Ina configuration files za kudhibiti module loading.
- **/etc/modprobe** na **/etc/modprobe.conf**: Files za global module settings.

### Other Autostart Locations

Linux hutumia files mbalimbali kwa ku-execute programs kiotomatiki wakati user anaingia, na zinaweza kuwa na malware:

- **/etc/profile.d/**\*, **/etc/profile**, na **/etc/bash.bashrc**: Hu-execute kwa user wowote anapoingia.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, na **\~/.config/autostart**: User-specific files zinazo-run wanapoingia.
- **/etc/rc.local**: Huirun baada ya system services zote kuanza, ikionyesha mwisho wa transition kwenda multiuser environment.

## Examine Logs

Linux systems hufuatilia user activities na system events kupitia log files mbalimbali. Logs hizi ni muhimu sana kwa kutambua unauthorized access, malware infections, na security incidents nyingine. Key log files ni pamoja na:

- **/var/log/syslog** (Debian) au **/var/log/messages** (RedHat): Hukamata system-wide messages na activities.
- **/var/log/auth.log** (Debian) au **/var/log/secure** (RedHat): Hurekodi authentication attempts, logins zilizofaulu na zilizoshindikana.
- Tumia `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` kuchuja authentication events zinazohusika.
- **/var/log/boot.log**: Ina messages za system startup.
- **/var/log/maillog** au **/var/log/mail.log**: Huhifadhi logs za shughuli za email server, muhimu kwa kufuatilia services zinazohusiana na email.
- **/var/log/kern.log**: Huhifadhi kernel messages, ikiwemo errors na warnings.
- **/var/log/dmesg**: Ina messages za device driver.
- **/var/log/faillog**: Hurekodi failed login attempts, kusaidia katika uchunguzi wa security breach.
- **/var/log/cron**: Huhifadhi cron job executions.
- **/var/log/daemon.log**: Hufuatilia shughuli za background service.
- **/var/log/btmp**: Huhifadhi failed login attempts.
- **/var/log/httpd/**: Ina Apache HTTPD error na access logs.
- **/var/log/mysqld.log** au **/var/log/mysql.log**: Huhifadhi shughuli za MySQL database.
- **/var/log/xferlog**: Hurekodi FTP file transfers.
- **/var/log/**: Kila mara angalia unexpected logs hapa.

> [!TIP]
> Linux system logs na audit subsystems zinaweza kuzimwa au kufutwa wakati wa intrusion au malware incident. Kwa sababu logs kwenye Linux systems kwa ujumla huwa na taarifa muhimu sana kuhusu malicious activities, intruders huzifuta mara kwa mara. Kwa hiyo, unapochunguza available log files, ni muhimu kuangalia gaps au entries zisizo katika order ambayo inaweza kuwa ishara ya deletion au tampering.

### Journald triage (`journalctl`)

Kwenye modern Linux hosts, **systemd journal** kawaida ndiyo source ya thamani zaidi kwa **service execution**, **auth events**, **package operations**, na **kernel/user-space messages**. Wakati wa live response, jaribu kuhifadhi wote **persistent** journal (`/var/log/journal/`) na **runtime** journal (`/run/log/journal/`) kwa sababu shughuli za attacker za muda mfupi zinaweza kuwepo kwenye ya pili pekee.
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
Sehemu muhimu za journal za triage ni pamoja na `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, na `MESSAGE`. Ikiwa journald ilisanidiwa bila persistent storage, tarajia tu data za hivi karibuni chini ya `/run/log/journal/`.

### Audit framework triage (`auditd`)

Ikiwa `auditd` imewezeshwa, itumie kila wakati unapohitaji **process attribution** kwa mabadiliko ya faili, utekelezaji wa amri, shughuli za kuingia, au usakinishaji wa package.
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
Wakati sheria ziliwekwa pamoja na keys, pivota kutoka kwao badala ya ku-grep raw logs:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux hudumisha command history kwa kila user**, iliyohifadhiwa katika:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Zaidi ya hayo, command `last -Faiwx` hutoa orodha ya user logins. Kagua ili kuona logins zisizojulikana au zisizotarajiwa.

Kagua files ambazo zinaweza kutoa rprivileges za ziada:

- Pitia `/etc/sudoers` kwa user privileges zisizotarajiwa ambazo huenda zilitolewa.
- Pitia `/etc/sudoers.d/` kwa user privileges zisizotarajiwa ambazo huenda zilitolewa.
- Chunguza `/etc/groups` ili kutambua unusual group memberships au permissions.
- Chunguza `/etc/passwd` ili kutambua unusual group memberships au permissions.

Baadhi ya apps pia hutengeneza logs zao:

- **SSH**: Chunguza _\~/.ssh/authorized_keys_ na _\~/.ssh/known_hosts_ kwa unauthorized remote connections.
- **Gnome Desktop**: Tazama _\~/.recently-used.xbel_ kwa files zilizofikiwa hivi karibuni kupitia Gnome applications.
- **Firefox/Chrome**: Kagua browser history na downloads katika _\~/.mozilla/firefox_ au _\~/.config/google-chrome_ kwa suspicious activities.
- **VIM**: Pitia _\~/.viminfo_ kwa usage details, kama vile accessed file paths na search history.
- **Open Office**: Kagua recent document access ambayo inaweza kuashiria compromised files.
- **FTP/SFTP**: Pitia logs katika _\~/.ftp_history_ au _\~/.sftp_history_ kwa file transfers ambazo huenda hazikuidhinishwa.
- **MySQL**: Chunguza _\~/.mysql_history_ kwa executed MySQL queries, ambazo zinaweza kufichua unauthorized database activities.
- **Less**: Changanua _\~/.lesshst_ kwa usage history, ikijumuisha viewed files na commands executed.
- **Git**: Chunguza _\~/.gitconfig_ na project _.git/logs_ kwa changes to repositories.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) ni software ndogo iliyoandikwa kwa pure Python 3 ambayo huchanganua Linux log files (`/var/log/syslog*` au `/var/log/messages*` kulingana na distro) ili kuunda USB event history tables.

Ni muhimu **kujua USBs zote zilizotumiwa** na itakuwa na manufaa zaidi ikiwa una authorized list of USBs ili kupata "violation events" (matumizi ya USBs ambazo hazipo ndani ya orodha hiyo).

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Mifano
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Kagua Akaunti za Watumiaji na Shughuli za Logon

Chunguza _**/etc/passwd**_, _**/etc/shadow**_ na **security logs** kwa majina au akaunti zisizo za kawaida zilizoundwa na au kutumika karibu na matukio yanayojulikana yasiyoidhinishwa. Pia, kagua mashambulizi yanayowezekana ya sudo brute-force.\
Zaidi ya hayo, kagua faili kama _**/etc/sudoers**_ na _**/etc/groups**_ kwa privileges zisizotarajiwa zilizotolewa kwa watumiaji.\
Hatimaye, tafuta akaunti zenye **no passwords** au passwords **rahisi kukisia**.

## Chunguza File System

### Kuchambua Miundo ya File System katika Uchunguzi wa Malware

Wakati wa kuchunguza matukio ya malware, muundo wa file system ni chanzo muhimu cha taarifa, ukifichua mfuatano wa matukio pamoja na content ya malware. Hata hivyo, waandishi wa malware wanatengeneza mbinu za kuzuia uchambuzi huu, kama vile kubadilisha file timestamps au kuepuka file system kwa uhifadhi wa data.

Ili kukabiliana na mbinu hizi za anti-forensic, ni muhimu:

- **Fanya timeline analysis ya kina** kwa kutumia tools kama **Autopsy** kwa kuonyesha event timelines kwa njia ya kuona au **Sleuth Kit's** `mactime` kwa timeline data ya kina.
- **Chunguza scripts zisizotarajiwa** katika $PATH ya system, ambazo zinaweza kujumuisha shell au PHP scripts zinazotumiwa na attackers.
- **Kagua `/dev` kwa files zisizo za kawaida**, kwani kimapokeo ina special files, lakini inaweza kuwa na files zinazohusiana na malware.
- **Tafuta hidden files au directories** zenye majina kama ".. " (dot dot space) au "..^G" (dot dot control-G), ambazo zinaweza kuficha content hasidi.
- **Tambua setuid root files** kwa kutumia command: `find / -user root -perm -04000 -print` Hii hupata files zenye elevated permissions, ambazo zinaweza kutumiwa vibaya na attackers.
- **Kagua deletion timestamps** katika inode tables ili kugundua mass file deletions, pengine zikionyesha uwepo wa rootkits au trojans.
- **Kagua consecutive inodes** kwa files hasidi zilizo karibu baada ya kubainisha moja, kwani huenda ziliwekwa pamoja.
- **Kagua common binary directories** (_/bin_, _/sbin_) kwa files zilizobadilishwa hivi karibuni, kwani hizi zinaweza kuwa zimehaririwa na malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Kumbuka kwamba **mshambulizi** anaweza **kurekebisha** **wakati** ili kufanya **faili zionekane** kuwa **halali**, lakini **hawezi** kurekebisha **inode**. Ukigundua kuwa **faili** inaonyesha kwamba iliundwa na kurekebishwa kwa **wakati uleule** kama faili nyingine zilizo kwenye folda ileile, lakini **inode** ni **kubwa isivyotarajiwa**, basi **timestamps za faili hiyo zilibadilishwa**.

### Uhakiki wa haraka unaolenga Inode

Ukipata shaka ya anti-forensics, endesha ukaguzi huu unaolenga inode mapema:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Wakati inode yenye shaka iko kwenye picha/kifaa cha filesystem ya EXT, kagua metadata ya inode moja kwa moja:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Useful fields:
- **Links**: if `0`, hakuna directory entry inayoreference inode kwa sasa.
- **dtime**: deletion timestamp iliyowekwa wakati inode ilipoondolewa kwenye link.
- **ctime/mtime**: husaidia kuoanisha metadata/mabadiliko ya content na timeline ya incident.

### Capabilities, xattrs, and preload-based userland rootkits

Uendelevu wa kisasa wa Linux mara nyingi huepuka binaries za wazi za **setuid** na badala yake hutumia vibaya **file capabilities**, **extended attributes**, na dynamic loader.
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
Zingatia hasa maktaba zinazorejelewa kutoka kwa njia **zinazoweza kuandikwa** kama `/tmp`, `/dev/shm`, `/var/tmp`, au maeneo ya ajabu chini ya `/usr/local/lib`. Pia angalia binaries zenye capabilities nje ya umiliki wa kawaida wa package na zilizanishe na matokeo ya uthibitishaji wa package (`rpm -Va`, `dpkg --verify`, `debsums`).

## Linganisha files za matoleo tofauti ya filesystem

### Muhtasari wa Ulinganisho wa Toleo la Filesystem

Ili kulinganisha matoleo ya filesystem na kubaini mabadiliko, tunatumia amri rahisi za `git diff`:

- **Ili kupata files mpya**, linganisha directories mbili:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Kwa maudhui yaliyobadilishwa**, orodhesha mabadiliko huku ukipuuza mistari mahususi:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Ili kugundua faili zilizofutwa**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Chaguo za kufilisha** (`--diff-filter`) husaidia kupunguza hadi mabadiliko mahususi kama faili zilizoongezwa (`A`), zilizofutwa (`D`), au zilizorekebishwa (`M`).
- `A`: Faili zilizoongezwa
- `C`: Faili zilizonakiliwa
- `D`: Faili zilizofutwa
- `M`: Faili zilizorekebishwa
- `R`: Faili zilizobadilishiwa jina
- `T`: Mabadiliko ya aina (k.m., file hadi symlink)
- `U`: Faili zisizounganishwa
- `X`: Faili zisizojulikana
- `B`: Faili zilizovunjika

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)

{{#include ../../banners/hacktricks-training.md}}
