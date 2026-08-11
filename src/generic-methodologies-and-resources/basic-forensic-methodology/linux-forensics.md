# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Initial Information Gathering

### Basic Information

Kwanza kabisa, inashauriwa kuwa na **USB** yenye **binaries na libraries zinazojulikana kuwa salama** (unaweza tu kupata ubuntu na kunakili folda _/bin_, _/sbin_, _/lib,_ na _/lib64_), kisha u-mount USB hiyo, na ubadilishe environment variables ili kutumia binaries hizo:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Baada ya kusanidi mfumo kutumia binaries salama na zinazojulikana, unaweza kuanza **kutoa baadhi ya taarifa za msingi**:
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
#### Taarifa za kutiliwa shaka

Unapopata taarifa za msingi, unapaswa kuangalia vitu visivyo vya kawaida kama:

- **Root processes** kwa kawaida huendeshwa kwa PIDS ndogo, kwa hivyo ukipata root process yenye PID kubwa unaweza kuwa na mashaka
- Angalia **registered logins** za users wasio na shell ndani ya `/etc/passwd`
- Angalia **password hashes** ndani ya `/etc/shadow` za users wasio na shell

### Memory Dump

Ili kupata memory ya mfumo unaoendesha, inapendekezwa kutumia [**LiME**](https://github.com/504ensicsLabs/LiME).\
Ili **ku-compile**, unahitaji kutumia **kernel ileile** inayotumiwa na mashine ya victim.

> [!TIP]
> Kumbuka kwamba **huwezi kusakinisha LiME au kitu kingine chochote** kwenye mashine ya victim, kwa sababu kufanya hivyo kutasababisha mabadiliko kadhaa ndani yake

Kwa hivyo, ikiwa una toleo linalofanana la Ubuntu, unaweza kutumia `apt-get install lime-forensics-dkms`\
Katika hali nyingine, unahitaji kupakua [**LiME**](https://github.com/504ensicsLabs/LiME) kutoka github na kui-compile kwa kutumia kernel headers sahihi. Ili **kupata kernel headers kamili** za mashine ya victim, unaweza tu **kunakili directory** `/lib/modules/<kernel version>` kwenye mashine yako, kisha **u-compile** LiME kwa kuzitumia:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME inasaidia **formats** 3:

- Raw (kila segment imeunganishwa pamoja)
- Padded (sawa na raw, lakini ikiwa na zero kwenye bits za kulia)
- Lime (format inayopendekezwa yenye metadata

LiME pia inaweza kutumika **kutuma dump kupitia mtandao** badala ya kuihifadhi kwenye mfumo kwa kutumia kitu kama: `path=tcp:4444`

### Disk Imaging

#### Kuzima

Kwanza kabisa, utahitaji **kuzima mfumo**. Hili si chaguo kila wakati kwa sababu wakati mwingine mfumo utakuwa production server ambayo kampuni haiwezi kumudu kuizima.\
Kuna **njia 2 za kuzima mfumo**, **kuzima kwa kawaida** na **kuzima kwa "plug the plug"**. Ya kwanza itaruhusu **processes kusitishwa kama kawaida** na **filesystem** **kusawazishwa**, lakini pia itaruhusu **malware** inayoweza kuwepo **kuharibu ushahidi**. Mbinu ya "pull the plug" inaweza kusababisha **upotevu wa taarifa fulani** (si taarifa nyingi zitapotea kwa sababu tayari tulichukua image ya memory) na **malware haitapata fursa yoyote** ya kufanya chochote kuihusu. Kwa hiyo, ikiwa **unashuku** kwamba kunaweza kuwa na **malware**, tekeleza tu **`sync`** **command** kwenye mfumo kisha pull the plug.

#### Kuchukua image ya disk

Ni muhimu kutambua kwamba **kabla ya kuunganisha kompyuta yako na kitu chochote kinachohusiana na kesi**, unahitaji kuhakikisha kwamba ita**mounted as read only** ili kuepuka kubadilisha taarifa yoyote.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Uchambuzi wa awali wa Disk Image

Kutengeneza image ya diski bila data zaidi.
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

### Faili za Mfumo Zilizorekebishwa

Linux hutoa tools za kuhakikisha uadilifu wa vipengele vya mfumo, jambo muhimu katika kutambua faili zinazoweza kuwa na matatizo.<sup>[[1]](#references)</sup>

- **RedHat-based systems**: Tumia `rpm -Va` kufanya ukaguzi wa kina.
- **Debian-based systems**: Tumia `dpkg --verify` kwa uthibitishaji wa awali, kisha `debsums | grep -v "OK$"` (baada ya kusakinisha `debsums` kwa `apt-get install debsums`) ili kutambua matatizo yoyote.

### Malware/Rootkit Detectors

Soma ukurasa ufuatao ili kujifunza kuhusu tools zinazoweza kusaidia kupata Malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Tafuta programu zilizosakinishwa

Ili kutafuta kwa ufanisi programu zilizosakinishwa kwenye Debian na RedHat systems, zingatia kutumia system logs na databases pamoja na ukaguzi wa kawaida katika directories zinazotumika sana.<sup>[[1]](#references)</sup>

- Kwa Debian, kagua _**`/var/lib/dpkg/status`**_ na _**`/var/log/dpkg.log`**_ ili kupata maelezo kuhusu usakinishaji wa packages, ukitumia `grep` kuchuja taarifa mahususi.
- Watumiaji wa RedHat wanaweza kuuliza RPM database kwa `rpm -qa --root=/mntpath/var/lib/rpm` ili kuorodhesha packages zilizosakinishwa.

Ili kugundua software iliyosakinishwa manually au nje ya package managers hawa, chunguza directories kama _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, na _**`/sbin`**_. Unganisha orodha za directories na commands mahususi za mfumo ili kutambua executables ambazo hazihusiani na packages zinazojulikana, na hivyo kuboresha utafutaji wako wa programu zote zilizosakinishwa.
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
## Kurejesha Binary Zinazoendeshwa Zilizofutwa

Fikiria mchakato uliotekelezwa kutoka /tmp/exec kisha ukafutwa. Inawezekana kuutoa
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Uchambuzi wa Syscall Trace kwa SQLite na FTS5

Wakati process bado inaendelea au inaweza kutekelezwa tena kwenye lab, **`strace`** inaweza kutoa trace ya haraka ya tabia bila kuhitaji kernel modules au telemetry kamili ya EDR. Kwa trace kubwa, epuka kusoma log ghafi moja kwa moja au kuibandika kwenye LLM: ihifadhi kwenye database ya **SQLite** na uulize tu sehemu ndogo unayohitaji.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> Kuambatisha `strace` hubadilisha muda wa process na kunaweza kuathiri race conditions au bugs nyingine dhaifu. Ikiwezekana, pendelea kuzaa upya tatizo kwenye mfumo wa copy/lab.

### Kukusanya

Kwa process mpya:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Kwa mchakato unaoendelea:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Chaguo muhimu:

- `-ff`: fuata forks/threads na uhifadhi matokeo ya kila mchakato
- `-ttt`: timestamps za epoch kwa ulinganishaji rahisi wa timeline
- `-yy`: bainisha file descriptors kuwa paths/sockets zinazoziunga mkono inapowezekana
- `-s 4096`: zuia path na buffer arguments ndefu zisikatwe

### Kusawazisha

Schema ya vitendo ni kuwa na safu moja kwa kila syscall na safu moja kwa kila argument:
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
Hii huepuka kujaribu kuweka mistari ya syscall yenye miundo tofauti katika jedwali moja pana na kufanya joins ziwe rahisi kutabirika wakati wa triage.

### Index maandishi yenye hoja nyingi kwa FTS5

Utafutaji wa njia kwa kutumia `LIKE "%...%"` huwa wa polepole sana kwenye traces kubwa. Unda index ya FTS5 kwa maandishi ya hoja na utafute humo badala yake:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Mfano: kurejesha shughuli za faili chini ya `/tmp` bila kuchanganua kila safu:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Uchunguzi wenye ishara muhimu

- **PATH hijacking / fake sudo**: tafuta shughuli za kuandika na `chmod`/`rename` chini ya `~/.local/bin/`, kisha zilinganisha na `execve` za baadaye za majina yanayoonekana kuwa ya privileged kama vile `sudo`.
- **TOCTOU kwenye temporary files**: fuatilia njia ileile ya `/tmp/...` kwenye `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink`, na `execve` ili kubaini mapengo kati ya ukaguzi na matumizi.
- **Chanzo halisi cha crash**: linganisha `mmap` ya file na uandishi au ufupishaji wa inode/path ileile na process nyingine, kisha kagua mfuatano wa signal/exit kwa `SIGBUS`.
- **Urejeshaji wa network destination**: chuja `connect`, `sendto`, `sendmsg`, `recvfrom`, na arguments zinazohusiana na socket ili kutoa peer IPs na ports.

### Uchambuzi wa trace kwa msaada wa LLM

Ukitaka LLM ikusaidie, mpe SQLite handle ya **read-only** na schema kamili. Iruhusu itoe raw SQL badala ya kuficha database nyuma ya helper functions finyu. Hii kwa kawaida hufanya kazi vizuri zaidi kwa joins, temporal correlation, na FTS lookups.

Kanuni za vitendo:

- Weka database katika hali ya read-only, kwa mfano kwa `sqlite3 'file:trace.db?mode=ro'`.
- Mpe model mifano ya queries halali za `JOIN` na `FTS5 MATCH`.
- **Usibandike** raw multi-GB `strace` logs kwenye prompt.
- Uliza maswali mahususi kama:
- "Orodhesha files persistent zilizoandikwa na program hii."
- "Je, iliunda au kubadilisha executables katika directories za PATH zinazodhibitiwa na user?"
- "Eleza kwa nini trace hii inaishia kwenye SIGBUS."

## Kagua maeneo ya Autostart

### Kazi zilizopangwa
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
#### Uwindaji: Matumizi mabaya ya Cron/Anacron kupitia 0anacron na stubs zinazotiliwa shaka
Washambuliaji mara nyingi huhariri stub ya 0anacron iliyopo katika kila saraka ya /etc/cron.*/ ili kuhakikisha utekelezaji wa mara kwa mara.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Utafutaji: kurejesha ugumu wa SSH na shells za backdoor
Mabadiliko kwenye sshd_config na shells za akaunti za mfumo ni mbinu za kawaida za post-exploitation za kudumisha ufikiaji.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Alama za Cloud C2 (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons kwa kawaida hutumia api.dropboxapi.com au content.dropboxapi.com kupitia HTTPS pamoja na tokeni za Authorization: Bearer.
- Fanya hunt katika proxy/Zeek/NetFlow kutafuta Dropbox egress isiyotarajiwa kutoka kwenye servers.
- Cloudflare Tunnel (`cloudflared`) hutoa C2 ya akiba kupitia outbound 443.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Njia ambapo malware inaweza kusakinishwa kama service:

- **/etc/inittab**: Huita initialization scripts kama rc.sysinit, ambazo huelekeza zaidi kwenye startup scripts.
- **/etc/rc.d/** na **/etc/rc.boot/**: Zina scripts za kuanzisha service, huku ya mwisho ikipatikana katika matoleo ya zamani ya Linux.
- **/etc/init.d/**: Hutumiwa katika baadhi ya matoleo ya Linux kama Debian kwa kuhifadhi startup scripts.
- Services pia zinaweza kuamilishwa kupitia **/etc/inetd.conf** au **/etc/xinetd/**, kulingana na Linux variant.
- **/etc/systemd/system**: Directory ya system na service manager scripts.
- **/etc/systemd/system/multi-user.target.wants/**: Ina links za services zinazopaswa kuanzishwa katika multi-user runlevel.
- **/usr/local/etc/rc.d/**: Kwa services maalum au za third-party.
- **\~/.config/autostart/**: Kwa applications za automatic startup zinazohusiana na user, ambazo zinaweza kuwa sehemu ya kujificha kwa malware inayolenga user.
- **/lib/systemd/system/**: System-wide default unit files zinazotolewa na packages zilizosakinishwa.

#### Utafutaji: systemd timers na transient units

Systemd persistence haiishii kwenye `.service` files. Chunguza `.timer` units, user-level units, na **transient units** zinazoundwa wakati wa runtime.
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
Transient units ni rahisi kupuuzwa kwa sababu `/run/systemd/transient/` ni **non-persistent**. Ikiwa unakusanya live image, ikusanye kabla ya kuzima mfumo.

### Kernel Modules

Linux kernel modules, ambazo mara nyingi hutumiwa na malware kama vipengele vya rootkit, hupakiwa wakati wa kuwasha mfumo. Saraka na faili muhimu kwa modules hizi ni pamoja na:

- **/lib/modules/$(uname -r)**: Huhifadhi modules za kernel version inayoendesha.
- **/etc/modprobe.d**: Ina configuration files za kudhibiti upakiaji wa modules.
- **/etc/modprobe** na **/etc/modprobe.conf**: Faili za global module settings.

### Other Autostart Locations

Linux hutumia faili mbalimbali kutekeleza programu kiotomatiki mtumiaji anapoingia, ambazo zinaweza kuwa na malware:

- **/etc/profile.d/**\*, **/etc/profile**, na **/etc/bash.bashrc**: Hutekelezwa mtumiaji yeyote anapoingia.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, na **\~/.config/autostart**: Faili mahususi za mtumiaji zinazoendeshwa anapoingia.
- **/etc/rc.local**: Huendeshwa baada ya system services zote kuanza, ikiashiria mwisho wa mpito kwenda kwenye multiuser environment.

## Examine Logs

Linux systems hufuatilia shughuli za watumiaji na matukio ya mfumo kupitia log files mbalimbali. Logs hizi ni muhimu katika kutambua unauthorized access, malware infections, na security incidents nyingine.<sup>[[2]](#references)</sup> Log files muhimu ni pamoja na:

- **/var/log/syslog** (Debian) au **/var/log/messages** (RedHat): Hunasa system-wide messages na shughuli.
- **/var/log/auth.log** (Debian) au **/var/log/secure** (RedHat): Hurekodi authentication attempts, successful logins na failed logins.
- Tumia `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` kuchuja authentication events zinazohusiana.
- **/var/log/boot.log**: Ina system startup messages.
- **/var/log/maillog** au **/var/log/mail.log**: Hurekodi shughuli za email server, zikiwa muhimu katika kufuatilia email-related services.
- **/var/log/kern.log**: Huhifadhi kernel messages, ikiwemo errors na warnings.
- **/var/log/dmesg**: Ina device driver messages.
- **/var/log/faillog**: Hurekodi failed login attempts, na kusaidia katika uchunguzi wa security breaches.
- **/var/log/cron**: Hurekodi utekelezaji wa cron jobs.
- **/var/log/daemon.log**: Hufuatilia shughuli za background services.
- **/var/log/btmp**: Hurekodi failed login attempts.
- **/var/log/httpd/**: Ina Apache HTTPD error na access logs.
- **/var/log/mysqld.log** au **/var/log/mysql.log**: Hurekodi shughuli za MySQL database.
- **/var/log/xferlog**: Hurekodi FTP file transfers.
- **/var/log/**: Kagua kila mara logs zisizotarajiwa hapa.

> [!TIP]
> Linux system logs na audit subsystems zinaweza kuzimwa au kufutwa wakati wa intrusion au malware incident. Kwa kuwa logs kwenye Linux systems kwa ujumla zina baadhi ya taarifa muhimu zaidi kuhusu malicious activities, intruders huzifuta mara kwa mara. Kwa hiyo, unapochunguza log files zinazopatikana, ni muhimu kutafuta gaps au entries zilizo nje ya mpangilio, ambazo zinaweza kuashiria kufutwa au tampering.

### Journald triage (`journalctl`)

Kwenye modern Linux hosts, **systemd journal** kwa kawaida ndiyo source yenye thamani kubwa zaidi kwa **service execution**, **auth events**, **package operations**, na **kernel/user-space messages**. Wakati wa live response, jaribu kuhifadhi **persistent** journal (`/var/log/journal/`) na **runtime** journal (`/run/log/journal/`) kwa sababu attacker activity ya muda mfupi inaweza kuwepo kwenye ya mwisho pekee.<sup>[[5]](#references)</sup>
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
Sehemu muhimu za journal kwa ajili ya uchunguzi wa awali zinajumuisha `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, na `MESSAGE`. Ikiwa journald iliwekwa bila hifadhi endelevu, tarajia data ya hivi karibuni pekee chini ya `/run/log/journal/`.

### Uchunguzi wa awali wa audit framework (`auditd`)

Ikiwa `auditd` imewezeshwa, ipendelee wakati wowote unapohitaji **utambuzi wa mchakato** kwa mabadiliko ya faili, utekelezaji wa amri, shughuli za kuingia, au usakinishaji wa package.<sup>[[6]](#references)</sup>
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
Wakati rules zilitumwa zikiwa na keys, pivot kutoka kwenye hizo badala ya kufanya grep kwenye raw logs:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux huhifadhi command history kwa kila user**, ikihifadhiwa katika:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Zaidi ya hayo, command `last -Faiwx` hutoa orodha ya user logins. Ichunguze kwa logins zisizojulikana au zisizotarajiwa.

Kagua files zinazoweza kutoa privileges za ziada:

- Kagua `/etc/sudoers` kwa privileges za user zisizotarajiwa ambazo huenda zilitolewa.
- Kagua `/etc/sudoers.d/` kwa privileges za user zisizotarajiwa ambazo huenda zilitolewa.
- Chunguza `/etc/groups` ili kutambua group memberships au permissions zisizo za kawaida.
- Chunguza `/etc/passwd` ili kutambua group memberships au permissions zisizo za kawaida.

Baadhi ya apps pia hutengeneza logs zake:

- **SSH**: Chunguza _\~/.ssh/authorized_keys_ na _\~/.ssh/known_hosts_ kwa remote connections zisizoidhinishwa.
- **Gnome Desktop**: Kagua _\~/.recently-used.xbel_ kwa files zilizofikiwa hivi karibuni kupitia Gnome applications.
- **Firefox/Chrome**: Kagua browser history na downloads katika _\~/.mozilla/firefox_ au _\~/.config/google-chrome_ kwa shughuli zinazotiliwa shaka.
- **VIM**: Kagua _\~/.viminfo_ kwa maelezo ya matumizi, kama vile file paths zilizofikiwa na search history.
- **Open Office**: Kagua document access za hivi karibuni ambazo zinaweza kuashiria files zilizoathiriwa.
- **FTP/SFTP**: Kagua logs katika _\~/.ftp_history_ au _\~/.sftp_history_ kwa file transfers ambazo huenda hazijaidhinishwa.
- **MySQL**: Chunguza _\~/.mysql_history_ kwa MySQL queries zilizotekelezwa, ambazo zinaweza kufichua database activities zisizoidhinishwa.
- **Less**: Changanua _\~/.lesshst_ kwa usage history, ikijumuisha files zilizotazamwa na commands zilizotekelezwa.
- **Git**: Chunguza _\~/.gitconfig_ na project _.git/logs_ kwa mabadiliko kwenye repositories.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) ni software ndogo iliyoandikwa kwa pure Python 3 ambayo huchanganua Linux log files (`/var/log/syslog*` au `/var/log/messages*`, kulingana na distro) ili kuunda tables za USB event history.

Ni muhimu **kujua USB zote zilizotumika**, na itakuwa na manufaa zaidi ikiwa una list iliyoidhinishwa ya USBs ili kupata "violation events" (matumizi ya USB ambazo hazipo kwenye list hiyo).

### Usakinishaji
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
Mifano na maelezo zaidi yanapatikana ndani ya github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Kagua Akaunti za Watumiaji na Shughuli za Logon

Chunguza _**/etc/passwd**_, _**/etc/shadow**_ na **security logs** ili kubaini majina au akaunti zisizo za kawaida zilizoundwa na/au kutumiwa karibu na matukio yanayojulikana kuwa hayajaidhinishwa. Pia, kagua uwezekano wa mashambulizi ya sudo brute-force.\
Zaidi ya hayo, kagua faili kama _**/etc/sudoers**_ na _**/etc/groups**_ ili kubaini privileges zisizotarajiwa zilizopewa watumiaji.\
Hatimaye, tafuta akaunti zilizo na **no passwords** au passwords **zinazoweza kukisiwa kwa urahisi**.<sup>[[1]](#references)</sup>

## Chunguza File System

### Kuchanganua Miundo ya File System katika Uchunguzi wa Malware

Wakati wa kuchunguza matukio ya malware, muundo wa file system ni chanzo muhimu cha taarifa, ukifichua mfuatano wa matukio pamoja na maudhui ya malware. Hata hivyo, waandishi wa malware wanabuni techniques za kuzuia uchanganuzi huu, kama vile kubadilisha file timestamps au kuepuka file system kwa ajili ya kuhifadhi data.<sup>[[1]](#references)</sup>

Ili kukabiliana na mbinu hizi za anti-forensic, ni muhimu:

- **Kufanya uchanganuzi wa kina wa timeline** kwa kutumia tools kama **Autopsy** kwa ajili ya kuonyesha timelines za matukio au `mactime` ya **Sleuth Kit** kwa data ya kina ya timeline.
- **Kuchunguza scripts zisizotarajiwa** katika $PATH ya mfumo, ambazo zinaweza kujumuisha shell au PHP scripts zinazotumiwa na attackers.
- **Kuchunguza `/dev` kwa files zisizo za kawaida**, kwa kuwa kwa kawaida huwa na special files, lakini zinaweza kuwa na files zinazohusiana na malware.
- **Kutafuta files au directories zilizofichwa** zenye majina kama ".. " (dot dot space) au "..^G" (dot dot control-G), ambazo zinaweza kuficha maudhui hasidi.
- **Kubaini setuid root files** kwa kutumia command: `find / -user root -perm -04000 -print` Hii hutafuta files zilizo na permissions zilizoinuliwa, ambazo zinaweza kutumiwa vibaya na attackers.
- **Kukagua deletion timestamps** katika inode tables ili kubaini kufutwa kwa files kwa wingi, jambo ambalo linaweza kuashiria uwepo wa rootkits au trojans.
- **Kukagua consecutive inodes** ili kutafuta files hasidi zilizo karibu baada ya kubaini file moja, kwa kuwa huenda ziliwekwa pamoja.
- **Kukagua common binary directories** (_/bin_, _/sbin_) kwa files zilizobadilishwa hivi karibuni, kwa kuwa huenda zilibadilishwa na malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Kumbuka kwamba **attacker** anaweza **kubadilisha** **time** ili kufanya **files zionekane** **halali**, lakini hawezi **kubadilisha** **inode**. Ukigundua kwamba **file** inaonyesha kuwa iliundwa na kubadilishwa **saa ileile** na files nyingine zilizo kwenye folder hiyo, lakini **inode** ni **kubwa isivyotarajiwa**, basi **timestamps** za file hiyo **zilibadilishwa**.

### Ukaguzi wa haraka unaolenga inode

Ikiwa unashuku anti-forensics, endesha ukaguzi huu unaolenga inode mapema:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Wakati inode yenye mashaka iko kwenye image/device ya EXT filesystem, kagua metadata ya inode moja kwa moja:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Useful fields:
- **Links**: ikiwa ni `0`, hakuna directory entry inayorejelea inode kwa sasa.
- **dtime**: timestamp ya kufutwa inayowekwa inode inapo-unlinkiwa.
- **ctime/mtime**: husaidia kuoanisha mabadiliko ya metadata/content na ratiba ya tukio.

### Capabilities, xattrs, na preload-based userland rootkits

Modern Linux persistence mara nyingi huepuka **setuid** binaries zilizo wazi na badala yake hutumia vibaya **file capabilities**, **extended attributes**, na dynamic loader.
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
Zingatia kwa makini libraries zinazoelekezwa kutoka kwenye paths **writable** kama vile `/tmp`, `/dev/shm`, `/var/tmp`, au maeneo yasiyo ya kawaida yaliyo chini ya `/usr/local/lib`. Pia kagua binaries zenye capabilities nje ya umiliki wa kawaida wa packages na zilinganishe na matokeo ya uthibitishaji wa packages (`rpm -Va`, `dpkg --verify`, `debsums`).

## Linganisha faili za matoleo tofauti ya mfumo wa faili

### Muhtasari wa Ulinganishaji wa Matoleo ya Mfumo wa Faili

Ili kulinganisha matoleo ya mfumo wa faili na kubaini mabadiliko, tunatumia amri zilizorahisishwa za `git diff`:<sup>[[3]](#references)</sup>

- **Ili kupata faili mpya**, linganisha directories mbili:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Kwa maudhui yaliyorekebishwa**, orodhesha mabadiliko huku ukipuuza mistari mahususi:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Ili kugundua faili zilizofutwa**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) husaidia kupunguza matokeo kwa mabadiliko maalum kama faili zilizoongezwa (`A`), zilizofutwa (`D`), au zilizorekebishwa (`M`).
- `A`: Faili zilizoongezwa
- `C`: Faili zilizonakiliwa
- `D`: Faili zilizofutwa
- `M`: Faili zilizorekebishwa
- `R`: Faili zilizopewa jina jipya
- `T`: Mabadiliko ya aina (kwa mfano, faili kuwa symlink)
- `U`: Faili ambazo hazijaunganishwa
- `X`: Faili zisizojulikana
- `B`: Faili zilizoharibika

## References

- [1] [Mwongozo wa Uchunguzi wa Malware kwa Mifumo ya Linux: Miongozo ya Uchunguzi wa Kidijitali – Sura ya 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Maelezo ya Linux Logs](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [Nyaraka za git diff – chaguo la --diff-filter](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Kuweka patch kwa ajili ya persistence: Jinsi malware ya DripDropper Linux inavyosambaa kwenye cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Uchambuzi wa Kiforensiki wa Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - Kukagua mfumo](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Msalimie Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [Kiendelezi cha SQLite FTS5](https://www.sqlite.org/fts5.html)
{{#include ../../banners/hacktricks-training.md}}
