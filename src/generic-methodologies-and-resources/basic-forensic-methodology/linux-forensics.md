# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Ukusanya Taarifa za Awali

### Taarifa za Msingi

Kwanza kabisa, inapendekezwa kuwa na baadhi ya **USB** zenye **good known binaries and libraries** ndani yake (unaweza tu kupata ubuntu na kunakili folda _/bin_, _/sbin_, _/lib,_ na _/lib64_), kisha weka USB, na urekebishe env variables ili kutumia hizo binaries:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Mara tu unapokuwa umesanidi mfumo utumie binaries nzuri na zinazojulikana unaweza kuanza **kutoa baadhi ya taarifa za msingi**:
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
#### Taarifa za kushuku

Wakati wa kupata taarifa za msingi unapaswa kuangalia vitu visivyo vya kawaida kama:

- **Root processes** kawaida huendeshwa na PIDs ndogo, hivyo ukipata root process yenye PID kubwa unaweza kushuku
- Angalia **registered logins** za users wasio na shell ndani ya `/etc/passwd`
- Angalia **password hashes** ndani ya `/etc/shadow` kwa users wasio na shell

### Memory Dump

Ili kupata memory ya mfumo unaoendesha, inapendekezwa kutumia [**LiME**](https://github.com/504ensicsLabs/LiME).\
Ili **kuikompaili**, unahitaji kutumia **same kernel** ambayo machine ya mwathiriwa inatumia.

> [!TIP]
> Kumbuka kwamba huwezi kusakinisha LiME au kitu kingine chochote kwenye machine ya mwathiriwa kwa sababu itafanya mabadiliko mengi kwake

Kwa hiyo, kama una toleo sawia la Ubuntu unaweza kutumia `apt-get install lime-forensics-dkms`\
Katika hali nyingine, unahitaji kupakua [**LiME**](https://github.com/504ensicsLabs/LiME) kutoka github na kuikompaili na correct kernel headers. Ili **kupata exact kernel headers** za machine ya mwathiriwa, unaweza tu **kunakili directory** `/lib/modules/<kernel version>` kwenda kwenye machine yako, kisha **kuikompaili** LiME ukizitumia:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME inasaidia **formats** 3:

- Raw (kila segment imeunganishwa pamoja)
- Padded (kama raw, lakini ikiwa na zeroes kwenye right bits)
- Lime (format iliyopendekezwa yenye metadata)

LiME pia inaweza kutumika **kutuma dump kupitia network** badala ya kuihifadhi kwenye system kwa kutumia kitu kama: `path=tcp:4444`

### Disk Imaging

#### Shutting down

Kwanza kabisa, utahitaji **kuzima system**. Hii si mara zote inawezekana kwa sababu wakati mwingine system inaweza kuwa production server ambayo kampuni haiwezi kumudu kuizima.\
Kuna **njia 2** za kuzima system, **normal shutdown** na **"plug the plug" shutdown**. Njia ya kwanza itaruhusu **processes kumalizika kama kawaida** na **filesystem** **kusynchronizishwa**, lakini pia itaruhusu uwezekano wa **malware** **kuharibu evidence**. Njia ya "pull the plug" inaweza kuleta **hasara fulani ya taarifa** (si nyingi za info zitaondoka kwa sababu tayari tulikuwa tumeshachukua image ya memory ) na **malware haitapata nafasi yoyote** ya kufanya lolote kuhusu hilo. Kwa hiyo, ikiwa **unashuku** kwamba kunaweza kuwa na **malware**, tekeleza tu **`sync`** **command** kwenye system na uvute plug.

#### Taking an image of the disk

Ni muhimu kutambua kwamba **kabla hujaunganisha computer yako na chochote kinachohusiana na kesi**, unahitaji kuwa na uhakika kwamba itakuwa **mounted as read only** ili kuepuka kurekebisha taarifa yoyote.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Image kabla ya uchambuzi

Kupiga picha ya disk image bila data zaidi.
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

Linux inatoa zana za kuhakikisha uadilifu wa vipengele vya mfumo, muhimu kwa kugundua faili zinazoweza kuwa na matatizo.

- **RedHat-based systems**: Tumia `rpm -Va` kwa ukaguzi wa kina.
- **Debian-based systems**: `dpkg --verify` kwa uthibitishaji wa awali, ukifuatiwa na `debsums | grep -v "OK$"` (baada ya kusakinisha `debsums` kwa `apt-get install debsums`) ili kutambua matatizo yoyote.

### Malware/Rootkit Detectors

Soma ukurasa ufuatao ili kujifunza kuhusu zana ambazo zinaweza kuwa muhimu kupata malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Tafuta programu zilizosakinishwa

Ili kutafuta kwa ufanisi programu zilizosakinishwa kwenye mifumo ya Debian na RedHat, zingatia kutumia system logs na databases pamoja na ukaguzi wa mikono katika directories za kawaida.

- Kwa Debian, kagua _**`/var/lib/dpkg/status`**_ na _**`/var/log/dpkg.log`**_ ili kupata maelezo kuhusu package installations, ukitumia `grep` kuchuja taarifa mahususi.
- Watumiaji wa RedHat wanaweza kuuliza RPM database kwa `rpm -qa --root=/mntpath/var/lib/rpm` ili kuorodhesha packages zilizosakinishwa.

Ili kugundua software iliyosakinishwa kwa mikono au nje ya package managers hizi, chunguza directories kama _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, na _**`/sbin`**_. Changanya directory listings na system-specific commands ili kutambua executables zisizohusishwa na packages zinazojulikana, na kuboresha utafutaji wako wa programu zote zilizosakinishwa.
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

Fikiria mchakato ambao uliendeshwa kutoka /tmp/exec kisha ukafutwa. Inawezekana kuutoa
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Syscall Trace Triage with SQLite and FTS5

Wakati mchakato bado unaendelea au unaweza kuendeshwa tena kwenye lab, **`strace`** inaweza kutoa behavioral trace ya haraka bila kuhitaji kernel modules au full EDR telemetry. Kwa traces kubwa, epuka kusoma raw log moja kwa moja au kui-paste kwenye LLM: ihifadhi kwenye **SQLite** database na uulize tu subset ndogo unayohitaji.

> [!WARNING]
> Kuattach `strace` hubadilisha process timing na inaweza kuathiri race conditions au bugs nyingine fragile. Pendelea ku-reproduce kwenye copy/lab system inapowezekana.

### Capture

Kwa mchakato mpya:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Kwa mchakato wa moja kwa moja:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Chaguo muhimu:

- `-ff`: fuata forks/threads na uhifadhi outputs za kila process
- `-ttt`: epoch timestamps kwa ajili ya timeline correlation rahisi
- `-yy`: resolve file descriptors to backing paths/sockets inapowezekana
- `-s 4096`: zuia long path na buffer arguments zisikatwe

### Normalize

Schema ya vitendo ni row moja kwa kila syscall na row moja kwa kila argument:
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
Hii huepuka kujaribu kusawazisha mistari ya syscall isiyo sawa kuwa jedwali moja pana na huifanya joins iwe ya kutabirika wakati wa triage.

### Index maandishi yenye arguments mazito kwa kutumia FTS5

Utafutaji wa njia kwa njia ya `LIKE "%...%"` huwa polepole sana kwenye traces kubwa. Tengeneza FTS5 index kwa maandishi ya arguments na utafute humo badala yake:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Mfano: rudisha shughuli za faili chini ya `/tmp` bila kuchanganua kila row:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Uchunguzi wenye ishara kali

- **PATH hijacking / fake sudo**: tafuta uandishi na shughuli za `chmod`/`rename` chini ya `~/.local/bin/`, kisha linganisha na `execve` za baadaye za majina yanayoonekana kuwa ya privileged kama `sudo`.
- **TOCTOU kwenye faili za muda**: pivot kwenye path ileile `/tmp/...` kupitia `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink`, na `execve` ili kutambua mapengo ya check/use.
- **Sababu ya mzizi wa crash**: linganisha `mmap` ya faili na uandishi au truncation ya inode/path ileile na process nyingine, kisha kagua mlolongo wa signal/exit kwa `SIGBUS`.
- **Urejeshaji wa destination ya network**: chuja `connect`, `sendto`, `sendmsg`, `recvfrom`, na arguments zinazohusiana na socket ili kutoa IPs na ports za peer.

### Uchambuzi wa trace ukisaidiwa na LLM

Ukihitaji LLM kusaidia, toa handle ya SQLite ya **read-only** na upe schema kamili. Acha i-issue raw SQL badala ya kuficha database nyuma ya helper functions finyu. Hii kawaida hufanya kazi vizuri zaidi kwa joins, temporal correlation, na FTS lookups.

Sheria za vitendo:

- Weka database kuwa read-only, kwa mfano kwa `sqlite3 'file:trace.db?mode=ro'`.
- Mpe model mifano ya queries halali za `JOIN` na `FTS5 MATCH`.
- Usibandike raw multi-GB `strace` logs ndani ya prompt.
- Uliza maswali yaliyoelekezwa kama:
- "Orodhesha persistent files zilizoandikwa na program hii."
- "Je, iliunda au kubadilisha executables kwenye user-controlled PATH directories?"
- "Eleza kwa nini trace hii inaishia katika SIGBUS."

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
Washambulizi mara nyingi huhariri stub ya 0anacron iliyopo chini ya kila saraka /etc/cron.*/ ili kuhakikisha utekelezaji wa mara kwa mara.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Uwinde: kurudisha nyuma ugumu wa SSH na backdoor shells
Mabadiliko kwenye sshd_config na shell za akaunti za mfumo ni ya kawaida baada ya exploitation ili kuhifadhi ufikiaji.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons kawaida hutumia api.dropboxapi.com au content.dropboxapi.com kupitia HTTPS na Authorization: Bearer tokens.
- Fanya hunt katika proxy/Zeek/NetFlow kwa Dropbox egress isiyotarajiwa kutoka kwa servers.
- Cloudflare Tunnel (`cloudflared`) hutoa backup C2 kupitia outbound 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Njia ambapo malware inaweza kusanikishwa kama service:

- **/etc/inittab**: Huita scripts za initialization kama rc.sysinit, zikiendelea hadi startup scripts.
- **/etc/rc.d/** na **/etc/rc.boot/**: Zina scripts za kuanzisha service, huku ya pili ikipatikana kwenye matoleo ya zamani ya Linux.
- **/etc/init.d/**: Hutumika katika matoleo fulani ya Linux kama Debian kwa kuhifadhi startup scripts.
- Services pia zinaweza kuanzishwa kupitia **/etc/inetd.conf** au **/etc/xinetd/**, kulingana na aina ya Linux.
- **/etc/systemd/system**: Directory ya scripts za system na service manager.
- **/etc/systemd/system/multi-user.target.wants/**: Ina links kwenda kwenye services zinazopaswa kuanzishwa katika multi-user runlevel.
- **/usr/local/etc/rc.d/**: Kwa services za custom au za third-party.
- **\~/.config/autostart/**: Kwa applications za automatic startup za mtumiaji, ambazo zinaweza kuwa mahali pa kujificha pa malware inayolenga mtumiaji.
- **/lib/systemd/system/**: System-wide default unit files zinazotolewa na packages zilizosanikishwa.

#### Hunt: systemd timers and transient units

Persistence ya Systemd haijakomea kwenye `.service` files pekee. Chunguza `.timer` units, user-level units, na **transient units** zinazoundwa wakati wa runtime.
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
Transient units ni rahisi kukosa kwa sababu `/run/systemd/transient/` ni **non-persistent**. Ukikusanya live image, ichukue kabla ya shutdown.

### Kernel Modules

Linux kernel modules, mara nyingi hutumiwa na malware kama rootkit components, hupakiwa wakati wa system boot. Directories na files muhimu kwa modules hizi ni pamoja na:

- **/lib/modules/$(uname -r)**: Hushikilia modules kwa running kernel version.
- **/etc/modprobe.d**: Ina configuration files za kudhibiti module loading.
- **/etc/modprobe** na **/etc/modprobe.conf**: Files za global module settings.

### Other Autostart Locations

Linux hutumia files mbalimbali kwa ku-execute programs moja kwa moja wakati user ana-login, na zinaweza kuficha malware:

- **/etc/profile.d/**\*, **/etc/profile**, na **/etc/bash.bashrc**: Hufanyika kwa any user login.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, na **\~/.config/autostart**: User-specific files zinazo-run wakati wa login yao.
- **/etc/rc.local**: Hufanya kazi baada ya all system services kuanza, ikiashiria mwisho wa transition kwenda multiuser environment.

## Examine Logs

Linux systems hufuatilia user activities na system events kupitia log files mbalimbali. Logs hizi ni muhimu sana kwa kutambua unauthorized access, malware infections, na security incidents nyingine. Key log files ni pamoja na:

- **/var/log/syslog** (Debian) au **/var/log/messages** (RedHat): Hushika system-wide messages na activities.
- **/var/log/auth.log** (Debian) au **/var/log/secure** (RedHat): Hurekodi authentication attempts, successful na failed logins.
- Tumia `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` kuchuja relevant authentication events.
- **/var/log/boot.log**: Ina system startup messages.
- **/var/log/maillog** au **/var/log/mail.log**: Huhifadhi logs za email server activities, muhimu kwa kufuatilia services zinazohusiana na email.
- **/var/log/kern.log**: Huhifadhi kernel messages, ikiwemo errors na warnings.
- **/var/log/dmesg**: Hushikilia device driver messages.
- **/var/log/faillog**: Hurekodi failed login attempts, kusaidia katika security breach investigations.
- **/var/log/cron**: Huhifadhi cron job executions.
- **/var/log/daemon.log**: Hufuatilia background service activities.
- **/var/log/btmp**: Huweka kumbukumbu za failed login attempts.
- **/var/log/httpd/**: Ina Apache HTTPD error na access logs.
- **/var/log/mysqld.log** au **/var/log/mysql.log**: Huhifadhi MySQL database activities.
- **/var/log/xferlog**: Hurekodi FTP file transfers.
- **/var/log/**: Kila mara angalia unexpected logs hapa.

> [!TIP]
> Linux system logs na audit subsystems zinaweza kuzimwa au kufutwa wakati wa intrusion au malware incident. Kwa kuwa logs kwenye Linux systems kwa ujumla huwa na taarifa muhimu sana kuhusu malicious activities, intruders kwa kawaida huzifuta. Hivyo, unapochunguza available log files, ni muhimu kutafuta gaps au entries zisizo katika mpangilio ambazo zinaweza kuwa dalili ya deletion au tampering.

### Journald triage (`journalctl`)

Kwenye modern Linux hosts, **systemd journal** kwa kawaida ndiyo chanzo chenye thamani kubwa zaidi kwa **service execution**, **auth events**, **package operations**, na **kernel/user-space messages**. Wakati wa live response, jaribu kuhifadhi zote mbili, **persistent** journal (`/var/log/journal/`) na **runtime** journal (`/run/log/journal/`) kwa sababu shughuli za attacker za muda mfupi zinaweza kuwepo tu katika ya pili.
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
Sehemu muhimu za journal kwa triage ni pamoja na `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, na `MESSAGE`. Ikiwa journald ilisanidiwa bila persistent storage, tarajia tu data ya hivi karibuni chini ya `/run/log/journal/`.

### Audit framework triage (`auditd`)

Ikiwa `auditd` imewezeshwa, ipendelee kila unapohitaji **process attribution** kwa mabadiliko ya faili, utekelezaji wa amri, shughuli za login, au usakinishaji wa package.
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
Wakati sheria zilipotumika pamoja na keys, badala yake pivot kutoka kwao badala ya grepping raw logs:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux hudumisha historia ya amri kwa kila mtumiaji**, iliyohifadhiwa katika:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Zaidi ya hayo, amri `last -Faiwx` hutoa orodha ya user logins. Iangalie kwa logins zisizojulikana au zisizotarajiwa.

Angalia files ambazo zinaweza kutoa rprivileges za ziada:

- Kagua `/etc/sudoers` kwa user privileges zisizotarajiwa ambazo huenda zimetolewa.
- Kagua `/etc/sudoers.d/` kwa user privileges zisizotarajiwa ambazo huenda zimetolewa.
- Chunguza `/etc/groups` ili kutambua unusual group memberships au permissions.
- Chunguza `/etc/passwd` ili kutambua unusual group memberships au permissions.

Baadhi ya apps pia hutengeneza logs zake:

- **SSH**: Chunguza _\~/.ssh/authorized_keys_ na _\~/.ssh/known_hosts_ kwa unauthorized remote connections.
- **Gnome Desktop**: Angalia _\~/.recently-used.xbel_ kwa files zilizofikiwa hivi karibuni kupitia Gnome applications.
- **Firefox/Chrome**: Kagua browser history na downloads katika _\~/.mozilla/firefox_ au _\~/.config/google-chrome_ kwa suspicious activities.
- **VIM**: Kagua _\~/.viminfo_ kwa usage details, kama vile accessed file paths na search history.
- **Open Office**: Angalia recent document access ambayo inaweza kuonyesha files zilizoathiriwa.
- **FTP/SFTP**: Kagua logs katika _\~/.ftp_history_ au _\~/.sftp_history_ kwa file transfers ambazo huenda hazikuidhinishwa.
- **MySQL**: Chunguza _\~/.mysql_history_ kwa executed MySQL queries, ambayo huenda ikaonyesha unauthorized database activities.
- **Less**: Changanua _\~/.lesshst_ kwa usage history, ikijumuisha files zilizotazamwa na commands zilizotekelezwa.
- **Git**: Chunguza _\~/.gitconfig_ na project _.git/logs_ kwa changes to repositories.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) ni software ndogo iliyoandikwa kwa pure Python 3 ambayo huchambua Linux log files (`/var/log/syslog*` au `/var/log/messages*` kutegemea distro) ili kujenga USB event history tables.

Ni muhimu **kujua USB zote ambazo zimetumika** na itakuwa na manufaa zaidi ikiwa una orodha iliyoidhinishwa ya USBs ili kupata "violation events" (matumizi ya USBs ambazo hazimo ndani ya orodha hiyo).

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

## Kagua Akaunti za Mtumiaji na Shughuli za Logon

Chunguza _**/etc/passwd**_, _**/etc/shadow**_ na **security logs** kwa majina ya ajabu au akaunti zilizoundwa na au kutumika karibu na matukio yanayojulikana ya matumizi yasiyoruhusiwa. Pia, angalia mashambulizi yanayoweza kuwa ya sudo brute-force.\
Zaidi ya hayo, kagua faili kama _**/etc/sudoers**_ na _**/etc/groups**_ kwa privileges zisizotarajiwa zilizotolewa kwa watumiaji.\
Hatimaye, tafuta akaunti zenye **hakuna passwords** au passwords **rahisi kukisia**.

## Chunguza File System

### Kuchambua Miundo ya File System katika Uchunguzi wa Malware

Wakati wa kuchunguza matukio ya malware, muundo wa file system ni chanzo muhimu cha taarifa, ukifichua mfuatano wa matukio pamoja na maudhui ya malware. Hata hivyo, waandishi wa malware wanatengeneza mbinu za kuzuia uchambuzi huu, kama kubadilisha file timestamps au kuepuka file system kwa uhifadhi wa data.

Ili kukabiliana na mbinu hizi za anti-forensic, ni muhimu:

- **Kufanya timeline analysis ya kina** kwa kutumia tools kama **Autopsy** kwa kuonesha visually timelines za matukio au **Sleuth Kit's** `mactime` kwa detailed timeline data.
- **Kuchunguza scripts zisizotarajiwa** katika $PATH ya system, ambazo zinaweza kujumuisha shell au PHP scripts zinazotumiwa na washambuliaji.
- **Kuchunguza `/dev` kwa files zisizo za kawaida**, kwani kitamaduni huwa na special files, lakini huenda ikawa na malware-related files.
- **Kutafuta hidden files au directories** zenye majina kama ".. " (dot dot space) au "..^G" (dot dot control-G), ambazo zinaweza kuficha maudhui ya hasidi.
- **Kutambua setuid root files** kwa kutumia command: `find / -user root -perm -04000 -print` Hii hupata files zenye permissions zilizoinuliwa, ambazo zinaweza kutumiwa vibaya na washambuliaji.
- **Kagua deletion timestamps** katika inode tables ili kugundua mass file deletions, jambo linaloweza kuashiria uwepo wa rootkits au trojans.
- **Kagua consecutive inodes** kwa files hasidi zilizo karibu baada ya kutambua moja, kwa sababu huenda zimewekwa pamoja.
- **Angalia common binary directories** (_/bin_, _/sbin_) kwa files zilizobadilishwa hivi karibuni, kwani huenda zimebadilishwa na malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Kumbuka kuwa **mshambulizi** anaweza **kurekebisha** **wakati** ili kufanya **files ziweze kuonekana** **halali**, lakini hawezi **kurekebisha** **inode**. Ukigundua kwamba **file** inaonyesha kuwa iliundwa na kurekebishwa wakati **huohuo** na files nyingine kwenye folder hiyo hiyo, lakini **inode** ni **kubwa isivyotarajiwa**, basi **timestamps za file hiyo zilibadilishwa**.

### Inode-focused quick triage

Kama unashuku anti-forensics, endesha ukaguzi huu wa inode-focused mapema:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Wakati inode ya kutia shaka iko kwenye picha/kifaa cha filesystem ya EXT, kagua metadata ya inode moja kwa moja:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Sehemu muhimu:

- **Links**: ikiwa `0`, hakuna ingizo la saraka linalorejelea inode kwa sasa.
- **dtime**: muhuri wa muda wa ufutaji uliowekwa wakati inode ilipofunguliwa kutoka kwa kiungo.
- **ctime/mtime**: husaidia kuoanisha mabadiliko ya metadata/maudhui na ratiba ya tukio.

### Capabilities, xattrs, and preload-based userland rootkits

Ukaaji wa kudumu wa Linux wa kisasa mara nyingi huepuka **setuid** binaries zilizo wazi na badala yake hutumia vibaya **file capabilities**, **extended attributes**, na dynamic loader.
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
Zingatia sana libraries zilizorejelewa kutoka njia **writable** kama `/tmp`, `/dev/shm`, `/var/tmp`, au maeneo ya ajabu chini ya `/usr/local/lib`. Pia angalia binaries zenye capability ambazo ziko nje ya umiliki wa kawaida wa package na ulinganishe na matokeo ya package verification (`rpm -Va`, `dpkg --verify`, `debsums`).

## Linganisha files za tofauti za filesystem versions

### Muhtasari wa Ulinganisho wa Filesystem Version

Ili kulinganisha filesystem versions na kubaini mabadiliko, tunatumia simplified `git diff` commands:

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
- **Filter options** (`--diff-filter`) husaidia kupunguza hadi mabadiliko mahususi kama yaliyoongezwa (`A`), yaliyofutwa (`D`), au yaliyobadilishwa (`M`) files.
- `A`: Added files
- `C`: Copied files
- `D`: Deleted files
- `M`: Modified files
- `R`: Renamed files
- `T`: Type changes (e.g., file to symlink)
- `U`: Unmerged files
- `X`: Unknown files
- `B`: Broken files

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
