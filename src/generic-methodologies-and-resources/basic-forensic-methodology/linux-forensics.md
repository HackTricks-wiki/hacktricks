# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## प्रारंभिक जानकारी एकत्र करना

### बुनियादी जानकारी

सबसे पहले, यह अनुशंसित है कि आपके पास **USB** में कुछ **अच्छी और विश्वसनीय binaries और libraries** हों (आप बस ubuntu प्राप्त करके _/bin_, _/sbin_, _/lib,_ और _/lib64_ folders को कॉपी कर सकते हैं), फिर USB को mount करें और उन binaries का उपयोग करने के लिए env variables को संशोधित करें:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
एक बार जब आप system को अच्छे और ज्ञात binaries का उपयोग करने के लिए configure कर लें, तो आप **कुछ बुनियादी जानकारी extract करना** शुरू कर सकते हैं:
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
#### संदिग्ध जानकारी

बुनियादी जानकारी प्राप्त करते समय आपको अजीब चीज़ों की जाँच करनी चाहिए, जैसे:

- **Root processes** आमतौर पर कम PIDS के साथ चलते हैं, इसलिए यदि आपको बड़े PID वाला root process मिले, तो आपको संदेह हो सकता है
- `/etc/passwd` के अंदर बिना shell वाले users के **registered logins** की जाँच करें
- बिना shell वाले users के लिए `/etc/shadow` के अंदर **password hashes** की जाँच करें

### Memory Dump

चल रहे system की memory प्राप्त करने के लिए [**LiME**](https://github.com/504ensicsLabs/LiME) का उपयोग करने की सलाह दी जाती है।\
इसे **compile** करने के लिए आपको उसी **kernel** का उपयोग करना होगा, जिसका उपयोग victim machine कर रही है।

> [!TIP]
> याद रखें कि आप victim machine में **LiME या कोई अन्य चीज़ install नहीं कर सकते**, क्योंकि इससे उसमें कई बदलाव हो जाएंगे

इसलिए, यदि आपके पास Ubuntu का identical version है, तो आप `apt-get install lime-forensics-dkms` का उपयोग कर सकते हैं।\
अन्य मामलों में, आपको github से [**LiME**](https://github.com/504ensicsLabs/LiME) download करना होगा और इसे सही kernel headers के साथ compile करना होगा। victim machine के **exact kernel headers प्राप्त करने** के लिए, आप केवल `/lib/modules/<kernel version>` directory को अपनी machine पर **copy** कर सकते हैं और फिर उनका उपयोग करके LiME को **compile** कर सकते हैं:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME 3 **formats** को support करता है:

- Raw (हर segment को एक साथ concatenate किया गया है)
- Padded (Raw जैसा ही, लेकिन दाईं ओर के bits में zeroes के साथ)
- Lime (metadata वाला recommended format

LiME का उपयोग **dump को network के माध्यम से भेजने** के लिए भी किया जा सकता है, बजाय इसे system पर store करने के, जैसे: `path=tcp:4444`

### डिस्क इमेजिंग

#### सिस्टम बंद करना

सबसे पहले, आपको **system को बंद करना** होगा। यह हमेशा संभव नहीं होता, क्योंकि कभी-कभी system एक production server होता है, जिसे company बंद करने का खर्च नहीं उठा सकती।\
System को बंद करने के **2 तरीके** हैं: एक **normal shutdown** और दूसरा **"plug the plug" shutdown**। पहला तरीका **processes को सामान्य रूप से terminate होने** और **filesystem के synchronize होने** की अनुमति देता है, लेकिन यह संभावित **malware** को **evidence नष्ट करने** का अवसर भी देता है। "Pull the plug" approach से **कुछ information loss** हो सकता है (बहुत अधिक info खोने की संभावना नहीं है, क्योंकि हमने memory की image पहले ही ले ली है) और **malware को कुछ भी करने का अवसर नहीं मिलेगा**। इसलिए, यदि आपको **संदेह** है कि कोई **malware** हो सकता है, तो system पर केवल **`sync`** **command** execute करें और plug निकाल दें।

#### डिस्क की image लेना

यह ध्यान रखना महत्वपूर्ण है कि **अपने computer को case से संबंधित किसी भी चीज़ से connect करने से पहले**, आपको यह सुनिश्चित करना होगा कि वह information को modify होने से रोकने के लिए **read only के रूप में mounted** हो।
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Image का pre-analysis

ऐसी disk image का imaging जिसमें और कोई data नहीं है।
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
## ज्ञात Malware के लिए खोज

### संशोधित System Files

Linux system components की integrity सुनिश्चित करने के लिए tools प्रदान करता है, जो संभावित रूप से problematic files का पता लगाने में महत्वपूर्ण हैं।<sup>[[1]](#references)</sup>

- **RedHat-based systems**: व्यापक जाँच के लिए `rpm -Va` का उपयोग करें।
- **Debian-based systems**: प्रारंभिक verification के लिए `dpkg --verify` का उपयोग करें, इसके बाद किसी भी समस्या की पहचान करने के लिए `debsums | grep -v "OK$"` चलाएँ (`apt-get install debsums` से `debsums` install करने के बाद)।

### Malware/Rootkit Detectors

Malware खोजने में उपयोगी tools के बारे में जानने के लिए निम्नलिखित page पढ़ें:


{{#ref}}
malware-analysis.md
{{#endref}}

## installed programs की खोज

Debian और RedHat systems पर installed programs को प्रभावी ढंग से खोजने के लिए, सामान्य directories में manual checks के साथ system logs और databases का उपयोग करने पर विचार करें।<sup>[[1]](#references)</sup>

- Debian के लिए, package installations के विवरण प्राप्त करने हेतु _**`/var/lib/dpkg/status`**_ और _**`/var/log/dpkg.log`**_ का निरीक्षण करें और specific information को filter करने के लिए `grep` का उपयोग करें।
- RedHat users installed packages की सूची बनाने के लिए `rpm -qa --root=/mntpath/var/lib/rpm` से RPM database को query कर सकते हैं।

इन package managers के बाहर या manually installed software का पता लगाने के लिए _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, और _**`/sbin`**_ जैसी directories को explore करें। सभी installed programs की खोज को बेहतर बनाने के लिए directory listings को system-specific commands के साथ combine करें, ताकि known packages से संबद्ध न होने वाले executables की पहचान की जा सके।
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
## Deleted Running Binaries को Recover करें

कल्पना करें कि कोई process `/tmp/exec` से execute किया गया और फिर delete कर दिया गया। इसे extract करना संभव है
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## SQLite और FTS5 के साथ Syscall Trace Triage

जब कोई process अभी भी चल रहा हो या lab में उसे फिर से execute किया जा सकता हो, **`strace`** kernel modules या full EDR telemetry की आवश्यकता के बिना तेज़ behavioral trace प्रदान कर सकता है। बड़ी traces के लिए, raw log को सीधे पढ़ने या उसे किसी LLM में paste करने से बचें: उसे **SQLite** database में store करें और केवल आवश्यक minimal subset को query करें।<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> `strace` attach करने से process timing बदल सकती है और race conditions या अन्य fragile bugs प्रभावित हो सकते हैं। जब संभव हो, copy/lab system पर reproduction करना बेहतर है।

### Capture

नए process के लिए:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
एक live process के लिए:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
उपयोगी विकल्प:

- `-ff`: forks/threads को follow करें और प्रत्येक process के outputs अलग रखें
- `-ttt`: आसान timeline correlation के लिए epoch timestamps
- `-yy`: संभव होने पर file descriptors को backing paths/sockets में resolve करें
- `-s 4096`: लंबे path और buffer arguments को truncate होने से बचाएं

### Normalize

एक व्यावहारिक schema में प्रत्येक syscall और प्रत्येक argument के लिए एक row होती है:
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
यह heterogeneous syscall lines को एक single wide table में flatten करने की कोशिश से बचाता है और triage के दौरान joins को predictable बनाए रखता है।

### FTS5 के साथ text-heavy arguments को index करें

बड़े traces पर `LIKE "%...%"` के साथ naive path hunting बहुत धीमी हो जाती है। Arguments के text के लिए FTS5 index बनाएं और इसके बजाय उसमें search करें:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
उदाहरण: हर row को scan किए बिना `/tmp` के अंतर्गत file activity recover करें:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### उच्च-सिग्नल जांच

- **PATH hijacking / fake sudo**: `~/.local/bin/` के अंतर्गत writes और `chmod`/`rename` activity खोजें, फिर इसे `sudo` जैसे privileged-looking names के बाद होने वाले `execve` से correlate करें।
- **अस्थायी फ़ाइलों पर TOCTOU**: check/use gaps की पहचान करने के लिए समान `/tmp/...` path को `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` और `execve` के दौरान track करें।
- **Crash का मूल कारण**: किसी फ़ाइल के `mmap` को उसी inode/path को किसी अन्य process द्वारा किए गए writes या truncation से correlate करें, फिर `SIGBUS` के लिए signal/exit sequence की जांच करें।
- **Network destination recovery**: peer IPs और ports निकालने के लिए `connect`, `sendto`, `sendmsg`, `recvfrom` और socket-related arguments को filter करें।

### LLM-assisted trace analysis

यदि आप LLM की सहायता लेना चाहते हैं, तो उसे एक **read-only** SQLite handle दें और पूरा schema उपलब्ध कराएं। Database को narrow helper functions के पीछे wrap करने के बजाय उसे raw SQL चलाने दें। Joins, temporal correlation और FTS lookups के लिए यह आमतौर पर बेहतर काम करता है।

व्यावहारिक नियम:

- Database को read-only रखें, उदाहरण के लिए `sqlite3 'file:trace.db?mode=ro'` के साथ।
- Model को valid `JOIN` और `FTS5 MATCH` queries के उदाहरण दें।
- Raw multi-GB `strace` logs को prompt में paste **न करें**।
- Focused questions पूछें, जैसे:
- "इस program द्वारा लिखी गई persistent files की सूची दें।"
- "क्या इसने user-controlled PATH directories में executables बनाए या replace किए?"
- "समझाएं कि यह trace SIGBUS पर क्यों समाप्त होती है।"

## Autostart locations की जांच करें

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
हमलावर periodic execution सुनिश्चित करने के लिए अक्सर प्रत्येक /etc/cron.*/ directory में मौजूद 0anacron stub को edit करते हैं।<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH hardening rollback और backdoor shells
sshd_config और system account shells में changes access बनाए रखने के लिए common post-exploitation तकनीक हैं।<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons आमतौर पर HTTPS पर Authorization: Bearer tokens के साथ api.dropboxapi.com या content.dropboxapi.com का उपयोग करते हैं।
- servers से होने वाले unexpected Dropbox egress के लिए proxy/Zeek/NetFlow में Hunt करें।
- Cloudflare Tunnel (`cloudflared`) outbound 443 पर backup C2 प्रदान करता है।<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

वे paths जहाँ malware को service के रूप में install किया जा सकता है:

- **/etc/inittab**: rc.sysinit जैसी initialization scripts को call करता है और आगे startup scripts को निर्देशित करता है।
- **/etc/rc.d/** और **/etc/rc.boot/**: service startup के लिए scripts रखते हैं; बाद वाला पुराने Linux versions में पाया जाता है।
- **/etc/init.d/**: Debian जैसे कुछ Linux versions में startup scripts रखने के लिए उपयोग किया जाता है।
- Services को **/etc/inetd.conf** या **/etc/xinetd/** के माध्यम से भी activate किया जा सकता है, जो Linux variant पर निर्भर करता है।
- **/etc/systemd/system**: system और service manager scripts के लिए directory।
- **/etc/systemd/system/multi-user.target.wants/**: उन services के links रखता है जिन्हें multi-user runlevel में start किया जाना चाहिए।
- **/usr/local/etc/rc.d/**: custom या third-party services के लिए।
- **\~/.config/autostart/**: user-specific automatic startup applications के लिए, जो user-targeted malware के लिए hiding spot हो सकता है।
- **/lib/systemd/system/**: installed packages द्वारा प्रदान की गई system-wide default unit files।

#### Hunt: systemd timers and transient units

Systemd persistence केवल `.service` files तक सीमित नहीं है। `.timer` units, user-level units और runtime पर बनाए गए **transient units** की जाँच करें।
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
Transient units को आसानी से नजरअंदाज किया जा सकता है क्योंकि `/run/systemd/transient/` **non-persistent** है। यदि आप live image एकत्र कर रहे हैं, तो shutdown से पहले इसे प्राप्त कर लें।

### Kernel Modules

Linux kernel modules, जिन्हें malware अक्सर rootkit components के रूप में उपयोग करता है, system boot के समय load किए जाते हैं। इन modules से संबंधित महत्वपूर्ण directories और files में शामिल हैं:

- **/lib/modules/$(uname -r)**: चल रहे kernel version के modules रखता है।
- **/etc/modprobe.d**: module loading को नियंत्रित करने वाली configuration files रखता है।
- **/etc/modprobe** और **/etc/modprobe.conf**: global module settings के लिए files।

### Other Autostart Locations

Linux user login पर programs को automatically execute करने के लिए विभिन्न files का उपयोग करता है, जिनमें malware छिपा हो सकता है:

- **/etc/profile.d/**\*, **/etc/profile**, और **/etc/bash.bashrc**: किसी भी user login पर execute होते हैं।
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, और **\~/.config/autostart**: user-specific files हैं, जो उनके login पर run होती हैं।
- **/etc/rc.local**: सभी system services शुरू होने के बाद run होता है और multiuser environment में transition के अंत को दर्शाता है।

## Examine Logs

Linux systems विभिन्न log files के माध्यम से user activities और system events को track करते हैं। ये logs unauthorized access, malware infections और अन्य security incidents की पहचान करने के लिए महत्वपूर्ण हैं।<sup>[[2]](#references)</sup> मुख्य log files में शामिल हैं:

- **/var/log/syslog** (Debian) या **/var/log/messages** (RedHat): system-wide messages और activities capture करते हैं।
- **/var/log/auth.log** (Debian) या **/var/log/secure** (RedHat): authentication attempts तथा successful और failed logins record करते हैं।
- Relevant authentication events को filter करने के लिए `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` का उपयोग करें।
- **/var/log/boot.log**: system startup messages रखता है।
- **/var/log/maillog** या **/var/log/mail.log**: email server activities log करता है और email-related services को track करने में उपयोगी है।
- **/var/log/kern.log**: errors और warnings सहित kernel messages store करता है।
- **/var/log/dmesg**: device driver messages रखता है।
- **/var/log/faillog**: failed login attempts record करता है, जिससे security breach investigations में सहायता मिलती है।
- **/var/log/cron**: cron job executions log करता है।
- **/var/log/daemon.log**: background service activities track करता है।
- **/var/log/btmp**: failed login attempts का documentation रखता है।
- **/var/log/httpd/**: Apache HTTPD error और access logs रखता है।
- **/var/log/mysqld.log** या **/var/log/mysql.log**: MySQL database activities log करता है।
- **/var/log/xferlog**: FTP file transfers record करता है।
- **/var/log/**: unexpected logs के लिए हमेशा यहां जांच करें।

> [!TIP]
> Linux system logs और audit subsystems को intrusion या malware incident के दौरान disable या delete किया जा सकता है। चूंकि Linux systems पर logs में आम तौर पर malicious activities से संबंधित सबसे उपयोगी information होती है, intruders उन्हें नियमित रूप से delete करते हैं। इसलिए, उपलब्ध log files की जांच करते समय gaps या out-of-order entries पर ध्यान देना महत्वपूर्ण है, जो deletion या tampering का संकेत हो सकते हैं।

### Journald triage (`journalctl`)

आधुनिक Linux hosts पर **systemd journal**, आम तौर पर **service execution**, **auth events**, **package operations**, और **kernel/user-space messages** के लिए सबसे महत्वपूर्ण source होता है। Live response के दौरान **persistent** journal (`/var/log/journal/`) और **runtime** journal (`/run/log/journal/`) दोनों को preserve करने का प्रयास करें, क्योंकि short-lived attacker activity केवल बाद वाले में मौजूद हो सकती है।<sup>[[5]](#references)</sup>
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
Triage के लिए उपयोगी journal fields में `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, और `MESSAGE` शामिल हैं। यदि journald को persistent storage के बिना configure किया गया था, तो `/run/log/journal/` के अंतर्गत केवल हालिया data की अपेक्षा करें।

### Audit framework triage (`auditd`)

यदि `auditd` enabled है, तो file changes, command execution, login activity या package installation के लिए **process attribution** आवश्यक होने पर इसे प्राथमिकता दें।<sup>[[6]](#references)</sup>
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
जब rules को keys के साथ deploy किया गया हो, तो raw logs में grep करने के बजाय उनसे pivot करें:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux प्रत्येक user के लिए command history बनाए रखता है**, जो इनमें stored होती है:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

इसके अलावा, `last -Faiwx` command user logins की list प्रदान करती है। Unknown या unexpected logins के लिए इसकी जाँच करें।

उन files की जाँच करें जो extra privileges प्रदान कर सकती हैं:

- `/etc/sudoers` की समीक्षा करें और देखें कि कहीं अप्रत्याशित user privileges grant तो नहीं किए गए हैं।
- `/etc/sudoers.d/` की समीक्षा करें और देखें कि कहीं अप्रत्याशित user privileges grant तो नहीं किए गए हैं।
- किसी भी असामान्य group memberships या permissions की पहचान करने के लिए `/etc/groups` की जाँच करें।
- किसी भी असामान्य group memberships या permissions की पहचान करने के लिए `/etc/passwd` की जाँच करें।

कुछ apps अपने स्वयं के logs भी generate करते हैं:

- **SSH**: unauthorized remote connections के लिए _\~/.ssh/authorized_keys_ और _\~/.ssh/known_hosts_ की जाँच करें।
- **Gnome Desktop**: Gnome applications के माध्यम से हाल ही में access की गई files के लिए _\~/.recently-used.xbel_ देखें।
- **Firefox/Chrome**: suspicious activities के लिए _\~/.mozilla/firefox_ या _\~/.config/google-chrome_ में browser history और downloads की जाँच करें।
- **VIM**: usage details, जैसे accessed file paths और search history, के लिए _\~/.viminfo_ की समीक्षा करें।
- **Open Office**: हाल ही में किए गए document access की जाँच करें, जो compromised files का संकेत दे सकता है।
- **FTP/SFTP**: unauthorized होने वाले file transfers के लिए _\~/.ftp_history_ या _\~/.sftp_history_ में logs की समीक्षा करें।
- **MySQL**: executed MySQL queries के लिए _\~/.mysql_history_ की जाँच करें, जो unauthorized database activities को उजागर कर सकती हैं।
- **Less**: usage history के लिए _\~/.lesshst_ का विश्लेषण करें, जिसमें viewed files और executed commands शामिल हैं।
- **Git**: repositories में हुए changes के लिए _\~/.gitconfig_ और project _.git/logs_ की जाँच करें।

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) pure Python 3 में लिखा गया एक छोटा software है, जो USB event history tables बनाने के लिए Linux log files (`/var/log/syslog*` या distro के अनुसार `/var/log/messages*`) को parse करता है।

यह **जानना महत्वपूर्ण है कि किन सभी USBs का उपयोग किया गया है**, और यदि आपके पास USBs की authorized list हो, तो यह और भी उपयोगी होगा, ताकि "violation events" (ऐसे USBs का उपयोग जो उस list में शामिल नहीं हैं) का पता लगाया जा सके।

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### उदाहरण
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
github के अंदर अधिक उदाहरण और जानकारी: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## User Accounts और Logon Activities की समीक्षा करें

ज्ञात unauthorized घटनाओं के आसपास बनाए गए या उपयोग किए गए असामान्य नामों या accounts के लिए _**/etc/passwd**_, _**/etc/shadow**_ और **security logs** की जांच करें। साथ ही, संभावित sudo brute-force attacks की भी जांच करें।\
इसके अलावा, users को दिए गए अप्रत्याशित privileges के लिए _**/etc/sudoers**_ और _**/etc/groups**_ जैसी files की जांच करें।\
अंत में, ऐसे accounts खोजें जिनके पास **passwords नहीं हैं** या **आसानी से guess किए जा सकने वाले** passwords हैं।<sup>[[1]](#references)</sup>

## File System की जांच करें

### Malware Investigation में File System Structures का विश्लेषण

Malware incidents की जांच करते समय, file system की structure information का एक महत्वपूर्ण source होती है, जो events के sequence और malware के content दोनों को प्रकट करती है। हालांकि, malware authors इस analysis में बाधा डालने के लिए techniques विकसित कर रहे हैं, जैसे file timestamps को modify करना या data storage के लिए file system का उपयोग करने से बचना।<sup>[[1]](#references)</sup>

इन anti-forensic methods का मुकाबला करने के लिए, यह आवश्यक है कि:

- **Tools जैसे **Autopsy** का उपयोग करके thorough timeline analysis करें**, ताकि event timelines को visualize किया जा सके, या detailed timeline data के लिए **Sleuth Kit's** `mactime` का उपयोग करें।
- System के $PATH में **unexpected scripts की जांच करें**, जिनमें attackers द्वारा उपयोग की जाने वाली shell या PHP scripts शामिल हो सकती हैं।
- **`/dev` में atypical files की जांच करें**, क्योंकि इसमें आमतौर पर special files होती हैं, लेकिन इसमें malware-related files भी हो सकती हैं।
- ".. " (dot dot space) या "..^G" (dot dot control-G) जैसे नामों वाली **hidden files या directories खोजें**, जो malicious content को छिपा सकती हैं।
- Command का उपयोग करके **setuid root files की पहचान करें**: `find / -user root -perm -04000 -print` यह elevated permissions वाली files खोजता है, जिनका attackers द्वारा दुरुपयोग किया जा सकता है।
- Mass file deletions का पता लगाने के लिए inode tables में **deletion timestamps की समीक्षा करें**, जो rootkits या trojans की मौजूदगी का संकेत दे सकता है।
- किसी malicious file की पहचान करने के बाद उसके पास मौजूद **consecutive inodes का निरीक्षण करें**, क्योंकि संभव है कि उन्हें एक साथ रखा गया हो।
- Recently modified files के लिए common binary directories (_/bin_, _/sbin_) की **जांच करें**, क्योंकि malware द्वारा इनमें बदलाव किया गया हो सकता है।
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> ध्यान दें कि एक **attacker** **time** को **modify** करके **files appear** को **legitimate** बना सकता है, लेकिन वह **inode** को **modify** नहीं कर सकता। यदि आपको पता चलता है कि कोई **file** उसी folder की बाकी files के **same time** पर बनाए और modified किए जाने का संकेत देती है, लेकिन उसका **inode** **unexpectedly bigger** है, तो उस file के **timestamps modified** किए गए थे।

### Inode-focused quick triage

यदि आपको **anti-forensics** का संदेह है, तो ये inode-focused checks जल्दी चलाएँ:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
जब कोई संदिग्ध inode EXT filesystem image/device पर हो, तो inode metadata का सीधे निरीक्षण करें:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
उपयोगी फ़ील्ड:
- **Links**: यदि `0` है, तो वर्तमान में कोई भी directory entry inode को reference नहीं करती।
- **dtime**: inode के unlink होने पर सेट किया गया deletion timestamp।
- **ctime/mtime**: metadata/content में हुए बदलावों को incident timeline के साथ correlate करने में मदद करता है।

### Capabilities, xattrs, और preload-based userland rootkits

Modern Linux persistence अक्सर स्पष्ट `setuid` binaries से बचती है और इसके बजाय **file capabilities**, **extended attributes**, तथा dynamic loader का दुरुपयोग करती है।
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
**writable** paths जैसे `/tmp`, `/dev/shm`, `/var/tmp`, या `/usr/local/lib` के अंतर्गत असामान्य स्थानों से संदर्भित libraries पर विशेष ध्यान दें। सामान्य package ownership से बाहर capability-bearing binaries की भी जाँच करें और उन्हें package verification परिणामों (`rpm -Va`, `dpkg --verify`, `debsums`) से correlate करें।

## अलग-अलग filesystem versions की files की तुलना करें

### Filesystem Version Comparison Summary

Filesystem versions की तुलना करने और परिवर्तनों को pinpoint करने के लिए, हम सरल `git diff` commands का उपयोग करते हैं:<sup>[[3]](#references)</sup>

- **नई files खोजने के लिए**, दो directories की तुलना करें:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **संशोधित सामग्री** के लिए, विशिष्ट पंक्तियों को अनदेखा करते हुए परिवर्तनों की सूची दें:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **हटाई गई फ़ाइलों का पता लगाने के लिए**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) विशिष्ट बदलावों तक सीमित करने में मदद करते हैं, जैसे जोड़ी गई (`A`), हटाई गई (`D`), या संशोधित (`M`) files।
- `A`: जोड़ी गई files
- `C`: कॉपी की गई files
- `D`: हटाई गई files
- `M`: संशोधित files
- `R`: नाम बदली गई files
- `T`: Type में बदलाव (जैसे, file से symlink)
- `U`: Merge न की गई files
- `X`: अज्ञात files
- `B`: खराब files

## संदर्भ

- [1] [Linux Systems के लिए Malware Forensics Field Guide: Digital Forensics Field Guides – Chapter 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Linux Logs की व्याख्या](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [git diff Documentation – --diff-filter option](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Persistence के लिए Patching: DripDropper Linux malware cloud में कैसे आगे बढ़ता है](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Linux Journals का Forensic Analysis](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - System का Auditing](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Say hi to Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
