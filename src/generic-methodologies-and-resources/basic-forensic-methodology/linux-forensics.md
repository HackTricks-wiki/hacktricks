# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## प्रारंभिक जानकारी एकत्र करना

### बुनियादी जानकारी

सबसे पहले, कुछ **USB** रखना recommended है जिसमें **good known binaries and libraries** हों (आप बस ubuntu ले सकते हैं और folders _/bin_, _/sbin_, _/lib,_ और _/lib64_ copy कर सकते हैं), फिर USB mount करें, और उन binaries को use करने के लिए env variables modify करें:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
एक बार जब आपने सिस्टम को अच्छे और ज्ञात binaries का उपयोग करने के लिए configured कर लिया है, तो आप **कुछ basic information निकालना** शुरू कर सकते हैं:
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

जब आप मूल जानकारी प्राप्त कर रहे हों, तो आपको ऐसी अजीब चीज़ों की जाँच करनी चाहिए जैसे:

- **Root processes** आमतौर पर कम PIDS के साथ चलते हैं, इसलिए यदि आपको बड़ा PID वाला root process मिले तो आपको संदेह हो सकता है
- `/etc/passwd` में shell के बिना users के **registered logins** की जाँच करें
- shell के बिना users के लिए `/etc/shadow` के अंदर **password hashes** की जाँच करें

### Memory Dump

चल रहे system की memory प्राप्त करने के लिए, [**LiME**](https://github.com/504ensicsLabs/LiME) का उपयोग करने की सलाह दी जाती है।\
इसे **compile** करने के लिए, आपको वही **kernel** इस्तेमाल करना होगा जो victim machine उपयोग कर रही है।

> [!TIP]
> याद रखें कि आप victim machine पर LiME या कोई और चीज़ **install नहीं** कर सकते, क्योंकि इससे उसमें कई बदलाव हो जाएंगे

तो, यदि आपके पास Ubuntu का एक identical version है, तो आप `apt-get install lime-forensics-dkms` का उपयोग कर सकते हैं\
अन्य मामलों में, आपको github से [**LiME**](https://github.com/504ensicsLabs/LiME) डाउनलोड करना होगा और उसे सही kernel headers के साथ compile करना होगा। victim machine के exact kernel headers **प्राप्त** करने के लिए, आप बस `/lib/modules/<kernel version>` directory को अपनी machine पर **copy** कर सकते हैं, और फिर उन्हीं का उपयोग करके LiME को **compile** कर सकते हैं:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME 3 **formats** को support करता है:

- Raw (हर segment को concatenate करके)
- Padded (raw जैसा ही, लेकिन right bits में zeroes के साथ)
- Lime (metadata के साथ recommended format)

LiME का use **network के जरिए dump भेजने** के लिए भी किया जा सकता है, बजाय इसे system पर store करने के, जैसे: `path=tcp:4444`

### Disk Imaging

#### Shutting down

सबसे पहले, आपको **system को shut down** करना होगा। यह हमेशा possible नहीं होता क्योंकि कई बार system एक production server होता है जिसे company shut down afford नहीं कर सकती।\
System को shut down करने के **2 तरीके** हैं, एक **normal shutdown** और एक **"plug the plug" shutdown**। पहला तरीका **processes को usual तरीके से terminate** होने देगा और **filesystem** को **synchronize** करेगा, लेकिन यह possible **malware** को **evidence destroy** करने का भी मौका देगा। "pull the plug" approach में **कुछ information loss** हो सकता है (memory का image हम पहले ही ले चुके हैं, इसलिए ज्यादा info lost नहीं होगी) और **malware के पास** कुछ भी करने का **मौका नहीं** होगा। इसलिए, अगर आपको **suspect** है कि **malware** हो सकता है, तो बस system पर **`sync`** **command** execute करें और plug खींच दें।

#### Taking an image of the disk

यह ध्यान रखना important है कि **अपने computer को case से related किसी भी चीज़ से connect करने से पहले**, आपको सुनिश्चित करना होगा कि यह **read only** के रूप में **mounted** होगा ताकि कोई information modify न हो।
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### डिस्क इमेज पूर्व-विश्लेषण

बिना किसी अतिरिक्त डेटा के disk image की imaging करना।
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
## ज्ञात Malware के लिए Search करें

### Modified System Files

Linux system components की integrity सुनिश्चित करने के लिए tools प्रदान करता है, जो potentially problematic files को spot करने के लिए crucial हैं।

- **RedHat-based systems**: comprehensive check के लिए `rpm -Va` का use करें।
- **Debian-based systems**: initial verification के लिए `dpkg --verify`, फिर किसी भी issue को identify करने के लिए `debsums | grep -v "OK$"` ( `debsums` को `apt-get install debsums` से install करने के बाद) का use करें।

### Malware/Rootkit Detectors

मालware ढूँढने में useful tools के बारे में जानने के लिए निम्न page पढ़ें:


{{#ref}}
malware-analysis.md
{{#endref}}

## Installed programs के लिए Search करें

Debian और RedHat दोनों systems पर installed programs को effectively search करने के लिए, common directories में manual checks के साथ system logs और databases का use करने पर विचार करें।

- Debian के लिए, package installations की details निकालने हेतु _**`/var/lib/dpkg/status`**_ और _**`/var/log/dpkg.log`**_ inspect करें, specific information को filter करने के लिए `grep` का use करें।
- RedHat users installed packages की list देखने के लिए RPM database को `rpm -qa --root=/mntpath/var/lib/rpm` से query कर सकते हैं।

Package managers के बाहर manually या installed software को uncover करने के लिए _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, और _**`/sbin`**_ जैसी directories को explore करें। सभी installed programs के लिए अपनी search को बेहतर बनाने हेतु directory listings को system-specific commands के साथ combine करें ताकि ऐसे executables identify हों जो known packages से associated नहीं हैं।
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
## हटाए गए चल रहे बाइनरीज़ को रिकवर करें

एक ऐसे process की कल्पना करें जो /tmp/exec से execute किया गया था और फिर delete कर दिया गया। इसे extract करना संभव है
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## SQLite और FTS5 के साथ Syscall Trace Triage

जब कोई process अभी भी चल रहा हो या lab में फिर से execute किया जा सके, **`strace`** kernel modules या full EDR telemetry की जरूरत के बिना तेज behavioral trace दे सकता है। बड़े traces के लिए, raw log को सीधे पढ़ने या उसे किसी LLM में paste करने से बचें: इसे एक **SQLite** database में store करें और केवल वही minimal subset query करें जिसकी आपको जरूरत है।

> [!WARNING]
> `strace` attach करने से process timing बदलती है और race conditions या अन्य fragile bugs प्रभावित हो सकते हैं। संभव हो तो copy/lab system पर reproduce करना बेहतर है।

### Capture

एक नए process के लिए:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
एक live process के लिए:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
उपयोगी विकल्प:

- `-ff`: forks/threads का follow करें और प्रति-process outputs को अलग रखें
- `-ttt`: आसान timeline correlation के लिए epoch timestamps
- `-yy`: जब संभव हो, file descriptors को backing paths/sockets पर resolve करें
- `-s 4096`: लंबे path और buffer arguments को truncate होने से बचाएँ

### Normalize

एक practical schema है प्रति syscall एक row और प्रति argument एक row:
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
यह heterogeneous syscall lines को एक single wide table में flatten करने की कोशिश से बचाता है और triage के दौरान joins को predictable रखता है।

### Index text-heavy arguments with FTS5

Naive path hunting with `LIKE "%...%"` बड़े traces पर बहुत धीमा हो जाता है। इसके बजाय argument text के लिए एक FTS5 index बनाएं और उसी से search करें:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
उदाहरण: हर row को scan किए बिना `/tmp` के तहत file activity recover करें:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### उच्च-सिग्नल जाँचें

- **PATH hijacking / fake sudo**: `~/.local/bin/` के तहत writes और `chmod`/`rename` activity खोजें, फिर बाद में `execve` of privileged-looking names जैसे `sudo` के साथ correlate करें।
- **TOCTOU on temporary files**: same `/tmp/...` path पर `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink`, और `execve` के across pivot करें ताकि check/use gaps identify हो सकें।
- **Crash root cause**: किसी file के `mmap` को same inode/path पर दूसरे process द्वारा किए गए writes या truncation के साथ correlate करें, फिर `SIGBUS` के लिए signal/exit sequence inspect करें।
- **Network destination recovery**: `connect`, `sendto`, `sendmsg`, `recvfrom`, और socket-related arguments filter करें ताकि peer IPs और ports extract किए जा सकें।

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
#### हंट: Cron/Anacron abuse via 0anacron और संदिग्ध stubs
Attackers अक्सर प्रत्येक /etc/cron.*/ directory के अंदर मौजूद 0anacron stub को edit करते हैं ताकि periodic execution सुनिश्चित हो सके।
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH hardening rollback and backdoor shells
sshd_config और system account shells में किए गए बदलाव post‑exploitation के बाद access बनाए रखने के लिए आम हैं।
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons typically use api.dropboxapi.com or content.dropboxapi.com over HTTPS with Authorization: Bearer tokens.
- proxy/Zeek/NetFlow में unexpected Dropbox egress को servers से hunt करें।
- Cloudflare Tunnel (`cloudflared`) outbound 443 के over backup C2 provide करता है।
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Paths where a malware could be installed as a service:

- **/etc/inittab**: प्रारंभिक scripts जैसे rc.sysinit को कॉल करता है, जो आगे startup scripts की ओर निर्देशित करता है।
- **/etc/rc.d/** और **/etc/rc.boot/**: service startup के लिए scripts होते हैं, latter पुराने Linux versions में पाया जाता है।
- **/etc/init.d/**: Debian जैसे कुछ Linux versions में startup scripts store करने के लिए उपयोग किया जाता है।
- Services को **/etc/inetd.conf** या **/etc/xinetd/** के जरिए भी activate किया जा सकता है, Linux variant के अनुसार।
- **/etc/systemd/system**: system और service manager scripts के लिए एक directory।
- **/etc/systemd/system/multi-user.target.wants/**: multi-user runlevel में start होने वाली services के links होते हैं।
- **/usr/local/etc/rc.d/**: custom या third-party services के लिए।
- **\~/.config/autostart/**: user-specific automatic startup applications के लिए, जो user-targeted malware के लिए hiding spot हो सकता है।
- **/lib/systemd/system/**: installed packages द्वारा दिए गए system-wide default unit files।

#### Hunt: systemd timers and transient units

Systemd persistence केवल `.service` files तक सीमित नहीं है। `.timer` units, user-level units, और runtime पर बनाए गए **transient units** की जांच करें।
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
Transient units को मिस करना आसान है क्योंकि `/run/systemd/transient/` **non-persistent** है। अगर आप live image collect कर रहे हैं, तो shutdown से पहले इसे grab कर लें।

### Kernel Modules

Linux kernel modules, जो अक्सर malware द्वारा rootkit components के रूप में उपयोग किए जाते हैं, system boot पर load होते हैं। इन modules के लिए महत्वपूर्ण directories और files हैं:

- **/lib/modules/$(uname -r)**: चल रहे kernel version के लिए modules रखता है।
- **/etc/modprobe.d**: module loading को control करने के लिए configuration files होती हैं।
- **/etc/modprobe** और **/etc/modprobe.conf**: global module settings के लिए files।

### Other Autostart Locations

Linux उपयोगकर्ता login के दौरान programs को automatically execute करने के लिए विभिन्न files का उपयोग करता है, जिनमें malware हो सकता है:

- **/etc/profile.d/**\*, **/etc/profile**, और **/etc/bash.bashrc**: किसी भी user login के लिए execute होते हैं।
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, और **\~/.config/autostart**: user-specific files जो उनके login पर run होती हैं।
- **/etc/rc.local**: सभी system services शुरू होने के बाद run होता है, जो multiuser environment में transition का अंत दर्शाता है।

## Examine Logs

Linux systems विभिन्न log files के माध्यम से user activities और system events को track करते हैं। ये logs unauthorized access, malware infections, और अन्य security incidents की पहचान के लिए महत्वपूर्ण हैं। प्रमुख log files में शामिल हैं:

- **/var/log/syslog** (Debian) या **/var/log/messages** (RedHat): system-wide messages और activities capture करते हैं।
- **/var/log/auth.log** (Debian) या **/var/log/secure** (RedHat): authentication attempts, सफल और असफल logins रिकॉर्ड करते हैं।
- `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` का उपयोग relevant authentication events filter करने के लिए करें।
- **/var/log/boot.log**: system startup messages रखता है।
- **/var/log/maillog** या **/var/log/mail.log**: email server activities के logs, email-related services को track करने के लिए उपयोगी।
- **/var/log/kern.log**: kernel messages, including errors and warnings, store करता है।
- **/var/log/dmesg**: device driver messages रखता है।
- **/var/log/faillog**: failed login attempts रिकॉर्ड करता है, security breach investigations में मदद करता है।
- **/var/log/cron**: cron job executions logs करता है।
- **/var/log/daemon.log**: background service activities track करता है।
- **/var/log/btmp**: failed login attempts documents करता है।
- **/var/log/httpd/**: Apache HTTPD error और access logs रखता है।
- **/var/log/mysqld.log** या **/var/log/mysql.log**: MySQL database activities logs करता है।
- **/var/log/xferlog**: FTP file transfers रिकॉर्ड करता है।
- **/var/log/**: यहाँ हमेशा unexpected logs check करें।

> [!TIP]
> Linux system logs और audit subsystems किसी intrusion या malware incident के दौरान disabled या deleted हो सकते हैं। क्योंकि Linux systems पर logs आम तौर पर malicious activities के बारे में सबसे उपयोगी जानकारी रखते हैं, intruders इन्हें अक्सर delete कर देते हैं। इसलिए, उपलब्ध log files की जांच करते समय gaps या out of order entries देखना महत्वपूर्ण है, जो deletion या tampering का संकेत हो सकते हैं।

### Journald triage (`journalctl`)

Modern Linux hosts पर, **systemd journal** आमतौर पर **service execution**, **auth events**, **package operations**, और **kernel/user-space messages** के लिए सबसे उच्च-मूल्य स्रोत होता है। Live response के दौरान, **persistent** journal (`/var/log/journal/`) और **runtime** journal (`/run/log/journal/`) दोनों को preserve करने की कोशिश करें, क्योंकि short-lived attacker activity केवल दूसरे में मौजूद हो सकती है।
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
ट्रायेज के लिए उपयोगी journal fields में `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, और `MESSAGE` शामिल हैं। यदि journald को persistent storage के बिना configure किया गया था, तो केवल हालिया data `/run/log/journal/` के तहत अपेक्षित होगा।

### Audit framework ट्रायेज (`auditd`)

यदि `auditd` enabled है, तो file changes, command execution, login activity, या package installation के लिए **process attribution** की जरूरत होने पर इसे प्राथमिकता दें।
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
जब rules keys के साथ deployed किए गए थे, तो raw logs को grepping करने के बजाय उनसे pivot करें:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux प्रत्येक user के लिए command history बनाए रखता है**, जो यहां stored होती है:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

इसके अलावा, `last -Faiwx` command user logins की list प्रदान करती है। इसे unknown या unexpected logins के लिए check करें।

ऐसी files check करें जो extra rprivileges दे सकती हैं:

- अनअपेक्षित user privileges जो grant किए गए हों, उनके लिए `/etc/sudoers` review करें।
- अनअपेक्षित user privileges जो grant किए गए हों, उनके लिए `/etc/sudoers.d/` review करें।
- किसी unusual group memberships या permissions की पहचान करने के लिए `/etc/groups` examine करें।
- किसी unusual group memberships या permissions की पहचान करने के लिए `/etc/passwd` examine करें।

कुछ apps अपनी खुद की logs भी generate करते हैं:

- **SSH**: unauthorized remote connections के लिए _\~/.ssh/authorized_keys_ और _\~/.ssh/known_hosts_ examine करें।
- **Gnome Desktop**: Gnome applications के माध्यम से recently accessed files के लिए _\~/.recently-used.xbel_ देखें।
- **Firefox/Chrome**: suspicious activities के लिए _\~/.mozilla/firefox_ या _\~/.config/google-chrome_ में browser history और downloads check करें।
- **VIM**: accessed file paths और search history जैसी usage details के लिए _\~/.viminfo_ review करें।
- **Open Office**: recent document access check करें, जो compromised files का संकेत दे सकता है।
- **FTP/SFTP**: unauthorized हो सकने वाले file transfers के लिए _\~/.ftp_history_ या _\~/.sftp_history_ में logs review करें।
- **MySQL**: executed MySQL queries के लिए _\~/.mysql_history_ investigate करें, जो unauthorized database activities को reveal कर सकती हैं।
- **Less**: viewed files और executed commands सहित usage history के लिए _\~/.lesshst_ analyze करें।
- **Git**: repositories में changes के लिए _\~/.gitconfig_ और project _.git/logs_ examine करें।

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) एक छोटा software है जो pure Python 3 में लिखा गया है, जो USB event history tables बनाने के लिए Linux log files (`/var/log/syslog*` या `/var/log/messages*` distro पर निर्भर करता है) parse करता है।

यह **जानना महत्वपूर्ण है कि कौन-कौन से USBs इस्तेमाल हुए हैं** और यदि आपके पास USBs की एक authorized list है, तो यह "violation events" (उन USBs का use जो उस list में नहीं हैं) खोजने में अधिक उपयोगी होगा।

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
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## User Accounts और Logon Activities की समीक्षा करें

_**/etc/passwd**_, _**/etc/shadow**_ और **security logs** की जांच करें ताकि असामान्य नाम या ऐसे accounts मिलें जो known unauthorized events के ठीक आसपास बनाए गए हों या उपयोग किए गए हों। साथ ही, संभावित sudo brute-force attacks भी जांचें।\
इसके अलावा, _**/etc/sudoers**_ और _**/etc/groups**_ जैसी files को users को दिए गए unexpected privileges के लिए जांचें।\
अंत में, ऐसे accounts देखें जिनमें **no passwords** हों या **easily guessed** passwords हों।

## File System की जांच करें

### Malware Investigation में File System Structures का विश्लेषण

जब malware incidents की जांच की जाती है, तो file system की structure information का एक महत्वपूर्ण source होती है, जो events का क्रम और malware की content दोनों reveal करती है। हालांकि, malware authors इस analysis को hinder करने के लिए techniques विकसित कर रहे हैं, जैसे file timestamps बदलना या data storage के लिए file system से बचना।

इन anti-forensic methods का मुकाबला करने के लिए, यह जरूरी है कि:

- **Autopsy** जैसे tools का उपयोग करके **thorough timeline analysis** करें, ताकि event timelines visualize की जा सकें, या detailed timeline data के लिए **Sleuth Kit's** `mactime` का उपयोग करें।
- सिस्टम के $PATH में **unexpected scripts** की जांच करें, जिनमें attackers द्वारा उपयोग किए गए shell या PHP scripts शामिल हो सकते हैं।
- **/dev** में **atypical files** की जांच करें, क्योंकि इसमें आमतौर पर special files होते हैं, लेकिन इसमें malware-related files भी हो सकती हैं।
- **hidden files or directories** खोजें जिनके नाम ".. " (dot dot space) या "..^G" (dot dot control-G) जैसे हों, जो malicious content छिपा सकते हैं।
- `find / -user root -perm -04000 -print` कमांड का उपयोग करके **setuid root files** पहचानें। यह elevated permissions वाली files खोजता है, जिनका attackers दुरुपयोग कर सकते हैं।
- inode tables में **deletion timestamps** की समीक्षा करें ताकि mass file deletions का पता चल सके, जो rootkits या trojans की उपस्थिति का संकेत दे सकता है।
- एक malicious file पहचानने के बाद **consecutive inodes** की जांच करें, क्योंकि nearby malicious files साथ-साथ रखे गए हो सकते हैं।
- **common binary directories** (_/bin_, _/sbin_) में हाल ही में modified files देखें, क्योंकि ये malware द्वारा बदली गई हो सकती हैं।
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> ध्यान दें कि एक **attacker** **time** को **modify** कर सकता है ताकि **files appear** **legitimate** लगें, लेकिन वह **inode** को **modify** नहीं कर सकता। यदि आपको लगता है कि कोई **file** यह संकेत देती है कि वह उसी फ़ोल्डर की बाकी फ़ाइलों के **same time** पर बनाई और संशोधित की गई थी, लेकिन **inode** अप्रत्याशित रूप से बड़ा है, तो उस **file** के **timestamps** **modified** किए गए थे।

### Inode-focused quick triage

यदि आपको anti-forensics का संदेह है, तो ये inode-focused checks जल्दी चलाएँ:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
जब कोई संदिग्ध inode किसी EXT filesystem image/device पर हो, तो inode metadata को सीधे inspect करें:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
उपयोगी फ़ील्ड्स:
- **Links**: अगर `0`, तो कोई directory entry वर्तमान में inode को संदर्भित नहीं कर रहा है।
- **dtime**: deletion timestamp, जो inode के unlink होने पर set किया जाता है।
- **ctime/mtime**: metadata/content changes को incident timeline के साथ correlate करने में मदद करता है।

### Capabilities, xattrs, and preload-based userland rootkits

Modern Linux persistence अक्सर obvious `setuid` binaries से बचती है और instead **file capabilities**, **extended attributes**, और dynamic loader का abuse करती है।
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
**writable** paths जैसे `/tmp`, `/dev/shm`, `/var/tmp`, या `/usr/local/lib` के तहत अजीब locations से referenced libraries पर विशेष ध्यान दें। साथ ही सामान्य package ownership के बाहर capability-bearing binaries भी check करें और उन्हें package verification results (`rpm -Va`, `dpkg --verify`, `debsums`) के साथ correlate करें।

## अलग-अलग filesystem versions की files की तुलना करें

### Filesystem Version Comparison Summary

Filesystem versions की तुलना करने और changes pinpoint करने के लिए, हम simplified `git diff` commands का उपयोग करते हैं:

- **नई files खोजने के लिए**, दो directories की तुलना करें:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **संशोधित सामग्री के लिए**, विशिष्ट लाइनों को अनदेखा करते हुए बदलाव सूचीबद्ध करें:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **हटाई गई files का पता लगाने के लिए**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) विशिष्ट बदलावों तक सीमित करने में मदद करते हैं, जैसे added (`A`), deleted (`D`), या modified (`M`) files।
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
