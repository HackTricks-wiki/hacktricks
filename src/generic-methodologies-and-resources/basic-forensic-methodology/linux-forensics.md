# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## प्रारंभिक जानकारी एकत्र करना

### मूल जानकारी

सबसे पहले, यह सलाह दी जाती है कि आपके पास कुछ **USB** हो जिसमें **अच्छी तरह ज्ञात binaries और libraries** हों (आप बस ubuntu लेकर फ़ोल्डर _/bin_, _/sbin_, _/lib,_ और _/lib64_ कॉपी कर सकते हैं), फिर USB को mount करें, और env variables को संशोधित करके उन binaries का उपयोग करें:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
एक बार जब आपने सिस्टम को अच्छे और ज्ञात binaries का उपयोग करने के लिए configure कर लिया है, तो आप **कुछ basic information निकालना** शुरू कर सकते हैं:
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

बेसिक जानकारी प्राप्त करते समय आपको ऐसी अजीब चीज़ें चेक करनी चाहिए जैसे:

- **Root processes** आमतौर पर low PIDS पर चलते हैं, इसलिए अगर आपको कोई root process बड़ा PID के साथ मिले तो आपको शक हो सकता है
- `/etc/passwd` में shell के बिना users के **registered logins** चेक करें
- shell के बिना users के लिए `/etc/shadow` के अंदर **password hashes** चेक करें

### Memory Dump

चल रहे सिस्टम की memory प्राप्त करने के लिए, [**LiME**](https://github.com/504ensicsLabs/LiME) का उपयोग करना recommended है।\
इसे **compile** करने के लिए, आपको वही **kernel** इस्तेमाल करना होगा जो victim machine उपयोग कर रही है।

> [!TIP]
> याद रखें कि आप victim machine पर LiME या कोई और चीज़ **install** नहीं कर सकते, क्योंकि इससे उसमें कई changes हो जाएंगे

तो, अगर आपके पास Ubuntu का identical version है, तो आप `apt-get install lime-forensics-dkms` इस्तेमाल कर सकते हैं\
अन्य मामलों में, आपको github से [**LiME**](https://github.com/504ensicsLabs/LiME) download करके उसे सही kernel headers के साथ compile करना होगा। victim machine के exact kernel headers प्राप्त करने के लिए, आप बस directory `/lib/modules/<kernel version>` को अपनी machine पर **copy** कर सकते हैं, और फिर उन्हीं का उपयोग करके LiME **compile** कर सकते हैं:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME 3 **formats** को सपोर्ट करता है:

- Raw (हर segment को एक साथ जोड़कर)
- Padded (raw जैसा ही, लेकिन right bits में zeroes के साथ)
- Lime (metadata के साथ recommended format)

LiME का उपयोग system पर store करने के बजाय **network के via dump भेजने** के लिए भी किया जा सकता है, जैसे: `path=tcp:4444`

### Disk Imaging

#### Shutting down

सबसे पहले, आपको **system को shut down** करना होगा। यह हमेशा संभव नहीं होता क्योंकि कभी-कभी system एक production server होता है जिसे company shut down करने का risk नहीं उठा सकती।\
System को shut down करने के **2 ways** हैं, एक **normal shutdown** और एक **"plug the plug" shutdown**। पहला तरीका **processes को सामान्य रूप से terminate** होने देगा और **filesystem** को **synchronized** होने देगा, लेकिन इससे possible **malware** को **evidence destroy** करने का मौका भी मिल सकता है। "pull the plug" approach में **कुछ information loss** हो सकती है (लेकिन ज्यादा info lose नहीं होगी क्योंकि हम पहले ही memory का image ले चुके हैं) और **malware के पास** कुछ भी करने का **कोई मौका नहीं** होगा। इसलिए, अगर आपको **suspect** है कि **malware** हो सकता है, तो system पर बस **`sync`** **command** execute करें और plug को निकाल दें।

#### Taking an image of the disk

यह ध्यान रखना important है कि **case से related किसी भी चीज़ से अपना computer connect करने से पहले**, आपको सुनिश्चित करना चाहिए कि वह **read only** के रूप में **mounted** होगा ताकि कोई भी information modify न हो।
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### डिस्क इमेज पूर्व-विश्लेषण

एक डिस्क इमेज का इमेजिंग करना, जिसमें और कोई डेटा न हो।
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
## ज्ञात Malware की खोज करें

### Modified System Files

Linux system components की integrity सुनिश्चित करने के लिए tools देता है, जो potentially problematic files को spot करने के लिए crucial है।

- **RedHat-based systems**: व्यापक check के लिए `rpm -Va` use करें।
- **Debian-based systems**: initial verification के लिए `dpkg --verify`, फिर किसी भी issue को identify करने के लिए `debsums | grep -v "OK$"` (`debsums` को `apt-get install debsums` से install करने के बाद) use करें।

### Malware/Rootkit Detectors

Malware ढूँढने में useful tools के बारे में जानने के लिए following page पढ़ें:


{{#ref}}
malware-analysis.md
{{#endref}}

## Installed programs की खोज करें

Debian और RedHat दोनों systems पर installed programs को effectively search करने के लिए, common directories में manual checks के साथ system logs और databases को leverage करने पर विचार करें।

- Debian के लिए, package installations के details fetch करने हेतु _**`/var/lib/dpkg/status`**_ और _**`/var/log/dpkg.log`**_ inspect करें, और specific information filter करने के लिए `grep` use करें।
- RedHat users `rpm -qa --root=/mntpath/var/lib/rpm` के साथ RPM database query करके installed packages की list प्राप्त कर सकते हैं।

Package managers के बाहर manually या outside installed software को uncover करने के लिए, _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, और _**`/sbin`**_ जैसी directories explore करें। Directory listings को system-specific commands के साथ combine करें ताकि known packages से associated न होने वाले executables identify किए जा सकें, जिससे सभी installed programs की आपकी search बेहतर हो।
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
## हटाए गए चल रहे binaries को रिकवर करें

कल्पना करें कि एक process को /tmp/exec से execute किया गया था और फिर delete कर दिया गया। इसे extract करना संभव है
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Autostart locations की जाँच करें

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
#### हंट: 0anacron और संदिग्ध stubs के माध्यम से Cron/Anacron abuse
Attackers अक्सर प्रत्येक /etc/cron.*/ directory के तहत मौजूद 0anacron stub को edit करते हैं ताकि periodic execution सुनिश्चित हो सके।
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH hardening rollback and backdoor shells
sshd_config और system account shells में बदलाव post‑exploitation के बाद access बनाए रखने के लिए आम हैं।
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons typically use api.dropboxapi.com or content.dropboxapi.com over HTTPS with Authorization: Bearer tokens.
- proxy/Zeek/NetFlow में unexpected Dropbox egress को servers से hunt करें.
- Cloudflare Tunnel (`cloudflared`) outbound 443 over backup C2 प्रदान करता है.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Paths where a malware could be installed as a service:

- **/etc/inittab**: प्रारंभिक scripts जैसे rc.sysinit को कॉल करता है, जो आगे startup scripts की ओर निर्देशित करता है।
- **/etc/rc.d/** और **/etc/rc.boot/**: service startup के लिए scripts होते हैं; दूसरा पुराने Linux versions में मिलता है।
- **/etc/init.d/**: Debian जैसे कुछ Linux versions में startup scripts संग्रहीत करने के लिए उपयोग होता है।
- Services को **/etc/inetd.conf** या **/etc/xinetd/** के जरिए भी activate किया जा सकता है, Linux variant पर निर्भर करते हुए।
- **/etc/systemd/system**: system और service manager scripts के लिए एक directory।
- **/etc/systemd/system/multi-user.target.wants/**: उन services के links होते हैं जिन्हें multi-user runlevel में start किया जाना चाहिए।
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
Transient units को मिस करना आसान है क्योंकि `/run/systemd/transient/` **non-persistent** है। अगर आप live image collect कर रहे हैं, तो shutdown से पहले इसे grab करें।

### Kernel Modules

Linux kernel modules, जो अक्सर malware द्वारा rootkit components के रूप में उपयोग किए जाते हैं, system boot पर load होते हैं। इन modules के लिए critical directories और files में शामिल हैं:

- **/lib/modules/$(uname -r)**: Running kernel version के लिए modules रखता है।
- **/etc/modprobe.d**: Module loading को control करने के लिए configuration files रखता है।
- **/etc/modprobe** और **/etc/modprobe.conf**: Global module settings के लिए files।

### Other Autostart Locations

Linux programs को user login पर automatically execute करने के लिए विभिन्न files use करता है, जिनमें malware भी हो सकता है:

- **/etc/profile.d/**\*, **/etc/profile**, और **/etc/bash.bashrc**: किसी भी user login पर execute होते हैं।
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, और **\~/.config/autostart**: User-specific files जो उनके login पर run होते हैं।
- **/etc/rc.local**: सभी system services शुरू होने के बाद run होता है, जो multiuser environment में transition के अंत को mark करता है।

## Examine Logs

Linux systems user activities और system events को विभिन्न log files के through track करते हैं। ये logs unauthorized access, malware infections, और अन्य security incidents की पहचान के लिए महत्वपूर्ण हैं। Key log files में शामिल हैं:

- **/var/log/syslog** (Debian) या **/var/log/messages** (RedHat): System-wide messages और activities capture करते हैं।
- **/var/log/auth.log** (Debian) या **/var/log/secure** (RedHat): Authentication attempts, successful और failed logins record करते हैं।
- Relevant authentication events को filter करने के लिए `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` use करें।
- **/var/log/boot.log**: System startup messages रखता है।
- **/var/log/maillog** या **/var/log/mail.log**: Email server activities log करता है, email-related services track करने के लिए useful।
- **/var/log/kern.log**: Kernel messages store करता है, जिसमें errors और warnings शामिल हैं।
- **/var/log/dmesg**: Device driver messages रखता है।
- **/var/log/faillog**: Failed login attempts record करता है, security breach investigations में मदद करता है।
- **/var/log/cron**: Cron job executions log करता है।
- **/var/log/daemon.log**: Background service activities track करता है।
- **/var/log/btmp**: Failed login attempts document करता है।
- **/var/log/httpd/**: Apache HTTPD error और access logs रखता है।
- **/var/log/mysqld.log** या **/var/log/mysql.log**: MySQL database activities log करता है।
- **/var/log/xferlog**: FTP file transfers record करता है।
- **/var/log/**: यहाँ हमेशा unexpected logs check करें।

> [!TIP]
> Linux system logs और audit subsystems किसी intrusion या malware incident में disabled या deleted हो सकते हैं। क्योंकि Linux systems पर logs generally malicious activities के बारे में कुछ सबसे useful information contain करते हैं, intruders routine तौर पर उन्हें delete करते हैं। इसलिए, available log files examine करते समय gaps या out of order entries ढूँढना important है, क्योंकि यह deletion या tampering का indication हो सकता है।

### Journald triage (`journalctl`)

Modern Linux hosts पर, **systemd journal** आमतौर पर **service execution**, **auth events**, **package operations**, और **kernel/user-space messages** के लिए सबसे high-value source होता है। Live response के दौरान, **persistent** journal (`/var/log/journal/`) और **runtime** journal (`/run/log/journal/`) दोनों को preserve करने की कोशिश करें, क्योंकि short-lived attacker activity केवल दूसरे में मौजूद हो सकती है।
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
ट्रायाज के लिए उपयोगी journal फ़ील्ड्स में `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, और `MESSAGE` शामिल हैं। अगर journald को persistent storage के बिना configure किया गया था, तो `/run/log/journal/` के तहत केवल हालिया data की अपेक्षा करें।

### Audit framework triage (`auditd`)

अगर `auditd` enabled है, तो file changes, command execution, login activity, या package installation के लिए **process attribution** की ज़रूरत होने पर इसे हमेशा prefer करें।
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
जब rules keys के साथ deploy किए गए थे, तो raw logs को grepping करने के बजाय उनसे pivot करें:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux प्रत्येक user के लिए command history बनाए रखता है**, जो यहाँ stored होती है:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

इसके अलावा, `last -Faiwx` command user logins की list देती है। इसे unknown या unexpected logins के लिए check करें।

Extra rprivileges दे सकने वाली files check करें:

- `/etc/sudoers` में ऐसे user privileges देखें जो अनपेक्षित रूप से granted किए गए हों।
- `/etc/sudoers.d/` में ऐसे user privileges देखें जो अनपेक्षित रूप से granted किए गए हों।
- `/etc/groups` examine करें ताकि unusual group memberships या permissions पहचानी जा सकें।
- `/etc/passwd` examine करें ताकि unusual group memberships या permissions पहचानी जा सकें।

कुछ apps अपनी own logs भी generate करती हैं:

- **SSH**: _\~/.ssh/authorized_keys_ और _\~/.ssh/known_hosts_ को unauthorized remote connections के लिए examine करें।
- **Gnome Desktop**: _\~/.recently-used.xbel_ में Gnome applications के जरिए recently accessed files देखें।
- **Firefox/Chrome**: suspicious activities के लिए browser history और downloads को _\~/.mozilla/firefox_ या _\~/.config/google-chrome_ में check करें।
- **VIM**: _\~/.viminfo_ में usage details, जैसे accessed file paths और search history, review करें।
- **Open Office**: recent document access check करें, जो compromised files का संकेत दे सकता है।
- **FTP/SFTP**: unauthorized file transfers के लिए _\~/.ftp_history_ या _\~/.sftp_history_ में logs review करें।
- **MySQL**: executed MySQL queries के लिए _\~/.mysql_history_ investigate करें, जो unauthorized database activities को उजागर कर सकती हैं।
- **Less**: viewed files और executed commands सहित usage history के लिए _\~/.lesshst_ analyze करें।
- **Git**: repositories में changes के लिए _\~/.gitconfig_ और project _.git/logs_ examine करें।

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) एक छोटा software है जो pure Python 3 में लिखा गया है, जो USB event history tables बनाने के लिए Linux log files (`/var/log/syslog*` या `/var/log/messages*` distro के अनुसार) parse करता है।

यह **जानना interesting है कि कौन-कौन से USBs use हुए हैं** और अगर आपके पास USBs की authorized list हो तो यह और भी useful होगा, ताकि "violation events" (ऐसे USBs का use जो उस list में नहीं हैं) find किए जा सकें।

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

## यूज़र अकाउंट्स और लॉगऑन गतिविधियों की समीक्षा करें

_**/etc/passwd**_, _**/etc/shadow**_ और **security logs** की जाँच करें ताकि असामान्य नामों या उन अकाउंट्स का पता चल सके जो ज्ञात अनधिकृत घटनाओं के करीब बनाए गए और/या उपयोग किए गए हों। साथ ही, संभावित sudo brute-force attacks की भी जाँच करें।\
इसके अलावा, _**/etc/sudoers**_ और _**/etc/groups**_ जैसी फ़ाइलों में users को दी गई अप्रत्याशित privileges की जाँच करें।\
अंत में, ऐसे accounts देखें जिनके **no passwords** हों या जिनके पास **easily guessed** passwords हों।

## फ़ाइल सिस्टम की जाँच करें

### Malware Investigation में File System Structures का विश्लेषण

जब malware incidents की जाँच की जाती है, तो file system की संरचना जानकारी का एक महत्वपूर्ण स्रोत होती है, जो घटनाओं के क्रम और malware की सामग्री दोनों को उजागर करती है। हालांकि, malware authors इस विश्लेषण को बाधित करने के लिए techniques विकसित कर रहे हैं, जैसे file timestamps को modify करना या data storage के लिए file system से बचना।

इन anti-forensic methods का मुकाबला करने के लिए, यह ज़रूरी है कि:

- **Autopsy** जैसे tools का उपयोग करके **thorough timeline analysis** करें, ताकि event timelines को visualize किया जा सके, या detailed timeline data के लिए **Sleuth Kit's** `mactime` का उपयोग करें।
- system के $PATH में **unexpected scripts** की जाँच करें, जिनमें shell या PHP scripts शामिल हो सकती हैं जिनका attackers उपयोग करते हैं।
- atypical files के लिए `/dev` की जाँच करें, क्योंकि इसमें परंपरागत रूप से special files होती हैं, लेकिन यहाँ malware-related files भी हो सकती हैं।
- hidden files या directories खोजें जिनके नाम ".. " (dot dot space) या "..^G" (dot dot control-G) जैसे हों, जो malicious content छिपा सकते हैं।
- `find / -user root -perm -04000 -print` कमांड का उपयोग करके setuid root files की पहचान करें। यह elevated permissions वाली files ढूँढता है, जिनका attackers दुरुपयोग कर सकते हैं।
- inode tables में deletion timestamps की समीक्षा करें ताकि mass file deletions का पता चल सके, जो rootkits या trojans की उपस्थिति का संकेत दे सकते हैं।
- एक malicious file की पहचान करने के बाद पास-पास के malicious files के लिए consecutive inodes की जाँच करें, क्योंकि उन्हें साथ-साथ रखा गया हो सकता है।
- common binary directories (_/bin_, _/sbin_) में हाल ही में modified files की जाँच करें, क्योंकि इन्हें malware द्वारा बदला जा सकता है।
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> ध्यान दें कि एक **attacker** **time** को **modify** कर सकता है ताकि **files appear** **legitimate** लगें, लेकिन वह **inode** को **modify** नहीं कर सकता। यदि आपको पता चलता है कि कोई **file** संकेत देती है कि वह उसी **time** पर बनाई और **modified** गई थी जिस **same folder** में बाकी files थीं, लेकिन **inode** अप्रत्याशित रूप से बड़ा है, तो उस **file** के **timestamps** बदल दिए गए थे।

### Inode-focused quick triage

यदि आपको anti-forensics का संदेह है, तो इन inode-focused checks को पहले चलाएँ:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
जब EXT filesystem image/device पर कोई संदिग्ध inode हो, तो inode metadata को सीधे inspect करें:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
उपयोगी fields:
- **Links**: यदि `0`, तो वर्तमान में कोई directory entry inode को संदर्भित नहीं करती।
- **dtime**: deletion timestamp, जो inode के unlinked होने पर set होता है।
- **ctime/mtime**: metadata/content changes को incident timeline के साथ correlate करने में मदद करता है।

### Capabilities, xattrs, and preload-based userland rootkits

Modern Linux persistence अक्सर obvious `setuid` binaries से बचती है और इसके बजाय **file capabilities**, **extended attributes**, और dynamic loader का abuse करती है।
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
विशेष ध्यान उन libraries पर दें जो **writable** paths जैसे `/tmp`, `/dev/shm`, `/var/tmp`, या `/usr/local/lib` के अजीब locations से refer की गई हों। साथ ही normal package ownership के बाहर मौजूद capability-bearing binaries भी check करें और उन्हें package verification results (`rpm -Va`, `dpkg --verify`, `debsums`) के साथ correlate करें।

## अलग-अलग filesystem versions की files compare करें

### Filesystem Version Comparison Summary

filesystem versions की तुलना करने और changes pinpoint करने के लिए, हम simplified `git diff` commands का उपयोग करते हैं:

- **नई files खोजने के लिए**, दो directories compare करें:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **संशोधित सामग्री के लिए**, परिवर्तनों की सूची बनाएं जबकि विशिष्ट पंक्तियों को अनदेखा करें:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Deleted files का पता लगाने के लिए**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) विशिष्ट बदलावों तक सीमित करने में मदद करती हैं, जैसे added (`A`), deleted (`D`), या modified (`M`) files।
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

{{#include ../../banners/hacktricks-training.md}}
