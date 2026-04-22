# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## 초기 정보 수집

### 기본 정보

우선, **좋은 것으로 검증된 바이너리와 라이브러리**가 들어 있는 **USB**를 하나 준비하는 것이 좋습니다(그냥 ubuntu를 받아서 _/bin_, _/sbin_, _/lib,_ 그리고 _/lib64_ 폴더를 복사하면 됩니다). 그런 다음 USB를 마운트하고, 해당 바이너리를 사용하도록 env 변수를 수정합니다:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
시스템을 good and known binaries를 사용하도록 구성했다면, 이제 **몇 가지 기본 정보를 추출**하기 시작할 수 있습니다:
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

기본 정보를 얻는 동안 다음과 같은 이상한 것들을 확인해야 합니다:

- **Root processes**는 보통 낮은 PID로 실행되므로, 큰 PID를 가진 root process를 찾으면 의심할 수 있습니다
- `/etc/passwd`에서 shell이 없는 users의 **registered logins**를 확인
- shell이 없는 users에 대해 `/etc/shadow`에서 **password hashes**를 확인

### Memory Dump

실행 중인 시스템의 memory를 얻으려면 [**LiME**](https://github.com/504ensicsLabs/LiME)를 사용하는 것이 권장됩니다.\
이를 **compile**하려면, 피해자 machine이 사용 중인 것과 **같은 kernel**을 사용해야 합니다.

> [!TIP]
> victim machine에 LiME나 다른 어떤 것도 **install**할 수 없다는 점을 기억하세요. 그렇게 하면 여러 변경 사항이 생깁니다

따라서 동일한 버전의 Ubuntu가 있다면 `apt-get install lime-forensics-dkms`를 사용할 수 있습니다\
다른 경우에는 github에서 [**LiME**](https://github.com/504ensicsLabs/LiME)를 다운로드하고 올바른 kernel headers로 compile해야 합니다. 피해자 machine의 **정확한 kernel headers**를 얻으려면, 단순히 `/lib/modules/<kernel version>` 디렉터리를 자신의 machine으로 **copy**한 다음, 그것들을 사용해 LiME를 **compile**하면 됩니다:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME는 3가지 **formats**를 지원합니다:

- Raw (모든 segment가 이어서 결합됨)
- Padded (raw와 같지만, 오른쪽 bits에 zeroes가 있음)
- Lime (metadata가 포함된 권장 format)

LiME는 시스템에 저장하는 대신 `path=tcp:4444` 같은 것을 사용해 **network를 통해 dump를 전송**하는 데도 사용할 수 있습니다.

### Disk Imaging

#### Shutting down

먼저, **시스템을 shut down**해야 합니다. 이는 항상 가능한 것은 아닌데, 어떤 경우에는 시스템이 회사가 내릴 수 없는 production server일 수 있기 때문입니다.\
시스템을 shut down하는 방법은 **2가지**가 있습니다. **normal shutdown**과 **"plug the plug" shutdown**입니다. 첫 번째 방법은 **processes**가 평소처럼 종료되고 **filesystem**이 **synchronized**되도록 허용하지만, 동시에 가능한 **malware**가 **evidence를 파괴**할 기회도 줍니다. "pull the plug" 방식은 **일부 information loss**를 동반할 수 있지만(이미 memory image를 확보했기 때문에 잃는 정보는 많지 않습니다), **malware**는 이에 대해 아무 것도 할 수 없습니다. 따라서 **malware**가 있다고 **suspect**된다면, 시스템에서 **`sync`** **command**를 실행한 뒤 전원을 뽑아버리면 됩니다.

#### Taking an image of the disk

**case**와 관련된 어떤 것에든 컴퓨터를 연결하기 **전에**, 정보가 변경되지 않도록 반드시 **read only**로 **mounted**될 것인지 확인해야 한다는 점을 기억하는 것이 중요합니다.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### 디스크 이미지 사전 분석

더 이상 데이터가 없는 디스크 이미지를 이미징하는 것.
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
## 알려진 Malware 검색

### 수정된 시스템 파일

Linux는 시스템 구성 요소의 무결성을 보장하는 도구를 제공하며, 이는 잠재적으로 문제가 있는 파일을 찾아내는 데 중요합니다.

- **RedHat 기반 시스템**: 포괄적인 점검을 위해 `rpm -Va`를 사용하세요.
- **Debian 기반 시스템**: 초기 검증을 위해 `dpkg --verify`를 사용한 뒤, 문제를 식별하기 위해 (`apt-get install debsums`로 `debsums`를 설치한 후) `debsums | grep -v "OK$"`를 사용하세요.

### Malware/Rootkit Detectors

도구에 대해 알아보려면 다음 페이지를 읽어, malware를 찾는 데 유용할 수 있는 도구들을 확인하세요:


{{#ref}}
malware-analysis.md
{{#endref}}

## 설치된 프로그램 검색

Debian 및 RedHat 시스템 모두에서 설치된 프로그램을 효과적으로 검색하려면, 일반적인 디렉터리에서의 수동 점검과 함께 시스템 로그 및 데이터베이스를 활용하는 것을 고려하세요.

- Debian의 경우, 패키지 설치 세부 정보를 가져오기 위해 _**`/var/lib/dpkg/status`**_ 및 _**`/var/log/dpkg.log`**_를 확인하고, 특정 정보를 필터링하기 위해 `grep`을 사용하세요.
- RedHat 사용자는 `rpm -qa --root=/mntpath/var/lib/rpm`로 RPM 데이터베이스를 조회하여 설치된 패키지 목록을 확인할 수 있습니다.

패키지 관리자에 의해 설치되지 않았거나 수동으로 설치된 소프트웨어를 찾으려면, _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, 그리고 _**`/sbin`**_ 같은 디렉터리를 살펴보세요. 디렉터리 목록 확인과 시스템별 명령을 함께 사용하여 알려진 패키지와 연결되지 않은 실행 파일을 식별하면, 설치된 모든 프로그램을 찾는 데 도움이 됩니다.
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
## 삭제된 실행 중인 바이너리 복구

프로세스가 /tmp/exec에서 실행된 다음 삭제되었다고 가정해 보자. 이를 추출할 수 있다.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Autostart 위치 검사

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
공격자는 주기적 실행을 보장하기 위해 각 /etc/cron.*/ 디렉터리 아래에 있는 0anacron stub을 자주 수정합니다.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH hardening rollback and backdoor shells
sshd_config와 system 계정 shell에 대한 변경은 접근을 유지하기 위해 post-exploitation 이후 흔히 발생합니다.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API 비콘은 일반적으로 HTTPS에서 Authorization: Bearer tokens와 함께 api.dropboxapi.com 또는 content.dropboxapi.com를 사용합니다.
- proxy/Zeek/NetFlow에서 서버에서 발생하는 예상치 못한 Dropbox egress를 hunt하세요.
- Cloudflare Tunnel (`cloudflared`)은 outbound 443을 통해 backup C2를 제공합니다.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

악성코드가 서비스로 설치될 수 있는 경로:

- **/etc/inittab**: rc.sysinit 같은 초기화 스크립트를 호출하고, 이를 통해 추가 startup 스크립트로 연결한다.
- **/etc/rc.d/** 및 **/etc/rc.boot/**: 서비스 시작용 스크립트를 포함하며, 후자는 오래된 Linux 버전에서 발견된다.
- **/etc/init.d/**: Debian 같은 특정 Linux 버전에서 startup 스크립트를 저장하는 데 사용된다.
- 서비스는 Linux 변형에 따라 **/etc/inetd.conf** 또는 **/etc/xinetd/**를 통해서도 활성화될 수 있다.
- **/etc/systemd/system**: system 및 service manager 스크립트를 위한 디렉터리.
- **/etc/systemd/system/multi-user.target.wants/**: multi-user runlevel에서 시작되어야 하는 서비스로의 링크를 포함한다.
- **/usr/local/etc/rc.d/**: 사용자 정의 또는 서드파티 서비스용.
- **\~/.config/autostart/**: 사용자별 자동 시작 애플리케이션용이며, 사용자 대상 malware를 숨기는 장소가 될 수 있다.
- **/lib/systemd/system/**: 설치된 패키지가 제공하는 시스템 전체 기본 unit 파일.

#### Hunt: systemd timers and transient units

Systemd persistence는 `.service` 파일에만 제한되지 않는다. 런타임에 생성되는 `.timer` unit, 사용자 수준 unit, 그리고 **transient units**를 조사하라.
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
Transient units are easy to miss because `/run/systemd/transient/` is **non-persistent**. If you are collecting a live image, grab it before shutdown.

### Kernel Modules

Linux kernel modules, often utilized by malware as rootkit components, are loaded at system boot. The directories and files critical for these modules include:

- **/lib/modules/$(uname -r)**: 현재 실행 중인 kernel 버전의 modules를 보관합니다.
- **/etc/modprobe.d**: module loading을 제어하는 configuration files를 포함합니다.
- **/etc/modprobe** and **/etc/modprobe.conf**: 전역 module settings용 파일입니다.

### Other Autostart Locations

Linux는 사용자 로그인 시 프로그램을 자동 실행하기 위해 다양한 파일을 사용하며, 여기에 malware가 숨어 있을 수 있습니다:

- **/etc/profile.d/**\*, **/etc/profile**, and **/etc/bash.bashrc**: 어떤 user login에도 실행됩니다.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, and **\~/.config/autostart**: 로그인 시 실행되는 사용자별 파일입니다.
- **/etc/rc.local**: 모든 system services가 시작된 뒤 실행되며, multiuser 환경으로의 전환이 끝났음을 의미합니다.

## Examine Logs

Linux systems는 다양한 log files를 통해 user activities와 system events를 추적합니다. 이 logs는 unauthorized access, malware infections, 그리고 다른 security incidents를 식별하는 데 핵심적입니다. 주요 log files는 다음과 같습니다:

- **/var/log/syslog** (Debian) or **/var/log/messages** (RedHat): system-wide messages와 activities를 기록합니다.
- **/var/log/auth.log** (Debian) or **/var/log/secure** (RedHat): authentication attempts, 성공 및 실패한 logins를 기록합니다.
- `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`를 사용해 관련 authentication events를 필터링합니다.
- **/var/log/boot.log**: system startup messages를 포함합니다.
- **/var/log/maillog** or **/var/log/mail.log**: email server activities를 기록하며, email-related services 추적에 유용합니다.
- **/var/log/kern.log**: errors와 warnings를 포함한 kernel messages를 저장합니다.
- **/var/log/dmesg**: device driver messages를 보관합니다.
- **/var/log/faillog**: failed login attempts를 기록하여 security breach investigations에 도움을 줍니다.
- **/var/log/cron**: cron job executions를 기록합니다.
- **/var/log/daemon.log**: background service activities를 추적합니다.
- **/var/log/btmp**: failed login attempts를 기록합니다.
- **/var/log/httpd/**: Apache HTTPD error 및 access logs를 포함합니다.
- **/var/log/mysqld.log** or **/var/log/mysql.log**: MySQL database activities를 기록합니다.
- **/var/log/xferlog**: FTP file transfers를 기록합니다.
- **/var/log/**: 항상 여기에서 unexpected logs를 확인합니다.

> [!TIP]
> Linux system logs and audit subsystems may be disabled or deleted in an intrusion or malware incident. Because logs on Linux systems generally contain some of the most useful information about malicious activities, intruders routinely delete them. Therefore, when examining available log files, it is important to look for gaps or out of order entries that might be an indication of deletion or tampering.

### Journald triage (`journalctl`)

현대 Linux hosts에서는 **systemd journal**이 보통 **service execution**, **auth events**, **package operations**, 그리고 **kernel/user-space messages**의 가장 가치 있는 source입니다. live response 중에는 **persistent** journal (`/var/log/journal/`)과 **runtime** journal (`/run/log/journal/`) 둘 다 보존하려고 하세요. 짧게 존재한 attacker activity는 후자에만 남아 있을 수 있습니다.
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
유용한 journal 필드로는 triage에 `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, 그리고 `MESSAGE`가 있습니다. `journald`가 persistent storage 없이 구성되었다면, `/run/log/journal/` 아래에는 최근 데이터만 존재할 것으로 예상하세요.

### Audit framework triage (`auditd`)

`auditd`가 활성화되어 있다면, 파일 변경, 명령 실행, 로그인 활동, 또는 패키지 설치에 대해 **process attribution**이 필요할 때마다 이를 우선 사용하세요.
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
키가 포함된 규칙이 배포되었을 때는, 원시 로그를 grep하는 대신 그 규칙들에서 pivot 하세요:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux는 각 사용자별 명령 기록을 유지**하며, 다음 위치에 저장됩니다:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

또한 `last -Faiwx` 명령은 사용자 로그인 목록을 제공합니다. 알 수 없거나 예상치 못한 로그인을 확인하세요.

추가 rprivileges를 부여할 수 있는 파일을 확인하세요:

- 부여되었을 수 있는 예상치 못한 사용자 권한이 있는지 `/etc/sudoers`를 검토합니다.
- 부여되었을 수 있는 예상치 못한 사용자 권한이 있는지 `/etc/sudoers.d/`를 검토합니다.
- 비정상적인 그룹 멤버십이나 권한을 식별하기 위해 `/etc/groups`를 살펴봅니다.
- 비정상적인 그룹 멤버십이나 권한을 식별하기 위해 `/etc/passwd`를 살펴봅니다.

일부 앱도 자체 로그를 생성합니다:

- **SSH**: 무단 원격 연결이 있었는지 _\~/.ssh/authorized_keys_와 _\~/.ssh/known_hosts_를 확인합니다.
- **Gnome Desktop**: Gnome 애플리케이션을 통해 최근 접근한 파일을 확인하려면 _\~/.recently-used.xbel_을 살펴봅니다.
- **Firefox/Chrome**: 의심스러운 활동이 있는지 브라우저 기록과 다운로드를 _\~/.mozilla/firefox_ 또는 _\~/.config/google-chrome_에서 확인합니다.
- **VIM**: 접근한 파일 경로와 검색 기록 같은 사용 세부 정보를 위해 _\~/.viminfo_를 검토합니다.
- **Open Office**: 침해되었을 수 있는 파일을 나타낼 수 있는 최근 문서 접근 여부를 확인합니다.
- **FTP/SFTP**: 허가되지 않았을 수 있는 파일 전송이 있었는지 _\~/.ftp_history_ 또는 _\~/.sftp_history_의 로그를 검토합니다.
- **MySQL**: 실행된 MySQL 쿼리를 확인하기 위해 _\~/.mysql_history_를 조사하며, 이는 허가되지 않은 데이터베이스 활동을 드러낼 수 있습니다.
- **Less**: 본 파일과 실행된 명령을 포함한 사용 기록을 위해 _\~/.lesshst_를 분석합니다.
- **Git**: 저장소 변경 사항을 확인하기 위해 _\~/.gitconfig_와 프로젝트 _.git/logs_를 살펴봅니다.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip)은 배포판에 따라 `/var/log/syslog*` 또는 `/var/log/messages*` 같은 Linux 로그 파일을 파싱하여 USB 이벤트 기록 테이블을 구성하는, 순수 Python 3로 작성된 작은 소프트웨어입니다.

사용된 모든 USB를 **아는 것**은 흥미로우며, 승인된 USB 목록이 있다면 그 목록에 없는 USB의 사용인 "violation events"를 찾는 데 더 유용합니다.

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### 예시
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## 사용자 계정 및 로그인 활동 검토

_**/etc/passwd**_, _**/etc/shadow**_ 및 **security logs**를 점검하여, 알려진 무단 행위와 가까운 시점에 생성되었거나 사용된 비정상적인 이름이나 계정을 찾으세요. 또한 sudo brute-force 공격 가능성도 확인하세요.\
더불어, _**/etc/sudoers**_ 및 _**/etc/groups**_ 같은 파일에서 사용자에게 부여된 예상치 못한 권한이 있는지 확인하세요.\
마지막으로, **비밀번호가 없거나** **쉽게 추측 가능한** 비밀번호를 사용하는 계정이 있는지 살펴보세요.

## 파일 시스템 검사

### 악성코드 조사에서 파일 시스템 구조 분석

악성코드 사건을 조사할 때 파일 시스템의 구조는 중요한 정보원이며, 사건의 순서와 악성코드의 내용을 드러냅니다. 그러나 악성코드 작성자들은 파일 타임스탬프를 수정하거나 데이터 저장에 파일 시스템을 사용하지 않는 방식으로 이러한 분석을 방해하는 기법을 개발하고 있습니다.

이러한 anti-forensic 방법에 대응하려면 다음이 중요합니다:

- **Autopsy** 같은 도구로 **상세한 타임라인 분석**을 수행하여 이벤트 타임라인을 시각화하거나, **Sleuth Kit**의 `mactime`으로 세부 타임라인 데이터를 확인합니다.
- 시스템의 $PATH 안에 있는 **예상치 못한 스크립트**를 조사하세요. 공격자가 사용한 shell 또는 PHP 스크립트가 포함될 수 있습니다.
- 전통적으로 특수 파일을 포함하지만 malware 관련 파일을 보관할 수도 있는 `/dev`의 **비정상적인 파일**을 점검하세요.
- ".. " (점 점 공백) 또는 "..^G" (점 점 제어-G) 같은 이름의 **숨겨진 파일이나 디렉터리**를 검색하여 악성 내용을 숨기고 있을 가능성을 확인하세요.
- 다음 명령으로 **setuid root 파일**을 식별하세요: `find / -user root -perm -04000 -print` 이 명령은 공격자가 악용할 수 있는 상승된 권한의 파일을 찾습니다.
- inode 테이블의 **삭제 타임스탬프**를 검토하여 대량 파일 삭제를 찾아보세요. 이는 rootkits 또는 trojans의 존재를 시사할 수 있습니다.
- 하나를 식별한 후, 인접한 악성 파일이 있을 수 있으므로 **연속된 inode**를 검사하세요. 함께 배치되었을 수 있습니다.
- 최근 수정된 파일이 malware에 의해 변경되었을 수 있으므로 **일반적인 binary 디렉터리**(_/bin_, _/sbin_)를 확인하세요.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> **공격자**는 **time**을 **수정**해서 **files appear** **legitimate**하게 만들 수 있지만, **inode**는 **수정**할 수 없습니다. **file**이 같은 폴더의 나머지 파일들과 **같은 시각**에 생성되고 수정된 것으로 표시되는데도 **inode**가 **예상보다 더 크다**면, **그 파일의 timestamps가 수정된 것**입니다.

### Inode-focused quick triage

anti-forensics가 의심되면, 다음 inode-focused 검사를 초기에 실행하세요:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
의심스러운 inode가 EXT 파일시스템 image/device에 있을 때, inode metadata를 직접 확인합니다:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
유용한 필드:
- **Links**: `0`이면, 현재 어떤 디렉터리 항목도 해당 inode를 참조하지 않습니다.
- **dtime**: inode가 unlink되었을 때 설정되는 삭제 타임스탬프입니다.
- **ctime/mtime**: 메타데이터/콘텐츠 변경을 incident 타임라인과 상관관계 분석하는 데 도움이 됩니다.

### Capabilities, xattrs, and preload-based userland rootkits

현대 Linux persistence는 보통 눈에 띄는 `setuid` binary를 피하고, 대신 **file capabilities**, **extended attributes**, 그리고 dynamic loader를 악용합니다.
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
**쓰기 가능한** 경로인 `/tmp`, `/dev/shm`, `/var/tmp`, 또는 `/usr/local/lib` 아래의 이상한 위치에서 참조되는 라이브러리에 특히 주의하세요. 또한 일반적인 패키지 소유 범위 밖에 있는 capability-bearing binary도 확인하고, 패키지 검증 결과(`rpm -Va`, `dpkg --verify`, `debsums`)와 연관지으세요.

## 서로 다른 filesystem version의 파일 비교

### Filesystem Version Comparison Summary

filesystem version을 비교하고 변경 사항을 정확히 찾아내려면, 단순화된 `git diff` 명령을 사용합니다:

- **새 파일을 찾으려면**, 두 디렉터리를 비교합니다:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **수정된 내용의 경우**, 특정 줄은 무시하고 변경 사항을 나열하세요:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **삭제된 파일을 탐지하려면**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`)는 추가(`A`), 삭제(`D`), 수정(`M`)된 파일처럼 특정 변경만 좁혀서 볼 때 도움이 됩니다.
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
