# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## 초기 정보 수집

### 기본 정보

먼저 **정상적인 바이너리와 라이브러리가 들어 있는 **USB**를 준비하는 것이 좋습니다**(ubuntu를 가져와 _/bin_, _/sbin_, _/lib,_ 및 _/lib64_ 폴더를 복사하면 됩니다). 그런 다음 USB를 마운트하고 env 변수를 수정하여 해당 바이너리를 사용합니다:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
시스템이 신뢰할 수 있고 검증된 binaries를 사용하도록 구성했다면 **몇 가지 기본 정보 추출**을 시작할 수 있습니다:
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
#### 의심스러운 정보

기본 정보를 수집하는 동안 다음과 같은 이상한 항목을 확인해야 합니다.

- **Root 프로세스**는 일반적으로 낮은 PID로 실행되므로, 큰 PID를 가진 Root 프로세스를 발견하면 의심할 수 있습니다.
- `/etc/passwd`에서 셸이 없는 사용자의 **등록된 로그인**을 확인합니다.
- 셸이 없는 사용자의 `/etc/shadow` 내부에 **password hashes**가 있는지 확인합니다.

### Memory Dump

실행 중인 시스템의 메모리를 확보하려면 [**LiME**](https://github.com/504ensicsLabs/LiME)를 사용하는 것이 좋습니다.\
이를 **compile**하려면 피해자 시스템이 사용하는 것과 **동일한 kernel**을 사용해야 합니다.

> [!TIP]
> 피해자 시스템에 **LiME 또는 다른 어떤 것도 설치할 수 없다는 점**을 기억하세요. 설치하면 시스템에 여러 변경 사항이 발생합니다.

따라서 동일한 버전의 Ubuntu가 있다면 `apt-get install lime-forensics-dkms`를 사용할 수 있습니다.\
그 외의 경우에는 github에서 [**LiME**](https://github.com/504ensicsLabs/LiME)를 다운로드하고 올바른 kernel headers를 사용해 compile해야 합니다. 피해자 시스템의 **정확한 kernel headers를 확보**하려면 `/lib/modules/<kernel version>` **directory를 그대로 복사**한 다음 이를 사용해 LiME을 compile하면 됩니다:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME은 3가지 **formats**를 지원합니다:

- Raw (모든 세그먼트를 서로 연결)
- Padded (Raw와 동일하지만 오른쪽 비트에 0이 추가됨)
- Lime (메타데이터가 포함된 권장 format

LiME은 다음과 같은 방식으로 시스템에 저장하는 대신 **네트워크를 통해 dump를 전송**하는 데 사용할 수도 있습니다: `path=tcp:4444`

### Disk Imaging

#### Shutting down

먼저 **시스템을 종료**해야 합니다. 이는 항상 가능한 선택은 아닙니다. 시스템이 회사에서 종료할 수 없는 production server인 경우도 있기 때문입니다.\
시스템을 종료하는 방법에는 **일반 종료**와 **"plug the plug" 종료**의 **2가지 방법**이 있습니다. 첫 번째 방법은 **processes가 평소처럼 종료**되고 **filesystem**이 **동기화**되도록 하지만, **malware**가 **증거를 파괴**할 수 있는 가능성도 허용합니다. "pull the plug" 방식은 **일부 정보 손실**을 초래할 수 있지만(이미 memory의 image를 확보했으므로 많은 정보가 손실되지는 않습니다) **malware에는 어떤 조치도 취할 기회가 없습니다**. 따라서 **malware가 있을 수 있다고 **의심**한다면 시스템에서 **`sync`** **command**를 실행한 후 전원을 뽑으십시오.

#### Taking an image of the disk

**사건과 관련된 어떤 것에 컴퓨터를 연결하기 전에**, 정보가 수정되지 않도록 해당 장치가 **read only로 mount**될 것인지 반드시 확인해야 합니다.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### 디스크 이미지 사전 분석

더 이상 데이터가 없는 디스크 이미지 이미징.
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

Linux는 시스템 구성 요소의 무결성을 확인하는 도구를 제공하며, 이는 잠재적으로 문제가 있는 파일을 식별하는 데 중요합니다.<sup>[[1]](#references)</sup>

- **RedHat 기반 시스템**: `rpm -Va`를 사용하여 종합적인 검사를 수행합니다.
- **Debian 기반 시스템**: 먼저 `dpkg --verify`로 검증한 다음, 문제가 있는 항목을 식별하기 위해 `debsums | grep -v "OK$"`를 실행합니다(`apt-get install debsums`로 `debsums` 설치 후 사용).

### Malware/Rootkit 탐지 도구

Malware를 찾는 데 유용한 도구에 대해 알아보려면 다음 페이지를 읽어보세요:


{{#ref}}
malware-analysis.md
{{#endref}}

## 설치된 프로그램 검색

Debian 및 RedHat 시스템에서 설치된 프로그램을 효과적으로 검색하려면 일반적인 디렉터리에서 수동으로 확인하는 동시에 시스템 로그와 데이터베이스를 활용하세요.<sup>[[1]](#references)</sup>

- Debian의 경우 _**`/var/lib/dpkg/status`**_ 및 _**`/var/log/dpkg.log`**_를 확인하여 패키지 설치에 대한 세부 정보를 가져오고, `grep`을 사용하여 특정 정보를 필터링합니다.
- RedHat 사용자는 `rpm -qa --root=/mntpath/var/lib/rpm`으로 RPM 데이터베이스를 조회하여 설치된 패키지를 나열할 수 있습니다.

이러한 패키지 관리자 외부에서 수동으로 설치된 software를 찾으려면 _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ 및 _**`/sbin`**_과 같은 디렉터리를 확인합니다. 디렉터리 목록과 시스템별 명령을 함께 사용하여 알려진 패키지와 연결되지 않은 실행 파일을 식별하면, 설치된 모든 프로그램을 더욱 효과적으로 검색할 수 있습니다.
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

/tmp/exec에서 실행된 후 삭제된 process를 생각해 보세요. 이를 추출할 수 있습니다.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## SQLite 및 FTS5를 사용한 Syscall Trace Triage

프로세스가 아직 실행 중이거나 lab에서 다시 실행할 수 있는 경우, **`strace`**는 kernel module이나 전체 EDR telemetry 없이도 빠른 behavior trace를 제공할 수 있습니다. 대규모 trace의 경우 raw log를 직접 읽거나 LLM에 붙여넣지 말고, **SQLite** database에 저장한 후 필요한 최소 subset만 query하세요.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> `strace`를 attach하면 process timing이 변경되어 race condition이나 기타 취약한 bug에 영향을 줄 수 있습니다. 가능한 경우 copy/lab system에서 재현하는 것을 우선하세요.

### Capture

새 process의 경우:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
실행 중인 프로세스의 경우:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
유용한 옵션:

- `-ff`: fork/thread를 추적하고 프로세스별 출력을 유지
- `-ttt`: 타임라인 상관 분석을 쉽게 하기 위한 epoch timestamp
- `-yy`: 가능한 경우 file descriptor를 백업 경로/socket으로 확인
- `-s 4096`: 긴 경로 및 buffer 인수가 잘리지 않도록 유지

### 정규화

실용적인 schema는 syscall당 한 행, 인수당 한 행으로 구성합니다:
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
이는 서로 다른 syscall 행을 하나의 넓은 테이블로 평탄화하려는 시도를 피하고, triage 중 join을 예측 가능하게 유지합니다.

### 텍스트가 많은 인수를 FTS5로 인덱싱

대규모 trace에서 `LIKE "%...%"`를 사용한 순진한 경로 검색은 매우 느려집니다. 인수 텍스트에 대한 FTS5 인덱스를 생성한 다음 대신 이를 검색하세요:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
예: 모든 행을 스캔하지 않고 `/tmp` 아래의 파일 활동 복구:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### 높은 신호의 조사

- **PATH hijacking / fake sudo**: `~/.local/bin/` 아래의 쓰기 및 `chmod`/`rename` activity를 검색한 다음, `sudo`와 같이 권한 상승으로 보이는 이름에 대한 이후 `execve`와 상호 연관시킵니다.
- **임시 파일의 TOCTOU**: 동일한 `/tmp/...` 경로를 `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink`, `execve` 전반에서 추적하여 check/use 간격을 식별합니다.
- **Crash root cause**: 한 process가 동일한 inode/path에 쓰기 또는 truncation을 수행하는 동안 다른 process가 해당 파일을 `mmap`한 상황을 상호 연관시킨 다음, `SIGBUS`에 대한 signal/exit sequence를 검사합니다.
- **Network destination recovery**: `connect`, `sendto`, `sendmsg`, `recvfrom` 및 socket 관련 arguments를 필터링하여 peer IP와 port를 추출합니다.

### LLM 지원 trace analysis

LLM의 지원을 받으려면 **read-only** SQLite handle을 노출하고 전체 schema를 제공합니다. 데이터베이스를 제한적인 helper function으로 감싸는 대신 raw SQL을 실행하도록 하세요. 일반적으로 joins, temporal correlation 및 FTS lookups에 더 효과적입니다.

실용적인 규칙:

- 예를 들어 `sqlite3 'file:trace.db?mode=ro'`와 같이 database를 read-only로 유지합니다.
- 유효한 `JOIN` 및 `FTS5 MATCH` query의 예를 model에 제공합니다.
- raw multi-GB `strace` logs를 prompt에 붙여 넣지 **마세요**.
- 다음과 같이 구체적인 질문을 합니다:
- "이 program이 작성한 persistent files를 나열해 줘."
- "user-controlled PATH directories에 executables를 생성하거나 교체했나?"
- "이 trace가 SIGBUS로 끝나는 이유를 설명해 줘."

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
#### Hunt: 0anacron 및 의심스러운 stub를 통한 Cron/Anacron abuse
공격자는 주기적인 실행을 보장하기 위해 각 /etc/cron.*/ 디렉터리에 있는 0anacron stub를 수정하는 경우가 많습니다.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### 추적: SSH hardening rollback 및 backdoor shells
sshd_config 및 system account shells에 대한 변경은 access를 유지하기 위한 일반적인 post-exploitation 활동입니다.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API beacon은 일반적으로 HTTPS를 통해 api.dropboxapi.com 또는 content.dropboxapi.com을 사용하며, Authorization: Bearer token을 포함합니다.
- proxy/Zeek/NetFlow에서 서버에서 발생하는 예상치 못한 Dropbox egress를 Hunt합니다.
- Cloudflare Tunnel (`cloudflared`)은 outbound 443을 통한 backup C2를 제공합니다.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

malware가 service로 설치될 수 있는 경로:

- **/etc/inittab**: rc.sysinit과 같은 initialization scripts를 호출하고, 이후 startup scripts로 연결합니다.
- **/etc/rc.d/** 및 **/etc/rc.boot/**: service startup을 위한 scripts를 포함하며, 후자는 오래된 Linux versions에서 발견됩니다.
- **/etc/init.d/**: Debian과 같은 특정 Linux versions에서 startup scripts를 저장하는 데 사용됩니다.
- Linux variant에 따라 **/etc/inetd.conf** 또는 **/etc/xinetd/**를 통해 services가 활성화될 수도 있습니다.
- **/etc/systemd/system**: system 및 service manager scripts를 위한 directory입니다.
- **/etc/systemd/system/multi-user.target.wants/**: multi-user runlevel에서 시작되어야 하는 services에 대한 links를 포함합니다.
- **/usr/local/etc/rc.d/**: custom 또는 third-party services를 위한 경로입니다.
- **\~/.config/autostart/**: user-specific automatic startup applications를 위한 경로이며, user-targeted malware의 hiding spot이 될 수 있습니다.
- **/lib/systemd/system/**: installed packages가 제공하는 system-wide default unit files입니다.

#### Hunt: systemd timers and transient units

systemd persistence는 `.service` files에만 국한되지 않습니다. `.timer` units, user-level units 및 runtime에 생성되는 **transient units**를 조사하세요.
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
Transient units는 `/run/systemd/transient/`가 **비영구적**이기 때문에 쉽게 놓칠 수 있습니다. live image를 수집하는 경우 시스템 종료 전에 이를 확보하세요.

### Kernel Modules

Linux kernel modules는 rootkit 구성 요소로 자주 활용되며 시스템 부팅 시 로드됩니다. 이러한 modules와 관련된 중요한 디렉터리 및 파일은 다음과 같습니다.

- **/lib/modules/$(uname -r)**: 실행 중인 kernel 버전의 modules를 보관합니다.
- **/etc/modprobe.d**: module 로딩을 제어하는 configuration 파일을 포함합니다.
- **/etc/modprobe** 및 **/etc/modprobe.conf**: 전역 module 설정을 위한 파일입니다.

### 기타 Autostart 위치

Linux는 사용자 로그인 시 프로그램을 자동으로 실행하기 위해 다양한 파일을 사용하며, 여기에 malware가 숨어 있을 수 있습니다.

- **/etc/profile.d/**\*, **/etc/profile**, **/etc/bash.bashrc**: 모든 사용자 로그인 시 실행됩니다.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, **\~/.config/autostart**: 해당 사용자의 로그인 시 실행되는 사용자별 파일입니다.
- **/etc/rc.local**: 모든 system service가 시작된 후 실행되며, multiuser 환경으로 전환되는 과정의 종료 지점을 나타냅니다.

## 로그 검사

Linux 시스템은 다양한 log 파일을 통해 사용자 활동과 시스템 이벤트를 추적합니다. 이러한 log는 무단 access, malware 감염 및 기타 security incident를 식별하는 데 중요합니다.<sup>[[2]](#references)</sup> 주요 log 파일은 다음과 같습니다.

- **/var/log/syslog** (Debian) 또는 **/var/log/messages** (RedHat): 시스템 전체의 message와 활동을 기록합니다.
- **/var/log/auth.log** (Debian) 또는 **/var/log/secure** (RedHat): authentication 시도와 성공 및 실패한 로그인을 기록합니다.
- 관련 authentication event를 필터링하려면 `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`를 사용합니다.
- **/var/log/boot.log**: 시스템 startup message를 포함합니다.
- **/var/log/maillog** 또는 **/var/log/mail.log**: email server 활동을 기록하며, email 관련 service를 추적하는 데 유용합니다.
- **/var/log/kern.log**: error와 warning을 포함한 kernel message를 저장합니다.
- **/var/log/dmesg**: device driver message를 보관합니다.
- **/var/log/faillog**: 실패한 login 시도를 기록하여 security breach 조사에 도움이 됩니다.
- **/var/log/cron**: cron job 실행을 기록합니다.
- **/var/log/daemon.log**: background service 활동을 추적합니다.
- **/var/log/btmp**: 실패한 login 시도를 기록합니다.
- **/var/log/httpd/**: Apache HTTPD error 및 access log를 포함합니다.
- **/var/log/mysqld.log** 또는 **/var/log/mysql.log**: MySQL database 활동을 기록합니다.
- **/var/log/xferlog**: FTP file transfer를 기록합니다.
- **/var/log/**: 이 경로에서 예상하지 못한 log가 있는지 항상 확인합니다.

> [!TIP]
> 침입 또는 malware incident가 발생하면 Linux system log와 audit subsystem이 비활성화되거나 삭제될 수 있습니다. Linux 시스템의 log에는 일반적으로 악성 활동에 관한 가장 유용한 정보가 포함되어 있기 때문에, 침입자는 정기적으로 이를 삭제합니다. 따라서 사용 가능한 log 파일을 검사할 때 삭제 또는 변조의 징후일 수 있는 공백이나 순서가 맞지 않는 entry를 확인하는 것이 중요합니다.

### Journald triage (`journalctl`)

최신 Linux host에서 **systemd journal**은 일반적으로 **service execution**, **auth event**, **package operation**, **kernel/user-space message**를 확인할 수 있는 가장 가치 높은 source입니다. live response 중에는 **persistent** journal(`/var/log/journal/`)과 **runtime** journal(`/run/log/journal/`)을 모두 보존하도록 하세요. 공격자의 단기 활동이 후자에만 존재할 수 있기 때문입니다.<sup>[[5]](#references)</sup>
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
분류에 유용한 journal 필드에는 `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, `MESSAGE`가 있습니다. journald가 영구 저장소 없이 구성된 경우 `/run/log/journal/`에서 최근 데이터만 확인할 수 있습니다.

### Audit framework triage (`auditd`)

`auditd`가 활성화되어 있다면 파일 변경, 명령 실행, 로그인 활동 또는 패키지 설치에 대한 **process attribution**이 필요할 때 우선적으로 사용하세요.<sup>[[6]](#references)</sup>
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
규칙이 키와 함께 배포된 경우, 원시 로그를 grep하는 대신 해당 키에서 pivot하세요:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux는 각 사용자에 대한 command history를 유지하며**, 다음 위치에 저장합니다:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

또한 `last -Faiwx` command는 사용자 login 목록을 제공합니다. 알 수 없거나 예상치 못한 login이 있는지 확인하세요.

추가적인 privileges를 부여할 수 있는 파일을 확인하세요:

- 예상치 못한 사용자 privileges가 부여되었는지 `/etc/sudoers`를 검토합니다.
- 예상치 못한 사용자 privileges가 부여되었는지 `/etc/sudoers.d/`를 검토합니다.
- 비정상적인 group memberships 또는 permissions를 식별하기 위해 `/etc/groups`를 검사합니다.
- 비정상적인 group memberships 또는 permissions를 식별하기 위해 `/etc/passwd`를 검사합니다.

일부 apps는 자체 logs도 생성합니다:

- **SSH**: 승인되지 않은 remote connections를 확인하기 위해 _\~/.ssh/authorized_keys_ 및 _\~/.ssh/known_hosts_를 검사합니다.
- **Gnome Desktop**: Gnome applications를 통해 최근에 액세스한 파일을 확인하려면 _\~/.recently-used.xbel_을 살펴봅니다.
- **Firefox/Chrome**: 의심스러운 활동이 있는지 _\~/.mozilla/firefox_ 또는 _\~/.config/google-chrome_에서 browser history와 downloads를 확인합니다.
- **VIM**: 액세스한 file paths와 search history 등의 사용 세부 정보를 확인하기 위해 _\~/.viminfo_를 검토합니다.
- **Open Office**: compromised files를 나타낼 수 있는 최근 document access를 확인합니다.
- **FTP/SFTP**: 승인되지 않았을 수 있는 file transfers를 확인하기 위해 _\~/.ftp_history_ 또는 _\~/.sftp_history_의 logs를 검토합니다.
- **MySQL**: 승인되지 않은 database activities를 드러낼 수 있는 실행된 MySQL queries를 확인하기 위해 _\~/.mysql_history_를 조사합니다.
- **Less**: 확인한 files와 실행된 commands를 포함한 사용 history를 분석하려면 _\~/.lesshst_를 분석합니다.
- **Git**: repositories의 변경 사항을 확인하기 위해 _\~/.gitconfig_ 및 project _.git/logs_를 검사합니다.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip)은 순수 Python 3로 작성된 작은 software로, USB event history tables를 생성하기 위해 Linux log files를 파싱합니다. 배포판에 따라 대상 log files는 (`/var/log/syslog*` 또는 `/var/log/messages*`)입니다.

**사용된 모든 USB를 확인하는 것**은 중요하며, "violation events"를 찾기 위해 승인된 USB 목록이 있다면 더욱 유용합니다. 여기서 "violation events"란 해당 목록에 포함되지 않은 USB의 사용을 의미합니다.

### 설치
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
github 내부에서 더 많은 예제와 정보를 확인할 수 있습니다: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## 사용자 계정 및 로그온 활동 검토

_**/etc/passwd**_, _**/etc/shadow**_ 및 **보안 로그**를 조사하여 알려진 비인가 이벤트가 발생한 시점과 근접한 시간에 생성되었거나 사용된 비정상적인 이름 또는 계정이 있는지 확인합니다. 또한 sudo brute-force 공격 가능성도 확인합니다.\
또한 _**/etc/sudoers**_ 및 _**/etc/groups**_와 같은 파일을 확인하여 사용자에게 예기치 않은 권한이 부여되었는지 조사합니다.\
마지막으로 **비밀번호가 없거나** **쉽게 추측할 수 있는** 비밀번호를 사용하는 계정을 찾습니다.<sup>[[1]](#references)</sup>

## 파일 시스템 검사

### Malware Investigation에서 파일 시스템 구조 분석

Malware incident를 조사할 때 파일 시스템의 구조는 중요한 정보 출처로, 이벤트의 순서와 malware의 내용을 모두 보여줍니다. 그러나 malware 작성자는 파일 타임스탬프를 수정하거나 데이터 저장에 파일 시스템을 사용하지 않는 등의 방식으로 이러한 분석을 방해하는 기술을 개발하고 있습니다.<sup>[[1]](#references)</sup>

이러한 anti-forensic 방법에 대응하려면 다음을 수행해야 합니다:

- **Autopsy**와 같은 도구를 사용하여 이벤트 타임라인을 시각화하거나, **Sleuth Kit**의 `mactime`을 사용하여 상세한 타임라인 데이터를 확인하는 등 **철저한 타임라인 분석을 수행합니다**.
- 시스템의 $PATH에서 **예상하지 못한 스크립트를 조사합니다**. 여기에는 공격자가 사용한 shell 또는 PHP 스크립트가 포함될 수 있습니다.
- **`/dev`에서 비정상적인 파일을 검사합니다**. 일반적으로 특수 파일이 포함되는 디렉터리지만, malware 관련 파일이 존재할 수도 있습니다.
- ".. " (dot dot space) 또는 "..^G" (dot dot control-G)와 같은 이름을 가진 **숨겨진 파일 또는 디렉터리를 검색합니다**. 이러한 파일이나 디렉터리는 악성 콘텐츠를 숨길 수 있습니다.
- 다음 명령을 사용하여 **setuid root 파일을 식별합니다**: `find / -user root -perm -04000 -print` 이 명령은 공격자가 악용할 수 있는 높은 권한이 설정된 파일을 찾습니다.
- inode 테이블에서 **삭제 타임스탬프를 검토하여** 대량 파일 삭제를 확인합니다. 이는 rootkit 또는 trojan의 존재를 나타낼 수 있습니다.
- 하나의 악성 파일을 식별한 후 **연속된 inode를 검사하여** 주변에 있는 악성 파일을 확인합니다. 이러한 파일들은 함께 배치되었을 수 있습니다.
- **일반적인 binary 디렉터리**(_/bin_, _/sbin_)에서 최근 수정된 파일을 확인합니다. 이러한 파일은 malware에 의해 변경되었을 수 있습니다.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> **공격자**는 **시간**을 **수정**하여 **파일이** **정상적인 것처럼 보이게** 만들 수 있지만, **inode**는 수정할 수 없습니다. 동일한 폴더의 다른 파일과 **동일한 시간에** 생성 및 수정된 것으로 표시되는 **파일**을 발견했는데 **inode**가 **예상보다 큰 경우**, 해당 파일의 **타임스탬프가 수정된 것**입니다.

### inode 중심의 빠른 초기 조사

anti-forensics가 의심되면 다음 inode 중심 검사를 초기에 실행하세요:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
의심스러운 inode가 EXT 파일 시스템 이미지/디바이스에 있는 경우, inode 메타데이터를 직접 검사합니다:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
유용한 필드:
- **Links**: 현재 어떤 디렉터리 엔트리도 inode를 참조하지 않으면 `0`입니다.
- **dtime**: inode이 unlink될 때 설정되는 삭제 timestamp입니다.
- **ctime/mtime**: metadata/content 변경 사항을 incident timeline과 연관시키는 데 도움이 됩니다.

### Capabilities, xattrs, 및 preload 기반 userland rootkits

Modern Linux persistence는 명확한 **setuid** binaries를 피하고 대신 **file capabilities**, **extended attributes**, 그리고 dynamic loader를 악용하는 경우가 많습니다.
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
특히 `/tmp`, `/dev/shm`, `/var/tmp` 또는 `/usr/local/lib` 아래의 비정상적인 위치와 같이 **writable** 경로에서 참조되는 libraries에 주의하세요. 또한 일반적인 package ownership 범위를 벗어난 capability-bearing binaries를 확인하고, 이를 package verification 결과(`rpm -Va`, `dpkg --verify`, `debsums`)와 연관 지어 분석하세요.

## 서로 다른 filesystem 버전의 파일 비교

### Filesystem Version Comparison Summary

filesystem 버전을 비교하고 변경 사항을 특정하려면 간소화된 `git diff` 명령을 사용합니다:<sup>[[3]](#references)</sup>

- **새 파일을 찾으려면**, 두 디렉터리를 비교합니다:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **수정된 콘텐츠의 경우**, 특정 줄은 무시하고 변경 사항을 나열하세요:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **삭제된 파일을 탐지하려면**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`)는 추가된 (`A`), 삭제된 (`D`) 또는 수정된 (`M`) 파일과 같은 특정 변경 사항으로 범위를 좁히는 데 도움이 됩니다.
- `A`: 추가된 파일
- `C`: 복사된 파일
- `D`: 삭제된 파일
- `M`: 수정된 파일
- `R`: 이름이 변경된 파일
- `T`: 유형 변경(예: 파일에서 symlink로 변경)
- `U`: 병합되지 않은 파일
- `X`: 알 수 없는 파일
- `B`: 손상된 파일

## References

- [1] [Linux 시스템을 위한 Malware Forensics Field Guide: Digital Forensics Field Guides – Chapter 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Linux Logs 설명](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [git diff Documentation – --diff-filter 옵션](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – persistence를 위한 Patching: DripDropper Linux malware가 cloud를 통해 이동하는 방식](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Linux Journals의 Forensic Analysis](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - system Auditing](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Pike에게 인사하세요!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)
{{#include ../../banners/hacktricks-training.md}}
