# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## 초기 정보 수집

### 기본 정보

우선 **USB**에 **정상으로 알려진 바이너리와 라이브러리**를 준비하는 것이 좋습니다(ubuntu를 가져와 _/bin_, _/sbin_, _/lib,_ 및 _/lib64_ 폴더를 복사하면 됩니다). 그런 다음 USB를 mount하고, 해당 바이너리를 사용하도록 env 변수를 수정합니다:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
시스템이 정상적이고 알려진 바이너리를 사용하도록 구성했다면 **몇 가지 기본 정보를 추출**하기 시작할 수 있습니다:
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

기본 정보를 수집하는 동안 다음과 같은 이상한 항목을 확인해야 합니다:

- **Root processes**는 일반적으로 낮은 PIDS로 실행되므로, 큰 PID를 가진 root process를 발견하면 의심할 수 있습니다.
- `/etc/passwd`에서 shell이 없는 사용자의 **registered logins**를 확인합니다.
- shell이 없는 사용자의 `/etc/shadow`에서 **password hashes**를 확인합니다.

### Memory Dump

실행 중인 시스템의 메모리를 얻으려면 [**LiME**](https://github.com/504ensicsLabs/LiME)를 사용하는 것이 좋습니다.\
이를 **compile**하려면 victim machine이 사용하는 것과 **동일한 kernel**을 사용해야 합니다.

> [!TIP]
> victim machine에서는 **LiME 또는 다른 어떤 것도 설치할 수 없습니다**. 설치하면 시스템에 여러 변경 사항이 발생하기 때문입니다.

따라서 동일한 Ubuntu 버전이 있다면 `apt-get install lime-forensics-dkms`를 사용할 수 있습니다.\
그 외의 경우에는 github에서 [**LiME**](https://github.com/504ensicsLabs/LiME)를 다운로드하고 올바른 kernel headers를 사용해 compile해야 합니다. victim machine의 **정확한 kernel headers를 얻으려면** `/lib/modules/<kernel version>` **directory를 복사**한 다음, 해당 파일을 사용해 LiME를 **compile**하면 됩니다:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME은 3가지 **형식**을 지원합니다:

- Raw (모든 세그먼트를 서로 연결)
- Padded (Raw와 동일하지만 오른쪽 비트를 0으로 채움)
- Lime (메타데이터가 포함된 권장 형식

LiME은 다음과 같이 `path=tcp:4444`를 사용하여 시스템에 저장하는 대신 **네트워크를 통해 덤프를 전송**하는 데에도 사용할 수 있습니다.

### 디스크 이미징

#### 시스템 종료

먼저 **시스템을 종료**해야 합니다. 회사에서 시스템 종료를 감당할 수 없는 production server인 경우도 있으므로, 항상 가능한 방법은 아닙니다.\
시스템을 종료하는 방법에는 **일반 종료**와 **"플러그를 뽑는" 종료**의 **2가지 방법**이 있습니다. 첫 번째 방법은 **프로세스가 평소처럼 종료**되고 **파일시스템**이 **동기화**되도록 하지만, 동시에 존재할 가능성이 있는 **malware**가 **증거를 파괴**하도록 허용할 수도 있습니다. "플러그를 뽑는" 방식은 **일부 정보 손실**을 초래할 수 있지만(이미 메모리 이미지를 확보했으므로 많은 정보가 손실되지는 않습니다) **malware가 어떠한 조치도 취할 기회가 없게 됩니다**. 따라서 **malware가 있을 수 있다고 의심**되면 시스템에서 **`sync`** **명령**만 실행한 다음 플러그를 뽑으십시오.

#### 디스크 이미지 생성

**사건과 관련된 어떤 것에든 컴퓨터를 연결하기 전에**, 정보가 수정되지 않도록 반드시 **읽기 전용으로 마운트**되는지 확인해야 한다는 점이 중요합니다.
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

### 수정된 System Files

Linux는 잠재적으로 문제가 있는 파일을 식별하는 데 중요한 System Components의 무결성을 확인하는 도구를 제공합니다.<sup>[[1]](#references)</sup>

- **RedHat 기반 시스템**: 포괄적인 검사를 위해 `rpm -Va`를 사용합니다.
- **Debian 기반 시스템**: 초기 검증에는 `dpkg --verify`를 사용하고, 문제가 있는 항목을 식별하려면 `debsums | grep -v "OK$"`를 사용합니다(`apt-get install debsums`로 `debsums` 설치 후).

### Malware/Rootkit Detectors

Malware를 찾는 데 유용한 도구를 알아보려면 다음 페이지를 읽어보세요:


{{#ref}}
malware-analysis.md
{{#endref}}

## 설치된 프로그램 검색

Debian 및 RedHat 시스템에 설치된 프로그램을 효과적으로 검색하려면 일반적인 디렉터리에서 수동으로 확인하는 것과 함께 System Logs 및 Databases를 활용하는 것이 좋습니다.<sup>[[1]](#references)</sup>

- Debian에서는 _**`/var/lib/dpkg/status`**_ 및 _**`/var/log/dpkg.log`**_를 확인하여 패키지 설치에 관한 세부 정보를 가져오고, `grep`을 사용해 특정 정보를 필터링합니다.
- RedHat 사용자는 RPM database를 `rpm -qa --root=/mntpath/var/lib/rpm`으로 조회하여 설치된 패키지를 나열할 수 있습니다.

이러한 Package Managers를 사용하지 않고 수동으로 설치된 Software를 찾으려면 _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, _**`/sbin`**_과 같은 디렉터리를 확인합니다. 디렉터리 목록과 System-specific Commands를 함께 사용하여 알려진 패키지와 연결되지 않은 Executables를 식별하면, 설치된 모든 프로그램을 더욱 철저히 검색할 수 있습니다.
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

/tmp/exec에서 실행된 후 삭제된 process를 가정해 보겠습니다. 해당 process를 추출할 수 있습니다.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## SQLite 및 FTS5를 사용한 Syscall Trace Triage

프로세스가 아직 실행 중이거나 lab에서 다시 실행할 수 있는 경우, **`strace`**는 kernel modules나 전체 EDR telemetry 없이도 빠르게 동작 trace를 수집할 수 있습니다. 대규모 trace의 경우 raw log를 직접 읽거나 LLM에 붙여넣지 말고, **SQLite** database에 저장한 다음 필요한 최소 subset만 query하세요.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> `strace`를 attach하면 process timing이 변경되고 race conditions나 기타 취약한 bugs에 영향을 줄 수 있습니다. 가능한 경우 copy/lab system에서 재현하는 것을 우선하세요.

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
- `-ttt`: 손쉬운 타임라인 상관 분석을 위한 epoch timestamp
- `-yy`: 가능한 경우 파일 디스크립터를 백킹 경로/소켓으로 확인
- `-s 4096`: 긴 경로 및 buffer 인수가 잘리지 않도록 유지

### 정규화

실용적인 스키마는 syscall당 한 행, 인수당 한 열입니다:
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

### FTS5로 텍스트가 많은 인수 인덱싱

대규모 trace에서 `LIKE "%...%"`를 사용한 단순한 path 검색은 매우 느려집니다. 인수 텍스트에 대한 FTS5 인덱스를 생성한 후 대신 이를 검색하세요:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
예시: 모든 행을 스캔하지 않고 `/tmp` 아래의 파일 활동을 복구하려면:
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

- **PATH hijacking / fake sudo**: `~/.local/bin/` 아래에서 쓰기 및 `chmod`/`rename` activity를 검색한 다음, `sudo`와 같이 privileged로 보이는 이름에 대한 이후 `execve`와 상관관계를 분석합니다.
- **TOCTOU on temporary files**: 동일한 `/tmp/...` path를 대상으로 `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink`, `execve`를 추적하여 check/use gap을 식별합니다.
- **Crash root cause**: 한 process가 file을 `mmap`한 뒤 다른 process가 동일한 inode/path에 write 또는 truncation을 수행하는지 상관관계를 분석하고, signal/exit sequence에서 `SIGBUS`를 확인합니다.
- **Network destination recovery**: `connect`, `sendto`, `sendmsg`, `recvfrom` 및 socket 관련 arguments를 필터링하여 peer IP와 port를 추출합니다.

### LLM-assisted trace analysis

LLM의 assistance를 받으려면 **read-only** SQLite handle을 제공하고 전체 schema를 함께 전달합니다. Database를 제한적인 helper functions 뒤에 감싸는 대신 raw SQL을 실행하도록 하세요. 이렇게 하면 일반적으로 joins, temporal correlation 및 FTS lookups에 더 효과적입니다.

Practical rules:

- 예를 들어 `sqlite3 'file:trace.db?mode=ro'`와 같이 database를 read-only로 유지합니다.
- 유효한 `JOIN` 및 `FTS5 MATCH` queries의 examples를 model에 제공합니다.
- Raw multi-GB `strace` logs를 prompt에 붙여 넣지 **마세요**.
- 다음과 같이 focused questions를 요청합니다:
- "이 program이 write한 persistent files를 나열해 줘."
- "user-controlled PATH directories에 executables를 create하거나 replace했는가?"
- "이 trace가 SIGBUS로 종료되는 이유를 설명해 줘."

## Autostart locations 검사

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
#### Hunt: 0anacron 및 의심스러운 스텁을 통한 Cron/Anacron 악용
공격자는 주기적인 실행을 보장하기 위해 각 /etc/cron.*/ 디렉터리에 있는 0anacron 스텁을 수정하는 경우가 많습니다.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH hardening rollback and backdoor shells
sshd_config 및 system account shell 변경은 access를 유지하기 위한 일반적인 post-exploitation 행위입니다.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API beacon은 일반적으로 HTTPS를 통해 api.dropboxapi.com 또는 content.dropboxapi.com을 사용하며, Authorization: Bearer token을 포함합니다.
- proxy/Zeek/NetFlow에서 서버에서 발생하는 예상치 못한 Dropbox outbound traffic을 Hunt합니다.
- Cloudflare Tunnel (`cloudflared`)은 outbound 443을 통한 backup C2를 제공합니다.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### 서비스

malware가 서비스로 설치될 수 있는 경로:

- **/etc/inittab**: rc.sysinit와 같은 초기화 스크립트를 호출하고, 이후 startup scripts로 연결합니다.
- **/etc/rc.d/** 및 **/etc/rc.boot/**: 서비스 startup을 위한 스크립트를 포함하며, 후자는 이전 Linux 버전에서 확인됩니다.
- **/etc/init.d/**: Debian과 같은 일부 Linux 버전에서 startup scripts를 저장하는 데 사용됩니다.
- Linux variant에 따라 **/etc/inetd.conf** 또는 **/etc/xinetd/**를 통해 서비스가 활성화될 수도 있습니다.
- **/etc/systemd/system**: system 및 service manager scripts를 위한 디렉터리입니다.
- **/etc/systemd/system/multi-user.target.wants/**: multi-user runlevel에서 시작되어야 하는 서비스로 연결되는 링크를 포함합니다.
- **/usr/local/etc/rc.d/**: custom 또는 third-party 서비스용입니다.
- **\~/.config/autostart/**: user-specific automatic startup applications용이며, user-targeted malware의 은닉 장소로 사용될 수 있습니다.
- **/lib/systemd/system/**: 설치된 package가 제공하는 system-wide default unit files입니다.

#### Hunt: systemd timers 및 transient units

systemd persistence는 `.service` files에만 국한되지 않습니다. `.timer` units, user-level units 및 runtime에 생성된 **transient units**를 조사하세요.
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
Transient units는 `/run/systemd/transient/`가 **비영구적**이기 때문에 쉽게 놓칠 수 있습니다. live image를 수집하는 경우 종료 전에 이를 확보하세요.

### Kernel Modules

Linux kernel modules는 malware가 rootkit components로 자주 활용하며, system boot 시 로드됩니다. 이러한 modules와 관련된 중요한 directories 및 files는 다음과 같습니다.

- **/lib/modules/$(uname -r)**: 실행 중인 kernel version용 modules를 보관합니다.
- **/etc/modprobe.d**: module loading을 제어하기 위한 configuration files를 포함합니다.
- **/etc/modprobe** 및 **/etc/modprobe.conf**: 전역 module settings를 위한 files입니다.

### 기타 Autostart 위치

Linux는 user login 시 programs를 자동으로 실행하기 위해 다양한 files를 사용하며, 여기에 malware가 숨어 있을 수 있습니다.

- **/etc/profile.d/**\*, **/etc/profile**, **/etc/bash.bashrc**: 모든 user login 시 실행됩니다.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, **\~/.config/autostart**: 해당 user의 login 시 실행되는 user-specific files입니다.
- **/etc/rc.local**: 모든 system services가 시작된 후 실행되며, multiuser environment로의 transition이 끝나는 시점을 나타냅니다.

## Logs 검사

Linux systems는 다양한 log files를 통해 user activities와 system events를 추적합니다. 이러한 logs는 unauthorized access, malware infections 및 기타 security incidents를 식별하는 데 중요합니다.<sup>[[2]](#references)</sup> 주요 log files는 다음과 같습니다.

- **/var/log/syslog** (Debian) 또는 **/var/log/messages** (RedHat): system-wide messages와 activities를 기록합니다.
- **/var/log/auth.log** (Debian) 또는 **/var/log/secure** (RedHat): authentication attempts 및 성공하거나 실패한 logins를 기록합니다.
- `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`를 사용하여 관련 authentication events를 필터링합니다.
- **/var/log/boot.log**: system startup messages를 포함합니다.
- **/var/log/maillog** 또는 **/var/log/mail.log**: email server activities를 기록하며, email-related services를 추적하는 데 유용합니다.
- **/var/log/kern.log**: errors와 warnings를 포함한 kernel messages를 저장합니다.
- **/var/log/dmesg**: device driver messages를 보관합니다.
- **/var/log/faillog**: failed login attempts를 기록하여 security breach investigations를 지원합니다.
- **/var/log/cron**: cron job executions를 기록합니다.
- **/var/log/daemon.log**: background service activities를 추적합니다.
- **/var/log/btmp**: failed login attempts를 기록합니다.
- **/var/log/httpd/**: Apache HTTPD error 및 access logs를 포함합니다.
- **/var/log/mysqld.log** 또는 **/var/log/mysql.log**: MySQL database activities를 기록합니다.
- **/var/log/xferlog**: FTP file transfers를 기록합니다.
- **/var/log/**: 이 위치에 예상하지 못한 logs가 있는지 항상 확인합니다.

> [!TIP]
> Linux system logs 및 audit subsystems는 intrusion 또는 malware incident에서 비활성화되거나 삭제될 수 있습니다. Linux systems의 logs에는 일반적으로 malicious activities에 대한 가장 유용한 정보가 포함되므로, intruders는 정기적으로 이를 삭제합니다. 따라서 사용 가능한 log files를 검사할 때는 삭제 또는 tampering의 징후일 수 있는 gaps나 순서가 맞지 않는 entries가 있는지 확인하는 것이 중요합니다.

### Journald triage (`journalctl`)

최신 Linux hosts에서 **systemd journal**은 일반적으로 **service execution**, **auth events**, **package operations**, **kernel/user-space messages**에 대한 가치가 가장 높은 source입니다. live response 중에는 **persistent** journal (`/var/log/journal/`)과 **runtime** journal (`/run/log/journal/`)을 모두 보존하도록 하세요. 짧은 시간 동안 발생한 attacker activity가 후자에만 존재할 수 있기 때문입니다.<sup>[[5]](#references)</sup>
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
트리아지에 유용한 journal 필드에는 `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, `MESSAGE`가 있습니다. journald가 persistent storage 없이 구성된 경우 `/run/log/journal/`에서 최근 데이터만 확인할 수 있습니다.

### Audit framework 트리아지 (`auditd`)

`auditd`가 활성화되어 있다면 파일 변경, command 실행, 로그인 활동 또는 package 설치에 대한 **process attribution**이 필요할 때 이를 우선 사용하세요.<sup>[[6]](#references)</sup>
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
키를 사용해 규칙이 배포된 경우, 원시 로그를 grep하는 대신 해당 키에서 pivot하세요:
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

또한 `last -Faiwx` command는 사용자 login 목록을 제공합니다. 알 수 없거나 예상하지 못한 login이 있는지 확인하세요.

추가 privileges를 부여할 수 있는 파일을 확인하세요:

- 예상하지 못한 사용자 privileges가 부여되었는지 `/etc/sudoers`를 검토하세요.
- 예상하지 못한 사용자 privileges가 부여되었는지 `/etc/sudoers.d/`를 검토하세요.
- 비정상적인 group membership 또는 permissions를 식별하기 위해 `/etc/groups`를 확인하세요.
- 비정상적인 group membership 또는 permissions를 식별하기 위해 `/etc/passwd`를 확인하세요.

일부 apps는 자체 logs도 생성합니다:

- **SSH**: 인증되지 않은 원격 connections를 확인하기 위해 _\~/.ssh/authorized_keys_ 및 _\~/.ssh/known_hosts_를 확인하세요.
- **Gnome Desktop**: Gnome applications를 통해 최근에 접근한 파일을 확인하려면 _\~/.recently-used.xbel_을 살펴보세요.
- **Firefox/Chrome**: 의심스러운 활동을 확인하기 위해 _\~/.mozilla/firefox_ 또는 _\~/.config/google-chrome_에서 browser history와 downloads를 확인하세요.
- **VIM**: 접근한 file paths와 search history 등의 사용 세부 정보를 확인하려면 _\~/.viminfo_를 검토하세요.
- **Open Office**: 손상된 files를 나타낼 수 있는 최근 document access를 확인하세요.
- **FTP/SFTP**: 인증되지 않았을 수 있는 file transfers를 확인하기 위해 _\~/.ftp_history_ 또는 _\~/.sftp_history_의 logs를 검토하세요.
- **MySQL**: 실행된 MySQL queries를 확인하고, 인증되지 않은 database activities가 드러날 수 있는 _\~/.mysql_history_를 조사하세요.
- **Less**: 열람한 files와 실행된 commands를 포함한 사용 history를 확인하기 위해 _\~/.lesshst_를 분석하세요.
- **Git**: repositories의 변경 사항을 확인하기 위해 _\~/.gitconfig_ 및 project의 _.git/logs_를 살펴보세요.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip)은 순수 Python 3로 작성된 작은 software로, Linux log files(` distro에 따라 `/var/log/syslog*` 또는 `/var/log/messages*`)를 parsing하여 USB event history tables를 생성합니다.

**사용된 모든 USB를 파악하는 것**은 중요하며, authorized USB 목록이 있다면 해당 목록에 포함되지 않은 USB의 사용인 "violation events"를 찾는 데 더욱 유용합니다.

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

## 사용자 계정 및 Logon 활동 검토

_**/etc/passwd**_, _**/etc/shadow**_ 및 **보안 로그**를 조사하여, 알려진 무단 이벤트와 가까운 시점에 생성되거나 사용된 비정상적인 이름 또는 계정이 있는지 확인합니다. 또한 sudo brute-force 공격 가능성도 확인합니다.\
또한 _**/etc/sudoers**_ 및 _**/etc/groups**_와 같은 파일을 확인하여 사용자에게 부여된 예상치 못한 권한이 있는지 살펴봅니다.\
마지막으로 **비밀번호가 없는** 계정이나 **쉽게 추측할 수 있는** 비밀번호를 사용하는 계정을 찾습니다.<sup>[[1]](#references)</sup>

## 파일 시스템 검사

### Malware Investigation에서 파일 시스템 구조 분석

Malware incident를 조사할 때 파일 시스템의 구조는 사건의 순서와 malware의 콘텐츠를 모두 보여주는 중요한 정보원입니다. 그러나 malware 작성자는 파일 타임스탬프를 수정하거나 데이터 저장에 파일 시스템을 사용하지 않는 등의 기법을 개발하여 이러한 분석을 방해하고 있습니다.<sup>[[1]](#references)</sup>

이러한 anti-forensic 기법에 대응하려면 다음을 수행해야 합니다.

- **Autopsy**와 같은 도구를 사용하여 이벤트 타임라인을 시각화하거나 **Sleuth Kit**의 `mactime`을 사용하여 상세한 타임라인 데이터를 확인하는 등 **철저한 타임라인 분석을 수행**합니다.
- 시스템의 $PATH에서 **예상치 못한 스크립트**를 조사합니다. 여기에는 공격자가 사용한 shell 또는 PHP 스크립트가 포함될 수 있습니다.
- 일반적으로 특수 파일이 포함되는 `/dev`에서 **비정상적인 파일을 검사**합니다. 이 디렉터리에는 malware와 관련된 파일이 존재할 수도 있습니다.
- ".. " (dot dot space) 또는 "..^G" (dot dot control-G)와 같은 이름을 가진 **숨겨진 파일이나 디렉터리**를 검색합니다. 이러한 파일이나 디렉터리는 악성 콘텐츠를 숨길 수 있습니다.
- 다음 명령을 사용하여 **setuid root 파일을 식별**합니다: `find / -user root -perm -04000 -print` 이 명령은 상승된 권한을 가진 파일을 찾으며, 공격자가 이를 악용할 수 있습니다.
- inode 테이블에서 **삭제 타임스탬프를 검토**하여 대량 파일 삭제를 탐지합니다. 이는 rootkit 또는 trojan의 존재를 나타낼 수 있습니다.
- 하나의 악성 파일을 식별한 후 **연속된 inode를 검사**하여 인접한 악성 파일이 있는지 확인합니다. 해당 파일들이 함께 배치되었을 수 있기 때문입니다.
- **일반적인 binary 디렉터리**(_/bin_, _/sbin_)에서 최근 수정된 파일을 확인합니다. 이러한 파일은 malware에 의해 변경되었을 수 있습니다.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> **attacker**가 **time**을 **modify**하여 **files appear** **legitimate**하게 만들 수 있지만, **inode**는 **modify**할 수 없습니다. **file**이 동일한 폴더의 다른 **files**와 **same time**에 생성되고 수정되었다고 나타나지만 **inode**가 **unexpectedly bigger**라면, 해당 **file**의 **timestamps**가 **modified**된 것입니다.

### Inode 중심 빠른 triage

anti-forensics를 의심한다면 다음 inode 중심 검사를 초기에 실행하세요:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
EXT filesystem 이미지/디바이스에서 의심스러운 inode가 발견되면 inode 메타데이터를 직접 검사합니다:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
유용한 필드:
- **Links**: `0`이면 현재 해당 inode를 참조하는 directory entry가 없습니다.
- **dtime**: inode가 unlink될 때 설정되는 deletion timestamp입니다.
- **ctime/mtime**: metadata/content 변경 사항을 incident timeline과 연관시키는 데 도움이 됩니다.

### Capabilities, xattrs, and preload-based userland rootkits

Modern Linux persistence는 흔히 명백한 `setuid` binaries를 피하고 대신 **file capabilities**, **extended attributes**, dynamic loader를 악용합니다.
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
**writable** 경로(`/tmp`, `/dev/shm`, `/var/tmp` 또는 `/usr/local/lib` 아래의 특이한 위치)에서 참조되는 libraries에 특히 주의하세요. 또한 일반적인 package ownership 범위를 벗어난 capability-bearing binaries를 확인하고, 이를 package verification 결과(`rpm -Va`, `dpkg --verify`, `debsums`)와 연관 지어 분석하세요.

## 서로 다른 filesystem 버전의 파일 비교

### Filesystem 버전 비교 요약

filesystem 버전을 비교하고 변경 사항을 정확히 파악하려면 단순화한 `git diff` commands를 사용합니다:<sup>[[3]](#references)</sup>

- **새 files를 찾으려면**, 두 directories를 비교합니다:
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
- **Filter options** (`--diff-filter`)을 사용하면 추가된 (`A`), 삭제된 (`D`) 또는 수정된 (`M`) 파일과 같은 특정 변경 사항으로 범위를 좁힐 수 있습니다.
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

- [1] [Linux 시스템을 위한 Malware Forensics Field Guide: Digital Forensics Field Guides - Chapter 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Linux Logs Explained](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [git diff Documentation - --diff-filter option](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary - Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Say hi to Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
