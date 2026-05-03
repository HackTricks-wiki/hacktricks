# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## 초기 정보 수집

### 기본 정보

우선, **USB**에 **잘 알려진 바이너리와 라이브러리**를 넣어두는 것이 좋습니다(ubuntu를 받아서 _/bin_, _/sbin_, _/lib,_ 그리고 _/lib64_ 폴더를 복사하면 됩니다). 그런 다음 USB를 마운트하고, 해당 바이너리를 사용하도록 env 변수를 수정합니다:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
시스템을 good하고 known된 binaries를 사용하도록 구성한 후에는 **몇 가지 basic information을 추출**하기 시작할 수 있습니다:
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

기본 정보를 얻는 동안 다음과 같은 이상한 점을 확인해야 합니다:

- **Root processes**는 보통 낮은 PID를 사용하므로, 큰 PID를 가진 root process를 발견하면 의심할 수 있습니다
- `/etc/passwd`에서 shell이 없는 사용자의 **registered logins**를 확인
- shell이 없는 사용자의 `/etc/shadow`에서 **password hashes**를 확인

### Memory Dump

실행 중인 시스템의 메모리를 얻으려면 [**LiME**](https://github.com/504ensicsLabs/LiME)를 사용하는 것이 권장됩니다.\
이를 **compile**하려면 피해자 머신이 사용하는 것과 **same kernel**을 사용해야 합니다.

> [!TIP]
> 피해자 머신에는 LiME나 그 어떤 것도 **install**할 수 없다는 점을 기억하세요. 그렇게 하면 여러 변경 사항이 발생합니다

따라서 동일한 버전의 Ubuntu가 있다면 `apt-get install lime-forensics-dkms`를 사용할 수 있습니다.\
다른 경우에는 github에서 [**LiME**](https://github.com/504ensicsLabs/LiME)를 다운로드하고 올바른 kernel headers로 compile해야 합니다. 피해자 머신의 **exact kernel headers**를 얻으려면, 단순히 `/lib/modules/<kernel version>` 디렉터리를 자신의 머신으로 **copy**한 뒤, 그것을 사용해 LiME를 **compile**하면 됩니다:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME는 3가지 **formats**를 지원합니다:

- Raw (모든 segment를 하나로 이어 붙인 것)
- Padded (raw와 같지만, 오른쪽 비트에 zeroes가 있음)
- Lime (metadata가 포함된 권장 format)

LiME는 시스템에 저장하는 대신 `path=tcp:4444` 같은 것을 사용해 **네트워크를 통해 dump를 전송**하는 데에도 사용할 수 있습니다.

### Disk Imaging

#### Shutting down

먼저, **시스템을 종료**해야 합니다. 이는 때때로 회사가 종료할 여유가 없는 production server일 수 있어 항상 가능한 선택은 아닙니다.\
시스템을 종료하는 방법에는 **2가지**가 있는데, **normal shutdown**과 **"plug the plug" shutdown**입니다. 첫 번째 방법은 **processes**가 평소처럼 종료되고 **filesystem**이 **synchronized**되도록 하지만, 동시에 **malware**가 증거를 **파괴**할 가능성도 열어둡니다. "pull the plug" 방식은 **일부 정보 손실**이 발생할 수 있지만(이미 memory의 image를 떠 두었기 때문에 많은 정보가 사라지지는 않습니다) **malware가 아무런 조치도 취할 기회가 없습니다**. 따라서 **malware**가 있을 수 있다고 **의심**된다면, 시스템에서 **`sync`** **command**를 실행한 뒤 전원을 뽑으십시오.

#### Taking an image of the disk

**중요한 점은, case와 관련된 어떤 것에든 컴퓨터를 연결하기 전에**, 어떤 정보도 수정되지 않도록 반드시 **read only**로 **mounted**될 것인지 확인해야 한다는 것입니다.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Image 사전 분석

더 이상의 데이터 없이 디스크 이미지를 이미징하는 것.
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

Linux는 시스템 구성 요소의 무결성을 보장하는 도구를 제공하며, 이는 잠재적으로 문제가 있는 파일을 찾는 데 중요합니다.

- **RedHat 기반 시스템**: `rpm -Va`를 사용해 포괄적으로 검사합니다.
- **Debian 기반 시스템**: 먼저 `dpkg --verify`로 검증하고, 이어서 `debsums | grep -v "OK$"`를 실행해(`apt-get install debsums`로 `debsums` 설치 후) 문제를 식별합니다.

### Malware/Rootkit 탐지기

악성코드를 찾는 데 유용한 도구를 알아보려면 다음 페이지를 읽어보세요:


{{#ref}}
malware-analysis.md
{{#endref}}

## 설치된 프로그램 검색

Debian 및 RedHat 시스템 모두에서 설치된 프로그램을 효과적으로 검색하려면, 일반적인 디렉터리의 수동 점검과 함께 시스템 로그 및 데이터베이스를 활용하는 것이 좋습니다.

- Debian에서는 _**`/var/lib/dpkg/status`**_와 _**`/var/log/dpkg.log`**_를 확인해 패키지 설치 세부 정보를 가져오고, `grep`으로 특정 정보를 필터링합니다.
- RedHat 사용자는 `rpm -qa --root=/mntpath/var/lib/rpm`로 RPM 데이터베이스를 조회해 설치된 패키지를 나열할 수 있습니다.

패키지 관리자 외부에서 수동으로 설치된 소프트웨어를 찾으려면 _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, _**`/sbin`**_ 같은 디렉터리를 살펴보세요. 디렉터리 목록과 시스템별 명령을 함께 사용해 알려진 패키지와 연관되지 않은 실행 파일을 식별하면, 설치된 모든 프로그램을 더 잘 찾아낼 수 있습니다.
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

/tmp/exec에서 실행된 후 삭제된 프로세스가 있다고 가정해보자. 이를 추출할 수 있다
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Syscall Trace Triage with SQLite and FTS5

프로세스가 아직 실행 중이거나 lab에서 다시 실행할 수 있다면, **`strace`** 는 kernel modules나 전체 EDR telemetry 없이도 빠른 동작 추적을 제공할 수 있다. 대용량 trace의 경우, raw log를 직접 읽거나 LLM에 그대로 붙여넣지 말고: **SQLite** database에 저장한 뒤 필요한 최소 subset만 query하라.

> [!WARNING]
> `strace`를 attach하면 process timing이 바뀌고 race conditions나 다른 취약한 bug에 영향을 줄 수 있다. 가능하다면 copy/lab system에서 재현하는 것을 우선하라.

### Capture

새 process의 경우:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
실행 중인 process의 경우:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
유용한 옵션:

- `-ff`: fork/thread를 따라가며 프로세스별 출력을 유지
- `-ttt`: 타임라인 상관관계를 쉽게 하기 위한 epoch timestamps
- `-yy`: 가능할 때 file descriptors를 backing paths/sockets로 resolve
- `-s 4096`: 긴 path와 buffer arguments가 잘리지 않도록 유지

### Normalize

실용적인 schema는 syscall당 한 row, argument당 한 row입니다:
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
이렇게 하면 서로 다른 syscall 라인을 하나의 넓은 테이블로 억지로 평탄화하려는 시도를 피하고, triage 동안 join을 예측 가능하게 유지할 수 있습니다.

### Index text-heavy arguments with FTS5

`LIKE "%...%"`를 사용한 단순한 경로 탐색은 대규모 trace에서 매우 느려집니다. 대신 argument text에 FTS5 index를 만들고 그것으로 검색하세요:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
예시: 모든 행을 스캔하지 않고 `/tmp` 아래의 파일 activity를 recover하려면:
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

- **PATH hijacking / fake sudo**: `~/.local/bin/` 아래의 쓰기 및 `chmod`/`rename` 활동을 찾은 뒤, 그 뒤에 `sudo` 같은 권한이 있어 보이는 이름에 대한 `execve`와 상관관계를 확인하세요.
- **TOCTOU on temporary files**: 같은 `/tmp/...` 경로를 `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink`, `execve` 전반에 걸쳐 추적해 check/use 간극을 식별하세요.
- **Crash root cause**: 다른 프로세스가 같은 inode/path에 대해 `mmap`된 파일을 `write`하거나 `truncate`한 것과 상관관계를 확인한 뒤, `SIGBUS`를 위한 signal/exit sequence를 점검하세요.
- **Network destination recovery**: `connect`, `sendto`, `sendmsg`, `recvfrom`, 그리고 socket 관련 인자를 필터링해 peer IP와 port를 추출하세요.

### LLM-assisted trace analysis

LLM의 도움을 받고 싶다면, **read-only** SQLite handle을 노출하고 전체 schema를 제공하세요. database를 좁은 helper functions 뒤에 감싸는 대신 raw SQL을 실행하게 하세요. 이렇게 하면 보통 joins, temporal correlation, FTS lookups에 더 잘 작동합니다.

Practical rules:

- 예를 들어 `sqlite3 'file:trace.db?mode=ro'`로 database를 read-only로 유지하세요.
- 모델에 유효한 `JOIN` 및 `FTS5 MATCH` query 예시를 제공하세요.
- `strace` raw multi-GB 로그를 prompt에 그대로 붙여 넣지 마세요.
- 다음과 같이 집중된 질문을 하세요:
- "이 program이 쓴 persistent files를 나열하세요."
- "user-controlled PATH directories에 executables를 생성하거나 교체했나요?"
- "이 trace가 왜 SIGBUS로 끝나는지 설명하세요."

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
#### Hunt: Cron/Anacron abuse via 0anacron and suspicious stubs
공격자들은 주기적 실행을 보장하기 위해 각 /etc/cron.*/ 디렉터리 아래에 있는 0anacron stub를 종종 수정합니다.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH hardening rollback and backdoor shells
sshd_config와 시스템 계정 shell 변경은 접근을 유지하기 위한 post-exploitation 이후의 흔한 작업입니다.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API 비콘은 일반적으로 HTTPS로 api.dropboxapi.com 또는 content.dropboxapi.com을 사용하며 Authorization: Bearer 토큰을 포함한다.
- proxy/Zeek/NetFlow에서 서버로부터의 예상치 못한 Dropbox egress를 탐지하라.
- Cloudflare Tunnel (`cloudflared`)은 outbound 443을 통한 backup C2를 제공한다.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

악성코드가 서비스로 설치될 수 있는 경로:

- **/etc/inittab**: rc.sysinit 같은 초기화 스크립트를 호출하고, 이를 통해 추가 시작 스크립트로 연결한다.
- **/etc/rc.d/** 및 **/etc/rc.boot/**: 서비스 시작용 스크립트를 포함하며, 후자는 오래된 Linux 버전에서 발견된다.
- **/etc/init.d/**: Debian 같은 특정 Linux 버전에서 시작 스크립트를 저장하는 데 사용된다.
- 서비스는 Linux 변종에 따라 **/etc/inetd.conf** 또는 **/etc/xinetd/**를 통해서도 활성화될 수 있다.
- **/etc/systemd/system**: 시스템 및 서비스 관리자 스크립트를 위한 디렉터리.
- **/etc/systemd/system/multi-user.target.wants/**: multi-user runlevel에서 시작되어야 하는 서비스로의 링크를 포함한다.
- **/usr/local/etc/rc.d/**: 사용자 정의 또는 서드파티 서비스용.
- **\~/.config/autostart/**: 사용자별 자동 시작 애플리케이션용이며, 사용자 대상 악성코드의 은닉처가 될 수 있다.
- **/lib/systemd/system/**: 설치된 패키지가 제공하는 시스템 전역 기본 unit 파일.

#### Hunt: systemd timers and transient units

Systemd persistence는 `.service` 파일에만 제한되지 않는다. `.timer` units, user-level units, 그리고 런타임에 생성되는 **transient units**를 조사하라.
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
Transient units는 `/run/systemd/transient/`가 **non-persistent**이기 때문에 쉽게 놓칠 수 있습니다. live image를 수집 중이라면 shutdown 전에 확보하세요.

### Kernel Modules

Linux kernel modules는 종종 malware에 의해 rootkit 구성 요소로 사용되며, system boot 시 로드됩니다. 이러한 modules에 중요한 directories와 files는 다음과 같습니다:

- **/lib/modules/$(uname -r)**: 현재 kernel version에 대한 modules를 보관합니다.
- **/etc/modprobe.d**: module loading을 제어하는 configuration files를 포함합니다.
- **/etc/modprobe** 및 **/etc/modprobe.conf**: 전역 module settings용 files입니다.

### Other Autostart Locations

Linux는 user login 시 programs를 자동 실행하기 위해 다양한 files를 사용하며, malware가 숨어 있을 수 있습니다:

- **/etc/profile.d/**\*, **/etc/profile**, and **/etc/bash.bashrc**: 어떤 user login에서도 실행됩니다.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, and **\~/.config/autostart**: login 시 실행되는 user-specific files입니다.
- **/etc/rc.local**: 모든 system services가 시작된 후 실행되며, multiuser environment로의 전환이 끝났음을 나타냅니다.

## Examine Logs

Linux systems는 다양한 log files를 통해 user activities와 system events를 추적합니다. 이러한 logs는 unauthorized access, malware infections, 그리고 기타 security incidents를 식별하는 데 매우 중요합니다. 주요 log files는 다음과 같습니다:

- **/var/log/syslog** (Debian) 또는 **/var/log/messages** (RedHat): system-wide messages와 activities를 캡처합니다.
- **/var/log/auth.log** (Debian) 또는 **/var/log/secure** (RedHat): authentication attempts, 성공 및 실패한 logins를 기록합니다.
- `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`를 사용해 관련 authentication events를 필터링하세요.
- **/var/log/boot.log**: system startup messages를 포함합니다.
- **/var/log/maillog** 또는 **/var/log/mail.log**: email server activities를 기록하며, email-related services 추적에 유용합니다.
- **/var/log/kern.log**: errors와 warnings를 포함한 kernel messages를 저장합니다.
- **/var/log/dmesg**: device driver messages를 보관합니다.
- **/var/log/faillog**: failed login attempts를 기록하여 security breach investigations에 도움을 줍니다.
- **/var/log/cron**: cron job executions를 기록합니다.
- **/var/log/daemon.log**: background service activities를 추적합니다.
- **/var/log/btmp**: failed login attempts를 문서화합니다.
- **/var/log/httpd/**: Apache HTTPD error 및 access logs를 포함합니다.
- **/var/log/mysqld.log** 또는 **/var/log/mysql.log**: MySQL database activities를 기록합니다.
- **/var/log/xferlog**: FTP file transfers를 기록합니다.
- **/var/log/**: 여기서 unexpected logs가 있는지 항상 확인하세요.

> [!TIP]
> Linux system logs와 audit subsystems는 intrusion 또는 malware incident에서 비활성화되거나 삭제될 수 있습니다. Linux systems의 logs에는 악성 활동에 대한 매우 유용한 정보가 보통 많이 들어 있으므로, intruders는 이를 일상적으로 삭제합니다. 따라서 사용 가능한 log files를 조사할 때는 삭제나 tampering의 징후일 수 있는 gaps나 순서가 어긋난 entries를 확인하는 것이 중요합니다.

### Journald triage (`journalctl`)

현대적인 Linux hosts에서는 **systemd journal**이 보통 **service execution**, **auth events**, **package operations**, 그리고 **kernel/user-space messages**에 대한 가장 가치 있는 source입니다. live response 중에는 **persistent** journal(`/var/log/journal/`)과 **runtime** journal(`/run/log/journal/`) 둘 다 보존하려고 하세요. short-lived attacker activity는 후자에만 존재할 수 있습니다.
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
triage에 유용한 journal 필드는 `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, 그리고 `MESSAGE`이다. journald가 persistent storage 없이 구성되었다면 `/run/log/journal/` 아래에 최근 데이터만 존재할 것으로 예상하라.

### Audit framework triage (`auditd`)

`auditd`가 활성화되어 있다면, 파일 변경, command execution, login activity, 또는 package installation에 대한 **process attribution**이 필요할 때는 항상 이를 우선 사용하라.
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
키가 포함된 규칙이 배포되었다면, 원시 로그를 grep하는 대신 그 규칙에서 pivot하세요:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux는 각 사용자별로 명령 기록을 유지하며**, 다음 위치에 저장됩니다:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

또한, `last -Faiwx` 명령은 사용자 로그인 목록을 제공합니다. 알 수 없거나 예상치 못한 로그인이 있는지 확인하세요.

추가 rprivileges를 부여할 수 있는 파일을 확인하세요:

- 예상치 못한 사용자 권한이 부여되었는지 `/etc/sudoers`를 검토합니다.
- 예상치 못한 사용자 권한이 부여되었는지 `/etc/sudoers.d/`를 검토합니다.
- 비정상적인 그룹 멤버십이나 권한을 식별하기 위해 `/etc/groups`를 검사합니다.
- 비정상적인 그룹 멤버십이나 권한을 식별하기 위해 `/etc/passwd`를 검사합니다.

일부 앱은 자체 로그도 생성합니다:

- **SSH**: 승인되지 않은 원격 연결이 있는지 _\~/.ssh/authorized_keys_ 및 _\~/.ssh/known_hosts_를 검사합니다.
- **Gnome Desktop**: Gnome 애플리케이션을 통해 최근에 접근한 파일이 있는지 _\~/.recently-used.xbel_를 확인합니다.
- **Firefox/Chrome**: 의심스러운 활동이 있는지 브라우저 기록과 다운로드를 _\~/.mozilla/firefox_ 또는 _\~/.config/google-chrome_에서 확인합니다.
- **VIM**: 접근한 파일 경로와 검색 기록 같은 사용 상세 정보를 위해 _\~/.viminfo_를 검토합니다.
- **Open Office**: 손상되었을 수 있는 파일을 나타낼 수 있는 최근 문서 접근을 확인합니다.
- **FTP/SFTP**: 무단일 수 있는 파일 전송이 있었는지 _\~/.ftp_history_ 또는 _\~/.sftp_history_의 로그를 검토합니다.
- **MySQL**: 실행된 MySQL 쿼리를 위해 _\~/.mysql_history_를 조사하여, 무단 데이터베이스 활동이 드러날 수 있는지 확인합니다.
- **Less**: 열람한 파일과 실행된 명령을 포함한 사용 기록을 위해 _\~/.lesshst_를 분석합니다.
- **Git**: 저장소 변경 사항을 위해 _\~/.gitconfig_와 프로젝트 _.git/logs_를 검사합니다.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) is a small piece of software written in pure Python 3 which parses Linux log files (`/var/log/syslog*` or `/var/log/messages*` depending on the distro) for constructing USB event history tables.

사용된 모든 USB를 **알아두는 것**은 흥미롭고, 승인된 USB 목록이 있다면 그 목록에 없는 USB의 사용인 "violation events"를 찾는 데 더 유용합니다.

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Examples
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## 사용자 계정 및 로그인 활동 검토

_**/etc/passwd**_, _**/etc/shadow**_ 및 **security logs**를 검사하여 알려진 비인가 이벤트와 시간적으로 가까운 시점에 생성되었거나 사용된, 비정상적인 이름이나 계정을 찾습니다. 또한 가능한 sudo brute-force attack도 확인하세요.\
추가로, 사용자에게 부여된 예상치 못한 권한이 있는지 _**/etc/sudoers**_ 및 _**/etc/groups**_ 같은 파일을 확인합니다.\
마지막으로, **password가 없거나** **쉽게 추측 가능한** password를 가진 계정을 찾아보세요.

## 파일 시스템 검사

### Malware Investigation에서 파일 시스템 구조 분석

Malware incident를 조사할 때 파일 시스템 구조는 중요한 정보원으로, 사건의 순서와 malware의 내용을 드러냅니다. 그러나 malware 작성자들은 파일 타임스탬프를 수정하거나 데이터 저장에 file system을 사용하지 않는 등의 방법으로 이러한 분석을 방해하는 기법을 개발하고 있습니다.

이러한 anti-forensic 방법에 대응하려면 다음이 중요합니다:

- **Autopsy** 같은 도구로 이벤트 timeline을 시각화하거나 **Sleuth Kit's** `mactime`으로 상세한 timeline 데이터를 확인해 **철저한 timeline 분석을 수행**합니다.
- 시스템의 $PATH 안에 있는 **예상치 못한 scripts**를 조사합니다. 여기에는 공격자가 사용한 shell 또는 PHP scripts가 포함될 수 있습니다.
- 전통적으로 special files를 담는 **`/dev`의 비정상적인 파일을 검사**하지만, malware 관련 파일이 있을 수도 있습니다.
- ".. " (dot dot space) 또는 "..^G" (dot dot control-G) 같은 이름의 **숨겨진 파일이나 디렉터리**를 검색하여 악성 콘텐츠를 숨겼는지 확인합니다.
- 명령어 `find / -user root -perm -04000 -print`를 사용하여 **setuid root files**를 식별합니다. 이 명령은 공격자들이 악용할 수 있는 상승된 권한을 가진 파일을 찾습니다.
- inode table의 **삭제 타임스탬프**를 검토하여 대량 파일 삭제를 찾아냅니다. 이는 rootkits 또는 trojans의 존재를 시사할 수 있습니다.
- 하나를 찾은 뒤 **연속된 inode**를 검사하여 근처의 악성 파일을 확인합니다. 함께 배치되었을 수 있기 때문입니다.
- 최근 수정된 파일이 있는지 **일반적인 binary 디렉터리**(_/bin_, _/sbin_)를 확인합니다. 이는 malware에 의해 변경되었을 수 있습니다.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> **공격자**는 **시간**을 **수정**하여 **파일이 보이게** **합법적으로** 만들 수 있지만, **inode**는 **수정**할 수 없습니다. 만약 어떤 **파일**이 같은 폴더의 다른 파일들과 **같은 시간**에 생성되고 수정된 것으로 표시되는데도 **inode**가 **예상보다 더 크다**면, 그 **파일의 타임스탬프가 수정된 것**입니다.

### Inode-focused quick triage

anti-forensics가 의심되면, 초기에 다음 inode-focused 점검을 수행하세요:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
EXT filesystem 이미지/디바이스에서 의심스러운 inode가 발견되면, inode 메타데이터를 직접 확인하세요:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
유용한 필드:
- **Links**: `0`이면 현재 어떤 디렉터리 항목도 inode를 참조하지 않음.
- **dtime**: inode가 unlink될 때 설정되는 삭제 타임스탬프.
- **ctime/mtime**: 메타데이터/콘텐츠 변경을 incident timeline과 대조하는 데 도움.

### Capabilities, xattrs, and preload-based userland rootkits

현대 Linux persistence는 흔한 `setuid` 바이너리를 피하고 대신 **file capabilities**, **extended attributes**, 그리고 dynamic loader를 악용하는 경우가 많다.
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
특히 `/tmp`, `/dev/shm`, `/var/tmp` 같은 **writable** 경로나 `/usr/local/lib` 아래의 이상한 위치에서 참조되는 libraries에 주의하세요. 또한 정상적인 package ownership 밖에 있는 capability-bearing binaries를 확인하고, package verification 결과(`rpm -Va`, `dpkg --verify`, `debsums`)와 대조하세요.

## 서로 다른 filesystem versions의 파일 비교

### Filesystem Version Comparison Summary

filesystem versions를 비교하고 변경 사항을 정확히 찾아내려면, 단순화된 `git diff` commands를 사용합니다:

- **새 파일을 찾으려면**, 두 디렉터리를 비교합니다:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **수정된 content의 경우**, 특정 lines는 무시하고 변경 사항을 나열하세요:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **삭제된 파일을 탐지하려면**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`)은 추가된 (`A`), 삭제된 (`D`), 또는 수정된 (`M`) 파일처럼 특정 변경 사항으로 범위를 좁히는 데 도움이 됩니다.
- `A`: 추가된 파일
- `C`: 복사된 파일
- `D`: 삭제된 파일
- `M`: 수정된 파일
- `R`: 이름이 변경된 파일
- `T`: 유형 변경(예: file to symlink)
- `U`: 병합되지 않은 파일
- `X`: 알 수 없는 파일
- `B`: 손상된 파일

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
