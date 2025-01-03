# User Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

사용자 네임스페이스는 **사용자 및 그룹 ID 매핑의 격리를 제공하는** 리눅스 커널 기능으로, 각 사용자 네임스페이스가 **자신만의 사용자 및 그룹 ID 세트를 가질 수 있도록** 합니다. 이 격리는 서로 다른 사용자 네임스페이스에서 실행되는 프로세스가 **숫자적으로 동일한 사용자 및 그룹 ID를 공유하더라도 서로 다른 권한과 소유권을 가질 수 있게** 합니다.

사용자 네임스페이스는 특히 컨테이너화에서 유용하며, 각 컨테이너는 독립적인 사용자 및 그룹 ID 세트를 가져야 하므로 컨테이너와 호스트 시스템 간의 보안 및 격리를 개선할 수 있습니다.

### How it works:

1. 새로운 사용자 네임스페이스가 생성되면, **빈 사용자 및 그룹 ID 매핑 세트로 시작합니다**. 이는 새로운 사용자 네임스페이스에서 실행되는 모든 프로세스가 **초기에는 네임스페이스 외부에서 권한이 없음을 의미합니다**.
2. ID 매핑은 새로운 네임스페이스의 사용자 및 그룹 ID와 부모(또는 호스트) 네임스페이스의 ID 간에 설정될 수 있습니다. 이는 **새로운 네임스페이스의 프로세스가 부모 네임스페이스의 사용자 및 그룹 ID에 해당하는 권한과 소유권을 가질 수 있게** 합니다. 그러나 ID 매핑은 특정 범위와 ID의 하위 집합으로 제한될 수 있어, 새로운 네임스페이스의 프로세스에 부여된 권한을 세밀하게 제어할 수 있습니다.
3. 사용자 네임스페이스 내에서, **프로세스는 네임스페이스 내에서의 작업에 대해 전체 루트 권한(UID 0)을 가질 수 있으며**, 여전히 네임스페이스 외부에서는 제한된 권한을 가집니다. 이는 **컨테이너가 호스트 시스템에서 전체 루트 권한을 가지지 않고도 자신의 네임스페이스 내에서 루트와 유사한 기능을 수행할 수 있게** 합니다.
4. 프로세스는 `setns()` 시스템 호출을 사용하여 네임스페이스 간에 이동하거나, `unshare()` 또는 `clone()` 시스템 호출을 사용하여 `CLONE_NEWUSER` 플래그와 함께 새로운 네임스페이스를 생성할 수 있습니다. 프로세스가 새로운 네임스페이스로 이동하거나 생성할 때, 해당 네임스페이스와 연결된 사용자 및 그룹 ID 매핑을 사용하기 시작합니다.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
`--mount-proc` 매개변수를 사용하여 `/proc` 파일 시스템의 새 인스턴스를 마운트하면, 새 마운트 네임스페이스가 **해당 네임스페이스에 특정한 프로세스 정보에 대한 정확하고 격리된 뷰를 갖도록** 보장합니다.

<details>

<summary>오류: bash: fork: 메모리를 할당할 수 없습니다</summary>

`unshare`가 `-f` 옵션 없이 실행될 때, Linux가 새로운 PID(프로세스 ID) 네임스페이스를 처리하는 방식 때문에 오류가 발생합니다. 주요 세부사항과 해결책은 아래에 설명되어 있습니다:

1. **문제 설명**:

- Linux 커널은 프로세스가 `unshare` 시스템 호출을 사용하여 새로운 네임스페이스를 생성할 수 있도록 허용합니다. 그러나 새로운 PID 네임스페이스를 생성하는 프로세스(이를 "unshare" 프로세스라고 함)는 새로운 네임스페이스에 들어가지 않으며, 오직 그 자식 프로세스만 들어갑니다.
- `%unshare -p /bin/bash%`를 실행하면 `unshare`와 동일한 프로세스에서 `/bin/bash`가 시작됩니다. 결과적으로 `/bin/bash`와 그 자식 프로세스는 원래 PID 네임스페이스에 있습니다.
- 새로운 네임스페이스에서 `/bin/bash`의 첫 번째 자식 프로세스는 PID 1이 됩니다. 이 프로세스가 종료되면, 다른 프로세스가 없을 경우 네임스페이스의 정리가 트리거됩니다. PID 1은 고아 프로세스를 입양하는 특별한 역할을 가지고 있습니다. 그러면 Linux 커널은 해당 네임스페이스에서 PID 할당을 비활성화합니다.

2. **결과**:

- 새로운 네임스페이스에서 PID 1의 종료는 `PIDNS_HASH_ADDING` 플래그의 정리를 초래합니다. 이로 인해 새로운 프로세스를 생성할 때 `alloc_pid` 함수가 새로운 PID를 할당하지 못하게 되어 "메모리를 할당할 수 없습니다" 오류가 발생합니다.

3. **해결책**:
- 이 문제는 `unshare`와 함께 `-f` 옵션을 사용하여 해결할 수 있습니다. 이 옵션은 `unshare`가 새로운 PID 네임스페이스를 생성한 후 새로운 프로세스를 포크하도록 만듭니다.
- `%unshare -fp /bin/bash%`를 실행하면 `unshare` 명령 자체가 새로운 네임스페이스에서 PID 1이 됩니다. 그 결과 `/bin/bash`와 그 자식 프로세스는 이 새로운 네임스페이스 내에서 안전하게 포함되어 PID 1의 조기 종료를 방지하고 정상적인 PID 할당을 허용합니다.

`unshare`가 `-f` 플래그와 함께 실행되도록 보장함으로써, 새로운 PID 네임스페이스가 올바르게 유지되어 `/bin/bash`와 그 하위 프로세스가 메모리 할당 오류 없이 작동할 수 있습니다.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
사용자 네임스페이스를 사용하려면 Docker 데몬을 **`--userns-remap=default`**로 시작해야 합니다(우분투 14.04에서는 `/etc/default/docker`를 수정한 후 `sudo service docker restart`를 실행하여 이 작업을 수행할 수 있습니다).

### &#x20;프로세스가 어떤 네임스페이스에 있는지 확인하기
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
docker 컨테이너에서 사용자 맵을 확인하는 것은 다음과 같이 가능합니다:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
호스트에서 다음과 같이:
```bash
cat /proc/<pid>/uid_map
```
### 모든 사용자 네임스페이스 찾기
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### 사용자 네임스페이스에 들어가기
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
또한, **루트일 경우에만 다른 프로세스 네임스페이스에 들어갈 수 있습니다**. 그리고 **디스크립터**가 없으면 **다른 네임스페이스에 들어갈 수 없습니다** (예: `/proc/self/ns/user`).

### 새로운 사용자 네임스페이스 생성 (매핑 포함)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Recovering Capabilities

사용자 네임스페이스의 경우, **새로운 사용자 네임스페이스가 생성되면, 해당 네임스페이스에 들어가는 프로세스는 그 네임스페이스 내에서 전체 권한 세트를 부여받습니다**. 이러한 권한은 프로세스가 **파일 시스템을 마운트**하거나, 장치를 생성하거나, 파일의 소유권을 변경하는 등의 특권 작업을 수행할 수 있게 해주지만, **오직 자신의 사용자 네임스페이스의 맥락 내에서만** 가능합니다.

예를 들어, 사용자 네임스페이스 내에서 `CAP_SYS_ADMIN` 권한을 가지고 있을 때, 파일 시스템을 마운트하는 것과 같이 일반적으로 이 권한이 필요한 작업을 수행할 수 있지만, 오직 자신의 사용자 네임스페이스의 맥락 내에서만 가능합니다. 이 권한으로 수행하는 모든 작업은 호스트 시스템이나 다른 네임스페이스에 영향을 미치지 않습니다.

> [!WARNING]
> 따라서, 새로운 사용자 네임스페이스 내에 새로운 프로세스를 생성하는 것이 **모든 권한을 다시 부여받게 할 것입니다** (CapEff: 000001ffffffffff), 실제로는 **네임스페이스와 관련된 권한만 사용할 수 있습니다** (예: 마운트) 하지만 모든 권한을 사용할 수는 없습니다. 따라서, 이것만으로는 Docker 컨테이너에서 탈출하기에 충분하지 않습니다.
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#include ../../../../banners/hacktricks-training.md}}
