# 사용자 네임스페이스

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## 참조

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## 기본 정보

사용자 네임스페이스는 Linux 커널 기능으로, **사용자 및 그룹 ID 매핑의 격리를 제공합니다**, 각 사용자 네임스페이스가 **자신만의 사용자 및 그룹 ID 세트**를 가질 수 있게 합니다. 이 격리는 서로 다른 사용자 네임스페이스에서 실행되는 프로세스들이 수치적으로 동일한 사용자 및 그룹 ID를 공유하더라도 **서로 다른 권한과 소유권을 가질 수 있게** 합니다.

사용자 네임스페이스는 특히 컨테이너화에서 유용합니다. 각 컨테이너가 자체적인 독립적인 사용자 및 그룹 ID 세트를 가져야 하며, 이를 통해 컨테이너와 호스트 시스템 간의 보안 및 격리를 향상시킵니다.

### 동작 방식:

1. 새로운 사용자 네임스페이스가 생성되면 **빈 사용자 및 그룹 ID 매핑 집합으로 시작합니다**. 이는 새 네임스페이스에서 실행되는 어떤 프로세스도 **초기에는 네임스페이스 외부에서 권한이 없음을** 의미합니다.
2. ID 매핑은 새 네임스페이스의 사용자 및 그룹 ID와 부모(또는 호스트) 네임스페이스의 ID 사이에 설정될 수 있습니다. 이렇게 하면 **새 네임스페이스의 프로세스가 부모 네임스페이스의 사용자 및 그룹 ID에 해당하는 권한 및 소유권을 가질 수 있습니다**. 다만, ID 매핑은 특정 범위나 ID의 부분집합으로 제한될 수 있어 새 네임스페이스의 프로세스에 부여되는 권한을 세밀하게 제어할 수 있습니다.
3. 사용자 네임스페이스 내에서는 **프로세스가 네임스페이스 내부의 작업에 대해 full root privileges (UID 0)를 가질 수 있으며**, 동시에 네임스페이스 외부에서는 권한이 제한됩니다. 이를 통해 **컨테이너는 호스트 시스템에서 완전한 root 권한을 갖지 않으면서도 자체 네임스페이스 내에서 root와 유사한 기능으로 실행될 수 있습니다**.
4. 프로세스는 `setns()` system call을 사용해 네임스페이스 간 이동하거나 `unshare()` 또는 `clone()` system call을 `CLONE_NEWUSER` 플래그와 함께 사용해 새 네임스페이스를 생성할 수 있습니다. 프로세스가 새 네임스페이스로 이동하거나 생성하면 해당 네임스페이스에 연결된 사용자 및 그룹 ID 매핑을 사용하기 시작합니다.

## 실습:

### 서로 다른 네임스페이스 생성

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
파라미터 `--mount-proc`를 사용해 `/proc` 파일시스템의 새 인스턴스를 마운트하면, 새로운 마운트 네임스페이스가 해당 네임스페이스에 특화된 프로세스 정보를 **정확하고 격리된 관점**으로 보도록 보장합니다.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **문제 설명**:

- Linux 커널은 `unshare` 시스템 호출을 사용해 프로세스가 새로운 네임스페이스를 생성할 수 있도록 허용합니다. 그러나 새로운 PID 네임스페이스 생성의 시작 프로세스(일명 "unshare" 프로세스)는 새 네임스페이스로 들어가지 않으며, 그 자식 프로세스들만 들어갑니다.
- Running `%unshare -p /bin/bash%`는 `unshare`와 동일한 프로세스에서 `/bin/bash`를 시작합니다. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- `/bin/bash`의 새 네임스페이스에서의 첫 번째 자식 프로세스는 PID 1이 됩니다. 이 프로세스가 종료되면, PID 1은 고아 프로세스를 인수하는 특별한 역할을 하기 때문에 다른 프로세스가 없다면 네임스페이스 정리를 촉발합니다. 그 결과 Linux 커널은 해당 네임스페이스에서 PID 할당을 비활성화합니다.

2. **결과**:

- 새 네임스페이스에서 PID 1의 종료는 `PIDNS_HASH_ADDING` 플래그의 정리를 초래합니다. 이로 인해 `alloc_pid` 함수가 새로운 프로세스를 생성할 때 새로운 PID를 할당하지 못해 "Cannot allocate memory" 오류를 발생시킵니다.

3. **해결책**:
- 이 문제는 `unshare`에 `-f` 옵션을 사용하여 해결할 수 있습니다. 이 옵션은 새로운 PID 네임스페이스를 만든 후 `unshare`가 새 프로세스를 fork하도록 만듭니다.
- `%unshare -fp /bin/bash%`를 실행하면 `unshare` 명령 자체가 새 네임스페이스에서 PID 1이 되도록 보장합니다. 그러면 `/bin/bash`와 그 자식 프로세스들은 이 새 네임스페이스 내에 안전하게 수용되어 PID 1의 조기 종료를 방지하고 정상적인 PID 할당을 허용합니다.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
To use user namespace, Docker daemon needs to started with **`--userns-remap=default`**(In ubuntu 14.04, this can be done by modifying `/etc/default/docker` and then executing `sudo service docker restart`)

### 프로세스가 어느 네임스페이스에 있는지 확인하기
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
docker 컨테이너에서 user map을 다음 명령으로 확인할 수 있습니다:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
또는 호스트에서 다음과 같이:
```bash
cat /proc/<pid>/uid_map
```
### 모든 User namespaces 찾기
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### User namespace 안으로 들어가기
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
또한, **다른 프로세스 네임스페이스로 들어갈 수 있는 것은 root인 경우뿐입니다**. 그리고 **해당 네임스페이스를 가리키는 디스크립터 없이** 다른 네임스페이스에 **들어갈 수 없습니다** (예: `/proc/self/ns/user`).

### 새 사용자 네임스페이스 생성 (매핑 포함)
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
### 비특권 UID/GID 매핑 규칙

`uid_map`/`gid_map`에 쓰는 프로세스가 부모 user namespace에 **CAP_SETUID/CAP_SETGID를 가지고 있지 않은 경우**, 커널은 더 엄격한 규칙을 적용합니다: 호출자의 유효 UID/GID에 대해 오직 **하나의 매핑만** 허용되며, `gid_map`의 경우 `/proc/<pid>/setgroups`에 `deny`를 써서 **먼저 `setgroups(2)`를 비활성화해야 합니다**.
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### ID-mapped Mounts (MOUNT_ATTR_IDMAP)

ID-mapped mounts **마운트에 user namespace 매핑을 연결하여**, 해당 마운트를 통해 접근할 때 파일 소유권이 재매핑됩니다. 이는 container runtimes(특히 rootless)에서 **재귀적인 `chown` 없이 host 경로를 공유하면서도** user namespace의 UID/GID 변환을 적용하기 위해 자주 사용됩니다.

공격적 관점에서, **만약 mount namespace를 생성하고 당신의 user namespace 안에서 `CAP_SYS_ADMIN`을 보유할 수 있고**, 파일시스템이 ID-mapped mounts를 지원한다면, bind mounts의 소유권 *뷰*를 재매핑할 수 있습니다. 이것은 디스크 상의 실제 소유권을 변경하지는 않지만, 그렇지 않으면 쓰기 불가능한 파일이 네임스페이스 내에서 당신의 매핑된 UID/GID 소유로 보이게 만들 수 있습니다.

### Recovering Capabilities

user namespace의 경우, **새 user namespace가 생성되면 그 네임스페이스로 들어가는 프로세스는 그 네임스페이스 내에서 전체 set의 capabilities를 부여받습니다**. 이러한 capabilities는 프로세스가 **mounting** **filesystems**, 장치 생성, 파일 소유권 변경과 같은 특권 작업을 수행할 수 있게 하지만, 오직 그 user namespace의 컨텍스트 내에서만 유효합니다.

예를 들어, user namespace 내에서 `CAP_SYS_ADMIN` capability를 가지고 있다면, 일반적으로 이 capability를 필요로 하는 작업들(예: filesystems 마운트)을 수행할 수 있지만, 이는 오직 당신의 user namespace 컨텍스트 내에서만 적용됩니다. 이 capability로 수행하는 작업들은 호스트 시스템이나 다른 네임스페이스에 영향을 주지 않습니다.

> [!WARNING]
> 따라서, 새 User namespace 안으로 새로운 프로세스를 넣는 것이 모든 capabilities를 되돌려주는 것처럼 보일지라도 (CapEff: 000001ffffffffff), 실제로는 네임스페이스와 관련된 권한(예: mount)만 사용할 수 있고 모든 권한을 사용할 수 있는 것은 아닙니다. 그러므로 이것만으로는 Docker 컨테이너에서 탈출하기에 충분하지 않습니다.
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
{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## 참고자료

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}
