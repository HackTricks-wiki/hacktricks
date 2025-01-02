# Mount Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

마운트 네임스페이스는 프로세스 그룹이 보는 파일 시스템 마운트 지점의 격리를 제공하는 리눅스 커널 기능입니다. 각 마운트 네임스페이스는 고유한 파일 시스템 마운트 지점 집합을 가지며, **하나의 네임스페이스에서 마운트 지점에 대한 변경 사항은 다른 네임스페이스에 영향을 미치지 않습니다**. 이는 서로 다른 마운트 네임스페이스에서 실행되는 프로세스가 파일 시스템 계층 구조에 대한 서로 다른 뷰를 가질 수 있음을 의미합니다.

마운트 네임스페이스는 각 컨테이너가 다른 컨테이너 및 호스트 시스템과 격리된 고유한 파일 시스템 및 구성을 가져야 하는 컨테이너화에서 특히 유용합니다.

### How it works:

1. 새로운 마운트 네임스페이스가 생성되면, **부모 네임스페이스의 마운트 지점 복사본으로 초기화**됩니다. 이는 생성 시 새로운 네임스페이스가 부모와 동일한 파일 시스템 뷰를 공유함을 의미합니다. 그러나 네임스페이스 내의 마운트 지점에 대한 이후의 변경 사항은 부모 또는 다른 네임스페이스에 영향을 미치지 않습니다.
2. 프로세스가 네임스페이스 내에서 마운트 지점을 수정할 때, 예를 들어 파일 시스템을 마운트하거나 언마운트할 때, **변경 사항은 해당 네임스페이스에 국한**되며 다른 네임스페이스에 영향을 미치지 않습니다. 이는 각 네임스페이스가 고유한 독립적인 파일 시스템 계층 구조를 가질 수 있게 합니다.
3. 프로세스는 `setns()` 시스템 호출을 사용하여 네임스페이스 간에 이동하거나, `unshare()` 또는 `clone()` 시스템 호출을 사용하여 `CLONE_NEWNS` 플래그로 새로운 네임스페이스를 생성할 수 있습니다. 프로세스가 새로운 네임스페이스로 이동하거나 생성할 때, 해당 네임스페이스와 연결된 마운트 지점을 사용하기 시작합니다.
4. **파일 설명자와 아이노드는 네임스페이스 간에 공유**되며, 이는 하나의 네임스페이스에 있는 프로세스가 파일을 가리키는 열린 파일 설명자를 가지고 있다면, 해당 파일 설명자를 다른 네임스페이스의 프로세스에 **전달할 수 있으며**, **두 프로세스 모두 동일한 파일에 접근**할 수 있음을 의미합니다. 그러나 파일의 경로는 마운트 지점의 차이로 인해 두 네임스페이스에서 동일하지 않을 수 있습니다.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
새로운 인스턴스의 `/proc` 파일 시스템을 마운트하면 `--mount-proc` 매개변수를 사용하여 새로운 마운트 네임스페이스가 **해당 네임스페이스에 특정한 프로세스 정보에 대한 정확하고 격리된 뷰**를 갖도록 보장합니다.

<details>

<summary>오류: bash: fork: 메모리를 할당할 수 없습니다</summary>

`unshare`가 `-f` 옵션 없이 실행될 때, Linux가 새로운 PID(프로세스 ID) 네임스페이스를 처리하는 방식 때문에 오류가 발생합니다. 주요 세부사항과 해결책은 아래에 설명되어 있습니다:

1. **문제 설명**:

- Linux 커널은 프로세스가 `unshare` 시스템 호출을 사용하여 새로운 네임스페이스를 생성할 수 있도록 허용합니다. 그러나 새로운 PID 네임스페이스를 생성하는 프로세스(이를 "unshare" 프로세스라고 함)는 새로운 네임스페이스에 들어가지 않으며, 오직 그 자식 프로세스만 들어갑니다.
- `%unshare -p /bin/bash%`를 실행하면 `/bin/bash`가 `unshare`와 동일한 프로세스에서 시작됩니다. 결과적으로 `/bin/bash`와 그 자식 프로세스는 원래 PID 네임스페이스에 있습니다.
- 새로운 네임스페이스에서 `/bin/bash`의 첫 번째 자식 프로세스는 PID 1이 됩니다. 이 프로세스가 종료되면, 다른 프로세스가 없을 경우 네임스페이스의 정리가 트리거됩니다. PID 1은 고아 프로세스를 입양하는 특별한 역할을 가지고 있습니다. 그러면 Linux 커널은 해당 네임스페이스에서 PID 할당을 비활성화합니다.

2. **결과**:

- 새로운 네임스페이스에서 PID 1의 종료는 `PIDNS_HASH_ADDING` 플래그의 정리를 초래합니다. 이로 인해 새로운 프로세스를 생성할 때 `alloc_pid` 함수가 새로운 PID를 할당하는 데 실패하여 "메모리를 할당할 수 없습니다" 오류가 발생합니다.

3. **해결책**:
- 이 문제는 `unshare`와 함께 `-f` 옵션을 사용하여 해결할 수 있습니다. 이 옵션은 `unshare`가 새로운 PID 네임스페이스를 생성한 후 새로운 프로세스를 포크하도록 만듭니다.
- `%unshare -fp /bin/bash%`를 실행하면 `unshare` 명령 자체가 새로운 네임스페이스에서 PID 1이 됩니다. `/bin/bash`와 그 자식 프로세스는 이 새로운 네임스페이스 내에서 안전하게 포함되어 PID 1의 조기 종료를 방지하고 정상적인 PID 할당을 허용합니다.

`unshare`가 `-f` 플래그와 함께 실행되도록 보장함으로써 새로운 PID 네임스페이스가 올바르게 유지되며, `/bin/bash`와 그 하위 프로세스가 메모리 할당 오류 없이 작동할 수 있습니다.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;프로세스가 어떤 네임스페이스에 있는지 확인하기
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### 모든 마운트 네임스페이스 찾기
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

```bash
findmnt
```
### Mount 네임스페이스 내부로 들어가기
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
또한, **루트 사용자**만 **다른 프로세스 네임스페이스에 들어갈 수 있습니다**. 그리고 **디스크립터**가 없으면 **다른 네임스페이스에 들어갈 수 없습니다** (예: `/proc/self/ns/mnt`).

새로운 마운트는 네임스페이스 내에서만 접근할 수 있기 때문에, 네임스페이스가 그 안에서만 접근할 수 있는 민감한 정보를 포함할 가능성이 있습니다.

### 무언가 마운트하기
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```

```
# findmnt # List existing mounts
TARGET                                SOURCE                                                                                                           FSTYPE     OPTIONS
/                                     /dev/mapper/web05--vg-root

# unshare --mount  # run a shell in a new mount namespace
# mount --bind /usr/bin/ /mnt/
# ls /mnt/cp
/mnt/cp
# exit  # exit the shell, and hence the mount namespace
# ls /mnt/cp
ls: cannot access '/mnt/cp': No such file or directory

## Notice there's different files in /tmp
# ls /tmp
revshell.elf

# ls /mnt/tmp
krb5cc_75401103_X5yEyy
systemd-private-3d87c249e8a84451994ad692609cd4b6-apache2.service-77w9dT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-resolved.service-RnMUhT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-timesyncd.service-FAnDql
vmware-root_662-2689143848

```
## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux](https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux)

{{#include ../../../../banners/hacktricks-training.md}}
