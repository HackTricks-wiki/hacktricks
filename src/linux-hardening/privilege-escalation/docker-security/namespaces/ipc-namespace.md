# IPC Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## 기본 정보

IPC (Inter-Process Communication) 네임스페이스는 메시지 큐, 공유 메모리 세그먼트 및 세마포와 같은 System V IPC 객체의 **격리**를 제공하는 Linux 커널 기능입니다. 이 격리는 **다른 IPC 네임스페이스에 있는 프로세스가 서로의 IPC 객체에 직접 접근하거나 수정할 수 없도록** 하여 프로세스 그룹 간에 추가적인 보안 및 프라이버시 계층을 제공합니다.

### 작동 방식:

1. 새로운 IPC 네임스페이스가 생성되면, **완전히 격리된 System V IPC 객체 세트**로 시작합니다. 이는 새로운 IPC 네임스페이스에서 실행되는 프로세스가 기본적으로 다른 네임스페이스나 호스트 시스템의 IPC 객체에 접근하거나 간섭할 수 없음을 의미합니다.
2. 네임스페이스 내에서 생성된 IPC 객체는 **해당 네임스페이스 내의 프로세스만 볼 수 있고 접근할 수 있습니다**. 각 IPC 객체는 해당 네임스페이스 내에서 고유한 키로 식별됩니다. 키는 다른 네임스페이스에서 동일할 수 있지만, 객체 자체는 격리되어 있으며 네임스페이스 간에 접근할 수 없습니다.
3. 프로세스는 `setns()` 시스템 호출을 사용하여 네임스페이스 간에 이동하거나 `unshare()` 또는 `clone()` 시스템 호출을 사용하여 `CLONE_NEWIPC` 플래그와 함께 새로운 네임스페이스를 생성할 수 있습니다. 프로세스가 새로운 네임스페이스로 이동하거나 생성할 때, 해당 네임스페이스와 연결된 IPC 객체를 사용하기 시작합니다.

## 실습:

### 다양한 네임스페이스 생성

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
새로운 인스턴스의 `/proc` 파일 시스템을 마운트하면 `--mount-proc` 매개변수를 사용하여 새로운 마운트 네임스페이스가 **해당 네임스페이스에 특정한 프로세스 정보에 대한 정확하고 격리된 뷰를 갖도록** 보장합니다.

<details>

<summary>오류: bash: fork: 메모리를 할당할 수 없습니다</summary>

`unshare`가 `-f` 옵션 없이 실행될 때, Linux가 새로운 PID(프로세스 ID) 네임스페이스를 처리하는 방식 때문에 오류가 발생합니다. 주요 세부사항과 해결책은 아래에 설명되어 있습니다:

1. **문제 설명**:

- Linux 커널은 프로세스가 `unshare` 시스템 호출을 사용하여 새로운 네임스페이스를 생성할 수 있도록 허용합니다. 그러나 새로운 PID 네임스페이스를 생성하는 프로세스(이를 "unshare" 프로세스라고 함)는 새로운 네임스페이스에 들어가지 않으며, 오직 그 자식 프로세스만 들어갑니다.
- `%unshare -p /bin/bash%`를 실행하면 `/bin/bash`가 `unshare`와 동일한 프로세스에서 시작됩니다. 결과적으로 `/bin/bash`와 그 자식 프로세스는 원래 PID 네임스페이스에 있습니다.
- 새로운 네임스페이스에서 `/bin/bash`의 첫 번째 자식 프로세스는 PID 1이 됩니다. 이 프로세스가 종료되면, 다른 프로세스가 없을 경우 네임스페이스의 정리가 트리거됩니다. PID 1은 고아 프로세스를 입양하는 특별한 역할을 가지고 있습니다. 그러면 Linux 커널은 해당 네임스페이스에서 PID 할당을 비활성화합니다.

2. **결과**:

- 새로운 네임스페이스에서 PID 1의 종료는 `PIDNS_HASH_ADDING` 플래그의 정리를 초래합니다. 이로 인해 새로운 프로세스를 생성할 때 `alloc_pid` 함수가 새로운 PID를 할당하지 못하게 되어 "메모리를 할당할 수 없습니다" 오류가 발생합니다.

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
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### 모든 IPC 네임스페이스 찾기
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### IPC 네임스페이스에 들어가기
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
또한, **루트 사용자**인 경우에만 **다른 프로세스 네임스페이스에 들어갈 수 있습니다**. 그리고 **디스크립터**가 없으면 **다른 네임스페이스에 들어갈 수 없습니다** (예: `/proc/self/ns/net`).

### IPC 객체 생성
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
