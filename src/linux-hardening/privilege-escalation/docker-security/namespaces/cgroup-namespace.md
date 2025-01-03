# CGroup Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

cgroup 네임스페이스는 **네임스페이스 내에서 실행되는 프로세스의 cgroup 계층을 격리하는** 리눅스 커널 기능입니다. cgroups는 **제어 그룹**의 약자로, CPU, 메모리 및 I/O와 같은 **시스템 리소스에 대한 제한을 관리하고 시행하기 위해 프로세스를 계층적 그룹으로 조직할 수 있게 해주는 커널 기능입니다.

cgroup 네임스페이스는 우리가 이전에 논의한 다른 네임스페이스 유형(PID, mount, network 등)과는 별개의 네임스페이스 유형이 아니지만, 네임스페이스 격리 개념과 관련이 있습니다. **Cgroup 네임스페이스는 cgroup 계층의 뷰를 가상화**하여, cgroup 네임스페이스 내에서 실행되는 프로세스가 호스트 또는 다른 네임스페이스에서 실행되는 프로세스와 비교하여 계층의 다른 뷰를 갖도록 합니다.

### How it works:

1. 새로운 cgroup 네임스페이스가 생성되면, **생성 프로세스의 cgroup을 기반으로 한 cgroup 계층의 뷰로 시작합니다**. 이는 새로운 cgroup 네임스페이스에서 실행되는 프로세스가 전체 cgroup 계층의 하위 집합만 볼 수 있으며, 생성 프로세스의 cgroup에 뿌리를 둔 cgroup 서브트리로 제한된다는 것을 의미합니다.
2. cgroup 네임스페이스 내의 프로세스는 **자신의 cgroup을 계층의 루트로 봅니다**. 이는 네임스페이스 내부의 프로세스 관점에서 자신의 cgroup이 루트처럼 보이며, 자신의 서브트리 외부의 cgroup을 볼 수 없거나 접근할 수 없다는 것을 의미합니다.
3. cgroup 네임스페이스는 리소스의 격리를 직접 제공하지 않습니다; **그들은 단지 cgroup 계층 뷰의 격리만 제공합니다**. **리소스 제어 및 격리는 여전히 cgroup** 서브시스템(예: cpu, memory 등) 자체에 의해 시행됩니다.

CGroups에 대한 더 많은 정보는 다음을 확인하세요:

{{#ref}}
../cgroups.md
{{#endref}}

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
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
- `%unshare -fp /bin/bash%`를 실행하면 `unshare` 명령 자체가 새로운 네임스페이스에서 PID 1이 됩니다. 그 결과 `/bin/bash`와 그 자식 프로세스는 이 새로운 네임스페이스 내에서 안전하게 포함되어 PID 1의 조기 종료를 방지하고 정상적인 PID 할당을 허용합니다.

`unshare`가 `-f` 플래그와 함께 실행되도록 보장함으로써 새로운 PID 네임스페이스가 올바르게 유지되며, `/bin/bash`와 그 하위 프로세스가 메모리 할당 오류 없이 작동할 수 있습니다.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;프로세스가 어떤 네임스페이스에 있는지 확인하기
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### 모든 CGroup 네임스페이스 찾기
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### CGroup 네임스페이스 내부로 들어가기
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
또한, **루트 사용자일 경우에만 다른 프로세스 네임스페이스에 들어갈 수 있습니다**. 그리고 **디스크립터**가 없으면 **다른 네임스페이스에 들어갈 수 없습니다** (예: `/proc/self/ns/cgroup`).

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
