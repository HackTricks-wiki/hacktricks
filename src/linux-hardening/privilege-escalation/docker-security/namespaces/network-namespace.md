# Network Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

네트워크 네임스페이스는 네트워크 스택의 격리를 제공하는 리눅스 커널 기능으로, **각 네트워크 네임스페이스가 독립적인 네트워크 구성**, 인터페이스, IP 주소, 라우팅 테이블 및 방화벽 규칙을 가질 수 있도록 합니다. 이 격리는 컨테이너화와 같은 다양한 시나리오에서 유용하며, 각 컨테이너는 다른 컨테이너 및 호스트 시스템과 독립적인 네트워크 구성을 가져야 합니다.

### How it works:

1. 새로운 네트워크 네임스페이스가 생성되면, **완전히 격리된 네트워크 스택**으로 시작하며, 루프백 인터페이스(lo) 외에는 **네트워크 인터페이스가 없습니다**. 이는 새로운 네트워크 네임스페이스에서 실행되는 프로세스가 기본적으로 다른 네임스페이스나 호스트 시스템의 프로세스와 통신할 수 없음을 의미합니다.
2. veth 쌍과 같은 **가상 네트워크 인터페이스**를 생성하고 네트워크 네임스페이스 간에 이동할 수 있습니다. 이를 통해 네임스페이스 간 또는 네임스페이스와 호스트 시스템 간의 네트워크 연결을 설정할 수 있습니다. 예를 들어, veth 쌍의 한 쪽 끝을 컨테이너의 네트워크 네임스페이스에 배치하고, 다른 쪽 끝을 호스트 네임스페이스의 **브리지** 또는 다른 네트워크 인터페이스에 연결하여 컨테이너에 네트워크 연결을 제공합니다.
3. 네임스페이스 내의 네트워크 인터페이스는 다른 네임스페이스와 독립적으로 **자신의 IP 주소, 라우팅 테이블 및 방화벽 규칙**을 가질 수 있습니다. 이를 통해 서로 다른 네트워크 네임스페이스의 프로세스가 서로 다른 네트워크 구성을 가질 수 있으며, 마치 별도의 네트워크 시스템에서 실행되는 것처럼 작동할 수 있습니다.
4. 프로세스는 `setns()` 시스템 호출을 사용하여 네임스페이스 간에 이동하거나, `unshare()` 또는 `clone()` 시스템 호출을 사용하여 `CLONE_NEWNET` 플래그와 함께 새로운 네임스페이스를 생성할 수 있습니다. 프로세스가 새로운 네임스페이스로 이동하거나 생성할 때, 해당 네임스페이스와 연결된 네트워크 구성 및 인터페이스를 사용하기 시작합니다.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
`/proc` 파일 시스템의 새 인스턴스를 마운트하면 `--mount-proc` 매개변수를 사용하여 새 마운트 네임스페이스가 **해당 네임스페이스에 특정한 프로세스 정보에 대한 정확하고 격리된 뷰**를 갖도록 보장합니다.

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

`unshare`가 `-f` 플래그와 함께 실행되도록 보장함으로써 새로운 PID 네임스페이스가 올바르게 유지되며, `/bin/bash`와 그 하위 프로세스가 메모리 할당 오류 없이 작동할 수 있습니다.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### 프로세스가 어떤 네임스페이스에 있는지 확인하기
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### 모든 네트워크 네임스페이스 찾기
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### 네트워크 네임스페이스 내부로 들어가기
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
또한, **루트 사용자만 다른 프로세스 네임스페이스에 들어갈 수 있습니다**. 그리고 **디스크립터** 없이 다른 네임스페이스에 **들어갈 수 없습니다** (예: `/proc/self/ns/net`).

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
