# IPC 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

IPC 네임스페이스는 **System V IPC objects**와 **POSIX message queues**를 격리합니다. 여기에는 호스트에서 서로 관련 없는 프로세스 간에 공유될 수 있는 shared memory segments, semaphores, message queues가 포함됩니다. 실제로 이를 통해 컨테이너가 다른 workload 또는 호스트에 속한 IPC objects에 임의로 연결하는 것을 방지합니다.

mount, PID 또는 user namespaces와 비교하면 IPC 네임스페이스는 자주 논의되지 않지만, 그렇다고 중요하지 않은 것은 아닙니다. shared memory 및 관련 IPC 메커니즘에는 매우 유용한 state가 포함될 수 있습니다. 호스트 IPC 네임스페이스가 노출되면 workload가 컨테이너 경계를 넘어 공유될 의도가 없었던 inter-process coordination objects 또는 data를 확인할 수 있습니다.

## 작동 방식

runtime이 새로운 IPC 네임스페이스를 생성하면 프로세스는 자체적으로 격리된 IPC identifiers 집합을 갖게 됩니다. 즉, `ipcs`와 같은 명령은 해당 네임스페이스에서 사용할 수 있는 objects만 표시합니다. 반대로 컨테이너가 호스트 IPC 네임스페이스에 join하면 해당 objects가 공유되는 global view의 일부가 됩니다.

이는 애플리케이션이나 services가 shared memory를 많이 사용하는 환경에서 특히 중요합니다. 컨테이너가 IPC만으로 직접 탈출할 수 없더라도 네임스페이스를 통해 information이 leak되거나 cross-process interference가 가능해져 이후 attack에 실질적인 도움이 될 수 있습니다.

## 실습

다음 명령으로 private IPC 네임스페이스를 생성할 수 있습니다:
```bash
sudo unshare --ipc --fork bash
ipcs
```
그리고 다음과 runtime 동작을 비교합니다:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Runtime Usage

Docker와 Podman은 기본적으로 IPC를 격리합니다. Kubernetes는 일반적으로 Pod에 자체 IPC namespace를 제공하며, 같은 Pod의 컨테이너 간에는 공유되지만 기본적으로 host와는 공유되지 않습니다. Host IPC 공유도 가능하지만, 이를 사소한 runtime 옵션이 아니라 격리 수준을 크게 낮추는 설정으로 취급해야 합니다.

## Misconfigurations

가장 명백한 실수는 `--ipc=host` 또는 `hostIPC: true`를 사용하는 것입니다. 이는 legacy software와의 호환성 또는 편의를 위해 설정할 수 있지만, trust model을 크게 변경합니다. 또 다른 반복되는 문제는 host PID나 host networking만큼 극적으로 느껴지지 않는다는 이유로 IPC를 단순히 간과하는 것입니다. 실제로 workload가 browsers, databases, scientific workloads 또는 shared memory를 많이 사용하는 기타 software를 처리한다면 IPC surface는 매우 중요할 수 있습니다.

## Abuse

Host IPC가 공유되면 attacker는 shared memory objects를 검사하거나 간섭하고, host 또는 neighboring workload의 동작에 대한 새로운 정보를 얻거나, 해당 정보를 process visibility 및 ptrace-style capabilities와 결합할 수 있습니다. IPC sharing은 전체 breakout path라기보다는 supporting weakness인 경우가 많지만, supporting weaknesses가 중요한 이유는 실제 attack chain을 더 짧고 안정적으로 만들기 때문입니다.

첫 번째로 유용한 단계는 어떤 IPC objects가 전혀 표시되는지 enumerate하는 것입니다:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
호스트 IPC namespace가 공유되어 있다면, 대규모 shared-memory segments 또는 흥미로운 object owners를 통해 애플리케이션 동작을 즉시 파악할 수 있습니다:
```bash
ipcs -m -p
ipcs -q -p
```
일부 환경에서는 `/dev/shm` 콘텐츠 자체에서 확인해 볼 가치가 있는 파일 이름, 아티팩트 또는 토큰이 leak될 수 있습니다:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC sharing만으로 즉시 host root 권한을 얻는 경우는 드물지만, 이후 process attack을 훨씬 쉽게 만드는 데이터 및 coordination channel을 노출할 수 있습니다.

### 전체 예시: `/dev/shm` Secret Recovery

가장 현실적인 전체 abuse case는 직접적인 escape가 아니라 데이터 탈취입니다. host IPC 또는 광범위한 shared-memory layout이 노출되면 민감한 artifact를 직접 복구할 수 있는 경우가 있습니다:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
영향:

- 공유 메모리에 남아 있는 secrets 또는 session material 추출
- 현재 host에서 활성화된 applications에 대한 정보 획득
- 이후 PID-namespace 또는 ptrace 기반 attacks를 더욱 정밀하게 targeting

따라서 IPC sharing은 standalone host-escape primitive라기보다 **attack amplifier**로 이해하는 것이 더 적절합니다.

## 점검

이 명령어들은 workload가 private IPC view를 사용하는지, 의미 있는 shared-memory 또는 message objects가 표시되는지, 그리고 `/dev/shm` 자체가 유용한 artifacts를 노출하는지를 확인하기 위한 것입니다.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
여기서 흥미로운 점:

- `ipcs -a`에서 예상치 못한 사용자나 서비스가 소유한 객체가 확인된다면, namespace가 예상만큼 격리되지 않았을 수 있습니다.
- 크기가 크거나 비정상적인 shared memory segment는 추가 조사를 진행할 가치가 있는 경우가 많습니다.
- 광범위한 `/dev/shm` mount가 항상 버그인 것은 아니지만, 일부 환경에서는 파일명, artifact 및 일시적인 secret이 leak될 수 있습니다.

IPC는 더 중요한 namespace 유형만큼 많은 주목을 받는 경우가 드물지만, 이를 많이 사용하는 환경에서는 host와 공유하는 것이 분명한 security decision입니다.

{{#include ../../../../../banners/hacktricks-training.md}}
