# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

IPC namespace는 **System V IPC objects** 및 **POSIX message queues**를 격리합니다. 여기에는 호스트에서 서로 관련 없는 프로세스 간에 공유되었을 shared memory segments, semaphores, message queues가 포함됩니다. 실제로 이는 컨테이너가 다른 workload 또는 호스트에 속한 IPC objects에 임의로 연결하는 것을 방지합니다.

mount, PID 또는 user namespaces에 비해 IPC namespace는 자주 논의되지 않지만, 그렇다고 중요하지 않은 것은 아닙니다. shared memory 및 관련 IPC mechanisms에는 매우 유용한 상태 정보가 포함될 수 있습니다. 호스트 IPC namespace가 노출되면 workload가 프로세스 간 coordination objects 또는 컨테이너 경계를 넘어 공유할 의도가 없었던 데이터에 대한 visibility를 확보할 수 있습니다.

## 동작

runtime이 새로운 IPC namespace를 생성하면 프로세스는 자체적으로 격리된 IPC identifiers 집합을 갖게 됩니다. 따라서 `ipcs`와 같은 commands는 해당 namespace에서 사용 가능한 objects만 표시합니다. 반대로 컨테이너가 host IPC namespace에 join하면 이러한 objects가 공유된 global view의 일부가 됩니다.

이는 applications 또는 services가 shared memory를 많이 사용하는 environments에서 특히 중요합니다. 컨테이너가 IPC만으로 직접 escape할 수 없는 경우에도 namespace가 information을 leak하거나 cross-process interference를 enable할 수 있으며, 이는 이후 attack에 실질적인 도움이 됩니다.

## 실습

다음 명령으로 private IPC namespace를 생성할 수 있습니다:
```bash
sudo unshare --ipc --fork bash
ipcs
```
그리고 다음과 runtime 동작을 비교합니다:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## 런타임 사용

Docker와 Podman은 기본적으로 IPC를 격리합니다. Kubernetes는 일반적으로 Pod에 자체 IPC namespace를 제공하며, 동일한 Pod의 컨테이너 간에는 공유되지만 기본적으로 host와는 공유되지 않습니다. Host IPC 공유는 가능하지만, 이를 사소한 runtime 옵션이 아니라 격리 수준을 의미 있게 낮추는 설정으로 취급해야 합니다.

## Misconfigurations

가장 명백한 실수는 `--ipc=host` 또는 `hostIPC: true`입니다. 이는 legacy software와의 호환성이나 편의를 위해 설정될 수 있지만, trust model을 크게 변경합니다. 또 다른 반복적인 문제는 IPC가 host PID나 host networking보다 덜 극적으로 느껴져 단순히 간과되는 것입니다. 실제로 workload가 browsers, databases, scientific workloads 또는 shared memory를 많이 사용하는 기타 software를 처리한다면 IPC surface는 매우 중요할 수 있습니다.

## Abuse

Host IPC가 공유되면 attacker는 shared memory objects를 검사하거나 방해하고, host 또는 인접 workload의 동작에 대한 새로운 정보를 얻거나, 이를 process visibility 및 ptrace-style capabilities와 결합할 수 있습니다. IPC sharing은 종종 전체 breakout path라기보다는 supporting weakness이지만, supporting weakness가 중요한 이유는 실제 attack chain을 단축하고 안정화하기 때문입니다.

첫 번째 유용한 단계는 어떤 IPC objects가 전혀 표시되는지 enumerate하는 것입니다:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
host IPC namespace가 공유되어 있다면, 대규모 shared-memory segment나 흥미로운 object owner를 통해 애플리케이션 동작을 즉시 파악할 수 있습니다:
```bash
ipcs -m -p
ipcs -q -p
```
일부 환경에서는 `/dev/shm` 콘텐츠 자체가 확인할 가치가 있는 파일명, 아티팩트 또는 토큰을 leak합니다:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC 공유만으로 즉시 호스트 root를 획득하는 경우는 드물지만, 이후 process 공격을 훨씬 쉽게 만드는 데이터 및 coordination channel을 노출할 수 있습니다.

### 전체 예시: `/dev/shm` Secret 복구

가장 현실적인 전체 abuse 사례는 직접적인 escape가 아니라 data theft입니다. 호스트 IPC 또는 광범위한 shared-memory 레이아웃이 노출되면 민감한 artifact를 직접 복구할 수 있는 경우가 있습니다:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
영향:

- shared memory에 남아 있는 secrets 또는 session material 추출
- host에서 현재 활성화된 applications에 대한 정보 확보
- 이후 PID-namespace 또는 ptrace 기반 attacks를 더 효과적으로 targeting

따라서 IPC sharing은 standalone host-escape primitive라기보다 **attack amplifier**로 이해하는 것이 더 적절합니다.

## Checks

다음 commands는 workload가 private IPC view를 사용하는지, 의미 있는 shared-memory 또는 message objects가 노출되는지, 그리고 `/dev/shm` 자체가 유용한 artifacts를 노출하는지를 확인하기 위한 것입니다.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
여기서 흥미로운 점:

- `ipcs -a`에서 예상하지 못한 사용자나 서비스가 소유한 객체를 표시한다면, namespace가 예상만큼 격리되지 않았을 수 있습니다.
- 크기가 크거나 비정상적인 shared memory 세그먼트는 추가로 조사할 가치가 있습니다.
- 광범위한 `/dev/shm` 마운트가 자동으로 버그인 것은 아니지만, 일부 환경에서는 파일 이름, artifacts 및 일시적인 secrets를 leak할 수 있습니다.

IPC는 더 큰 namespace 유형만큼 많은 관심을 받는 경우가 드뭅니다. 하지만 IPC를 많이 사용하는 환경에서는 이를 host와 공유하는 것이 분명한 security decision입니다.
{{#include ../../../../../banners/hacktricks-training.md}}
