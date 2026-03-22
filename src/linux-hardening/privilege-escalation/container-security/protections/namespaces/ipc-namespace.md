# IPC 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

IPC 네임스페이스는 **System V IPC objects**와 **POSIX message queues**를 격리한다. 여기에는 공유 메모리 세그먼트, 세마포어, 그리고 그렇지 않으면 호스트의 관련 없는 프로세스들에 걸쳐 보였을 메시지 큐가 포함된다. 실질적으로 이는 컨테이너가 다른 워크로드나 호스트에 속한 IPC 객체에 임의로 접근하는 것을 방지한다.

mount, PID, 또는 user 네임스페이스와 비교해 IPC 네임스페이스는 덜 자주 논의되지만, 그렇다고 해서 중요하지 않은 것은 아니다. 공유 메모리와 관련된 IPC 메커니즘은 매우 유용한 상태를 포함할 수 있다. 호스트 IPC 네임스페이스가 노출되면 워크로드는 컨테이너 경계를 넘길 의도로 만들어지지 않은 프로세스 간 조정 객체나 데이터에 대한 가시성을 얻을 수 있다.

## 동작

런타임이 새로운 IPC 네임스페이스를 생성하면 프로세스는 자체 격리된 IPC 식별자 집합을 갖게 된다. 이는 `ipcs`와 같은 명령이 해당 네임스페이스에서만 사용 가능한 객체들을 표시한다는 의미다. 반대로 컨테이너가 호스트 IPC 네임스페이스에 합류하면 그 객체들은 공유된 전역 뷰의 일부가 된다.

애플리케이션이나 서비스가 공유 메모리를 많이 사용하는 환경에서는 이것이 특히 중요하다. 설령 컨테이너가 IPC만으로 직접 탈출할 수 없다 하더라도, 네임스페이스는 정보를 leak하거나 교차 프로세스 간 간섭을 가능하게 하여 이후 공격에 실질적으로 도움이 될 수 있다.

## 실습

You can create a private IPC namespace with:
```bash
sudo unshare --ipc --fork bash
ipcs
```
그리고 런타임 동작을 다음과 비교하세요:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Runtime Usage

Docker와 Podman은 기본적으로 IPC를 격리한다. Kubernetes는 일반적으로 Pod에 자체 IPC 네임스페이스를 부여하며, 같은 Pod 안의 컨테이너들끼리는 공유하지만 기본적으로 host와는 공유하지 않는다. host IPC 공유는 가능하지만, 이는 단순한 런타임 옵션이 아닌 격리 수준의 중요한 감소로 취급해야 한다.

## Misconfigurations

명백한 실수는 `--ipc=host` 또는 `hostIPC: true`이다. 이는 레거시 소프트웨어와의 호환성이나 편의상 선택할 수 있으나, 신뢰 모델을 상당히 변경한다. 또 다른 반복되는 문제는 IPC를 간과하는 것으로, host PID나 host networking보다 덜 극적이라고 느껴지기 때문이다. 실제로 워크로드가 브라우저, 데이터베이스, 과학적 워크로드 또는 공유 메모리를 많이 사용하는 기타 소프트웨어를 다루는 경우 IPC 표면은 매우 중요할 수 있다.

## Abuse

host IPC가 공유될 때, 공격자는 공유 메모리 객체를 검사하거나 간섭하고, host나 인접한 워크로드 동작에 대한 새로운 통찰을 얻거나 그곳에서 얻은 정보를 프로세스 가시성 및 ptrace-style 기능과 결합할 수 있다. IPC 공유는 전체 탈출 경로라기보다는 보조적 약점인 경우가 많지만, 보조적 약점은 실제 공격 체인을 단축하고 안정화시키기 때문에 중요하다.

The first useful step is to enumerate what IPC objects are visible at all:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
호스트 IPC 네임스페이스가 공유되어 있다면, 큰 공유 메모리 세그먼트나 흥미로운 객체 소유자가 애플리케이션 동작을 즉시 드러낼 수 있습니다:
```bash
ipcs -m -p
ipcs -q -p
```
일부 환경에서는 `/dev/shm`의 내용물 자체가 파일 이름, 아티팩트 또는 확인할 가치가 있는 tokens를 leak하기도 합니다:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC 공유는 자체만으로 즉시 host root를 얻는 경우는 드물지만, 나중의 프로세스 공격을 훨씬 쉽게 만드는 데이터와 조정 채널을 노출할 수 있다.

### 전체 예제: `/dev/shm` Secret Recovery

가장 현실적인 전체 악용 사례는 직접적인 escape보다는 데이터 절도로, host IPC나 광범위한 공유 메모리 레이아웃이 노출되면 민감한 아티팩트를 직접 복구할 수 있는 경우가 있다:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
영향:

- shared memory에 남아 있는 비밀이나 세션 자료의 추출
- 호스트에서 현재 실행 중인 애플리케이션에 대한 정보 획득
- 추후 PID-namespace 또는 ptrace 기반 공격을 더 잘 겨냥할 수 있음

IPC 공유는 따라서 단독 host-escape primitive라기보다는 **공격 증폭기**로 이해하는 것이 더 적절하다.

## 확인

이 명령들은 워크로드가 private IPC 뷰를 가지고 있는지, 의미 있는 shared-memory 또는 message objects가 보이는지, 그리고 `/dev/shm` 자체가 유용한 아티팩트를 노출하는지 여부를 확인하기 위한 것이다.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
- `ipcs -a`가 예상치 못한 사용자나 서비스가 소유한 객체를 표시하면, namespace가 기대만큼 격리되어 있지 않을 수 있습니다.
- 큰 또는 특이한 shared memory segments는 종종 후속 조사가 필요합니다.
- 광범위한 `/dev/shm` 마운트가 자동으로 버그는 아니지만, 일부 환경에서는 filenames, artifacts, 및 transient secrets를 leaks할 수 있습니다.

IPC는 보통 더 큰 namespace 유형만큼 주목받지 못하지만, 이를 많이 사용하는 환경에서는 host와 공유하는 것이 분명한 보안 결정입니다.
{{#include ../../../../../banners/hacktricks-training.md}}
