# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

The IPC namespace는 **System V IPC objects**와 **POSIX message queues**를 격리합니다. 여기에는 shared memory segments, semaphores, 그리고 그렇지 않으면 호스트의 관련 없는 프로세스들 간에 보였을 message queues가 포함됩니다. 실무적으로 이는 container가 다른 workloads나 host에 속한 IPC objects에 손쉽게 attach하는 것을 방지합니다.

mount, PID, or user namespaces와 비교할 때 IPC namespace는 덜 자주 논의되지만, 그렇다고 해서 중요하지 않다는 뜻은 아닙니다. Shared memory 및 관련 IPC 메커니즘에는 매우 유용한 상태가 포함될 수 있습니다. host IPC namespace가 노출되면 workload는 container 경계를 넘어서는 의도로 만들어지지 않은 inter-process coordination objects나 데이터에 대한 가시성을 얻을 수 있습니다.

## 동작

런타임이 새로운 IPC namespace를 생성하면 프로세스는 자체 격리된 IPC 식별자 집합을 갖게 됩니다. 이는 `ipcs`와 같은 명령이 해당 namespace에서만 사용 가능한 객체들을 표시한다는 뜻입니다. 반대로 container가 host IPC namespace에 가입하면 그 객체들은 공유된 전역 뷰의 일부가 됩니다.

이것은 애플리케이션이나 서비스가 shared memory를 많이 사용하는 환경에서 특히 중요합니다. container가 IPC만으로 직접 탈출할 수 없더라도, 그 namespace는 정보를 leak하거나 이후 공격에 실질적으로 도움이 되는 교차 프로세스 간 간섭을 가능하게 할 수 있습니다.

## Lab

다음과 같이 private IPC namespace를 생성할 수 있습니다:
```bash
sudo unshare --ipc --fork bash
ipcs
```
그리고 런타임 동작을 다음과 비교하세요:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## 런타임 사용

Docker와 Podman은 기본적으로 IPC를 격리합니다. Kubernetes는 일반적으로 Pod에 자체 IPC 네임스페이스를 부여하며, 동일한 Pod 내의 컨테이너들끼리는 공유되지만 기본적으로 호스트와는 공유되지 않습니다. Host IPC 공유는 가능하지만, 단순한 런타임 옵션이라기보다 격리를 크게 약화시키는 중요한 설정으로 다뤄야 합니다.

## 잘못된 구성

명백한 실수는 `--ipc=host` 또는 `hostIPC: true`입니다. 레거시 소프트웨어 호환성이나 편의상 이렇게 할 수 있지만, 신뢰 모델을 크게 바꿉니다. 또 다른 반복되는 문제는 host PID나 host networking보다 덜 극적이라고 생각해 IPC를 간과하는 것입니다. 실제로 워크로드가 브라우저, 데이터베이스, 과학적 워크로드 또는 공유 메모리를 많이 사용하는 다른 소프트웨어를 다룬다면, IPC 표면은 매우 중요해질 수 있습니다.

## 악용

호스트 IPC가 공유되면, 공격자는 공유 메모리 객체를 검사하거나 조작할 수 있고, 호스트나 인접한 워크로드의 동작에 대한 새로운 통찰을 얻거나, 거기서 얻은 정보를 프로세스 가시성 및 ptrace-style 기능과 결합할 수 있습니다. IPC 공유는 전체 탈출 경로라기보다는 보조적 취약점인 경우가 많지만, 보조 취약점도 실제 공격 체인을 단축하고 안정화하므로 중요합니다.

첫 번째 유용한 단계는 어떤 IPC 객체가 보이는지 모두 열거하는 것입니다:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
호스트 IPC 네임스페이스가 공유되어 있다면, 큰 공유 메모리 세그먼트나 흥미로운 객체 소유자는 애플리케이션의 동작을 즉시 드러낼 수 있습니다:
```bash
ipcs -m -p
ipcs -q -p
```
일부 환경에서는 `/dev/shm`의 내용 자체가 filenames, artifacts, or tokens을 leak할 수 있어 확인할 가치가 있습니다:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC 공유만으로는 호스트 root를 즉시 얻는 경우는 드물지만, 데이터와 조정 채널을 노출시켜 이후의 프로세스 공격을 훨씬 쉽게 만들 수 있다.

### 전체 예시: `/dev/shm` 비밀 복구

가장 현실적인 전체 악용 사례는 직접적인 escape보다는 데이터 도난이다. 호스트 IPC나 광범위한 공유 메모리 레이아웃이 노출된 경우 민감한 아티팩트를 때때로 직접 복구할 수 있다:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impact:

- 공유 메모리에 남아 있는 비밀(시크릿) 또는 세션 자료의 추출
- 호스트에서 현재 실행 중인 애플리케이션에 대한 정보 파악
- 나중의 PID-namespace 또는 ptrace 기반 공격을 위한 더 나은 표적화

IPC 공유는 따라서 독립적인 host-escape primitive라기보다는 **공격 증폭기**로 이해하는 것이 더 낫다.

## 확인

이 명령들은 워크로드가 프라이빗한 IPC 뷰를 가지고 있는지, 의미 있는 공유 메모리 또는 메시지 객체가 보이는지, 그리고 `/dev/shm` 자체가 유용한 아티팩트를 노출하는지를 확인하기 위한 것이다.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
여기서 주목할 점:

- If `ipcs -a` reveals objects owned by unexpected users or services, the namespace may not be as isolated as expected.
- 크거나 비정상적인 공유 메모리 세그먼트는 종종 후속 조사할 가치가 있습니다.
- 광범위한 `/dev/shm` 마운트가 자동으로 버그인 것은 아니지만, 일부 환경에서는 `/dev/shm`이 파일명, 아티팩트, 그리고 일시적 비밀을 leaks할 수 있습니다.

IPC는 더 큰 네임스페이스 유형들만큼 주목받지 못하는 경우가 많지만, 이를 많이 사용하는 환경에서는 호스트와 공유하는 것이 중요한 보안 결정입니다.
