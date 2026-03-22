# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

The cgroup namespace는 cgroups를 대체하지 않으며 자체적으로 리소스 제한을 강제하지 않습니다. 대신 프로세스에 보이는 **how the cgroup hierarchy appears**를 변경합니다. 다시 말해, 보이는 cgroup 경로 정보를 가상화하여 워크로드가 전체 호스트 계층 대신 컨테이너 범위의 뷰를 보도록 합니다.

이 기능은 주로 가시성 및 정보 축소 기능입니다. 환경을 자체 포함된 것처럼 보이게 하고 호스트의 cgroup 레이아웃에 대한 노출을 줄이는 데 도움이 됩니다. 겸손하게 들릴 수 있지만, 불필요한 호스트 구조 노출은 정찰을 돕고 환경 의존적인 exploit chains를 단순화할 수 있기 때문에 여전히 중요합니다.

## Operation

Without a private cgroup namespace, a process may see host-relative cgroup paths that expose more of the machine's hierarchy than is useful. With a private cgroup namespace, `/proc/self/cgroup` and related observations become more localized to the container's own view. This is particularly helpful in modern runtime stacks that want the workload to see a cleaner, less host-revealing environment.

## Lab

You can inspect a cgroup namespace with:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
그리고 런타임 동작을 다음과 비교하세요:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
The change is mostly about what the process can see, not about whether cgroup enforcement exists.

## 보안 영향

cgroup namespace는 **가시성 강화 계층(visibility-hardening layer)**으로 이해하는 것이 가장 적절하다. 그 자체만으로는 container에 writable cgroup mounts가 있거나 broad capabilities가 부여되어 있거나 위험한 cgroup v1 환경이 존재하는 경우 breakout을 막지 못한다. 그러나 host cgroup namespace가 공유되어 있으면 process는 시스템이 어떻게 구성되어 있는지 더 많이 알게 되고, 호스트 기준의 cgroup 경로를 다른 관찰 결과와 맞춰 연결하기가 더 쉬워질 수 있다.

따라서 이 namespace가 보통 container breakout 관련 글에서 주인공은 아니지만, host information leak을 최소화하려는 더 넓은 목표에는 기여한다.

## Abuse

즉각적인 악용 가치는 대부분 reconnaissance다. host cgroup namespace가 공유되어 있다면, 보이는 경로들을 비교하고 호스트를 드러내는 계층 구조의 세부사항을 찾아라:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
쓰기 가능한 cgroup 경로도 노출되어 있다면, 그 가시성을 위험한 레거시 인터페이스 검색과 결합하세요:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
namespace 자체만으로는 즉시 escape를 제공하는 경우는 드물지만, cgroup-based abuse primitives를 테스트하기 전에 환경을 매핑하기는 더 쉬워지는 경우가 많다.

### 전체 예: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace만으로는 보통 escape에 충분하지 않다. 실제적인 escalation은 host-revealing cgroup paths가 writable cgroup v1 interfaces와 결합될 때 발생한다:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
해당 파일들에 접근 가능하고 쓰기 가능하다면, 즉시 [cgroups.md](../cgroups.md)에 있는 전체 `release_agent` exploitation flow로 전환하세요. 영향은 컨테이너 내부에서 호스트 코드 실행입니다.

writable cgroup interfaces가 없으면 영향은 보통 reconnaissance에 국한됩니다.

## 확인

이 명령들의 목적은 프로세스가 private cgroup namespace view를 가지고 있는지, 또는 실제로 필요로 하는 것보다 호스트 계층에 대해 더 많은 정보를 수집하고 있는지를 확인하는 것입니다.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
여기서 흥미로운 점:

- 네임스페이스 식별자가 관심 있는 호스트 프로세스와 일치하면, cgroup namespace가 공유될 수 있다.
- `/proc/self/cgroup`의 호스트를 드러내는 경로는 직접적으로 악용할 수 없더라도 유용한 정찰 수단이다.
- cgroup mounts도 쓰기 가능하다면, 가시성 문제는 훨씬 더 중요해진다.

cgroup namespace는 주된 탈출 방지 메커니즘이라기보다는 가시성 강화 계층으로 취급되어야 한다. 호스트의 cgroup 구조를 불필요하게 노출하면 공격자에게 정찰 가치를 더해준다.
{{#include ../../../../../banners/hacktricks-training.md}}
