# cgroup 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

cgroup 네임스페이스는 cgroups를 대체하지 않으며 자체적으로 리소스 제한을 강제하지도 않습니다. 대신, 프로세스에 보이는 **cgroup 계층이 어떻게 보이는지**를 변경합니다. 즉, 보이는 cgroup 경로 정보를 가상화하여 워크로드가 전체 호스트 계층이 아닌 컨테이너 범위의 보기만 보도록 합니다.

이는 주로 가시성 및 정보 축소 기능입니다. 환경을 자체적으로 보이게 하여 호스트의 cgroup 배치에 대해 덜 노출되게 도와줍니다. 겉보기에는 사소해 보일 수 있지만, 호스트 구조에 대한 불필요한 노출은 정찰을 돕고 환경 의존적 익스플로잇 체인을 단순화할 수 있으므로 중요합니다.

## 동작

개인 cgroup 네임스페이스가 없으면 프로세스는 호스트 상대 cgroup 경로를 볼 수 있어 머신의 계층 구조를 불필요하게 많이 노출할 수 있습니다. 개인 cgroup 네임스페이스가 있으면 `/proc/self/cgroup` 등 관련 관찰 결과가 컨테이너 자체의 보기로 더 국지화됩니다. 이는 워크로드가 더 깔끔하고 호스트에 덜 노출된 환경을 보길 원하는 최신 런타임 스택에서 특히 유용합니다.

## 실습

다음 명령으로 cgroup 네임스페이스를 검사할 수 있습니다:
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
이 변경은 주로 프로세스가 무엇을 볼 수 있는지에 관한 것이며, cgroup enforcement의 존재 여부와 관련된 것은 아니다.

## Security Impact

The cgroup namespace is best understood as a **가시성 강화 계층**. 단독으로는 컨테이너에 쓰기 가능한 cgroup mounts가 있거나, 광범위한 capabilities를 보유했거나, 위험한 cgroup v1 환경이 있는 경우 breakout을 막지 못한다. 하지만 host cgroup namespace가 공유되어 있다면, 프로세스는 시스템이 어떻게 구성되어 있는지 더 많이 알게 되어 host-relative cgroup paths를 다른 관찰 결과들과 맞춰보기 쉬워질 수 있다.

따라서 이 namespace가 보통 container breakout writeups의 주인공은 아니더라도, 호스트 정보 leakage를 최소화하려는 더 넓은 목표에 기여한다.

## Abuse

직접적인 abuse 가치는 주로 정찰이다. host cgroup namespace가 공유되어 있다면, 보이는 경로들을 비교하고 호스트를 드러내는 계층 구조 세부사항을 찾아라:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
쓰기 가능한 cgroup 경로도 노출되어 있다면, 그 가시성을 위험한 레거시 인터페이스를 찾는 검색과 결합하세요:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
namespace 자체만으로는 즉각적인 탈출을 제공하는 경우는 드물지만, cgroup-based abuse primitives를 테스트하기 전에 환경을 매핑하기가 더 쉬워지는 경우가 많다.

### 전체 예: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace만으로는 보통 탈출에 충분하지 않다. 실제 권한 상승은 호스트를 노출하는 cgroup 경로들이 writable cgroup v1 interfaces와 결합될 때 발생한다:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
해당 파일들에 접근 가능하고 쓰기 가능한 경우, 즉시 [cgroups.md](../cgroups.md)에 있는 전체 `release_agent` exploitation 흐름으로 전환하세요. 영향은 container 내부에서 host code execution입니다.

쓰기 가능한 cgroup 인터페이스가 없으면, 영향은 보통 reconnaissance에 국한됩니다.

## 확인

이 명령들의 목적은 프로세스가 private cgroup namespace view를 가지고 있는지, 또는 실제로 필요로 하는 것보다 host hierarchy에 대해 더 많은 정보를 알아내고 있는지 확인하는 것입니다.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
- 네임스페이스 식별자가 당신이 관심 있는 호스트 프로세스와 일치하면, the cgroup namespace가 공유되어 있을 수 있다.
- `/proc/self/cgroup`의 호스트를 드러내는 경로는 직접적으로 악용할 수 없더라도 유용한 정찰 정보가 된다.
- If cgroup mounts are also writable라면, 가시성 문제는 훨씬 더 중요해진다.

The cgroup namespace는 기본적인 탈출 방지 메커니즘이기보다는 가시성 강화 계층(visibility-hardening layer)으로 취급해야 한다. 호스트의 cgroup 구조를 불필요하게 노출하는 것은 공격자에게 정찰 가치를 더해준다.
