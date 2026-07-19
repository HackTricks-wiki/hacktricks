# cgroup 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

cgroup 네임스페이스는 cgroups를 대체하지 않으며 리소스 제한을 직접 적용하지도 않습니다. 대신 **cgroup 계층 구조가 프로세스에 표시되는 방식**을 변경합니다. 즉, 표시되는 cgroup 경로 정보를 가상화하여 workload가 전체 호스트 계층 구조가 아닌 컨테이너 범위의 뷰를 보도록 합니다.

이는 주로 가시성과 정보 축소를 위한 기능입니다. 환경을 독립적으로 보이게 하고 호스트의 cgroup 레이아웃에 대한 노출을 줄이는 데 도움이 됩니다. 사소하게 들릴 수 있지만, 호스트 구조에 대한 불필요한 가시성은 reconnaissance를 지원하고 환경에 의존하는 exploit chain을 단순화할 수 있으므로 여전히 중요합니다.

## 동작

private cgroup 네임스페이스가 없으면 프로세스가 시스템 계층 구조 중 불필요한 부분까지 노출하는 호스트 기준 cgroup 경로를 볼 수 있습니다. private cgroup 네임스페이스를 사용하면 `/proc/self/cgroup` 및 관련 정보가 컨테이너 자체의 뷰에 맞게 더 국소화됩니다. 이는 workload가 더 깔끔하고 호스트 정보를 덜 드러내는 환경을 보도록 하는 최신 runtime stack에서 특히 유용합니다.

이 가상화는 `/proc/<pid>/cgroup`뿐만 아니라 `/proc/<pid>/mountinfo`에도 영향을 줍니다. 다른 cgroup-namespace 관점에서 다른 프로세스를 읽을 때 네임스페이스 루트 외부의 경로는 앞에 `../` 구성 요소가 붙은 형태로 표시됩니다. 이는 위임된 subtree보다 상위 항목을 보고 있다는 것을 알려 주는 유용한 단서입니다. labs 및 post-exploitation에서 알아둘 점은, 새로 생성된 cgroup 네임스페이스에서는 `mountinfo`가 새로운 루트를 올바르게 반영하기 전에 해당 네임스페이스 내부에서 **cgroupfs remount**가 필요한 경우가 많다는 것입니다. 그렇지 않으면 `/..`과 같은 mount root가 계속 표시될 수 있습니다. 이는 네임스페이스 자체는 이미 변경되었더라도 상속된 mount가 여전히 상위 항목을 루트로 하는 뷰를 노출하고 있다는 의미입니다.

## 실습

다음 명령으로 cgroup 네임스페이스를 확인할 수 있습니다:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
`mountinfo`에 새로운 cgroup-namespace 루트가 더 명확하게 표시되도록 하려면, 새로운 namespace 내부에서 cgroup filesystem을 다시 마운트한 후 다시 비교합니다:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
그리고 runtime 동작을 다음과 비교합니다:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
이 변경은 cgroup enforcement가 존재하는지 여부보다는 프로세스가 볼 수 있는 대상에 관한 것입니다.

## 보안 영향

cgroup namespace는 **visibility-hardening layer**로 이해하는 것이 가장 좋습니다. 이것만으로는 컨테이너에 writable cgroup mounts, broad capabilities 또는 위험한 cgroup v1 환경이 있는 경우 breakout을 막을 수 없습니다. 그러나 host cgroup namespace가 공유되면 프로세스는 시스템이 어떻게 구성되어 있는지 더 많은 정보를 파악하게 되며, host-relative cgroup paths를 다른 관찰 결과와 연결하기가 더 쉬워질 수 있습니다.

**cgroup v2**에서는 delegation rules가 더 엄격하기 때문에 namespace가 조금 더 중요해집니다. hierarchy가 `nsdelegate`로 mount된 경우, kernel은 cgroup namespaces를 delegation boundaries로 취급합니다. 즉, ancestor control files는 delegatee의 접근 범위 밖에 유지되어야 하며, namespace root에서의 writes는 `cgroup.procs`, `cgroup.threads`, `cgroup.subtree_control` 같은 delegation-safe files로 제한됩니다. 그렇다고 해서 namespace 자체가 escape primitive가 되는 것은 아니지만, compromised workload가 검사할 수 있는 대상과 안전하게 sub-cgroups를 생성할 수 있는 위치가 달라집니다.

따라서 이 namespace가 container breakout writeups에서 보통 핵심적으로 다뤄지지는 않더라도, host information leakage를 최소화하고 cgroup delegation을 제한한다는 더 큰 목표에는 여전히 기여합니다.

## 악용

즉각적인 abuse value는 대부분 reconnaissance입니다. host cgroup namespace가 공유된 경우, 표시되는 paths를 비교하고 host를 드러내는 hierarchy details를 찾아보세요:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
쓰기 가능한 cgroup 경로도 노출되어 있다면, 해당 가시성을 위험한 레거시 인터페이스 검색과 결합합니다:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
namespace 자체만으로 즉시 escape가 발생하는 경우는 드물지만, cgroup 기반 abuse primitive를 테스트하기 전에 환경을 매핑하기 쉽게 만드는 경우가 많습니다.

빠르게 runtime reality check를 수행하면 attack path의 우선순위를 정하는 데도 도움이 됩니다. Docker는 `--cgroupns=host|private`를 노출하며, Podman은 `host`, `private`, `container:<id>`, `ns:<path>`를 지원합니다. 특히 Podman에서는 기본값이 일반적으로 **cgroup v1에서는 `host`**이고 **cgroup v2에서는 `private`**이므로, cgroup version만 식별해도 전체 OCI config를 확인하기 전에 어떤 namespace posture가 더 가능성 높은지 알 수 있습니다.

### Modern v2 Recon: 이것은 Delegated Subtree인가?

Modern host에서는 중요한 질문이 `release_agent`가 아니라, 현재 process가 nested group을 생성할 수 있을 만큼 충분한 visibility 또는 write access가 있는 delegated **cgroup v2** subtree 내부에 있는지 여부인 경우가 많습니다:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
유용한 해석:

- `cgroup2fs`는 unified v2 hierarchy에 있음을 의미하므로, classic v1-only `release_agent` chains를 가장 먼저 추측해서는 안 됩니다.
- `cgroup.controllers`는 parent에서 사용할 수 있는 controllers와, 따라서 현재 subtree가 children으로 확장될 때 잠재적으로 전달할 수 있는 controllers를 보여 줍니다.
- `cgroup.subtree_control`은 descendants에 실제로 활성화된 controllers를 보여 줍니다.
- `cgroup.events`는 `populated=0/1`을 노출합니다. 이를 통해 subtree가 비어 있는지 확인할 수 있지만, v1 `release_agent`와 같은 host-code-execution primitive는 **아닙니다**.

다른 process namespace를 직접 검사할 수 있을 만큼 충분한 privilege가 이미 있다면 다음을 사용하여 views를 비교합니다:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### 전체 예시: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace만으로는 일반적으로 escape에 충분하지 않습니다. 실제 권한 상승은 host를 노출하는 cgroup 경로가 Writable cgroup v1 인터페이스와 결합될 때 발생합니다:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
해당 파일에 접근할 수 있고 쓰기도 가능하다면, [cgroups.md](../cgroups.md)의 전체 `release_agent` exploitation flow로 즉시 pivot하세요. 영향은 container 내부에서 host code execution이 가능해지는 것입니다.

쓰기가 가능한 cgroup 인터페이스가 없다면, 영향은 일반적으로 reconnaissance로 제한됩니다.

## Checks

이 명령의 목적은 process가 private cgroup namespace view를 사용하는지, 또는 실제로 필요한 것보다 더 많은 host hierarchy 정보를 학습하는지를 확인하는 것입니다.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
여기서 주목할 만한 내용:

- namespace identifier가 관심 있는 host process와 일치하면 cgroup namespace가 공유되고 있을 수 있습니다.
- `/proc/self/cgroup`의 host를 드러내는 경로 또는 `mountinfo`의 ancestor-rooted 항목은 직접적으로 exploit할 수 없더라도 유용한 reconnaissance 정보입니다.
- `cgroup2fs`가 사용 중인 경우, 이전 v1 primitive가 여전히 존재한다고 가정하기보다는 delegation, 표시되는 controller, writable subtree에 집중해야 합니다.
- cgroup mount도 writable하다면 visibility 문제가 훨씬 더 중요해집니다.

cgroup namespace는 primary escape-prevention mechanism이 아니라 visibility-hardening layer로 취급해야 합니다. 불필요하게 host cgroup 구조를 노출하면 attacker에게 reconnaissance 가치가 추가됩니다.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
