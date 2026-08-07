# cgroup 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

cgroup 네임스페이스는 cgroup을 대체하지 않으며, 자체적으로 리소스 제한을 적용하지도 않습니다. 대신 **cgroup 계층 구조가 프로세스에 어떻게 표시되는지**를 변경합니다. 즉, 표시되는 cgroup 경로 정보를 가상화하여 workload가 전체 host 계층 구조가 아닌 container 범위의 view를 보도록 합니다.

이는 주로 visibility와 information-reduction을 위한 기능입니다. 환경이 자체적으로 완결된 것처럼 보이게 하고 host의 cgroup layout에 대한 노출을 줄이는 데 도움이 됩니다. 사소해 보일 수 있지만, host 구조에 대한 불필요한 visibility는 reconnaissance를 지원하고 환경에 의존하는 exploit chain을 단순화할 수 있으므로 여전히 중요합니다.

## 동작

private cgroup 네임스페이스가 없으면 프로세스가 machine의 계층 구조 중 필요 이상으로 많은 부분을 노출하는 host-relative cgroup 경로를 볼 수 있습니다. private cgroup 네임스페이스를 사용하면 `/proc/self/cgroup` 및 관련 관찰 결과가 container 자체의 view에 더욱 국한됩니다. 이는 workload가 더 깔끔하고 host 정보를 덜 노출하는 환경을 보도록 하려는 최신 runtime stack에서 특히 유용합니다.

이 가상화는 `/proc/<pid>/cgroup`뿐만 아니라 `/proc/<pid>/mountinfo`에도 영향을 줍니다. 다른 cgroup-namespace 관점에서 다른 프로세스를 읽을 때 namespace root 외부의 경로는 앞에 `../` 구성 요소가 붙은 형태로 표시됩니다. 이는 자신에게 위임된 subtree보다 상위 항목을 확인하고 있다는 유용한 단서입니다. labs 및 post-exploitation에서 알아둘 점은, 새로 생성된 cgroup 네임스페이스에서 `mountinfo`가 새 root를 정상적으로 반영하려면 해당 namespace 내부에서 **cgroupfs remount**가 필요한 경우가 많다는 것입니다. 그렇지 않으면 `/..`와 같은 mount root가 여전히 표시될 수 있습니다. 이는 namespace 자체는 이미 변경되었더라도 상속된 mount가 여전히 ancestor-rooted view를 노출하고 있음을 의미합니다.<sup>[[1]](#references)</sup>

## Lab

다음 명령으로 cgroup 네임스페이스를 확인할 수 있습니다:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
`mountinfo`에 새로운 cgroup-namespace 루트가 더 명확하게 표시되도록 하려면, 새로운 namespace 내부에서 cgroup filesystem을 다시 마운트한 후 다시 비교하세요:
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
이 변경은 cgroup enforcement가 존재하는지 여부보다는 프로세스가 무엇을 볼 수 있는지에 관한 것입니다.

## 보안 영향

cgroup namespace는 **visibility-hardening layer**로 이해하는 것이 가장 좋습니다. 이것만으로는 컨테이너에 writable cgroup mounts, 광범위한 capabilities 또는 위험한 cgroup v1 환경이 있는 경우 breakout을 막을 수 없습니다. 그러나 host cgroup namespace가 공유되면 프로세스는 시스템 구성 방식에 대해 더 많은 정보를 얻으며, host-relative cgroup paths를 다른 관찰 결과와 연결하기가 더 쉬워질 수 있습니다.

**cgroup v2**에서는 delegation rules가 더 엄격하기 때문에 namespace가 조금 더 중요해집니다. hierarchy가 `nsdelegate`와 함께 mount되면 kernel은 cgroup namespaces를 delegation boundaries로 취급합니다. 즉, ancestor control files는 delegatee의 접근 범위 밖에 있어야 하며, namespace root에서의 writes는 `cgroup.procs`, `cgroup.threads`, `cgroup.subtree_control`과 같은 delegation-safe files로 제한됩니다.<sup>[[2]](#references)</sup> 그렇다고 해서 namespace 자체가 escape primitive가 되는 것은 아니지만, compromised workload가 무엇을 inspect할 수 있는지와 어디에서 안전하게 sub-cgroups를 생성할 수 있는지를 변경합니다.

따라서 이 namespace는 일반적인 container breakout writeups에서 주로 다뤄지는 핵심 요소는 아니지만, host information leak를 최소화하고 cgroup delegation을 제한한다는 더 광범위한 목표에 기여합니다.

## 악용

즉각적인 악용 가치는 대부분 reconnaissance입니다. host cgroup namespace가 공유된 경우, 표시되는 paths를 비교하고 host를 드러내는 hierarchy 세부 정보를 찾아보십시오:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
쓰기 가능한 cgroup 경로도 노출되어 있다면, 해당 가시성을 위험한 레거시 인터페이스 검색과 결합하세요:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
네임스페이스 자체만으로 즉시 탈출할 수 있는 경우는 드물지만, cgroup 기반 abuse primitive를 테스트하기 전에 환경을 매핑하기 쉽게 만드는 경우가 많습니다.

빠르게 runtime 현실을 점검하면 공격 경로의 우선순위를 정하는 데도 도움이 됩니다. Docker는 `--cgroupns=host|private`를 노출하며, Podman은 `host`, `private`, `container:<id>`, `ns:<path>`를 지원합니다. 특히 Podman에서는 기본값이 일반적으로 **cgroup v1에서는 `host`**이고 **cgroup v2에서는 `private`**이므로, cgroup 버전만 식별해도 전체 OCI config를 검사하기 전에 어떤 namespace 설정이 더 가능성 높은지 알 수 있습니다.

### Modern v2 Recon: Is This A Delegated Subtree?

Modern host에서는 현재 process가 중첩된 group을 생성할 수 있을 만큼의 visibility 또는 write access를 가진 delegated **cgroup v2** subtree 내부에 있는지가 중요한 질문인 경우가 많습니다:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
유용한 해석:

- `cgroup2fs`는 unified v2 hierarchy에 있다는 의미이므로, 기존 v1 전용 `release_agent` chains를 첫 번째 추측으로 삼아서는 안 됩니다.
- `cgroup.controllers`는 parent에서 사용할 수 있는 controllers를 보여 주며, 따라서 현재 subtree가 잠재적으로 children으로 확장할 수 있는 대상을 나타냅니다.
- `cgroup.subtree_control`은 descendants에 실제로 enabled된 controllers를 보여 줍니다.
- `cgroup.events`는 `populated=0/1`을 노출합니다. 이는 subtree가 비어 있는지 감시할 때 유용하지만, v1 `release_agent`와 같은 **host-code-execution primitive**는 아닙니다.

이미 다른 process namespace를 직접 inspect할 수 있을 만큼 충분한 privilege가 있다면 다음으로 views를 비교합니다:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### 전체 예시: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace만으로는 일반적으로 escape에 충분하지 않습니다. 실질적인 escalation은 host를 노출하는 cgroup paths가 writable cgroup v1 interfaces와 결합될 때 발생합니다:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
해당 파일에 접근할 수 있고 쓰기 권한도 있다면 [cgroups.md](../cgroups.md)의 전체 `release_agent` exploitation flow로 즉시 pivot하세요. 영향 범위는 container 내부에서 host code execution이 가능한 수준입니다.

쓰기 가능한 cgroup interfaces가 없다면 영향은 일반적으로 reconnaissance로 제한됩니다.

## Checks

이 명령어들의 목적은 해당 process가 private cgroup namespace view를 사용하는지, 또는 실제로 필요한 수준보다 더 많은 host hierarchy 정보를 학습하고 있는지를 확인하는 것입니다.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
여기서 중요한 점:

- namespace 식별자가 관심 대상인 host process와 일치하면 cgroup namespace가 공유되고 있을 수 있습니다.
- `/proc/self/cgroup`의 host를 노출하는 경로 또는 `mountinfo`의 상위 계층을 root로 하는 항목은 직접 exploit할 수 없더라도 reconnaissance에 유용합니다.
- `cgroup2fs`가 사용 중이라면 기존 v1 primitive가 여전히 존재한다고 가정하지 말고, delegation, 노출된 controller 및 쓰기 가능한 subtree에 집중해야 합니다.
- cgroup mount도 쓰기 가능한 경우에는 visibility 문제가 훨씬 더 중요해집니다.

cgroup namespace는 primary escape-prevention mechanism이 아니라 visibility-hardening layer로 간주해야 합니다. 불필요하게 host cgroup 구조를 노출하면 attacker에게 추가적인 reconnaissance 가치를 제공합니다.

## References

- [1] [cgroup_namespaces(7) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [2] [Control Group v2 — Linux Kernel 문서](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
