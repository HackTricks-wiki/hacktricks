# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

The cgroup namespace는 cgroups를 대체하지 않으며, 그 자체로 resource limits를 강제하지도 않습니다. 대신 process에 **cgroup 계층이 어떻게 보이는지**를 바꿉니다. 다른 말로 하면, visible cgroup path 정보를 virtualize해서 workload가 전체 host hierarchy가 아니라 container-scoped view를 보게 합니다.

이것은 주로 visibility와 information-reduction 기능입니다. 환경을 self-contained처럼 보이게 하고 host의 cgroup layout에 대해 더 적게 드러내는 데 도움이 됩니다. 별것 아닌 것처럼 들릴 수 있지만, 불필요한 host structure visibility는 reconnaissance에 도움이 되고 environment-dependent exploit chains를 단순화할 수 있으므로 여전히 중요합니다.

## Operation

private cgroup namespace가 없으면 process는 host-relative cgroup paths를 볼 수 있고, 이는 machine hierarchy를 필요한 것보다 더 많이 노출할 수 있습니다. private cgroup namespace가 있으면 `/proc/self/cgroup`와 관련 관찰값들이 container 자체의 view에 더 가깝게 localized 됩니다. 이는 workload가 더 깔끔하고 host를 덜 드러내는 환경을 보게 하고 싶어 하는 modern runtime stacks에서 특히 유용합니다.

virtualization은 `/proc/<pid>/mountinfo`에도 영향을 주며, `/proc/<pid>/cgroup`만 영향을 주는 것은 아닙니다. 다른 cgroup-namespace perspective에서 다른 process를 읽을 때, namespace root 밖의 path는 앞에 `../` components가 붙은 형태로 표시됩니다. 이는 delegated subtree보다 위를 보고 있다는 유용한 단서입니다. labs와 post-exploitation에서 유용한 세부 사항 하나는, 새로 생성된 cgroup namespace는 종종 `mountinfo`가 새 root를 깔끔하게 반영하기 전에 **그 namespace 내부에서 cgroupfs remount**가 필요하다는 점입니다. 그렇지 않으면 `/..` 같은 mount root가 여전히 보일 수 있는데, 이는 namespace 자체는 이미 바뀌었더라도 상속된 mount가 여전히 ancestor-rooted view를 노출하고 있다는 뜻입니다.

## Lab

You can inspect a cgroup namespace with:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
`mountinfo`가 새로운 cgroup-namespace root를 더 명확하게 보여주게 하려면, 새 namespace 안에서 cgroup filesystem을 다시 mount하고 다시 비교하세요:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
런타임 동작을 다음과 비교하세요:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
변경의 핵심은 cgroup enforcement가 존재하느냐가 아니라, 프로세스가 무엇을 볼 수 있느냐에 더 가깝습니다.

## Security Impact

cgroup namespace는 **visibility-hardening layer**로 이해하는 것이 가장 좋습니다. 이것만으로는 컨테이너에 writable cgroup mounts, broad capabilities, 또는 위험한 cgroup v1 환경이 있으면 breakout을 막지 못합니다. 그러나 host cgroup namespace가 shared되어 있으면, 프로세스는 시스템이 어떻게 조직되어 있는지에 대해 더 많은 정보를 알게 되고, 다른 관찰 결과와 host-relative cgroup path를 맞춰 보기 쉬워질 수 있습니다.

**cgroup v2**에서는 delegation 규칙이 더 엄격하기 때문에 namespace의 중요성이 조금 더 커집니다. hierarchy가 `nsdelegate`로 mounted되어 있으면, kernel은 cgroup namespaces를 delegation boundary로 취급합니다: ancestor control files는 delegatee의 reach 밖에 있어야 하며, namespace root에서의 writes는 `cgroup.procs`, `cgroup.threads`, `cgroup.subtree_control` 같은 delegation-safe files로 제한됩니다. 이것이 namespace를 그 자체로 escape primitive로 만들지는 않지만, compromised workload가 무엇을 inspect할 수 있는지와 어디에 sub-cgroups를 안전하게 만들 수 있는지를 바꿉니다.

따라서 이 namespace는 보통 container breakout writeups의 주인공은 아니지만, host information leakage를 최소화하고 cgroup delegation을 제한하는 더 큰 목표에는 여전히 기여합니다.

## Abuse

즉각적인 abuse 가치는 대부분 reconnaissance입니다. host cgroup namespace가 shared되어 있다면, visible path를 비교하고 host를 드러내는 hierarchy details를 찾아보세요:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
writable cgroup 경로도 노출되어 있다면, 그 가시성을 위험한 legacy 인터페이스 검색과 결합하세요:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
namespace 자체가 즉시 escape를 제공하는 경우는 드물지만, cgroup 기반 abuse primitive를 테스트하기 전에 환경을 매핑하기는 훨씬 쉽게 만들어 줍니다.

간단한 runtime 현실 점검도 attack path의 우선순위를 정하는 데 도움이 됩니다. Docker는 `--cgroupns=host|private`를 노출하고, Podman은 `host`, `private`, `container:<id>`, `ns:<path>`를 지원합니다. 특히 Podman에서는 기본값이 보통 **cgroup v1에서는 `host`**이고 **cgroup v2에서는 `private`**이므로, 전체 OCI config를 보기 전에 cgroup 버전만 확인해도 어떤 namespace posture가 더 유력한지 알 수 있습니다.

### Modern v2 Recon: Is This A Delegated Subtree?

현대 호스트에서 흥미로운 질문은 종종 `release_agent`가 아니라, 현재 process가 중첩 그룹을 만들 수 있을 만큼의 visibility 또는 write access를 가진 delegated **cgroup v2** subtree 안에 있는지 여부입니다:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
유용한 해석:

- `cgroup2fs`는 unified v2 hierarchy에 있다는 뜻이므로, classic v1-only `release_agent` chain은 더 이상 첫 번째 가정이 되어서는 안 됩니다.
- `cgroup.controllers`는 parent에서 어떤 controller를 사용할 수 있는지 보여주며, 따라서 현재 subtree가 children 쪽으로 무엇을 fan out할 수 있는지 나타냅니다.
- `cgroup.subtree_control`은 descendants에 대해 실제로 어떤 controller가 enabled되어 있는지 보여줍니다.
- `cgroup.events`는 `populated=0/1`을 노출하는데, subtree가 비었는지 확인하는 데 유용하지만, v1 `release_agent`처럼 host-code-execution primitive는 **아닙니다**.

이미 다른 process namespace를 직접 inspect할 만큼 충분한 privilege가 있다면, 다음과 같이 views를 비교하세요:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Full Example: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace만으로는 보통 escape에 충분하지 않습니다. 실제 escalation은 호스트가 드러나는 cgroup 경로가 writable cgroup v1 interface와 결합될 때 발생합니다:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
If those files are reachable and writable, pivot immediately into the full `release_agent` exploitation flow from [cgroups.md](../cgroups.md). The impact is host code execution from inside the container.

쓰기 가능한 cgroup 인터페이스가 없으면, 영향은 보통 reconnaissance에 제한됩니다.

## Checks

이 명령들의 목적은 프로세스가 private cgroup namespace view를 가지고 있는지, 아니면 실제로 필요 이상으로 host hierarchy에 대해 더 많은 정보를 얻고 있는지 확인하는 것입니다.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
What is interesting here:

- 네임스페이스 식별자가 관심 있는 host process와 일치하면, cgroup namespace가 공유될 수 있다.
- `/proc/self/cgroup`의 host를 드러내는 path 또는 `mountinfo`의 ancestor-rooted entry는 직접적으로 exploit 가능하지 않더라도 유용한 reconnaissance이다.
- `cgroup2fs`가 사용 중이면, 예전 v1 primitive가 여전히 존재한다고 가정하기보다 delegation, visible controllers, writable subtree에 집중하라.
- cgroup mount도 writable하면, visibility 질문이 훨씬 더 중요해진다.

cgroup namespace는 primary escape-prevention mechanism이라기보다 visibility-hardening layer로 취급해야 한다. host cgroup structure를 불필요하게 노출하면 attacker에게 reconnaissance value를 더해준다.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
