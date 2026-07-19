# 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

네임스페이스는 컨테이너가 실제로는 호스트 프로세스 트리일 뿐인데도 "자체 머신"처럼 느껴지게 만드는 kernel 기능입니다. 네임스페이스는 새로운 kernel을 생성하지 않으며 모든 것을 virtualize하지도 않지만, kernel이 선택된 리소스에 대한 서로 다른 뷰를 서로 다른 프로세스 그룹에 제공하도록 합니다. 이것이 컨테이너 illusion의 핵심입니다. workload는 underlying system이 공유되고 있더라도 로컬에 존재하는 것처럼 보이는 filesystem, process table, network stack, hostname, IPC resources, user/group identity model을 확인합니다.

이것이 대부분의 사람들이 컨테이너 작동 방식을 배울 때 네임스페이스를 첫 번째로 접하는 개념인 이유입니다. 동시에 네임스페이스는 가장 흔하게 오해되는 개념 중 하나이기도 합니다. 독자들은 흔히 "has namespaces"가 "is safely isolated"를 의미한다고 가정하기 때문입니다. 실제로 네임스페이스는 해당 네임스페이스가 설계된 특정 리소스 종류만 isolate합니다. 프로세스에 private PID namespace가 있어도 writable host bind mount를 가지고 있다면 여전히 위험할 수 있습니다. private network namespace가 있어도 `CAP_SYS_ADMIN`을 유지하고 seccomp 없이 실행된다면 여전히 위험할 수 있습니다. 네임스페이스는 foundational하지만, 최종 boundary를 구성하는 하나의 layer일 뿐입니다.

## 네임스페이스 유형

Linux containers는 일반적으로 여러 네임스페이스 유형을 동시에 사용합니다. **mount namespace**는 프로세스에 별도의 mount table을 제공하며, 그 결과 통제된 filesystem view를 제공합니다. **PID namespace**는 process visibility와 numbering을 변경하여 workload가 자체 process tree를 확인하도록 합니다. **network namespace**는 interfaces, routes, sockets, firewall state를 isolate합니다. **IPC namespace**는 SysV IPC와 POSIX message queues를 isolate합니다. **UTS namespace**는 hostname과 NIS domain name을 isolate합니다. **user namespace**는 user 및 group IDs를 remap하여 container 내부의 root가 반드시 host의 root를 의미하지 않도록 합니다. **cgroup namespace**는 표시되는 cgroup hierarchy를 virtualize하며, **time namespace**는 최신 kernel에서 선택된 clocks를 virtualize합니다.

각 네임스페이스는 서로 다른 문제를 해결합니다. 따라서 실용적인 container security analysis는 흔히 **어떤 네임스페이스가 isolated되어 있는지**와 **어떤 네임스페이스가 의도적으로 host와 shared되었는지**를 확인하는 과정이 됩니다.

## Host Namespace Sharing

많은 container breakouts는 kernel vulnerability에서 시작하지 않습니다. operator가 isolation model을 의도적으로 약화시키는 것에서 시작합니다. `--pid=host`, `--network=host`, `--userns=host` 예시는 여기서 host namespace sharing을 설명하기 위한 구체적인 **Docker/Podman-style CLI flags**입니다. 다른 runtimes는 동일한 개념을 다르게 표현합니다. Kubernetes에서는 일반적으로 `hostPID: true`, `hostNetwork: true`, `hostIPC: true`와 같은 Pod settings로 대응되는 기능이 나타납니다. containerd 또는 CRI-O와 같은 lower-level runtime stacks에서는 동일한 동작이 사용자에게 노출되는 동일한 이름의 flag가 아니라, 생성된 OCI runtime configuration을 통해 구현되는 경우가 많습니다. 이러한 모든 경우의 결과는 유사합니다. workload는 더 이상 기본 isolated namespace view를 받지 않습니다.

따라서 namespace reviews는 "the process is in some namespace"에서 절대 멈춰서는 안 됩니다. 중요한 질문은 해당 네임스페이스가 container에 private한지, sibling containers와 shared되었는지, 아니면 host에 직접 joined되었는지입니다. Kubernetes에서는 `hostPID`, `hostNetwork`, `hostIPC`와 같은 flags로 동일한 개념이 나타납니다. 플랫폼에 따라 이름은 달라지지만 risk pattern은 동일합니다. shared host namespace는 container의 남은 privileges와 접근 가능한 host state를 훨씬 더 중요하게 만듭니다.

## Inspection

가장 간단한 overview는 다음과 같습니다:
```bash
ls -l /proc/self/ns
```
각 항목은 inode와 유사한 식별자를 가진 symbolic link입니다. 두 프로세스가 동일한 namespace 식별자를 가리키면 해당 유형의 동일한 namespace에 속합니다. 따라서 `/proc`는 현재 프로세스와 시스템의 다른 흥미로운 프로세스를 비교하는 데 매우 유용한 위치입니다.

다음과 같은 간단한 명령만으로도 시작하기에 충분한 경우가 많습니다:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
그 다음 단계는 container process를 host 또는 인접한 process와 비교하여 namespace가 실제로 private한지 여부를 확인하는 것입니다.

### Host에서 Namespace 인스턴스 열거

이미 host access 권한이 있고 특정 유형의 서로 다른 namespace가 몇 개 존재하는지 파악하려는 경우, `/proc`를 통해 빠르게 목록을 확인할 수 있습니다:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
특정 namespace identifier에 속한 프로세스를 찾으려면 `readlink` 대신 `ls -l`로 전환하고 대상 namespace 번호를 grep하세요:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
이 명령어들은 호스트가 하나의 격리된 workload, 여러 개의 격리된 workload 또는 공유 namespace 인스턴스와 private namespace 인스턴스가 혼합된 환경 중 무엇을 실행 중인지 확인하는 데 유용합니다.

### Target Namespace 진입

호출자에게 충분한 권한이 있는 경우, `nsenter`는 다른 프로세스의 namespace에 참여하는 표준 방법입니다:
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
이러한 형식을 함께 나열한 이유는 모든 assessment에 이 형식이 전부 필요하기 때문이 아니라, operator가 all-namespaces 형식만 기억하는 대신 정확한 진입 syntax를 알고 있으면 namespace-specific post-exploitation이 훨씬 쉬워지는 경우가 많기 때문입니다.

## 페이지

다음 페이지에서는 각 namespace를 더 자세히 설명합니다:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

각 페이지를 읽을 때 다음 두 가지를 염두에 두세요. 첫째, 각 namespace는 한 종류의 view만 격리합니다. 둘째, 나머지 privilege model이 해당 격리를 여전히 의미 있게 유지할 때만 private namespace가 유용합니다.

## Runtime 기본값

| Runtime / platform | 기본 namespace 상태 | 일반적인 수동 약화 |
| --- | --- | --- |
| Docker Engine | 기본적으로 새로운 mount, PID, network, IPC, UTS namespace를 생성합니다. user namespace를 사용할 수 있지만, 표준 rootful setup에서는 기본적으로 활성화되지 않습니다. | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | 기본적으로 새로운 namespace를 생성하며, rootless Podman은 자동으로 user namespace를 사용합니다. cgroup namespace 기본값은 cgroup version에 따라 달라집니다. | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | 기본적으로 Pod는 host PID, network 또는 IPC를 공유하지 않습니다. Pod networking은 각 container가 아니라 Pod에 대해 private입니다. 지원되는 cluster에서는 `spec.hostUsers: false`를 사용해 user namespace를 opt-in할 수 있습니다. | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / user-namespace opt-in 생략, privileged workload 설정 |
| containerd / CRI-O under Kubernetes | 일반적으로 Kubernetes Pod 기본값을 따릅니다. | Kubernetes 행과 동일합니다. direct CRI/OCI spec에서도 host namespace join을 요청할 수 있습니다. |

주요 portability 규칙은 간단합니다. host namespace sharing이라는 **개념**은 runtime 전반에서 공통적이지만, 그 **syntax**는 runtime별로 다릅니다.
{{#include ../../../../../banners/hacktricks-training.md}}
