# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces는 container가 실제로는 host의 process tree일 뿐인데도 "자체 machine"처럼 느껴지게 만드는 kernel 기능입니다. 새로운 kernel을 생성하거나 모든 것을 virtualize하지는 않지만, kernel이 선택된 resource에 대한 서로 다른 view를 process group별로 제공할 수 있게 합니다. 이것이 container illusion의 핵심입니다. workload는 filesystem, process table, network stack, hostname, IPC resource, user/group identity model이 local한 것처럼 보이는 환경을 보지만, 실제 underlying system은 shared 상태입니다.

이 때문에 container의 작동 방식을 배울 때 대부분의 사람들이 가장 먼저 접하는 개념이 namespaces입니다. 동시에 namespaces는 가장 흔히 오해되는 개념 중 하나이기도 합니다. 독자들은 "namespaces가 있다"는 것이 "안전하게 격리되어 있다"는 의미라고 가정하는 경우가 많기 때문입니다. 실제로 namespace는 자신이 격리하도록 설계된 특정 resource class만 격리합니다. process가 private PID namespace를 가지고 있어도 writable host bind mount를 가지고 있다면 여전히 위험할 수 있습니다. private network namespace를 가지고 있어도 `CAP_SYS_ADMIN`을 유지하고 seccomp 없이 실행된다면 여전히 위험할 수 있습니다. Namespaces는 foundational layer이지만, 최종 boundary를 구성하는 여러 layer 중 하나일 뿐입니다.

## Namespace Types

Linux containers는 일반적으로 여러 namespace type에 동시에 의존합니다. **mount namespace**는 process에 별도의 mount table을 제공하므로 controlled filesystem view를 제공합니다. **PID namespace**는 process visibility와 numbering을 변경하여 workload가 자체 process tree를 보게 합니다. **network namespace**는 interface, route, socket, firewall state를 격리합니다. **IPC namespace**는 SysV IPC와 POSIX message queue를 격리합니다. **UTS namespace**는 hostname과 NIS domain name을 격리합니다. **user namespace**는 user와 group ID를 remap하므로 container 내부의 root가 반드시 host의 root를 의미하지는 않습니다. **cgroup namespace**는 visible cgroup hierarchy를 virtualize하며, **time namespace**는 최신 kernel에서 선택된 clock을 virtualize합니다.

각 namespace는 서로 다른 문제를 해결합니다. 따라서 practical container security analysis는 **어떤 namespace가 격리되어 있는지**와 **어떤 namespace가 의도적으로 host와 shared되었는지**를 확인하는 작업으로 귀결되는 경우가 많습니다.

## Host Namespace Sharing

많은 container breakout은 kernel vulnerability에서 시작하지 않습니다. 대신 operator가 isolation model을 의도적으로 약화하는 것에서 시작합니다. `--pid=host`, `--network=host`, `--userns=host` 예시는 host namespace sharing을 구체적으로 보여 주기 위해 사용한 **Docker/Podman-style CLI flags**입니다. 다른 runtime은 동일한 개념을 다른 방식으로 표현합니다. Kubernetes에서는 일반적으로 `hostPID: true`, `hostNetwork: true`, `hostIPC: true`와 같은 Pod setting으로 나타납니다. containerd 또는 CRI-O와 같은 lower-level runtime stack에서는 동일한 동작이 보통 동일한 이름의 user-facing flag가 아니라 생성된 OCI runtime configuration을 통해 설정됩니다. 이 모든 경우의 결과는 유사합니다. workload는 더 이상 기본적으로 격리된 namespace view를 받지 않습니다.

이 때문에 namespace review는 "process가 어떤 namespace 안에 있다"는 확인에서 멈춰서는 안 됩니다. 중요한 질문은 해당 namespace가 container에 private한지, sibling container와 shared되었는지, 아니면 host에 직접 joined되었는지입니다. Kubernetes에서는 동일한 개념이 `hostPID`, `hostNetwork`, `hostIPC`와 같은 flag로 나타납니다. Platform마다 이름은 달라지지만 risk pattern은 동일합니다. shared host namespace는 container가 가진 나머지 privilege와 접근 가능한 host state를 훨씬 더 중요하게 만듭니다.

## Inspection

가장 간단한 overview는 다음과 같습니다:
```bash
ls -l /proc/self/ns
```
각 항목은 inode와 유사한 식별자를 가진 symbolic link입니다. 두 프로세스가 동일한 namespace 식별자를 가리키면 해당 유형의 동일한 namespace에 속합니다. 따라서 `/proc`는 현재 프로세스와 시스템의 다른 관심 있는 프로세스를 비교하기에 매우 유용한 위치입니다.

다음과 같은 간단한 명령만으로도 시작하기에 충분한 경우가 많습니다:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
그곳에서 다음 단계는 container 프로세스를 host 또는 인접한 프로세스와 비교하여 네임스페이스가 실제로 private인지 확인하는 것입니다.

### Host에서 네임스페이스 인스턴스 열거

이미 host access가 있고 특정 유형의 서로 다른 네임스페이스가 몇 개 존재하는지 파악하려는 경우, `/proc`은 빠른 인벤토리를 제공합니다:
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
특정 namespace 식별자에 속한 프로세스를 찾으려면 `readlink` 대신 `ls -l`로 전환한 다음 대상 namespace 번호를 grep하세요:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
이 명령어들은 호스트가 하나의 격리된 워크로드를 실행 중인지, 여러 개의 격리된 워크로드를 실행 중인지, 아니면 공유 네임스페이스 인스턴스와 전용 네임스페이스 인스턴스가 혼합되어 있는지 판단하는 데 유용합니다.

### 대상 네임스페이스 진입

호출자에게 충분한 권한이 있는 경우, `nsenter`는 다른 프로세스의 네임스페이스에 참여하는 표준 방법입니다:
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
이러한 형식을 함께 나열하는 이유는 모든 assessment에 모든 형식이 필요해서가 아니라, operator가 all-namespaces 형식만 기억하는 대신 정확한 진입 syntax를 알고 있으면 namespace-specific post-exploitation이 훨씬 쉬워지는 경우가 많기 때문입니다.

## Runtime 기본값

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
| Docker Engine | 기본적으로 새로운 mount, PID, network, IPC, UTS namespace를 생성합니다. user namespace는 사용할 수 있지만 표준 rootful setup에서는 기본적으로 활성화되지 않습니다 | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | 기본적으로 새로운 namespace를 생성합니다. rootless Podman은 자동으로 user namespace를 사용하며, cgroup namespace 기본값은 cgroup version에 따라 달라집니다 | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | 기본적으로 Pod는 host PID, network 또는 IPC를 공유하지 않습니다. Pod networking은 각 개별 container가 아니라 Pod에 대해 private입니다. 지원되는 cluster에서는 `spec.hostUsers: false`를 통해 user namespace를 opt-in할 수 있습니다 | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / user-namespace opt-in 생략, privileged workload 설정 |
| containerd / CRI-O under Kubernetes | 일반적으로 Kubernetes Pod 기본값을 따릅니다 | Kubernetes 행과 동일합니다. 직접 지정하는 CRI/OCI spec에서도 host namespace join을 요청할 수 있습니다 |

주요 portability 규칙은 간단합니다. host namespace sharing이라는 **개념**은 runtime 전반에서 공통되지만, 그 **syntax**는 runtime마다 다릅니다.

{{#include ../../../../../banners/hacktricks-training.md}}
