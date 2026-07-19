# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

좋은 container assessment는 두 가지 질문에 동시에 답해야 합니다. 첫째, 현재 workload에서 attacker가 무엇을 할 수 있는가? 둘째, 이를 가능하게 만든 operator의 선택은 무엇인가? Enumeration tools는 첫 번째 질문에 도움을 주고, hardening guidance는 두 번째 질문에 도움을 줍니다. 두 내용을 한 페이지에 유지하면 이 섹션은 단순한 escape tricks 모음이 아니라 현장에서 참고할 수 있는 자료로 더 유용해집니다.

현대 환경에서 실무적으로 업데이트해야 할 점은, 오래된 container writeup 중 상당수가 암묵적으로 **rootful runtime**, **user namespace isolation 없음**, 그리고 대개 **cgroup v1**을 가정한다는 것입니다. 이러한 가정은 더 이상 안전하지 않습니다. 오래된 escape primitive를 검토하는 데 시간을 쓰기 전에, 먼저 workload가 rootless 또는 userns-remapped인지, host가 cgroup v2를 사용하는지, Kubernetes 또는 runtime이 현재 기본 seccomp 및 AppArmor profile을 적용하고 있는지 확인해야 합니다. 이러한 세부 사항에 따라 유명한 breakout이 여전히 적용되는지가 결정되는 경우가 많습니다.

## Enumeration Tools

container 환경을 빠르게 파악하는 데 여전히 유용한 tool은 다음과 같습니다.

- `linpeas`는 다양한 container 지표, mounted socket, capability set, 위험한 filesystem 및 breakout 단서를 식별할 수 있습니다.
- `CDK`는 특히 container 환경에 초점을 맞추며 enumeration과 일부 자동화된 escape check를 포함합니다.
- `amicontained`는 가볍고 container restriction, capability, namespace 노출 및 가능성 높은 breakout class를 식별하는 데 유용합니다.
- `deepce`는 breakout 중심의 check를 제공하는 또 다른 container 전용 enumerator입니다.
- `grype`는 runtime escape analysis만이 아니라 image-package vulnerability review까지 assessment에 포함할 때 유용합니다.
- `Tracee`는 static posture만으로는 부족하고 **runtime evidence**가 필요할 때 유용하며, 특히 의심스러운 process execution, file access 및 container-aware event 수집에 적합합니다.
- `Inspektor Gadget`은 pod, container, namespace 및 기타 상위 수준 개념과 연결된 eBPF 기반 visibility가 필요한 Kubernetes 및 Linux-host investigation에 유용합니다.

이러한 tool의 가치는 확실성이 아니라 속도와 범위에 있습니다. 대략적인 posture를 빠르게 파악하는 데 도움을 주지만, 중요한 finding은 실제 runtime, namespace, capability 및 mount model을 기준으로 수동 해석해야 합니다.

## Hardening Priorities

가장 중요한 hardening 원칙은 개념적으로 단순하지만, 구현 방식은 platform마다 다릅니다. privileged container를 피하십시오. mounted runtime socket을 피하십시오. 매우 구체적인 이유가 없다면 container에 writable host path를 제공하지 마십시오. 가능한 경우 user namespace 또는 rootless execution을 사용하십시오. 모든 capability를 drop한 뒤 workload에 실제로 필요한 것만 다시 추가하십시오. application compatibility 문제를 해결하기 위해 seccomp, AppArmor 및 SELinux를 비활성화하지 말고 활성화된 상태로 유지하십시오. compromised container가 host의 service를 쉽게 deny할 수 없도록 resource를 제한하십시오.

Image 및 build hygiene는 runtime posture만큼 중요합니다. minimal image를 사용하고, 자주 rebuild하며, scan하고, 가능한 경우 provenance를 요구하며, secret을 layer에 포함하지 마십시오. non-root로 실행되고 작은 image를 사용하며 syscall 및 capability surface가 좁은 container는, 사전에 debugging tool이 설치된 대형 convenience image를 host와 동등한 root 권한으로 실행하는 경우보다 훨씬 쉽게 방어할 수 있습니다.

Kubernetes의 경우 현재 hardening baseline은 많은 operator가 여전히 생각하는 것보다 더 명확한 기준을 제시합니다. 기본 제공되는 **Pod Security Standards**는 `restricted`를 "current best practice" profile로 간주합니다. `allowPrivilegeEscalation`은 `false`여야 하고, workload는 non-root로 실행되어야 하며, seccomp는 `RuntimeDefault` 또는 `Localhost`로 명시적으로 설정되어야 하고, capability set은 적극적으로 drop해야 합니다. Assessment 중에는 이 점이 중요합니다. `warn` 또는 `audit` label만 사용하는 cluster는 문서상으로는 hardened 상태처럼 보이지만, 실제로는 여전히 위험한 pod를 허용할 수 있기 때문입니다.

## Modern Triage Questions

Escape 전용 페이지를 살펴보기 전에 다음의 간단한 질문에 답하십시오.

1. Workload는 **rootful**, **rootless** 또는 **userns-remapped** 중 무엇입니까?
2. Node는 **cgroup v1** 또는 **cgroup v2** 중 무엇을 사용합니까?
3. **seccomp** 및 **AppArmor/SELinux**가 명시적으로 구성되어 있습니까, 아니면 사용 가능한 경우에만 상속됩니까?
4. Kubernetes에서 namespace가 실제로 `baseline` 또는 `restricted`를 **enforcing**하고 있습니까, 아니면 warning/auditing만 수행합니까?

유용한 check:
```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```
여기서 중요한 점:

- `/proc/self/uid_map`에 컨테이너 root가 **높은 host UID 범위**에 매핑되어 있는 것으로 표시되면, 컨테이너의 root가 더 이상 host-root와 동등하지 않으므로 오래된 host-root writeup 중 다수는 관련성이 낮아집니다.
- `/sys/fs/cgroup`가 `cgroup2fs`라면 `release_agent` abuse와 같은 오래된 **cgroup v1** 전용 writeup을 더 이상 첫 번째 가설로 삼아서는 안 됩니다.
- seccomp와 AppArmor가 암묵적으로만 상속되는 경우, portability가 defenders가 예상하는 것보다 약할 수 있습니다. Kubernetes에서는 node defaults에 조용히 의존하는 것보다 `RuntimeDefault`를 명시적으로 설정하는 편이 더 강력한 경우가 많습니다.
- `supplementalGroupsPolicy`가 `Strict`로 설정되어 있으면, pod는 image 내부의 `/etc/group`에서 추가 group membership을 조용히 상속하지 않아야 하므로 group 기반 volume 및 file access 동작을 더 예측하기 쉬워집니다.
- `pod-security.kubernetes.io/enforce=restricted`와 같은 Namespace labels는 직접 확인할 가치가 있습니다. `warn`과 `audit`도 유용하지만, 위험한 pod가 생성되는 것을 막지는 않습니다.

## Runtime Baseline Triage

Runtime baseline은 컨테이너가 일반적인 격리 workload처럼 보이는지, 아니면 host에 영향을 줄 수 있는 control plane foothold처럼 보이는지를 빠르게 판단하는 과정입니다. 다음에 읽을 내용을 우선순위화할 수 있을 만큼 충분한 사실을 수집해야 합니다. 대상은 runtime socket abuse, host mounts, namespaces, cgroups, capabilities 또는 image-secret review가 될 수 있습니다.

workload 내부에서 유용한 checks:
```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
해석:

- `memory.max` / `pids.max`가 누락되었거나 제한 없이 설정되어 있으면, 완전한 escape가 없어도 blast radius 통제가 취약하다는 의미입니다.
- `NoNewPrivs: 0`인 root shell, 광범위한 capabilities, permissive한 seccomp가 함께 있으면 제한적인 non-root workload보다 훨씬 더 흥미로운 대상입니다.
- Runtime sockets와 writable host mounts는 이미 management 또는 filesystem control path를 노출하므로 일반적으로 kernel exploits보다 우선순위가 높습니다.
- 공유된 PID, network, IPC 또는 cgroup namespaces가 그 자체로 항상 full escape를 의미하지는 않지만, 다음 단계를 찾기 쉽게 만듭니다.

## Resource-Exhaustion Examples

Resource controls는 화려하지 않지만 compromise의 blast radius를 제한하므로 container security의 일부입니다. memory, CPU 또는 PID limits가 없으면 간단한 shell만으로도 host 또는 인접 workload의 성능을 저하시킬 수 있습니다.

Example host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
이 예시들은 모든 위험한 container 결과가 명확한 "escape"인 것은 아니라는 점을 보여 주기 때문에 유용합니다. 취약한 cgroup 제한만으로도 code execution이 실제 운영 환경에 영향을 미치는 결과로 이어질 수 있습니다.

Kubernetes 기반 환경에서는 DoS를 이론적인 문제로 간주하기 전에 resource controls가 아예 존재하는지도 확인해야 합니다:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening 도구

Docker 중심 환경에서는 `docker-bench-security`가 널리 인정된 benchmark 지침을 기준으로 일반적인 configuration 문제를 점검하므로, 호스트 측 audit baseline으로 여전히 유용합니다:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
이 도구는 threat modeling을 대체하지 않지만, 시간이 지나며 누적되는 부주의한 daemon, mount, network 및 runtime 기본 설정을 찾는 데에는 여전히 유용합니다.

Kubernetes 및 runtime 중심 환경에서는 static checks를 runtime visibility와 함께 사용하세요.

- `Tracee`는 container-aware runtime detection과 빠른 forensics에 유용하며, compromised workload가 실제로 무엇에 접근했는지 확인해야 할 때 사용할 수 있습니다.
- `Inspektor Gadget`은 assessment에서 kernel-level telemetry를 pods, containers, DNS activity, file execution 또는 network behavior에 매핑해야 할 때 유용합니다.

## 점검

assessment 중 첫 번째 빠른 점검에 다음 명령을 사용하세요:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
여기서 흥미로운 점:

- 광범위한 capabilities를 가진 root process와 `Seccomp: 0`은 즉시 주의해야 합니다.
- **1:1 UID map**도 가진 root process는 적절히 격리된 user namespace 내부의 "root"보다 훨씬 더 흥미롭습니다.
- `cgroup2fs`는 일반적으로 오래된 **cgroup v1** escape chain이 최우선으로 시작할 지점은 아니라는 의미인 반면, `memory.max` 또는 `pids.max`가 없다는 것은 여전히 취약한 blast-radius control을 가리킵니다.
- 의심스러운 mounts와 runtime sockets는 kernel exploit보다 impact에 도달하는 더 빠른 경로를 제공하는 경우가 많습니다.
- 취약한 runtime posture와 취약한 resource limits의 조합은 대개 단일한 isolated mistake라기보다 전반적으로 permissive한 container environment를 나타냅니다.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
