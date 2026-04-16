# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

좋은 container assessment는 두 가지 병렬 질문에 답해야 합니다. 첫째, 현재 workload에서 attacker가 무엇을 할 수 있는가? 둘째, 어떤 operator 선택이 그것을 가능하게 했는가? Enumeration tools는 첫 번째 질문에, hardening guidance는 두 번째 질문에 도움이 됩니다. 두 가지를 한 페이지에 함께 두면 이 섹션은 escape trick 목록이 아니라 field reference로서 더 유용해집니다.

현대 환경에서 유용한 실제 업데이트 하나는, 많은 오래된 container writeup이 조용히 **rootful runtime**, **no user namespace isolation**, 그리고 종종 **cgroup v1**을 가정한다는 점입니다. 이러한 가정은 이제 안전하지 않습니다. 오래된 escape primitive에 시간을 쓰기 전에, 먼저 workload가 rootless인지 userns-remapped인지, host가 cgroup v2를 사용하는지, 그리고 Kubernetes 또는 runtime이 기본 seccomp 및 AppArmor profiles를 적용하고 있는지 확인하세요. 이런 세부 사항이 유명한 breakout이 여전히 적용되는지를 결정하는 경우가 많습니다.

## Enumeration Tools

다음의 여러 tools는 container 환경을 빠르게 특성 파악하는 데 여전히 유용합니다:

- `linpeas` can identify many container indicators, mounted sockets, capability sets, dangerous filesystems, and breakout hints.
- `CDK`는 특히 container 환경에 초점을 맞추며, enumeration과 일부 자동화된 escape checks를 포함합니다.
- `amicontained`는 가볍고, container restrictions, capabilities, namespace 노출, 그리고 가능성이 높은 breakout classes를 식별하는 데 유용합니다.
- `deepce`는 breakout-oriented checks를 제공하는 또 다른 container-focused enumerator입니다.
- `grype`는 assessment에 runtime escape analysis뿐 아니라 image-package vulnerability review가 포함될 때 유용합니다.
- `Tracee`는 static posture만이 아니라 **runtime evidence**가 필요할 때 유용하며, 특히 의심스러운 process execution, file access, 그리고 container-aware event collection에 적합합니다.
- `Inspektor Gadget`는 Kubernetes와 Linux-host 조사에서 pods, containers, namespaces, 그리고 다른 상위 수준 개념에 연결된 eBPF-backed visibility가 필요할 때 유용합니다.

이 tools의 가치는 속도와 coverage이지, 확실성은 아닙니다. 이들은 rough posture를 빠르게 드러내 주지만, 흥미로운 findings는 여전히 실제 runtime, namespace, capability, mount model과 대조하여 수동으로 해석해야 합니다.

## Hardening Priorities

가장 중요한 hardening 원칙은 platform마다 구현은 다르지만 개념적으로는 매우 단순합니다. privileged containers를 피하세요. mounted runtime sockets를 피하세요. 매우 구체적인 이유가 없는 한 container에 writable host paths를 주지 마세요. 가능하다면 user namespaces 또는 rootless execution을 사용하세요. 모든 capabilities를 drop하고 workload가 실제로 필요한 것만 다시 추가하세요. 애플리케이션 호환성 문제를 해결하려고 seccomp, AppArmor, SELinux를 비활성화하지 말고 활성화된 상태로 유지하세요. 리소스를 제한하여 compromised container가 host에 trivially deny of service를 일으키지 못하게 하세요.

Image와 build hygiene는 runtime posture만큼 중요합니다. minimal images를 사용하고, 자주 rebuild하며, scan하고, 가능하다면 provenance를 요구하고, layers에서 secrets를 제외하세요. non-root로 실행되고 작은 image와 좁은 syscall 및 capability surface를 가진 container는, debugging tools가 미리 설치된 host-equivalent root로 실행되는 큰 convenience image보다 방어하기 훨씬 쉽습니다.

Kubernetes의 경우, 현재 hardening baseline은 많은 operator가 여전히 가정하는 것보다 더 opinionated합니다. 내장된 **Pod Security Standards**는 `restricted`를 "current best practice" profile로 취급합니다: `allowPrivilegeEscalation`은 `false`여야 하고, workload는 non-root로 실행되어야 하며, seccomp는 명시적으로 `RuntimeDefault` 또는 `Localhost`로 설정되어야 하고, capability sets는 공격적으로 drop되어야 합니다. assessment 중에는 이것이 중요합니다. 왜냐하면 `warn` 또는 `audit` label만 사용하는 cluster는 문서상으로는 hardened해 보여도 실제로는 여전히 risky pods를 허용할 수 있기 때문입니다.

## Modern Triage Questions

escape-specific pages로 들어가기 전에, 다음의 빠른 질문에 답하세요:

1. workload가 **rootful**, **rootless**, 또는 **userns-remapped**인가?
2. node가 **cgroup v1** 또는 **cgroup v2**를 사용하는가?
3. **seccomp**와 **AppArmor/SELinux**가 명시적으로 구성되어 있는가, 아니면 사용 가능할 때 단순히 상속되는가?
4. Kubernetes에서 namespace가 실제로 `baseline` 또는 `restricted`를 **enforcing**하는가, 아니면 warning/auditing만 하는가?

유용한 checks:
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
What is interesting here:

- If `/proc/self/uid_map` shows container root mapped to a **high host UID range**, many older host-root writeups become less relevant because root in the container is no longer host-root equivalent.
- If `/sys/fs/cgroup` is `cgroup2fs`, old **cgroup v1**-specific writeups such as `release_agent` abuse should no longer be your first guess.
- If seccomp and AppArmor are only inherited implicitly, portability can be weaker than defenders expect. In Kubernetes, explicitly setting `RuntimeDefault` is often stronger than silently relying on node defaults.
- If `supplementalGroupsPolicy` is set to `Strict`, the pod should avoid silently inheriting extra group memberships from `/etc/group` inside the image, which makes group-based volume and file access behavior more predictable.
- Namespace labels such as `pod-security.kubernetes.io/enforce=restricted` are worth checking directly. `warn` and `audit` are useful, but they do not stop a risky pod from being created.

## Resource-Exhaustion Examples

Resource controls are not glamorous, but they are part of container security because they limit the blast radius of compromise. Without memory, CPU, or PID limits, a simple shell may be enough to degrade the host or neighboring workloads.

Example host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
이러한 예제는 모든 위험한 container 결과가 깔끔한 "escape"는 아니라는 점을 보여주므로 유용하다. 약한 cgroup 제한도 code execution을 실제 운영상 영향으로 바꿀 수 있다.

Kubernetes-backed environments에서는 DoS를 이론적인 것으로만 보기 전에 resource controls가 아예 존재하는지도 확인하라:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Tooling

Docker 중심 환경에서는 `docker-bench-security`가 여전히 유용한 host-side audit baseline입니다. 이는 널리 인정되는 benchmark guidance를 기준으로 일반적인 configuration issues를 점검하기 때문입니다:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
도구는 threat modeling의 대체재는 아니지만, 시간이 지나며 누적되는 부주의한 daemon, mount, network, runtime 기본값을 찾아내는 데 여전히 유용하다.

Kubernetes와 runtime이 많은 환경에서는 static checks를 runtime visibility와 함께 사용하라:

- `Tracee`는 container-aware runtime detection과, compromised workload가 실제로 무엇을 건드렸는지 확인해야 할 때 빠른 forensics에 유용하다.
- `Inspektor Gadget`은 assessment가 kernel-level telemetry를 pods, containers, DNS activity, file execution, 또는 network behavior에 다시 매핑해야 할 때 유용하다.

## Checks

assessment 동안 빠른 1차 명령으로 다음을 사용하라:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
여기서 흥미로운 점은 다음과 같습니다:

- broad capabilities와 `Seccomp: 0`을 가진 root process는 즉시 주의가 필요합니다.
- **1:1 UID map**도 가진 root process는, properly isolated user namespace 안의 "root"보다 훨씬 더 흥미롭습니다.
- `cgroup2fs`는 보통 오래된 **cgroup v1** escape chains가 최선의 시작점이 아님을 의미하지만, `memory.max`나 `pids.max`가 없다면 여전히 weak blast-radius controls을 시사합니다.
- Suspicious mounts와 runtime sockets는 종종 kernel exploit보다 더 빠르게 impact로 이어지는 경로를 제공합니다.
- weak runtime posture와 weak resource limits의 조합은 대개 단일한 isolated mistake보다는 전반적으로 permissive한 container environment를 의미합니다.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
