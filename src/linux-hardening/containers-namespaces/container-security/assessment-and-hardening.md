# 평가 및 강화

{{#include ../../../banners/hacktricks-training.md}}

## 개요

좋은 컨테이너 평가는 서로 연관된 두 가지 질문에 답해야 합니다. 첫째, 공격자는 현재 워크로드에서 무엇을 할 수 있는가? 둘째, 어떤 운영자 선택이 이를 가능하게 했는가? Enumeration 도구는 첫 번째 질문에 답하는 데 도움이 되고, hardening 지침은 두 번째 질문에 답하는 데 도움이 됩니다. 두 내용을 한 페이지에 함께 두면, 이 섹션은 단순한 escape 기법 목록이 아니라 현장 참고 자료로 더 유용해집니다.

최신 환경을 고려해 실무적으로 업데이트할 점은, 오래된 컨테이너 관련 글 중 상당수가 **rootful runtime**, **user namespace isolation 없음**, 그리고 대개 **cgroup v1**을 은연중에 전제한다는 것입니다. 이제는 이러한 전제를 안전하다고 볼 수 없습니다. 오래된 escape 기법을 살펴보느라 시간을 쓰기 전에, 워크로드가 rootless인지 또는 userns-remapped인지, 호스트가 cgroup v2를 사용하는지, Kubernetes나 runtime이 기본 seccomp 및 AppArmor 프로필을 적용하고 있는지 먼저 확인하세요. 이런 세부 사항에 따라 널리 알려진 breakout이 여전히 가능한지가 달라지는 경우가 많습니다.

## Enumeration 도구

컨테이너 환경을 빠르게 파악할 때 여전히 유용한 도구는 다음과 같습니다.

- `linpeas`는 다양한 컨테이너 지표, 마운트된 소켓, capability 집합, 위험한 파일시스템, breakout 단서를 찾아낼 수 있습니다.
- `CDK`는 컨테이너 환경에 특화되어 있으며 enumeration과 일부 자동화된 escape 검사를 제공합니다.
- `amicontained`는 가볍고, 컨테이너 제한, capability, namespace 노출, 가능성 있는 breakout 유형을 파악하는 데 유용합니다.
- `deepce`는 breakout 중심 검사 기능을 갖춘 또 다른 컨테이너 전용 enumerator입니다.
- 평가에 runtime escape 분석뿐 아니라 이미지 패키지 취약점 검토도 포함된다면 `grype`가 유용합니다.
- 정적 보안 상태만이 아니라 **runtime 증거**가 필요할 때, 특히 의심스러운 프로세스 실행, 파일 접근, 컨테이너 인식 이벤트 수집에 `Tracee`가 유용합니다.
- Kubernetes 및 Linux 호스트 조사에서 eBPF 기반 가시성을 Pod, 컨테이너, namespace 및 기타 상위 수준 개념과 연결해야 할 때 `Inspektor Gadget`이 유용합니다.

이러한 도구의 가치는 확실성이 아니라 속도와 범위에 있습니다. 대략적인 보안 상태를 빠르게 파악하는 데 도움이 되지만, 흥미로운 발견 사항은 실제 runtime, namespace, capability, mount 모델을 기준으로 수동 해석해야 합니다.

## Hardening 우선순위

가장 중요한 hardening 원칙은 개념적으로 간단하지만, 플랫폼마다 구현 방식은 다릅니다. privileged 컨테이너는 피하세요. runtime 소켓을 마운트하지 마세요. 특별히 필요한 이유가 없다면 컨테이너에 호스트 경로를 쓰기 가능하게 제공하지 마세요. 가능한 경우 user namespace 또는 rootless 실행을 사용하세요. 모든 capability를 제거하고, 워크로드에 꼭 필요한 것만 다시 추가하세요. 애플리케이션 호환성 문제를 해결하기 위해 seccomp, AppArmor, SELinux를 비활성화하지 말고 활성 상태로 유지하세요. 리소스를 제한해 침해된 컨테이너가 호스트의 서비스 거부를 손쉽게 유발하지 못하게 하세요.

이미지 및 빌드 위생도 runtime 보안 상태만큼 중요합니다. 최소 이미지를 사용하고, 자주 다시 빌드하며, 스캔하고, 가능한 경우 출처 증명을 요구하고, 이미지 레이어에 비밀 정보를 포함하지 마세요. non-root로 실행되고 이미지가 작으며 syscall 및 capability 표면이 좁은 컨테이너는, 호스트와 동등한 root 권한으로 디버깅 도구까지 사전 설치된 대형 편의성 이미지보다 훨씬 방어하기 쉽습니다.

Kubernetes의 최신 hardening 기준은 많은 운영자가 여전히 생각하는 것보다 더 엄격합니다. 내장된 **Pod Security Standards**는 `restricted`를 "현재 권장되는 모범 사례" 프로필로 취급합니다. `allowPrivilegeEscalation`은 `false`여야 하고, 워크로드는 non-root로 실행해야 하며, seccomp는 `RuntimeDefault` 또는 `Localhost`로 명시적으로 설정해야 하고, capability 집합은 적극적으로 제거해야 합니다. 평가 시 이는 중요합니다. `warn` 또는 `audit` 레이블만 사용하는 클러스터는 문서상으로는 보안이 강화된 것처럼 보여도 실제로는 위험한 Pod를 계속 허용할 수 있기 때문입니다.<sup>[[1]](#references)</sup>

Pod에 service-account token이 마운트되어 있다면 권한을 **대상 namespace별로** 평가하세요. 한 namespace의 Pod를 나열하는 규칙이 다른 namespace에서도 권한을 가진다는 뜻은 아닙니다. 다른 Pod에 마운트된 token은 권한이 다를 수 있습니다. 실제로 검토 중인 identity를 사용해 `kubectl auth can-i list pods -n <target-namespace>`와 `kubectl auth can-i list secrets -n <target-namespace>`를 실행하세요. Secret 목록 조회가 허용된다면 심각한 단서입니다. 목록 응답에는 Secret 내용이 포함될 수 있지만, 그렇다고 privileged token이 존재한다는 점이 입증되는 것은 아닙니다. 호스트에 접근하려면 추가로 사용할 수 있는 워크로드 생성 권한, 제안된 `hostPath` mount의 admission 허용, 그리고 의도한 파일 작업을 허용하는 노드/Pod 보안 컨텍스트가 필요합니다. Kubernetes의 [authorization checks](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) 및 [RBAC privilege-escalation guidance](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)를 참고하세요.

## 최신 Triage 질문

escape 전용 페이지를 살펴보기 전에 다음 질문에 답하세요.

1. 워크로드는 **rootful**, **rootless**, **userns-remapped** 중 무엇인가요?
2. 노드는 **cgroup v1** 또는 **cgroup v2** 중 무엇을 사용하나요?
3. **seccomp**와 **AppArmor/SELinux**는 명시적으로 설정되어 있나요, 아니면 사용 가능한 경우에만 상속되나요?
4. Kubernetes에서 namespace가 실제로 `baseline` 또는 `restricted`를 **enforcing**하고 있나요, 아니면 경고/감사만 하고 있나요?

유용한 검사:

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

여기서 주목할 점은 다음과 같습니다.

- `/proc/self/uid_map`에 컨테이너의 root가 **높은 호스트 UID 범위**에 매핑되어 있다고 표시되면, 오래된 호스트 root 관련 글은 덜 유효해집니다. 컨테이너의 root가 더 이상 호스트 root와 동등하지 않기 때문입니다.
- `/sys/fs/cgroup`이 `cgroup2fs`라면, `release_agent` 악용과 같은 오래된 **cgroup v1** 관련 글을 가장 먼저 의심해서는 안 됩니다.
- seccomp와 AppArmor가 명시적으로 설정되지 않고 상속만 된다면, 이식성이 방어자가 예상하는 것보다 떨어질 수 있습니다. Kubernetes에서는 노드 기본값에 조용히 의존하는 것보다 `RuntimeDefault`를 명시적으로 설정하는 편이 대체로 더 강력합니다.
- `supplementalGroupsPolicy`가 `Strict`로 설정되어 있다면, 파드는 이미지 내부의 `/etc/group`에서 추가 그룹 멤버십을 조용히 상속하지 않아야 합니다. 따라서 그룹 기반 볼륨 및 파일 액세스 동작을 더 예측하기 쉽습니다.
- `pod-security.kubernetes.io/enforce=restricted`와 같은 네임스페이스 레이블은 직접 확인할 가치가 있습니다. `warn`과 `audit`도 유용하지만, 위험한 파드의 생성을 막지는 못합니다.

## 런타임 기준선 초기 분류

런타임 기준선 점검은 컨테이너가 일반적인 격리 워크로드처럼 보이는지, 아니면 호스트에 영향을 미칠 수 있는 제어 플레인 발판처럼 보이는지 빠르게 파악하는 절차입니다. 다음에 살펴볼 항목의 우선순위를 정할 수 있도록, 런타임 소켓 악용, 호스트 마운트, 네임스페이스, cgroups, capabilities 또는 이미지 시크릿 검토에 필요한 사실을 충분히 수집해야 합니다.

워크로드 내부에서 유용한 점검:

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

- `memory.max` / `pids.max`가 없거나 제한이 없으면, 명확한 escape가 없어도 피해 범위를 제한하는 통제가 취약하다는 뜻입니다.
- `NoNewPrivs: 0`, 광범위한 capabilities, permissive한 seccomp를 갖춘 root shell은 권한이 제한된 non-root workload보다 훨씬 주목할 만합니다.
- Runtime socket과 쓰기 가능한 host mount는 이미 관리 경로나 파일시스템 제어 경로를 노출하므로 보통 kernel exploit보다 우선순위가 높습니다.
- PID, network, IPC 또는 cgroup namespace를 공유한다고 해서 항상 그 자체로 완전한 escape가 되는 것은 아니지만, 다음 단계를 찾기가 더 쉬워집니다.

## 리소스 고갈 예시

리소스 제어는 화려하지는 않지만, 침해의 피해 범위를 제한하므로 container security의 일부입니다. memory, CPU 또는 PID 제한이 없으면 간단한 shell만으로도 host나 인접 workload의 성능을 저하시킬 수 있습니다.

host에 영향을 미치는 테스트 예시:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

이러한 예시가 유용한 이유는 위험한 컨테이너 결과가 모두 깔끔한 "escape"로 이어지는 것은 아니라는 점을 보여주기 때문입니다. cgroup 제한이 허술하면 코드 실행이 실제 운영상의 영향으로 이어질 수 있습니다.

Kubernetes 기반 환경에서는 DoS를 이론적인 문제로 치부하기 전에 리소스 제어 기능이 존재하는지도 확인하세요:

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Hardening Tooling

Docker 중심 환경에서는 `docker-bench-security`가 널리 인정받는 벤치마크 지침을 기준으로 일반적인 구성 문제를 점검하므로 호스트 측 감사 기준선으로 여전히 유용합니다. 구성 벤치마크로는 설치된 런타임이 새로 공개된 취약점의 영향을 받는지 확인할 수 없으므로, 런타임 보안 권고는 별도로 검토해야 합니다. <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

이 도구가 threat modeling을 대체하지는 않지만, 시간이 지나며 누적되는 부주의한 daemon, mount, network 및 runtime 기본 설정을 찾는 데 여전히 유용합니다.

Kubernetes 및 runtime 중심 환경에서는 정적 검사와 runtime 가시성을 함께 활용하세요.

- `Tracee`는 컨테이너를 인식하는 runtime 탐지와 신속한 포렌식에 유용하며, 침해된 워크로드가 실제로 어떤 항목에 접근했는지 확인할 때 도움이 됩니다.
- `Inspektor Gadget`은 평가 과정에서 커널 수준 원격 측정 데이터를 pod, 컨테이너, DNS 활동, 파일 실행 또는 네트워크 동작에 매핑해야 할 때 유용합니다.

## Checks

평가 중 빠른 1차 점검 명령으로 다음을 사용하세요:

```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```

여기서 주목할 점:

- 광범위한 capabilities를 보유하고 `Seccomp: 0`인 root 프로세스는 즉시 주의를 기울여야 합니다.
- **1:1 UID map**도 사용하는 root 프로세스는 제대로 격리된 user namespace 내부의 "root"보다 훨씬 더 주목할 만합니다.
- `cgroup2fs`는 오래된 **cgroup v1** escape chain 다수가 최선의 시작점이 아닐 가능성이 크다는 뜻입니다. 반면 `memory.max` 또는 `pids.max`가 없으면 blast radius 제어가 취약하다는 신호입니다.
- 의심스러운 mount와 runtime socket은 흔히 커널 exploit보다 더 빠르게 영향을 줄 수 있는 경로를 제공합니다.
- 취약한 runtime 설정과 취약한 리소스 제한이 함께 나타나면, 대개 단일한 실수라기보다 전반적으로 permissive한 컨테이너 환경임을 의미합니다.

## References

- [1] [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
