# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs`는 `execve()`를 통해 process가 더 많은 privilege를 획득하지 못하도록 방지하는 kernel hardening 기능입니다. 실질적으로 이 flag가 설정되면 setuid binary, setgid binary 또는 Linux file capabilities가 설정된 file을 실행해도 process가 이미 보유한 privilege를 초과하는 추가 privilege가 부여되지 않습니다. Containerized 환경에서는 많은 privilege-escalation chain이 실행 시 privilege를 변경하는 executable을 image 내부에서 찾는 것에 의존하므로 이것이 중요합니다.

Defensive 관점에서 `no_new_privs`는 namespaces, seccomp 또는 capability dropping을 대체하지 않습니다. 이는 보강 계층입니다. 이미 code execution을 획득한 이후 발생하는 특정 follow-up escalation class를 차단합니다. 따라서 image에 helper binary, package-manager artifact 또는 부분적인 compromise와 결합될 경우 위험한 legacy tool이 포함된 환경에서 특히 유용합니다.

## Operation

이 동작의 기반이 되는 kernel flag는 `PR_SET_NO_NEW_PRIVS`입니다. process에 이 flag가 설정되면 이후의 `execve()` 호출로 privilege를 증가시킬 수 없습니다. 중요한 점은 process가 여전히 binary를 실행할 수 있다는 것입니다. 단지 kernel이 원래 허용했을 privilege boundary를 해당 binary를 사용해 넘어갈 수 없을 뿐입니다.<sup>[[1]](#references)</sup>

Kernel 동작은 **상속되며 되돌릴 수 없습니다**. task가 `no_new_privs`를 설정하면 해당 bit는 `fork()`, `clone()` 및 `execve()`를 통해 상속되며 이후 해제할 수 없습니다.<sup>[[1]](#references)</sup> 이는 assessment에서 유용합니다. Container process에 `NoNewPrivs: 1`이 하나라도 있으면 완전히 다른 process tree를 확인하는 경우가 아닌 한 descendant process도 일반적으로 해당 mode를 유지한다는 의미이기 때문입니다.

Kubernetes 중심 환경에서는 `allowPrivilegeEscalation: false`가 container process에 대해 이 동작으로 매핑됩니다.<sup>[[2]](#references)</sup> Docker 및 Podman style runtime에서는 일반적으로 security option을 통해 명시적으로 활성화합니다. OCI layer에서는 동일한 개념이 `process.noNewPrivileges`로 나타납니다.

## Important Nuances

`no_new_privs`는 **exec-time** privilege gain을 차단하지만 모든 privilege 변경을 차단하는 것은 아닙니다.<sup>[[1]](#references)</sup> 구체적으로 다음과 같습니다.

- setuid 및 setgid transition은 `execve()`에서 작동하지 않음
- file capabilities는 `execve()`에서 permitted set에 추가되지 않음
- AppArmor 또는 SELinux와 같은 LSM은 `execve()` 이후 constraint를 완화하지 않음
- 이미 보유한 privilege는 여전히 보유한 privilege임

마지막 항목은 operation 측면에서 중요합니다. process가 이미 root로 실행 중이거나, 이미 위험한 capability를 보유하고 있거나, 이미 강력한 runtime API 또는 writable host mount에 접근할 수 있다면 `no_new_privs`를 설정해도 해당 exposure가 무력화되지 않습니다. 이는 privilege-escalation chain에서 흔히 사용되는 **다음 단계** 하나만 제거합니다.

또한 이 flag는 `execve()`에 의존하지 않는 privilege 변경을 차단하지 않습니다.<sup>[[1]](#references)</sup> 예를 들어 이미 충분한 privilege를 가진 task는 여전히 `setuid(2)`를 직접 호출하거나 Unix socket을 통해 privileged file descriptor를 전달받을 수 있습니다. 따라서 `no_new_privs`는 standalone 해답이 아니라 [seccomp](seccomp.md), capability sets 및 namespace exposure와 함께 검토해야 합니다.

## Lab

현재 process state를 확인합니다:
```bash
grep NoNewPrivs /proc/self/status
```
runtime이 flag를 활성화하는 container와 비교해 보세요:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
보안이 강화된 workload에서는 결과에 `NoNewPrivs: 1`이 표시되어야 합니다.

setuid binary에 대한 실제 효과도 확인할 수 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
비교의 요점은 `su`가 보편적으로 exploit 가능하다는 것이 아닙니다. 동일한 image라도 `execve()`가 여전히 privilege boundary를 넘을 수 있는지에 따라 매우 다르게 동작할 수 있다는 것입니다.

## Security Impact

`no_new_privs`가 없으면 container 내부의 foothold가 setuid helper 또는 file capabilities가 설정된 binary를 통해 여전히 privilege escalation될 수 있습니다. 반대로 활성화되어 있으면 exec 이후 발생하는 privilege 변경이 차단됩니다. 이 효과는 애플리케이션에 애초에 필요하지 않았던 여러 utility를 포함하는 광범위한 base image에서 특히 중요합니다.

seccomp와의 상호작용도 중요합니다. Unprivileged task는 일반적으로 filter mode에서 seccomp filter를 설치하기 전에 `no_new_privs`를 설정해야 합니다.<sup>[[1]](#references)</sup> 이것이 hardened container에서 `Seccomp`와 `NoNewPrivs`가 함께 활성화된 상태로 표시되는 경우가 많은 이유 중 하나입니다. Attacker 관점에서 둘 다 보인다는 것은 일반적으로 해당 environment가 우연히가 아니라 의도적으로 구성되었음을 의미합니다.

## Misconfigurations

가장 흔한 문제는 해당 control과 호환되는 environment에서 이를 활성화하지 않는 것입니다. Kubernetes에서는 `allowPrivilegeEscalation`을 활성화된 상태로 두는 것이 흔한 기본 운영 실수입니다. Docker와 Podman에서는 관련 security option을 생략하는 것이 동일한 효과를 냅니다. 또 다른 반복적인 failure mode는 container가 "not privileged"이므로 exec 시점의 privilege transition이 자동으로 무관하다고 가정하는 것입니다.

더 미묘한 Kubernetes pitfall은 container가 `privileged`이거나 `CAP_SYS_ADMIN`을 가지고 있을 때 `allowPrivilegeEscalation: false`가 사람들이 예상하는 방식으로 적용되지 않는다는 점입니다. Kubernetes API 문서에는 이러한 경우 `allowPrivilegeEscalation`이 사실상 항상 true라고 명시되어 있습니다.<sup>[[2]](#references)</sup> 실제로 이는 해당 field를 최종 posture의 하나의 signal로 취급해야 하며, runtime이 최종적으로 `NoNewPrivs: 1`이 되었다는 보장으로 보아서는 안 된다는 의미입니다.

## Abuse

`no_new_privs`가 설정되지 않았다면, 첫 번째 질문은 image에 여전히 privilege를 높일 수 있는 binary가 포함되어 있는지 여부입니다.
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
흥미로운 결과에는 다음이 포함됩니다:

- `NoNewPrivs: 0`
- `su`, `mount`, `passwd` 또는 배포판별 admin tools와 같은 setuid helpers
- network 또는 filesystem privileges를 부여하는 file capabilities가 있는 binaries

실제 assessment에서 이러한 findings만으로는 작동하는 escalation을 입증할 수 없지만, 다음에 테스트할 가치가 있는 binaries를 정확히 식별할 수 있습니다.

Kubernetes에서는 YAML의 의도와 kernel의 실제 상태가 일치하는지도 확인하세요:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
흥미로운 조합은 다음과 같습니다:

- Pod spec에는 `allowPrivilegeEscalation: false`가 설정되어 있지만 컨테이너에는 `NoNewPrivs: 0`이 설정된 경우
- `cap_sys_admin`이 존재하여 Kubernetes field를 훨씬 덜 신뢰할 수 있는 경우
- `Seccomp: 0`과 `NoNewPrivs: 0`이 함께 설정되어 있어, 단일한 실수가 아니라 전반적으로 약화된 runtime posture를 나타내는 경우

### 전체 예시: setuid를 통한 컨테이너 내부 privilege escalation

이 control은 일반적으로 host escape를 직접 방지하기보다는 **컨테이너 내부 privilege escalation**을 방지합니다. `NoNewPrivs`가 `0`이고 setuid helper가 존재한다면 이를 명시적으로 테스트합니다:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
알려진 setuid binary가 존재하고 정상적으로 작동한다면, privilege transition이 유지되는 방식으로 실행해 보세요:
```bash
/bin/su -c id 2>/dev/null
```
이 자체로 container에서 escape할 수 있는 것은 아니지만, container 내부의 low-privilege foothold를 container-root로 전환할 수 있으며, 이는 이후 mounts, runtime sockets 또는 kernel-facing interfaces를 통한 host escape의 prerequisite가 되는 경우가 많습니다.

## 점검

이 점검의 목표는 exec-time privilege gain이 차단되어 있는지, 그리고 차단되어 있지 않을 경우 중요한 helper가 image에 여전히 포함되어 있는지를 확인하는 것입니다.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
여기서 주목할 점:

- `NoNewPrivs: 1`이 일반적으로 더 안전한 결과입니다.
- `NoNewPrivs: 0`이면 setuid 및 file-cap 기반 escalation 경로가 여전히 유효합니다.
- `NoNewPrivs: 1`과 `Seccomp: 2`가 함께 표시되면 더 의도적인 hardening 상태라는 일반적인 신호입니다.
- Kubernetes manifest에서 `allowPrivilegeEscalation: false`라고 지정하는 것은 유용하지만, 최종 기준은 kernel 상태입니다.
- setuid/file-cap binary가 거의 없거나 전혀 없는 minimal image는 `no_new_privs`가 누락된 경우에도 attacker에게 더 적은 post-exploitation 옵션을 제공합니다.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 활성화되지 않음 | `--security-opt no-new-privileges=true`로 명시적으로 활성화하며, `dockerd --no-new-privileges`를 통한 daemon-wide default도 존재함 | flag 생략, `--privileged` |
| Podman | 기본적으로 활성화되지 않음 | `--security-opt no-new-privileges` 또는 이에 상응하는 security configuration으로 명시적으로 활성화함 | option 생략, `--privileged` |
| Kubernetes | workload policy로 제어됨 | `allowPrivilegeEscalation: false`는 해당 효과를 요청하지만, `privileged: true` 및 `CAP_SYS_ADMIN`이 있으면 실질적으로 true로 유지됨 | `allowPrivilegeEscalation: true`, `privileged: true`, `CAP_SYS_ADMIN` 추가 |
| containerd / CRI-O under Kubernetes | Kubernetes workload settings / OCI `process.noNewPrivileges`를 따름 | 일반적으로 Pod security context에서 상속되어 OCI runtime config로 변환됨 | Kubernetes 행과 동일 |

이 protection은 runtime에 지원 기능이 없어서가 아니라, 단순히 아무도 활성화하지 않았기 때문에 누락되는 경우가 많습니다.

## References

- [1] [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
