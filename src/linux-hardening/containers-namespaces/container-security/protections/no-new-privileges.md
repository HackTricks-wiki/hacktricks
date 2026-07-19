# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs`는 `execve()`를 수행하는 동안 프로세스가 더 많은 권한을 획득하지 못하도록 하는 kernel hardening 기능입니다. 실질적으로 이 flag가 설정되면 setuid binary, setgid binary 또는 Linux file capabilities가 설정된 파일을 실행해도 프로세스가 이미 보유한 권한을 초과하는 추가 권한이 부여되지 않습니다. Containerized 환경에서 이는 중요한데, 많은 privilege-escalation chain이 실행될 때 권한을 변경하는 executable을 image 내부에서 찾는 것에 의존하기 때문입니다.

Defensive 관점에서 `no_new_privs`는 namespaces, seccomp 또는 capability dropping을 대체하지 않습니다. 이는 보강 계층입니다. 이미 code execution을 획득한 이후 발생할 수 있는 특정 follow-up escalation class를 차단합니다. 따라서 images에 helper binaries, package-manager artifacts 또는 partial compromise와 결합될 경우 위험해질 수 있는 legacy tools가 포함된 환경에서 특히 유용합니다.

## 동작

이 동작을 담당하는 kernel flag는 `PR_SET_NO_NEW_PRIVS`입니다. 프로세스에 한 번 설정되면 이후 `execve()` 호출로 privilege를 증가시킬 수 없습니다. 중요한 점은 프로세스가 여전히 binaries를 실행할 수 있다는 것입니다. 단지 kernel이 원래 허용했을 privilege boundary를 해당 binaries를 사용해 넘을 수 없을 뿐입니다.

kernel 동작은 **상속되며 되돌릴 수 없습니다**. task가 `no_new_privs`를 설정하면 해당 bit는 `fork()`, `clone()`, `execve()`를 거쳐 상속되며 이후 해제할 수 없습니다. 이는 assessment에서 유용한데, container process에 `NoNewPrivs: 1`이 설정되어 있으면 완전히 다른 process tree를 확인하는 경우가 아닌 한 descendants도 일반적으로 해당 mode를 유지한다는 의미이기 때문입니다.

Kubernetes 중심 환경에서는 `allowPrivilegeEscalation: false`가 container process에 대해 이 동작으로 매핑됩니다. Docker 및 Podman style runtimes에서는 일반적으로 security option을 통해 명시적으로 활성화합니다. OCI layer에서는 동일한 개념이 `process.noNewPrivileges`로 나타납니다.

## 중요한 세부 사항

`no_new_privs`는 **exec-time** privilege gain을 차단하지만 모든 privilege change를 차단하지는 않습니다. 특히 다음과 같습니다.

- setuid 및 setgid transition은 `execve()`에서 동작하지 않음
- file capabilities는 `execve()`에서 permitted set에 추가되지 않음
- AppArmor 또는 SELinux와 같은 LSM은 `execve()` 이후 constraints를 완화하지 않음
- 이미 보유한 privilege는 그대로 이미 보유한 privilege임

마지막 항목은 운영 측면에서 중요합니다. 프로세스가 이미 root로 실행 중이거나, 이미 위험한 capability를 보유하고 있거나, 이미 강력한 runtime API 또는 writable host mount에 접근할 수 있다면 `no_new_privs`를 설정해도 해당 exposure가 무력화되지 않습니다. 이는 privilege-escalation chain에서 흔한 **next step** 하나만 제거합니다.

또한 이 flag는 `execve()`에 의존하지 않는 privilege change를 차단하지 않습니다. 예를 들어 이미 충분한 privilege를 가진 task는 여전히 `setuid(2)`를 직접 호출하거나 Unix socket을 통해 privileged file descriptor를 전달받을 수 있습니다. 따라서 `no_new_privs`는 standalone answer가 아니라 [seccomp](seccomp.md), capability sets 및 namespace exposure와 함께 검토해야 합니다.

## Lab

현재 process state를 확인합니다:
```bash
grep NoNewPrivs /proc/self/status
```
runtime이 해당 flag를 활성화하는 컨테이너와 비교해 보세요:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
강화된 workload에서는 결과에 `NoNewPrivs: 1`이 표시되어야 합니다.

setuid binary에 대한 실제 효과도 다음과 같이 확인할 수 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
비교의 핵심은 `su`가 어디서나 exploit 가능하다는 뜻이 아닙니다. 동일한 image라도 `execve()`가 여전히 privilege boundary를 넘어가는 것이 허용되는지에 따라 매우 다르게 동작할 수 있다는 뜻입니다.

## Security Impact

`no_new_privs`가 없으면 container 내부의 foothold가 setuid helpers 또는 file capabilities가 설정된 binaries를 통해 여전히 upgrade될 수 있습니다. 이 옵션이 있으면 exec 이후 발생하는 privilege changes가 차단됩니다. 이러한 효과는 application에 애초에 필요하지 않았던 많은 utilities를 포함하는 광범위한 base images에서 특히 중요합니다.

seccomp와의 상호작용도 중요합니다. 일반적으로 unprivileged tasks가 filter mode에서 seccomp filter를 설치하려면 먼저 `no_new_privs`가 설정되어 있어야 합니다. hardened containers에서 `Seccomp`와 `NoNewPrivs`가 함께 enabled로 표시되는 이유 중 하나가 이것입니다. attacker 관점에서 둘 다 보인다면, 대개 해당 environment가 실수로가 아니라 의도적으로 configured되었다는 뜻입니다.

## Misconfigurations

가장 흔한 문제는 해당 control과 호환되는 environments에서 이를 단순히 enabled하지 않는 것입니다. Kubernetes에서는 `allowPrivilegeEscalation`을 enabled 상태로 두는 것이 흔한 기본 operational mistake입니다. Docker와 Podman에서는 관련 security option을 생략하는 것이 같은 효과를 냅니다. 또 다른 반복되는 failure mode는 container가 "not privileged"이므로 exec-time privilege transitions가 자동으로 무관하다고 가정하는 것입니다.

더 미묘한 Kubernetes pitfall은 container가 `privileged`이거나 `CAP_SYS_ADMIN`을 보유한 경우 `allowPrivilegeEscalation: false`가 사람들이 예상하는 방식으로 **honored되지 않는다**는 점입니다. Kubernetes API 문서에는 이러한 경우 `allowPrivilegeEscalation`이 사실상 항상 true라고 설명되어 있습니다. 실제로는 이 field를 최종 posture에서 하나의 signal로 취급해야 하며, runtime이 결국 `NoNewPrivs: 1`로 설정되었다는 guarantee로 간주해서는 안 됩니다.

## Abuse

`no_new_privs`가 설정되지 않았다면, 첫 번째 질문은 image에 privilege를 여전히 raise할 수 있는 binaries가 포함되어 있는지 여부입니다:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
흥미로운 결과에는 다음이 포함됩니다:

- `NoNewPrivs: 0`
- `su`, `mount`, `passwd` 또는 배포판별 admin tools와 같은 setuid helpers
- network 또는 filesystem privileges를 부여하는 file capabilities가 있는 binaries

실제 assessment에서 이러한 findings만으로 작동하는 escalation이 입증되는 것은 아니지만, 다음에 테스트할 가치가 있는 binaries를 정확히 식별할 수 있습니다.

Kubernetes에서는 YAML intent가 kernel reality와 일치하는지도 확인해야 합니다:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
흥미로운 조합은 다음과 같습니다:

- Pod spec에 `allowPrivilegeEscalation: false`가 있지만 컨테이너에는 `NoNewPrivs: 0`이 설정된 경우
- `cap_sys_admin`이 존재하여 Kubernetes field의 신뢰성이 크게 떨어지는 경우
- `Seccomp: 0` 및 `NoNewPrivs: 0`이 설정되어 단일한 isolated mistake가 아니라 전반적으로 약화된 runtime posture를 나타내는 경우

### 전체 예시: setuid를 통한 컨테이너 내부 권한 상승

이 control은 일반적으로 host escape를 직접 방지하기보다는 **컨테이너 내부 권한 상승**을 방지합니다. `NoNewPrivs`가 `0`이고 setuid helper가 존재한다면 이를 명시적으로 테스트하십시오:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
알려진 setuid binary가 존재하고 정상적으로 작동한다면, 권한 전환이 유지되는 방식으로 실행해 보세요:
```bash
/bin/su -c id 2>/dev/null
```
이것만으로 container를 escape할 수 있는 것은 아니지만, container 내부의 low-privilege foothold를 container-root로 전환할 수 있으며, 이는 이후 mounts, runtime sockets 또는 kernel-facing interfaces를 통한 host escape의 prerequisite가 되는 경우가 많습니다.

## Checks

이 checks의 목적은 exec-time privilege gain이 차단되어 있는지, 그리고 차단되어 있지 않은 경우 중요한 역할을 할 수 있는 helpers가 image에 여전히 포함되어 있는지를 확인하는 것입니다.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
여기서 중요한 점:

- `NoNewPrivs: 1`은 일반적으로 더 안전한 결과입니다.
- `NoNewPrivs: 0`이면 setuid 및 file-cap 기반 권한 상승 경로가 여전히 유효합니다.
- `NoNewPrivs: 1`과 `Seccomp: 2`가 함께 나타나는 것은 더 의도적인 hardening 상태의 일반적인 징후입니다.
- `allowPrivilegeEscalation: false`라고 지정된 Kubernetes manifest는 유용하지만, 실제 기준은 kernel 상태입니다.
- setuid/file-cap binary가 거의 없거나 전혀 없는 minimal image는 `no_new_privs`가 누락된 경우에도 attacker에게 더 적은 post-exploitation 옵션을 제공합니다.

## Runtime 기본값

| Runtime / platform | 기본 상태 | 기본 동작 | 일반적인 수동 약화 |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 활성화되지 않음 | `--security-opt no-new-privileges=true`로 명시적으로 활성화하며, `dockerd --no-new-privileges`를 통한 daemon 전체 기본값도 존재 | flag 생략, `--privileged` |
| Podman | 기본적으로 활성화되지 않음 | `--security-opt no-new-privileges` 또는 동등한 security configuration으로 명시적으로 활성화 | option 생략, `--privileged` |
| Kubernetes | workload policy로 제어됨 | `allowPrivilegeEscalation: false`는 해당 효과를 요청하지만, `privileged: true` 및 `CAP_SYS_ADMIN`이 있으면 실질적으로 true로 유지됨 | `allowPrivilegeEscalation: true`, `privileged: true`, `CAP_SYS_ADMIN` 추가 |
| Kubernetes에서의 containerd / CRI-O | Kubernetes workload 설정 / OCI `process.noNewPrivileges`를 따름 | 일반적으로 Pod security context에서 상속되며 OCI runtime config로 변환됨 | Kubernetes 행과 동일 |

이 protection이 없는 경우는 runtime에 지원 기능이 없어서가 아니라, 단순히 아무도 이를 활성화하지 않았기 때문인 경우가 많습니다.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
