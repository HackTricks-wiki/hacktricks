# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs`는 `execve()`를 통해 프로세스가 더 많은 privilege를 얻는 것을 막는 kernel hardening 기능입니다. 실제로는 플래그가 설정된 뒤에는 setuid binary, setgid binary, 또는 Linux file capabilities가 있는 file을 실행해도 프로세스가 이미 가지고 있던 privilege 이상은 얻지 못합니다. containerized 환경에서는 특히 중요한데, 많은 privilege-escalation chain이 이미지 안에서 실행 시 privilege가 바뀌는 executable을 찾는 데 의존하기 때문입니다.

방어 관점에서 `no_new_privs`는 namespaces, seccomp, capability dropping의 대체재가 아닙니다. 이는 보강 계층입니다. code execution을 이미 얻은 뒤의 특정 follow-up escalation 분류를 차단합니다. 그래서 image에 helper binaries, package-manager artifacts, 또는 부분 compromise와 결합되면 위험한 legacy tools가 들어 있는 환경에서 특히 유용합니다.

## Operation

이 동작의 핵심 kernel flag는 `PR_SET_NO_NEW_PRIVS`입니다. 이것이 프로세스에 설정되면 이후 `execve()` 호출로 privilege를 증가시킬 수 없습니다. 중요한 점은 프로세스가 여전히 binary를 실행할 수는 있다는 것입니다. 단지 kernel이 원래 허용했을 privilege boundary를 그 binary로 넘는 용도로는 사용할 수 없을 뿐입니다.

kernel 동작은 또한 **상속되고 되돌릴 수 없습니다**: 한 task가 `no_new_privs`를 설정하면 이 비트는 `fork()`, `clone()`, `execve()` 전반에 걸쳐 상속되며, 나중에 해제할 수 없습니다. assessment에서 유용한 이유는 container process에서 `NoNewPrivs: 1`이 보이면, 완전히 다른 process tree를 보고 있는 경우가 아니라면 자식들도 보통 같은 모드로 유지되어야 한다는 뜻이기 때문입니다.

Kubernetes 중심 환경에서는 `allowPrivilegeEscalation: false`가 container process에 대해 이 동작에 매핑됩니다. Docker와 Podman 계열 runtime에서는 보통 security option을 통해 명시적으로 활성화합니다. OCI layer에서는 같은 개념이 `process.noNewPrivileges`로 나타납니다.

## Important Nuances

`no_new_privs`는 exec-time privilege gain만 막고, 모든 privilege change를 막지는 않습니다. 특히:

- setuid 및 setgid 전환은 `execve()`를 통해 더 이상 동작하지 않습니다
- file capabilities는 `execve()` 시 permitted set에 추가되지 않습니다
- AppArmor나 SELinux 같은 LSMs는 `execve()` 이후 constraint를 완화하지 않습니다
- 이미 보유한 privilege는 여전히 이미 보유한 privilege입니다

마지막 점은 운영상 중요합니다. 프로세스가 이미 root로 실행 중이거나, 이미 위험한 capability를 가지고 있거나, 이미 강력한 runtime API 또는 writable host mount에 접근할 수 있다면 `no_new_privs`를 설정해도 그 노출을 무력화하지는 못합니다. 이것은 privilege-escalation chain에서 흔한 다음 단계 하나를 제거할 뿐입니다.

또한 이 flag는 `execve()`에 의존하지 않는 privilege change는 막지 못한다는 점도 알아두어야 합니다. 예를 들어, 이미 충분히 privileged한 task는 `setuid(2)`를 직접 호출하거나 Unix socket을 통해 privileged file descriptor를 받을 수 있습니다. 그래서 `no_new_privs`는 [seccomp](seccomp.md), capability sets, namespace exposure와 함께 읽어야 하며, 단독 해답으로 보면 안 됩니다.

## Lab

현재 process state를 검사합니다:
```bash
grep NoNewPrivs /proc/self/status
```
런타임이 해당 플래그를 활성화한 container와 비교해보자:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
강화된 workload에서는 결과에 `NoNewPrivs: 1`이 표시되어야 합니다.

또한 setuid binary를 대상으로 실제 효과를 확인할 수도 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
비교의 요점은 `su`가 보편적으로 exploitable하다는 것이 아니다. 같은 이미지라도 `execve()`가 여전히 privilege boundary를 넘어갈 수 있는지에 따라 매우 다르게 동작할 수 있다는 점이다.

## Security Impact

`no_new_privs`가 없으면, container 안의 foothold가 setuid helper나 file capabilities가 있는 binary를 통해 여전히 upgraded될 수 있다. 이것이 있으면, exec 이후의 privilege 변화는 차단된다. 이 효과는 애초에 애플리케이션이 전혀 필요로 하지 않았던 여러 utility를 포함한 broad base images에서 특히 중요하다.

중요한 seccomp 상호작용도 있다. unprivileged task는 일반적으로 filter mode에서 seccomp filter를 설치하기 전에 `no_new_privs`를 설정해야 한다. 이것이 hardened container에서 종종 `Seccomp`와 `NoNewPrivs`가 함께 활성화되어 보이는 이유 중 하나다. attacker 관점에서는 둘 다 보인다면 대개 환경이 우연이 아니라 의도적으로 구성되었다는 뜻이다.

## Misconfigurations

가장 흔한 문제는 호환 가능한 환경에서 control을 그냥 활성화하지 않는 것이다. Kubernetes에서는 `allowPrivilegeEscalation`을 켜 둔 상태로 두는 것이 흔한 운영 실수다. Docker와 Podman에서는 관련 security option을 생략하면 같은 효과가 난다. 또 다른 반복적인 실패 모드는 container가 "not privileged"이기 때문에 exec-time privilege transition은 자동으로 무의미하다고 가정하는 것이다.

더 미묘한 Kubernetes 함정은 container가 `privileged`이거나 `CAP_SYS_ADMIN`을 가지고 있을 때 `allowPrivilegeEscalation: false`가 사람들이 기대하는 방식으로는 **적용되지 않는다**는 점이다. Kubernetes API는 이런 경우 `allowPrivilegeEscalation`이 사실상 항상 true라고 문서화한다. 실제로는 이 필드를 최종 posture의 신호 중 하나로만 봐야 하며, runtime이 결국 `NoNewPrivs: 1` 상태가 되었다는 보증으로 보면 안 된다.

## Abuse

`no_new_privs`가 설정되어 있지 않다면, 첫 번째 질문은 이미지에 여전히 privilege를 올릴 수 있는 binary가 있는지 여부다:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
흥미로운 결과에는 다음이 포함됩니다:

- `NoNewPrivs: 0`
- `su`, `mount`, `passwd` 같은 setuid helper 또는 배포판별 admin tool
- network 또는 filesystem privilege를 부여하는 file capabilities가 있는 binaries

실제 assessment에서는 이런 결과만으로 working escalation이 입증되지는 않지만, 다음에 정확히 테스트해야 할 binaries를 식별해 줍니다.

Kubernetes에서는 YAML intent가 kernel reality와 일치하는지도 확인하십시오:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
흥미로운 조합은 다음과 같습니다:

- Pod spec에서는 `allowPrivilegeEscalation: false` 이지만 container에서는 `NoNewPrivs: 0`
- `cap_sys_admin`이 존재하여 Kubernetes 필드의 신뢰도가 훨씬 떨어지는 경우
- `Seccomp: 0` 및 `NoNewPrivs: 0`으로, 이는 보통 단일한 고립된 실수라기보다 전반적으로 약화된 runtime posture를 의미합니다

### Full Example: setuid를 통한 in-container privilege escalation

이 control은 보통 host escape를 직접 막기보다 **in-container privilege escalation**을 방지합니다. `NoNewPrivs`가 `0`이고 setuid helper가 존재한다면, 명시적으로 테스트하세요:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
알려진 setuid 바이너리가 존재하고 정상 동작한다면, 권한 전환을 유지하는 방식으로 실행해 보세요:
```bash
/bin/su -c id 2>/dev/null
```
이것만으로는 컨테이너를 탈출하지는 않지만, 컨테이너 내부의 low-privilege foothold를 container-root로 바꿀 수 있으며, 이는 종종 mounts, runtime sockets, 또는 kernel-facing interfaces를 통한 나중의 host escape를 위한 전제 조건이 됩니다.

## Checks

이 checks의 목표는 exec-time privilege gain이 차단되어 있는지, 그리고 image에 차단되지 않았을 경우 의미가 있을 helpers가 여전히 포함되어 있는지를 확인하는 것입니다.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
What is interesting here:

- `NoNewPrivs: 1` is usually the safer result.
- `NoNewPrivs: 0` means setuid and file-cap based escalation paths remain relevant.
- `NoNewPrivs: 1` plus `Seccomp: 2` is a common sign of a more intentional hardening posture.
- A Kubernetes manifest that says `allowPrivilegeEscalation: false` is useful, but the kernel status is the ground truth.
- A minimal image with few or no setuid/file-cap binaries gives an attacker fewer post-exploitation options even when `no_new_privs` is missing.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 활성화되지 않음 | `--security-opt no-new-privileges=true`로 명시적으로 활성화; daemon 전역 기본값도 `dockerd --no-new-privileges`로 설정 가능 | 플래그를 생략, `--privileged` |
| Podman | 기본적으로 활성화되지 않음 | `--security-opt no-new-privileges` 또는 동등한 security configuration으로 명시적으로 활성화 | 옵션을 생략, `--privileged` |
| Kubernetes | workload policy에 의해 제어됨 | `allowPrivilegeEscalation: false`가 효과를 요청하지만, `privileged: true`와 `CAP_SYS_ADMIN`은 사실상 true로 유지함 | `allowPrivilegeEscalation: true`, `privileged: true`, `CAP_SYS_ADMIN` 추가 |
| containerd / CRI-O under Kubernetes | Kubernetes workload settings / OCI `process.noNewPrivileges`를 따름 | 보통 Pod security context에서 상속되어 OCI runtime config로 변환됨 | Kubernetes 행과 동일 |

이 보호는 런타임이 지원하지 않아서가 아니라, 단순히 아무도 활성화하지 않았기 때문에 없는 경우가 많다.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
