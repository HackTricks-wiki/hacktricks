# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

**seccomp**는 커널이 프로세스에서 호출할 수 있는 syscall에 필터를 적용하도록 하는 메커니즘입니다. Container 환경에서는 일반적으로 filter mode로 사용되므로, 프로세스가 단순히 모호한 의미에서 "restricted" 상태로 표시되는 것이 아니라 구체적인 syscall 정책의 적용을 받습니다. 이는 많은 container breakout이 매우 특정한 커널 인터페이스에 접근해야 하기 때문에 중요합니다. 프로세스가 관련 syscall을 성공적으로 호출할 수 없다면 namespace나 capability의 세부 사항을 검토하기도 전에 많은 공격 유형이 사라집니다.

핵심적인 개념은 간단합니다. namespace는 **프로세스가 무엇을 볼 수 있는지** 결정하고, capability는 **프로세스가 명목상 시도할 수 있도록 허용된 권한 있는 작업이 무엇인지** 결정하며, seccomp는 **시도한 작업에 대한 syscall 진입점을 커널이 받아들이기라도 할지** 결정합니다. 이 때문에 seccomp는 capability만을 기준으로 보면 가능해 보이는 공격을 자주 방어합니다.

## Security Impact

많은 위험한 커널 공격 표면은 비교적 적은 수의 syscall을 통해서만 접근할 수 있습니다. Container hardening에서 반복적으로 중요한 예로는 `mount`, `unshare`, 특정 플래그와 함께 사용하는 `clone` 또는 `clone3`, `bpf`, `ptrace`, `keyctl`, `perf_event_open`이 있습니다. 이러한 syscall에 접근할 수 있는 attacker는 새로운 namespace를 생성하거나, 커널 subsystem을 조작하거나, 일반적인 application container에는 전혀 필요하지 않은 공격 표면과 상호작용할 수 있습니다.

이 때문에 default runtime seccomp profile이 매우 중요합니다. 이는 단순한 "추가 방어"가 아닙니다. 많은 환경에서 default runtime seccomp profile은 container가 커널 기능의 광범위한 부분을 사용할 수 있는지, 아니면 application에 실제로 필요한 것에 더 가까운 syscall 공격 표면으로 제한되는지를 결정합니다.

## Modes And Filter Construction

seccomp에는 역사적으로 아주 적은 syscall set만 사용할 수 있도록 남기는 strict mode가 있었지만, modern container runtime과 관련된 mode는 흔히 **seccomp-bpf**라고 부르는 seccomp filter mode입니다. 이 모델에서 커널은 syscall을 allow할지, errno와 함께 deny할지, trap할지, log할지, 또는 프로세스를 kill할지 결정하는 filter program을 평가합니다. Container runtime은 일반적인 application 동작을 계속 허용하면서도 위험한 syscall의 광범위한 class를 차단할 수 있을 만큼 표현력이 충분하기 때문에 이 메커니즘을 사용합니다.

두 가지 low-level 예제는 이 메커니즘을 추상적인 것이 아니라 구체적인 것으로 이해하는 데 유용합니다. Strict mode는 예전의 "최소한의 syscall set만 살아남는" 모델을 보여줍니다:
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
최종 `open`은 strict mode의 최소 허용 목록에 포함되지 않기 때문에 프로세스가 종료됩니다.

libseccomp filter 예시는 최신 policy 모델을 더 명확하게 보여 줍니다:
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
대부분의 독자가 runtime seccomp 프로파일을 생각할 때 떠올려야 하는 정책 유형이 바로 이것입니다.

## 실습

컨테이너에서 seccomp가 활성화되어 있는지 확인하는 간단한 방법은 다음과 같습니다:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
기본 프로필이 일반적으로 제한하는 작업을 시도해 볼 수도 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
컨테이너가 일반적인 기본 seccomp profile에서 실행 중이면 `unshare` 스타일 작업이 차단되는 경우가 많습니다. 이는 image 내부에 userspace tool이 존재하더라도 해당 tool에 필요한 kernel 경로를 사용하지 못할 수 있음을 보여 주므로 유용한 시연입니다.
컨테이너가 일반적인 기본 seccomp profile에서 실행 중이면 image 내부에 userspace tool이 존재하는 경우에도 `unshare` 스타일 작업이 차단되는 경우가 많습니다.

프로세스 상태를 더 일반적으로 확인하려면 다음을 실행합니다:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Runtime 사용

Docker는 기본 및 custom seccomp profile을 모두 지원하며, 관리자는 `--security-opt seccomp=unconfined`를 사용해 이를 비활성화할 수 있습니다. Podman도 유사한 지원을 제공하며, 일반적으로 매우 합리적인 기본 보안 상태에서 seccomp를 rootless execution과 함께 사용합니다. Kubernetes는 workload configuration을 통해 seccomp를 노출하며, 일반적으로 `RuntimeDefault`가 적절한 baseline이고 `Unconfined`는 편의상 사용하는 toggle이 아니라 정당화가 필요한 예외로 취급해야 합니다.

containerd 및 CRI-O 기반 환경에서는 정확한 경로가 더 여러 계층으로 구성되지만, 원칙은 동일합니다. 상위 engine 또는 orchestrator가 수행할 작업을 결정하고, runtime은 최종적으로 container process에 적용할 seccomp policy를 설치합니다. 결과는 여전히 kernel에 전달되는 최종 runtime configuration에 따라 달라집니다.

### Custom Policy 예제

Docker 및 유사한 engine은 JSON에서 custom seccomp profile을 로드할 수 있습니다. 다른 모든 작업은 허용하면서 `chmod`를 거부하는 최소 예제는 다음과 같습니다:
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
적용 대상:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
명령이 `Operation not permitted` 오류와 함께 실패하는 것은 제한이 단순한 일반 파일 권한이 아니라 syscall policy에서 비롯된다는 것을 보여 줍니다. 실제 hardening에서는 일반적으로 작은 blacklist를 사용하는 permissive default보다 allowlist가 더 강력합니다.

## Misconfigurations

가장 단순하지만 심각한 실수는 애플리케이션이 default policy에서 실패했다는 이유로 seccomp를 **unconfined**로 설정하는 것입니다. 이는 troubleshooting 중에 흔히 발생하며, 영구적인 해결책으로는 매우 위험합니다. filter가 사라지면 특히 강력한 capabilities가 있거나 host namespace sharing이 함께 사용되는 경우, syscall 기반 breakout primitive에 다시 접근할 수 있게 됩니다.

또 다른 흔한 문제는 blog나 내부 workaround에서 복사한 뒤 신중하게 검토하지 않은 **custom permissive profile**을 사용하는 것입니다. 일부 팀은 profile을 "애플리케이션이 중단되지 않도록 하는 것"에 초점을 맞춰 구성했기 때문에, "애플리케이션에 실제로 필요한 것만 부여하는 것"이 아니라 거의 모든 위험한 syscall을 그대로 유지하기도 합니다. 세 번째 오해는 non-root containers에서는 seccomp가 덜 중요하다고 생각하는 것입니다. 실제로 process가 UID 0이 아니더라도 상당한 kernel attack surface가 여전히 관련됩니다.

## Abuse

seccomp가 없거나 심각하게 약화되어 있다면, attacker는 namespace-creation syscall을 호출하거나 `bpf` 또는 `perf_event_open`을 통해 접근 가능한 kernel attack surface를 확장하거나, `keyctl`을 악용할 수 있습니다. 또한 이러한 syscall 경로를 `CAP_SYS_ADMIN`과 같은 위험한 capabilities와 결합할 수도 있습니다. 실제 공격에서는 seccomp만 유일하게 누락된 control인 경우는 많지 않지만, seccomp가 없으면 나머지 privilege model이 작동하기도 전에 위험한 syscall을 차단할 수 있는 몇 안 되는 defense 중 하나가 제거되므로 exploit path가 크게 짧아집니다.

가장 유용한 practical test는 default profile이 일반적으로 차단하는 정확한 syscall family를 시도하는 것입니다. 해당 syscall이 갑자기 작동한다면 container posture가 크게 변경된 것입니다:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
`CAP_SYS_ADMIN` 또는 다른 강력한 capability가 있는 경우, mount 기반 abuse를 수행하기 전에 seccomp가 유일하게 남은 장벽인지 테스트합니다:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
일부 targets에서는 즉각적인 목표가 full escape가 아니라 information gathering 및 kernel attack-surface 확장일 수 있습니다. 다음 commands는 특히 민감한 syscall 경로에 접근 가능한지 확인하는 데 도움이 됩니다:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
seccomp가 없고 컨테이너도 다른 방식으로 privileged 상태라면, 이때 이미 legacy container-escape pages에 문서화된 더 구체적인 breakout techniques로 pivot하는 것이 적절합니다.

### Full Example: seccomp Was The Only Thing Blocking `unshare`

많은 target에서 seccomp를 제거했을 때의 실제 효과는 namespace-creation 또는 mount syscalls가 갑자기 작동하기 시작하는 것입니다. 컨테이너에 `CAP_SYS_ADMIN`도 있다면 다음 sequence가 가능해질 수 있습니다:
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
이 자체만으로는 아직 host escape가 아니지만, mount 관련 exploitation을 막고 있던 장벽이 seccomp였음을 보여줍니다.

### 전체 예시: seccomp 비활성화 + cgroup v1 `release_agent`

seccomp가 비활성화되어 있고 container에서 cgroup v1 hierarchy를 mount할 수 있다면, cgroups 섹션의 `release_agent` technique에 접근할 수 있습니다:
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
이는 seccomp-only exploit이 아닙니다. 핵심은 seccomp가 unconfined 상태가 되면 이전에 차단되었던 syscall 중심의 breakout chain이 작성된 그대로 작동하기 시작할 수 있다는 점입니다.

## Checks

이러한 checks의 목적은 seccomp가 실제로 활성화되어 있는지, `no_new_privs`가 함께 설정되어 있는지, 그리고 runtime configuration에서 seccomp가 명시적으로 비활성화되어 있는지를 확인하는 것입니다.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
여기서 중요한 점:

- 0이 아닌 `Seccomp` 값은 filtering이 활성화되어 있음을 의미합니다. `0`은 일반적으로 seccomp 보호 기능이 없음을 의미합니다.
- Runtime security options에 `seccomp=unconfined`가 포함되어 있다면, workload는 가장 유용한 syscall-level 방어 기능 중 하나를 잃은 상태입니다.
- `NoNewPrivs`는 seccomp 자체는 아니지만, 두 설정이 함께 나타난다면 어느 쪽도 나타나지 않는 경우보다 더 신중한 hardening posture를 나타내는 경우가 많습니다.

Container에 이미 의심스러운 mounts, 광범위한 capabilities 또는 shared host namespaces가 있고 seccomp도 unconfined 상태라면, 이 조합은 주요 escalation signal로 간주해야 합니다. Container가 여전히 간단히 breakable하지 않을 수 있지만, attacker가 이용할 수 있는 kernel entry points의 수가 급격히 증가합니다.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Usually enabled by default | Uses Docker's built-in default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Usually enabled by default | Applies the runtime default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Not guaranteed by default** | If `securityContext.seccompProfile` is unset, the default is `Unconfined` unless the kubelet enables `--seccomp-default`; `RuntimeDefault` or `Localhost` must otherwise be set explicitly | `securityContext.seccompProfile.type: Unconfined`, leaving seccomp unset on clusters without `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes node and Pod settings | Runtime profile is used when Kubernetes asks for `RuntimeDefault` or when kubelet seccomp defaulting is enabled | Same as Kubernetes row; direct CRI/OCI configuration can also omit seccomp entirely |

Kubernetes의 동작은 operators를 가장 자주 놀라게 하는 부분입니다. 많은 clusters에서 Pod가 seccomp를 요청하거나 kubelet이 `RuntimeDefault`를 기본값으로 사용하도록 구성되지 않은 한, seccomp는 여전히 적용되지 않습니다.
{{#include ../../../../banners/hacktricks-training.md}}
