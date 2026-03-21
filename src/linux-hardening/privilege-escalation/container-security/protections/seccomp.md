# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

**seccomp**는 커널이 프로세스가 호출할 수 있는 syscalls에 필터를 적용하게 해주는 메커니즘입니다. 컨테이너화된 환경에서 seccomp는 보통 필터 모드로 사용되며, 이 경우 프로세스가 단순히 "제한됨"으로 모호하게 표시되는 것이 아니라 구체적인 syscall 정책의 적용을 받습니다. 이는 많은 컨테이너 탈출 공격이 매우 특정한 커널 인터페이스에 도달해야만 가능하므로 중요합니다. 만약 프로세스가 관련된 syscalls를 성공적으로 호출할 수 없다면, 네임스페이스나 capability의 세부 차이가 의미를 갖기 전에 많은 공격이 사라집니다.

핵심적인 사고 모델은 단순합니다: namespaces는 **프로세스가 무엇을 볼 수 있는지**를 결정하고, capabilities는 **프로세스가 표면상 시도할 수 있는 권한 있는 동작들**을 결정하며, seccomp는 **커널이 시도된 동작의 syscall 진입점을 수락할지 여부**를 결정합니다. 이 때문에 seccomp는 종종 capabilities만으로는 가능해 보이는 공격을 차단합니다.

## 보안 영향

많은 위험한 커널 표면은 비교적 적은 수의 syscalls를 통해서만 접근할 수 있습니다. 컨테이너 하드닝에서 반복적으로 중요한 예로는 `mount`, `unshare`, `clone` 또는 `clone3` (특정 플래그와 함께), `bpf`, `ptrace`, `keyctl`, `perf_event_open` 등이 있습니다. 공격자가 이러한 syscalls에 도달할 수 있다면 새로운 namespaces를 만들거나 커널 서브시스템을 조작하거나 일반 애플리케이션 컨테이너가 전혀 필요로 하지 않는 공격 표면과 상호작용할 수 있습니다.

이것이 기본 런타임 seccomp 프로파일이 매우 중요한 이유입니다. 그것들은 단순한 "추가 방어"가 아니라, 많은 환경에서 컨테이너가 커널 기능의 넓은 부분을 사용할 수 있는 경우와 애플리케이션이 실제로 필요로 하는 syscall 표면에 더 가깝게 제약된 경우를 가르는 차이입니다.

## 모드 및 필터 구성

seccomp는 역사적으로 남아 있는 syscall 집합이 극히 적은 strict mode를 갖고 있었지만, 현대 컨테이너 런타임과 관련된 모드는 보통 seccomp filter mode, 흔히 **seccomp-bpf**라고 불리는 모드입니다. 이 모델에서 커널은 syscall을 허용할지, errno로 거부할지, trapped 하거나 로깅하거나 프로세스를 종료할지 결정하는 필터 프로그램을 평가합니다. 컨테이너 런타임은 이 메커니즘을 사용하여 정상 애플리케이션 동작을 허용하면서도 위험한 syscall의 넓은 범주를 차단할 수 있을 만큼 표현력이 충분하기 때문입니다.

두 가지 저수준 예시는 메커니즘을 마법처럼 보이지 않고 구체적으로 만들어 주므로 유용합니다. Strict mode는 옛날의 "오직 최소한의 syscall 집합만 살아남는다" 모델을 보여줍니다:
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
마지막 `open`은 strict 모드의 최소 집합에 포함되지 않기 때문에 프로세스가 종료된다.

libseccomp 필터 예시는 현대 정책 모델을 더 명확하게 보여준다:
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
이 스타일의 정책은 대부분의 독자가 런타임 seccomp 프로필을 생각할 때 떠올리는 형태다.

## Lab

컨테이너에서 seccomp가 활성화되어 있는지 확인하는 간단한 방법은 다음과 같다:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
기본 프로필이 일반적으로 제한하는 작업을 시도해볼 수도 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
컨테이너가 일반적인 기본 seccomp 프로필로 실행 중이라면 `unshare`-style 동작은 종종 차단됩니다. 이는 userspace 도구가 이미지 내부에 존재하더라도 필요한 kernel 경로가 여전히 사용 불가능할 수 있음을 보여주므로 유용한 시연입니다.

컨테이너가 일반적인 기본 seccomp 프로필로 실행 중이라면 `unshare`-style 동작은 userspace 도구가 이미지 내부에 존재하더라도 종종 차단됩니다.

프로세스 상태를 더 일반적으로 검사하려면 다음을 실행하세요:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Runtime Usage

Docker는 기본 및 사용자 정의 seccomp 프로필을 모두 지원하며 관리자가 `--security-opt seccomp=unconfined`로 이를 비활성화할 수 있다. Podman도 유사한 지원을 제공하며 seccomp를 rootless execution과 함께 합리적인 기본 설정으로 자주 결합한다. Kubernetes는 workload 설정을 통해 seccomp를 노출하며, 여기서 `RuntimeDefault`는 보통 합리적인 기준이며 `Unconfined`는 편의상의 토글이 아니라 정당한 이유가 있는 예외로 취급해야 한다.

In containerd and CRI-O based environments, the exact path is more layered, but the principle is the same: the higher-level engine or orchestrator decides what should happen, and the runtime eventually installs the resulting seccomp policy for the container process. The outcome still depends on the final runtime configuration that reaches the kernel.

### Custom Policy Example

Docker 및 유사한 엔진은 JSON에서 사용자 정의 seccomp 프로필을 로드할 수 있다. 모든 것을 허용하되 `chmod`만 거부하는 최소 예제는 다음과 같다:
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
사용하여 적용:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
명령은 `Operation not permitted` 오류로 실패하며, 이는 제한이 일반 파일 권한이 아니라 syscall 정책에서 비롯되었음을 보여준다. 실제 하드닝에서는 allowlists가 일반적으로 소규모 블랙리스트를 사용하는 관대한 기본값보다 더 강력하다.

## Misconfigurations

가장 무딘 실수는 애플리케이션이 기본 정책에서 실패했다고 seccomp를 **unconfined**로 설정하는 것이다. 이는 문제 해결 중에 흔히 발생하며 영구적인 해결책으로는 매우 위험하다. 필터가 사라지면 많은 syscall 기반 탈출 프리미티브가 다시 이용 가능해지며, 특히 강력한 capabilities나 호스트 네임스페이스 공유가 있는 경우에 더 위험하다.

또 다른 흔한 문제는 블로그나 내부 임시방편에서 복사해온 **custom permissive profile**을 면밀히 검토하지 않고 사용하는 것이다. 팀들은 때때로 프로필이 "앱이 깨지는 것을 막기" 위해 만들어졌기 때문에 실제로 필요한 것만 허용하는 대신 거의 모든 위험한 syscall을 그대로 두는 경우가 있다. 세 번째 오해는 seccomp가 루트가 아닌 컨테이너에는 덜 중요하다고 생각하는 것이다. 실제로 프로세스가 UID 0이 아니더라도 많은 커널 공격 표면이 여전히 관련되어 있다.

## Abuse

seccomp가 없거나 심각하게 약화되어 있으면 공격자는 네임스페이스 생성 관련 syscall을 호출하거나 `bpf` 또는 `perf_event_open`을 통해 도달 가능한 커널 공격 표면을 확장하거나 `keyctl`을 악용하거나 이러한 syscall 경로를 `CAP_SYS_ADMIN`과 같은 위험한 capabilities와 결합할 수 있다. 실제 많은 공격에서 seccomp는 유일한 누락된 제어 수단은 아니지만, 그 부재는 위험한 syscall을 권한 모델의 나머지 부분이 개입하기 전에 차단할 수 있는 몇 안 되는 방어책 중 하나를 제거하므로 exploit 경로를 극적으로 단축시킨다.

가장 실용적인 테스트는 기본 프로필이 보통 차단하는 정확한 syscall 계열을 시도해보는 것이다. 만약 그것들이 갑자기 동작한다면, 컨테이너의 보안 태세가 크게 바뀐 것이다:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
`CAP_SYS_ADMIN` 또는 다른 강력한 capability가 존재한다면, mount-based abuse 전에 seccomp가 유일한 보안 장벽인지 확인해보세요:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
일부 대상에서는 즉각적인 목표가 완전한 escape가 아니라 정보 수집 및 kernel attack-surface 확장인 경우가 있습니다. 다음 명령들은 특히 민감한 syscall 경로에 접근 가능한지 여부를 판단하는 데 도움을 줍니다:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
If seccomp is absent and the container is also privileged in other ways, that is when it makes sense to pivot into the more specific breakout techniques already documented in the legacy container-escape pages.

### 전체 예: seccomp가 `unshare`를 막는 유일한 요소였을 때

On many targets, the practical effect of removing seccomp is that namespace-creation or mount syscalls suddenly start working. If the container also has `CAP_SYS_ADMIN`, the following sequence may become possible:
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
그 자체만으로는 아직 host escape는 아니지만, seccomp가 mount 관련 exploitation을 방지하는 장벽이었음을 보여준다.

### 전체 예제: seccomp 비활성화 + cgroup v1 `release_agent`

seccomp가 비활성화되어 있고 컨테이너가 cgroup v1 계층을 mount할 수 있다면, cgroups 섹션의 `release_agent` 기법에 도달할 수 있다:
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
이것은 seccomp 전용 exploit가 아니다. 핵심은 seccomp가 unconfined 상태가 되면, 이전에 차단되었던 syscall-heavy breakout chains가 정확히 작성된 대로 작동하기 시작할 수 있다는 것이다.

## Checks

이러한 검사의 목적은 seccomp가 활성화되어 있는지, `no_new_privs`가 함께 설정되어 있는지, 그리고 런타임 구성에서 seccomp가 명시적으로 비활성화되어 있는지를 확인하는 것이다.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
여기서 주목할 점:

- 0이 아닌 `Seccomp` 값은 필터링이 활성화되어 있음을 의미합니다; `0`은 보통 seccomp 보호가 없음을 의미합니다.
- 런타임 보안 옵션에 `seccomp=unconfined`가 포함되어 있으면, 워크로드는 가장 유용한 syscall-level 방어 수단 중 하나를 잃게 됩니다.
- `NoNewPrivs`는 seccomp 그 자체는 아니지만, 둘을 함께 보면 보통 둘 다 없는 경우보다 더 신중한 보안 강화 태세를 나타냅니다.

이미 컨테이너에 의심스러운 마운트, 광범위한 capabilities, 또는 공유된 host namespaces가 있고 seccomp도 unconfined라면, 그 조합은 심각한 권한 상승 신호로 간주해야 합니다. 컨테이너가 아직 쉽게 탈취될 수 없는 경우도 있지만, 공격자가 이용할 수 있는 커널 진입점의 수는 급격히 증가합니다.

## 런타임 기본값

| Runtime / platform | 기본 상태 | 기본 동작 | 일반적인 수동 약화 방법 |
| --- | --- | --- | --- |
| Docker Engine | 보통 기본적으로 활성화됨 | 재정의되지 않는 한 Docker의 내장 기본 seccomp 프로필을 사용함 | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | 보통 기본적으로 활성화됨 | 재정의되지 않는 한 런타임 기본 seccomp 프로필을 적용함 | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **기본으로 보장되지 않음** | 만약 `securityContext.seccompProfile`가 설정되지 않았다면, kubelet이 `--seccomp-default`를 활성화하지 않는 한 기본값은 `Unconfined`입니다; 그렇지 않으면 `RuntimeDefault` 또는 `Localhost`를 명시적으로 설정해야 합니다 | `securityContext.seccompProfile.type: Unconfined`, `seccompDefault`가 없는 클러스터에서 seccomp를 설정하지 않은 채로 두기, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes 노드 및 Pod 설정을 따름 | Kubernetes가 `RuntimeDefault`를 요청하거나 kubelet의 seccomp 기본값 설정이 활성화된 경우 런타임 프로필이 사용됨 | Kubernetes 행과 동일; CRI/OCI 직접 구성으로 seccomp를 완전히 생략할 수도 있음 |

Kubernetes 동작은 운영자들을 가장 자주 놀라게 합니다. 많은 클러스터에서 Pod가 요청하거나 kubelet이 `RuntimeDefault`로 기본 설정하도록 구성하지 않는 한 seccomp는 여전히 없을 수 있습니다.
