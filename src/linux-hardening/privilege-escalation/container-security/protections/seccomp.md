# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

**seccomp**는 커널이 프로세스가 호출할 수 있는 syscalls에 필터를 적용하도록 하는 메커니즘이다. 컨테이너화된 환경에서는 seccomp가 일반적으로 필터 모드로 사용되어 프로세스가 모호하게 "restricted"로 표시되는 대신 구체적인 syscall 정책의 적용을 받는다. 이는 많은 container breakouts가 매우 특정한 kernel 인터페이스에 도달해야 하기 때문에 중요하다. 프로세스가 관련 syscalls를 성공적으로 호출할 수 없다면, namespaces나 capabilities 관련 세부 사항이 중요해지기 전에 많은 종류의 공격이 사라진다.

핵심 개념은 간단하다: namespaces는 프로세스가 무엇을 볼 수 있는지를 결정하고, capabilities는 프로세스가 명목상 시도할 수 있는 권한 있는 행동을 결정하며, seccomp는 시도된 행동에 대해 kernel이 syscall 진입점을 수락할지 여부를 결정한다. 이 때문에 seccomp는 종종 capabilities만으로는 가능해 보이는 공격을 차단한다.

## 보안 영향

위험한 kernel 표면의 많은 부분은 비교적 적은 수의 syscalls를 통해서만 접근 가능하다. container hardening에서 반복해서 중요한 예로는 `mount`, `unshare`, `clone` 또는 특정 플래그를 가진 `clone3`, `bpf`, `ptrace`, `keyctl`, 그리고 `perf_event_open`이 있다. 공격자가 이러한 syscalls에 접근할 수 있다면 새로운 namespaces를 생성하거나 kernel 서브시스템을 조작하거나 일반 애플리케이션 컨테이너에서는 전혀 필요하지 않은 공격 표면과 상호작용할 수 있다.

이 때문에 기본 runtime seccomp profiles가 매우 중요하다. 그것들은 단순한 "추가 방어"가 아니다. 많은 환경에서 이것들이 컨테이너가 kernel 기능의 넓은 부분을 사용할 수 있게 하는지, 아니면 애플리케이션이 실제로 필요로 하는 것에 더 가까운 syscall 표면으로 제한되는지의 차이를 만든다.

## 모드 및 필터 구성

seccomp는 역사적으로 아주 적은 수의 syscall 집합만 남기는 strict 모드를 가졌지만, 현대의 container runtimes와 관련된 모드는 seccomp 필터 모드로, 종종 **seccomp-bpf**라고 불린다. 이 모델에서 kernel은 필터 프로그램을 평가하여 syscall을 허용할지, `errno`로 거부할지, 트랩할지, 로깅할지, 또는 프로세스를 종료할지를 결정한다. Container runtimes는 이 메커니즘을 사용한다. 이는 정상적인 애플리케이션 동작을 허용하면서도 위험한 syscalls의 넓은 범주를 차단할 만큼 표현력이 충분하기 때문이다.

두 개의 저수준 예시는 이 메커니즘을 마법이 아닌 구체적인 것으로 만드는 데 유용하다. Strict 모드는 오래된 "오직 최소한의 syscall 집합만 살아남는다" 모델을 보여준다:
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
마지막 `open`은 strict 모드의 최소 집합에 포함되지 않기 때문에 프로세스가 종료됩니다.

libseccomp 필터 예시는 현대적인 정책 모델을 더 명확하게 보여줍니다:
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
이러한 유형의 정책은 대부분의 독자가 런타임 seccomp 프로필을 생각할 때 떠올리는 것입니다.

## 실습

컨테이너에서 seccomp가 활성화되어 있는지 확인하는 간단한 방법은:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
기본 프로필이 일반적으로 제한하는 작업을 시도해 볼 수도 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
컨테이너가 일반 기본 seccomp profile 하에서 실행되고 있다면, `unshare`-스타일 작업은 종종 차단됩니다. 이는 userspace tool이 이미지 내부에 존재하더라도 필요한 커널 경로가 여전히 사용 불가능할 수 있음을 보여주기 때문에 유용한 시연입니다.

컨테이너가 일반 기본 seccomp profile 하에서 실행되고 있다면, userspace tool이 이미지 안에 존재하더라도 `unshare`-스타일 작업은 종종 차단됩니다.

프로세스 상태를 더 일반적으로 확인하려면, 다음을 실행하세요:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## 런타임 사용

Docker는 기본 및 사용자 지정 seccomp 프로파일을 모두 지원하며 관리자가 `--security-opt seccomp=unconfined`로 이를 비활성화할 수 있습니다. Podman도 유사한 지원을 제공하며 종종 seccomp를 rootless 실행과 결합해 합리적인 기본 설정을 유지합니다. Kubernetes는 워크로드 구성으로 seccomp를 노출하며, `RuntimeDefault`는 보통 합리적인 기준선이고 `Unconfined`는 편의상 토글로 사용하는 대신 정당한 사유가 필요한 예외로 처리해야 합니다.

containerd 및 CRI-O 기반 환경에서는 정확한 경로가 더 층이 많지만 원칙은 동일합니다: 상위 레벨의 엔진 또는 오케스트레이터가 어떻게 동작할지 결정하고, 런타임은 최종적으로 컨테이너 프로세스에 대한 seccomp 정책을 설치합니다. 결과는 커널에 도달하는 최종 런타임 구성에 의해 여전히 좌우됩니다.

### 사용자 지정 정책 예제

Docker 및 유사한 엔진은 JSON에서 사용자 지정 seccomp 프로파일을 로드할 수 있습니다. 모든 것을 허용하고 `chmod`만 거부하는 최소 예시는 다음과 같습니다:
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
적용 방식:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
The command fails with `Operation not permitted`, demonstrating that the restriction comes from the syscall policy rather than from ordinary file permissions alone. In real hardening, allowlists are generally stronger than permissive defaults with a small blacklist.

## 잘못된 구성

가장 무딘 실수는 애플리케이션이 기본 정책에서 실패했다는 이유로 seccomp를 **unconfined**으로 설정하는 것이다. 이는 문제 해결 과정에서 흔히 발생하며 영구적인 해결책으로는 매우 위험하다. 필터가 사라지면 많은 syscall 기반 탈출 프리미티브가 다시 이용 가능해지며, 특히 강력한 capabilities나 호스트 네임스페이스 공유가 함께 있을 때 더 그렇다.

또 다른 빈번한 문제는 블로그나 내부 우회법에서 복사해 온 **custom permissive profile**을 면밀히 검토하지 않고 사용하는 것이다. 팀들은 종종 프로파일이 "앱이 중단되지 않도록" 하는 데 초점을 맞춰 만들어졌기 때문에 실제로 필요한 것만 허용하는 대신 거의 모든 위험한 syscall을 유지해 버린다. 세 번째 오해는 seccomp가 non-root 컨테이너에서는 덜 중요하다고 가정하는 것이다. 실제로 프로세스가 UID 0이 아니더라도 커널의 공격 표면은 여전히 많이 남아 있다.

## 악용

seccomp가 없거나 심하게 약화되어 있으면 공격자는 네임스페이스 생성 관련 syscalls를 호출하거나 `bpf`나 `perf_event_open`을 통해 도달 가능한 커널 공격 표면을 확장하거나 `keyctl`을 악용하거나, 이런 syscall 경로들을 `CAP_SYS_ADMIN`과 같은 위험한 capabilities와 결합할 수 있다. 많은 실제 공격에서 seccomp는 유일한 누락된 제어 수단은 아니지만, seccomp가 없으면 위험한 syscall을 나머지 권한 모델이 개입하기 전에 차단할 수 있는 몇 안 되는 방어 수단 중 하나가 제거되어 익스플로잇 경로가 극적으로 단축된다.

가장 유용한 실무 테스트는 기본 프로파일이 보통 차단하는 정확한 syscall 계열을 시도해 보는 것이다. 만약 그것들이 갑자기 동작한다면, 컨테이너의 보안 상태가 크게 바뀐 것이다:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
만약 `CAP_SYS_ADMIN` 또는 다른 강력한 capability가 존재한다면, mount-based abuse에 앞서 seccomp가 유일한 차단 장치인지 테스트하세요:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
일부 대상에서는 즉각적인 목적이 완전한 escape가 아니라 information gathering 및 kernel attack-surface expansion일 수 있습니다. 다음 명령어들은 특히 민감한 syscall 경로에 접근 가능한지 여부를 판단하는 데 도움이 됩니다:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
If seccomp is absent and the container is also privileged in other ways, that is when it makes sense to pivot into the more specific breakout techniques already documented in the legacy container-escape pages.

### Full Example: seccomp Was The Only Thing Blocking `unshare`

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
그 자체로는 아직 host escape가 아니지만, seccomp가 mount-related exploitation을 방지하는 장벽이었다는 것을 보여준다.

### 전체 예시: seccomp 비활성화 + cgroup v1 `release_agent`

seccomp가 비활성화되어 있고 container가 cgroup v1 hierarchies를 mount할 수 있다면, cgroups 섹션의 `release_agent` 기법에 접근 가능해진다:
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
이것은 seccomp-only exploit이 아니다. 요점은 seccomp가 제약에서 벗어나면, 이전에 차단되었던 syscall-heavy breakout chains가 정확히 작성된 대로 작동하기 시작할 수 있다는 것이다.

## 검사

이 검사들의 목적은 seccomp가 전혀 활성화되어 있는지, `no_new_privs`가 함께 설정되어 있는지, 그리고 런타임 구성이 seccomp가 명시적으로 비활성화되어 있음을 보여주는지를 확인하는 것이다.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
여기서 흥미로운 점:

- 0이 아닌 `Seccomp` 값은 필터링이 활성화되어 있음을 의미합니다; `0`은 보통 seccomp 보호가 없음을 뜻합니다.
- 런타임 보안 옵션에 `seccomp=unconfined`가 포함되어 있으면, 워크로드는 가장 유용한 syscall 수준 방어 중 하나를 잃은 것입니다.
- `NoNewPrivs` 자체는 seccomp가 아니지만, 둘을 함께 보는 것은 보통 둘 다 없는 상황보다 더 신중한 하드닝 태세를 의미합니다.

컨테이너에 이미 의심스러운 mounts, 광범위한 capabilities, 또는 공유된 host namespaces가 있고 seccomp도 unconfined라면, 그 조합은 주요 권한 상승 신호로 간주해야 합니다. 해당 컨테이너가 여전히 쉽게 침해되지 않을 수는 있지만, 공격자가 이용할 수 있는 커널 진입점 수는 크게 증가합니다.

## 런타임 기본값

| Runtime / platform | 기본 상태 | 기본 동작 | 일반적인 수동 약화 방법 |
| --- | --- | --- | --- |
| Docker Engine | 대부분 기본적으로 활성화됨 | 오버라이드되지 않으면 Docker의 내장 기본 seccomp 프로필을 사용함 | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | 대부분 기본적으로 활성화됨 | 오버라이드되지 않으면 런타임 기본 seccomp 프로필을 적용함 | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **기본적으로 보장되지 않음** | `securityContext.seccompProfile`가 설정되지 않은 경우, kubelet이 `--seccomp-default`를 활성화하지 않으면 기본값은 `Unconfined`입니다; 그렇지 않으면 `RuntimeDefault` 또는 `Localhost`를 명시적으로 설정해야 합니다 | `securityContext.seccompProfile.type: Unconfined`, 클러스터에 `seccompDefault`가 없는 경우 seccomp를 비워둠, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes 노드 및 Pod 설정을 따름 | Kubernetes가 `RuntimeDefault`를 요청하거나 kubelet의 seccomp 기본화가 활성화된 경우 런타임 프로필을 사용함 | Kubernetes 행과 동일; 직접 CRI/OCI 구성으로 seccomp를 완전히 생략할 수도 있음 |

Kubernetes의 동작은 운영자들을 가장 자주 놀라게 하는 부분입니다. 많은 클러스터에서 Pod가 요청하거나 kubelet이 `RuntimeDefault`로 기본값을 설정하도록 구성되지 않는 한 seccomp는 여전히 없는 경우가 많습니다.
{{#include ../../../../banners/hacktricks-training.md}}
