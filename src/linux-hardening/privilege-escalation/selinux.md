# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux는 **레이블 기반의 Mandatory Access Control (MAC)** 시스템입니다. 실제로 이는 DAC 권한, 그룹 또는 Linux capabilities가 어떤 동작에 충분해 보이더라도, 커널이 **소스 컨텍스트**가 요청한 클래스/권한으로 **타겟 컨텍스트**에 접근하도록 허용되지 않았다면 이를 거부할 수 있음을 의미합니다.

컨텍스트는 일반적으로 다음과 같은 형태입니다:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
From a privesc 관점에서, the `type` (프로세스의 domain, 객체의 type)는 보통 가장 중요한 필드입니다:

- 프로세스는 `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t` 같은 **domain**에서 실행됩니다
- 파일과 소켓은 `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t` 같은 **type**을 가집니다
- 정책은 한 domain이 다른 domain을 읽기/쓰기/실행/전이(transition)할 수 있는지를 결정합니다

## 빠른 열거

SELinux가 활성화되어 있다면 초기에 SELinux를 열거하세요. 이는 일반적인 Linux privesc 경로가 실패하는 이유나 "harmless" SELinux 도구를 감싸는 권한 있는 wrapper가 실제로는 왜 중요한지를 설명해 줄 수 있기 때문입니다:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
유용한 후속 확인:
```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```
흥미로운 발견:

- `Disabled` 또는 `Permissive` 모드는 SELinux가 경계로서 가지는 대부분의 가치를 제거합니다.
- `unconfined_t`는 보통 SELinux가 존재하지만 해당 프로세스를 실질적으로 제약하지 못함을 의미합니다.
- `default_t`, `file_t` 또는 사용자 지정 경로에 대한 명백히 잘못된 라벨은 종종 라벨링 오류나 배포 미완료를 나타냅니다.
- `file_contexts.local`의 로컬 오버라이드는 정책 기본값보다 우선하므로 주의 깊게 검토해야 합니다.

## 정책 분석

다음 두 가지 질문에 답할 수 있다면 SELinux를 공격하거나 우회하기가 훨씬 쉽습니다:

1. **현재 도메인이 무엇에 접근할 수 있는가?**
2. **어떤 도메인으로 전이할 수 있는가?**

이를 위해 가장 유용한 도구는 `sepolicy`와 **SETools** (`seinfo`, `sesearch`, `sedta`)입니다:
```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```
호스트가 모든 사용자를 `unconfined_u`로 매핑하지 않고 **격리된 사용자**를 사용하는 경우에 특히 유용합니다. 이 경우 다음을 확인하세요:

- `semanage login -l`를 통해 사용자 매핑
- `semanage user -l`로 허용된 역할
- 접근 가능한 관리자 도메인 예: `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers` 항목에서 `ROLE=` 또는 `TYPE=` 사용

만약 `sudo -l`에 이런 항목이 포함되어 있다면, SELinux는 권한 경계의 일부입니다:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
또한 `newrole` 사용 가능 여부를 확인하세요:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` 및 `newrole`은 자동으로 악용 가능한 것은 아니지만, 권한 있는 래퍼나 `sudoers` 규칙이 더 나은 역할/타입을 선택하게 허용하면, 이들은 높은 가치의 권한 상승 프리미티브가 됩니다.

## 파일, 재라벨링 및 고가치 잘못된 구성

일반적인 SELinux 도구들 간의 가장 중요한 운영상 차이는 다음과 같습니다:

- `chcon`: 특정 경로에 대한 임시 라벨 변경
- `semanage fcontext`: 경로-라벨 규칙의 영구적 설정
- `restorecon` / `setfiles`: 정책/기본 라벨을 다시 적용

이것은 privesc 중에 매우 중요합니다. **재라벨링은 단순한 외관상의 변화가 아닙니다**. 재라벨링은 파일을 "정책에 의해 차단됨" 상태에서 "권한이 부여된 격리된 서비스가 읽거나 실행할 수 있음" 상태로 바꿀 수 있습니다.

로컬 재라벨 규칙 및 재라벨링 편차를 확인하세요:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
다음은 `sudo -l`, root wrappers, automation scripts 또는 file capabilities에서 찾아야 할 고가치 명령어:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
특히 흥미로운 항목:

- `semanage fcontext`: 경로가 받아야 하는 label을 영구적으로 변경함
- `restorecon` / `setfiles`: 해당 변경을 일괄적으로 재적용함
- `semodule -i`: 사용자 정의 정책 모듈을 로드함
- `semanage permissive -a <domain_t>`: 호스트 전체를 permissive로 전환하지 않고 특정 도메인만 permissive로 설정함
- `setsebool -P`: 정책 불리언을 영구적으로 변경함
- `load_policy`: 활성 정책을 다시 로드함

이것들은 종종 **도움이 되는 프리미티브**이며, 독립적인 루트 익스플로잇이 아닙니다. 이들의 가치는 다음을 가능하게 한다:

- 대상 도메인을 permissive로 만듦
- 자신의 도메인과 보호된 타입 간의 접근 권한을 확대함
- 공격자가 제어하는 파일의 레이블을 변경하여 권한 있는 서비스가 읽거나 실행할 수 있게 함
- 제한된(confined) 서비스를 충분히 약화시켜 기존의 로컬 버그를 악용 가능하게 함

예시 검사:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
root로 policy module을 로드할 수 있다면, 일반적으로 SELinux 경계를 제어합니다:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
그러므로 `audit2allow`, `semodule`, `semanage permissive`는 post-exploitation 동안 민감한 관리자 인터페이스로 취급되어야 한다. 이들은 고전적인 UNIX 권한을 변경하지 않고도 차단된 체인을 조용히 작동하게 만들 수 있다.

## 감사 단서

AVC denials는 종종 단순한 방어적 잡음이 아니라 공격에 활용할 수 있는 신호다. 이들은 다음을 알려준다:

- 어떤 대상 객체/타입을 건드렸는지
- 어떤 권한이 거부되었는지
- 현재 어떤 도메인을 제어하고 있는지
- 작은 정책 변경으로 체인이 작동할 수 있는지 여부
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
If a local exploit or persistence attempt keeps failing with `EACCES` or strange "permission denied" errors despite root-looking DAC permissions, SELinux is usually worth checking before discarding the vector.

## SELinux 사용자

일반 Linux 사용자 외에도 SELinux 사용자가 있다. 각 Linux 사용자는 정책의 일부로 SELinux 사용자에 매핑되며, 이를 통해 시스템은 서로 다른 계정에 서로 다른 허용된 역할과 도메인을 부과할 수 있다.

빠른 확인:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
많은 주류 시스템에서는 사용자들이 `unconfined_u`에 매핑되어 사용자 격리의 실질적 영향이 줄어듭니다. 하지만 강화된 배포에서는, 격리된 사용자가 `sudo`, `su`, `newrole`, 그리고 `runcon`을 훨씬 더 흥미롭게 만들 수 있는데, 그 이유는 **권한 상승 경로가 단지 UID 0이 되는 것뿐만 아니라 더 나은 SELinux 롤/타입으로 진입하는 것에 의존할 수 있기 때문입니다**.

## 컨테이너에서의 SELinux

컨테이너 런타임은 일반적으로 `container_t`와 같은 격리된 도메인에서 워크로드를 실행하고 컨테이너 콘텐츠를 `container_file_t`로 라벨링합니다. 컨테이너 프로세스가 탈출하더라도 여전히 컨테이너 라벨로 실행된다면, 라벨 경계가 유지되어 호스트에 대한 쓰기가 실패할 수 있습니다.

간단한 예:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
주목할 만한 최신 컨테이너 운영 사항:

- `--security-opt label=disable`는 작업 부하를 `spc_t`와 같은 unconfined 컨테이너 관련 타입으로 사실상 이동시킬 수 있습니다
- bind mounts with `:z` / `:Z`는 공유/개인 컨테이너 사용을 위해 호스트 경로의 relabeling을 트리거합니다
- 호스트 콘텐츠의 광범위한 relabeling은 그 자체로 보안 문제가 될 수 있습니다

이 페이지는 중복을 피하기 위해 컨테이너 관련 내용을 간단히 유지합니다. 컨테이너별 오용 사례와 런타임 예제를 보려면 다음을 확인하세요:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
