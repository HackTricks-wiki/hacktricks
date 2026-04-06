# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux는 **레이블 기반 강제 접근 통제 (MAC)** 시스템입니다. 실무적으로, 이는 DAC 권한, 그룹 또는 Linux capabilities가 해당 작업에 충분해 보여도 **소스 컨텍스트**가 요청된 클래스/권한으로 **타겟 컨텍스트**에 접근하도록 허용되지 않으면 커널이 여전히 이를 거부할 수 있음을 의미합니다.

A context usually looks like:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
From a privesc perspective, the `type` (domain for processes, type for objects) is usually the most important field:

- 프로세스는 **domain**에서 실행됩니다(예: `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`)
- 파일과 소켓에는 **type**이 설정됩니다(예: `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`)
- Policy는 한 domain이 다른 domain을 read/write/execute/transition할 수 있는지를 결정합니다

## 빠른 열거

SELinux가 활성화되어 있으면 초기에 SELinux를 열거하세요. 이는 일반적인 Linux privesc 경로가 실패하는 이유나 "harmless"한 SELinux 도구 주위의 권한 있는 래퍼가 실제로 중요한 이유를 설명해줄 수 있습니다:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
유용한 후속 확인 사항:
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
Interesting findings:

- `Disabled` or `Permissive` mode는 SELinux가 경계로서 갖는 대부분의 가치를 제거합니다.
- `unconfined_t`는 보통 SELinux는 존재하지만 해당 프로세스를 실질적으로 제한하고 있지 않음을 의미합니다.
- `default_t`, `file_t` 또는 커스텀 경로에 명백히 잘못된 레이블은 종종 잘못된 라벨링이나 배포 미완료를 나타냅니다.
- 로컬 오버라이드(`file_contexts.local`)가 정책 기본값보다 우선하므로 주의 깊게 검토하십시오.

## 정책 분석

두 가지 질문에 답할 수 있을 때 SELinux를 공격하거나 우회하기가 훨씬 쉬워집니다:

1. **내 현재 도메인이 무엇에 접근할 수 있는가?**
2. **내가 어떤 도메인으로 전환할 수 있는가?**

이를 위해 가장 유용한 도구는 `sepolicy`와 **SETools** (`seinfo`, `sesearch`, `sedta`):
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
이 방법은 호스트가 모두를 `unconfined_u`에 매핑하는 대신 **제한된 사용자**를 사용하는 경우에 특히 유용합니다. 이 경우 다음을 확인하세요:

- 사용자 매핑: `semanage login -l`
- 허용된 역할: `semanage user -l`
- 접근 가능한 관리자 도메인(예: `sysadm_t`, `secadm_t`, `webadm_t`)
- `sudoers` 항목이 `ROLE=` 또는 `TYPE=`를 사용하는지

만약 `sudo -l`에 이와 같은 항목이 포함되어 있다면, SELinux는 권한 경계의 일부입니다:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
또한 `newrole`이 사용 가능한지 확인하세요:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon`과 `newrole`은 자동으로 악용되지는 않지만, 권한 있는 래퍼나 `sudoers` 규칙이 더 나은 역할/유형을 선택하게 해준다면, 이들은 높은 가치의 권한 상승 수단이 됩니다.

## 파일, 레이블 재지정, 그리고 고가치 잘못된 구성

일반적인 SELinux 도구들 간의 가장 중요한 운영상의 차이는 다음과 같습니다:

- `chcon`: 특정 경로에 대한 임시 레이블 변경
- `semanage fcontext`: 영구적인 경로-레이블 규칙
- `restorecon` / `setfiles`: 정책/기본 레이블을 다시 적용

이는 privesc 상황에서 매우 중요합니다. **레이블 재지정은 단순한 미관상의 변화가 아닙니다**. 파일을 "정책에 의해 차단됨" 상태에서 "권한이 있는 제한된 서비스에 의해 읽기/실행 가능" 상태로 바꿀 수 있습니다.

로컬 레이블 재지정 규칙과 레이블 편차를 확인하세요:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
다음은 `sudo -l`, root wrappers, automation scripts, 또는 file capabilities에서 찾아야 할 가치 높은 명령들:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
특히 흥미로운 항목:

- `semanage fcontext`: 경로가 받아야 할 라벨을 영구적으로 변경합니다
- `restorecon` / `setfiles`: 그 변경사항을 대규모로 재적용합니다
- `semodule -i`: 커스텀 정책 모듈을 로드합니다
- `semanage permissive -a <domain_t>`: 호스트 전체를 전환하지 않고 특정 도메인을 permissive로 만듭니다
- `setsebool -P`: 정책 booleans를 영구적으로 변경합니다
- `load_policy`: 활성 정책을 다시 로드합니다

이것들은 종종 **helper primitives**이며, 독립적인 루트 익스플로잇이 아닙니다. 이들의 가치는 다음을 가능하게 한다는 점입니다:

- 대상 도메인을 permissive로 만듭니다
- 자신의 도메인과 보호된 타입(protected type) 간의 접근을 넓힙니다
- 공격자 제어 파일의 레이블을 변경하여 권한 있는 서비스가 읽거나 실행할 수 있게 합니다
- 격리된 서비스를 충분히 약화시켜 기존의 로컬 버그가 익스플로잇 가능해지도록 합니다

예시 검사:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
루트로 정책 모듈을 로드할 수 있다면, 일반적으로 SELinux 경계를 제어합니다:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
That is why `audit2allow`, `semodule`, and `semanage permissive` should be treated as sensitive admin surfaces during post-exploitation. They can silently convert a blocked chain into a working one without changing classic UNIX permissions.

## 감사 단서

AVC denials는 종종 단순한 방어적 잡음이 아니라 공격적 신호인 경우가 많다. 이것들은 당신에게 다음을 알려준다:

- 어떤 타깃 객체/타입을 건드렸는지
- 어떤 권한이 거부되었는지
- 현재 당신이 제어하고 있는 도메인이 무엇인지
- 작은 정책 변경이 체인을 작동시키는지 여부
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
로컬 exploit이나 persistence 시도가 root처럼 보이는 DAC 권한에도 불구하고 `EACCES` 또는 이상한 "permission denied" 오류로 계속 실패한다면, 해당 vector를 포기하기 전에 SELinux를 확인할 가치가 있다.

## SELinux 사용자

일반 Linux 사용자 외에 SELinux 사용자가 존재한다. 각 Linux 사용자는 정책의 일부로 SELinux 사용자에 매핑되며, 이를 통해 시스템은 계정마다 서로 다른 허용된 역할과 도메인을 적용할 수 있다.

빠른 확인:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
많은 주류 시스템에서는 사용자들이 `unconfined_u`에 매핑되어 있어 사용자 격리의 실질적인 영향이 줄어듭니다. 하지만 강화된(hardened) 배포 환경에서는 격리된 사용자가 `sudo`, `su`, `newrole`, `runcon`을 훨씬 더 흥미롭게 만들 수 있습니다. **권한 상승 경로는 단지 UID 0이 되는 것뿐만 아니라 더 좋은 SELinux 역할/타입(role/type)으로 진입하는 것에 달려있을 수 있기 때문입니다**.

## 컨테이너의 SELinux

컨테이너 런타임은 일반적으로 `container_t`와 같은 격리된 도메인에서 워크로드를 시작하고 컨테이너 콘텐츠에 `container_file_t` 라벨을 지정합니다. 컨테이너 프로세스가 탈출하더라도 여전히 컨테이너 라벨로 실행된다면, 라벨 경계가 유지되어 호스트에 대한 쓰기가 실패할 수 있습니다.

간단한 예:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
현대 컨테이너 운영에서 주목할 점:

- `--security-opt label=disable`는 워크로드를 `spc_t`와 같은 비제한(unconfined) 컨테이너 관련 타입으로 사실상 이동시킬 수 있습니다
- `:z` / `:Z`가 붙은 bind mounts는 호스트 경로를 공유/개별 컨테이너 사용용으로 재라벨링(relabeling)하도록 트리거합니다
- 호스트 콘텐츠의 광범위한 재라벨링은 그 자체로 보안 문제가 될 수 있습니다

이 페이지는 중복을 피하기 위해 컨테이너 관련 내용을 간단히 유지합니다. 컨테이너 특화된 악용 사례 및 런타임 예제는 다음을 확인하세요:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## 참고자료

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
