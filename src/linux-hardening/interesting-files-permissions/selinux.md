# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux는 **label-based Mandatory Access Control (MAC)** 시스템입니다. 실제로 이는 DAC 권한, 그룹 또는 Linux capabilities가 어떤 작업을 수행하기에 충분해 보여도, **source context**가 요청된 class/permission을 사용해 **target context**에 액세스하도록 허용되지 않으면 kernel이 해당 작업을 거부할 수 있음을 의미합니다.

context는 일반적으로 다음과 같은 형태입니다:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
privesc 관점에서 `type`(프로세스의 경우 domain, 객체의 경우 type)은 일반적으로 가장 중요한 필드입니다:

- 프로세스는 `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`와 같은 **domain**에서 실행됩니다.
- 파일과 소켓에는 `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`와 같은 **type**이 있습니다.
- Policy는 한 domain이 다른 domain으로 read/write/execute/transition할 수 있는지 결정합니다.

## 빠른 열거

SELinux가 활성화되어 있다면 초기에 이를 열거하세요. 일반적인 Linux privesc 경로가 실패하는 이유를 설명하거나, "무해한" SELinux tool을 감싼 privileged wrapper가 실제로 중요한 이유를 설명할 수 있기 때문입니다:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
유용한 후속 점검 사항:
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

- `Disabled` 또는 `Permissive` 모드는 경계로서 SELinux의 가치를 대부분 제거합니다.
- `unconfined_t`는 일반적으로 SELinux가 존재하지만 해당 프로세스를 실질적으로 제한하지 않는다는 의미입니다.
- 사용자 지정 경로에 `default_t`, `file_t` 또는 명백히 잘못된 label이 지정되어 있으면 label 지정이 잘못되었거나 배포가 불완전할 가능성이 큽니다.
- `file_contexts.local`의 로컬 override는 policy 기본값보다 우선하므로 주의 깊게 검토해야 합니다.

## Policy Analysis

현재 domain이 다음 두 가지 질문에 답할 수 있을 때 SELinux를 공격하거나 우회하기가 훨씬 쉬워집니다.

1. **현재 domain은 무엇에 access할 수 있는가?**
2. **어떤 domain으로 transition할 수 있는가?**

이를 위한 가장 유용한 도구는 `sepolicy`와 **SETools**(`seinfo`, `sesearch`, `sedta`)입니다:
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
이는 host가 모든 사용자를 `unconfined_u`에 매핑하는 대신 **confined users**를 사용하는 경우 특히 유용합니다. 이 경우 다음을 확인하세요.

- `semanage login -l`을 통한 사용자 매핑
- `semanage user -l`을 통한 허용된 roles
- `sysadm_t`, `secadm_t`, `webadm_t`와 같이 접근 가능한 admin domains
- `ROLE=` 또는 `TYPE=`을 사용하는 `sudoers` 항목

`sudo -l`에 다음과 같은 항목이 포함되어 있다면 SELinux는 privilege boundary의 일부입니다:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
또한 `newrole`을 사용할 수 있는지 확인하세요:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon`과 `newrole`은 자동으로 exploit 가능한 것은 아니지만, 권한 있는 wrapper 또는 `sudoers` rule에서 더 나은 role/type을 선택할 수 있게 허용하면 높은 가치의 escalation primitive가 됩니다.

## Files, Relabeling, and High-Value Misconfigurations

일반적인 SELinux tools 간 가장 중요한 운영상의 차이점은 다음과 같습니다.

- `chcon`: 특정 path의 일시적인 label 변경
- `semanage fcontext`: 영구적인 path-to-label rule
- `restorecon` / `setfiles`: policy/default label을 다시 적용

이는 privesc 과정에서 매우 중요합니다. **relabeling은 단순히 외관상의 변경이 아니기 때문입니다.** 이를 통해 파일이 "policy에 의해 차단된 상태"에서 "권한이 제한된 privileged service가 읽거나 실행할 수 있는 상태"로 바뀔 수 있습니다.

local relabel rule과 relabel drift를 확인합니다:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
미묘하지만 유용한 세부 사항이 하나 있습니다. 일반 `restorecon`은 **의심스러운 label을 항상 완전히 되돌리지는 않습니다**. 대상 type이 `customizable_types`에 포함되어 있다면 완전한 초기화를 강제하기 위해 `-F`가 필요할 수 있습니다. 공격자 관점에서는 이를 통해, 특이한 `chcon`이 "이미 restorecon을 실행했다"는 대략적인 정리 이후에도 남아 있을 수 있는 이유를 알 수 있습니다.
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
`sudo -l`, root 래퍼, 자동화 스크립트 또는 file capabilities에서 찾아볼 가치가 높은 명령어:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
MAC capability 중 하나라도 나타나면 [Linux capabilities page](linux-capabilities.md)도 함께 교차 확인하세요. `cap_mac_admin` 및 `cap_mac_override`는 흔하지 않지만 SELinux가 경계의 일부인 경우 직접적으로 관련됩니다.

특히 흥미로운 항목:

- `semanage fcontext`: 경로에 적용되어야 할 label을 영구적으로 변경
- `restorecon` / `setfiles`: 이러한 변경 사항을 대규모로 재적용
- `semodule -i`: custom policy module 로드
- `semanage permissive -a <domain_t>`: 전체 host를 전환하지 않고 하나의 domain을 permissive로 설정
- `setsebool -P`: policy boolean을 영구적으로 변경
- `load_policy`: active policy를 reload

이들은 대개 **standalone root exploit**가 아닌 **helper primitives**입니다. 이들의 가치는 다음 작업을 가능하게 한다는 데 있습니다.

- target domain을 permissive로 설정
- 자신의 domain과 protected type 간 access 확대
- privileged service가 읽거나 실행할 수 있도록 attacker-controlled file을 relabel
- confined service를 충분히 약화하여 기존 local bug를 exploitable하게 만듦

예시 확인 항목:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
root로 policy module을 load할 수 있다면, 일반적으로 SELinux boundary를 제어할 수 있습니다:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
그렇기 때문에 `audit2allow`, `semodule`, `semanage permissive`는 post-exploitation 중 민감한 관리자 표면으로 취급해야 합니다. 이러한 도구는 기존 UNIX 권한을 변경하지 않고도 차단된 chain을 작동하는 chain으로 조용히 변환할 수 있습니다.

## 숨겨진 거부와 모듈 추출

매우 흔한 offensive frustration은 예상한 AVC denial이 나타나지 않은 채 무난한 `EACCES`로 실패하는 chain입니다. `dontaudit` rule은 필요한 정확한 permission을 숨길 수 있습니다. `sudo` 또는 다른 privileged wrapper를 통해 `semodule`을 실행할 수 있다면, 일시적으로 `dontaudit`를 비활성화하여 조용한 실패를 정확한 policy 단서로 바꿀 수 있습니다:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
이는 local admins가 이미 변경한 내용을 검토할 때도 유용합니다. 작은 custom module이나 특정 domain에 대한 permissive rule 하나가 target service를 base policy가 예상하는 것보다 훨씬 느슨하게 동작하게 만드는 원인인 경우가 많습니다.

## Audit Clues

AVC denials는 단순한 방어 측 노이즈가 아니라 offensive signal인 경우가 많습니다. 다음 정보를 알려 줍니다.

- 어떤 target object/type에 접근했는지
- 어떤 permission이 거부되었는지
- 현재 어떤 domain을 제어하고 있는지
- 작은 policy 변경만으로 chain이 작동할 수 있는지
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
로컬 exploit 또는 persistence 시도가 `EACCES`나 이상한 "permission denied" 오류로 계속 실패하고, root처럼 보이는 DAC 권한이 있는데도 문제가 발생한다면, 해당 vector를 포기하기 전에 SELinux를 확인해 보는 것이 좋습니다.

## SELinux 사용자

일반 Linux 사용자 외에도 SELinux 사용자가 존재합니다. 각 Linux 사용자는 policy의 일부로 SELinux 사용자에 매핑되며, 이를 통해 시스템은 계정마다 서로 다른 허용 role과 domain을 적용할 수 있습니다.

빠른 확인:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
많은 mainstream 시스템에서는 사용자가 `unconfined_u`에 매핑되므로, 사용자 confinement의 실제 영향이 줄어듭니다. 그러나 hardened deployment에서는 confined user가 `sudo`, `su`, `newrole`, `runcon`을 훨씬 더 흥미롭게 만들 수 있습니다. **escalation path가 단순히 UID 0이 되는 것뿐 아니라, 더 적합한 SELinux role/type으로 진입하는 것에 따라 달라질 수 있기 때문입니다.** 또한 일부 confined user는 policy가 기본 setuid transition을 명시적으로 허용하지 않는 한 `sudo`/`su`를 전혀 실행할 수 없다는 점을 기억해야 합니다. 따라서 `staff_u` + `sysadm_r`를 사용하는 호스트에서는 겉보기에는 사소한 `sudo ROLE=` / `TYPE=` rule이 실제 privilege boundary가 될 수 있습니다.

## Containers에서의 SELinux

Container runtime은 일반적으로 `container_t`와 같은 confined domain에서 workload를 실행하고, container content에는 `container_file_t` label을 지정합니다. Container process가 escape하더라도 container label을 유지한 채 실행된다면, label boundary가 그대로 유지되므로 host에 대한 write가 여전히 실패할 수 있습니다.

간단한 예:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` 부분은 장식이 아닙니다. 많은 container deployment에서 runtime은 MCS categories를 동적으로 할당하므로, `container_t`로 실행되는 두 process도 서로 분리된 상태로 유지됩니다. escape가 host namespace에 도달했지만 원래 category set을 유지하는 경우, category mismatch로 인해 일부 host path를 계속 읽거나 쓸 수 없는 이유를 설명할 수 있습니다.

주목할 만한 최신 container operation:

- `--security-opt label=disable`은 workload를 `spc_t`와 같은 unconfined container-related type으로 사실상 이동시킬 수 있습니다.
- `:z` / `:Z`를 사용하는 bind mount는 shared/private container 사용을 위해 host path의 relabeling을 트리거합니다.
- host content를 광범위하게 relabeling하면 그 자체로 security issue가 될 수 있습니다.

이 페이지에서는 중복을 피하기 위해 container 관련 내용을 간략하게 다룹니다. container-specific abuse case 및 runtime example은 다음을 확인하세요:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: SELinux 사용](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: SELinux용 Policy analysis tools](https://github.com/SELinuxProject/setools)
- [confined 및 unconfined user 관리 - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
