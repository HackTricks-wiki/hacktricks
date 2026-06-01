# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux는 **label-based Mandatory Access Control (MAC)** 시스템이다. 실제로는, DAC 권한, 그룹, 또는 Linux capabilities가 어떤 동작에 충분해 보여도, **source context**가 요청한 class/permission으로 **target context**에 접근하도록 허용되지 않으면 kernel이 여전히 이를 거부할 수 있다는 뜻이다.

context는 보통 다음과 같이 보인다:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
privesc 관점에서 `type`(프로세스에 대한 domain, 객체에 대한 type)은 보통 가장 중요한 필드입니다:

- 프로세스는 `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t` 같은 **domain**에서 실행됩니다
- 파일과 socket은 `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t` 같은 **type**을 가집니다
- policy는 한 domain이 다른 domain을 read/write/execute/transition할 수 있는지 결정합니다

## Fast Enumeration

SELinux가 활성화되어 있다면, 초기에 열거하세요. 흔한 Linux privesc 경로가 왜 실패하는지, 또는 "harmless"한 SELinux tool 주위의 privileged wrapper가 왜 실제로 중요한지 설명해 줄 수 있기 때문입니다:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
유용한 추가 확인 사항:
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

- `Disabled` or `Permissive` mode removes most of the value of SELinux as a boundary.
- `unconfined_t` usually means SELinux is present but not meaningfully constraining that process.
- `default_t`, `file_t`, or obviously wrong labels on custom paths often indicate mislabeling or incomplete deployment.
- Local overrides in `file_contexts.local` take precedence over policy defaults, so review them carefully.

## Policy Analysis

SELinux는 다음 두 질문에 답할 수 있을 때 훨씬 더 공격하거나 우회하기 쉽습니다:

1. **현재 domain이 접근할 수 있는 것은 무엇인가?**
2. **어떤 domain으로 전환할 수 있는가?**

이를 위한 가장 유용한 tool은 `sepolicy`와 **SETools** (`seinfo`, `sesearch`, `sedta`)입니다:
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
이는 호스트가 모든 사용자를 `unconfined_u`로 매핑하는 대신 **confined users**를 사용하는 경우 특히 유용합니다. 이 경우 다음을 확인하세요:

- `semanage login -l`을 통한 user mappings
- `semanage user -l`을 통한 allowed roles
- `sysadm_t`, `secadm_t`, `webadm_t` 같은 reachable admin domains
- `ROLE=` 또는 `TYPE=`를 사용하는 `sudoers` 항목

`sudo -l`에 이런 항목이 포함되어 있다면, SELinux가 privilege boundary의 일부입니다:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
또한 `newrole`이 사용 가능한지 확인하세요:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` and `newrole`는 자동으로 exploitable하지 않지만, privileged wrapper나 `sudoers` rule이 더 나은 role/type를 선택하게 해주면, 이들은 고가치 escalation primitive가 됩니다.

## Files, Relabeling, and High-Value Misconfigurations

가장 중요한 운영상 차이는 일반적인 SELinux tools 간에 다음과 같습니다:

- `chcon`: 특정 path에 대한 temporary label 변경
- `semanage fcontext`: persistent path-to-label rule
- `restorecon` / `setfiles`: policy/default label을 다시 적용

이것은 privesc 동안 매우 중요합니다. 왜냐하면 **relabeling은 단순한 외형 변화가 아니기 때문입니다**. 이것은 file을 "blocked by policy"에서 "readable/executable by a privileged confined service"로 바꿀 수 있습니다.

local relabel rules와 relabel drift를 확인하세요:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
한 가지 미묘하지만 유용한 세부 사항: 일반 `restorecon`은 **항상 의심스러운 label을 완전히 되돌리지는 않습니다**. 대상 type이 `customizable_types`에 있으면, 전체 reset을 강제로 수행하려면 `-F`가 필요할 수 있습니다. 공격적인 관점에서 보면, 이는 평소와 다른 `chcon`이 때때로 대충의 "이미 `restorecon`을 실행했잖아" 같은 정리 이후에도 살아남을 수 있는 이유를 설명합니다.
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
`sudo -l`, root wrappers, automation scripts, 또는 file capabilities에서 찾아야 할 고가치 명령어:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
MAC capability가 하나라도 나타나면, [Linux capabilities page](linux-capabilities.md)도 함께 교차 확인하세요. `cap_mac_admin`과 `cap_mac_override`는 흔하지 않지만, SELinux가 경계의 일부일 때는 직접적으로 관련이 있습니다.

특히 흥미로운 것들:

- `semanage fcontext`: path가 받아야 할 label을 영구적으로 변경
- `restorecon` / `setfiles`: 그 변경 사항을 대규모로 다시 적용
- `semodule -i`: custom policy module을 로드
- `semanage permissive -a <domain_t>`: 전체 host를 바꾸지 않고 하나의 domain만 permissive로 만듦
- `setsebool -P`: policy boolean을 영구적으로 변경
- `load_policy`: 활성 policy를 다시 로드

이것들은 종종 **helper primitives**이지, 단독 root exploit은 아닙니다. 그 가치는 다음을 가능하게 한다는 점입니다:

- target domain을 permissive로 만들기
- 내 domain과 protected type 사이의 access를 넓히기
- attacker-controlled files를 다시 label해서 privileged service가 읽거나 실행할 수 있게 만들기
- confined service를 충분히 약화시켜 기존의 local bug가 exploit 가능해지게 만들기

Example checks:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
root로 policy module을 로드할 수 있다면, 보통 SELinux boundary를 제어할 수 있다:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
그렇기 때문에 `audit2allow`, `semodule`, 및 `semanage permissive`는 post-exploitation 중 민감한 admin surface로 취급되어야 합니다. 이들은 classic UNIX permissions를 바꾸지 않고도 차단된 chain을 작동하는 chain으로 조용히 바꿀 수 있습니다.

## Hidden Denials and Module Extraction

매우 흔한 offensive frustration은 예상한 AVC denial이 전혀 나타나지 않는데도 chain이 단순한 `EACCES`로 실패하는 경우입니다. `dontaudit` 규칙이 당신에게 필요한 정확한 permission을 숨기고 있을 수 있습니다. `sudo` 또는 다른 privileged wrapper를 통해 `semodule`을 실행할 수 있다면, `dontaudit`를 일시적으로 비활성화해서 조용한 실패를 정확한 policy clue로 바꿀 수 있습니다:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
이것은 로컬 관리자들이 이미 무엇을 변경했는지 검토하는 데도 유용합니다. 작은 custom module이나 one-domain permissive rule이 target service가 base policy가 시사하는 것보다 훨씬 더 느슨하게 동작하는 이유인 경우가 많습니다.

## Audit Clues

AVC denials는 단순한 defensive noise가 아니라, 종종 offensive signal입니다. 그것들은 다음을 알려줍니다:

- 어떤 target object/type에 닿았는지
- 어떤 permission이 denied되었는지
- 현재 어떤 domain을 control하고 있는지
- 작은 policy change로 chain이 동작하게 될지 여부
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
If a local exploit or persistence attempt keeps failing with `EACCES` or strange "permission denied" errors despite root-looking DAC permissions, SELinux is usually worth checking before discarding the vector.

## SELinux Users

일반 Linux 사용자 외에도 SELinux users가 있다. 각 Linux user는 policy의 일부로 SELinux user에 매핑되며, 이를 통해 시스템은 서로 다른 계정에 서로 다른 allowed roles와 domains을 적용할 수 있다.

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
많은 주류 시스템에서는 사용자가 `unconfined_u`에 매핑되므로, user confinement의 실제 영향이 줄어듭니다. 그러나 hardened deployment에서는 confined user가 `sudo`, `su`, `newrole`, `runcon`을 훨씬 더 흥미롭게 만들 수 있습니다. 왜냐하면 **escalation path가 단순히 UID 0이 되는 것만이 아니라, 더 나은 SELinux role/type로 들어가는 것에 달려 있을 수 있기 때문**입니다. 또한 일부 confined user는 policy가 기본 setuid transition을 명시적으로 허용하지 않으면 `sudo`/`su`를 아예 호출할 수 없다는 점도 기억해야 합니다. 따라서 `staff_u` + `sysadm_r`를 사용하는 host에서는 겉보기에는 사소해 보이는 `sudo ROLE=` / `TYPE=` rule이 실제 privilege boundary가 될 수 있습니다.

## SELinux in Containers

Container runtime은 일반적으로 workload를 `container_t` 같은 confined domain에서 시작하고 container content를 `container_file_t`로 label합니다. container process가 escape하더라도 여전히 container label을 유지한 채 실행되면, label boundary가 그대로 유지되었기 때문에 host write는 여전히 실패할 수 있습니다.

Quick example:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` 부분은 장식이 아니다. 많은 container 배포에서 runtime은 MCS categories를 동적으로 할당해서 `container_t`로 실행되는 두 process도 서로 분리되도록 한다. escape가 host namespace 안으로 들어가더라도 원래 category set을 유지하면, category mismatch가 일부 host path가 계속 unreadable하거나 unwritable한 이유를 설명할 수 있다.

주목할 만한 modern container 운영:

- `--security-opt label=disable`는 workload를 `spc_t` 같은 unconfined container-related type으로 effectively 옮길 수 있다
- `:z` / `:Z`가 붙은 bind mount는 shared/private container use를 위해 host path의 relabeling을 trigger한다
- host content의 broad relabeling은 그 자체로 security issue가 될 수 있다

이 페이지는 중복을 피하기 위해 container 내용을 짧게 유지한다. container-specific abuse cases와 runtime examples는 다음을 확인하라:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
