# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux는 **label-based Mandatory Access Control (MAC)** 시스템입니다. 실제로 이는 DAC permissions, groups 또는 Linux capabilities가 특정 작업에 충분해 보이더라도, 커널이 **source context**가 요청된 class/permission을 사용하여 **target context**에 액세스하는 것을 허용하지 않기 때문에 해당 작업을 거부할 수 있음을 의미합니다.<sup>[[1]](#references)</sup>

Context는 일반적으로 다음과 같은 형태입니다.<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
privesc 관점에서 `type`(프로세스의 경우 domain, 객체의 경우 type)은 일반적으로 가장 중요한 필드입니다:<sup>[[1]](#references)</sup>

- 프로세스는 `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`와 같은 **domain**에서 실행됩니다.
- 파일과 소켓에는 `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`와 같은 **type**이 지정됩니다.
- 정책은 한 domain이 다른 domain을 읽고/쓰고/실행하거나 transition할 수 있는지 결정합니다.

## 빠른 열거

SELinux가 활성화되어 있다면 초기에 열거해야 합니다. 일반적인 Linux privesc 경로가 실패하는 이유를 설명할 수 있고, "무해한" SELinux 도구를 감싼 권한 있는 wrapper가 실제로 중요한 이유도 설명할 수 있기 때문입니다:<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
유용한 후속 확인 사항:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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
Interesting findings:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- `Disabled` 또는 `Permissive` 모드는 경계로서 SELinux의 가치를 대부분 제거합니다.
- `unconfined_t`는 일반적으로 SELinux가 존재하지만 해당 프로세스를 의미 있게 제한하지 않는다는 뜻입니다.
- 사용자 지정 경로에 `default_t`, `file_t` 또는 명백히 잘못된 label이 지정되어 있다면 label이 잘못 지정되었거나 배포가 불완전할 가능성이 큽니다.
- `file_contexts.local`의 로컬 override는 policy 기본값보다 우선하므로 주의 깊게 검토해야 합니다.

## Policy 분석

다음 두 질문에 답할 수 있으면 SELinux를 공격하거나 우회하기가 훨씬 쉬워집니다.

1. **현재 domain에서 무엇에 액세스할 수 있는가?**
2. **어떤 domain으로 transition할 수 있는가?**

이를 위한 가장 유용한 도구는 `sepolicy`와 **SETools**(`seinfo`, `sesearch`, `sedta`)입니다:<sup>[[2]](#references)[[9]](#references)</sup>
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
이는 host가 모든 사용자를 `unconfined_u`에 매핑하는 대신 **confined users**를 사용하는 경우 특히 유용합니다. 이 경우 다음을 확인합니다:<sup>[[3]](#references)</sup>

- `semanage login -l`을 통한 사용자 매핑
- `semanage user -l`을 통한 허용된 role
- `sysadm_t`, `secadm_t`, `webadm_t`와 같이 접근 가능한 admin domain
- `ROLE=` 또는 `TYPE=`을 사용하는 `sudoers` 항목

`sudo -l`에 다음과 같은 항목이 포함되어 있다면 SELinux가 privilege boundary의 일부입니다:<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
또한 `newrole`을 사용할 수 있는지 확인합니다:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon`과 `newrole`은 자동으로 exploit 가능한 것은 아니지만, 권한이 있는 wrapper 또는 `sudoers` 규칙을 통해 더 나은 role/type을 선택할 수 있다면 높은 가치의 escalation primitive가 됩니다.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Files, Relabeling, and High-Value Misconfigurations

일반적인 SELinux 도구 간 가장 중요한 운영상의 차이점은 다음과 같습니다.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: 특정 path의 임시 label 변경
- `semanage fcontext`: 영구적인 path-to-label 규칙
- `restorecon` / `setfiles`: policy/default label을 다시 적용

이는 privesc 과정에서 매우 중요합니다. **relabeling은 단순한 외관상의 변경이 아니기 때문입니다.** 파일을 "policy에 의해 차단됨"에서 "권한이 있는 confined service가 읽거나 실행할 수 있음"으로 바꿀 수 있습니다.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

로컬 relabel 규칙과 relabel drift를 확인합니다.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
한 가지 미묘하지만 유용한 세부 사항은 일반적인 `restorecon`만으로는 의심스러운 label을 **항상 완전히 되돌리지 못한다**는 점입니다. 대상 type이 `customizable_types`에 포함되어 있다면, 전체 reset을 강제하기 위해 `-F`가 필요할 수 있습니다. Offensive 관점에서 보면, 이는 특이한 `chcon`이 "이미 restorecon을 실행했다"는 대략적인 cleanup 후에도 때때로 남아 있을 수 있는 이유를 설명합니다.<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
`sudo -l`, root wrappers, automation scripts 또는 file capabilities에서 우선적으로 확인할 가치가 높은 명령어:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
어느 MAC capability든 나타나면 [Linux capabilities page](linux-capabilities.md)도 함께 교차 확인해야 합니다. Linux capabilities 문서에서는 `cap_mac_admin` 및 `cap_mac_override`를 Smack 전용으로 설명하므로, 이름만 보고 SELinux를 우회한다고 가정해서는 안 됩니다.<sup>[[5]](#references)</sup>

특히 흥미로운 항목:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: 경로에 적용되어야 할 label을 영구적으로 변경
- `restorecon` / `setfiles`: 이러한 변경 사항을 대규모로 다시 적용
- `semodule -i`: custom policy module을 로드
- `semanage permissive -a <domain_t>`: 전체 host를 변경하지 않고 하나의 domain을 permissive로 설정
- `setsebool -P`: policy boolean을 영구적으로 변경
- `load_policy`: 활성 policy를 다시 로드

이들은 흔히 독립적인 root exploit이 아니라 **helper primitive**입니다. 이들의 가치는 다음과 같은 작업을 가능하게 한다는 점입니다:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- target domain을 permissive로 설정
- 자신의 domain과 protected type 간 access를 확대
- privileged service가 읽거나 실행할 수 있도록 attacker-controlled file의 label을 재지정
- 기존 local bug를 exploitable하게 만들 정도로 confined service를 약화

Example checks:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
root로 policy module을 로드할 수 있다면 일반적으로 SELinux 경계를 제어할 수 있습니다:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
그렇기 때문에 `audit2allow`, `semodule`, `semanage permissive`는 post-exploitation 중 민감한 관리자 표면으로 취급해야 합니다. 이들은 기존 UNIX permissions를 변경하지 않고도 차단된 chain을 조용히 작동하는 chain으로 바꿀 수 있습니다.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## 숨겨진 Denial과 Module 추출

매우 흔한 offensive frustration은 예상한 AVC denial이 전혀 나타나지 않은 채 chain이 무난한 `EACCES`와 함께 실패하는 경우입니다. `dontaudit` rules가 필요한 정확한 permission을 숨기고 있을 수 있습니다. `sudo` 또는 다른 privileged wrapper를 통해 `semodule`을 실행할 수 있다면, `dontaudit`를 일시적으로 비활성화하여 조용한 실패를 정확한 policy 단서로 바꿀 수 있습니다:<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
이는 로컬 관리자가 이미 변경한 내용을 검토할 때도 유용합니다. 작은 custom module이나 단일 도메인 permissive rule 때문에 대상 서비스가 base policy에서 예상되는 것보다 훨씬 느슨하게 동작하는 경우가 많습니다.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Audit Clues

AVC denial은 단순한 방어적 잡음이 아니라 공격 관점의 신호인 경우가 많습니다. 다음 정보를 알려 줍니다:<sup>[[1]](#references)[[15]](#references)</sup>

- 어떤 대상 object/type에 접근했는지
- 어떤 permission이 거부되었는지
- 현재 어떤 domain을 제어하고 있는지
- 작은 policy 변경으로 chain이 작동할 수 있는지
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
로컬 exploit 또는 persistence 시도가 `EACCES`나 이상한 "permission denied" 오류로 계속 실패하고, root처럼 보이는 DAC 권한이 있음에도 문제가 해결되지 않는다면 해당 vector를 포기하기 전에 SELinux를 확인해 볼 가치가 있습니다.<sup>[[1]](#references)</sup>

## SELinux 사용자

일반 Linux 사용자 외에도 SELinux 사용자가 존재합니다. 각 Linux 사용자는 policy의 일부로 SELinux 사용자에 매핑되며, 이를 통해 시스템은 계정마다 서로 다른 허용된 role과 domain을 적용할 수 있습니다.<sup>[[3]](#references)</sup>

빠른 확인:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
많은 mainstream 시스템에서는 사용자가 `unconfined_u`에 매핑되므로 사용자 confinement의 실제 영향이 줄어듭니다. 그러나 hardened deployment에서는 confined user가 `sudo`, `su`, `newrole`, `runcon`을 훨씬 더 흥미롭게 만들 수 있습니다. **escalation path가 UID 0이 되는 것뿐만 아니라 더 높은 SELinux role/type으로 진입하는 데 의존할 수 있기 때문입니다.** 또한 일부 confined user는 policy가 기본 setuid transition을 명시적으로 허용하지 않는 한 `sudo`/`su`를 전혀 실행할 수 없다는 점을 기억해야 합니다. 따라서 `staff_u` + `sysadm_r`를 사용하는 host에서는 겉보기에 사소한 `sudo ROLE=` / `TYPE=` rule이 실제 privilege boundary가 될 수 있습니다.<sup>[[3]](#references)</sup>

## 컨테이너의 SELinux

컨테이너 runtime은 일반적으로 workload를 `container_t`와 같은 confined domain에서 실행하고, 컨테이너 content에 `container_file_t` label을 지정합니다. 컨테이너 process가 escape하더라도 container label을 유지한 채 실행된다면 label boundary가 그대로 유지되므로 host에 대한 write가 여전히 실패할 수 있습니다.<sup>[[1]](#references)[[17]](#references)</sup>

간단한 예시:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` 부분은 장식이 아닙니다. 많은 container deployment에서 runtime은 MCS category를 동적으로 할당하므로, `container_t`로 실행되는 두 process도 서로 분리된 상태를 유지합니다. escape가 host namespace에 도달했지만 원래 category set을 유지한다면, category 불일치로 인해 일부 host path를 여전히 읽거나 쓸 수 없는 이유를 설명할 수 있습니다.<sup>[[17]](#references)</sup>

주목할 만한 최신 container operation:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable`은 container의 SELinux label separation을 해제합니다.
- `:z` / `:Z`가 포함된 bind mount는 shared/private container 사용을 위해 host path의 relabeling을 트리거합니다.
- host content에 대한 광범위한 relabeling은 그 자체로 security issue가 될 수 있습니다.

이 페이지에서는 중복을 피하기 위해 container 관련 내용을 간략하게 다룹니다. container별 abuse case와 runtime example은 다음을 참조하세요.

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Red Hat 문서: SELinux 사용](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: SELinux용 policy analysis tools](https://github.com/SELinuxProject/setools)
- [3] [제한된 사용자와 제한되지 않은 사용자 관리 - RHEL 9 문서](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Linux manual page](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Linux manual page](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Linux manual page](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Linux manual page](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Linux manual page](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Linux manual page](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Linux manual page](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Podman run 문서](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Linux container에 Multi-Category Security를 사용해야 하는 이유](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman top 문서](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Linux manual page](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}
