# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux는 **label 기반 Mandatory Access Control (MAC)** 시스템입니다. 실제로는 DAC 권한, 그룹 또는 Linux capabilities가 어떤 작업을 수행하기에 충분해 보여도, **source context**가 요청된 class/permission으로 **target context**에 접근하도록 허용되지 않으면 커널이 해당 작업을 거부할 수 있다는 뜻입니다.<sup>[[1]](#references)</sup>

context는 보통 다음과 같은 형태입니다:<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

privesc 관점에서 `type`(프로세스의 경우 domain, 객체의 경우 type)은 보통 가장 중요한 필드입니다:<sup>[[1]](#references)</sup>

- 프로세스는 `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`와 같은 **domain**에서 실행됩니다.
- 파일과 소켓에는 `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`와 같은 **type**이 지정됩니다.
- Policy는 한 domain이 다른 domain에 대해 read/write/execute/transition할 수 있는지 결정합니다.

## 빠른 열거

SELinux가 활성화되어 있다면 초기에 열거하세요. 일반적인 Linux privesc 경로가 실패하는 이유를 설명하거나, "무해한" SELinux 도구를 감싼 privileged wrapper가 실제로는 중요한 이유를 파악하는 데 도움이 됩니다:<sup>[[1]](#references)</sup>

```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```

유용한 후속 점검:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>

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

- `Disabled` 또는 `Permissive` 모드에서는 경계로서 SELinux가 제공하는 가치가 대부분 사라집니다.
- `unconfined_t`는 일반적으로 SELinux가 설치되어 있지만 해당 프로세스를 실질적으로 제한하지 않는다는 뜻입니다.
- 사용자 지정 경로에 `default_t`, `file_t` 또는 명백히 잘못된 레이블이 지정되어 있다면 레이블이 잘못 지정되었거나 배포가 완료되지 않았을 가능성이 높습니다.
- `file_contexts.local`의 로컬 재정의는 정책 기본값보다 우선하므로 주의 깊게 검토하세요.

## 정책 분석

다음 두 질문에 답할 수 있으면 SELinux를 공격하거나 우회하기가 훨씬 쉬워집니다.

1. **현재 도메인에서 무엇에 접근할 수 있는가?**
2. **어떤 도메인으로 전환할 수 있는가?**

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

이는 호스트가 모든 사용자를 `unconfined_u`에 매핑하는 대신 **제한된 사용자**를 사용하는 경우 특히 유용합니다. 이 경우 다음을 확인하세요:<sup>[[3]](#references)</sup>

- `semanage login -l`을 통한 사용자 매핑
- `semanage user -l`을 통해 허용된 역할
- `sysadm_t`, `secadm_t`, `webadm_t`와 같은 접근 가능한 관리자 도메인
- `ROLE=` 또는 `TYPE=`을 사용하는 `sudoers` 항목

`sudo -l`에 다음과 같은 항목이 있으면 SELinux가 권한 경계의 일부입니다:<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

또한 `newrole`을 사용할 수 있는지 확인하세요:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon`과 `newrole`은 자동으로 악용 가능한 것은 아니지만, 권한이 있는 wrapper나 `sudoers` 규칙을 통해 더 유리한 role/type을 선택할 수 있다면 높은 가치의 권한 상승 수단이 됩니다.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### 쓰기 가능한 전이 진입점 감사

전이 그래프는 정책을 살펴볼 단서일 뿐입니다. 이를 공격 경로로 만들려면 더 유용한 도메인으로 진입하는 실행 파일의 type을 식별한 다음, 해당 레이블이 지정된 실행 파일을 수정할 수 있는지 또는 상위 디렉터리를 통해 실행 파일을 교체할 수 있는지 확인해야 합니다.<sup>[[9]](#references)[[20]](#references)</sup> 자동 `execve` 전이에는 적용 가능한 `type_transition` 규칙, 소스 도메인의 실행 권한, 대상 도메인의 `entrypoint` 권한, 그리고 도메인 간 전이 권한이 필요합니다.<sup>[[20]](#references)</sup> 대상 도메인은 SELinux 액세스 권한을 얻을 수 있지만, 실행 자체로는 Linux UID가 변경되지 않습니다. [SUID/SGID 및 ACL](suid-sgid-and-acl-triage.md)은 별도로 확인하세요.<sup>[[20]](#references)[[21]](#references)</sup>

보고된 entrypoint type을 사용해 관련 규칙을 확인한 다음, 해당 경로와 상위 디렉터리에 쓰기 권한이 있는지 살펴보세요.<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

진입점 유형을 실제 실행 파일 경로와 연관 지으세요. 정책의 허용 규칙을 실제로 사용할 수 있는지 판단하기 전에 파일 또는 상위 디렉터리에 대한 DAC, ACL, SELinux 쓰기 권한, 파일 레이블, 조건부 boolean을 확인하세요.<sup>[[20]](#references)[[22]](#references)</sup> 경로를 제자리에서 수정하는 대신 교체한다면 새 inode의 context를 확인하세요. 파일시스템 레이블은 확장 속성으로 저장되므로, 교체된 파일에 진입점 유형이 유지되지 않을 수 있습니다.<sup>[[21]](#references)</sup> SELinux를 인식하는 프로그램은 `setexeccon`으로 전환을 요청할 수 있으므로, 자동 `type_transition` 규칙이 없다고 해서 모든 전환 가능성이 배제되는 것은 아닙니다.<sup>[[20]](#references)</sup>

## 파일, 레이블 재지정 및 주요 가치가 높은 잘못된 설정

일반적으로 사용하는 SELinux 도구 간의 가장 중요한 실무상 차이는 다음과 같습니다.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: 특정 경로의 레이블을 일시적으로 변경
- `semanage fcontext`: 경로와 레이블 간의 영구 규칙
- `restorecon` / `setfiles`: 정책/기본 레이블 다시 적용

privesc 과정에서 이는 매우 중요합니다. **레이블 재지정은 단순한 외관상의 변경이 아닙니다.** 파일을 "정책에 의해 차단된" 상태에서 "권한이 높은 제한 서비스가 읽거나 실행할 수 있는" 상태로 바꿀 수 있습니다.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

로컬 레이블 재지정 규칙과 레이블 변경 상태를 확인하세요.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

한 가지 미묘하지만 유용한 점은 일반 `restorecon`이 **의심스러운 레이블을 항상 완전히 되돌리는 것은 아니라는 것**입니다. 대상 유형이 `customizable_types`에 있다면 완전히 초기화하기 위해 `-F`를 사용해야 할 수 있습니다. 공격자 관점에서는 이 때문에 비정상적인 `chcon`이 "이미 restorecon을 실행했다"는 허술한 정리 후에도 남아 있을 수 있습니다.<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

`sudo -l`, root 래퍼, 자동화 스크립트 또는 파일 capability에서 찾아볼 가치가 높은 명령:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

MAC capability 중 하나라도 표시되면 [Linux capabilities page](linux-capabilities.md)도 함께 확인하세요. Linux capabilities 문서에서는 `cap_mac_admin`과 `cap_mac_override`가 Smack 전용이라고 설명하므로, 이름만 보고 SELinux를 우회한다고 단정하지 마세요.<sup>[[5]](#references)</sup>

특히 주목할 항목:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: 경로에 적용할 레이블을 지속적으로 변경
- `restorecon` / `setfiles`: 이러한 변경 사항을 대규모로 재적용
- `semodule -i`: 사용자 지정 policy module을 로드
- `semanage permissive -a <domain_t>`: 전체 호스트를 permissive로 전환하지 않고 특정 domain만 permissive로 설정
- `setsebool -P`: policy boolean을 영구적으로 변경
- `load_policy`: 활성 policy를 다시 로드

이러한 기능은 독립적인 root exploit이라기보다 **helper primitive**인 경우가 많습니다. 그 가치는 다음과 같은 작업을 가능하게 한다는 데 있습니다:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- 대상 domain을 permissive로 설정
- 내 domain과 보호된 type 간의 접근 범위를 확대
- 공격자가 제어하는 파일의 레이블을 변경해 권한이 있는 서비스가 해당 파일을 읽거나 실행하도록 설정
- 제한된 서비스를 충분히 약화해 기존 local bug를 악용 가능하게 만들기

확인 예시:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```

root로 policy module을 로드할 수 있다면, 일반적으로 SELinux 경계를 제어할 수 있습니다:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>

```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```

그렇기 때문에 `audit2allow`, `semodule`, `semanage permissive`는 post-exploitation 중 민감한 관리자 인터페이스로 취급해야 합니다. 이러한 도구는 기존 UNIX 권한을 변경하지 않고도 차단된 체인을 작동하는 체인으로 조용히 바꿀 수 있습니다.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## 숨겨진 거부와 모듈 추출

흔히 겪는 공격상의 난관은 예상한 AVC 거부 기록이 나타나지 않은 채 일반적인 `EACCES` 오류만으로 체인이 실패하는 것입니다. `dontaudit` 규칙이 필요한 정확한 권한을 숨기고 있을 수 있습니다. `sudo` 또는 다른 권한 있는 래퍼를 통해 `semodule`을 실행할 수 있다면, `dontaudit`를 일시적으로 비활성화하여 조용한 실패를 정확한 정책 단서로 바꿀 수 있습니다.<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

이는 로컬 관리자가 이미 변경한 내용을 검토할 때도 유용합니다. 작은 custom module이나 특정 도메인에 대한 permissive rule 하나가 대상 서비스의 동작을 기본 policy가 예상하는 것보다 훨씬 느슨하게 만드는 원인인 경우가 많습니다.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Audit 단서

AVC 거부는 방어 측 잡음에 그치지 않고 공격 관점의 신호인 경우가 많습니다. 다음 정보를 알려 줍니다:<sup>[[1]](#references)[[15]](#references)</sup>

- 어떤 대상 객체/type에 접근했는지
- 어떤 permission이 거부되었는지
- 현재 어떤 domain을 제어하는지
- 작은 policy 변경으로 공격 체인이 작동할지 여부

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

로컬 exploit이나 persistence 시도가 `EACCES` 또는 이상한 "permission denied" 오류로 계속 실패하고, DAC 권한은 root 권한처럼 보인다면 이 벡터를 포기하기 전에 SELinux를 확인해 볼 가치가 있습니다.<sup>[[1]](#references)</sup>

## SELinux 사용자

일반 Linux 사용자 외에도 SELinux 사용자가 있습니다. 정책의 일부로 각 Linux 사용자는 SELinux 사용자에 매핑되며, 이를 통해 시스템은 계정마다 허용되는 역할과 도메인을 다르게 적용할 수 있습니다.<sup>[[3]](#references)</sup>

빠른 확인:<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

많은 주류 시스템에서는 사용자를 `unconfined_u`에 매핑하므로 사용자 격리의 실질적인 효과가 줄어듭니다. 하지만 강화된 배포 환경에서는 **권한 상승 경로가 UID 0이 되는 것뿐 아니라 더 적합한 SELinux role/type으로 전환하는 데 달려 있을 수 있으므로**, 격리된 사용자의 `sudo`, `su`, `newrole`, `runcon`이 훨씬 더 중요해질 수 있습니다. 또한 일부 격리된 사용자는 정책에서 기본 setuid 전환을 명시적으로 허용하지 않으면 `sudo`/`su`를 실행할 수 없다는 점도 기억하세요. 따라서 `staff_u` + `sysadm_r`를 사용하는 호스트에서는 사소해 보이는 `sudo ROLE=` / `TYPE=` 규칙이 실제 권한 경계가 될 수 있습니다.<sup>[[3]](#references)</sup>

## SELinux in Containers

컨테이너 런타임은 일반적으로 `container_t`와 같은 격리된 도메인에서 워크로드를 실행하고, 컨테이너 콘텐츠에는 `container_file_t` 레이블을 지정합니다. 컨테이너 프로세스가 탈출하더라도 컨테이너 레이블을 유지하고 있다면 레이블 경계가 그대로 유지되어 호스트에 쓰기 작업을 하지 못할 수 있습니다.<sup>[[1]](#references)[[17]](#references)</sup>

간단한 예시:<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

`c647,c780` 부분은 장식이 아닙니다. 많은 컨테이너 배포 환경에서 런타임은 MCS 카테고리를 동적으로 할당하므로, `container_t`로 실행되는 두 프로세스도 서로 격리됩니다. 탈출에 성공해 호스트 네임스페이스에 진입하더라도 원래 카테고리 집합이 유지되면, 카테고리 불일치로 인해 일부 호스트 경로를 읽거나 쓸 수 없는 이유를 설명할 수 있습니다.<sup>[[17]](#references)</sup>

주목할 만한 최신 컨테이너 작업:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable`은 컨테이너의 SELinux 레이블 격리를 비활성화합니다
- `:z` / `:Z`가 붙은 bind mount는 공유/전용 컨테이너 사용을 위해 호스트 경로의 레이블을 변경합니다
- 호스트 콘텐츠를 광범위하게 다시 레이블링하면 그 자체로 보안 문제가 될 수 있습니다

중복을 피하기 위해 이 페이지에서는 컨테이너 콘텐츠를 간략하게 다룹니다. 컨테이너별 악용 사례와 런타임 예시는 다음을 참조하세요.

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}



## References

- [1] [Red Hat 문서: SELinux 사용하기](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: SELinux 정책 분석 도구](https://github.com/SELinuxProject/setools)
- [3] [제한된 사용자 및 제한되지 않은 사용자 관리 - RHEL 9 문서](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Podman run 문서](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Linux 컨테이너에 Multi-Category Security를 사용해야 하는 이유](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman top 문서](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/selinux.8.html)
- [20] [SELinux Notebook: 도메인 및 객체 전환](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10: SELinux 사용하기](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [SETools sesearch(1) 매뉴얼](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
