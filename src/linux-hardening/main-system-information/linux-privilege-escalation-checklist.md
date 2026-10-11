# Linux 권한 상승 체크리스트

{{#include ../../banners/hacktricks-training.md}}

# 체크리스트 - Linux 권한 상승



### **Linux 로컬 권한 상승 벡터를 찾는 데 가장 좋은 도구:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [시스템 정보](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS 정보** 확인
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) 확인. **쓰기 가능한 폴더**가 있는가?
- [ ] [**환경 변수**](../linux-basics/linux-privilege-escalation/index.html#env-info) 확인. 민감한 정보가 있는가?
- [ ] **스크립트를 사용해** [**kernel exploit**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) 검색 (DirtyCow?)
- [ ] kernel PoC를 실행하기 전에 `uname -r`만 보지 말고 **실제 필수 조건**을 확인하세요. 아키텍처, 필요한 `CONFIG_*` 옵션/모듈, namespace 생성 가능 여부, 활성화된 완화책을 점검합니다. 예를 들어 `unshare -Urn true`로 user/network namespace 사용 가능 여부를 테스트하세요. 최신 netfilter exploit은 `CONFIG_USER_NS`, 비특권 user namespace, `CONFIG_NF_TABLES`가 필요할 수 있습니다.<sup>[[3]](#references)</sup>
- [ ] [**sudo 버전**이 취약한지 **확인**](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** 서명 검증 실패](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module 및 module 로딩 설정 오류**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) 검토: `insmod`, `modinfo`, `lsmod`, `dmesg`, 서명 적용, `modules_disabled`.
- [ ] helper 경로를 수정하거나 트리거할 수 있는 경우 [**kernel.modprobe / modprobe_path 악용 경로**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) 확인.
- [ ] [**쓰기 가능한 /lib/modules 경로**](kernel-modules-and-modprobe.md#writable-libmodules-review) 확인. 쓰기 가능한 `.ko*` 파일과 `modules.*` metadata도 점검합니다.
- [ ] 추가 시스템 열거 ([날짜, 시스템 통계, CPU 정보, 프린터](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [추가 방어책 열거](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [드라이브](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] 마운트된 드라이브 **목록 확인**
- [ ] **마운트되지 않은 드라이브가 있는가?**
- [ ] fstab에 **자격 증명이 있는가?**

### [**설치된 소프트웨어**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] [**유용한 소프트웨어**](../linux-basics/linux-privilege-escalation/index.html#useful-software)가 **설치되어 있는지 확인**
- [ ] [**취약한 소프트웨어**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)가 **설치되어 있는지 확인**
- [ ] Debian/Ubuntu에서는 **needrestart interpreter scanning**이 설치/활성화되어 있는지 확인합니다: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. 취약한 빌드는 APT나 `unattended-upgrades`가 root 권한으로 needrestart를 실행할 때 공격자가 제어하는 `PYTHONPATH`/`RUBYLIB`를 재사용하거나, `/proc/<pid>/exe`에 race condition을 일으키거나, 공격자가 제어하는 Perl 경로를 검사해 권한 경계를 넘었습니다.<sup>[[4]](#references)</sup>

### [프로세스](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] **알 수 없는 소프트웨어가 실행 중인가?**
- [ ] 소프트웨어가 필요한 수준보다 **높은 권한으로 실행 중인가?**
- [ ] **실행 중인 프로세스의 exploit**을 검색합니다 (특히 현재 실행 중인 버전).
- [ ] 실행 중인 프로세스의 **바이너리를 수정할 수 있는가?**
- [ ] **프로세스를 모니터링**하고 흥미로운 프로세스가 자주 실행되는지 확인합니다.
- [ ] 흥미로운 **프로세스 메모리**(암호가 저장되어 있을 수 있는 곳)를 **읽을 수 있는가?**

### [예약 작업/Cron 작업?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] cron이 [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)을 수정하고 있으며 해당 경로에 **쓸 수 있는가?**
- [ ] cron 작업에 [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)가 있는가?
- [ ] [**수정 가능한 스크립트** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)가 **실행되고 있거나**, **수정 가능한 폴더** 안에 있는가?
- [ ] [**매우 자주 실행되는**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) **스크립트**를 발견했는가? (1분, 2분 또는 5분마다)

### [서비스](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] **쓰기 가능한 .service** 파일이 있는가?
- [ ] **서비스가 실행하는 쓰기 가능한 바이너리**가 있는가?
- [ ] **root unit이 참조하는 쓰기 가능한 helper, config 또는 environment 파일**(`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)이 있는가? `systemctl cat <unit>`으로 병합된 unit을 확인하고 [service/socket 파일 악용](../interesting-files-permissions/write-to-root.md)을 검토합니다.
- [ ] 필요할 때 실행되는 권한 있는 workflow가 권한이 낮은 사용자가 쓸 수 있는 디렉터리의 helper를 실행하는가? helper와 상위 디렉터리 모두에서 [사용자 수정 가능 경로의 root 실행](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries)을 확인합니다. 짧게 실행되는 helper는 workflow가 동작 중일 때만 보일 수 있습니다.
- [ ] **systemd PATH에 쓰기 가능한 폴더**가 있는가?
- [ ] `ExecStart`/`User`를 덮어쓸 수 있는 `/etc/systemd/system/<unit>.d/*.conf`의 **쓰기 가능한 systemd unit drop-in**이 있는가?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] 쓰기 가능한 **timer**가 있는가?

### [소켓](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] 쓰기 가능한 **.socket** 파일이 있는가?
- [ ] 소켓과 **통신할 수 있는가?**
- [ ] 흥미로운 정보가 담긴 **HTTP 소켓**이 있는가?
- [ ] `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` 또는 kubelet endpoint 같은 [**container-runtime 또는 node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md)에 접근할 수 있는가? 일반적인 CLI가 없어도 raw HTTP/gRPC API를 테스트하세요.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] D-Bus와 **통신할 수 있는가?**

### [네트워크](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] 현재 위치를 파악하기 위해 네트워크 열거
- [ ] 시스템 내부에서 shell을 얻은 뒤에야 접근할 수 있는 **열린 포트가 있는가?**
- [ ] `tcpdump`로 트래픽을 **스니핑할 수 있는가?**

### [사용자](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] 일반 사용자/그룹 **열거**
- [ ] **매우 큰 UID**를 가지고 있는가? **시스템**이 **취약한가?**
- [ ] 소속된 [**그룹을 이용해 권한을 상승할 수 있는가?**](../user-information/interesting-groups-linux-pe/index.html)
- [ ] **클립보드** 데이터가 있는가?
- [ ] 암호 정책은?
- [ ] 이전에 발견한 **모든 알려진 암호를 사용해** 가능한 **각 사용자로** 로그인해 봅니다. 암호 없이도 로그인을 시도합니다.

### [쓰기 가능한 PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] PATH 내 폴더에 **쓰기 권한이 있다면** 권한을 상승할 수 있습니다.

### [SUDO 및 SUID 명령](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] `sudo`로 **명령을 실행할 수 있는가?** 이를 이용해 root 권한으로 무엇이든 READ, WRITE 또는 EXECUTE할 수 있는가? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] `sudo -l`에서 `sudoedit`가 허용되면 취약한 버전(`sudo -V` < 1.9.12p2)에서 `SUDO_EDITOR`/`VISUAL`/`EDITOR`를 통한 **sudoedit 인자 주입**(CVE-2023-22809)을 확인합니다. 임의 파일을 편집할 수 있습니다. 예: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] **악용 가능한 SUID 바이너리**가 있는가? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** 명령이 **경로**로 **제한**되어 있는가? 제한을 **우회할 수 있는가?**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)
- [ ] [**경로가 지정되지 않은 Sudo/SUID 바이너리**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)가 있는가?
- [ ] [**경로를 지정하는 SUID 바이너리**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)가 있는가? 우회
- [ ] [**LD_PRELOAD 취약점**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] 쓰기 가능한 폴더에서 [**SUID 바이너리에 필요한 .so 라이브러리가 누락**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection)되어 있는가?
- [ ] [**SUID RPATH/RUNPATH 또는 쓰기 가능한 라이브러리 경로**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)가 있는가?
- [ ] [**사용 가능한 SUDO token**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)이 있는가? [**SUDO token을 만들 수 있는가?**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)
- [ ] [**sudoers 파일을 읽거나 수정할 수 있는가?**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)
- [ ] [**/etc/ld.so.conf.d/를 수정할 수 있는가?**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) 명령

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] 바이너리에 **예상치 못한 capability**가 있는가?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] 파일에 **예상치 못한 ACL**이 있는가?

### [열려 있는 Shell 세션](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL 예측 가능한 PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH에서 흥미로운 설정 값**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [흥미로운 파일](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile 파일** - 민감한 데이터를 읽을 수 있는가? 권한 상승을 위해 쓸 수 있는가?
- [ ] **passwd/shadow 파일** - 민감한 데이터를 읽을 수 있는가? 권한 상승을 위해 쓸 수 있는가?
- [ ] 민감한 데이터가 있는지 **흔히 주목할 만한 폴더 확인**
- [ ] **이상한 위치/소유 파일** - 실행 파일에 접근하거나 수정할 수 있는가?
- [ ] 최근 몇 분 안에 **수정된 파일**
- [ ] **Sqlite DB 파일**
- [ ] **숨김 파일**
- [ ] PATH 내 **스크립트/바이너리**
- [ ] **웹 파일** (암호?)
- [ ] **백업**?
- [ ] 암호가 들어 있는 것으로 **알려진 파일**: **Linpeas**와 **LaZagne** 사용
- [ ] **일반 검색**

### [**쓰기 가능한 파일**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] 임의 명령을 실행하도록 **python 라이브러리를 수정할 수 있는가?**
- [ ] **로그 파일을 수정할 수 있는가?** **Logtotten** exploit
- [ ] **/etc/sysconfig/network-scripts/**를 수정할 수 있는가? Centos/Redhat exploit
- [ ] [**ini, int.d, systemd 또는 rc.d 파일에 쓸 수 있는가?**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)

### [**기타 트릭**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**NFS를 악용해 권한을 상승할 수 있는가?**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)
- [ ] [**제한된 shell에서 탈출해야 하는가?**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)



## References

- [1] [Sudo 권고문: sudoedit 임의 파일 편집](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux 문서: systemd drop-in 설정](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit 요구 사항 및 조사](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys 보안 권고문: needrestart의 LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
