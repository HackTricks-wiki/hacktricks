# 체크리스트 - Linux 권한 상승

{{#include ../banners/hacktricks-training.md}}

### **로컬 Linux 권한 상승 벡터를 찾기 위한 최고의 도구:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] **OS 정보** 수집
- [ ] [**PATH**](privilege-escalation/index.html#path)를 확인, 쓰기 가능한 폴더가 있나요?
- [ ] [**env variables**](privilege-escalation/index.html#env-info)를 확인, 민감한 정보가 있나요?
- [ ] 스크립트를 사용해 [**kernel exploits**](privilege-escalation/index.html#kernel-exploits)를 검색 (DirtyCow?)
- [ ] [**sudo version**가 취약한지 확인](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] 추가 시스템 열거 ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [가능한 방어책들을 더 열거](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] 마운트된 드라이브 나열
- [ ] 마운트되지 않은 드라이브가 있나요?
- [ ] fstab에 자격증명이 있나요?

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] [**유용한 소프트웨어**가 설치되어 있는지 확인](privilege-escalation/index.html#useful-software)
- [ ] [**취약한 소프트웨어**가 설치되어 있는지 확인](privilege-escalation/index.html#vulnerable-software-installed)

### [Processes](privilege-escalation/index.html#processes)

- [ ] 알 수 없는 소프트웨어가 실행 중인가요?
- [ ] 권한이 과도한 소프트웨어가 실행 중인가요?
- [ ] 실행 중인 프로세스(특히 버전)에 대한 익스플로잇을 검색하세요.
- [ ] 실행 중인 프로세스의 바이너리를 수정할 수 있나요?
- [ ] 프로세스를 모니터링하고 흥미로운 프로세스가 자주 실행되는지 확인하세요.
- [ ] 암호 등이 저장되어 있을 수 있는 흥미로운 프로세스 메모리를 읽을 수 있나요?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] 어떤 cron이 [**PATH** ](privilege-escalation/index.html#cron-path)를 변경하고 있고 그 경로에 **쓰기**할 수 있나요?
- [ ] cron 작업에 [**와일드카드** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)가 있나요?
- [ ] 실행되는 일부 [**수정 가능한 스크립트** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink)가 있거나 **수정 가능한 폴더** 내부에 있나요?
- [ ] 일부 **스크립트**가 매우 [**자주 실행**](privilege-escalation/index.html#frequent-cron-jobs)되나요? (매 1, 2 또는 5분마다)

### [Services](privilege-escalation/index.html#services)

- [ ] 쓰기 가능한 .service 파일이 있나요?
- [ ] 서비스에 의해 실행되는 쓰기 가능한 바이너리가 있나요?
- [ ] systemd PATH에 쓰기 가능한 폴더가 있나요?
- [ ] `/etc/systemd/system/<unit>.d/*.conf`에 `ExecStart`/`User`를 덮어쓸 수 있는 쓰기 가능한 systemd unit drop-in이 있나요?

### [Timers](privilege-escalation/index.html#timers)

- [ ] 쓰기 가능한 타이머가 있나요?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] 쓰기 가능한 .socket 파일이 있나요?
- [ ] 어떤 소켓과 통신할 수 있나요?
- [ ] 흥미로운 정보를 가진 HTTP 소켓이 있나요?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] 어떤 D-Bus와 통신할 수 있나요?

### [Network](privilege-escalation/index.html#network)

- [ ] 네트워크를 열거하여 현재 위치를 파악
- [ ] 쉘을 얻기 전에는 접근할 수 없던 열린 포트가 있나요?
- [ ] `tcpdump`를 사용해 트래픽을 스니핑할 수 있나요?

### [Users](privilege-escalation/index.html#users)

- [ ] 일반 사용자/그룹 열거
- [ ] 매우 큰 UID를 가지고 있나요? 머신이 **취약**한가요?
- [ ] 속한 그룹 덕분에 [**권한을 상승시킬 수 있나요**](privilege-escalation/interesting-groups-linux-pe/index.html)?
- [ ] 클립보드 데이터?
- [ ] 암호 정책?
- [ ] 이전에 발견한 모든 알려진 암호를 사용해 가능한 모든 사용자로 로그인해 보세요. 암호 없이 로그인도 시도해 보세요.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] PATH의 일부 폴더에 **쓰기 권한**이 있으면 권한 상승이 가능할 수 있습니다

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] **sudo**로 어떤 명령이든 실행할 수 있나요? 이를 이용해 root로 무언가를 읽기, 쓰기 또는 실행할 수 있나요? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] `sudo -l`이 `sudoedit`을 허용한다면, 취약한 버전(`sudo -V` < 1.9.12p2)에서 `SUDO_EDITOR`/`VISUAL`/`EDITOR`를 통해 임의 파일을 편집할 수 있는 **sudoedit argument injection** (CVE-2023-22809)을 확인하세요. 예: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] exploitable한 SUID 바이너리가 있나요? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** 명령이 **path**로 제한되어 있나요? 제한을 **우회**할 수 있나요](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? 우회 가능?
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] 쓰기 가능한 폴더에서 로드될 수 있는 [**.so 라이브러리 부족 문제 in SUID binary**](privilege-escalation/index.html#suid-binary-so-injection)인가요?
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)? [**SUDO 토큰 생성 가능**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] [**sudoers 파일을 읽거나 수정할 수 있나요**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] `/etc/ld.so.conf.d/`를 수정할 수 있나요? (privilege-escalation/index.html#etc-ld-so-conf-d)
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) 명령

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] 어떤 바이너리에 예기치 않은 **capability**가 있나요?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] 어떤 파일에 예기치 않은 **ACL**이 설정되어 있나요?

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profile 파일** - 민감한 데이터 읽기? 권한 상승을 위해 쓰기 가능?
- [ ] **passwd/shadow 파일** - 민감한 데이터 읽기? 권한 상승을 위해 쓰기 가능?
- [ ] 민감한 데이터가 있는지 **흔히 관심 있는 폴더들** 확인
- [ ] **이상한 위치/소유 파일**, 실행 파일에 접근하거나 변경할 수 있는지
- [ ] 최근 몇 분 내에 **수정된 파일**
- [ ] **Sqlite DB 파일**
- [ ] **숨김 파일**
- [ ] **PATH의 스크립트/바이너리**
- [ ] **웹 파일** (암호?)
- [ ] **백업**?
- [ ] **암호를 포함하는 것으로 알려진 파일들**: **Linpeas**와 **LaZagne** 사용
- [ ] 일반적인 검색

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] 임의 명령을 실행하도록 **python 라이브러리 수정** 가능?
- [ ] **로그 파일**을 수정할 수 있나요? **Logtotten** 익스플로잇
- [ ] `/etc/sysconfig/network-scripts/`를 수정할 수 있나요? Centos/Redhat 익스플로잇
- [ ] [**ini, init.d, systemd 또는 rc.d 파일에 쓰기 가능**인지 확인](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] [**NFS를 악용해 권한 상승 가능한지**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] 제한된 쉘에서 탈출할 필요가 있나요? ([**escape from a restrictive shell**](privilege-escalation/index.html#escaping-from-restricted-shells))

## References

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
