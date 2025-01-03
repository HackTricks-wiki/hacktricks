# 체크리스트 - 리눅스 권한 상승

{{#include ../banners/hacktricks-training.md}}

### **리눅스 로컬 권한 상승 벡터를 찾기 위한 최고의 도구:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [시스템 정보](privilege-escalation/#system-information)

- [ ] **OS 정보** 가져오기
- [ ] [**PATH**](privilege-escalation/#path) 확인, **쓰기 가능한 폴더**가 있나요?
- [ ] [**env 변수**](privilege-escalation/#env-info) 확인, 민감한 정보가 있나요?
- [ ] [**커널 익스플로잇**](privilege-escalation/#kernel-exploits) **스크립트를 사용하여** 검색 (DirtyCow?)
- [ ] [**sudo 버전**이 취약한지](privilege-escalation/#sudo-version) **확인**
- [ ] [**Dmesg** 서명 검증 실패](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] 더 많은 시스템 열거 ([날짜, 시스템 통계, CPU 정보, 프린터](privilege-escalation/#more-system-enumeration))
- [ ] [더 많은 방어 수단 열거](privilege-escalation/#enumerate-possible-defenses)

### [드라이브](privilege-escalation/#drives)

- [ ] **마운트된** 드라이브 목록
- [ ] **마운트되지 않은 드라이브가 있나요?**
- [ ] **fstab에 자격 증명**이 있나요?

### [**설치된 소프트웨어**](privilege-escalation/#installed-software)

- [ ] **설치된** [**유용한 소프트웨어**](privilege-escalation/#useful-software) **확인**
- [ ] **설치된** [**취약한 소프트웨어**](privilege-escalation/#vulnerable-software-installed) **확인**

### [프로세스](privilege-escalation/#processes)

- [ ] **알 수 없는 소프트웨어가 실행되고** 있나요?
- [ ] **더 많은 권한을 가진** 소프트웨어가 실행되고 있나요?
- [ ] **실행 중인 프로세스의 익스플로잇** 검색 (특히 실행 중인 버전).
- [ ] **실행 중인 프로세스의 바이너리**를 **수정**할 수 있나요?
- [ ] **프로세스 모니터링** 및 흥미로운 프로세스가 자주 실행되는지 확인.
- [ ] **흥미로운 프로세스 메모리**를 **읽을 수** 있나요 (비밀번호가 저장될 수 있는 곳)?

### [예약된/크론 작업?](privilege-escalation/#scheduled-jobs)

- [ ] [**PATH**](privilege-escalation/#cron-path)가 크론에 의해 수정되고 있으며, **쓰기**가 가능한가요?
- [ ] 크론 작업에 [**와일드카드**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)가 있나요?
- [ ] **수정 가능한 스크립트**가 **실행**되거나 **수정 가능한 폴더**에 있나요?
- [ ] 어떤 **스크립트**가 [**매우 자주**](privilege-escalation/#frequent-cron-jobs) **실행되고** 있는지 감지했나요? (매 1, 2 또는 5분마다)

### [서비스](privilege-escalation/#services)

- [ ] **쓰기 가능한 .service** 파일이 있나요?
- [ ] **서비스**에 의해 실행되는 **쓰기 가능한 바이너리**가 있나요?
- [ ] **systemd PATH**에 **쓰기 가능한 폴더**가 있나요?

### [타이머](privilege-escalation/#timers)

- [ ] **쓰기 가능한 타이머**가 있나요?

### [소켓](privilege-escalation/#sockets)

- [ ] **쓰기 가능한 .socket** 파일이 있나요?
- [ ] **어떤 소켓과 통신**할 수 있나요?
- [ ] 흥미로운 정보가 있는 **HTTP 소켓**이 있나요?

### [D-Bus](privilege-escalation/#d-bus)

- [ ] **어떤 D-Bus와 통신**할 수 있나요?

### [네트워크](privilege-escalation/#network)

- [ ] 네트워크를 열거하여 당신의 위치를 파악하세요
- [ ] **이전에 접근할 수 없었던 열린 포트**가 있나요?
- [ ] `tcpdump`를 사용하여 **트래픽을 스니핑**할 수 있나요?

### [사용자](privilege-escalation/#users)

- [ ] 일반 사용자/그룹 **열거**
- [ ] **매우 큰 UID**가 있나요? **기계**가 **취약한가요**?
- [ ] 당신이 속한 [**그룹 덕분에 권한을 상승**](privilege-escalation/interesting-groups-linux-pe/)시킬 수 있나요?
- [ ] **클립보드** 데이터?
- [ ] 비밀번호 정책?
- [ ] 이전에 발견한 **모든 알려진 비밀번호**를 사용하여 **각 사용자**로 로그인 시도. 비밀번호 없이도 로그인 시도.

### [쓰기 가능한 PATH](privilege-escalation/#writable-path-abuses)

- [ ] **PATH의 일부 폴더에 대한 쓰기 권한**이 있다면 권한을 상승시킬 수 있습니다.

### [SUDO 및 SUID 명령](privilege-escalation/#sudo-and-suid)

- [ ] **sudo로 어떤 명령을 실행**할 수 있나요? 루트로 **READ, WRITE 또는 EXECUTE**할 수 있나요? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] **익스플로잇 가능한 SUID 바이너리**가 있나요? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** 명령이 **경로에 의해 제한**되어 있나요? 제한을 **우회**할 수 있나요](privilege-escalation/#sudo-execution-bypassing-paths)?
- [ ] [**경로가 표시되지 않은 Sudo/SUID 바이너리**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
- [ ] [**경로를 지정한 SUID 바이너리**](privilege-escalation/#suid-binary-with-command-path)? 우회
- [ ] [**LD_PRELOAD 취약점**](privilege-escalation/#ld_preload)
- [ ] **쓰기 가능한 폴더에서** [**SUID 바이너리에 .so 라이브러리 부족**](privilege-escalation/#suid-binary-so-injection)?
- [ ] [**SUDO 토큰 사용 가능**](privilege-escalation/#reusing-sudo-tokens)? [**SUDO 토큰을 생성할 수 있나요**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] [**sudoers 파일을 읽거나 수정**](privilege-escalation/#etc-sudoers-etc-sudoers-d)할 수 있나요?
- [ ] [**/etc/ld.so.conf.d/**를 **수정**할 수 있나요](privilege-escalation/#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) 명령

### [능력](privilege-escalation/#capabilities)

- [ ] 어떤 바이너리에 **예상치 못한 능력**이 있나요?

### [ACLs](privilege-escalation/#acls)

- [ ] 어떤 파일에 **예상치 못한 ACL**이 있나요?

### [열린 셸 세션](privilege-escalation/#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

- [ ] **Debian** [**OpenSSL 예측 가능한 PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH 흥미로운 구성 값**](privilege-escalation/#ssh-interesting-configuration-values)

### [흥미로운 파일](privilege-escalation/#interesting-files)

- [ ] **프로파일 파일** - 민감한 데이터 읽기? privesc에 쓰기?
- [ ] **passwd/shadow 파일** - 민감한 데이터 읽기? privesc에 쓰기?
- [ ] 민감한 데이터를 위해 **일반적으로 흥미로운 폴더** 확인
- [ ] **이상한 위치/소유 파일,** 접근하거나 실행 파일을 변경할 수 있습니다
- [ ] **최근 몇 분 내에 수정됨**
- [ ] **Sqlite DB 파일**
- [ ] **숨겨진 파일**
- [ ] **PATH의 스크립트/바이너리**
- [ ] **웹 파일** (비밀번호?)
- [ ] **백업**?
- [ ] **비밀번호가 포함된 알려진 파일**: **Linpeas** 및 **LaZagne** 사용
- [ ] **일반 검색**

### [**쓰기 가능한 파일**](privilege-escalation/#writable-files)

- [ ] **임의의 명령을 실행하기 위해 파이썬 라이브러리 수정**?
- [ ] **로그 파일을 수정**할 수 있나요? **Logtotten** 익스플로잇
- [ ] **/etc/sysconfig/network-scripts/**를 **수정**할 수 있나요? Centos/Redhat 익스플로잇
- [ ] [**ini, int.d, systemd 또는 rc.d 파일에 쓸 수 있나요**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**기타 트릭**](privilege-escalation/#other-tricks)

- [ ] [**NFS를 악용하여 권한을 상승**](privilege-escalation/#nfs-privilege-escalation)시킬 수 있나요?
- [ ] [**제한된 셸에서 탈출**](privilege-escalation/#escaping-from-restricted-shells)해야 하나요?

{{#include ../banners/hacktricks-training.md}}
