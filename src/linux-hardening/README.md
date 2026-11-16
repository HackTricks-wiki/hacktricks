# Linux 강화

{{#include ../banners/hacktricks-training.md}}

이 섹션에서는 Linux 호스트를 조사하고, 권한 경계를 파악하고, 로컬 액세스를 제한하는 제어 기능을 검토합니다. 일반적인 평가를 위해 [Linux 기초](linux-basics/README.md)와 [권한 상승 체크리스트](main-system-information/linux-privilege-escalation-checklist.md)부터 살펴본 다음, 아래에서 관련 주제를 확인하세요.

- [Linux 기초](linux-basics/README.md): 권한 상승 방법론, 유용한 명령어, 환경 변수, 제한 우회.
- [주요 시스템 정보](main-system-information/README.md): 커널, 모듈, sudo, 파일시스템 동작, jail, 권한 상승 체크리스트.
- [사용자 정보](user-information/README.md): Linux ID, 그룹, SSH agent forwarding, Active Directory 통합.
- [흥미로운 파일 및 권한](interesting-files-permissions/README.md): 쓰기 가능한 경로, capabilities, SUID 동작, NFS, 와일드카드 확장, SELinux.
- [네트워크 정보](network-information/README.md): 로컬 서비스, 소켓, 네트워크 관련 exploit 예시.
- [소프트웨어 정보](software-information/README.md): 인증 모듈 및 애플리케이션별 공격 표면.
- [프로세스, crontab, systemd 및 D-Bus](processes-crontab-systemd-dbus/README.md): 예약 실행 및 프로세스 간 통신.
- [컨테이너 및 네임스페이스](containers-namespaces/README.md): 런타임, 격리 경계, 컨테이너 강화.
- [AppArmor 정책 제어 파일 악용](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): 권한이 있는 helper가 로컬 사용자가 연 AppArmor 제어 파일에 쓸 수 있는지 확인합니다.
- [Post-exploitation](post-exploitation/README.md): 자격 증명 탐색, persistence, 호스트 수준의 후속 기법.

영향을 받는 커널에서는 권한이 없는 사용자가 AppArmor securityfs 정책 제어 파일을 열 수 있지만, 직접 쓰기는 거부될 수 있습니다. 권한이 있는 helper가 해당 파일을 stdout으로 상속하면, helper의 쓰기로 로드된 정책을 변경할 수 있습니다. 이는 취약한 컨테이너 프로필을 찾는 것과는 별개의 로컬 공격 경로입니다. 테스트 전에 해당 커널 공급업체와 helper의 수정 사항을 확인하세요.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Qualys CrackArmor 기술 권고](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Ubuntu CrackArmor 취약점 지식 베이스](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
