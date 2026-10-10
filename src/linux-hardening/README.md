# Linux 강화

{{#include ../banners/hacktricks-training.md}}

이 섹션에서는 Linux 호스트를 조사하고, 권한 경계를 이해하며, 로컬 액세스를 제한하는 통제를 검토합니다. 일반적인 평가를 위해 [Linux 기본 사항](linux-basics/README.md)과 [권한 상승 체크리스트](main-system-information/linux-privilege-escalation-checklist.md)부터 살펴본 다음, 아래에서 관련 주제를 확인하세요.

- [Linux 기본 사항](linux-basics/README.md): privilege escalation 방법론, 유용한 명령어, 환경 변수 및 제한 우회.
- [주요 시스템 정보](main-system-information/README.md): 커널, 모듈, sudo, 파일 시스템 동작, jail 및 privilege escalation 체크리스트.
- [사용자 정보](user-information/README.md): Linux 사용자 ID, 그룹, SSH agent forwarding 및 Active Directory 통합.
- [흥미로운 파일과 권한](interesting-files-permissions/README.md): 쓰기 가능한 경로, capabilities, SUID 동작, NFS, 와일드카드 확장 및 SELinux.
- [네트워크 정보](network-information/README.md): 로컬 서비스, 소켓 및 네트워크 관련 exploit 예제.
- [소프트웨어 정보](software-information/README.md): 인증 모듈 및 애플리케이션별 attack surface.
- [프로세스, crontab, systemd 및 D-Bus](processes-crontab-systemd-dbus/README.md): 예약 실행 및 프로세스 간 통신.
- [컨테이너 및 namespace](containers-namespaces/README.md): 런타임, 격리 경계 및 컨테이너 강화.
- [Post-exploitation](post-exploitation/README.md): 자격 증명 탐색, persistence 및 호스트 수준의 후속 기법.
{{#include ../banners/hacktricks-training.md}}
