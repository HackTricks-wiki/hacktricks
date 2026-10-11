# 사용자 정보

{{#include ../../banners/hacktricks-training.md}}

사용자 ID, 그룹 멤버십, 위임된 자격 증명은 프로세스가 접근할 수 있는 리소스를 결정합니다. 아래 접근 경로를 조사하기 전에 유효 사용자 ID와 보조 그룹을 확인하세요.

- [사용자, 세션 및 자격 증명 흔적](user-and-session-triage.md)은 계정 열거, 활성 로그인, SSH 및 셸 흔적, 자격 증명 저장소를 다룹니다.
- [실제, 유효 및 저장된 사용자 ID](euid-ruid-suid.md)는 SUID 프로그램 및 프로세스 실행 과정에서의 ID 변경을 설명합니다.
- [Linux 권한 상승에 유용한 그룹](interesting-groups-linux-pe/README.md)은 LXD/LXC를 포함해 그룹이 부여하는 접근 권한을 다룹니다.
- [SSH forwarding agent 악용](ssh-forward-agent-exploitation.md)은 전달된 SSH 자격 증명으로 인한 위험을 살펴봅니다.
- [Linux Active Directory](linux-active-directory.md)는 AD 환경에 가입된 호스트를 다룹니다.
{{#include ../../banners/hacktricks-training.md}}
