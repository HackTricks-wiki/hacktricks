# 주요 시스템 정보

{{#include ../../banners/hacktricks-training.md}}

로컬 권한 상승 기법을 선택하기 전에 호스트의 커널, 파일 시스템, 권한이 높은 helper, 그리고 사용 가능한 탈출 경로를 점검하세요. [권한 상승 체크리스트](linux-privilege-escalation-checklist.md)에는 간결한 작업 순서가 나와 있습니다.

- [커널 취약점 평가 및 런타임 노출](kernel-vulnerability-assessment.md)에서는 빌드 적용 가능성, 도달 가능성, 활성화된 완화책을 점검합니다.
- [커널 모듈 및 modprobe 악용](kernel-modules-and-modprobe.md)에서는 모듈 로드와 helper 경로 노출을 다룹니다.
- [Sudo 명령 악용](sudo-command-abuse.md)에서는 위임된 명령이 권한 경계를 넘을 수 있는 방법을 살펴봅니다.
- [심볼릭 링크, 하드 링크 및 파일 디스크립터](filesystem-links-and-file-descriptors.md)에서는 경로 리디렉션, 상속된 파일, 삭제됐지만 열린 파일을 다룹니다.
- [파일 시스템, inode 및 복구](filesystem-inodes-and-recovery.md)에서는 조사에 유용한 파일 시스템 동작을 설명합니다.
- [체크리스트: Linux 권한 상승](linux-privilege-escalation-checklist.md)에는 호스트 점검 항목과 더 자세한 자료 링크가 나와 있습니다.
- [jail에서 탈출하기](escaping-from-limited-bash.md)에서는 제한된 셸과 제약된 환경을 다룹니다.
- [커널/LPE/CVE 자료](kernel-lpe-cves/README.md)에는 로컬 권한 상승 및 취약점 분석 자료가 모여 있습니다.
{{#include ../../banners/hacktricks-training.md}}
