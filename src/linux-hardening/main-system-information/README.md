# 주요 시스템 정보

{{#include ../../banners/hacktricks-training.md}}

로컬 권한 상승 기법을 선택하기 전에 호스트의 커널, 파일 시스템, 권한이 있는 헬퍼, 사용 가능한 탈출 경로를 확인하세요. [권한 상승 체크리스트](linux-privilege-escalation-checklist.md)에는 간결한 작업 순서가 정리되어 있습니다.

- [커널 취약점 평가 및 런타임 노출](kernel-vulnerability-assessment.md)에서는 빌드 적용 가능성, 도달 가능성, 활성화된 완화 조치를 확인합니다.
- [커널 모듈 및 modprobe 악용](kernel-modules-and-modprobe.md)에서는 모듈 로딩과 헬퍼 경로 노출을 다룹니다.
- [sudo 명령 악용](sudo-command-abuse.md)에서는 위임된 명령이 권한 경계를 넘을 수 있는 방법을 살펴봅니다.
- [심볼릭 링크, 하드 링크, 파일 디스크립터](filesystem-links-and-file-descriptors.md)에서는 경로 리디렉션과 상속되거나 삭제된 채 열린 파일을 다룹니다.
- [파일 시스템, inode 및 복구](filesystem-inodes-and-recovery.md)에서는 조사에 유용한 파일 시스템 동작을 설명합니다.
- [체크리스트: Linux 권한 상승](linux-privilege-escalation-checklist.md)에는 호스트 점검 항목과 더 자세한 자료 링크가 나와 있습니다.
- [jail 탈출](escaping-from-limited-bash.md)에서는 제한된 셸과 제약된 환경을 다룹니다.
- [커널/LPE/CVE 자료](kernel-lpe-cves/README.md)에는 로컬 권한 상승 및 취약점에 관한 집중 분석 자료가 정리되어 있습니다.
{{#include ../../banners/hacktricks-training.md}}
