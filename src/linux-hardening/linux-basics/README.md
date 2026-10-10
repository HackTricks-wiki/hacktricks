# Linux 기본 사항

{{#include ../../banners/hacktricks-training.md}}

Linux 호스트 평가의 시작점입니다. 여기서는 권한 상승 전반의 워크플로, 실용적인 명령어, 환경 변수, 호스트에서 실행할 수 있는 항목에 영향을 주는 일반적인 제한 사항을 다룹니다.

- [Linux 권한 상승](linux-privilege-escalation/README.md)에서는 열거와 잠재적인 로컬 권한 상승 경로를 살펴봅니다. 더 짧은 작업 목록은 [권한 상승 체크리스트](../main-system-information/linux-privilege-escalation-checklist.md)를 참조하세요.
- [셸 시작, 별칭, 히스토리](shell-startup-aliases-and-history.md)에서는 명령어 확인, 시작 파일 실행, 히스토리에서 얻을 수 있는 단서를 설명합니다.
- [유용한 Linux 명령어](useful-linux-commands.md)에는 파일, 프로세스, 서비스, 환경을 검사하는 명령어가 정리되어 있습니다.
- [Linux 환경 변수](linux-environment-variables.md)에서는 환경 값이 실행에 미치는 영향과 민감한 값이 나타날 수 있는 위치를 설명합니다.
- [Linux 제한 우회](bypass-linux-restrictions/README.md)에서는 파일 시스템 보호, `noexec`, distroless 시스템을 포함한 제한된 셸과 실행 환경을 다룹니다.

## 네이티브 바이너리 익스플로잇

평가 중 취약한 Linux 실행 파일을 발견했다면 Binary Exploitation의 관련 자료를 참고하세요.

- [ELF 형식 및 로더 동작](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md)과 [바이너리 보호 기법 및 우회](../../binary-exploitation/common-binary-protections-and-bypasses/README.md)에서는 실행 파일의 레이아웃과 완화 기법을 설명합니다.
- [스택 익스플로잇](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md)과 [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md)에서는 제어 흐름 공격을 다룹니다.
- [Libc 힙 익스플로잇](../../binary-exploitation/libc-heap/README.md)과 [포맷 스트링](../../binary-exploitation/format-strings/README.md)에서는 그 밖의 일반적인 메모리 손상 경로를 다룹니다.

커널 관련 사례 연구는 [Kernel/LPE/CVE 자료](../main-system-information/kernel-lpe-cves/README.md)에서 확인할 수 있습니다.
{{#include ../../banners/hacktricks-training.md}}
