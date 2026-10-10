# 컨테이너와 네임스페이스

{{#include ../../banners/hacktricks-training.md}}

컨테이너는 격리 및 권한 설정을 적용해 실행되는 Linux 프로세스입니다. 런타임, 마운트된 호스트 리소스, 부여된 capabilities, 네임스페이스 설정을 함께 평가하세요. [컨테이너 보안 개요](container-security/README.md)에서는 이러한 계층을 설명하고 각 제어 항목으로 연결합니다.

- [Containerd (`ctr`) 권한 상승](containerd-ctr-privilege-escalation.md)에서는 containerd 관리 인터페이스에 대한 접근을 다룹니다.
- [RunC 권한 상승](runc-privilege-escalation.md)에서는 런타임별 권한 상승 내용을 다룹니다.
- [컨테이너 보안](container-security/README.md)에서는 런타임, 노출된 API, 이미지 위험, 민감한 마운트, 권한 있는 컨테이너, 평가, 네임스페이스, seccomp, 강제 접근 제어와 같은 보호 기법을 설명합니다.
{{#include ../../banners/hacktricks-training.md}}
