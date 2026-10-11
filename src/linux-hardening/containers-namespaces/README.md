# Containers and Namespaces

{{#include ../../banners/hacktricks-training.md}}

컨테이너는 격리 및 권한 구성을 적용해 실행되는 Linux 프로세스입니다. 런타임, 마운트된 호스트 리소스, 부여된 capabilities, namespace 설정을 함께 평가하세요. [컨테이너 보안 개요](container-security/README.md)에서는 이러한 계층을 설명하고 각 제어 항목으로 연결합니다.

- [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md)은 containerd의 관리 인터페이스에 대한 접근을 중점적으로 다룹니다.
- [RunC privilege escalation](runc-privilege-escalation.md)은 런타임별 privilege escalation 관련 내용을 다룹니다.
- [컨테이너 보안](container-security/README.md)에서는 런타임, 노출된 API, 이미지 위험, 민감한 마운트, 권한이 부여된 컨테이너, 평가 및 namespace, seccomp, mandatory access control과 같은 보호 기법을 설명합니다.
{{#include ../../banners/hacktricks-training.md}}
