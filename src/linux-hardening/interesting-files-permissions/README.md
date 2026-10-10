# 흥미로운 파일과 권한

{{#include ../../banners/hacktricks-training.md}}

파일 소유권, 쓰기 권한, 마운트 옵션, 실행 권한은 로컬 사용자가 실제로 접근할 수 있는 범위를 바꿀 수 있습니다. 먼저 대상 파일이나 실행 경로를 찾은 다음, 관련 페이지를 확인하세요.

- [SUID, SGID, ACL 및 민감한 파일](suid-sgid-and-acl-triage.md)은 실행 권한과 숨겨진 접근 권한을 조사하는 기본 절차를 제공합니다.
- [root 권한으로 임의 파일 쓰기](write-to-root.md)는 권한이 높은 경로에 파일을 써서 권한 상승으로 이어지는 방법을 설명합니다.
- [Linux capabilities](linux-capabilities.md)는 프로세스별 및 파일별 capabilities를 설명합니다.
- [SUID 공유 라이브러리 및 linker 악용](suid-shared-library-and-linker-abuse.md)은 권한이 높은 바이너리의 동적 로딩을 다룹니다.
- [`ld.so` 권한 상승 예시](ld.so.conf-example.md)는 linker 설정 사례를 살펴봅니다.
- [NFS `no_root_squash` 및 `no_all_squash` 잘못된 설정](nfs-no_root_squash-misconfiguration-pe.md)은 원격 파일 시스템의 사용자 ID 매핑을 다룹니다.
- [와일드카드 spare 기법](wildcards-spare-tricks.md)은 권한이 높은 명령에서 인자가 확장되는 방식을 다룹니다.
- [SELinux](selinux.md)는 정책 적용과 관련 조사 단계를 설명합니다.
{{#include ../../banners/hacktricks-training.md}}
