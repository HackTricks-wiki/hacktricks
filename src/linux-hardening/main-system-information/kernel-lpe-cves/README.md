# 커널, LPE 및 CVE 자료

{{#include ../../../banners/hacktricks-training.md}}

이 사례 연구에서는 서로 다른 로컬 권한 상승 프리미티브를 다룹니다. 기법을 적용하기 전에 각 문서에서 영향을 받는 제품 또는 커널, 구성 및 전제 조건을 확인하세요. 더 폭넓은 호스트 열거에는 [Linux 권한 상승 체크리스트](../linux-privilege-escalation-checklist.md)를 사용하세요.

Dirty Pipe (CVE-2022-0847)의 경우, [원본 연구](https://dirtypipe.cm4all.com/)에서 upstream stable 수정 버전이 5.10.102, 5.15.25, 5.16.11임을 확인할 수 있습니다. 영향을 받는 이전 버전 범위에 속하는 커널 버전은 추가 검토가 필요한 단서일 뿐입니다. 배포판 커널은 서로 다른 릴리스 이름으로 수정 사항을 백포트할 수 있으며, page-cache 쓰기 프리미티브를 사용하려면 대상 파일을 읽을 수 있어야 합니다. 읽을 수 있는 SUID 실행 파일을 덮어쓰는 것은 set-ID 전환이 여전히 유효한 경우 가능한 권한 상승 경로 중 하나입니다. `/etc/passwd`를 수정한 뒤 인증하는 방식도 로컬 PAM 스택에 따라 달라질 수 있습니다. 도달 가능성을 평가하기 전에 설치된 벤더 커널 패키지, 재부팅 후 실행 중인 커널, 대상 권한, 마운트 옵션 `nosuid`, `no_new_privs`를 확인하세요. 수동 열거 중에는 쓰기 프로브를 실행하지 마세요. [Ubuntu의 릴리스별 상태](https://ubuntu.com/security/CVE-2022-0847)를 참조하세요.

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): 신뢰할 수 없는 프로세스 경로 검색을 통한 권한 있는 실행.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): 커널 page-cache 덮어쓰기 경로.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): 타이머 처리 과정의 경쟁 조건.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): 프로세스 종료 경쟁 조건 중 발생하는 파일 디스크립터 접근.

## 관련 바이너리 익스플로잇 사례 연구

Binary Exploitation 섹션에서는 이러한 Linux 커널 대상을 위한 익스플로잇 프리미티브, 메모리 레이아웃 및 완화 기법 우회 방법을 자세히 다룹니다.

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): 소켓 버그를 커널 읽기 및 쓰기 프리미티브로 발전시킨 사례.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): 파이프 버퍼와 workqueue를 통해 확장한 포인터 쓰기 프리미티브.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): 커널 힙 익스플로잇 및 완화 기법 우회.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): 위에서 요약한 타이머 경쟁 조건을 바이너리 익스플로잇 관점에서 다룹니다.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): arm64 커널 익스플로잇을 위한 주소 탐색.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): 커널 메모리 접근으로 이어지는 Android GPU 경로.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): 커널 쓰기에 이용되는 Android 가속기 버그.
{{#include ../../../banners/hacktricks-training.md}}
