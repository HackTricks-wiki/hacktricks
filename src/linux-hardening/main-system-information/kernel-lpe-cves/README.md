# Kernel, LPE 및 CVE 자료

{{#include ../../../banners/hacktricks-training.md}}

이 사례 연구에서는 서로 다른 local privilege escalation 원시 기법을 다룹니다. 기법을 적용하기 전에 각 문서에서 영향을 받는 제품 또는 커널, 구성 및 전제 조건을 확인하세요. 더 폭넓은 호스트 열거에는 [Linux privilege escalation checklist](../linux-privilege-escalation-checklist.md)를 사용하세요.

Dirty Pipe (CVE-2022-0847)의 경우, [원본 연구](https://dirtypipe.cm4all.com/)에 upstream stable 수정 버전이 5.10.102, 5.15.25, 5.16.11로 나와 있습니다. 이전의 취약 버전 범위에 속하는 커널 버전은 검토의 단서일 뿐입니다. 배포판 커널은 서로 다른 릴리스 이름으로 수정 사항을 백포트할 수 있으며, page-cache 쓰기 원시 기법을 사용하려면 대상 파일을 읽을 수 있어야 합니다. set-ID 전환이 여전히 유효한 경우, 읽기 가능한 SUID 실행 파일을 덮어쓰는 것이 가능한 권한 상승 경로 중 하나입니다. `/etc/passwd`를 수정한 다음 인증하는 방법도 로컬 PAM 스택에 따라 달라질 수 있습니다. 도달 가능성을 평가하기 전에 설치된 공급업체 커널 패키지, 재부팅 후 실행 중인 커널, 대상 권한, 마운트의 `nosuid`, `no_new_privs`를 확인하세요. 수동 열거 중에는 쓰기 프로브를 실행하지 마세요. [Ubuntu의 릴리스별 상태](https://ubuntu.com/security/CVE-2022-0847)를 참조하세요.

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): 신뢰할 수 없는 프로세스 경로 탐색을 통한 권한 있는 실행입니다.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): 커널 page-cache 덮어쓰기 경로입니다.
- [POSIX CPU timers TOCTOU race and exploitation, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit): task 종료 중 타이머 만료/삭제와 IRQ 경로의 전제 조건 및 exploit 연구를 다룹니다.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): 프로세스 종료 race 중 descriptor에 접근하는 기법입니다.

## 관련 Binary Exploitation 사례 연구

Binary Exploitation 섹션에서는 이러한 Linux 커널 대상의 exploit 원시 기법, 메모리 레이아웃 및 완화 기법 우회에 대해 더 자세히 다룹니다.

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): 소켓 버그를 커널 읽기 및 쓰기 원시 기법으로 발전시킵니다.
- [AF_ALG concurrent-writer scatterlist underflow](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): skcipher writer race를 커널 쓰기로 발전시킵니다.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): 포인터 쓰기 원시 기법을 pipe buffer와 workqueue를 통해 확장합니다.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): 커널 heap exploitation 및 완화 기법 우회를 다룹니다.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): arm64 커널 exploitation을 위한 주소 탐색을 다룹니다.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): Android GPU 경로를 통한 커널 메모리 접근을 다룹니다.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): Android 가속기 버그를 커널 쓰기에 이용합니다.
{{#include ../../../banners/hacktricks-training.md}}
