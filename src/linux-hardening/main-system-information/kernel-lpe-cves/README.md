# Kernel, LPE 및 CVE 자료

{{#include ../../../banners/hacktricks-training.md}}

이 사례 연구에서는 서로 다른 local privilege escalation primitive를 다룹니다. 기법을 적용하기 전에 각 문서에서 영향을 받는 제품 또는 kernel, 구성 및 사전 요구 사항을 확인하세요. 더 폭넓은 호스트 열거에는 [Linux privilege escalation checklist](../linux-privilege-escalation-checklist.md)를 사용하세요.

Dirty Pipe (CVE-2022-0847)의 경우 [원본 연구](https://dirtypipe.cm4all.com/)에서 upstream stable 수정 버전이 5.10.102, 5.15.25, 5.16.11임을 확인할 수 있습니다. 이전의 취약 버전에 해당하는 kernel 버전은 검토 단서일 뿐입니다. 배포판 kernel은 다른 릴리스 이름으로 수정 사항을 backport할 수 있으며, page-cache write primitive를 사용하려면 대상 파일을 읽을 수 있어야 합니다. 읽을 수 있는 SUID 실행 파일을 덮어쓰는 것은 set-ID 전환이 여전히 유효한 경우 가능한 권한 상승 경로 중 하나입니다. `/etc/passwd`를 수정한 다음 인증하는 방법도 로컬 PAM 스택에 따라 달라질 수 있습니다. 악용 가능성을 평가하기 전에 설치된 벤더 kernel 패키지, 재부팅 후 실행 중인 kernel, 대상 권한, `nosuid` mount 옵션 및 `no_new_privs`를 확인하세요. 수동 열거 중에는 write probe를 실행하지 마세요. [Ubuntu의 릴리스별 상태](https://ubuntu.com/security/CVE-2022-0847)를 참조하세요.

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): 신뢰할 수 없는 process 경로 검색을 통한 권한 있는 실행.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): kernel page-cache 덮어쓰기 경로.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): timer 처리 과정의 race.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): process 종료 race 중 발생하는 descriptor 접근.

## 관련 binary exploitation 사례 연구

Binary Exploitation 섹션에서는 다음 Linux kernel 대상의 exploit primitive, memory layout 및 mitigation 우회 방법을 자세히 다룹니다.

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): socket 버그를 kernel read 및 write primitive로 발전시킨 사례.
- [AF_ALG concurrent-writer scatterlist underflow](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): skcipher writer race를 kernel write로 발전시킨 사례.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): pipe buffer와 workqueue를 통해 확장한 pointer-write primitive.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): kernel heap exploitation 및 mitigation 우회 방법.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): 위에서 요약한 timer race를 binary exploitation 관점에서 다룹니다.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): arm64 kernel exploitation을 위한 주소 탐색.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): kernel memory 접근으로 이어지는 Android GPU 경로.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): kernel write에 사용된 Android accelerator 버그.
{{#include ../../../banners/hacktricks-training.md}}
