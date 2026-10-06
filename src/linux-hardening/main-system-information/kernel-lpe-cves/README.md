# Kernel, LPE, and CVE Material

{{#include ../../../banners/hacktricks-training.md}}

These case studies cover distinct local privilege escalation primitives. Check the affected product or kernel, configuration, and prerequisites in each article before applying a technique. For broader host enumeration, use the [Linux privilege escalation checklist](../linux-privilege-escalation-checklist.md).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): privileged execution through untrusted process-path discovery.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): a kernel page-cache overwrite path.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): a race in timer handling.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): descriptor access across a process exit race.

## Related binary exploitation case studies

The Binary Exploitation section goes deeper into exploit primitives, memory layout, and mitigation bypasses for these Linux kernel targets:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): a socket bug developed into kernel read and write primitives.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): a pointer-write primitive extended through pipe buffers and workqueues.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): kernel heap exploitation and mitigation bypasses.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): the binary exploitation treatment of the timer race also summarized above.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): address discovery for arm64 kernel exploitation.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): an Android GPU path to kernel memory access.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): an Android accelerator bug used for kernel writes.
{{#include ../../../banners/hacktricks-training.md}}
