# Kernel, LPE और CVE सामग्री

{{#include ../../../banners/hacktricks-training.md}}

इन case studies में local privilege escalation के अलग-अलग primitives शामिल हैं। किसी technique को लागू करने से पहले हर article में प्रभावित product या kernel, configuration और prerequisites जाँचें। Host की व्यापक enumeration के लिए [Linux privilege escalation checklist](../linux-privilege-escalation-checklist.md) देखें।

Dirty Pipe (CVE-2022-0847) के लिए, [मूल शोध](https://dirtypipe.cm4all.com/) में upstream stable fixes के versions 5.10.102, 5.15.25 और 5.16.11 बताए गए हैं। पुराने affected range में kernel version मिलना केवल आगे जाँच करने का संकेत है: distribution kernels अलग release names के तहत fixes को backport कर सकते हैं, और page-cache write primitive के लिए संबंधित target file का readable होना ज़रूरी है। किसी readable SUID executable को overwrite करना privilege पाने का एक संभावित रास्ता है, बशर्ते उसका set-ID transition प्रभावी रहे; `/etc/passwd` में बदलाव करके फिर authenticate करना भी local PAM stack पर निर्भर हो सकता है। Reachability का आकलन करने से पहले installed vendor kernel package, reboot के बाद चल रहा kernel, target permissions, `nosuid` mount और `no_new_privs` जाँचें। Passive enumeration के दौरान write probe न चलाएँ। [Ubuntu की release-specific स्थिति](https://ubuntu.com/security/CVE-2022-0847) देखें।

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): untrusted process-path discovery के ज़रिए privileged execution।
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): kernel page-cache overwrite का रास्ता।
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): timer handling में race।
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): process exit race के दौरान descriptor access।

## Binary Exploitation की संबंधित case studies

Binary Exploitation section इन Linux kernel targets के exploit primitives, memory layout और mitigation bypasses की अधिक गहराई से पड़ताल करता है:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): socket bug को kernel read और write primitives में विकसित किया गया।
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): pointer-write primitive को pipe buffers और workqueues के ज़रिए आगे बढ़ाया गया।
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): kernel heap exploitation और mitigation bypasses।
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): timer race का binary exploitation विश्लेषण, जिसका सार ऊपर भी दिया गया है।
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): arm64 kernel exploitation के लिए address discovery।
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): kernel memory access तक पहुँचने का Android GPU रास्ता।
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): kernel writes के लिए इस्तेमाल किया गया Android accelerator bug।
{{#include ../../../banners/hacktricks-training.md}}
