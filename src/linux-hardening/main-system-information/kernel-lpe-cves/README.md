# Kernel, LPE na CVE

{{#include ../../../banners/hacktricks-training.md}}

Tafiti hizi za visa zinaangazia mbinu tofauti za msingi za local privilege escalation. Kabla ya kutumia mbinu, angalia bidhaa au kernel iliyoathiriwa, usanidi na masharti ya awali katika makala husika. Kwa enumeration pana ya host, tumia [orodha hakiki ya Linux privilege escalation](../linux-privilege-escalation-checklist.md).

Kwa Dirty Pipe (CVE-2022-0847), [utafiti wa awali](https://dirtypipe.cm4all.com/) unaonyesha marekebisho ya upstream stable katika matoleo 5.10.102, 5.15.25 na 5.16.11. Toleo la kernel lililo katika masafa ya zamani yaliyoathiriwa ni kidokezo tu cha kuchunguza: kernels za distribution zinaweza kuwa na marekebisho yaliyowekwa nyuma chini ya majina tofauti ya matoleo, na faili lengwa husika lazima iweze kusomeka ili kutumia mbinu ya kuandika kwenye page-cache. Kubatilisha executable ya SUID inayosomeka ni njia mojawapo ya kupata privilege ikiwa mabadiliko yake ya set-ID bado yanafanya kazi; kurekebisha `/etc/passwd` na kisha kuingia pia kunaweza kutegemea PAM stack ya mfumo husika. Kabla ya kutathmini uwezekano wa kutumia mbinu hii, kagua package ya kernel ya vendor iliyosakinishwa, kernel inayoendeshwa baada ya kuwasha upya, ruhusa za faili lengwa, mount `nosuid` na `no_new_privs`. Usifanye jaribio la kuandika wakati wa passive enumeration. Tazama [hali mahususi ya toleo la Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Ugunduzi wa service ya VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): utekelezaji wenye privilege kupitia ugunduzi wa process-path usioaminika.
- [Kubatilisha page-cache kwa AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): njia ya kubatilisha page-cache ya kernel.
- [TOCTOU ya POSIX CPU timers, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): race katika ushughulikiaji wa timer.
- [Race ya kutoka kwa Linux ptrace na wizi wa file descriptor kwa `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): ufikiaji wa descriptor wakati wa race ya mchakato kutoka.

## Tafiti zinazohusiana za Binary Exploitation

Sehemu ya Binary Exploitation inachunguza kwa undani zaidi primitives za exploit, mpangilio wa kumbukumbu na mbinu za kukwepa mitigation kwa targets hizi za Linux kernel:

- [Use-after-free ya AF_UNIX out-of-band SKB](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): hitilafu ya socket iliyotumika kutengeneza primitives za kusoma na kuandika kernel.
- [Use-after-free ya Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): primitive ya kuandika pointer iliyopanuliwa kupitia pipe buffers na workqueues.
- [Uandishi wa nje ya mipaka katika streams za ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): unyonyaji wa kernel heap na mbinu za kukwepa mitigation.
- [TOCTOU ya POSIX CPU timers, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): maelezo ya Binary Exploitation kuhusu race ya timer yaliyofupishwa pia hapo juu.
- [Kukwepa KASLR ya static linear-map kwenye Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): ugunduzi wa anwani kwa ajili ya unyonyaji wa kernel ya arm64.
- [Kukwepa privilege ya Adreno A7xx GPU/SMMU](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): njia ya Android GPU ya kufikia kumbukumbu ya kernel.
- [Use-after-free ya job-timeout ya Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): hitilafu ya Android accelerator iliyotumika kuandika kwenye kernel.
{{#include ../../../banners/hacktricks-training.md}}
