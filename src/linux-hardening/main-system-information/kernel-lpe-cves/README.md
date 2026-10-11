# Nyenzo za Kernel, LPE, na CVE

{{#include ../../../banners/hacktricks-training.md}}

Tafiti hizi za matukio zinashughulikia misingi tofauti ya local privilege escalation. Kabla ya kutumia mbinu, hakiki bidhaa au kernel iliyoathiriwa, usanidi, na mahitaji ya awali katika kila makala. Kwa uchunguzi mpana zaidi wa hosti, tumia [orodha ya ukaguzi wa Linux privilege escalation](../linux-privilege-escalation-checklist.md).

Kwa Dirty Pipe (CVE-2022-0847), [utafiti wa awali](https://dirtypipe.cm4all.com/) unaonyesha kuwa marekebisho ya upstream stable yalitolewa katika matoleo 5.10.102, 5.15.25, na 5.16.11. Toleo la kernel katika safu ya zamani iliyoathiriwa ni kidokezo tu cha kuchunguza: kernel za usambazaji zinaweza kuwa na marekebisho yaliyorudishwa (backport) chini ya majina tofauti ya matoleo, na faili lengwa husika lazima iweze kusomwa ili kutumia primitive ya kuandika kwenye page-cache. Kubadilisha executable ya SUID inayoweza kusomwa ni njia moja inayoweza kutoa privilege, ikiwa mabadiliko yake ya set-ID bado yanafanya kazi; kubadilisha `/etc/passwd` na kisha kuingia kunaweza pia kutegemea usanidi wa ndani wa PAM. Kabla ya kutathmini uwezekano wa kutumia udhaifu huo, hakiki kifurushi cha kernel cha vendor kilichosakinishwa, kernel inayoendeshwa baada ya kuwasha upya, ruhusa za faili lengwa, mount `nosuid`, na `no_new_privs`. Usifanye jaribio la kuandika wakati wa uchunguzi usiobadilisha mfumo. Tazama [hali ya Ubuntu kwa kila toleo](https://ubuntu.com/security/CVE-2022-0847).

- [Ugunduzi wa huduma ya VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): utekelezaji wenye privilege kupitia ugunduzi wa njia ya mchakato usioaminika.
- [Kubatilisha page-cache kupitia AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): njia ya kubatilisha page-cache ya kernel.
- [TOCTOU ya vipima muda vya CPU vya POSIX, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): race katika ushughulikiaji wa timer.
- [Race ya kutoka kwa Linux ptrace na wizi wa file descriptor kupitia `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): ufikiaji wa descriptor wakati wa race ya mchakato kutoka.

## Tafiti zinazohusiana za Binary Exploitation

Sehemu ya Binary Exploitation inaeleza kwa kina zaidi exploit primitives, mpangilio wa kumbukumbu, na mbinu za kukwepa mitigations kwa malengo haya ya Linux kernel:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): hitilafu ya socket iliyotumiwa kutengeneza primitives za kusoma na kuandika kwenye kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): primitive ya kuandika pointer iliyopanuliwa kupitia pipe buffers na workqueues.
- [Uandishi nje ya mipaka wa ksmbd streams, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): unyonyaji wa kernel heap na mbinu za kukwepa mitigations.
- [TOCTOU ya vipima muda vya CPU vya POSIX, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): maelezo ya binary exploitation kuhusu race ya timer, ambayo pia imefupishwa hapo juu.
- [Kukwepa KASLR ya static linear-map kwenye Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): kugundua anwani kwa ajili ya unyonyaji wa kernel ya arm64.
- [Kukwepa privilege ya Adreno A7xx GPU/SMMU](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): njia ya Android GPU ya kufikia kumbukumbu ya kernel.
- [Use-after-free ya muda kuisha kwa kazi ya Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): hitilafu ya Android accelerator iliyotumiwa kuandika kwenye kernel.
{{#include ../../../banners/hacktricks-training.md}}
