# Nyenzo za Kernel, LPE, na CVE

{{#include ../../../banners/hacktricks-training.md}}

Mifano hii inashughulikia primitive tofauti za local privilege escalation. Kabla ya kutumia technique, kagua bidhaa au kernel iliyoathiriwa, usanidi, na masharti ya awali katika kila makala. Kwa uchunguzi mpana zaidi wa host, tumia [orodha ya ukaguzi wa Linux privilege escalation](../linux-privilege-escalation-checklist.md).

Kuhusu Dirty Pipe (CVE-2022-0847), [utafiti wa awali](https://dirtypipe.cm4all.com/) unaonyesha kuwa marekebisho ya upstream stable yalitolewa katika matoleo 5.10.102, 5.15.25, na 5.16.11. Toleo la kernel lililo katika kipindi cha zamani kilichoathiriwa ni kidokezo tu cha kufanya ukaguzi: kernel za usambazaji zinaweza kuwa na marekebisho yaliyowekwa nyuma (backport) chini ya majina tofauti ya matoleo, na faili lengwa husika lazima iweze kusomwa ili kutumia primitive ya kuandika kwenye page cache. Kubatilisha executable ya SUID inayoweza kusomwa ni njia moja inayowezekana ya kupata privilege ikiwa mabadiliko yake ya set-ID bado yanafanya kazi; kurekebisha `/etc/passwd` kisha kufanya authentication pia kunaweza kutegemea PAM stack ya mfumo husika. Kabla ya kutathmini uwezekano wa kutumia udhaifu huu, kagua package ya kernel ya vendor iliyosakinishwa, kernel inayotumika baada ya kuwasha upya, ruhusa za faili lengwa, `nosuid` ya mount, na `no_new_privs`. Usifanye jaribio la kuandika wakati wa enumeration tulivu. Tazama [hali mahususi ya toleo la Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Ugunduzi wa huduma ya VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): utekelezaji wenye privilege kupitia ugunduzi wa process path isiyoaminika.
- [Kubatilisha page cache kupitia AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): njia ya kubatilisha page cache ya kernel.
- [TOCTOU ya POSIX CPU timers, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): race katika ushughulikiaji wa timer.
- [Race ya Linux ptrace wakati wa kutoka kwa process na wizi wa file descriptor kupitia `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): ufikiaji wa descriptor wakati wa race ya kutoka kwa process.

## Mifano Husika ya Binary Exploitation

Sehemu ya Binary Exploitation inaeleza kwa undani zaidi exploit primitives, mpangilio wa kumbukumbu, na mbinu za kukwepa mitigations kwa targets hizi za Linux kernel:

- [Use-after-free ya SKB ya AF_UNIX out-of-band](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): hitilafu ya socket iliyobadilishwa kuwa primitive za kusoma na kuandika kwenye kernel.
- [Use-after-free ya Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): primitive ya kuandika pointer iliyopanuliwa kupitia pipe buffers na workqueues.
- [Uandishi nje ya mipaka wa ksmbd streams, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): kernel heap exploitation na mbinu za kukwepa mitigations.
- [TOCTOU ya POSIX CPU timers, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): maelezo ya binary exploitation kuhusu race ya timer iliyofupishwa pia hapo juu.
- [Kukwepa KASLR ya arm64 static linear-map](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): ugunduzi wa anwani kwa ajili ya kernel exploitation ya arm64.
- [Kukwepa privilege ya Adreno A7xx GPU/SMMU](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): njia ya Android GPU ya kufikia kumbukumbu ya kernel.
- [Use-after-free ya Pixel Bigwave job-timeout](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): hitilafu ya Android accelerator iliyotumika kuandika kwenye kernel.
{{#include ../../../banners/hacktricks-training.md}}
