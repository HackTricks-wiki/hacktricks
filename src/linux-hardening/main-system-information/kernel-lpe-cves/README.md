# Kernel, LPE, na Maudhui ya CVE

{{#include ../../../banners/hacktricks-training.md}}

Uchunguzi kifani huu unahusu mbinu tofauti za local privilege escalation. Kabla ya kutumia mbinu, angalia bidhaa au kernel iliyoathirika, usanidi na masharti ya awali katika kila makala. Kwa uchunguzi mpana zaidi wa host, tumia [orodha ya ukaguzi wa Linux privilege escalation](../linux-privilege-escalation-checklist.md).

Kwa Dirty Pipe (CVE-2022-0847), [utafiti wa awali](https://dirtypipe.cm4all.com/) unabainisha marekebisho ya upstream stable katika matoleo 5.10.102, 5.15.25, na 5.16.11. Toleo la kernel lililo katika safu ya zamani iliyoathirika ni kidokezo cha kuchunguza tu: kernel za usambazaji zinaweza kuwa na marekebisho yaliyobackportiwa chini ya majina tofauti ya matoleo, na faili husika lengwa lazima iweze kusomwa ili primitive ya kuandika kwenye page cache ifanye kazi. Kuandika juu ya executable ya SUID inayoweza kusomwa ni njia moja inayowezekana ya kupata privilege, ikiwa mabadiliko yake ya set-ID bado yanafanya kazi; kurekebisha `/etc/passwd` na kisha ku-authenticate kunaweza pia kutegemea local PAM stack. Kabla ya kutathmini uwezekano wa kufikiwa, angalia kifurushi cha kernel cha vendor kilichosakinishwa, kernel inayoendeshwa baada ya kuwasha upya, ruhusa za lengo, mount ya `nosuid`, na `no_new_privs`. Usifanye jaribio la kuandika wakati wa passive enumeration. Tazama [hali mahususi ya toleo la Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Ugunduzi wa service ya VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): utekelezaji wenye privilege kupitia ugunduzi wa process-path isiyoaminika.
- [Kuandika juu ya page cache kupitia AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): njia ya kuandika juu ya page cache ya kernel.
- [TOCTOU ya POSIX CPU timers, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): race katika ushughulikiaji wa timer.
- [Race ya kutoka kwa Linux ptrace na wizi wa file descriptor kupitia `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): ufikiaji wa descriptor wakati wa race ya kutoka kwa process.

## Uchunguzi kifani unaohusiana wa binary exploitation

Sehemu ya Binary Exploitation inachambua kwa kina zaidi exploit primitives, mpangilio wa memory, na mbinu za kukwepa ulinzi kwa malengo haya ya Linux kernel:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): hitilafu ya socket iliyotumika kutengeneza primitives za kusoma na kuandika kwenye kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): primitive ya kuandika pointer iliyopanuliwa kupitia pipe buffers na workqueues.
- [Uandishi wa nje ya mipaka kwenye streams za ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): unyonyaji wa kernel heap na mbinu za kukwepa ulinzi.
- [TOCTOU ya POSIX CPU timers, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): uchambuzi wa binary exploitation wa race ya timer ambao pia umefupishwa hapo juu.
- [Kukwepa KASLR ya static linear-map kwenye Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): ugunduzi wa anwani kwa ajili ya binary exploitation ya kernel ya arm64.
- [Kukwepa privilege ya Adreno A7xx GPU/SMMU](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): njia ya Android GPU ya kufikia memory ya kernel.
- [Pixel Bigwave use-after-free ya job-timeout](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): hitilafu ya Android accelerator iliyotumika kuandika kwenye kernel.
{{#include ../../../banners/hacktricks-training.md}}
