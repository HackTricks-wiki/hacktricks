# Nyenzo za Kernel, LPE na CVE

{{#include ../../../banners/hacktricks-training.md}}

Uchunguzi huu wa kesi unahusu mbinu tofauti za local privilege escalation. Kabla ya kutumia mbinu yoyote, angalia bidhaa au kernel iliyoathirika, usanidi na masharti ya awali katika kila makala. Kwa uchunguzi mpana zaidi wa host, tumia [orodha hakiki ya Linux privilege escalation](../linux-privilege-escalation-checklist.md).

Kwa Dirty Pipe (CVE-2022-0847), [utafiti wa awali](https://dirtypipe.cm4all.com/) unabainisha marekebisho ya upstream stable katika matoleo 5.10.102, 5.15.25 na 5.16.11. Toleo la kernel lililo katika masafa ya zamani yaliyoathirika ni kidokezo tu cha uchunguzi: kernels za usambazaji zinaweza kuwa na marekebisho yaliyorejeshwa (backport) chini ya majina tofauti ya toleo, na faili lengwa husika lazima isomeke ili kutumia mbinu ya kuandika kwenye page cache. Kubadilisha executable ya SUID inayosomeka ni njia mojawapo ya kupata mamlaka ya juu, iwapo mabadiliko yake ya set-ID bado yanafanya kazi; kurekebisha `/etc/passwd` na kisha kuthibitisha utambulisho kunaweza pia kutegemea usanidi wa PAM wa mfumo. Kabla ya kutathmini uwezekano wa kutumia njia hii, angalia kifurushi cha kernel cha vendor kilichosakinishwa, kernel inayoendeshwa baada ya kuwasha upya, ruhusa za faili lengwa, mount `nosuid` na `no_new_privs`. Usifanye jaribio la kuandika wakati wa uchunguzi usiobadilisha mfumo. Tazama [hali mahususi kwa toleo la Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Ugunduzi wa huduma ya VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): utekelezaji wenye mamlaka ya juu kupitia ugunduzi wa njia za mchakato zisizoaminika.
- [Uandikaji upya wa AF_ALG splice page-cache, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): njia ya kuandika upya page cache ya kernel.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): race katika ushughulikiaji wa timer.
- [Race ya Linux ptrace wakati wa kutoka kwa mchakato na wizi wa file descriptor kupitia `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): ufikiaji wa descriptor wakati wa race ya kutoka kwa mchakato.

## Uchunguzi wa kesi zinazohusiana na binary exploitation

Sehemu ya Binary Exploitation inaeleza kwa kina zaidi exploit primitives, mpangilio wa memory na mbinu za kukwepa ulinzi kwa malengo haya ya Linux kernel:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): hitilafu ya socket iliyotengenezwa kuwa read na write primitives za kernel.
- [AF_ALG concurrent-writer scatterlist underflow](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): race ya skcipher writer iliyotengenezwa kuwa write ya kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): pointer-write primitive iliyopanuliwa kupitia pipe buffers na workqueues.
- [Uandikaji nje ya mipaka kwenye ksmbd streams, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): unyonyaji wa kernel heap na mbinu za kukwepa ulinzi.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): maelezo ya binary exploitation kuhusu race ya timer, iliyofupishwa pia hapo juu.
- [Kukwepa KASLR kupitia static linear-map ya Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): ugunduzi wa anwani kwa ajili ya kernel exploitation ya arm64.
- [Kukwepa ulinzi wa Adreno A7xx GPU/SMMU](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): njia ya Android GPU ya kufikia memory ya kernel.
- [Pixel Bigwave use-after-free ya job-timeout](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): hitilafu ya Android accelerator iliyotumika kuandika kwenye kernel.
{{#include ../../../banners/hacktricks-training.md}}
