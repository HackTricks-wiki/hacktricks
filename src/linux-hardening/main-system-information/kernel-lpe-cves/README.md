# Nyenzo za Kernel, LPE, na CVE

{{#include ../../../banners/hacktricks-training.md}}

Tafiti hizi za kesi zinahusu primitives tofauti za local privilege escalation. Kagua bidhaa au kernel iliyoathiriwa, usanidi, na masharti ya awali katika kila makala kabla ya kutumia mbinu. Kwa uchunguzi mpana zaidi wa host, tumia [orodha hakiki ya Linux ya privilege escalation](../linux-privilege-escalation-checklist.md).

Kwa Dirty Pipe (CVE-2022-0847), [utafiti wa awali](https://dirtypipe.cm4all.com/) unaonyesha marekebisho ya upstream stable katika matoleo 5.10.102, 5.15.25, na 5.16.11. Toleo la kernel lililo katika safu ya zamani iliyoathiriwa ni dalili tu ya kuchunguza zaidi: kernel za usambazaji zinaweza kujumuisha marekebisho (backport) chini ya majina tofauti ya matoleo, na faili husika lengwa lazima iweze kusomwa ili kutumia primitive ya kuandika kwenye page-cache. Kubadilisha executable ya SUID inayoweza kusomwa ni njia moja inayowezekana ya kupata privilege ikiwa mpito wake wa set-ID bado unafanya kazi; kurekebisha `/etc/passwd` na kisha kuthibitisha utambulisho kunaweza pia kutegemea local PAM stack. Kabla ya kutathmini uwezekano wa kutumia udhaifu huu, kagua kifurushi cha kernel cha vendor kilichosakinishwa, kernel inayoendeshwa baada ya kuwasha upya, ruhusa za faili lengwa, mount `nosuid`, na `no_new_privs`. Usifanye jaribio la kuandika wakati wa uchunguzi wa kimya. Tazama [hali mahususi kwa toleo la Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Ugunduzi wa huduma ya VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): utekelezaji wenye privilege kupitia ugunduzi wa process-path usioaminika.
- [Uandishi upya wa AF_ALG splice page-cache, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): njia ya kernel ya kuandika upya page-cache.
- [Mashindano ya TOCTOU ya POSIX CPU timers na exploitation, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit): kuisha/kufutwa kwa timer wakati task inatoka, ikijumuisha masharti ya awali ya IRQ-path na utafiti wa exploit.
- [Mashindano ya ptrace exit ya Linux na wizi wa file descriptor kupitia `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): ufikiaji wa descriptor wakati wa mashindano ya mchakato kutoka.

## Tafiti za Kesi Zinazohusiana za Binary Exploitation

Sehemu ya Binary Exploitation inachunguza kwa undani zaidi exploit primitives, mpangilio wa memory, na mbinu za kukwepa mitigations kwa targets hizi za Linux kernel:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): hitilafu ya socket iliyotumika kutengeneza primitives za kusoma na kuandika kernel.
- [AF_ALG concurrent-writer scatterlist underflow](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): mashindano ya skcipher writer yaliyotumika kutengeneza uandishi kwenye kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): primitive ya kuandika pointer iliyopanuliwa kupitia pipe buffers na workqueues.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): exploitation ya kernel heap na mbinu za kukwepa mitigations.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): ugunduzi wa anwani kwa ajili ya kernel exploitation ya arm64.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): njia ya Android GPU ya kufikia memory ya kernel.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): hitilafu ya Android accelerator iliyotumika kuandika kwenye kernel.
{{#include ../../../banners/hacktricks-training.md}}
