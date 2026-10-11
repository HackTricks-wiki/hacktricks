# Kernel-, LPE- en CVE-materiaal

{{#include ../../../banners/hacktricks-training.md}}

Hierdie gevallestudies behandel verskillende primitiewe vir plaaslike voorregte-eskalasie. Gaan die betrokke produk of kernel, konfigurasie en voorvereistes in elke artikel na voordat jy ’n tegniek toepas. Gebruik die [Linux-kontrolelys vir voorregte-eskalasie](../linux-privilege-escalation-checklist.md) vir breër gasheerenumerasie.

Vir Dirty Pipe (CVE-2022-0847) identifiseer die [oorspronklike navorsing](https://dirtypipe.cm4all.com/) die stroomop stabiele regstellings in 5.10.102, 5.15.25 en 5.16.11. ’n Kernelweergawe in ’n ouer kwesbare reeks is slegs ’n leidraad vir verdere ondersoek: verspreidingskernels kan regstellings terugporteer onder ander vrystellingsname, en die betrokke teikenlêer moet leesbaar wees vir die page-cache-skryfprimitief. Oorskryf van ’n leesbare SUID-uitvoerbare lêer is een moontlike pad na voorregte wanneer die set-ID-oorgang steeds effektief is; die wysiging van `/etc/passwd` en daarna verifikasie kan ook van die plaaslike PAM-stapel afhang. Gaan die geïnstalleerde verskaffer-kernelpakket, die kernel wat ná herlaai loop, teikentoestemmings, die `nosuid`-monteeropsie en `no_new_privs` na voordat jy bereikbaarheid beoordeel. Moenie ’n skryfproef uitvoer tydens passiewe enumerasie nie. Sien [Ubuntu se status per vrystelling](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools-diensontdekking, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): bevoorregte uitvoering deur onbetroubare prosespad-ontdekking.
- [AF_ALG splice page-cache-oorskrywing, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ’n kernel page-cache-oorskrywingspad.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): ’n wedloop in timerhantering.
- [Linux ptrace-exit-wedloop en `pidfd_getfd`-lêerbeskrywerdiefstal](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): toegang tot beskrywers tydens ’n proses-exit-wedloop.

## Verwante gevallestudies oor binêre uitbuiting

Die afdeling Binary Exploitation gaan dieper in op uitbuitingsprimitiewe, geheue-uitleg en omseiling van versagtings vir hierdie Linux-kernteikens:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): ’n sokfout uitgebou tot kernel-lees- en skryfprimitiewe.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): ’n wyser-skryfprimitief uitgebrei deur pypbuffers en workqueues.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): kernelheap-uitbuiting en omseiling van versagtings.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): die uiteensetting van die timer-wedloop vanuit die perspektief van binêre uitbuiting, ook hier bo opgesom.
- [Arm64 static linear-map KASLR-bypassing](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): adresontdekking vir arm64-kerneluitbuiting.
- [Adreno A7xx GPU/SMMU-voorregtebypassing](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): ’n Android-GPU-pad na toegang tot kernelgeheue.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): ’n Android-versnellerfout wat vir ker nelskrywings gebruik word.
{{#include ../../../banners/hacktricks-training.md}}
