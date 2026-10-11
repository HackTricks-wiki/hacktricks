# Kernel-, LPE- en CVE-materiaal

{{#include ../../../banners/hacktricks-training.md}}

Hierdie gevallestudies dek verskillende primitives vir plaaslike privilege escalation. Gaan die betrokke produk of kernel, konfigurasie en voorvereistes in elke artikel na voordat jy ’n tegniek toepas. Vir breër host enumeration, gebruik die [Linux privilege escalation-kontrolelys](../linux-privilege-escalation-checklist.md).

Vir Dirty Pipe (CVE-2022-0847) identifiseer die [oorspronklike navorsing](https://dirtypipe.cm4all.com/) die upstream stable-regstellings by 5.10.102, 5.15.25 en 5.16.11. ’n Kernelweergawe in ’n ouer geaffekteerde reeks is slegs ’n leidraad vir verdere ondersoek: verspreidingskernels kan regstellings terugporteer onder ander weergawename, en die betrokke teikenlêer moet leesbaar wees vir die page-cache-skryfprimitive. Om ’n leesbare SUID-uitvoerbare lêer te oorskryf, is een moontlike privilege escalation-pad wanneer die set-ID-oorgang steeds effektief is; die wysiging van `/etc/passwd` en daaropvolgende verifikasie kan ook van die plaaslike PAM-stapel afhang. Gaan die geïnstalleerde verskaffer se kernelpakket, die kernel wat ná herlaai loop, teikentoestemmings, die mount-opsie `nosuid` en `no_new_privs` na voordat jy bereikbaarheid beoordeel. Moenie ’n skryfproef tydens passiewe enumeration uitvoer nie. Sien [Ubuntu se status per vrystelling](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): bevoorregte uitvoering deur onbetroubare process-path discovery.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ’n kernel page-cache-oorskryfpad.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): ’n wedren in timerhantering.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): toegang tot file descriptors tydens ’n proses-exit-wedren.

## Verwante gevallestudies oor binary exploitation

Die afdeling Binary Exploitation gaan dieper in op exploit-primitives, geheue-uitleg en omseiling van versagtings vir hierdie Linux-kernteikens:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): ’n socket-fout wat ontwikkel is tot kernel-lees- en -skryfprimitives.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): ’n pointer-skryfprimitive wat uitgebrei is deur pipe buffers en workqueues.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): kernel-heap-exploitation en omseiling van versagtings.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): die behandeling van die timer-wedren vanuit binary exploitation, ook hier bo opgesom.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): adresontdekking vir arm64-kernelexploitation.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): ’n Android-GPU-pad na toegang tot kernelgeheue.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): ’n Android-versnellerfout wat vir kernel-skryfbewerkings gebruik word.
{{#include ../../../banners/hacktricks-training.md}}
