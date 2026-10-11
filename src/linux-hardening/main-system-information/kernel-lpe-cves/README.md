# Kernel-, LPE- en CVE-materiaal

{{#include ../../../banners/hacktricks-training.md}}

Hierdie gevallestudies dek afsonderlike primitiewe vir plaaslike voorregte-escalasie. Gaan die betrokke produk of kernel, konfigurasie en voorvereistes in elke artikel na voordat jy ’n tegniek toepas. Gebruik die [Linux-voorregte-escalasie-kontrolelys](../linux-privilege-escalation-checklist.md) vir breër host-enumerasie.

Vir Dirty Pipe (CVE-2022-0847) dui die [oorspronklike navorsing](https://dirtypipe.cm4all.com/) stroomop-stabiele regstellings aan by 5.10.102, 5.15.25 en 5.16.11. ’n Kernel-weergawe in ’n ouer geaffekteerde reeks is slegs ’n leidraad vir verdere ondersoek: verspreiding-kernels kan regstellings terugporteer onder ander vrystellingname, en die betrokke teikenlêer moet leesbaar wees vir die page-cache-skryfprimitief. Die oorskryf van ’n leesbare SUID-uitvoerbare lêer is een moontlike voorregtepad wanneer die set-ID-oorgang steeds effektief is; die wysiging van `/etc/passwd` en daaropvolgende aanmelding kan ook van die plaaslike PAM-stapel afhang. Gaan die geïnstalleerde verskaffer se kernel-pakket, die kernel wat ná herlaai loop, teikentoestemmings, die mount-opsie `nosuid` en `no_new_privs` na voordat jy bereikbaarheid beoordeel. Moenie ’n skryfproef tydens passiewe enumerasie uitvoer nie. Sien [Ubuntu se status per vrystelling](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools-diensontdekking, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): bevoorregte uitvoering deur prosespad-ontdekking wat nie vertrou word nie.
- [AF_ALG splice page-cache-oorskryf, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ’n kernel page-cache-oorskryfpad.
- [POSIX CPU-timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): ’n wedloop in timerhantering.
- [Linux ptrace-uitgangswedloop en `pidfd_getfd`-lêerbeskrywerdiefstal](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): toegang tot lêerbeskrywers tydens ’n prosesuitgangswedloop.

## Verwante gevallestudies oor binêre uitbuiting

Die afdeling Binary Exploitation gaan dieper in op uitbuitingsprimitiewe, geheue-uitleg en versagtingsomseilings vir hierdie Linux-kernteikens:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): ’n sokfout wat ontwikkel is tot lees- en skryfprimitiewe in die kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): ’n wyser-skryfprimitief wat uitgebrei is deur pypbuffers en workqueues.
- [ksmbd-strome out-of-bounds-skryf, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): kernel-heap-uitbuiting en versagtingsomseilings.
- [POSIX CPU-timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): die behandeling van die timerwedloop vanuit binêre uitbuiting, ook hier bo opgesom.
- [Arm64 statiese linear-map KASLR-omseiling](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): adresontdekking vir arm64-kerneluitbuiting.
- [Adreno A7xx GPU/SMMU-voorregte-omseiling](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): ’n Android-GPU-pad na toegang tot kernelgeheue.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): ’n Android-versnellerfout wat vir kernelskrywings gebruik word.
{{#include ../../../banners/hacktricks-training.md}}
