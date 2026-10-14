# Kernel-, LPE- en CVE-materiaal

{{#include ../../../banners/hacktricks-training.md}}

Hierdie gevallestudies dek verskillende primitiewe vir plaaslike voorregte-eskalasie. Gaan die betrokke produk of kernel, konfigurasie en voorvereistes in elke artikel na voordat jy ’n tegniek toepas. Gebruik die [Linux-kontrolelys vir voorregte-eskalasie](../linux-privilege-escalation-checklist.md) vir breër host-enumerering.

Vir Dirty Pipe (CVE-2022-0847) identifiseer die [oorspronklike navorsing](https://dirtypipe.cm4all.com/) upstream-stabiele regstellings in weergawes 5.10.102, 5.15.25 en 5.16.11. ’n Kernel-weergawe in ’n ouer, geraakte reeks is slegs ’n leidraad vir verdere ondersoek: verspreidingskernels kan regstellings terugporteer onder ander vrystellingname, en die betrokke teikenlêer moet leesbaar wees vir die page-cache-skryfprimitief. Om ’n leesbare SUID-uitvoerbare lêer te oorskryf, is een moontlike voorregtepad as sy set-ID-oorgang steeds werk; die wysiging van `/etc/passwd` en daaropvolgende verifikasie kan ook van die plaaslike PAM-stapel afhang. Gaan die geïnstalleerde verskaffer-kernelpakket, die kernel wat ná herlaai loop, teikenlêertoestemmings, `nosuid`-monterings en `no_new_privs` na voordat jy bepaal of dit bereikbaar is. Moenie ’n skryfprobe tydens passiewe enumerering uitvoer nie. Sien [Ubuntu se status vir spesifieke vrystellings](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools-diensontdekking, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): bevoorregte uitvoering deur onbetroubare prosespad-ontdekking.
- [AF_ALG splice page-cache-oorskrywing, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ’n kernel page-cache-oorskrywingroete.
- [POSIX CPU timers TOCTOU-wedloop en uitbuiting, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit): timerverval/-skraping tydens taakbeëindiging, met voorvereistes vir die IRQ-pad en uitbuitingsnavorsing.
- [Linux ptrace-beëindigingswedloop en lêerbeskriwervoordiefstal met `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): toegang tot lêerbeskrywers tydens ’n prosesbeëindigingswedloop.

## Verwante gevallestudies oor binêre uitbuiting

Die afdeling Binary Exploitation gaan dieper in op uitbuitingsprimitiewe, geheue-uitleg en versagtingsomseilings vir hierdie Linux-kernteikens:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): ’n sokfout wat ontwikkel is tot kernel-lees- en -skryfprimitiewe.
- [AF_ALG scatterlist-onderloop met gelyktydige skrywers](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): ’n skrywer-wedloop in skcipher wat ontwikkel is tot ’n kernel-skryfbewerking.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): ’n wyser-skryfprimitief wat uitgebrei is deur pypbuffers en workqueues.
- [ksmbd streams-skryfbewerking buite grense, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): kernel-heap-uitbuiting en versagtingsomseilings.
- [Omseiling van Arm64 statiese lineêre kaart-KASLR](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): adresontdekking vir arm64-kernel-uitbuiting.
- [Adreno A7xx GPU/SMMU-voorregteomseiling](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): ’n Android-GPU-roete na toegang tot kernelgeheue.
- [Pixel Bigwave use-after-free weens werktyd-uittel](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): ’n Android-versnellerfout wat vir kernel-skryfbewerkings gebruik is.
{{#include ../../../banners/hacktricks-training.md}}
