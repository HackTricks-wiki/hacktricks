# Kernel-, LPE- en CVE-materiaal

{{#include ../../../banners/hacktricks-training.md}}

Hierdie gevallestudies dek afsonderlike plaaslike privilege escalation-primitiewe. Gaan die betrokke produk of kernel, konfigurasie en voorvereistes in elke artikel na voordat jy ’n tegniek toepas. Gebruik die [Linux privilege escalation-kontrolelys](../linux-privilege-escalation-checklist.md) vir breër host-enumeration.

Vir Dirty Pipe (CVE-2022-0847) identifiseer die [oorspronklike navorsing](https://dirtypipe.cm4all.com/) die upstream stable regstellings as 5.10.102, 5.15.25 en 5.16.11. ’n Kernel-weergawe in ’n ouer reeks wat geraak word, is slegs ’n leidraad vir verdere ondersoek: distribution-kernels kan regstellings terugporteer onder ander vrystellingname, en die betrokke teikenlêer moet leesbaar wees vir die page-cache write-primitive. Oorskryf van ’n leesbare SUID-uitvoerbare lêer is een moontlike privilege-pad wanneer die set-ID-oorgang steeds effektief is; die wysiging van `/etc/passwd` en daarna authenticating kan ook van die plaaslike PAM-stack afhang. Gaan die geïnstalleerde vendor-kernel-pakket, die kernel wat ná ’n herlaai loop, teikentoestemmings, die mount-opsie `nosuid` en `no_new_privs` na voordat jy die bereikbaarheid beoordeel. Moenie ’n write-probe tydens passiewe enumeration uitvoer nie. Sien [Ubuntu se status per vrystelling](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): bevoorregte uitvoering via onbetroubare process-path discovery.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ’n kernel page-cache overwrite-pad.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): ’n wedloop in timer-hantering.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): descriptor-toegang tydens ’n process-exit-wedloop.

## Verwante gevallestudies oor binêre uitbuiting

Die afdeling Binary Exploitation gaan dieper in op exploit-primitiewe, geheue-uitleg en omseilings van versagtingsmaatreëls vir hierdie Linux-kernel-teikens:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): ’n socket-fout wat uitgebou is tot kernel-lees- en -skryfprimitiewe.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): ’n pointer-write-primitive wat uitgebrei is via pipe-buffers en workqueues.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): kernel-heap-uitbuiting en omseilings van versagtingsmaatreëls.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): die behandeling van die timer-wedloop vanuit die perspektief van binêre uitbuiting, wat ook hier bo opgesom is.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): adres-ontdekking vir arm64-kernel-uitbuiting.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): ’n Android GPU-pad na kernel-geheue-toegang.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): ’n Android-versnellerfout wat vir kernel-skryfbewerkings gebruik is.
{{#include ../../../banners/hacktricks-training.md}}
