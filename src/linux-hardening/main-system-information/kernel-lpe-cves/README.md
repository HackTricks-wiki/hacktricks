# Kernel-, LPE- und CVE-Material

{{#include ../../../banners/hacktricks-training.md}}

Diese Fallstudien behandeln verschiedene Primitives zur lokalen Rechteausweitung. Prüfe in jedem Artikel das betroffene Produkt oder den betroffenen Kernel, die Konfiguration und die Voraussetzungen, bevor du eine Technik anwendest. Für eine umfassendere Host-Aufzählung verwende die [Linux-Checkliste zur Rechteausweitung](../linux-privilege-escalation-checklist.md).

Für Dirty Pipe (CVE-2022-0847) nennt die [ursprüngliche Forschung](https://dirtypipe.cm4all.com/) die Upstream-Stable-Fixes in den Versionen 5.10.102, 5.15.25 und 5.16.11. Eine Kernelversion in einem älteren betroffenen Bereich ist lediglich ein Ansatzpunkt für weitere Prüfung: Distributions-Kernel können Fixes unter anderen Release-Bezeichnungen zurückportieren, und die relevante Zieldatei muss für das Page-Cache-Write-Primitive lesbar sein. Das Überschreiben einer lesbaren SUID-Executable ist ein möglicher Weg zu höheren Rechten, sofern der Set-ID-Übergang weiterhin wirksam ist; auch das Ändern von `/etc/passwd` und die anschließende Authentifizierung können vom lokalen PAM-Stack abhängen. Prüfe das installierte Hersteller-Kernelpaket, den nach einem Neustart laufenden Kernel, die Zielberechtigungen, das Mount-Flag `nosuid` und `no_new_privs`, bevor du die Erreichbarkeit bewertest. Führe bei einer passiven Aufzählung keine Schreibsonde aus. Siehe [Ubuntus versionsspezifischen Status](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): privilegierte Ausführung durch Ermittlung von Prozesspfaden aus nicht vertrauenswürdigen Quellen.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ein Pfad zum Überschreiben des Kernel-Page-Cache.
- [POSIX CPU timers TOCTOU race and exploitation, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit): Ablauf und Löschung von Timern während des Task-Exit, einschließlich Voraussetzungen für den IRQ-Pfad und Exploit-Forschung.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): Zugriff auf Dateideskriptoren während eines Prozess-Exit-Race.

## Verwandte Fallstudien zur Binary Exploitation

Der Abschnitt Binary Exploitation behandelt Exploit-Primitives, Speicherlayout und das Umgehen von Mitigations für diese Linux-Kernel-Ziele ausführlicher:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): ein Socket-Bug, aus dem Kernel-Lese- und Schreib-Primitives entwickelt wurden.
- [AF_ALG concurrent-writer scatterlist underflow](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): aus einem Race in einem skcipher-Writer wurde ein Kernel-Write entwickelt.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): ein Pointer-Write-Primitive, erweitert über Pipe-Buffer und Workqueues.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): Kernel-Heap-Exploitation und das Umgehen von Mitigations.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): Adressermittlung für die arm64-Kernel-Exploitation.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): ein Android-GPU-Pfad zum Zugriff auf Kernel-Speicher.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): ein Android-Accelerator-Bug, der für Kernel-Writes genutzt wurde.
{{#include ../../../banners/hacktricks-training.md}}
