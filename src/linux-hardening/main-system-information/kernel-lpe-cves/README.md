# Kernel-, LPE- und CVE-Material

{{#include ../../../banners/hacktricks-training.md}}

Diese Fallstudien behandeln verschiedene Primitiven zur lokalen Rechteausweitung. Prüfe vor der Anwendung einer Technik das betroffene Produkt oder den Kernel, die Konfiguration und die jeweiligen Voraussetzungen im entsprechenden Artikel. Für eine umfassendere Host-Aufzählung verwende die [Linux-Checkliste zur Rechteausweitung](../linux-privilege-escalation-checklist.md).

Für Dirty Pipe (CVE-2022-0847) nennt die [ursprüngliche Forschung](https://dirtypipe.cm4all.com/) Upstream-Stable-Fixes in den Versionen 5.10.102, 5.15.25 und 5.16.11. Eine Kernelversion aus einem älteren betroffenen Bereich ist lediglich ein Hinweis zur weiteren Prüfung: Distributions-Kernel können Fixes unter abweichenden Release-Namen zurückportieren, und die relevante Zieldatei muss für das Page-Cache-Schreibprimitive lesbar sein. Das Überschreiben einer lesbaren SUID-Executable ist ein möglicher Weg zu höheren Rechten, wenn deren set-ID-Übergang weiterhin wirksam ist; auch das Ändern von `/etc/passwd` und die anschließende Authentifizierung können vom lokalen PAM-Stack abhängen. Prüfe vor der Bewertung der Erreichbarkeit das installierte Kernel-Paket des Anbieters, den nach einem Neustart laufenden Kernel, die Berechtigungen des Ziels, das Mount-Flag `nosuid` und `no_new_privs`. Führe bei passiver Aufzählung keine Schreibprobe aus. Siehe den [versionsspezifischen Status von Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Erkennung des VMware-Tools-Dienstes, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): privilegierte Ausführung durch Erkennung nicht vertrauenswürdiger Prozesspfade.
- [AF_ALG-Splice-Überschreiben des Page Cache, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ein Pfad zum Überschreiben des Kernel-Page-Cache.
- [TOCTOU bei POSIX-CPU-Timern, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): eine Race Condition bei der Timer-Verarbeitung.
- [Linux-ptrace-Exit-Race und Dateideskriptor-Diebstahl mit `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): Zugriff auf Deskriptoren während einer Race Condition beim Prozessende.

## Verwandte Fallstudien zur Binary Exploitation

Der Abschnitt Binary Exploitation behandelt Exploit-Primitiven, Speicher-Layouts und das Umgehen von Mitigations für diese Linux-Kernel-Ziele ausführlicher:

- [AF_UNIX-Out-of-Band-SKB-Use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): Ein Socket-Bug wurde zu Kernel-Lese- und Schreibprimitiven weiterentwickelt.
- [Futex-PI-Use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): Ein Pointer-Schreibprimitiv wurde über Pipe-Puffer und Workqueues erweitert.
- [ksmbd-Streams-Out-of-bounds-Write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): Kernel-Heap-Exploitation und das Umgehen von Mitigations.
- [TOCTOU bei POSIX-CPU-Timern, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): die Behandlung der Timer-Race-Condition im Kontext der Binary Exploitation, die oben ebenfalls zusammengefasst ist.
- [KASLR-Umgehung bei der statischen linearen Arm64-Map](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): Adressermittlung für die Arm64-Kernel-Exploitation.
- [Adreno-A7xx-GPU/SMMU-Rechteumgehung](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): Ein Android-GPU-Pfad zum Zugriff auf den Kernel-Speicher.
- [Pixel-Bigwave-Use-after-free durch Job-Timeout](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): Ein Android-Accelerator-Bug, der zum Schreiben in den Kernel verwendet wird.
{{#include ../../../banners/hacktricks-training.md}}
