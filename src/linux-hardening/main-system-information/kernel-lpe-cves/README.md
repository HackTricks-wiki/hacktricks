# Kernel-, LPE- und CVE-Material

{{#include ../../../banners/hacktricks-training.md}}

Diese Fallstudien behandeln verschiedene Primitive zur lokalen Privilegieneskalation. Prüfe vor der Anwendung einer Technik das betroffene Produkt oder den Kernel, die Konfiguration und die jeweiligen Voraussetzungen im entsprechenden Artikel. Für eine umfassendere Host-Aufzählung verwende die [Checkliste zur Linux-Privilegieneskalation](../linux-privilege-escalation-checklist.md).

Für Dirty Pipe (CVE-2022-0847) nennt die [ursprüngliche Forschung](https://dirtypipe.cm4all.com/) die Upstream-Stable-Fixes in 5.10.102, 5.15.25 und 5.16.11. Eine Kernelversion in einem älteren betroffenen Bereich ist lediglich ein Anhaltspunkt für eine Überprüfung: Distributions-Kernel können Fixes unter abweichenden Release-Namen zurückportieren, und die relevante Zieldatei muss für das Page-Cache-Schreibprimitive lesbar sein. Das Überschreiben einer lesbaren SUID-Executable ist ein möglicher Pfad zur Privilegieneskalation, wenn deren Set-ID-Übergang weiterhin wirksam ist; auch das Ändern von `/etc/passwd` und anschließende Authentifizieren kann vom lokalen PAM-Stack abhängen. Prüfe das installierte Kernelpaket des Anbieters, den nach dem Neustart laufenden Kernel, die Zielberechtigungen, den Mount-Parameter `nosuid` und `no_new_privs`, bevor du die Erreichbarkeit bewertest. Führe während einer passiven Aufzählung keinen Schreibtest aus. Siehe [Ubuntus Status für die jeweilige Version](https://ubuntu.com/security/CVE-2022-0847).

- [Erkennung des VMware-Tools-Dienstes, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): privilegierte Ausführung durch Erkennung eines nicht vertrauenswürdigen Prozesspfads.
- [AF_ALG-Splice-Überschreiben des Page Cache, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ein Pfad zum Überschreiben des Kernel-Page-Cache.
- [TOCTOU-Race bei POSIX-CPU-Timern, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): ein Race bei der Timer-Verarbeitung.
- [Linux-ptrace-Exit-Race und Dateideskriptor-Diebstahl über `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): Zugriff auf Deskriptoren während eines Prozess-Exit-Race.

## Verwandte Fallstudien zur Binary Exploitation

Der Abschnitt Binary Exploitation behandelt Exploit-Primitive, Speicherlayout und das Umgehen von Mitigations für diese Linux-Kernel-Ziele ausführlicher:

- [AF_UNIX-Out-of-Band-SKB-Use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): Ein Socket-Fehler wurde zu Kernel-Lese- und Schreibprimitiven weiterentwickelt.
- [AF_ALG-Scatterlist-Underflow bei konkurrierenden Schreibern](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): Ein Race bei einem skcipher-Schreiber wurde zu einem Kernel-Schreibzugriff weiterentwickelt.
- [Futex-PI-Use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): Ein Zeigerschreib-Primitive wurde über Pipe-Puffer und Workqueues erweitert.
- [Out-of-Bounds-Schreibzugriff auf ksmbd-Streams, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): Kernel-Heap-Exploitation und das Umgehen von Mitigations.
- [TOCTOU-Race bei POSIX-CPU-Timern, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): die oben ebenfalls zusammengefasste Behandlung des Timer-Race aus Sicht der Binary Exploitation.
- [KASLR-Umgehung der statischen linearen Arm64-Map](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): Ermittlung von Adressen für Arm64-Kernel-Exploitation.
- [Umgehung der Adreno-A7xx-GPU/SMMU-Privilegien](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): ein Android-GPU-Pfad zum Zugriff auf den Kernel-Speicher.
- [Use-after-free durch Job-Timeout bei Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): Ein Android-Beschleunigerfehler, der für Kernel-Schreibzugriffe genutzt wird.
{{#include ../../../banners/hacktricks-training.md}}
