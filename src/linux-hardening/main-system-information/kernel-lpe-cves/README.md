# Kernel-, LPE- und CVE-Material

{{#include ../../../banners/hacktricks-training.md}}

Diese Fallstudien behandeln unterschiedliche Primitive zur lokalen Privilegieneskalation. Prüfe in jedem Artikel das betroffene Produkt oder den betroffenen Kernel, die Konfiguration und die Voraussetzungen, bevor du eine Technik anwendest. Für eine umfassendere Host-Aufklärung verwende die [Linux-Checkliste zur Privilegieneskalation](../linux-privilege-escalation-checklist.md).

Für Dirty Pipe (CVE-2022-0847) nennt die [ursprüngliche Forschung](https://dirtypipe.cm4all.com/) die Upstream-Stable-Fixes in 5.10.102, 5.15.25 und 5.16.11. Eine Kernel-Version in einem älteren betroffenen Bereich ist lediglich ein Anlass für eine Prüfung: Distributions-Kernel können Fixes unter anderen Release-Bezeichnungen zurückportieren, und die relevante Zieldatei muss lesbar sein, damit das Page-Cache-Schreibprimitive funktioniert. Das Überschreiben einer lesbaren SUID-Datei ist ein möglicher Weg zur Privilegieneskalation, sofern deren set-ID-Übergang weiterhin wirksam ist; auch das Ändern von `/etc/passwd` mit anschließender Authentifizierung kann vom lokalen PAM-Stack abhängen. Prüfe vor der Beurteilung der Erreichbarkeit das installierte Kernel-Paket des Herstellers, den nach einem Neustart laufenden Kernel, die Berechtigungen des Ziels, das Mount-Flag `nosuid` und `no_new_privs`. Führe bei passiver Aufklärung keinen Schreibtest aus. Siehe [den versionsspezifischen Status von Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [VMware-Tools-Service-Erkennung, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): privilegierte Ausführung durch Erkennung von Prozessen über einen nicht vertrauenswürdigen Suchpfad.
- [AF_ALG-Splice-Überschreiben des Page-Cache, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ein Pfad zum Überschreiben des Kernel-Page-Cache.
- [POSIX-CPU-Timer-TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): eine Race Condition bei der Timer-Verarbeitung.
- [Linux-ptrace-Exit-Race und Dateideskriptor-Diebstahl mit `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): Zugriff auf Deskriptoren während einer Race Condition beim Prozessende.

## Verwandte Fallstudien zu Binary Exploitation

Der Abschnitt Binary Exploitation geht ausführlicher auf Exploit-Primitiven, Speicherlayouts und das Umgehen von Mitigations für diese Linux-Kernel-Ziele ein:

- [AF_UNIX-Out-of-Band-SKB-Use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): Ein Socket-Bug wird zu Kernel-Lese- und Schreibprimitiven weiterentwickelt.
- [Futex-PI-Use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): Ein Pointer-Schreibprimitive wird über Pipe-Puffer und Workqueues erweitert.
- [ksmbd-Streams-Out-of-Bounds-Write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): Kernel-Heap-Exploitation und das Umgehen von Mitigations.
- [POSIX-CPU-Timer-TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): die Behandlung der Timer-Race-Condition aus Sicht der Binary Exploitation, die oben ebenfalls zusammengefasst ist.
- [Arm64-KASLR-Bypass für statische lineare Mappings](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): Adressfindung für arm64-Kernel-Exploitation.
- [Adreno-A7xx-GPU/SMMU-Privilegien-Bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): ein Android-GPU-Pfad zum Zugriff auf Kernel-Speicher.
- [Pixel-Bigwave-Use-after-free durch Job-Timeout](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): ein Android-Beschleuniger-Bug, der für Kernel-Schreibzugriffe genutzt wird.
{{#include ../../../banners/hacktricks-training.md}}
