# Kernel-, LPE- und CVE-Material

{{#include ../../../banners/hacktricks-training.md}}

Diese Fallstudien behandeln verschiedene Primitiven zur lokalen Privilegienausweitung. Prüfe in jedem Artikel das betroffene Produkt oder den betroffenen Kernel, die Konfiguration und die Voraussetzungen, bevor du eine Technik anwendest. Für eine umfassendere Host-Aufzählung verwende die [Linux-Checkliste zur Privilegienausweitung](../linux-privilege-escalation-checklist.md).

Für Dirty Pipe (CVE-2022-0847) nennt die [Originalrecherche](https://dirtypipe.cm4all.com/) die Upstream-Stable-Fixes in den Versionen 5.10.102, 5.15.25 und 5.16.11. Eine Kernel-Version in einem älteren betroffenen Bereich ist lediglich ein Ansatzpunkt für eine Prüfung: Distributions-Kernel können Fixes unter anderen Release-Bezeichnungen zurückportieren, und die relevante Zieldatei muss für die Page-Cache-Schreibprimitive lesbar sein. Das Überschreiben einer lesbaren SUID-Datei ist ein möglicher Pfad zur Privilegienausweitung, wenn ihr Set-ID-Übergang weiterhin wirksam ist; auch das Ändern von `/etc/passwd` und anschließende Authentifizieren kann vom lokalen PAM-Stack abhängen. Prüfe vor der Bewertung der Erreichbarkeit das installierte Kernel-Paket des Anbieters, den nach dem Neustart laufenden Kernel, die Zielberechtigungen, das Mount-Flag `nosuid` und `no_new_privs`. Führe während einer passiven Aufzählung keine Schreibprobe aus. Siehe [den release-spezifischen Status von Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [VMware-Tools-Serviceerkennung, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): privilegierte Ausführung durch Erkennung von Prozesspfaden aus nicht vertrauenswürdigen Quellen.
- [AF_ALG-Splice-Überschreiben des Page-Cache, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ein Pfad zum Überschreiben des Kernel-Page-Cache.
- [TOCTOU bei POSIX-CPU-Timern, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): eine Race Condition bei der Timer-Verarbeitung.
- [Linux-ptrace-Exit-Race und Dateideskriptor-Diebstahl mit `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): Zugriff auf Deskriptoren während einer Race Condition beim Prozessende.

## Verwandte Fallstudien zu Binary Exploitation

Der Abschnitt Binary Exploitation geht näher auf Exploit-Primitiven, Speicherlayout und das Umgehen von Mitigations für diese Linux-Kernel-Ziele ein:

- [AF_UNIX-Out-of-Band-SKB-Use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): Ein Socket-Fehler wurde zu Kernel-Lese- und Schreibprimitiven weiterentwickelt.
- [Futex-PI-Use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): Eine Pointer-Schreibprimitive wurde mithilfe von Pipe-Puffern und Workqueues erweitert.
- [Out-of-bounds-Schreibvorgang in ksmbd-Streams, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): Kernel-Heap-Exploitation und Umgehung von Mitigations.
- [TOCTOU bei POSIX-CPU-Timern, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): Die Behandlung der Timer-Race Condition im Kontext von Binary Exploitation, die auch oben zusammengefasst wird.
- [Umgehung von Arm64-Static-Linear-Map-KASLR](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): Adressermittlung für arm64-Kernel-Exploitation.
- [Umgehung der Adreno-A7xx-GPU/SMMU-Privilegien](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): Ein Android-GPU-Pfad zum Zugriff auf den Kernel-Speicher.
- [Use-after-free durch Job-Timeout bei Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): Ein Android-Beschleunigerfehler, der für Kernel-Schreibzugriffe genutzt wird.
{{#include ../../../banners/hacktricks-training.md}}
