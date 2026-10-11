# Kernel-, LPE- und CVE-Material

{{#include ../../../banners/hacktricks-training.md}}

Diese Fallstudien behandeln verschiedene Primitive zur lokalen Rechteausweitung. Prüfe in jedem Artikel das betroffene Produkt bzw. den Kernel, die Konfiguration und die Voraussetzungen, bevor du eine Technik anwendest. Für eine umfassendere Host-Aufklärung verwende die [Linux-Checkliste zur Rechteausweitung](../linux-privilege-escalation-checklist.md).

Für Dirty Pipe (CVE-2022-0847) nennt die [Originalforschung](https://dirtypipe.cm4all.com/) Upstream-Stable-Fixes in den Versionen 5.10.102, 5.15.25 und 5.16.11. Eine Kernelversion in einem älteren betroffenen Bereich ist lediglich ein Hinweis zur weiteren Prüfung: Distributions-Kernel können Fixes unter abweichenden Release-Bezeichnungen zurückportieren, und die relevante Zieldatei muss für das Page-Cache-Schreibprimitive lesbar sein. Das Überschreiben einer lesbaren SUID-Datei ist ein möglicher Weg zu höheren Rechten, wenn ihr Set-ID-Übergang weiterhin wirksam ist; auch das Ändern von `/etc/passwd` und anschließende Authentifizieren kann vom lokalen PAM-Stack abhängen. Prüfe vor der Bewertung der Erreichbarkeit das installierte Kernelpaket des Anbieters, den nach einem Neustart laufenden Kernel, die Zielberechtigungen, das Mount-Flag `nosuid` und `no_new_privs`. Führe während einer passiven Aufklärung keinen Schreibtest aus. Siehe [den versionsspezifischen Status von Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Erkennung des VMware-Tools-Dienstes, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): privilegierte Ausführung durch nicht vertrauenswürdige Erkennung des Prozesspfads.
- [AF_ALG-Spleiß-Überschreiben des Page-Cache, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): ein Pfad zum Überschreiben des Kernel-Page-Cache.
- [TOCTOU bei POSIX-CPU-Timern, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): eine Race Condition bei der Timerverarbeitung.
- [Linux-ptrace-Exit-Race und Dateideskriptor-Diebstahl über `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): Zugriff auf Deskriptoren während einer Race Condition beim Prozessende.

## Verwandte Fallstudien zur Binary Exploitation

Der Abschnitt Binary Exploitation behandelt Exploit-Primitive, Speicherlayouts und das Umgehen von Mitigations für diese Linux-Kernel-Ziele ausführlicher:

- [AF_UNIX-Out-of-Band-SKB-Use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): Ein Socket-Bug wurde zu Kernel-Lese- und Schreibprimitiven weiterentwickelt.
- [Futex-PI-Use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): Ein Pointer-Schreibprimitive wurde über Pipe-Puffer und Workqueues erweitert.
- [ksmbd-Streams-Out-of-Bounds-Schreibzugriff, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): Kernel-Heap-Exploitation und das Umgehen von Mitigations.
- [TOCTOU bei POSIX-CPU-Timern, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): Die Binary-Exploitation-Behandlung der oben ebenfalls zusammengefassten Timer-Race-Condition.
- [Umgehung von Arm64-Static-Linear-Map-KASLR](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): Adressermittlung für die Arm64-Kernel-Exploitation.
- [Umgehung der Adreno-A7xx-GPU/SMMU-Rechtebeschränkung](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): Ein Android-GPU-Pfad zum Zugriff auf den Kernel-Speicher.
- [Pixel-Bigwave-Use-after-free durch Job-Timeout](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): Ein Android-Beschleuniger-Bug, der zum Schreiben in den Kernel verwendet wird.
{{#include ../../../banners/hacktricks-training.md}}
