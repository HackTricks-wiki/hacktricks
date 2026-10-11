# Hauptsysteminformationen

{{#include ../../banners/hacktricks-training.md}}

Untersuche den Kernel, das Dateisystem, privilegierte Hilfsprogramme und verfügbare Fluchtwege des Hosts, bevor du eine lokale Rechteausweitungstechnik auswählst. Die [Checkliste zur Rechteausweitung](linux-privilege-escalation-checklist.md) bietet eine kompakte Reihenfolge der Vorgehensweise.

- [Bewertung von Kernel-Schwachstellen und Laufzeit-Exposition](kernel-vulnerability-assessment.md) prüft die Anwendbarkeit auf den Build, die Erreichbarkeit und aktive Gegenmaßnahmen.
- [Kernel-Module und modprobe-Missbrauch](kernel-modules-and-modprobe.md) behandelt das Laden von Modulen und die Offenlegung von Hilfspfaden.
- [Missbrauch von Sudo-Befehlen](sudo-command-abuse.md) untersucht, wie delegierte Befehle Privilegiengrenzen überschreiten können.
- [Symlinks, Hardlinks und Dateideskriptoren](filesystem-links-and-file-descriptors.md) behandelt die Umleitung von Pfaden sowie geerbte oder gelöschte, aber noch geöffnete Dateien.
- [Dateisystem, Inodes und Wiederherstellung](filesystem-inodes-and-recovery.md) erklärt Dateisystemverhalten, das bei Untersuchungen nützlich ist.
- [Checkliste: Linux-Rechteausweitung](linux-privilege-escalation-checklist.md) listet Host-Prüfungen auf und verweist auf weiterführende Inhalte.
- [Ausbrechen aus Jails](escaping-from-limited-bash.md) behandelt eingeschränkte Shells und begrenzte Umgebungen.
- [Kernel/LPE/CVE-Material](kernel-lpe-cves/README.md) bündelt gezielte Berichte zu lokaler Rechteausweitung und Schwachstellen.
{{#include ../../banners/hacktricks-training.md}}
