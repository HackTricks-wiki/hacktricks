# Allgemeine Systeminformationen

{{#include ../../banners/hacktricks-training.md}}

Untersuche den Kernel, das Dateisystem, privilegierte Hilfsprogramme und verfügbare Escape-Pfade des Hosts, bevor du eine lokale Privilegieneskalationstechnik auswählst. Die [Checkliste zur Privilegieneskalation](linux-privilege-escalation-checklist.md) bietet eine kompakte Reihenfolge für die einzelnen Schritte.

- [Bewertung von Kernel-Schwachstellen und Laufzeit-Exposition](kernel-vulnerability-assessment.md) prüft die Anwendbarkeit auf den Build, die Erreichbarkeit und aktive Mitigations.
- [Kernel-Module und Modprobe-Missbrauch](kernel-modules-and-modprobe.md) behandelt das Laden von Modulen und die Offenlegung von Helper-Pfaden.
- [Missbrauch von Sudo-Befehlen](sudo-command-abuse.md) untersucht, wie delegierte Befehle Privilegiengrenzen überschreiten können.
- [Symlinks, Hardlinks und Dateideskriptoren](filesystem-links-and-file-descriptors.md) behandelt die Umleitung von Pfaden sowie geerbte oder gelöschte, aber noch geöffnete Dateien.
- [Dateisystem, Inodes und Wiederherstellung](filesystem-inodes-and-recovery.md) erklärt für Untersuchungen nützliches Dateisystemverhalten.
- [Checkliste: Privilegieneskalation unter Linux](linux-privilege-escalation-checklist.md) listet Host-Prüfungen auf und verweist auf weiterführende Inhalte.
- [Ausbrechen aus Jails](escaping-from-limited-bash.md) behandelt eingeschränkte Shells und begrenzte Umgebungen.
- [Kernel-/LPE-/CVE-Material](kernel-lpe-cves/README.md) bündelt gezielte Beiträge zur lokalen Privilegieneskalation und zu Schwachstellen.
{{#include ../../banners/hacktricks-training.md}}
