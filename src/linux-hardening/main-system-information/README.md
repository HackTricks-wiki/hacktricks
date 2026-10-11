# Informationen zum Hauptsystem

{{#include ../../banners/hacktricks-training.md}}

Untersuche den Kernel, das Dateisystem, privilegierte Hilfsprogramme und mögliche Escape-Wege des Hosts, bevor du eine lokale Privilegieneskalationstechnik auswählst. Die [Checkliste zur Privilegieneskalation](linux-privilege-escalation-checklist.md) bietet eine kompakte Reihenfolge der Schritte.

- [Bewertung von Kernel-Schwachstellen und Laufzeit-Exposition](kernel-vulnerability-assessment.md) prüft die Anwendbarkeit auf den Build, die Erreichbarkeit und aktive Schutzmaßnahmen.
- [Kernel-Module und Modprobe-Missbrauch](kernel-modules-and-modprobe.md) behandelt das Laden von Modulen und die Exposition von Hilfsprogramm-Pfaden.
- [Missbrauch von Sudo-Befehlen](sudo-command-abuse.md) untersucht, wie delegierte Befehle Privilegiengrenzen überschreiten können.
- [Symlinks, Hardlinks und Dateideskriptoren](filesystem-links-and-file-descriptors.md) behandelt Pfadumleitungen sowie vererbte oder gelöschte, aber noch geöffnete Dateien.
- [Dateisystem, Inodes und Wiederherstellung](filesystem-inodes-and-recovery.md) erläutert Dateisystemverhalten, das bei Untersuchungen nützlich ist.
- [Checkliste: Linux-Privilegieneskalation](linux-privilege-escalation-checklist.md) listet Prüfungen des Hosts auf und verweist auf weiterführendes Material.
- [Escape aus Jails](escaping-from-limited-bash.md) behandelt eingeschränkte Shells und begrenzte Umgebungen.
- [Kernel/LPE/CVE-Material](kernel-lpe-cves/README.md) bündelt gezielte Berichte zu lokaler Privilegieneskalation und Schwachstellen.
{{#include ../../banners/hacktricks-training.md}}
