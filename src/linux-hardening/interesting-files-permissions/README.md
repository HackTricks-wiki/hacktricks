# Interessante Dateien und Berechtigungen

{{#include ../../banners/hacktricks-training.md}}

Dateieigentümerschaft, Schreibzugriff, Mount-Optionen und Ausführungsberechtigungen können die effektive Reichweite eines lokalen Benutzers verändern. Ermittle zunächst die Zieldatei oder den Ausführungspfad und nutze dann die passende Seite:

- [SUID, SGID, ACLs und sensible Dateien](suid-sgid-and-acl-triage.md) bietet einen Einstieg in die Untersuchung von Ausführungsberechtigungen und versteckten Zugriffsrechten.
- [Beliebige Dateien als root schreiben](write-to-root.md) beschreibt, wie Schreibzugriffe auf privilegierte Pfade zur Rechteausweitung genutzt werden können.
- [Linux capabilities](linux-capabilities.md) erklärt prozess- und dateibezogene Capabilities.
- [SUID Shared-Library- und Linker-Missbrauch](suid-shared-library-and-linker-abuse.md) behandelt das dynamische Laden im Kontext privilegierter Binärdateien.
- [Beispiel zur Rechteausweitung mit `ld.so`](ld.so.conf-example.md) behandelt einen Fall mit Linker-Konfiguration.
- [Fehlkonfiguration von NFS mit `no_root_squash` und `no_all_squash`](nfs-no_root_squash-misconfiguration-pe.md) behandelt die Zuordnung von Identitäten auf Remote-Dateisystemen.
- [Wildcard-Spare-Tricks](wildcards-spare-tricks.md) behandelt die Argumenterweiterung in privilegierten Befehlen.
- [SELinux](selinux.md) erklärt die Durchsetzung von Richtlinien und relevante Untersuchungsschritte.
{{#include ../../banners/hacktricks-training.md}}
