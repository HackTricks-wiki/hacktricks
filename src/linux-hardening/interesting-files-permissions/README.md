# Interessante Dateien und Berechtigungen

{{#include ../../banners/hacktricks-training.md}}

Dateieigentümerschaft, Schreibzugriff, Mount-Optionen und Ausführungsprivilegien können den effektiven Zugriff eines lokalen Benutzers verändern. Ermittle zunächst die Zieldatei oder den Ausführungspfad und verwende dann die passende Seite:

- [SUID, SGID, ACLs und sensible Dateien](suid-sgid-and-acl-triage.md) bietet einen Einstieg in die Analyse von Ausführungsprivilegien und verborgenen Zugriffsrechten.
- [Beliebiges Schreiben in Dateien als root](write-to-root.md) beschreibt, wie Schreibzugriffe auf privilegierte Pfade zur Rechteausweitung genutzt werden können.
- [Linux capabilities](linux-capabilities.md) erklärt prozess- und dateibezogene capabilities.
- [Missbrauch von SUID-Shared-Libraries und Linkern](suid-shared-library-and-linker-abuse.md) behandelt dynamisches Laden im Umfeld privilegierter Binaries.
- [Beispiel für eine Rechteausweitung über `ld.so`](ld.so.conf-example.md) zeigt einen Fall mit einer Linker-Konfiguration.
- [Fehlkonfiguration von NFS mit `no_root_squash` und `no_all_squash`](nfs-no_root_squash-misconfiguration-pe.md) behandelt die Zuordnung von Identitäten auf Remote-Dateisystemen.
- [Wildcard-Ersatztricks](wildcards-spare-tricks.md) behandelt die Argumenterweiterung in privilegierten Befehlen.
- [SELinux](selinux.md) erklärt die Durchsetzung von Richtlinien und relevante Untersuchungsschritte.
{{#include ../../banners/hacktricks-training.md}}
