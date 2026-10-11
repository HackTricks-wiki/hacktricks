# Interessante Dateien und Berechtigungen

{{#include ../../banners/hacktricks-training.md}}

Dateieigentümerschaft, Schreibzugriff, Mount-Optionen und Ausführungsberechtigungen können den effektiven Zugriff eines lokalen Benutzers verändern. Ermittle zunächst die Zieldatei oder den Ausführungspfad und lies dann die relevante Seite:

- [SUID, SGID, ACLs und sensible Dateien](suid-sgid-and-acl-triage.md) bietet einen Einstieg in die Überprüfung von Ausführungsberechtigungen und versteckten Zugriffsrechten.
- [Beliebiges Schreiben in Dateien als root](write-to-root.md) beschreibt, wie Schreibzugriffe auf privilegierte Pfade zur Rechteausweitung genutzt werden können.
- [Linux capabilities](linux-capabilities.md) erklärt prozess- und dateibezogene capabilities.
- [Missbrauch von SUID-Shared-Libraries und Linkern](suid-shared-library-and-linker-abuse.md) behandelt das dynamische Laden im Zusammenhang mit privilegierten Binärdateien.
- [Beispiel für eine Rechteausweitung über `ld.so`](ld.so.conf-example.md) behandelt einen Fall mit einer Linker-Konfiguration.
- [Fehlkonfiguration von NFS mit `no_root_squash` und `no_all_squash`](nfs-no_root_squash-misconfiguration-pe.md) behandelt die Zuordnung von Identitäten bei Remote-Dateisystemen.
- [Wildcard-Tricks mit Ersatzargumenten](wildcards-spare-tricks.md) behandelt die Argumenterweiterung in privilegierten Befehlen.
- [SELinux](selinux.md) erklärt die Durchsetzung von Richtlinien und relevante Untersuchungsschritte.
{{#include ../../banners/hacktricks-training.md}}
