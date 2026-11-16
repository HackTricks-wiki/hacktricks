# Linux-Härtung

{{#include ../banners/hacktricks-training.md}}

Nutze diesen Abschnitt, um Linux-Hosts zu untersuchen, Privilegiengrenzen zu verstehen und die Kontrollen zu überprüfen, die den lokalen Zugriff einschränken. Beginne mit den [Linux-Grundlagen](linux-basics/README.md) und der [Privilege-Escalation-Checkliste](main-system-information/linux-privilege-escalation-checklist.md) für eine allgemeine Bewertung und folge dann dem passenden Thema unten.

- [Linux-Grundlagen](linux-basics/README.md): Methodik zur Privilege Escalation, nützliche Befehle, Umgebungsvariablen und Umgehung von Einschränkungen.
- [Systeminformationen](main-system-information/README.md): Kernel, Module, sudo, Dateisystemverhalten, Jails und die Privilege-Escalation-Checkliste.
- [Benutzerinformationen](user-information/README.md): Linux-Identitäten, Gruppen, SSH-Agent-Weiterleitung und Active-Directory-Integration.
- [Interessante Dateien und Berechtigungen](interesting-files-permissions/README.md): beschreibbare Pfade, Capabilities, SUID-Verhalten, NFS, Wildcard-Expansion und SELinux.
- [Netzwerkinformationen](network-information/README.md): lokale Dienste, Sockets und Beispiele für netzwerkbezogene Exploits.
- [Softwareinformationen](software-information/README.md): Authentifizierungsmodule und anwendungsspezifische Angriffsflächen.
- [Prozesse, Crontab, systemd und D-Bus](processes-crontab-systemd-dbus/README.md): geplante Ausführung und Interprozesskommunikation.
- [Container und Namespaces](containers-namespaces/README.md): Runtimes, Isolationsgrenzen und Container-Hardening.
- [Missbrauch von AppArmor-Policy-Control-Dateien](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): Prüfe, ob ein privilegierter Helper in eine AppArmor-Control-Datei schreiben kann, die von einem lokalen Benutzer geöffnet wurde.
- [Post-exploitation](post-exploitation/README.md): Aufspüren von Zugangsdaten, Persistenz und weitere Techniken auf Host-Ebene.

Bei betroffenen Kerneln kann das Öffnen einer AppArmor-Policy-Control-Datei in securityfs als unprivilegierter Benutzer erfolgreich sein, obwohl ein direkter Schreibzugriff verweigert wird. Wenn ein privilegierter Helper diese Datei als stdout erbt, kann sein Schreibvorgang die geladene Policy ändern. Dies ist ein eigenständiger lokaler Angriffsweg und nicht bloß das Auffinden eines schwachen Container-Profils. Prüfe vor dem Testen, ob der Hersteller Kernel- und Helper-Fixes bereitgestellt hat.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Technischer Sicherheitshinweis von Qualys zu CrackArmor](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Ubuntu-Wissensdatenbank zur CrackArmor-Sicherheitslücke](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
