# Container und Namespaces

{{#include ../../banners/hacktricks-training.md}}

Ein Container ist ein Linux-Prozess, der mit einer Konfiguration für Isolation und Berechtigungen ausgeführt wird. Bewerte Laufzeitumgebung, eingebundene Host-Ressourcen, gewährte Capabilities und Namespace-Einstellungen zusammen. Die [Übersicht zur Container-Sicherheit](container-security/README.md) erläutert diese Ebenen und verweist auf die jeweiligen Kontrollen.

- [Containerd (`ctr`) Privilege Escalation](containerd-ctr-privilege-escalation.md) konzentriert sich auf den Zugriff auf die Verwaltungsschnittstelle von containerd.
- [RunC Privilege Escalation](runc-privilege-escalation.md) behandelt laufzeitspezifische Methoden zur Rechteausweitung.
- [Container-Sicherheit](container-security/README.md) erläutert Laufzeitumgebungen, exponierte APIs, Image-Risiken, sensible Mounts, privilegierte Container, Assessments und Schutzmaßnahmen wie Namespaces, seccomp und obligatorische Zugriffskontrolle.
{{#include ../../banners/hacktricks-training.md}}
