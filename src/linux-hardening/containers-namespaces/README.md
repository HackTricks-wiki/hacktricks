# Container und Namespaces

{{#include ../../banners/hacktricks-training.md}}

Ein Container ist ein Linux-Prozess, der mit einer Isolations- und Berechtigungskonfiguration ausgeführt wird. Bewerte Laufzeit, eingehängte Host-Ressourcen, gewährte Capabilities und Namespace-Einstellungen gemeinsam. Die [Übersicht zur Containersicherheit](container-security/README.md) erläutert diese Ebenen und verweist auf die einzelnen Kontrollen.

- [Containerd (`ctr`)-Privilegieneskalation](containerd-ctr-privilege-escalation.md) konzentriert sich auf den Zugriff auf die Verwaltungsschnittstelle von containerd.
- [RunC-Privilegieneskalation](runc-privilege-escalation.md) behandelt laufzeitspezifisches Material zur Privilegieneskalation.
- [Containersicherheit](container-security/README.md) erläutert Laufzeiten, offengelegte APIs, Image-Risiken, sensible Mounts, privilegierte Container, Assessments und Schutzmaßnahmen wie Namespaces, seccomp und obligatorische Zugriffskontrolle.
{{#include ../../banners/hacktricks-training.md}}
