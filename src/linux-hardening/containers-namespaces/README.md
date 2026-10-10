# Container und Namespaces

{{#include ../../banners/hacktricks-training.md}}

Ein Container ist ein Linux-Prozess, der mit einer Isolations- und Berechtigungskonfiguration ausgeführt wird. Bewerte Runtime, eingehängte Hostressourcen, gewährte Capabilities und Namespace-Einstellungen gemeinsam. Die [Übersicht zur Containersicherheit](container-security/README.md) erläutert diese Ebenen und verlinkt die jeweiligen Kontrollmechanismen.

- [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md) konzentriert sich auf den Zugriff auf die Verwaltungsschnittstelle von containerd.
- [RunC privilege escalation](runc-privilege-escalation.md) behandelt Runtime-spezifische Inhalte zur privilege escalation.
- [Containersicherheit](container-security/README.md) erläutert Runtimes, exponierte APIs, Image-Risiken, sensible Mounts, privilegierte Container, die Bewertung und Schutzmaßnahmen wie Namespaces, seccomp und Mandatory Access Control.
{{#include ../../banners/hacktricks-training.md}}
