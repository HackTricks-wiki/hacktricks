# Container-Schutzübersicht

{{#include ../../../../banners/hacktricks-training.md}}

Die wichtigste Idee bei der Härtung von Containern ist, dass es keine einzelne Kontrolle namens "container security" gibt. Was oft als Container-Isolation bezeichnet wird, ist in Wirklichkeit das Ergebnis mehrerer Linux-Sicherheits- und Ressourcenverwaltungsmechanismen, die zusammenarbeiten. Wenn die Dokumentation nur einen davon beschreibt, neigen Leser dazu, seine Stärke zu überschätzen. Wenn die Dokumentation alle auflistet, ohne zu erklären, wie sie interagieren, erhält man eine Namensliste, aber kein echtes Modell. Dieser Abschnitt versucht, beide Fehler zu vermeiden.

Im Zentrum des Modells stehen **namespaces**, die isolieren, was der Workload sehen kann. Sie geben dem Prozess eine private oder teilweise private Sicht auf Dateisystem-Mounts, PIDs, Networking, IPC-Objekte, Hostnamen, User/Group-Mappings, cgroup-Pfade und einige Uhren. Aber namespaces allein bestimmen nicht, was ein Prozess tun darf. Hier kommen die nächsten Schichten ins Spiel.

**cgroups** regeln die Ressourcennutzung. Sie sind nicht primär eine Isolationsgrenze im selben Sinne wie Mount- oder PID-namespaces, aber sie sind operativ wichtig, weil sie Speicher, CPU, PIDs, I/O und Gerätezugriff einschränken. Sie haben auch sicherheitsrelevante Bedeutung, weil historische Escape-Techniken beschreibbare cgroup-Features ausnutzten, besonders in cgroup v1-Umgebungen.

**Capabilities** teilen das alte allmächtige root-Modell in kleinere Privilegien-Einheiten. Das ist für Container grundlegend, weil viele Workloads innerhalb des Containers weiterhin als UID 0 laufen. Die Frage ist daher nicht nur "ist der Prozess root?", sondern vielmehr "welche Capabilities sind erhalten geblieben, innerhalb welcher namespaces, unter welchen seccomp- und MAC-Einschränkungen?" Deshalb kann ein root-Prozess in einem Container relativ eingeschränkt sein, während ein root-Prozess in einem anderen Container praktisch kaum vom Host-root zu unterscheiden ist.

**seccomp** filtert syscalls und reduziert die vom Workload exponierte Kernel-Angriffsfläche. Oft ist dies der Mechanismus, der offensichtlich gefährliche Aufrufe wie `unshare`, `mount`, `keyctl` oder andere in Escape-Chains verwendete syscalls blockiert. Selbst wenn ein Prozess eine Capability hat, die eine Operation erlauben würde, kann seccomp den syscall-Pfad blockieren, bevor der Kernel ihn vollständig verarbeitet.

**AppArmor** und **SELinux** fügen Mandatory Access Control zusätzlich zu normalen Dateisystem- und Privilegprüfungen hinzu. Diese sind besonders wichtig, weil sie auch dann wirksam bleiben, wenn ein Container mehr Capabilities hat, als er sollte. Ein Workload kann das theoretische Privileg besitzen, eine Aktion zu versuchen, wird aber dennoch daran gehindert, weil sein Label oder Profil den Zugriff auf den relevanten Pfad, das Objekt oder die Operation verbietet.

Schließlich gibt es zusätzliche Härtungsschichten, die weniger Beachtung finden, aber in echten Angriffen regelmäßig eine Rolle spielen: `no_new_privs`, masked procfs paths, schreibgeschützte Systempfade, schreibgeschützte root-Dateisysteme und sorgfältige Runtime-Defaults. Diese Mechanismen stoppen oft die "letzte Meile" einer Kompromittierung, besonders wenn ein Angreifer versucht, Codeausführung in einen breiteren Privileggewinn umzuwandeln.

Der Rest dieses Ordners erklärt jeden dieser Mechanismen ausführlicher, einschließlich dessen, was das Kernel-Primitiv tatsächlich macht, wie man es lokal beobachtet, wie gängige Runtimes es verwenden und wie Betreiber es versehentlich abschwächen.

## Read Next

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

Many real escapes also depend on what host content was mounted into the workload, so after reading the core protections it is useful to continue with:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
