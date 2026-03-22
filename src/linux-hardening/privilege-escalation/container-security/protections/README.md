# Übersicht zu Container-Schutzmaßnahmen

{{#include ../../../../banners/hacktricks-training.md}}

Die wichtigste Idee bei der Härtung von Containern ist, dass es keine einzelne Kontrolle mit dem Namen "container security" gibt. Was viele als container isolation bezeichnen, ist in Wirklichkeit das Zusammenspiel mehrerer Linux-Sicherheits- und Ressourcenverwaltungsmechanismen. Wenn die Dokumentation nur einen davon beschreibt, neigen Leser dazu, dessen Stärke zu überschätzen. Wenn die Dokumentation alle aufzählt, aber nicht erklärt, wie sie interagieren, entsteht nur ein Namenskatalog, kein wirkliches Modell. Dieser Abschnitt versucht, beide Fehler zu vermeiden.

Im Zentrum des Modells stehen **namespaces**, die isolieren, was der Workload sehen kann. Sie geben dem Prozess eine private oder teilweise private Sicht auf Filesystem-Mounts, PIDs, Networking, IPC-Objekte, Hostnamen, user/group mappings, cgroup paths und einige Uhren. Aber namespaces alleine entscheiden nicht, was ein Prozess darf. An dieser Stelle greifen die nächsten Schichten.

**cgroups** regeln die Ressourcennutzung. Sie sind nicht primär eine Isolationsebene im gleichen Sinne wie Mount- oder PID-namespaces, aber sie sind operativ entscheidend, weil sie Memory, CPU, PIDs, I/O und Gerätezugriff einschränken. Historisch waren beschreibbare cgroup-Features in cgroup v1-Umgebungen außerdem eine häufige Quelle für Breakout-Techniken, weshalb sie auch sicherheitsrelevant sind.

**Capabilities** zerlegen das alte allmächtige Root-Modell in kleinere Privileg-Einheiten. Das ist für Container grundlegend, weil viele Workloads weiterhin als UID 0 innerhalb des Containers laufen. Die Frage ist daher nicht nur "ist der Prozess root?", sondern eher "welche capabilities blieben erhalten, innerhalb welcher namespaces, unter welchen seccomp- und MAC-Einschränkungen?" Deshalb kann ein root-Prozess in einem Container relativ eingeschränkt sein, während ein root-Prozess in einem anderen Container praktisch kaum vom Host-root zu unterscheiden ist.

**seccomp** filtert Syscalls und reduziert die vom Workload exponierte Kernel-Angriffsfläche. Häufig ist dies der Mechanismus, der offensichtlich gefährliche Aufrufe wie `unshare`, `mount`, `keyctl` oder andere in Breakout-Ketten verwendete syscalls blockiert. Selbst wenn ein Prozess eine Capability besitzt, die eine Operation erlauben würde, kann seccomp den syscall-Pfad bereits blockieren, bevor der Kernel ihn vollständig verarbeitet.

**AppArmor** und **SELinux** fügen Mandatory Access Control oberhalb der normalen Dateisystem- und Privilegprüfungen hinzu. Sie sind besonders wichtig, weil sie weiterhin greifen, selbst wenn ein Container mehr capabilities hat, als er eigentlich sollte. Ein Workload kann das theoretische Privileg besitzen, eine Aktion zu versuchen, wird dabei aber dennoch daran gehindert, weil sein Label oder Profil den Zugriff auf den relevanten Pfad, das Objekt oder die Operation verbietet.

Schließlich gibt es zusätzliche Härtungsschichten, die weniger Aufmerksamkeit erhalten, in realen Angriffen aber regelmäßig eine Rolle spielen: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems und sorgfältig gewählte runtime defaults. Diese Mechanismen stoppen oft die "letzte Meile" einer Kompromittierung, besonders wenn ein Angreifer versucht, Codeausführung in eine breitere Privilegienerweiterung umzuwandeln.

Der Rest dieses Ordners erklärt jede dieser Mechanismen detaillierter: was das Kernel-Primitive tatsächlich macht, wie man es lokal beobachtet, wie gängige Runtimes es nutzen und wie Betreiber es versehentlich schwächen.

## Als Nächstes lesen

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
