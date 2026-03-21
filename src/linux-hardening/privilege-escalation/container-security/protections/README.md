# Übersicht: Container-Schutz

{{#include ../../../../banners/hacktricks-training.md}}

Die wichtigste Idee beim Hardening von Containern ist, dass es keine einzelne Kontrolle namens "container security" gibt. Was üblicherweise als container isolation bezeichnet wird, ist in Wirklichkeit das Ergebnis mehrerer Linux-Sicherheits- und Ressourcenverwaltungsmechanismen, die zusammenwirken. Wenn die Dokumentation nur einen davon beschreibt, neigen Leser dazu, seine Stärke zu überschätzen. Wenn die Dokumentation alle aufzählt, aber nicht erklärt, wie sie miteinander interagieren, erhält der Leser ein Namenskatalog, aber kein echtes Modell. Dieser Abschnitt versucht, beide Fehler zu vermeiden.

Im Zentrum des Modells stehen die **namespaces**, die isolieren, was die Workload sehen kann. Sie geben dem Prozess eine private oder teilweise private Sicht auf Dateisystem-Mounts, PIDs, Networking, IPC-Objekte, Hostnamen, User/Group-Mappings, cgroup-Pfade und einige Uhren. Aber namespaces allein entscheiden nicht, was ein Prozess tun darf. Hier greifen die nächsten Schichten.

**cgroups** regeln die Ressourcennutzung. Sie sind nicht primär eine Isolationsgrenze im gleichen Sinne wie mount- oder PID-namespaces, aber sie sind betrieblich entscheidend, weil sie Speicher, CPU, PIDs, I/O und Gerätezugriff einschränken. Sie haben auch Sicherheitsrelevanz, weil frühere Breakout-Techniken schreibbare cgroup-Funktionen ausgenutzt haben, besonders in cgroup v1-Umgebungen.

**capabilities** teilen das alte allmächtige Root-Modell in kleinere Privileg-Einheiten auf. Das ist für Container grundlegend, weil viele Workloads innerhalb des Containers weiterhin als UID 0 laufen. Die Frage ist daher nicht nur "ist der Prozess root?", sondern vielmehr "welche capabilities haben überlebt, innerhalb welcher namespaces, unter welchen seccomp- und MAC-Einschränkungen?" Deshalb kann ein Root-Prozess in einem Container relativ eingeschränkt sein, während ein Root-Prozess in einem anderen Container in der Praxis fast nicht vom Host-Root zu unterscheiden ist.

**seccomp** filtert Syscalls und reduziert die vom Workload exponierte Kernel-Angriffsfläche. Dies ist oft der Mechanismus, der offensichtlich gefährliche Aufrufe wie `unshare`, `mount`, `keyctl` oder andere Syscalls in Breakout-Ketten blockiert. Selbst wenn ein Prozess eine capability besitzt, die eine Operation erlauben würde, kann seccomp den Syscall-Pfad blockieren, bevor der Kernel ihn vollständig verarbeitet.

**AppArmor** und **SELinux** fügen Mandatory Access Control zusätzlich zu normalen Dateisystem- und Privilegprüfungen hinzu. Diese sind besonders wichtig, weil sie weiterhin relevant sind, selbst wenn ein Container mehr capabilities hat, als er haben sollte. Eine Workload kann das theoretische Privileg besitzen, eine Aktion zu versuchen, wird aber dennoch daran gehindert, weil ihr Label oder Profile den Zugriff auf den relevanten Pfad, das Objekt oder die Operation verbietet.

Schließlich gibt es zusätzliche Hardening-Schichten, die weniger Aufmerksamkeit erhalten, aber in echten Angriffen regelmäßig eine Rolle spielen: `no_new_privs`, maskierte procfs-Pfade, read-only Systempfade, read-only root filesystems und sorgfältige Runtime-Defaults. Diese Mechanismen stoppen oft die "letzte Meile" eines Kompromisses, besonders wenn ein Angreifer versucht, Codeausführung in einen breiteren Privilege-Gewinn zu verwandeln.

Der Rest dieses Ordners erklärt jede dieser Mechanismen detaillierter, einschließlich dessen, was die Kernel-Primitive tatsächlich macht, wie man sie lokal beobachtet, wie gängige Runtimes sie verwenden und wie Betreiber sie versehentlich schwächen.

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

Viele reale Escapes hängen außerdem davon ab, welche Host-Inhalte in die Workload gemountet wurden. Nachdem Sie die Kernschutzmaßnahmen gelesen haben, ist es nützlich, mit Folgendem fortzufahren:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
