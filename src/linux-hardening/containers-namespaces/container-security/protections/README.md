# Überblick über Container-Protections

{{#include ../../../../banners/hacktricks-training.md}}

Die wichtigste Idee beim Hardening von Containern ist, dass es kein einzelnes Control namens „container security“ gibt. Was als Container-Isolation bezeichnet wird, ist in Wirklichkeit das Ergebnis mehrerer Linux-Sicherheits- und Ressourcenverwaltungsmechanismen, die zusammenarbeiten. Wenn die Dokumentation nur einen dieser Mechanismen beschreibt, überschätzen Leser tendenziell seine Stärke. Wenn die Dokumentation alle Mechanismen aufzählt, ohne zu erklären, wie sie interagieren, erhalten Leser zwar einen Katalog von Namen, aber kein echtes Modell. Dieser Abschnitt versucht, beide Fehler zu vermeiden.

Im Zentrum des Modells stehen **namespaces**, die isolieren, was die Workload sehen kann. Sie geben dem Prozess eine private oder teilweise private Sicht auf Filesystem-Mounts, PIDs, Networking, IPC-Objekte, Hostnames, User-/Group-Mappings, cgroup-Pfade und einige Clocks. Namespaces allein entscheiden jedoch nicht, was ein Prozess tun darf. Hier kommen die nächsten Schichten ins Spiel.

**cgroups** steuern die Ressourcennutzung. Sie sind nicht primär eine Isolationsgrenze im selben Sinne wie Mount- oder PID-Namespaces, aber operativ entscheidend, weil sie Memory, CPU, PIDs, I/O und Device-Zugriff begrenzen. Sie sind auch sicherheitsrelevant, da historische breakout-Techniken schreibbare cgroup-Funktionen missbrauchten, insbesondere in cgroup-v1-Umgebungen.

**Capabilities** teilen das alte, allmächtige Root-Modell in kleinere Privilege-Einheiten auf. Das ist für Container grundlegend, da viele Workloads weiterhin als UID 0 innerhalb des Containers laufen. Die Frage lautet daher nicht nur „ist der Prozess root?“, sondern vielmehr „welche Capabilities sind in welchen Namespaces und unter welchen seccomp- und MAC-Einschränkungen erhalten geblieben?“ Deshalb kann ein Root-Prozess in einem Container relativ eingeschränkt sein, während ein Root-Prozess in einem anderen Container in der Praxis kaum von Host-root zu unterscheiden ist.

**seccomp** filtert Syscalls und reduziert die dem Workload zugängliche Kernel-Angriffsfläche. Dies ist häufig der Mechanismus, der offensichtlich gefährliche Calls wie `unshare`, `mount`, `keyctl` oder andere in breakout chains verwendete Syscalls blockiert. Selbst wenn ein Prozess über eine Capability verfügt, die eine Operation ansonsten erlauben würde, kann seccomp den Syscall-Pfad dennoch blockieren, bevor der Kernel ihn vollständig verarbeitet.

**AppArmor** und **SELinux** fügen den normalen Filesystem- und Privilege-Prüfungen Mandatory Access Control hinzu. Diese sind besonders wichtig, weil sie auch dann weiterhin wirksam sind, wenn ein Container über mehr Capabilities verfügt, als er sollte. Ein Workload kann das theoretische Privilege besitzen, eine Aktion zu versuchen, aber dennoch daran gehindert werden, sie auszuführen, weil sein Label oder Profil den Zugriff auf den relevanten Pfad, das relevante Objekt oder die relevante Operation verbietet.

Schließlich gibt es zusätzliche Hardening-Schichten, die weniger Aufmerksamkeit erhalten, aber bei realen Angriffen regelmäßig relevant sind: `no_new_privs`, maskierte procfs-Pfade, schreibgeschützte Systempfade, schreibgeschützte Root-Filesystems und sorgfältig gewählte Runtime-Defaults. Diese Mechanismen verhindern häufig die „letzte Meile“ eines Compromise, insbesondere wenn ein Angreifer versucht, Code Execution in einen weitergehenden Privilege-Gewinn umzuwandeln.

Der Rest dieses Ordners erklärt jeden dieser Mechanismen ausführlicher, einschließlich dessen, was das jeweilige Kernel-Primitive tatsächlich tut, wie es lokal beobachtet werden kann, wie gängige Runtimes es verwenden und wie Betreiber es versehentlich abschwächen.

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

Viele reale escapes hängen auch davon ab, welche Host-Inhalte in den Workload gemountet wurden. Nach dem Lesen der grundlegenden Protections ist es daher sinnvoll, fortzufahren mit:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}

{{#include ../../../../banners/hacktricks-training.md}}
