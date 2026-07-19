# Überblick über Container-Schutzmaßnahmen

{{#include ../../../../banners/hacktricks-training.md}}

Die wichtigste Erkenntnis beim Hardening von Containern ist, dass es keine einzelne Kontrolle namens „container security“ gibt. Die sogenannte Container-Isolation ist in Wirklichkeit das Ergebnis mehrerer Linux-Mechanismen für Security und Ressourcenverwaltung, die zusammenarbeiten. Wenn die Dokumentation nur einen dieser Mechanismen beschreibt, überschätzen Leser leicht seine Stärke. Wenn die Dokumentation alle Mechanismen auflistet, ohne ihre Wechselwirkungen zu erklären, erhalten Leser zwar einen Katalog von Namen, aber kein brauchbares Modell. Dieser Abschnitt versucht, beide Fehler zu vermeiden.

Im Zentrum des Modells stehen **namespaces**, die isolieren, was die Workload sehen kann. Sie geben dem Prozess eine private oder teilweise private Sicht auf Filesystem-Mounts, PIDs, Netzwerk, IPC-Objekte, Hostnamen, User-/Group-Zuordnungen, cgroup-Pfade und einige clocks. Namespaces allein entscheiden jedoch nicht, was ein Prozess tun darf. Hier kommen die nächsten Schichten ins Spiel.

**cgroups** steuern die Ressourcennutzung. Sie sind nicht in erster Linie eine Isolationsgrenze im selben Sinne wie Mount- oder PID-namespaces, aber sie sind für den Betrieb entscheidend, da sie Speicher, CPU, PIDs, I/O und Device-Zugriff beschränken. Sie sind auch aus Security-Sicht relevant, weil historische Breakout-Techniken beschreibbare cgroup-Funktionen ausgenutzt haben, insbesondere in cgroup-v1-Umgebungen.

**Capabilities** teilen das alte, allmächtige Root-Modell in kleinere Privilege-Einheiten auf. Das ist für Container grundlegend, weil viele Workloads weiterhin als UID 0 innerhalb des Containers laufen. Die Frage lautet daher nicht nur „ist der Prozess root?“, sondern vielmehr „welche Capabilities sind erhalten geblieben, innerhalb welcher namespaces und unter welchen seccomp- und MAC-Einschränkungen?“. Deshalb kann ein Root-Prozess in einem Container relativ eingeschränkt sein, während ein Root-Prozess in einem anderen Container in der Praxis kaum von Host-root zu unterscheiden ist.

**seccomp** filtert Syscalls und reduziert die Kernel-Angriffsfläche, die der Workload erreicht. Dies ist häufig der Mechanismus, der offensichtlich gefährliche Aufrufe wie `unshare`, `mount`, `keyctl` oder andere in Breakout-Ketten verwendete Syscalls blockiert. Selbst wenn ein Prozess über eine Capability verfügt, die eine Operation andernfalls erlauben würde, kann seccomp den Syscall-Pfad weiterhin blockieren, bevor der Kernel ihn vollständig verarbeitet.

**AppArmor** und **SELinux** fügen den normalen Filesystem- und Privilege-Prüfungen Mandatory Access Control hinzu. Diese Mechanismen sind besonders wichtig, weil sie auch dann weiterhin wirksam sind, wenn ein Container über mehr Capabilities verfügt, als er sollte. Ein Workload kann die theoretischen Privileges besitzen, um eine Aktion zu versuchen, aber dennoch daran gehindert werden, sie auszuführen, weil sein Label oder Profil den Zugriff auf den relevanten Pfad, das Objekt oder die Operation verbietet.

Schließlich gibt es zusätzliche Hardening-Schichten, denen weniger Aufmerksamkeit zuteilwird, die bei realen Angriffen aber regelmäßig eine Rolle spielen: `no_new_privs`, maskierte procfs-Pfade, schreibgeschützte Systempfade, schreibgeschützte Root-Filesystems und sorgfältig gewählte Runtime-Defaults. Diese Mechanismen verhindern häufig die „letzte Meile“ eines Compromises, insbesondere wenn ein Angreifer versucht, Codeausführung in eine umfassendere Privilege-Erweiterung umzuwandeln.

Der restliche Inhalt dieses Ordners erläutert jeden dieser Mechanismen ausführlicher. Dabei wird erklärt, was das jeweilige Kernel-Primitive tatsächlich tut, wie es lokal beobachtet werden kann, wie gängige Runtimes es verwenden und wie Betreiber es versehentlich schwächen.

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

Viele reale Escapes hängen außerdem davon ab, welche Host-Inhalte in den Workload gemountet wurden. Nach der Lektüre der grundlegenden Schutzmaßnahmen ist es daher sinnvoll, fortzufahren mit:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
