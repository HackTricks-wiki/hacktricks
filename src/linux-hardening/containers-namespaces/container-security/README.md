# Container-Sicherheit

{{#include ../../../banners/hacktricks-training.md}}

## Was ein Container tatsächlich ist

Eine praktische Möglichkeit, einen Container zu definieren, ist folgende: Ein Container ist ein **gewöhnlicher Linux-Prozessbaum**, der unter einer bestimmten OCI-ähnlichen Konfiguration gestartet wurde, sodass er ein kontrolliertes Dateisystem, eine kontrollierte Menge an Kernel-Ressourcen und ein eingeschränktes Privilegienmodell sieht. Der Prozess kann glauben, dass er PID 1 ist, dass er über einen eigenen Netzwerk-Stack verfügt, dass ihm sein eigener Hostname und eigene IPC-Ressourcen gehören und dass er sogar als root in seinem eigenen User Namespace ausgeführt wird. Unter der Oberfläche ist er jedoch weiterhin ein Host-Prozess, den der Kernel wie jeden anderen Prozess einplant.

Aus diesem Grund befasst sich Container-Sicherheit im Kern damit, wie diese Illusion konstruiert wird und wie sie scheitert. Wenn der Mount Namespace unzureichend geschützt ist, kann der Prozess möglicherweise das Host-Dateisystem sehen. Wenn der User Namespace fehlt oder deaktiviert ist, kann root innerhalb des Containers zu direkt auf root auf dem Host abgebildet werden. Wenn seccomp unconfined ist und der Capability-Satz zu umfangreich ist, kann der Prozess Syscalls und privilegierte Kernel-Funktionen erreichen, die eigentlich unzugänglich bleiben sollten. Wenn der Runtime-Socket im Container eingebunden ist, benötigt der Container möglicherweise überhaupt keinen Kernel breakout, da er die Runtime einfach anweisen kann, einen mächtigeren Schwester-Container zu starten oder das Host-Root-Dateisystem direkt einzubinden.

## Wie sich Container von virtuellen Maschinen unterscheiden

Eine VM enthält normalerweise ihren eigenen Kernel und eine Hardware-Abstraktionsgrenze. Das bedeutet, dass der Gast-Kernel abstürzen, in Panik geraten oder kompromittiert werden kann, ohne dass dies automatisch eine direkte Kontrolle über den Host-Kernel impliziert. Bei Containern erhält die Workload keinen separaten Kernel. Stattdessen erhält sie eine sorgfältig gefilterte und durch Namespaces getrennte Sicht auf denselben Kernel, den der Host verwendet. Daher sind Container normalerweise leichter, starten schneller, lassen sich dichter auf einer Maschine unterbringen und eignen sich besser für kurzlebige Anwendungsbereitstellungen. Der Preis dafür ist, dass die Isolationsgrenze wesentlich direkter von einer korrekten Host- und Runtime-Konfiguration abhängt.

Das bedeutet nicht, dass Container "unsicher" und VMs "sicher" sind. Es bedeutet, dass sich das Sicherheitsmodell unterscheidet. Ein gut konfigurierter Container-Stack mit rootless execution, User Namespaces, standardmäßigem seccomp, einem strengen Capability-Satz, ohne gemeinsame Host Namespaces und mit einer starken Durchsetzung von SELinux oder AppArmor kann sehr robust sein. Umgekehrt ist ein Container, der mit `--privileged`, gemeinsam genutztem Host-PID/Netzwerk, einem darin eingebundenen Docker-Socket und einem beschreibbaren Bind Mount von `/` gestartet wurde, funktional wesentlich näher an Host-root-Zugriff als an einer sicher isolierten Application Sandbox. Der Unterschied ergibt sich aus den aktivierten oder deaktivierten Ebenen.

Es gibt außerdem einen Mittelweg, den Leser verstehen sollten, da er in realen Umgebungen immer häufiger vorkommt. **Sandboxed Container Runtimes** wie **gVisor** und **Kata Containers** härten die Grenze absichtlich stärker als ein klassischer `runc`-Container. gVisor platziert eine Userspace-Kernel-Schicht zwischen der Workload und vielen Host-Kernel-Schnittstellen, während Kata die Workload innerhalb einer leichtgewichtigen virtuellen Maschine startet. Diese werden weiterhin über Container-Ökosysteme und Orchestrierungs-Workflows verwendet, aber ihre Sicherheitseigenschaften unterscheiden sich von einfachen OCI-Runtimes. Sie sollten daher gedanklich nicht mit "normalen Docker-Containern" gleichgesetzt werden, als würde sich alles auf dieselbe Weise verhalten.

## Der Container-Stack: Mehrere Ebenen, nicht nur eine

Wenn jemand sagt: "Dieser Container ist unsicher", lautet die nützliche Anschlussfrage: **Welche Ebene hat ihn unsicher gemacht?** Eine containerisierte Workload ist normalerweise das Ergebnis mehrerer Komponenten, die zusammenarbeiten.

An der Spitze gibt es häufig eine **Image-Build-Ebene** wie BuildKit, Buildah oder Kaniko, die das OCI-Image und die Metadaten erstellt. Über der Low-Level-Runtime kann sich eine **Engine oder ein Manager** wie Docker Engine, Podman, containerd, CRI-O, Incus oder systemd-nspawn befinden. In Cluster-Umgebungen kann außerdem ein **Orchestrator** wie Kubernetes die angeforderte Sicherheitskonfiguration anhand der Workload-Konfiguration bestimmen. Schließlich ist es der **Kernel**, der Namespaces, cgroups, seccomp und die MAC-Richtlinie tatsächlich durchsetzt.

Dieses Schichtenmodell ist wichtig, um Defaults zu verstehen. Eine Einschränkung kann von Kubernetes angefordert, über CRI durch containerd oder CRI-O übertragen, durch den Runtime-Wrapper in eine OCI-Spezifikation umgewandelt und erst danach von `runc`, `crun`, `runsc` oder einer anderen Runtime gegenüber dem Kernel durchgesetzt werden. Wenn sich Defaults zwischen Umgebungen unterscheiden, liegt das häufig daran, dass eine dieser Ebenen die endgültige Konfiguration verändert hat. Derselbe Mechanismus kann daher in Docker oder Podman als CLI-Flag, in Kubernetes als Pod- oder `securityContext`-Feld und in Low-Level-Runtime-Stacks als für die Workload erzeugte OCI-Konfiguration erscheinen. Aus diesem Grund sollten CLI-Beispiele in diesem Abschnitt als **Runtime-spezifische Syntax für ein allgemeines Container-Konzept** verstanden werden, nicht als universelle Flags, die von jedem Tool unterstützt werden.

## Die tatsächliche Container-Sicherheitsgrenze

In der Praxis entsteht Container-Sicherheit durch **überlappende Kontrollen**, nicht durch eine einzelne perfekte Kontrolle. Namespaces isolieren die Sichtbarkeit. cgroups steuern und begrenzen die Ressourcennutzung. Capabilities reduzieren, was ein privilegiert wirkender Prozess tatsächlich tun kann. seccomp blockiert gefährliche Syscalls, bevor sie den Kernel erreichen. AppArmor und SELinux ergänzen die normalen DAC-Prüfungen um Mandatory Access Control. `no_new_privs`, maskierte procfs-Pfade und schreibgeschützte Systempfade erschweren gängige Privilegien- und proc/sys-Missbrauchsketten. Auch die Runtime selbst ist relevant, da sie entscheidet, wie Mounts, Sockets, Labels und Namespace-Beitritte erstellt werden.

Deshalb wirkt ein großer Teil der Dokumentation zur Container-Sicherheit wiederholend. Dieselbe Escape-Kette hängt oft gleichzeitig von mehreren Mechanismen ab. Ein beschreibbarer Host-Bind-Mount ist beispielsweise problematisch, wird jedoch deutlich gefährlicher, wenn der Container außerdem als echter root auf dem Host ausgeführt wird, über `CAP_SYS_ADMIN` verfügt, durch seccomp nicht eingeschränkt ist und keiner Beschränkung durch SELinux oder AppArmor unterliegt. Ebenso stellt das gemeinsame Verwenden des Host-PID-Namespaces eine ernsthafte Gefährdung dar, wird für einen Angreifer jedoch erheblich nützlicher, wenn dies mit `CAP_SYS_PTRACE`, schwachen procfs-Schutzmaßnahmen oder Namespace-Entry-Tools wie `nsenter` kombiniert wird. Die richtige Art, dieses Thema zu dokumentieren, besteht daher nicht darin, denselben Angriff auf jeder Seite zu wiederholen, sondern zu erklären, welchen Beitrag jede Ebene zur endgültigen Grenze leistet.

## Wie dieser Abschnitt zu lesen ist

Der Abschnitt ist von den allgemeinsten zu den spezifischsten Konzepten gegliedert.

Beginne mit der Übersicht über Runtime und Ökosystem:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Überprüfe anschließend die Control Planes und Supply-Chain-Oberflächen, die häufig darüber entscheiden, ob ein Angreifer überhaupt einen Kernel escape benötigt:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Gehe anschließend zum Schutzmodell über:

{{#ref}}
protections/
{{#endref}}

Die Namespace-Seiten erklären die einzelnen Kernel-Isolationsprimitiven:

{{#ref}}
protections/namespaces/
{{#endref}}

Die Seiten zu cgroups, Capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, maskierten Pfaden und schreibgeschützten Systempfaden erklären die Mechanismen, die normalerweise zusätzlich zu Namespaces eingesetzt werden:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Eine gute erste Enumeration-Haltung

Bei der Bewertung eines containerisierten Ziels ist es wesentlich nützlicher, eine kleine Anzahl präziser technischer Fragen zu stellen, als sofort zu bekannten Escape-PoCs überzugehen. Identifiziere zunächst den **Stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer oder etwas Spezialisierteres. Identifiziere anschließend die **Runtime**: `runc`, `crun`, `runsc`, `kata-runtime` oder eine andere OCI-kompatible Implementierung. Prüfe danach, ob die Umgebung **rootful oder rootless** ist, ob **User Namespaces** aktiv sind, ob **Host Namespaces** gemeinsam verwendet werden, welche **Capabilities** verbleiben, ob **seccomp** aktiviert ist, ob eine **MAC-Richtlinie** tatsächlich durchgesetzt wird, ob **gefährliche Mounts oder Sockets** vorhanden sind und ob der Prozess mit der Container-Runtime-API interagieren kann.

Diese Antworten sagen wesentlich mehr über die tatsächliche Sicherheitslage aus als der Name des Base-Images. Bei vielen Assessments kann man die wahrscheinliche Breakout-Familie bereits vorhersagen, bevor man auch nur eine einzige Anwendungsdatei gelesen hat, indem man einfach die endgültige Container-Konfiguration versteht.

## Abdeckung

Dieser Abschnitt behandelt das frühere Docker-orientierte Material in einer containerorientierten Struktur: Runtime- und Daemon-Exposure, Authorization Plugins, Image Trust und Build Secrets, sensible Host-Mounts, distroless Workloads, privilegierte Container sowie die Kernel-Schutzmaßnahmen, die normalerweise rund um die Container-Ausführung eingesetzt werden.

{{#include ../../../banners/hacktricks-training.md}}
