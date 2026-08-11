# Container-Sicherheit

{{#include ../../../banners/hacktricks-training.md}}

## Was Ein Container Tatsächlich Ist

Eine praktische Möglichkeit, einen Container zu definieren, ist folgende: Ein Container ist ein **normaler Linux-Prozessbaum**, der unter einer spezifischen OCI-style-Konfiguration gestartet wurde, sodass er ein kontrolliertes Dateisystem, eine kontrollierte Menge an Kernel-Ressourcen und ein eingeschränktes Privilegienmodell sieht. Der Prozess kann glauben, dass er PID 1 ist, kann glauben, dass er seinen eigenen Netzwerk-Stack besitzt, kann glauben, dass ihm sein eigener Hostname und seine eigenen IPC-Ressourcen gehören, und kann sogar als root innerhalb seines eigenen User Namespace laufen. Unter der Oberfläche ist er jedoch weiterhin ein Host-Prozess, den der Kernel wie jeden anderen Prozess einplant.

Deshalb ist Container-Sicherheit im Kern die Untersuchung, wie diese Illusion konstruiert wird und wie sie versagt. Wenn der Mount Namespace schwach ist, kann der Prozess möglicherweise das Host-Dateisystem sehen. Wenn der User Namespace fehlt oder deaktiviert ist, kann root innerhalb des Containers zu direkt auf root auf dem Host abgebildet werden. Wenn seccomp unconfined ist und das Capability-Set zu umfangreich ist, kann der Prozess Syscalls und privilegierte Kernel-Funktionen erreichen, die eigentlich außerhalb seiner Reichweite bleiben sollten. Wenn der Runtime-Socket innerhalb des Containers gemountet ist, benötigt der Container möglicherweise überhaupt keinen Kernel breakout, da er die Runtime einfach auffordern kann, einen mächtigeren Schwester-Container zu starten oder das Host-Root-Dateisystem direkt zu mounten.

## Wie Sich Container Von Virtuellen Maschinen Unterscheiden

Eine VM verfügt normalerweise über ihren eigenen Kernel und eine Hardware-Abstraktionsgrenze. Das bedeutet, dass der Gast-Kernel abstürzen, in Panik geraten oder exploitet werden kann, ohne automatisch eine direkte Kontrolle über den Host-Kernel zu bedeuten. Bei Containern erhält die Workload keinen separaten Kernel. Stattdessen erhält sie eine sorgfältig gefilterte und durch Namespaces isolierte Sicht auf denselben Kernel, den auch der Host verwendet. Dadurch sind Container normalerweise leichter, starten schneller, lassen sich dichter auf einer Maschine packen und eignen sich besser für kurzlebige Anwendungsbereitstellungen. Der Preis dafür ist, dass die Isolationsgrenze wesentlich stärker von einer korrekten Host- und Runtime-Konfiguration abhängt.

Das bedeutet nicht, dass Container "unsicher" und VMs "sicher" sind. Es bedeutet, dass das Sicherheitsmodell anders ist. Ein gut konfigurierter Container-Stack mit rootless execution, User Namespaces, standardmäßigem seccomp, einem strikten Capability-Set, ohne gemeinsam verwendete Host Namespaces und mit starker SELinux- oder AppArmor-Durchsetzung kann sehr robust sein. Umgekehrt ist ein Container, der mit `--privileged`, gemeinsam verwendetem Host-PID-/Netzwerk-Namespace, innerhalb des Containers gemountetem Docker-Socket und einem beschreibbaren Bind Mount von `/` gestartet wurde, funktional wesentlich näher an Host-root-Zugriff als an einer sicher isolierten Application Sandbox. Der Unterschied ergibt sich aus den aktivierten oder deaktivierten Schichten.

Es gibt außerdem einen Mittelweg, den Leser verstehen sollten, da er in realen Umgebungen immer häufiger vorkommt. **Sandboxed Container Runtimes** wie **gVisor** und **Kata Containers** härten die Grenze absichtlich stärker als ein klassischer `runc`-Container. gVisor platziert eine Userspace-Kernel-Schicht zwischen der Workload und vielen Host-Kernel-Schnittstellen, während Kata die Workload innerhalb einer leichtgewichtigen virtuellen Maschine startet. Diese werden weiterhin über Container-Ökosysteme und Orchestrierungs-Workflows verwendet, aber ihre Sicherheitseigenschaften unterscheiden sich von einfachen OCI-Runtimes. Sie sollten daher nicht gedanklich mit "normalen Docker-Containern" gleichgesetzt werden, als würde sich alles auf dieselbe Weise verhalten.

## Der Container-Stack: Mehrere Schichten, Nicht Nur Eine

Wenn jemand sagt: "Dieser Container ist unsicher", lautet die nützliche Anschlussfrage: **Welche Schicht hat ihn unsicher gemacht?** Eine containerisierte Workload ist normalerweise das Ergebnis mehrerer Komponenten, die zusammenarbeiten.

An der Spitze befindet sich häufig eine **Image-Build-Schicht** wie BuildKit, Buildah oder Kaniko, die das OCI-Image und die Metadaten erstellt. Über der Low-Level-Runtime kann sich eine **Engine oder ein Manager** wie Docker Engine, Podman, containerd, CRI-O, Incus oder systemd-nspawn befinden. In Cluster-Umgebungen kann zusätzlich ein **Orchestrator** wie Kubernetes die angeforderte Sicherheitskonfiguration anhand der Workload-Konfiguration festlegen. Schließlich ist der **Kernel** dafür verantwortlich, Namespaces, cgroups, seccomp und MAC-Richtlinien tatsächlich durchzusetzen.

Dieses Schichtenmodell ist wichtig, um Defaults zu verstehen. Eine Einschränkung kann von Kubernetes angefordert, über CRI durch containerd oder CRI-O übersetzt, durch den Runtime-Wrapper in eine OCI-Spezifikation umgewandelt und erst danach von `runc`, `crun`, `runsc` oder einer anderen Runtime gegenüber dem Kernel durchgesetzt werden. Wenn sich Defaults zwischen Umgebungen unterscheiden, liegt das häufig daran, dass eine dieser Schichten die endgültige Konfiguration geändert hat. Derselbe Mechanismus kann daher in Docker oder Podman als CLI-Flag, in Kubernetes als Pod- oder `securityContext`-Feld und in Low-Level-Runtime-Stacks als für die Workload erzeugte OCI-Konfiguration erscheinen. CLI-Beispiele in diesem Abschnitt sollten deshalb als **Runtime-spezifische Syntax für ein allgemeines Container-Konzept** verstanden werden und nicht als universelle Flags, die von jedem Tool unterstützt werden.

## Die Tatsächliche Container-Sicherheitsgrenze

In der Praxis entsteht Container-Sicherheit durch **überlappende Kontrollen**, nicht durch eine einzelne perfekte Kontrolle. Namespaces isolieren die Sichtbarkeit. cgroups steuern und begrenzen die Ressourcennutzung. Capabilities reduzieren, was ein privilegiert wirkender Prozess tatsächlich tun kann. seccomp blockiert gefährliche Syscalls, bevor diese den Kernel erreichen. AppArmor und SELinux fügen der normalen DAC-Prüfung Mandatory Access Control hinzu. `no_new_privs`, maskierte procfs-Pfade und schreibgeschützte Systempfade erschweren gängige Privilege- und proc/sys-Abuse-Ketten. Auch die Runtime selbst ist relevant, da sie entscheidet, wie Mounts, Sockets, Labels und Namespace-Beitritte erstellt werden.

Deshalb wirkt ein großer Teil der Container-Sicherheitsdokumentation repetitiv. Dieselbe Escape-Kette hängt häufig gleichzeitig von mehreren Mechanismen ab. Ein beschreibbarer Host-Bind-Mount ist beispielsweise problematisch, wird aber wesentlich gefährlicher, wenn der Container zusätzlich als echter root auf dem Host läuft, über `CAP_SYS_ADMIN` verfügt, durch seccomp unconfined ist und nicht durch SELinux oder AppArmor eingeschränkt wird. Ebenso ist das Teilen des Host-PID-Namespaces eine ernsthafte Angriffsfläche, wird für einen Angreifer jedoch deutlich nützlicher, wenn es mit `CAP_SYS_PTRACE`, schwachen procfs-Schutzmaßnahmen oder Tools zum Betreten von Namespaces wie `nsenter` kombiniert wird. Die richtige Art, dieses Thema zu dokumentieren, besteht daher nicht darin, denselben Angriff auf jeder Seite zu wiederholen, sondern zu erklären, welchen Beitrag jede Schicht zur endgültigen Grenze leistet.

## Wie Dieser Abschnitt Zu Lesen Ist

Der Abschnitt ist von den allgemeinsten zu den spezifischsten Konzepten geordnet.

Beginne mit der Übersicht über Runtime und Ökosystem:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Anschließend sollten die Control Planes und Supply-Chain-Angriffsflächen betrachtet werden, die häufig darüber entscheiden, ob ein Angreifer überhaupt einen Kernel escape benötigt:

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

Danach geht es weiter mit dem Schutzmodell:

{{#ref}}
protections/
{{#endref}}

Die Namespace-Seiten erklären die Kernel-Isolationsprimitive einzeln:

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

## Eine Gute Ausgangshaltung Bei Der Enumeration

Bei der Bewertung eines containerisierten Ziels ist es wesentlich nützlicher, eine kleine Anzahl präziser technischer Fragen zu stellen, als sofort zu bekannten Escape-PoCs überzugehen. Identifiziere zunächst den **Stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer oder etwas Spezialisierteres. Identifiziere anschließend die **Runtime**: `runc`, `crun`, `runsc`, `kata-runtime` oder eine andere OCI-kompatible Implementierung. Prüfe danach, ob die Umgebung **rootful oder rootless** ist, ob **User Namespaces** aktiv sind, ob **Host Namespaces** gemeinsam verwendet werden, welche **Capabilities** noch vorhanden sind, ob **seccomp** aktiviert ist, ob eine **MAC-Richtlinie** tatsächlich durchgesetzt wird, ob **gefährliche Mounts oder Sockets** vorhanden sind und ob der Prozess mit der Container-Runtime-API interagieren kann.

Diese Antworten sagen wesentlich mehr über die tatsächliche Sicherheitslage aus als der Name des Base-Images. Bei vielen Assessments lässt sich die wahrscheinliche Breakout-Familie bereits vorhersagen, bevor auch nur eine einzige Anwendungsdatei gelesen wurde, indem man einfach die endgültige Container-Konfiguration versteht.

## Abdeckung

Dieser Abschnitt behandelt das frühere Docker-fokussierte Material in einer containerorientierten Gliederung: Runtime- und Daemon-Exposure, Authorization Plugins, Image Trust und Build Secrets, sensible Host-Mounts, Distroless-Workloads, privilegierte Container sowie die Kernel-Schutzmechanismen, die normalerweise um die Container-Ausführung herum eingesetzt werden.

{{#include ../../../banners/hacktricks-training.md}}
