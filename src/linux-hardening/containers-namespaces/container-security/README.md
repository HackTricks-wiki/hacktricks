# Container-Sicherheit

{{#include ../../../banners/hacktricks-training.md}}

## Was ein Container tatsächlich ist

Eine praktische Definition eines Containers lautet: Ein Container ist ein **regulärer Linux-Prozessbaum**, der unter einer spezifischen OCI-ähnlichen Konfiguration gestartet wurde, sodass er ein kontrolliertes Dateisystem, eine kontrollierte Menge an Kernel-Ressourcen und ein eingeschränktes Berechtigungsmodell sieht. Der Prozess kann glauben, dass er PID 1 ist, seinen eigenen Netzwerk-Stack besitzt, seinen eigenen Hostnamen und eigene IPC-Ressourcen hat und sogar als root in seinem eigenen User Namespace ausgeführt wird. Hinter den Kulissen ist er jedoch weiterhin ein Host-Prozess, den der Kernel wie jeden anderen Prozess einplant.

Deshalb ist Container-Sicherheit letztlich die Untersuchung, wie diese Illusion erzeugt wird und wie sie versagt. Wenn der Mount Namespace schwach geschützt ist, kann der Prozess möglicherweise das Dateisystem des Hosts sehen. Wenn der User Namespace fehlt oder deaktiviert ist, kann root innerhalb des Containers zu direkt auf root auf dem Host abgebildet werden. Wenn seccomp unconfined ist und die Menge der Capabilities zu umfangreich ist, kann der Prozess Systemaufrufe und privilegierte Kernel-Funktionen erreichen, die eigentlich außerhalb seiner Reichweite bleiben sollten. Wenn der Runtime-Socket im Container gemountet ist, benötigt der Container möglicherweise überhaupt keinen Kernel-Breakout, weil er die Runtime einfach anweisen kann, einen leistungsfähigeren Schwestercontainer zu starten oder das Root-Dateisystem des Hosts direkt zu mounten.

## Wie sich Container von Virtual Machines unterscheiden

Eine VM verfügt normalerweise über ihren eigenen Kernel und eine Hardware-Abstraktionsgrenze. Das bedeutet, dass der Gast-Kernel abstürzen, in Panik geraten oder kompromittiert werden kann, ohne dass dies automatisch direkte Kontrolle über den Host-Kernel bedeutet. Container erhalten keinen separaten Kernel. Stattdessen erhalten sie eine sorgfältig gefilterte und namespacete Sicht auf denselben Kernel, den auch der Host verwendet. Daher sind Container normalerweise leichter, starten schneller, lassen sich dichter auf einer Maschine unterbringen und eignen sich besser für kurzlebige Anwendungsbereitstellungen. Der Preis dafür ist, dass die Isolationsgrenze viel direkter von der korrekten Konfiguration des Hosts und der Runtime abhängt.

Das bedeutet nicht, dass Container „unsicher“ und VMs „sicher“ sind. Es bedeutet, dass sich das Sicherheitsmodell unterscheidet. Ein gut konfigurierter Container-Stack mit rootless-Ausführung, User Namespaces, standardmäßigem seccomp, einer strikten Capability-Menge, ohne gemeinsam verwendete Host-Namespaces und mit starker SELinux- oder AppArmor-Durchsetzung kann sehr robust sein. Umgekehrt ist ein Container, der mit `--privileged`, gemeinsam verwendetem Host-PID-/Netzwerk-Namespace, einem darin gemounteten Docker-Socket und einem beschreibbaren Bind-Mount von `/` gestartet wurde, funktional deutlich näher an Host-root-Zugriff als an einer sicher isolierten Application Sandbox. Der Unterschied ergibt sich aus den aktivierten oder deaktivierten Schichten.

Es gibt außerdem einen Mittelweg, den Leser verstehen sollten, weil er in realen Umgebungen immer häufiger auftritt. **Sandboxed Container Runtimes** wie **gVisor** und **Kata Containers** härten die Grenze absichtlich stärker als ein klassischer `runc`-Container. gVisor platziert eine Userspace-Kernel-Schicht zwischen der Workload und vielen Host-Kernel-Schnittstellen, während Kata die Workload innerhalb einer leichtgewichtigen virtuellen Maschine startet. Diese werden weiterhin über Container-Ökosysteme und Orchestrierungs-Workflows verwendet, ihre Sicherheitseigenschaften unterscheiden sich jedoch von denen einfacher OCI-Runtimes. Sie sollten daher gedanklich nicht mit „normalen Docker-Containern“ gleichgesetzt werden, als würde sich alles identisch verhalten.

## Der Container-Stack: Mehrere Schichten, nicht nur eine

Wenn jemand sagt: „Dieser Container ist unsicher“, lautet die nützliche Anschlussfrage: **Welche Schicht hat ihn unsicher gemacht?** Eine containerisierte Workload ist normalerweise das Ergebnis mehrerer Komponenten, die zusammenarbeiten.

An der Spitze befindet sich häufig eine **Image-Build-Schicht** wie BuildKit, Buildah oder Kaniko, die das OCI-Image und die Metadaten erstellt. Oberhalb der Low-Level-Runtime kann sich eine **Engine oder ein Manager** wie Docker Engine, Podman, containerd, CRI-O, Incus oder systemd-nspawn befinden. In Cluster-Umgebungen kann außerdem ein **Orchestrator** wie Kubernetes die angeforderte Sicherheitslage anhand der Workload-Konfiguration bestimmen. Schließlich ist der **Kernel** dafür zuständig, Namespaces, cgroups, seccomp und die MAC-Richtlinie tatsächlich durchzusetzen.

Dieses Schichtenmodell ist wichtig, um Defaults zu verstehen. Eine Einschränkung kann von Kubernetes angefordert, über CRI durch containerd oder CRI-O übersetzt, durch den Runtime-Wrapper in eine OCI-Spezifikation umgewandelt und erst anschließend von `runc`, `crun`, `runsc` oder einer anderen Runtime gegenüber dem Kernel durchgesetzt werden. Wenn sich Defaults zwischen Umgebungen unterscheiden, liegt das häufig daran, dass eine dieser Schichten die endgültige Konfiguration verändert hat. Derselbe Mechanismus kann daher in Docker oder Podman als CLI-Flag, in Kubernetes als Pod- oder `securityContext`-Feld und in Low-Level-Runtime-Stacks als für die Workload erzeugte OCI-Konfiguration erscheinen. Aus diesem Grund sollten CLI-Beispiele in diesem Abschnitt als **Runtime-spezifische Syntax für ein allgemeines Container-Konzept** verstanden werden, nicht als universelle Flags, die von jedem Tool unterstützt werden.

## Die tatsächliche Container-Sicherheitsgrenze

In der Praxis entsteht Container-Sicherheit durch **überlappende Kontrollen**, nicht durch eine einzelne perfekte Kontrolle. Namespaces isolieren die Sichtbarkeit. cgroups steuern und begrenzen die Ressourcennutzung. Capabilities reduzieren, was ein scheinbar privilegierter Prozess tatsächlich tun kann. seccomp blockiert gefährliche Systemaufrufe, bevor sie den Kernel erreichen. AppArmor und SELinux fügen den normalen DAC-Prüfungen Mandatory Access Control hinzu. `no_new_privs`, maskierte procfs-Pfade und schreibgeschützte Systempfade erschweren gängige Privilege- und proc/sys-Missbrauchsketten. Auch die Runtime selbst ist relevant, da sie entscheidet, wie Mounts, Sockets, Labels und Namespace-Beitritte erstellt werden.

Deshalb wirkt ein großer Teil der Dokumentation zur Container-Sicherheit redundant. Dieselbe Escape-Kette hängt oft gleichzeitig von mehreren Mechanismen ab. Ein beschreibbarer Host-Bind-Mount ist beispielsweise bereits problematisch, wird aber noch wesentlich gefährlicher, wenn der Container zusätzlich als echter root auf dem Host ausgeführt wird, `CAP_SYS_ADMIN` besitzt, nicht durch seccomp eingeschränkt ist und keiner SELinux- oder AppArmor-Beschränkung unterliegt. Ebenso ist das Teilen des Host-PID-Namespace eine ernsthafte Gefährdung, wird für einen Angreifer jedoch erheblich nützlicher, wenn es mit `CAP_SYS_PTRACE`, schwachen procfs-Schutzmaßnahmen oder Namespace-Entry-Tools wie `nsenter` kombiniert wird. Der richtige Ansatz bei der Dokumentation dieses Themas besteht daher nicht darin, denselben Angriff auf jeder Seite zu wiederholen, sondern zu erklären, welchen Beitrag jede Schicht zur endgültigen Grenze leistet.

## Wie dieser Abschnitt zu lesen ist

Der Abschnitt ist von den allgemeinsten zu den spezifischsten Konzepten organisiert.

Beginne mit der Übersicht über Runtime und Ökosystem:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Sieh dir anschließend die Control Planes und Supply-Chain-Angriffsflächen an, die häufig darüber entscheiden, ob ein Angreifer überhaupt einen Kernel-Escape benötigt:

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

Die Namespace-Seiten erklären die einzelnen Kernel-Isolationsprimitive:

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

Bei der Bewertung eines containerisierten Ziels ist es wesentlich sinnvoller, eine kleine Anzahl präziser technischer Fragen zu stellen, als sofort zu bekannten Escape-PoCs überzugehen. Identifiziere zunächst den **Stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer oder etwas Spezialisierteres. Identifiziere anschließend die **Runtime**: `runc`, `crun`, `runsc`, `kata-runtime` oder eine andere OCI-kompatible Implementierung. Prüfe danach, ob die Umgebung **rootful oder rootless** ist, ob **User Namespaces** aktiv sind, ob **Host-Namespaces** gemeinsam verwendet werden, welche **Capabilities** verbleiben, ob **seccomp** aktiviert ist, ob eine **MAC-Richtlinie** tatsächlich durchgesetzt wird, ob **gefährliche Mounts oder Sockets** vorhanden sind und ob der Prozess mit der Container-Runtime-API interagieren kann.

Diese Antworten sagen wesentlich mehr über die tatsächliche Sicherheitslage aus als der Name des Base-Images. In vielen Assessments kann die wahrscheinliche Breakout-Familie bereits vorhergesagt werden, bevor eine einzige Anwendungsdatei gelesen wurde, allein durch das Verständnis der endgültigen Container-Konfiguration.

## Abdeckung

Dieser Abschnitt behandelt das frühere Docker-fokussierte Material in einer containerorientierten Organisation: Runtime- und Daemon-Exposure, Authorization Plugins, Image-Vertrauen und Build-Secrets, sensible Host-Mounts, Distroless-Workloads, privilegierte Container und die Kernel-Schutzmechanismen, die normalerweise über der Container-Ausführung liegen.
{{#include ../../../banners/hacktricks-training.md}}
