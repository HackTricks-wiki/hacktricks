# Container-Sicherheit

## Was Ein Container Tatsächlich Ist

Eine praktische Möglichkeit, einen Container zu definieren, lautet: Ein Container ist ein **normaler Linux-Prozessbaum**, der unter einer bestimmten Konfiguration im OCI-Stil gestartet wurde, sodass er ein kontrolliertes Dateisystem, eine kontrollierte Menge an Kernel-Ressourcen und ein eingeschränktes Berechtigungsmodell sieht. Der Prozess kann glauben, dass er PID 1 ist, kann glauben, dass er über einen eigenen Netzwerk-Stack verfügt, kann glauben, dass ihm sein eigener Hostname und seine eigenen IPC-Ressourcen gehören, und kann sogar als root in seinem eigenen User Namespace ausgeführt werden. Hinter den Kulissen ist er jedoch weiterhin ein Host-Prozess, den der Kernel wie jeden anderen einplant.

Aus diesem Grund befasst sich Container-Sicherheit im Grunde damit, wie diese Illusion aufgebaut wird und wie sie versagt. Ist der Mount Namespace schwach, kann der Prozess möglicherweise das Dateisystem des Hosts sehen. Fehlt der User Namespace oder ist er deaktiviert, kann root innerhalb des Containers zu eng auf root auf dem Host abgebildet werden. Ist seccomp unconfined und das Capability-Set zu umfangreich, kann der Prozess möglicherweise Syscalls und privilegierte Kernel-Funktionen erreichen, die eigentlich außerhalb seiner Reichweite bleiben sollten. Ist der Runtime-Socket in den Container eingebunden, benötigt der Container möglicherweise überhaupt keinen Kernel-Breakout, da er die Runtime einfach auffordern kann, einen privilegierteren Geschwister-Container zu starten oder das Root-Dateisystem des Hosts direkt einzubinden.

## Wie Sich Container Von Virtuellen Maschinen Unterscheiden

Eine VM verfügt normalerweise über einen eigenen Kernel und eine eigene Hardware-Abstraktionsgrenze. Das bedeutet, dass der Gast-Kernel abstürzen, in Panik geraten oder kompromittiert werden kann, ohne automatisch eine direkte Kontrolle über den Host-Kernel zu implizieren. Bei Containern erhält der Workload keinen separaten Kernel. Stattdessen erhält er eine sorgfältig gefilterte und durch Namespaces getrennte Sicht auf denselben Kernel, den der Host verwendet. Dadurch sind Container normalerweise leichter, starten schneller, lassen sich dichter auf einer Maschine packen und eignen sich besser für kurzlebige Anwendungsbereitstellungen. Der Preis dafür ist, dass die Isolationsgrenze viel direkter von einer korrekten Host- und Runtime-Konfiguration abhängt.

Das bedeutet nicht, dass Container "unsicher" und VMs "sicher" sind. Es bedeutet, dass sich das Sicherheitsmodell unterscheidet. Ein gut konfigurierter Container-Stack mit rootless-Ausführung, User Namespaces, standardmäßigem seccomp, einem strikten Capability-Set, ohne gemeinsame Host Namespaces und mit starker SELinux- oder AppArmor-Durchsetzung kann sehr robust sein. Umgekehrt ist ein Container, der mit `--privileged`, gemeinsam genutztem Host-PID-/Netzwerk-Namespace, einem darin eingebundenen Docker-Socket und einem beschreibbaren Bind Mount von `/` gestartet wurde, funktional viel näher an einem Host-root-Zugriff als an einer sicher isolierten Application Sandbox. Der Unterschied ergibt sich aus den aktivierten oder deaktivierten Schichten.

Es gibt außerdem einen Mittelweg, den Leser verstehen sollten, da er in realen Umgebungen immer häufiger vorkommt. **Sandboxed Container Runtimes** wie **gVisor** und **Kata Containers** härten die Grenze bewusst stärker als ein klassischer `runc`-Container. gVisor platziert eine Userspace-Kernel-Schicht zwischen dem Workload und vielen Host-Kernel-Schnittstellen, während Kata den Workload innerhalb einer leichtgewichtigen virtuellen Maschine startet. Diese werden weiterhin über Container-Ökosysteme und Orchestrierungs-Workflows verwendet, aber ihre Sicherheitseigenschaften unterscheiden sich von einfachen OCI-Runtimes und sollten nicht gedanklich mit "normalen Docker-Containern" gleichgesetzt werden, als würde alles auf dieselbe Weise funktionieren.

## Der Container-Stack: Mehrere Schichten, Nicht Nur Eine

Wenn jemand sagt: "Dieser Container ist unsicher", lautet die hilfreiche Anschlussfrage: **Welche Schicht hat ihn unsicher gemacht?** Ein containerisierter Workload ist normalerweise das Ergebnis mehrerer Komponenten, die zusammenarbeiten.

An oberster Stelle befindet sich häufig eine **Image-Build-Schicht** wie BuildKit, Buildah oder Kaniko, die das OCI-Image und die Metadaten erstellt. Über der Low-Level-Runtime kann sich eine **Engine oder ein Manager** wie Docker Engine, Podman, containerd, CRI-O, Incus oder systemd-nspawn befinden. In Cluster-Umgebungen kann außerdem ein **Orchestrator** wie Kubernetes die angeforderte Sicherheitskonfiguration anhand der Workload-Konfiguration bestimmen. Schließlich ist es der **Kernel**, der Namespaces, cgroups, seccomp und die MAC-Richtlinie tatsächlich durchsetzt.

Dieses Schichtenmodell ist wichtig, um Defaults zu verstehen. Eine Einschränkung kann von Kubernetes angefordert, über CRI durch containerd oder CRI-O übersetzt, durch den Runtime-Wrapper in eine OCI-Spezifikation umgewandelt und erst danach von `runc`, `crun`, `runsc` oder einer anderen Runtime gegenüber dem Kernel durchgesetzt werden. Wenn sich Defaults zwischen Umgebungen unterscheiden, liegt das oft daran, dass eine dieser Schichten die endgültige Konfiguration geändert hat. Derselbe Mechanismus kann daher in Docker oder Podman als CLI-Flag, in Kubernetes als Pod- oder `securityContext`-Feld und in Low-Level-Runtime-Stacks als für den Workload erzeugte OCI-Konfiguration erscheinen. Aus diesem Grund sollten CLI-Beispiele in diesem Abschnitt als **Runtime-spezifische Syntax für ein allgemeines Container-Konzept** verstanden werden, nicht als universelle Flags, die von jedem Tool unterstützt werden.

## Die Tatsächliche Container-Sicherheitsgrenze

In der Praxis entsteht Container-Sicherheit durch **überlappende Kontrollen**, nicht durch eine einzelne perfekte Kontrolle. Namespaces isolieren die Sichtbarkeit. cgroups steuern und begrenzen die Ressourcennutzung. Capabilities reduzieren, was ein scheinbar privilegierter Prozess tatsächlich tun kann. seccomp blockiert gefährliche Syscalls, bevor sie den Kernel erreichen. AppArmor und SELinux fügen den normalen DAC-Prüfungen Mandatory Access Control hinzu. `no_new_privs`, maskierte procfs-Pfade und schreibgeschützte Systempfade erschweren gängige Privilege- und proc/sys-Missbrauchsketten. Auch die Runtime selbst ist relevant, da sie festlegt, wie Mounts, Sockets, Labels und Namespace-Beitritte erstellt werden.

Deshalb wirkt ein großer Teil der Dokumentation zur Container-Sicherheit repetitiv. Dieselbe Escape-Kette hängt oft gleichzeitig von mehreren Mechanismen ab. Ein beschreibbarer Host-Bind-Mount ist beispielsweise problematisch, wird aber noch weitaus gefährlicher, wenn der Container außerdem als echter root auf dem Host läuft, über `CAP_SYS_ADMIN` verfügt, nicht durch seccomp eingeschränkt ist und nicht durch SELinux oder AppArmor begrenzt wird. Ebenso ist die gemeinsame Nutzung des Host-PID-Namespaces eine erhebliche Gefährdung, wird für einen Angreifer jedoch dramatisch nützlicher, wenn sie mit `CAP_SYS_PTRACE`, schwachen procfs-Schutzmechanismen oder Namespace-Entry-Tools wie `nsenter` kombiniert wird. Der richtige Ansatz zur Dokumentation des Themas besteht daher nicht darin, denselben Angriff auf jeder Seite zu wiederholen, sondern zu erklären, welchen Beitrag jede Schicht zur endgültigen Grenze leistet.

## Wie Dieser Abschnitt Zu Lesen Ist

Der Abschnitt ist von den allgemeinsten Konzepten zu den spezifischsten organisiert.

Beginne mit der Übersicht über Runtimes und das Ökosystem:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Prüfe anschließend die Control Planes und Supply-Chain-Angriffsflächen, die häufig bestimmen, ob ein Angreifer überhaupt einen Kernel-Escape benötigt:

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

## Eine Gute Erste Enumeration-Denkweise

Bei der Bewertung eines containerisierten Ziels ist es wesentlich hilfreicher, eine kleine Anzahl präziser technischer Fragen zu stellen, als sofort zu bekannten Escape-PoCs überzugehen. Identifiziere zunächst den **Stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer oder etwas Spezialisierteres. Identifiziere anschließend die **Runtime**: `runc`, `crun`, `runsc`, `kata-runtime` oder eine andere OCI-kompatible Implementierung. Prüfe danach, ob die Umgebung **rootful oder rootless** ist, ob **User Namespaces** aktiv sind, ob **Host Namespaces** gemeinsam genutzt werden, welche **Capabilities** noch vorhanden sind, ob **seccomp** aktiviert ist, ob eine **MAC-Richtlinie** tatsächlich durchgesetzt wird, ob **gefährliche Mounts oder Sockets** vorhanden sind und ob der Prozess mit der Container-Runtime-API interagieren kann.

Diese Antworten sagen wesentlich mehr über die tatsächliche Sicherheitslage aus als der Name des Base-Images. Bei vielen Assessments kann man die wahrscheinliche Breakout-Familie bereits vorhersagen, bevor man auch nur eine einzige Anwendungsdatei gelesen hat, indem man einfach die endgültige Container-Konfiguration versteht.

## Abdeckung

Dieser Abschnitt behandelt das alte Docker-orientierte Material in einer containerorientierten Struktur: Runtime- und Daemon-Exposure, Authorization Plugins, Image-Vertrauen und Build-Secrets, sensible Host-Mounts, distroless Workloads, privilegierte Container und die Kernel-Schutzmechanismen, die normalerweise um die Container-Ausführung herum eingesetzt werden.

{{#include ../../../banners/hacktricks-training.md}}
