# Container-Sicherheit

{{#include ../../../banners/hacktricks-training.md}}

## What A Container Actually Is

Eine praktische Definition eines Container ist diese: Ein Container ist ein **regulärer Linux-Prozessbaum**, der unter einer bestimmten OCI-style Konfiguration gestartet wurde, sodass er ein kontrolliertes Dateisystem, eine kontrollierte Menge an Kernel-Ressourcen und ein eingeschränktes Privilegmodell sieht. Der Prozess kann glauben, er sei PID 1, kann glauben, er habe seinen eigenen network stack, kann glauben, er besitze seinen eigenen Hostname und IPC-Ressourcen und kann sogar als root innerhalb seines eigenen user namespace laufen. Unter der Haube ist er jedoch immer noch ein Host-Prozess, den der Kernel wie jeden anderen plant.

Deshalb ist Container-Sicherheit in Wirklichkeit die Untersuchung, wie diese Illusion aufgebaut wird und wie sie versagt. Wenn das mount namespace schwach ist, kann der Prozess das Host-Dateisystem sehen. Wenn der user namespace fehlt oder deaktiviert ist, kann root innerhalb des Containers zu eng an root auf dem Host abgebildet werden. Wenn seccomp unkonfiguriert ist und der capability-Satz zu breit ist, kann der Prozess syscalls und privilegierte Kernel-Funktionen erreichen, die außerhalb der Reichweite bleiben sollten. Wenn der runtime socket im Container gemountet ist, braucht der Container möglicherweise keinen Kernel-Breakout, weil er einfach den runtime fragen kann, einen mächtigeren Sibling-Container zu starten oder das Host-Root-Dateisystem direkt zu mounten.

## How Containers Differ From Virtual Machines

Eine VM trägt normalerweise ihren eigenen Kernel und eine Hardware-Abstraktionsgrenze. Das bedeutet, der guest kernel kann abstürzen, panicen oder ausgenutzt werden, ohne automatisch direkte Kontrolle über den host kernel zu implizieren. Bei Containern bekommt die Workload keinen separaten Kernel. Stattdessen erhält sie eine sorgfältig gefilterte und namespacete Sicht auf denselben Kernel, den der Host verwendet. Dadurch sind Container in der Regel leichter, schneller zu starten, einfacher dicht auf einer Maschine zu packen und besser für kurzlebige Anwendungsbereitstellungen geeignet. Der Preis dafür ist, dass die Isolationsgrenze viel direkter von korrekter Host- und Runtime-Konfiguration abhängt.

Das bedeutet nicht, dass Container "unsicher" und VMs "sicher" sind. Es bedeutet, das Sicherheitsmodell ist anders. Ein gut konfigurierter Container-Stack mit rootless execution, user namespaces, default seccomp, einem strikten capability-Satz, ohne Host-namespace-Sharing und mit starker SELinux- oder AppArmor-Enforcement kann sehr robust sein. Umgekehrt ist ein Container, der mit `--privileged` gestartet wurde, Host PID-/network-Sharing hat, die Docker socket darin gemountet ist und ein beschreibbares Bind-Mount von `/` besitzt, funktional viel näher an Host-root-Zugriff als an einer sicher isolierten Anwendungs-Sandbox. Der Unterschied ergibt sich aus den Schichten, die aktiviert oder deaktiviert wurden.

Es gibt auch ein Mittelfeld, das Leser verstehen sollten, weil es in realen Umgebungen immer häufiger vorkommt. Sandboxed container runtimes wie gVisor und Kata Containers härten die Grenze absichtlich weiter als ein klassischer `runc`-Container. gVisor legt eine Userspace-Kernel-Schicht zwischen die Workload und viele Host-Kernel-Schnittstellen, während Kata die Workload innerhalb einer leichtgewichtigen virtuellen Maschine startet. Diese werden weiterhin durch Container-Ökosysteme und Orchestrierungs-Workflows genutzt, aber ihre Sicherheits-Eigenschaften unterscheiden sich von einfachen OCI-Runtimes und sollten nicht gedanklich mit "normalen Docker-Containern" zusammengefasst werden, als ob alles gleich funktionieren würde.

## The Container Stack: Several Layers, Not One

Wenn jemand sagt "this container is insecure", ist die nützliche Anschlussfrage: **welche Schicht hat ihn unsicher gemacht?** Eine containerisierte Workload ist normalerweise das Ergebnis mehrerer zusammenarbeitender Komponenten.

Oben gibt es oft eine **image build layer** wie BuildKit, Buildah oder Kaniko, die das OCI-Image und die Metadaten erstellt. Über dem Low-Level-Runtime kann es einen **engine or manager** wie Docker Engine, Podman, containerd, CRI-O, Incus oder systemd-nspawn geben. In Cluster-Umgebungen kann auch ein **orchestrator** wie Kubernetes die angeforderte Sicherheitsposition durch Workload-Konfiguration entscheiden. Schließlich ist der **kernel** das, was tatsächlich namespaces, cgroups, seccomp und MAC-Policy durchsetzt.

Dieses geschichtete Modell ist wichtig, um Defaults zu verstehen. Eine Einschränkung kann von Kubernetes angefordert, durch CRI von containerd oder CRI-O übersetzt, vom Runtime-Wrapper in ein OCI-Spec konvertiert und erst dann von `runc`, `crun`, `runsc` oder einer anderen Runtime gegenüber dem Kernel durchgesetzt werden. Wenn Defaults zwischen Umgebungen unterschiedlich sind, liegt das oft daran, dass eine dieser Schichten die finale Konfiguration geändert hat. Derselbe Mechanismus kann daher in Docker oder Podman als CLI-Flag, in Kubernetes als Pod- oder `securityContext`-Feld und in niedrigeren Runtime-Stacks als für die Workload generierte OCI-Konfiguration erscheinen. Aus diesem Grund sollten CLI-Beispiele in diesem Abschnitt als **runtime-spezifische Syntax für ein allgemeines Container-Konzept** gelesen werden, nicht als universelle Flags, die jedes Tool unterstützt.

## The Real Container Security Boundary

In der Praxis ergibt Container-Sicherheit sich aus **überlappenden Kontrollen**, nicht aus einer einzigen perfekten Kontrolle. Namespaces isolieren Sichtbarkeit. cgroups steuern und begrenzen Ressourcenverbrauch. Capabilities reduzieren, was ein privilegiert aussehender Prozess tatsächlich tun kann. seccomp blockiert gefährliche syscalls, bevor sie den Kernel erreichen. AppArmor und SELinux fügen Mandatory Access Control zusätzlich zu normalen DAC-Prüfungen hinzu. `no_new_privs`, masked procfs-Pfade und read-only System-Pfade erschweren gebräuchliche Privilege- und proc/sys-Missbrauchsketten. Auch die Runtime selbst ist wichtig, weil sie entscheidet, wie mounts, sockets, Labels und namespace-joins erstellt werden.

Deshalb wirkt viel Container-Sicherheitsdokumentation repetitiv. Dieselbe Escape-Kette hängt oft von mehreren Mechanismen gleichzeitig ab. Zum Beispiel ist ein beschreibbares Host-Bind-Mount schlecht, aber es wird weitaus schlimmer, wenn der Container auch als echter root auf dem Host läuft, `CAP_SYS_ADMIN` besitzt, von seccomp unkonfiguriert ist und nicht durch SELinux oder AppArmor eingeschränkt wird. Ebenso ist Host-PID-Sharing eine ernsthafte Schwachstelle, aber es wird für einen Angreifer dramatisch nützlicher, wenn es mit `CAP_SYS_PTRACE`, schwachen procfs-Schutzmaßnahmen oder Namespace-Entry-Tools wie `nsenter` kombiniert wird. Der richtige Weg, das Thema zu dokumentieren, besteht daher nicht darin, denselben Angriff auf jeder Seite zu wiederholen, sondern zu erklären, was jede Schicht zur finalen Grenze beiträgt.

## How To Read This Section

Der Abschnitt ist von den allgemeinsten Konzepten zu den spezifischeren organisiert.

Beginnen Sie mit dem Runtime- und Ökosystem-Überblick:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Dann prüfen Sie die Control-Planes und Supply-Chain-Oberflächen, die häufig entscheiden, ob ein Angreifer überhaupt einen Kernel-Escape benötigt:

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

Dann gehen Sie in das Schutzmodell:

{{#ref}}
protections/
{{#endref}}

Die Namespace-Seiten erklären die Kernel-Isolationsprimitiven einzeln:

{{#ref}}
protections/namespaces/
{{#endref}}

Die Seiten zu cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths und read-only paths erklären die Mechanismen, die normalerweise auf Namespaces aufgeschichtet werden:

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

## A Good First Enumeration Mindset

Bei der Bewertung eines containerisierten Ziels ist es weitaus nützlicher, eine kleine Anzahl präziser technischer Fragen zu stellen, als sofort zu bekannten Escape-PoCs zu springen. Identifizieren Sie zuerst den **Stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer oder etwas Spezielleres. Dann identifizieren Sie die **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` oder eine andere OCI-kompatible Implementation. Danach prüfen Sie, ob die Umgebung **rootful oder rootless** ist, ob **user namespaces** aktiv sind, ob irgendwelche **host namespaces** geteilt werden, welche **capabilities** verbleiben, ob **seccomp** aktiviert ist, ob eine **MAC-Policy** tatsächlich durchsetzt, ob **gefährliche mounts oder sockets** vorhanden sind und ob der Prozess mit der container runtime API interagieren kann.

Diese Antworten sagen Ihnen viel mehr über die tatsächliche Sicherheitslage als der Basis-Image-Name. In vielen Bewertungen können Sie die wahrscheinliche Escape-Familie vorhersagen, noch bevor Sie eine einzige Anwendungsdatei gelesen haben, allein durch das Verständnis der finalen Container-Konfiguration.

## Coverage

Dieser Abschnitt behandelt das alte Docker-fokussierte Material unter container-orientierter Organisation: runtime- und daemon-exposure, authorization plugins, image trust und build secrets, sensitive host mounts, distroless Workloads, privileged containers und die Kernel-Schutzmechanismen, die normalerweise um die Container-Ausführung geschichtet sind.
