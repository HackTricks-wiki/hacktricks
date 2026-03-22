# Container-Sicherheit

{{#include ../../../banners/hacktricks-training.md}}

## Was ein Container eigentlich ist

Eine praktische Möglichkeit, einen Container zu definieren, ist diese: Ein Container ist ein regulärer Linux-Prozessbaum, der unter einer spezifischen OCI-ähnlichen Konfiguration gestartet wurde, sodass er ein kontrolliertes Dateisystem, eine kontrollierte Menge an Kernel-Ressourcen und ein eingeschränktes Privilegienmodell sieht. Der Prozess kann glauben, PID 1 zu sein, kann glauben, seinen eigenen Netzwerk-Stack zu haben, kann glauben, seinen eigenen Hostname- und IPC-Ressourcen zu besitzen und kann sogar als root innerhalb seines eigenen user namespace laufen. Unter der Haube ist er jedoch weiterhin ein Host-Prozess, den der Kernel wie jeden anderen plant.

Deshalb ist Container-Sicherheit im Grunde die Untersuchung, wie diese Illusion konstruiert wird und wie sie versagt. Wenn das mount namespace schwach ist, kann der Prozess das Host-Dateisystem sehen. Wenn der user namespace fehlt oder deaktiviert ist, kann root im Container zu stark mit root auf dem Host korrespondieren. Wenn seccomp unkonfiguriert ist und der capability set zu breit ist, kann der Prozess Syscalls und privilegierte Kernel-Funktionen erreichen, die außerhalb seiner Reichweite bleiben sollten. Wenn der runtime socket im Container gemountet ist, braucht der Container womöglich gar keinen Kernel-Breakout, weil er einfach den Runtime fragen kann, einen mächtigeren Geschwister-Container zu starten oder direkt das Host-Root-Dateisystem zu mounten.

## Wie sich Container von Virtual Machines unterscheiden

Eine VM trägt normalerweise ihren eigenen Kernel und eine Hardware-Abstraktionsgrenze. Das bedeutet, dass der Guest-Kernel abstürzen, panicen oder ausgenutzt werden kann, ohne automatisch die direkte Kontrolle über den Host-Kernel zu implizieren. Bei Containern erhält die Workload keinen separaten Kernel. Stattdessen bekommt sie eine sorgfältig gefilterte und namespacete Sicht auf denselben Kernel, den der Host benutzt. Infolgedessen sind Container in der Regel leichter, schneller zu starten, einfacher dicht auf einer Maschine zu packen und besser für kurzlebige Anwendungs-Deployments geeignet. Der Preis dafür ist, dass die Isolationsgrenze viel direkter von korrekter Host- und Runtime-Konfiguration abhängt.

Das bedeutet nicht, dass Container "unsicher" und VMs "sicher" sind. Es bedeutet, dass das Sicherheitsmodell anders ist. Ein gut konfigurierter Container-Stack mit rootless execution, user namespaces, default seccomp, einem strikten capability set, ohne Host-Namespace-Sharing und mit strikter SELinux- oder AppArmor-Durchsetzung kann sehr robust sein. Umgekehrt ist ein Container, der mit `--privileged` gestartet wurde, Host-PID/Netzwerk teilt, die Docker-Socket darin gemountet hat und ein beschreibbares Bind-Mount von `/` besitzt, funktional dem Host-root-Zugriff viel näher als einer sicher isolierten Anwendungssandbox. Der Unterschied ergibt sich aus den Schichten, die aktiviert oder deaktiviert wurden.

Es gibt auch ein Mittelfeld, das Leser verstehen sollten, weil es in realen Umgebungen immer häufiger vorkommt. Sandboxed container runtimes wie gVisor und Kata Containers härten die Grenze bewusst über einen klassischen `runc`-Container hinaus. gVisor platziert eine Userspace-Kernel-Schicht zwischen der Workload und vielen Host-Kernel-Schnittstellen, während Kata die Workload innerhalb einer leichtgewichtigen virtuellen Maschine startet. Diese werden weiterhin über Container-Ökosysteme und Orchestrierungs-Workflows verwendet, aber ihre Sicherheits-Eigenschaften unterscheiden sich von plain OCI runtimes und sollten nicht gedanklich mit "normalen Docker-Containern" zusammengefasst werden, als ob alles gleich funktionieren würde.

## Der Container-Stack: Mehrere Schichten, nicht eine

Wenn jemand sagt "dieser Container ist unsicher", ist die nützliche Anschlussfrage: Welche Schicht hat ihn unsicher gemacht? Eine containerisierte Workload ist normalerweise das Ergebnis mehrerer zusammenarbeitender Komponenten.

Ganz oben gibt es oft eine image build layer wie BuildKit, Buildah oder Kaniko, die das OCI-Image und die Metadaten erstellt. Über der low-level runtime kann es einen engine oder manager wie Docker Engine, Podman, containerd, CRI-O, Incus oder systemd-nspawn geben. In Cluster-Umgebungen gibt es möglicherweise auch einen orchestrator wie Kubernetes, der die gewünschte Security-Posture über Workload-Konfiguration entscheidet. Schließlich ist der Kernel das, was tatsächlich Namespaces, cgroups, seccomp und MAC-Policy durchsetzt.

Dieses geschichtete Modell ist wichtig, um Defaults zu verstehen. Eine Einschränkung kann von Kubernetes angefragt, über CRI von containerd oder CRI-O übersetzt, vom Runtime-Wrapper in eine OCI-Spezifikation konvertiert und erst dann von `runc`, `crun`, `runsc` oder einer anderen Runtime gegen den Kernel durchgesetzt werden. Wenn Defaults zwischen Umgebungen variieren, liegt es oft daran, dass eine dieser Schichten die finale Konfiguration verändert hat. Der gleiche Mechanismus kann daher in Docker oder Podman als CLI-Flag erscheinen, in Kubernetes als Pod- oder `securityContext`-Feld und in tieferliegenden Runtime-Stacks als für die Workload generierte OCI-Konfiguration. Aus diesem Grund sollten CLI-Beispiele in diesem Abschnitt als runtime-spezifische Syntax für ein allgemeines Container-Konzept gelesen werden, nicht als universelle Flags, die von jedem Tool unterstützt werden.

## Die echte Container-Sicherheitsgrenze

In der Praxis entsteht Container-Sicherheit durch überlappende Kontrollen, nicht durch eine einzelne perfekte Kontrolle. Namespaces isolieren Sichtbarkeit. cgroups regeln und begrenzen Ressourcennutzung. Capabilities reduzieren, was ein privilegiert wirkender Prozess tatsächlich tun darf. seccomp blockiert gefährliche syscalls, bevor sie den Kernel erreichen. AppArmor und SELinux fügen Mandatory Access Control oberhalb normaler DAC-Prüfungen hinzu. `no_new_privs`, masked procfs paths und read-only system paths machen gängige Privilege- und proc/sys-Missbrauchs-Ketten schwieriger. Auch die Runtime selbst ist wichtig, weil sie entscheidet, wie Mounts, Sockets, Labels und Namespace-Joins erstellt werden.

Deshalb wirkt viel Container-Sicherheitsdokumentation repetitiv. Dieselbe Escape-Kette hängt oft gleichzeitig von mehreren Mechanismen ab. Zum Beispiel ist ein beschreibbares Host-Bind-Mount schlecht, aber es wird deutlich schlimmer, wenn der Container auch als echter root auf dem Host läuft, `CAP_SYS_ADMIN` besitzt, unkonfiguriert von seccomp ist und nicht durch SELinux oder AppArmor eingeschränkt wird. Ebenso ist Host-PID-Sharing eine ernste Exposition, aber es wird für einen Angreifer dramatisch nützlicher, wenn es mit `CAP_SYS_PTRACE`, schwachen procfs-Schutzmechanismen oder Namespace-Entry-Tools wie `nsenter` kombiniert wird. Die richtige Art, das Thema zu dokumentieren, besteht daher nicht darin, denselben Angriff auf jeder Seite zu wiederholen, sondern zu erklären, was jede Schicht zur finalen Grenze beiträgt.

## Wie man diesen Abschnitt liest

Der Abschnitt ist von den allgemeinsten Konzepten zu den spezifischsten organisiert.

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

Gehen Sie dann zum Schutzmodell über:

{{#ref}}
protections/
{{#endref}}

Die Namespace-Seiten erklären die Kernel-Isolationsprimitiven einzeln:

{{#ref}}
protections/namespaces/
{{#endref}}

Die Seiten zu cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths und read-only system paths erklären die Mechanismen, die üblicherweise auf Namespaces geschichtet werden:

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

## Eine gute erste Enumerations-Mentalität

Bei der Bewertung eines containerisierten Ziels ist es viel nützlicher, eine kleine Menge präziser technischer Fragen zu stellen, als sofort zu berühmten Escape PoCs zu springen. Identifizieren Sie zuerst den Stack: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer oder etwas Spezielleres. Dann identifizieren Sie die Runtime: `runc`, `crun`, `runsc`, `kata-runtime` oder eine andere OCI-kompatible Implementierung. Danach prüfen Sie, ob die Umgebung rootful oder rootless ist, ob user namespaces aktiv sind, ob Host-Namespaces geteilt werden, welche capabilities verbleiben, ob seccomp aktiviert ist, ob eine MAC-Policy tatsächlich durchsetzt, ob gefährliche Mounts oder Sockets vorhanden sind und ob der Prozess mit der Container-Runtime-API interagieren kann.

Diese Antworten sagen weit mehr über die reale Sicherheitslage aus als der Basis-Image-Name. In vielen Assessments können Sie die vermutlich auftretende Breakout-Familie vorhersagen, bevor Sie eine einzige Anwendungsdatei gelesen haben, nur indem Sie die finale Container-Konfiguration verstehen.

## Abdeckung

Dieser Abschnitt behandelt das alte Docker-fokussierte Material unter container-orientierter Organisation: runtime- und daemon-exposure, authorization plugins, image trust und build secrets, sensitive host mounts, distroless Workloads, privileged containers und die Kernel-Schutzmechanismen, die normalerweise um die Container-Ausführung geschichtet werden.
{{#include ../../../banners/hacktricks-training.md}}
