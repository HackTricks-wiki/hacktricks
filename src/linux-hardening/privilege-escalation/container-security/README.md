# Container-Sicherheit

{{#include ../../../banners/hacktricks-training.md}}

## Was ein Container tatsächlich ist

Eine praktische Definition eines Containers lautet so: Ein Container ist ein **normaler Linux-Prozessbaum**, der unter einer bestimmten OCI-style Konfiguration gestartet wurde, sodass er ein kontrolliertes Dateisystem, eine kontrollierte Menge an Kernel-Ressourcen und ein eingeschränktes Privilegmodell sieht. Der Prozess kann glauben, er sei PID 1, kann glauben, er habe seinen eigenen network stack, kann glauben, er besitze seinen eigenen hostname und IPC-Ressourcen, und kann sogar als root innerhalb seines eigenen user namespace laufen. Unter der Haube ist er jedoch weiterhin ein Host-Prozess, den der Kernel wie jeden anderen plant.

Deshalb ist container security in Wirklichkeit die Untersuchung, wie diese Illusion konstruiert wird und wie sie versagt. Wenn das mount namespace schwach ist, kann der Prozess das Host-Dateisystem sehen. Wenn der user namespace fehlt oder deaktiviert ist, kann root im Container zu eng an root auf dem Host gemappt sein. Wenn seccomp unkonfiguriert ist und der capability-Satz zu breit ist, kann der Prozess syscalls und privilegierte Kernel-Funktionen erreichen, die eigentlich unerreichbar bleiben sollten. Wenn der runtime socket innerhalb des Containers gemountet ist, braucht der Container möglicherweise gar keinen kernel breakout, weil er einfach den runtime fragen kann, einen mächtigeren sibling container zu starten oder das Host-Root-Dateisystem direkt zu mounten.

## Wie sich Container von Virtual Machines unterscheiden

Eine VM trägt normalerweise ihren eigenen Kernel und eine Hardware-Abstraktionsgrenze. Das bedeutet, dass der Guest-Kernel abstürzen, panicen oder exploitet werden kann, ohne automatisch direkte Kontrolle über den Host-Kernel zu implizieren. In Containern bekommt die Workload keinen separaten Kernel. Stattdessen erhält sie eine sorgfältig gefilterte und namespaced Sicht auf denselben Kernel, den der Host verwendet. Dadurch sind Container in der Regel leichter, schneller zu starten, einfacher dicht gepackt auf einer Maschine unterzubringen und besser für kurzlebige Anwendungsdeployments geeignet. Der Preis ist, dass die Isolationsgrenze viel direkter von korrekter Host- und Runtime-Konfiguration abhängt.

Das heißt nicht, dass Container "unsicher" und VMs "sicher" sind. Es bedeutet, dass das Sicherheitsmodell anders ist. Ein gut konfiguriertes Container-Stack mit rootless-Ausführung, user namespaces, default seccomp, einem strikten capability-Set, keiner Host-Namespace-Sharing und starker SELinux- oder AppArmor-Enforcement kann sehr robust sein. Umgekehrt ist ein Container, der mit `--privileged`, Host PID/network sharing, dem Docker socket darin gemountet und einem beschreibbaren bind mount von `/` gestartet wurde, funktional viel näher an Host-root-Zugang als an einer sicher isolierten Anwendungssandbox. Der Unterschied ergibt sich aus den aktivierten oder deaktivierten Schichten.

Es gibt auch einen Mittelweg, den Leser verstehen sollten, weil er in realen Umgebungen immer häufiger vorkommt. Sandboxed container runtimes wie gVisor und Kata Containers härten die Grenze bewusst über einen klassischen `runc` Container hinaus. gVisor legt eine Userspace-Kernel-Schicht zwischen die Workload und viele Host-Kernel-Interfaces, während Kata die Workload innerhalb einer leichten virtuellen Maschine startet. Diese werden weiterhin über Container-Ökosysteme und Orchestrierungs-Workflows genutzt, aber ihre Sicherheitseigenschaften unterscheiden sich von plain OCI runtimes und sollten nicht mental mit "normalen Docker-Containern" gleichgesetzt werden, als ob alles gleich funktionieren würde.

## Der Container-Stack: mehrere Schichten, nicht nur eine

Wenn jemand sagt "dieser Container ist unsicher", ist die nützliche Anschlussfrage: **welche Schicht hat ihn unsicher gemacht?** Eine containerisierte Workload ist normalerweise das Ergebnis mehrerer Komponenten, die zusammenarbeiten.

Oben gibt es oft eine **image build layer** wie BuildKit, Buildah oder Kaniko, die das OCI-Image und die Metadaten erstellt. Über dem low-level runtime kann es einen **engine oder manager** wie Docker Engine, Podman, containerd, CRI-O, Incus oder systemd-nspawn geben. In Cluster-Umgebungen kann außerdem ein **orchestrator** wie Kubernetes durch Workload-Konfiguration die gewünschte Sicherheitslage bestimmen. Schließlich ist der **Kernel** das, was tatsächlich namespaces, cgroups, seccomp und MAC-Policy durchsetzt.

Dieses geschichtete Modell ist wichtig, um Defaults zu verstehen. Eine Einschränkung kann von Kubernetes angefordert, durch CRI von containerd oder CRI-O übersetzt, in eine OCI spec vom runtime wrapper konvertiert und erst dann von `runc`, `crun`, `runsc` oder einem anderen runtime gegen den Kernel durchgesetzt werden. Wenn Defaults zwischen Umgebungen variieren, liegt das oft daran, dass eine dieser Schichten die finale Konfiguration verändert hat. Derselbe Mechanismus kann daher in Docker oder Podman als CLI-Flag erscheinen, in Kubernetes als Pod- oder `securityContext`-Feld und in niedrigeren Runtime-Stacks als für die Workload generierte OCI-Konfiguration. Aus diesem Grund sollten CLI-Beispiele in diesem Abschnitt als **runtime-spezifische Syntax für ein generelles Container-Konzept** gelesen werden, nicht als universelle Flags, die von jedem Tool unterstützt werden.

## Die echte Container-Sicherheitsgrenze

In der Praxis kommt container security von **überlappenden Kontrollen**, nicht von einer einzigen perfekten Kontrolle. Namespaces isolieren Sichtbarkeit. cgroups regeln und begrenzen Ressourcennutzung. Capabilities reduzieren, was ein privilegiert aussehender Prozess tatsächlich tun kann. seccomp blockiert gefährliche syscalls, bevor sie den Kernel erreichen. AppArmor und SELinux fügen Mandatory Access Control über normale DAC-Checks hinzu. `no_new_privs`, masked procfs paths und read-only system paths machen gebräuchliche Privilege- und proc/sys-Abuse-Ketten schwieriger. Auch der runtime selbst ist wichtig, weil er entscheidet, wie mounts, sockets, labels und namespace-joins erzeugt werden.

Deshalb wirkt viel Dokumentation zu container security repetitiv. Dieselbe Escape-Chain hängt oft von mehreren Mechanismen gleichzeitig ab. Zum Beispiel ist ein beschreibbares Host-bind-mount schlecht, aber es wird weitaus schlimmer, wenn der Container außerdem als real root auf dem Host läuft, `CAP_SYS_ADMIN` hat, unkonfiguriert von seccomp ist und nicht durch SELinux oder AppArmor eingeschränkt wird. Ebenso ist Host-PID-Sharing eine ernste Exposure, aber es wird für einen Angreifer dramatisch nützlicher, wenn es mit `CAP_SYS_PTRACE`, schwachen procfs-Schutzmaßnahmen oder Namespace-Eintritts-Tools wie `nsenter` kombiniert wird. Der richtige Weg, das Thema zu dokumentieren, ist daher nicht, denselben Angriff auf jeder Seite zu wiederholen, sondern zu erklären, was jede Schicht zum finalen Boundary beiträgt.

## Wie man diesen Abschnitt liest

Der Abschnitt ist von den allgemeinsten Konzepten zu den spezifischsten organisiert.

Beginnen Sie mit dem runtime- und Ökosystem-Überblick:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Dann überprüfen Sie die control planes und supply-chain-Oberflächen, die häufig entscheiden, ob ein Angreifer überhaupt einen kernel escape benötigt:

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

Dann wechseln Sie ins Schutzmodell:

{{#ref}}
protections/
{{#endref}}

Die Namespace-Seiten erklären die Kernel-Isolationsprimitiven einzeln:

{{#ref}}
protections/namespaces/
{{#endref}}

Die Seiten zu cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths und read-only paths erklären die Mechanismen, die normalerweise auf Namespaces aufgesetzt werden:

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

## Eine gute erste Enumeration-Mentalität

Bei der Bewertung eines containerisierten Ziels ist es viel nützlicher, eine kleine Menge präziser technischer Fragen zu stellen, als sofort zu berühmten escape PoCs zu springen. Identifizieren Sie zuerst den **Stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer oder etwas Spezielleres. Dann identifizieren Sie den **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` oder eine andere OCI-kompatible Implementierung. Danach prüfen Sie, ob die Umgebung **rootful oder rootless** ist, ob **user namespaces** aktiv sind, ob Host namespaces geteilt werden, welche **capabilities** verbleiben, ob **seccomp** aktiviert ist, ob eine **MAC policy** tatsächlich enforcing ist, ob **gefährliche mounts oder sockets** vorhanden sind und ob der Prozess mit der container runtime API interagieren kann.

Diese Antworten sagen viel mehr über die tatsächliche Sicherheitslage aus als der Name des Basis-Images je wird. In vielen Assessments können Sie die wahrscheinliche Breakout-Familie vorhersagen, bevor Sie eine einzige Anwendungsdatei gelesen haben, allein indem Sie die finale Container-Konfiguration verstehen.

## Coverage

Dieser Abschnitt deckt das alte Docker-fokussierte Material unter container-orientierter Organisation ab: runtime- und daemon-exposure, authorization plugins, image trust und build secrets, sensitive host mounts, distroless Workloads, privileged containers und die Kernel-Schutzmechanismen, die normalerweise um die Container-Ausführung geschichtet sind.
{{#include ../../../banners/hacktricks-training.md}}
