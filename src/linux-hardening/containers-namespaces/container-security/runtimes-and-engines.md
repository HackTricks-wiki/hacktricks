# Container-Runtimes, Engines, Builder und Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Eine der größten Verwechslungsquellen in der Container-Security besteht darin, dass mehrere völlig unterschiedliche Komponenten oft unter demselben Begriff zusammengefasst werden. „Docker“ kann sich auf ein Image-Format, eine CLI, einen Daemon, ein Build-System, einen Runtime-Stack oder einfach allgemein auf das Konzept von Containern beziehen. Für Security-Arbeit ist diese Mehrdeutigkeit problematisch, weil unterschiedliche Schichten für unterschiedliche Schutzmechanismen verantwortlich sind. Ein durch ein fehlerhaftes Bind-Mount verursachter Breakout ist nicht dasselbe wie ein durch einen Low-Level-Runtime-Bug verursachter Breakout, und beides ist wiederum nicht dasselbe wie ein Fehler in einer Cluster-Policy von Kubernetes.

Diese Seite trennt das Ökosystem nach Rollen, damit der restliche Abschnitt präzise beschreiben kann, wo ein Schutzmechanismus oder eine Schwachstelle tatsächlich liegt.

## OCI als gemeinsame Sprache

Moderne Linux-Container-Stacks können oft miteinander interagieren, weil sie eine Reihe von OCI-Spezifikationen verwenden. Die **OCI Image Specification** beschreibt, wie Images und Layer dargestellt werden. Die **OCI Runtime Specification** beschreibt, wie die Runtime den Prozess starten soll, einschließlich Namespaces, Mounts, cgroups und Security-Einstellungen. Die **OCI Distribution Specification** standardisiert, wie Registries Inhalte bereitstellen.

Das ist wichtig, weil es erklärt, warum ein mit einem Tool erstelltes Container-Image häufig mit einem anderen ausgeführt werden kann und warum mehrere Engines dieselbe Low-Level-Runtime verwenden können. Es erklärt auch, warum sich das Security-Verhalten verschiedener Produkte ähnlich anfühlen kann: Viele von ihnen erstellen dieselbe OCI-Runtime-Konfiguration und übergeben sie an dieselbe kleine Auswahl von Runtimes.

## Low-Level-OCI-Runtimes

Die Low-Level-Runtime ist die Komponente, die der Kernel-Grenze am nächsten ist. Sie erstellt tatsächlich Namespaces, schreibt cgroup-Einstellungen, wendet Capabilities und seccomp-Filter an und führt schließlich `execve()` für den Container-Prozess aus. Wenn über „Container-Isolation“ auf mechanischer Ebene gesprochen wird, ist normalerweise diese Schicht gemeint, auch wenn dies nicht ausdrücklich gesagt wird.

### `runc`

`runc` ist die Referenz-OCI-Runtime und bleibt die bekannteste Implementierung. Sie wird umfassend unter Docker, containerd und in vielen Kubernetes-Deployments eingesetzt. Ein großer Teil der öffentlichen Forschung und des Exploitation-Materials richtet sich gegen `runc`-artige Umgebungen, einfach weil diese verbreitet sind und weil `runc` die Grundlage definiert, die viele Menschen vor Augen haben, wenn sie an einen Linux-Container denken. Das Verständnis von `runc` vermittelt daher ein solides mentales Modell für die klassische Container-Isolation.

### `crun`

`crun` ist eine weitere OCI-Runtime, die in C geschrieben ist und häufig in modernen Podman-Umgebungen verwendet wird. Sie wird oft für ihre gute cgroup-v2-Unterstützung, ihre starken Rootless-Eigenschaften und ihren geringeren Overhead gelobt. Aus Security-Perspektive ist nicht entscheidend, dass sie in einer anderen Sprache geschrieben ist, sondern dass sie dieselbe Rolle erfüllt: Sie ist die Komponente, die die OCI-Konfiguration in einen laufenden Prozessbaum unter dem Kernel umwandelt. Ein Rootless-Podman-Workflow wirkt häufig sicherer, nicht weil `crun` auf magische Weise alles behebt, sondern weil der umgebende Stack tendenziell stärker auf User-Namespaces und Least Privilege setzt.

### `runsc` von gVisor

`runsc` ist die von gVisor verwendete Runtime. Hier verändert sich die Grenze auf wesentliche Weise. Statt die meisten Syscalls auf die übliche Weise direkt an den Host-Kernel weiterzugeben, fügt gVisor eine Userspace-Kernel-Schicht ein, die große Teile des Linux-Interfaces emuliert oder vermittelt. Das Ergebnis ist kein normaler `runc`-Container mit einigen zusätzlichen Flags, sondern ein anderes Sandbox-Design, dessen Zweck darin besteht, die Angriffsfläche des Host-Kernels zu reduzieren. Kompatibilitäts- und Performance-Abwägungen sind Teil dieses Designs. Umgebungen mit `runsc` sollten daher anders dokumentiert werden als normale OCI-Runtime-Umgebungen.

### `kata-runtime`

Kata Containers verschieben die Grenze noch weiter, indem sie die Workload innerhalb einer leichtgewichtigen virtuellen Maschine starten. Administrativ kann dies weiterhin wie ein Container-Deployment aussehen, und Orchestrierungsschichten können es weiterhin entsprechend behandeln. Die zugrunde liegende Isolationsgrenze liegt jedoch näher an Virtualisierung als an einem klassischen Container mit gemeinsam genutztem Host-Kernel. Das macht Kata nützlich, wenn eine stärkere Tenant-Isolation gewünscht ist, ohne auf containerzentrierte Workflows zu verzichten.

## Engines und Container-Manager

Wenn die Low-Level-Runtime die Komponente ist, die direkt mit dem Kernel kommuniziert, ist die Engine oder der Manager die Komponente, mit der Benutzer und Operatoren normalerweise interagieren. Sie kümmert sich um Image-Pulls, Metadaten, Logs, Netzwerke, Volumes, Lifecycle-Operationen und die Bereitstellung von APIs. Diese Schicht ist besonders wichtig, weil viele reale Compromises hier stattfinden: Zugriff auf einen Runtime-Socket oder eine Daemon-API kann einem Host-Compromise gleichkommen, selbst wenn die Low-Level-Runtime selbst vollkommen fehlerfrei ist.

### Docker Engine

Docker Engine ist die bekannteste Container-Plattform für Entwickler und einer der Gründe, warum die Container-Terminologie so stark von Docker geprägt wurde. Der typische Pfad verläuft von der `docker`-CLI zu `dockerd`, das wiederum Low-Level-Komponenten wie `containerd` und eine OCI-Runtime koordiniert. Historisch wurden Docker-Deployments häufig **rootful** betrieben, weshalb der Zugriff auf den Docker-Socket ein sehr mächtiges Primitive darstellt. Deshalb konzentriert sich so viel praktisches Privilege-Escalation-Material auf `docker.sock`: Wenn ein Prozess `dockerd` anweisen kann, einen privilegierten Container zu erstellen, Host-Pfade zu mounten oder Host-Namespaces zu verwenden, benötigt er möglicherweise überhaupt keinen Kernel-Exploit.

### Podman

Podman wurde rund um ein stärker daemonloses Modell entwickelt. Operativ unterstützt dies die Vorstellung, dass Container lediglich Prozesse sind, die über standardmäßige Linux-Mechanismen und nicht über einen langlebigen privilegierten Daemon verwaltet werden. Podman bietet außerdem eine deutlich stärkere **Rootless**-Ausrichtung als die klassischen Docker-Deployments, mit denen viele Menschen zuerst vertraut wurden. Das macht Podman nicht automatisch sicher, verändert aber das Standard-Risikoprofil erheblich, insbesondere in Kombination mit User-Namespaces, SELinux und `crun`.

### containerd

containerd ist eine zentrale Runtime-Management-Komponente in vielen modernen Stacks. Sie wird unter Docker eingesetzt und ist außerdem eines der wichtigsten Kubernetes-Runtime-Backends. containerd stellt leistungsfähige APIs bereit, verwaltet Images und Snapshots und delegiert die endgültige Prozesserstellung an eine Low-Level-Runtime. Bei Security-Diskussionen über containerd sollte betont werden, dass der Zugriff auf den containerd-Socket oder auf `ctr`-/`nerdctl`-Funktionen genauso gefährlich sein kann wie der Zugriff auf die Docker-API, selbst wenn sich Interface und Workflow weniger „developer friendly“ anfühlen.

### CRI-O

CRI-O ist stärker fokussiert als Docker Engine. Statt eine universelle Developer-Plattform zu sein, wurde es rund um eine saubere Implementierung der Kubernetes Container Runtime Interface entwickelt. Dadurch ist es besonders in Kubernetes-Distributionen und SELinux-lastigen Ökosystemen wie OpenShift verbreitet. Aus Security-Perspektive ist dieser engere Fokus nützlich, weil er konzeptionelle Unübersichtlichkeit reduziert: CRI-O gehört eindeutig zur Schicht „Container für Kubernetes ausführen“ und ist keine Plattform für alles.

### Incus, LXD und LXC

Incus-/LXD-/LXC-Systeme sollten von Docker-artigen Application-Containern getrennt betrachtet werden, weil sie häufig als **System-Container** eingesetzt werden. Von einem System-Container wird normalerweise erwartet, dass er eher wie eine leichtgewichtige Maschine mit einem umfassenderen Userspace, dauerhaft laufenden Services, umfangreicherem Device-Zugriff und stärkerer Host-Integration wirkt. Die Isolationsmechanismen basieren weiterhin auf Kernel-Primitiven, aber die operativen Erwartungen sind andere. Fehlkonfigurationen sehen daher häufig weniger wie „fehlerhafte App-Container-Defaults“ und eher wie Fehler bei leichtgewichtiger Virtualisierung oder Host-Delegation aus.

### systemd-nspawn

systemd-nspawn nimmt eine interessante Position ein, weil es systemd-nativ und sehr nützlich für Tests, Debugging und den Betrieb von OS-ähnlichen Umgebungen ist. Es ist nicht die vorherrschende Cloud-native-Produktions-Runtime, taucht aber häufig genug in Labs und distro-orientierten Umgebungen auf, um erwähnt zu werden. Für Security-Analysen ist es eine weitere Erinnerung daran, dass sich der Begriff „Container“ über mehrere Ökosysteme und Betriebsmodelle erstreckt.

### Apptainer / Singularity

Apptainer (früher Singularity) ist in Forschungs- und HPC-Umgebungen verbreitet. Die Trust-Annahmen, der User-Workflow und das Ausführungsmodell unterscheiden sich deutlich von Docker-/Kubernetes-zentrierten Stacks. In diesen Umgebungen ist es insbesondere wichtig, Benutzern die Ausführung paketierter Workloads zu ermöglichen, ohne ihnen weitreichende privilegierte Rechte zur Container-Verwaltung zu geben. Wenn ein Reviewer annimmt, jede Container-Umgebung sei im Wesentlichen „Docker auf einem Server“, wird er diese Deployments grundlegend falsch verstehen.

## Build-Time-Tooling

Viele Security-Diskussionen behandeln nur die Runtime, aber Build-Time-Tooling ist ebenfalls relevant, weil es den Image-Inhalt, die Offenlegung von Build-Secrets und den Umfang des vertrauenswürdigen Kontexts bestimmt, der in das finale Artefakt eingebettet wird.

**BuildKit** und `docker buildx` sind moderne Build-Backends, die Funktionen wie Caching, Secret-Mounting, SSH-Forwarding und Multi-Platform-Builds unterstützen. Diese Funktionen sind nützlich, erzeugen aus Security-Perspektive aber auch Stellen, an denen Secrets in Image-Layer leaken können oder an denen ein zu breit gefasster Build-Kontext Dateien offenlegen kann, die niemals enthalten sein sollten. **Buildah** erfüllt eine ähnliche Rolle in OCI-nativen Ökosystemen, insbesondere rund um Podman, während **Kaniko** häufig in CI-Umgebungen eingesetzt wird, die dem Build-Pipeline keinen privilegierten Docker-Daemon zur Verfügung stellen möchten.

Die zentrale Erkenntnis ist, dass Image-Erstellung und Image-Ausführung unterschiedliche Phasen sind. Eine schwache Build-Pipeline kann jedoch lange vor dem Start des Containers eine schwache Runtime-Sicherheitslage erzeugen.

## Orchestrierung ist eine weitere Schicht, nicht die Runtime

Kubernetes sollte gedanklich nicht mit der Runtime selbst gleichgesetzt werden. Kubernetes ist der Orchestrator. Es plant Pods, speichert den gewünschten Zustand und formuliert Security-Policies über die Workload-Konfiguration. Der kubelet kommuniziert anschließend mit einer CRI-Implementierung wie containerd oder CRI-O, die wiederum eine Low-Level-Runtime wie `runc`, `crun`, `runsc` oder `kata-runtime aufruft.

Diese Trennung ist wichtig, weil viele Menschen einen Schutzmechanismus fälschlicherweise „Kubernetes“ zuschreiben, obwohl er tatsächlich von der Node-Runtime durchgesetzt wird. Oder sie machen „containerd-Defaults“ für ein Verhalten verantwortlich, das aus einer Pod-Spec stammt. In der Praxis ist die finale Security-Posture eine Zusammensetzung: Der Orchestrator fordert etwas an, der Runtime-Stack übersetzt diese Anforderung und der Kernel setzt sie schließlich durch.

## Warum die Identifizierung der Runtime bei Assessments wichtig ist

Wenn Engine und Runtime früh identifiziert werden, lassen sich viele spätere Beobachtungen leichter interpretieren. Ein Rootless-Podman-Container deutet darauf hin, dass User-Namespaces wahrscheinlich eine Rolle spielen. Ein in eine Workload gemounteter Docker-Socket deutet darauf hin, dass API-basierte Privilege Escalation ein realistischer Pfad ist. Ein CRI-O-/OpenShift-Node sollte sofort an SELinux-Labels und Restricted-Workload-Policies denken lassen. Eine gVisor- oder Kata-Umgebung sollte vorsichtiger machen, wenn angenommen wird, dass ein klassischer `runc`-Breakout-PoC sich dort genauso verhält.

Deshalb sollte einer der ersten Schritte bei einem Container-Assessment immer darin bestehen, zwei einfache Fragen zu beantworten: **Welche Komponente verwaltet den Container** und **welche Runtime hat den Prozess tatsächlich gestartet**? Sobald diese Antworten feststehen, lässt sich der Rest der Umgebung normalerweise deutlich leichter analysieren.

## Runtime-Schwachstellen

Nicht jeder Container-Escape entsteht durch eine Fehlkonfiguration des Operators. Manchmal ist die Runtime selbst die verwundbare Komponente. Das ist wichtig, weil eine Workload scheinbar mit einer sorgfältigen Konfiguration betrieben werden kann und trotzdem über einen Low-Level-Runtime-Fehler gefährdet ist.

Das klassische Beispiel ist **CVE-2019-5736** in `runc`, bei dem ein bösartiger Container die `runc`-Binary auf dem Host überschreiben konnte und anschließend auf einen späteren Aufruf von `docker exec` oder eine ähnliche Runtime-Invocation warten musste, um vom Angreifer kontrollierten Code auszuführen. Der Exploit-Pfad unterscheidet sich deutlich von einem einfachen Bind-Mount- oder Capability-Fehler, weil er ausnutzt, wie die Runtime beim Handling von `exec` erneut in den Prozessbereich des Containers eintritt.<sup>[[1]](#references)</sup>

Ein minimaler Reproduktions-Workflow aus Red-Team-Perspektive ist:
```bash
go build main.go
./main
```
Dann vom Host:
```bash
docker exec -it <container-name> /bin/sh
```
Die wichtigste Erkenntnis betrifft nicht die genaue historische Exploit-Implementierung, sondern die Bedeutung für die Bewertung: Wenn die Runtime-Version verwundbar ist, kann gewöhnliche Codeausführung innerhalb des Containers ausreichen, um den Host zu kompromittieren, selbst wenn die sichtbare Container-Konfiguration nicht offensichtlich schwach wirkt.

Aktuelle Runtime-CVEs wie `CVE-2024-21626` in `runc`, BuildKit-Mount-Races und Parsing-Bugs in containerd bekräftigen denselben Punkt. Runtime-Version und Patch-Stand sind Teil der Sicherheitsgrenze und nicht lediglich unbedeutende Wartungsdetails.

## References

- [1] [Aus Docker über runC ausbrechen – CVE-2019-5736 erklärt](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
