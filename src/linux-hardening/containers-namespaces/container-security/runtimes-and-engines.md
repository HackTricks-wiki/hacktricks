# Container-Runtimes, Engines, Builder und Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Eine der größten Verwirrungsquellen bei der Container-Sicherheit besteht darin, dass mehrere völlig unterschiedliche Komponenten häufig unter demselben Begriff zusammengefasst werden. „Docker“ kann sich auf ein Image-Format, eine CLI, einen Daemon, ein Build-System, einen Runtime-Stack oder einfach allgemein auf das Konzept von Containern beziehen. Für Security-Arbeiten ist diese Mehrdeutigkeit problematisch, da unterschiedliche Schichten für unterschiedliche Schutzmechanismen verantwortlich sind. Ein durch ein fehlerhaftes Bind-Mount verursachter Breakout ist nicht dasselbe wie ein durch einen Low-Level-Runtime-Bug verursachter Breakout, und beides ist wiederum nicht dasselbe wie ein Fehler in der Cluster-Policy von Kubernetes.

Diese Seite unterteilt das Ökosystem nach Rollen, damit im restlichen Abschnitt präzise beschrieben werden kann, wo ein Schutzmechanismus oder eine Schwachstelle tatsächlich angesiedelt ist.

## OCI als gemeinsame Sprache

Moderne Linux-Container-Stacks können häufig miteinander interagieren, weil sie eine Reihe von OCI-Spezifikationen verwenden. Die **OCI Image Specification** beschreibt, wie Images und Layer dargestellt werden. Die **OCI Runtime Specification** beschreibt, wie die Runtime den Prozess starten soll, einschließlich Namespaces, Mounts, cgroups und Security-Einstellungen. Die **OCI Distribution Specification** standardisiert, wie Registries Inhalte bereitstellen.

Das ist wichtig, weil es erklärt, warum ein mit einem Tool erstelltes Container-Image oft mit einem anderen Tool ausgeführt werden kann und warum mehrere Engines dieselbe Low-Level-Runtime verwenden können. Es erklärt auch, warum sich das Security-Verhalten verschiedener Produkte ähneln kann: Viele von ihnen erstellen dieselbe OCI-Runtime-Konfiguration und übergeben sie an dieselbe kleine Gruppe von Runtimes.

## Low-Level-OCI-Runtimes

Die Low-Level-Runtime ist die Komponente, die der Kernel-Grenze am nächsten ist. Sie erstellt tatsächlich Namespaces, schreibt cgroup-Einstellungen, wendet Capabilities und seccomp-Filter an und führt schließlich `execve()` für den Container-Prozess aus. Wenn über „Container-Isolation“ auf der technischen Ebene gesprochen wird, ist normalerweise diese Schicht gemeint, auch wenn das nicht ausdrücklich gesagt wird.

### `runc`

`runc` ist die Referenz-OCI-Runtime und nach wie vor die bekannteste Implementierung. Sie wird häufig unter Docker, containerd und in vielen Kubernetes-Deployments eingesetzt. Ein großer Teil der öffentlichen Forschung und des Exploit-Materials zielt auf `runc`-ähnliche Umgebungen ab, einfach weil diese weit verbreitet sind und `runc` die Grundlage definiert, die viele Menschen vor Augen haben, wenn sie sich einen Linux-Container vorstellen. Das Verständnis von `runc` vermittelt daher ein solides mentales Modell für klassische Container-Isolation.

### `crun`

`crun` ist eine weitere OCI-Runtime, die in C geschrieben ist und häufig in modernen Podman-Umgebungen eingesetzt wird. Sie wird oft für gute cgroup-v2-Unterstützung, eine starke Rootless-Erfahrung und einen geringeren Overhead gelobt. Aus Security-Sicht ist nicht entscheidend, dass sie in einer anderen Sprache geschrieben ist, sondern dass sie weiterhin dieselbe Rolle erfüllt: Sie wandelt die OCI-Konfiguration in einen laufenden Prozessbaum unter dem Kernel um. Ein Rootless-Podman-Workflow wirkt häufig nicht deshalb sicherer, weil `crun` auf magische Weise alles behebt, sondern weil der umgebende Stack tendenziell stärker auf User-Namespaces und Least Privilege setzt.

### `runsc` aus gVisor

`runsc` ist die von gVisor verwendete Runtime. Hier verändert sich die Bedeutung der Grenze grundlegend. Anstatt die meisten Syscalls wie üblich direkt an den Host-Kernel weiterzugeben, fügt gVisor eine Userspace-Kernel-Schicht ein, die große Teile des Linux-Interfaces emuliert oder vermittelt. Das Ergebnis ist kein normaler `runc`-Container mit einigen zusätzlichen Flags, sondern ein anderes Sandbox-Design, dessen Zweck darin besteht, die Angriffsfläche des Host-Kernels zu reduzieren. Kompatibilitäts- und Performance-Trade-offs sind Teil dieses Designs. Umgebungen mit `runsc` sollten daher anders dokumentiert werden als normale OCI-Runtime-Umgebungen.

### `kata-runtime`

Kata Containers verschieben die Grenze noch weiter, indem sie die Workload innerhalb einer Lightweight Virtual Machine starten. Administrativ kann dies weiterhin wie ein Container-Deployment aussehen, und Orchestration-Layer können es weiterhin entsprechend behandeln. Die zugrunde liegende Isolationsgrenze liegt jedoch näher an Virtualisierung als an einem klassischen Container mit gemeinsam genutztem Host-Kernel. Dadurch ist Kata nützlich, wenn eine stärkere Tenant-Isolation gewünscht wird, ohne auf Container-zentrierte Workflows zu verzichten.

## Engines und Container-Manager

Wenn die Low-Level-Runtime direkt mit dem Kernel kommuniziert, ist die Engine oder der Manager die Komponente, mit der Benutzer und Operatoren normalerweise interagieren. Sie kümmert sich um Image-Pulls, Metadaten, Logs, Netzwerke, Volumes, Lifecycle-Operationen und die Bereitstellung von APIs. Diese Schicht ist besonders wichtig, da viele reale Compromises hier stattfinden: Zugriff auf einen Runtime-Socket oder eine Daemon-API kann einem Host-Compromise gleichkommen, selbst wenn die Low-Level-Runtime selbst völlig fehlerfrei ist.

### Docker Engine

Docker Engine ist die bekannteste Container-Plattform für Entwickler und einer der Gründe dafür, dass die Container-Terminologie so stark von Docker geprägt wurde. Der typische Pfad führt von der `docker` CLI zu `dockerd`, das wiederum Low-Level-Komponenten wie `containerd` und eine OCI-Runtime koordiniert. Historisch waren Docker-Deployments häufig **rootful**, weshalb der Zugriff auf den Docker-Socket ein äußerst mächtiges Primitive darstellt. Deshalb konzentriert sich viel praktisches Privilege-Escalation-Material auf `docker.sock`: Wenn ein Prozess `dockerd` anweisen kann, einen privilegierten Container zu erstellen, Host-Pfade zu mounten oder Host-Namespaces beizutreten, benötigt er möglicherweise überhaupt keinen Kernel-Exploit.

### Podman

Podman wurde auf Basis eines stärker daemonlosen Modells entwickelt. Das unterstützt die Vorstellung, dass Container lediglich Prozesse sind, die über standardmäßige Linux-Mechanismen verwaltet werden, anstatt über einen einzigen dauerhaft laufenden privilegierten Daemon. Podman bietet außerdem eine deutlich stärkere **Rootless**-Unterstützung als die klassischen Docker-Deployments, mit denen viele Menschen zuerst gearbeitet haben. Das macht Podman nicht automatisch sicher, verändert das standardmäßige Risikoprofil jedoch erheblich, insbesondere in Kombination mit User-Namespaces, SELinux und `crun`.

### containerd

containerd ist in vielen modernen Stacks eine zentrale Runtime-Management-Komponente. Sie wird unter Docker eingesetzt und ist außerdem eines der wichtigsten Kubernetes-Runtime-Backends. Sie stellt leistungsfähige APIs bereit, verwaltet Images und Snapshots und delegiert die endgültige Prozesserstellung an eine Low-Level-Runtime. Bei Security-Diskussionen über containerd sollte betont werden, dass der Zugriff auf den containerd-Socket oder auf `ctr`-/`nerdctl`-Funktionen genauso gefährlich sein kann wie der Zugriff auf die Docker-API, selbst wenn sich Interface und Workflow weniger „developer-friendly“ anfühlen.

### CRI-O

CRI-O ist stärker fokussiert als Docker Engine. Statt eine allgemeine Entwicklerplattform zu sein, wurde es entwickelt, um das Kubernetes Container Runtime Interface möglichst sauber zu implementieren. Dadurch ist es besonders in Kubernetes-Distributionen und SELinux-lastigen Ökosystemen wie OpenShift verbreitet. Aus Security-Sicht ist dieser begrenztere Umfang nützlich, da er konzeptionelle Unübersichtlichkeit reduziert: CRI-O gehört eindeutig zur Schicht „Container für Kubernetes ausführen“ und ist keine All-in-one-Plattform.

### Incus, LXD und LXC

Incus-/LXD-/LXC-Systeme sollten von Docker-ähnlichen Application-Containern getrennt betrachtet werden, da sie häufig als **System-Container** verwendet werden. Von einem System-Container wird normalerweise erwartet, dass er eher wie eine Lightweight Machine mit einem vollständigeren Userspace, dauerhaft laufenden Services, umfangreicherem Device-Exposure und stärkerer Host-Integration wirkt. Die Isolationsmechanismen basieren weiterhin auf Kernel-Primitiven, aber die betrieblichen Erwartungen sind andere. Fehlkonfigurationen sehen daher häufig weniger wie „fehlerhafte App-Container-Defaults“ und eher wie Fehler bei Lightweight Virtualization oder Host-Delegation aus.

### systemd-nspawn

systemd-nspawn nimmt eine interessante Position ein, da es systemd-nativ und sehr nützlich für Tests, Debugging und das Ausführen OS-ähnlicher Umgebungen ist. Es ist nicht die vorherrschende cloud-native Production-Runtime, taucht aber häufig genug in Labs und distro-orientierten Umgebungen auf, um erwähnt zu werden. Für Security-Analysen ist es eine weitere Erinnerung daran, dass der Begriff „Container“ mehrere Ökosysteme und Betriebsmodelle umfasst.

### Apptainer / Singularity

Apptainer (früher Singularity) ist in Forschungs- und HPC-Umgebungen weit verbreitet. Die Trust-Assumptions, der User-Workflow und das Execution-Modell unterscheiden sich in wichtigen Punkten von Docker-/Kubernetes-zentrierten Stacks. Insbesondere ist es in diesen Umgebungen oft besonders wichtig, Benutzern das Ausführen paketierter Workloads zu ermöglichen, ohne ihnen weitreichende privilegierte Container-Management-Rechte zu geben. Wenn ein Reviewer annimmt, jede Container-Umgebung sei im Wesentlichen „Docker auf einem Server“, wird er diese Deployments grundlegend falsch verstehen.

## Build-Time-Tooling

Viele Security-Diskussionen behandeln ausschließlich die Runtime. Build-Time-Tooling ist jedoch ebenfalls wichtig, da es den Image-Inhalt, die Exposure von Build-Secrets und den Umfang des vertrauenswürdigen Kontexts bestimmt, der in das finale Artefakt eingebettet wird.

**BuildKit** und `docker buildx` sind moderne Build-Backends, die Funktionen wie Caching, Secret-Mounting, SSH-Forwarding und Multi-Platform-Builds unterstützen. Diese Funktionen sind nützlich, schaffen aus Security-Sicht jedoch auch Stellen, an denen Secrets in Image-Layern leaken können oder an denen ein zu weit gefasster Build-Kontext Dateien offenlegt, die niemals enthalten sein sollten. **Buildah** erfüllt eine ähnliche Rolle in OCI-nativen Ökosystemen, insbesondere rund um Podman, während **Kaniko** häufig in CI-Umgebungen eingesetzt wird, die dem Build-Pipeline keinen privilegierten Docker-Daemon geben möchten.

Die zentrale Erkenntnis ist, dass Image-Erstellung und Image-Ausführung unterschiedliche Phasen sind. Eine schwache Build-Pipeline kann jedoch die Runtime-Sicherheitslage bereits erheblich schwächen, lange bevor der Container gestartet wird.

## Orchestration ist eine weitere Schicht und nicht die Runtime

Kubernetes sollte nicht gedanklich mit der Runtime gleichgesetzt werden. Kubernetes ist der Orchestrator. Es plant Pods, speichert den gewünschten Zustand und definiert Security-Policies über die Workload-Konfiguration. Der kubelet kommuniziert anschließend mit einer CRI-Implementierung wie containerd oder CRI-O, die wiederum eine Low-Level-Runtime wie `runc`, `crun`, `runsc` oder `kata-runtime` aufruft.

Diese Trennung ist wichtig, weil viele Menschen einen Schutzmechanismus fälschlicherweise „Kubernetes“ zuschreiben, obwohl er tatsächlich von der Node-Runtime erzwungen wird, oder „containerd-Defaults“ für ein Verhalten verantwortlich machen, das aus einer Pod-Spec stammt. In der Praxis ist die finale Security-Posture eine Zusammensetzung: Der Orchestrator fordert etwas an, der Runtime-Stack übersetzt diese Anforderung, und der Kernel erzwingt sie schließlich.

## Warum die Identifizierung der Runtime bei Assessments wichtig ist

Wenn Engine und Runtime früh identifiziert werden, lassen sich viele spätere Beobachtungen leichter interpretieren. Ein Rootless-Podman-Container deutet darauf hin, dass User-Namespaces wahrscheinlich eine Rolle spielen. Ein in eine Workload gemounteter Docker-Socket deutet darauf hin, dass API-basierte Privilege Escalation ein realistischer Pfad ist. Ein CRI-O-/OpenShift-Node sollte sofort an SELinux-Labels und eine restriktive Workload-Policy denken lassen. Eine gVisor- oder Kata-Umgebung sollte vorsichtiger machen, wenn angenommen wird, dass ein klassischer `runc`-Breakout-PoC dort identisch funktioniert.

Deshalb sollte einer der ersten Schritte bei einem Container-Assessment immer darin bestehen, zwei einfache Fragen zu beantworten: **Welche Komponente verwaltet den Container** und **welche Runtime hat den Prozess tatsächlich gestartet**? Sobald diese Antworten klar sind, lässt sich der Rest der Umgebung normalerweise deutlich leichter nachvollziehen.

## Runtime Vulnerabilities

Nicht jeder Container-Escape ist auf eine Fehlkonfiguration durch Operatoren zurückzuführen. Manchmal ist die Runtime selbst die verwundbare Komponente. Das ist wichtig, weil eine Workload scheinbar mit einer sorgfältigen Konfiguration laufen und dennoch über einen Low-Level-Runtime-Fehler exponiert sein kann.

Das klassische Beispiel ist **CVE-2019-5736** in `runc`. Dabei konnte ein bösartiger Container die `runc`-Binary auf dem Host überschreiben und anschließend auf ein späteres `docker exec` oder einen ähnlichen Runtime-Aufruf warten, um attacker-controlled Code auszuführen. Der Exploit-Pfad unterscheidet sich deutlich von einem einfachen Bind-Mount- oder Capability-Fehler, da er die Art und Weise ausnutzt, wie die Runtime bei der Verarbeitung von exec erneut in den Prozessbereich des Containers eintritt.

Ein minimaler Reproduction-Workflow aus Red-Team-Perspektive lautet:
```bash
go build main.go
./main
```
Dann vom Host:
```bash
docker exec -it <container-name> /bin/sh
```
Die zentrale Erkenntnis ist nicht die genaue historische Implementierung des Exploits, sondern die Auswirkung auf die Bewertung: Wenn die Runtime-Version verwundbar ist, kann gewöhnliche Codeausführung innerhalb des Containers ausreichen, um den Host zu kompromittieren, selbst wenn die sichtbare Container-Konfiguration nicht offensichtlich schwach wirkt.

Neuere Runtime-CVEs wie `CVE-2024-21626` in `runc`, BuildKit-Mount-Races und Parsing-Bugs in containerd unterstreichen denselben Punkt. Runtime-Version und Patchstand sind Teil der Sicherheitsgrenze und nicht lediglich Wartungsdetails.
{{#include ../../../banners/hacktricks-training.md}}
