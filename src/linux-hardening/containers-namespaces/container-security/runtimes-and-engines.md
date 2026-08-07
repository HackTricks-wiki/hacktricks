# Container-Runtimes, Engines, Builder und Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Eine der größten Verwechslungsquellen bei der Container-Sicherheit besteht darin, dass mehrere völlig unterschiedliche Komponenten häufig unter demselben Begriff zusammengefasst werden. „Docker“ kann sich auf ein Image-Format, eine CLI, einen Daemon, ein Build-System, einen Runtime-Stack oder einfach allgemein auf das Konzept von Containern beziehen. Für Sicherheitsarbeit ist diese Mehrdeutigkeit problematisch, da unterschiedliche Ebenen für unterschiedliche Schutzmechanismen verantwortlich sind. Ein Breakout, der durch ein fehlerhaftes Bind-Mount verursacht wird, ist nicht dasselbe wie ein Breakout durch einen Fehler in der Low-Level-Runtime, und beides ist wiederum nicht dasselbe wie ein Fehler in einer Cluster-Richtlinie von Kubernetes.

Diese Seite unterteilt das Ökosystem nach Rollen, damit im restlichen Abschnitt präzise beschrieben werden kann, wo ein Schutzmechanismus oder eine Schwachstelle tatsächlich liegt.

## OCI als gemeinsame Sprache

Moderne Linux-Container-Stacks können häufig miteinander interagieren, weil sie eine Reihe von OCI-Spezifikationen verwenden. Die **OCI Image Specification** beschreibt, wie Images und Layer dargestellt werden. Die **OCI Runtime Specification** beschreibt, wie die Runtime den Prozess starten soll, einschließlich Namespaces, Mounts, cgroups und Sicherheitseinstellungen. Die **OCI Distribution Specification** standardisiert, wie Registries Inhalte bereitstellen.

Das ist relevant, weil es erklärt, warum ein mit einem Tool erstelltes Container-Image häufig mit einem anderen ausgeführt werden kann und warum mehrere Engines dieselbe Low-Level-Runtime verwenden können. Es erklärt auch, warum sich das Sicherheitsverhalten verschiedener Produkte ähnlich anfühlen kann: Viele von ihnen erstellen dieselbe OCI-Runtime-Konfiguration und übergeben sie an dieselbe kleine Gruppe von Runtimes.

## Low-Level-OCI-Runtimes

Die Low-Level-Runtime ist die Komponente, die sich am nächsten an der Kernel-Grenze befindet. Sie erstellt tatsächlich Namespaces, schreibt cgroup-Einstellungen, wendet Capabilities und seccomp-Filter an und führt schließlich `execve()` für den Container-Prozess aus. Wenn über „Container-Isolation“ auf mechanischer Ebene gesprochen wird, ist normalerweise diese Ebene gemeint, auch wenn dies nicht ausdrücklich gesagt wird.

### `runc`

`runc` ist die Referenz-OCI-Runtime und bleibt die bekannteste Implementierung. Sie wird häufig unter Docker, containerd und vielen Kubernetes-Deployments eingesetzt. Ein großer Teil der öffentlichen Forschung und des Exploit-Materials zielt auf `runc`-ähnliche Umgebungen ab, schlicht weil diese weit verbreitet sind und `runc` die Grundlage definiert, die sich viele Menschen unter einem Linux-Container vorstellen. Das Verständnis von `runc` vermittelt daher ein gutes mentales Modell für die klassische Container-Isolation.

### `crun`

`crun` ist eine weitere OCI-Runtime, die in C geschrieben ist und häufig in modernen Podman-Umgebungen eingesetzt wird. Sie wird oft für gute cgroup-v2-Unterstützung, eine starke Rootless-Erfahrung und einen geringeren Overhead gelobt. Aus Sicherheitsperspektive ist nicht entscheidend, dass sie in einer anderen Sprache geschrieben ist, sondern dass sie weiterhin dieselbe Rolle erfüllt: Sie wandelt die OCI-Konfiguration in einen laufenden Prozessbaum unter dem Kernel um. Ein Rootless-Podman-Workflow wirkt häufig deshalb sicherer, weil `crun` nicht auf magische Weise alles behebt, sondern weil der umgebende Stack tendenziell stärker auf User-Namespaces und Least Privilege setzt.

### `runsc` von gVisor

`runsc` ist die von gVisor verwendete Runtime. Hier verändert sich die Bedeutung der Grenze grundlegend. Anstatt die meisten Syscalls auf übliche Weise direkt an den Host-Kernel weiterzuleiten, fügt gVisor eine Userspace-Kernel-Schicht ein, die große Teile der Linux-Schnittstelle emuliert oder vermittelt. Das Ergebnis ist kein normaler `runc`-Container mit einigen zusätzlichen Flags, sondern ein anderes Sandbox-Design, dessen Zweck darin besteht, die Angriffsfläche des Host-Kernels zu reduzieren. Kompatibilitäts- und Performance-Abwägungen sind Teil dieses Designs. Umgebungen mit `runsc` sollten daher anders dokumentiert werden als normale OCI-Runtime-Umgebungen.

### `kata-runtime`

Kata Containers verschieben die Grenze noch weiter, indem sie die Workload innerhalb einer leichtgewichtigen virtuellen Maschine starten. Administrativ kann dies weiterhin wie ein Container-Deployment aussehen, und Orchestrierungsebenen können es weiterhin entsprechend behandeln. Die zugrunde liegende Isolationsgrenze liegt jedoch näher an Virtualisierung als an einem klassischen Container mit gemeinsam genutztem Host-Kernel. Dadurch ist Kata nützlich, wenn eine stärkere Tenant-Isolation gewünscht wird, ohne auf containerzentrierte Workflows zu verzichten.

## Engines und Container-Manager

Wenn die Low-Level-Runtime die Komponente ist, die direkt mit dem Kernel kommuniziert, ist die Engine oder der Manager die Komponente, mit der Benutzer und Operatoren normalerweise interagieren. Sie verwaltet Image-Pulls, Metadaten, Logs, Netzwerke, Volumes, Lifecycle-Operationen und die API-Bereitstellung. Diese Ebene ist besonders wichtig, da viele reale Kompromittierungen hier stattfinden: Zugriff auf einen Runtime-Socket oder eine Daemon-API kann einer Kompromittierung des Hosts gleichkommen, selbst wenn die Low-Level-Runtime selbst einwandfrei funktioniert.

### Docker Engine

Docker Engine ist die bekannteste Container-Plattform für Entwickler und einer der Gründe, warum die Container-Terminologie so stark von Docker geprägt wurde. Der typische Weg führt von der `docker`-CLI zu `dockerd`, der wiederum niedrigere Komponenten wie `containerd` und eine OCI-Runtime koordiniert. Historisch waren Docker-Deployments häufig **rootful**, weshalb der Zugriff auf den Docker-Socket ein äußerst mächtiges Primitiv darstellte. Aus diesem Grund konzentriert sich viel praktisches Privilege-Escalation-Material auf `docker.sock`: Wenn ein Prozess `dockerd` dazu auffordern kann, einen privilegierten Container zu erstellen, Host-Pfade einzubinden oder Host-Namespaces zu verwenden, ist möglicherweise überhaupt kein Kernel-Exploit erforderlich.

### Podman

Podman wurde rund um ein stärker daemonloses Modell entwickelt. Dies unterstützt die Vorstellung, dass Container lediglich Prozesse sind, die über standardmäßige Linux-Mechanismen und nicht über einen dauerhaft laufenden privilegierten Daemon verwaltet werden. Außerdem bietet Podman eine deutlich bessere **Rootless**-Unterstützung als die klassischen Docker-Deployments, mit denen viele Menschen zuerst vertraut wurden. Das macht Podman nicht automatisch sicher, verändert aber das standardmäßige Risikoprofil erheblich, insbesondere in Kombination mit User-Namespaces, SELinux und `crun`.

### containerd

containerd ist eine zentrale Runtime-Management-Komponente in vielen modernen Stacks. Sie wird unter Docker eingesetzt und ist außerdem eines der führenden Kubernetes-Runtime-Backends. Sie stellt leistungsfähige APIs bereit, verwaltet Images und Snapshots und delegiert die endgültige Prozesserstellung an eine Low-Level-Runtime. Sicherheitsdiskussionen zu containerd sollten hervorheben, dass der Zugriff auf den containerd-Socket oder auf `ctr`-/`nerdctl`-Funktionen genauso gefährlich sein kann wie der Zugriff auf die Docker-API, auch wenn sich die Schnittstelle und der Workflow weniger „entwicklerfreundlich“ anfühlen.

### CRI-O

CRI-O ist stärker spezialisiert als Docker Engine. Statt eine allgemeine Entwicklerplattform zu sein, wurde es darauf ausgelegt, die Kubernetes Container Runtime Interface sauber zu implementieren. Dadurch ist es besonders in Kubernetes-Distributionen und SELinux-lastigen Ökosystemen wie OpenShift verbreitet. Aus Sicherheitsperspektive ist dieser engere Fokus nützlich, da er konzeptionelle Unübersichtlichkeit reduziert: CRI-O gehört eindeutig zur Ebene „Container für Kubernetes ausführen“ und ist keine Plattform für alle möglichen Zwecke.

### Incus, LXD und LXC

Incus-/LXD-/LXC-Systeme sollten von Docker-ähnlichen Application-Containern getrennt betrachtet werden, da sie häufig als **System-Container** eingesetzt werden. Von einem System-Container wird normalerweise erwartet, dass er eher wie eine leichtgewichtige Maschine mit einem umfangreicheren Userspace, dauerhaft laufenden Services, umfangreicherem Gerätezugriff und stärkerer Host-Integration wirkt. Die Isolationsmechanismen basieren weiterhin auf Kernel-Primitiven, die betrieblichen Erwartungen sind jedoch andere. Fehlkonfigurationen sehen hier daher häufig weniger wie „fehlerhafte Standardwerte für App-Container“ und eher wie Fehler bei leichtgewichtiger Virtualisierung oder Host-Delegation aus.

### systemd-nspawn

systemd-nspawn nimmt eine interessante Position ein, da es systemd-nativ und für Tests, Debugging sowie das Ausführen von Betriebssystem-ähnlichen Umgebungen sehr nützlich ist. Es ist nicht die vorherrschende cloud-native Produktions-Runtime, kommt aber häufig genug in Labs und distributionsorientierten Umgebungen vor, um erwähnt zu werden. Für Sicherheitsanalysen ist es eine weitere Erinnerung daran, dass sich das Konzept „Container“ über mehrere Ökosysteme und Betriebsstile erstreckt.

### Apptainer / Singularity

Apptainer (früher Singularity) ist in Forschungs- und HPC-Umgebungen weit verbreitet. Die Vertrauensannahmen, der Benutzer-Workflow und das Ausführungsmodell unterscheiden sich in wichtigen Punkten von Docker-/Kubernetes-zentrierten Stacks. Insbesondere ist es in diesen Umgebungen häufig wichtig, Benutzern die Ausführung paketierter Workloads zu ermöglichen, ohne ihnen weitreichende privilegierte Berechtigungen für das Container-Management zu geben. Wer davon ausgeht, dass jede Container-Umgebung im Grunde „Docker auf einem Server“ ist, wird diese Deployments grundlegend falsch verstehen.

## Build-Time-Tooling

Viele Sicherheitsdiskussionen befassen sich ausschließlich mit der Laufzeit. Build-Time-Tooling ist jedoch ebenfalls relevant, da es den Inhalt von Images, die Offenlegung von Build-Secrets und den Umfang des vertrauenswürdigen Kontexts bestimmt, der in das finale Artefakt eingebettet wird.

**BuildKit** und `docker buildx` sind moderne Build-Backends, die Funktionen wie Caching, Secret-Mounts, SSH-Weiterleitung und Multi-Platform-Builds unterstützen. Diese Funktionen sind nützlich, schaffen aus Sicherheitsperspektive aber auch Stellen, an denen Secrets in Image-Layer leaken können oder ein zu umfangreicher Build-Kontext Dateien offenlegt, die niemals hätten einbezogen werden dürfen. **Buildah** erfüllt eine ähnliche Rolle in OCI-nativen Ökosystemen, insbesondere rund um Podman, während **Kaniko** häufig in CI-Umgebungen eingesetzt wird, die dem Build-Pipeline keinen privilegierten Docker-Daemon zur Verfügung stellen möchten.

Die zentrale Erkenntnis ist, dass Image-Erstellung und Image-Ausführung unterschiedliche Phasen sind. Eine schwache Build-Pipeline kann jedoch bereits lange vor dem Start des Containers eine schwache Runtime-Sicherheitslage erzeugen.

## Orchestrierung ist eine weitere Ebene, nicht die Runtime

Kubernetes sollte nicht gedanklich mit der Runtime gleichgesetzt werden. Kubernetes ist der Orchestrator. Es plant Pods, speichert den gewünschten Zustand und formuliert Sicherheitsrichtlinien über die Workload-Konfiguration. Der kubelet kommuniziert anschließend mit einer CRI-Implementierung wie containerd oder CRI-O, die wiederum eine Low-Level-Runtime wie `runc`, `crun`, `runsc` oder `kata-runtime` aufruft.

Diese Trennung ist wichtig, da viele Menschen einen Schutzmechanismus fälschlicherweise „Kubernetes“ zuschreiben, obwohl er tatsächlich von der Node-Runtime durchgesetzt wird, oder „containerd-Defaults“ für ein Verhalten verantwortlich machen, das aus einer Pod-Spezifikation stammt. In der Praxis ist die endgültige Sicherheitslage eine Zusammensetzung: Der Orchestrator fordert etwas an, der Runtime-Stack übersetzt diese Anforderung, und der Kernel setzt sie schließlich durch.

## Warum die Identifizierung der Runtime während eines Assessments wichtig ist

Wenn Engine und Runtime frühzeitig identifiziert werden, lassen sich viele spätere Beobachtungen leichter interpretieren. Ein Rootless-Podman-Container deutet darauf hin, dass User-Namespaces wahrscheinlich eine Rolle spielen. Ein in eine Workload eingebundener Docker-Socket deutet darauf hin, dass API-basierte Privilege Escalation ein realistischer Weg ist. Ein CRI-O-/OpenShift-Node sollte sofort an SELinux-Labels und Richtlinien für eingeschränkte Workloads denken lassen. Eine gVisor- oder Kata-Umgebung sollte dazu führen, vorsichtiger anzunehmen, dass ein klassischer `runc`-Breakout-PoC sich dort genauso verhält.

Deshalb sollte einer der ersten Schritte bei einem Container-Assessment immer darin bestehen, zwei einfache Fragen zu beantworten: **Welche Komponente verwaltet den Container** und **welche Runtime hat den Prozess tatsächlich gestartet**? Sobald diese Antworten feststehen, lässt sich der Rest der Umgebung normalerweise deutlich leichter analysieren.

## Runtime-Schwachstellen

Nicht jeder Container-Escape ist auf eine Fehlkonfiguration durch Operatoren zurückzuführen. Manchmal ist die Runtime selbst die verwundbare Komponente. Das ist relevant, weil eine Workload trotz scheinbar sorgfältiger Konfiguration über einen Fehler in der Low-Level-Runtime gefährdet sein kann.

Das klassische Beispiel ist **CVE-2019-5736** in `runc`. Dabei konnte ein bösartiger Container die `runc`-Binärdatei auf dem Host überschreiben und anschließend auf einen späteren Aufruf von `docker exec` oder einer ähnlichen Runtime-Funktion warten, um von einem Angreifer kontrollierten Code auszulösen. Der Exploit-Pfad unterscheidet sich deutlich von einem einfachen Fehler bei Bind-Mounts oder Capabilities, da er die Art und Weise ausnutzt, wie die Runtime bei der Verarbeitung von exec erneut in den Prozessbereich des Containers eintritt.<sup>[[1]](#references)</sup>

Ein minimaler Reproduktions-Workflow aus Sicht eines red-team besteht aus:
```bash
go build main.go
./main
```
Dann vom Host aus:
```bash
docker exec -it <container-name> /bin/sh
```
Die wichtigste Erkenntnis ist nicht die genaue historische Umsetzung des Exploits, sondern die Bedeutung für die Bewertung: Wenn die Runtime-Version verwundbar ist, kann die Ausführung von Code innerhalb des Containers ausreichen, um den Host zu kompromittieren, selbst wenn die sichtbare Container-Konfiguration nicht offensichtlich schwach wirkt.

Aktuelle Runtime-CVEs wie `CVE-2024-21626` in `runc`, BuildKit-Mount-Races und Parsing-Bugs in containerd unterstreichen denselben Punkt. Runtime-Version und Patch-Stand sind Teil der Sicherheitsgrenze und nicht lediglich nebensächliche Wartungsdetails.

## Referenzen

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

{{#include ../../../banners/hacktricks-training.md}}
