# Container-Runtimes, Engines, Builder und Sandboxes

Eine der größten Verwirrungsquellen bei der Container-Sicherheit besteht darin, dass mehrere völlig unterschiedliche Komponenten häufig unter demselben Begriff zusammengefasst werden. „Docker“ kann sich auf ein Image-Format, eine CLI, einen Daemon, ein Build-System, einen Runtime-Stack oder einfach allgemein auf das Konzept von Containern beziehen. Für die Sicherheitsarbeit ist diese Mehrdeutigkeit problematisch, da verschiedene Ebenen für unterschiedliche Schutzmechanismen verantwortlich sind. Ein Breakout aufgrund eines fehlerhaften Bind-Mounts ist nicht dasselbe wie ein Breakout aufgrund eines Fehlers in einer Low-Level-Runtime, und beides ist wiederum nicht dasselbe wie ein Fehler in einer Cluster-Policy in Kubernetes.

Diese Seite unterteilt das Ökosystem nach Rollen, damit im restlichen Abschnitt präzise darüber gesprochen werden kann, wo sich ein Schutz oder eine Schwachstelle tatsächlich befindet.

## OCI als gemeinsame Sprache

Moderne Linux-Container-Stacks können häufig miteinander interagieren, weil sie eine Reihe von OCI-Spezifikationen verwenden. Die **OCI Image Specification** beschreibt, wie Images und Layer dargestellt werden. Die **OCI Runtime Specification** beschreibt, wie die Runtime den Prozess starten soll, einschließlich Namespaces, Mounts, cgroups und Sicherheitseinstellungen. Die **OCI Distribution Specification** standardisiert, wie Registries Inhalte bereitstellen.

Das ist wichtig, weil es erklärt, warum ein mit einem Tool erstelltes Container-Image oft mit einem anderen Tool ausgeführt werden kann und warum mehrere Engines dieselbe Low-Level-Runtime verwenden können. Es erklärt außerdem, warum sich das Sicherheitsverhalten verschiedener Produkte ähnlich verhalten kann: Viele von ihnen erstellen dieselbe OCI-Runtime-Konfiguration und übergeben sie an dieselbe kleine Auswahl an Runtimes.

## Low-Level-OCI-Runtimes

Die Low-Level-Runtime ist die Komponente, die der Kernel-Grenze am nächsten ist. Sie erstellt tatsächlich Namespaces, schreibt cgroup-Einstellungen, wendet Capabilities und seccomp-Filter an und führt schließlich `execve()` für den Container-Prozess aus. Wenn über „Container-Isolation“ auf der technischen Ebene gesprochen wird, ist normalerweise diese Ebene gemeint, auch wenn dies nicht ausdrücklich gesagt wird.

### `runc`

`runc` ist die Referenz-OCI-Runtime und nach wie vor die bekannteste Implementierung. Sie wird intensiv unter Docker, containerd und vielen Kubernetes-Deployments eingesetzt. Ein großer Teil der öffentlichen Forschung und der Exploit-Materialien zielt auf `runc`-artige Umgebungen ab, einfach weil diese häufig vorkommen und `runc` den Maßstab definiert, den sich viele Menschen unter einem Linux-Container vorstellen. Das Verständnis von `runc` vermittelt daher ein solides mentales Modell für klassische Container-Isolation.

### `crun`

`crun` ist eine weitere OCI-Runtime, die in C geschrieben ist und häufig in modernen Podman-Umgebungen verwendet wird. Sie wird oft für ihre gute cgroup-v2-Unterstützung, die gute Rootless-Erfahrung und den geringeren Overhead gelobt. Aus Sicherheitsperspektive ist nicht entscheidend, dass sie in einer anderen Sprache geschrieben ist, sondern dass sie dieselbe Rolle erfüllt: Sie wandelt die OCI-Konfiguration in einen laufenden Prozessbaum unter dem Kernel um. Ein Rootless-Podman-Workflow wirkt häufig sicherer, nicht weil `crun` auf magische Weise alles behebt, sondern weil der gesamte Stack darum herum stärker auf User-Namespaces und Least Privilege ausgerichtet ist.

### `runsc` von gVisor

`runsc` ist die von gVisor verwendete Runtime. Hier verändert sich die Bedeutung der Grenze erheblich. Anstatt die meisten Syscalls wie üblich direkt an den Host-Kernel weiterzugeben, fügt gVisor eine Userspace-Kernel-Schicht ein, die große Teile der Linux-Schnittstelle emuliert oder vermittelt. Das Ergebnis ist kein normaler `runc`-Container mit einigen zusätzlichen Flags, sondern ein anderes Sandbox-Design, dessen Zweck darin besteht, die Angriffsfläche des Host-Kernels zu reduzieren. Kompatibilitäts- und Performance-Abwägungen sind Teil dieses Designs. Umgebungen mit `runsc` sollten daher anders dokumentiert werden als normale OCI-Runtime-Umgebungen.

### `kata-runtime`

Kata Containers verschieben die Grenze noch weiter, indem sie die Workload innerhalb einer leichtgewichtigen virtuellen Maschine starten. Administrativ kann dies weiterhin wie ein Container-Deployment aussehen, und Orchestrierungsebenen können es weiterhin entsprechend behandeln. Die zugrunde liegende Isolationsgrenze liegt jedoch näher an Virtualisierung als an einem klassischen Container mit gemeinsam genutztem Host-Kernel. Dadurch eignet sich Kata, wenn eine stärkere Tenant-Isolation gewünscht wird, ohne auf Container-zentrierte Workflows zu verzichten.

## Engines und Container-Manager

Wenn die Low-Level-Runtime die Komponente ist, die direkt mit dem Kernel kommuniziert, ist die Engine oder der Manager die Komponente, mit der Benutzer und Betreiber normalerweise interagieren. Sie kümmert sich um Image-Pulls, Metadaten, Logs, Netzwerke, Volumes, Lifecycle-Operationen und die Bereitstellung von APIs. Diese Ebene ist besonders wichtig, da viele reale Kompromittierungen hier stattfinden: Der Zugriff auf einen Runtime-Socket oder eine Daemon-API kann einer Kompromittierung des Hosts gleichkommen, selbst wenn die Low-Level-Runtime selbst vollkommen fehlerfrei ist.

### Docker Engine

Docker Engine ist die bekannteste Container-Plattform für Entwickler und einer der Gründe, warum die Container-Terminologie so stark von Docker geprägt wurde. Der typische Ablauf ist `docker` CLI zu `dockerd`, das wiederum Low-Level-Komponenten wie `containerd` und eine OCI-Runtime koordiniert. In der Vergangenheit waren Docker-Deployments häufig **rootful**, wodurch der Zugriff auf den Docker-Socket ein äußerst mächtiges Primitiv darstellte. Deshalb konzentriert sich so viel praktisches Privilege-Escalation-Material auf `docker.sock`: Wenn ein Prozess `dockerd` anweisen kann, einen privilegierten Container zu erstellen, Host-Pfade zu mounten oder Host-Namespaces beizutreten, benötigt er möglicherweise überhaupt keinen Kernel-Exploit.

### Podman

Podman wurde rund um ein stärker daemonloses Modell entwickelt. Das unterstützt die Vorstellung, dass Container lediglich Prozesse sind, die über standardmäßige Linux-Mechanismen und nicht über einen dauerhaft laufenden privilegierten Daemon verwaltet werden. Podman bietet außerdem eine deutlich bessere **Rootless**-Unterstützung als die klassischen Docker-Deployments, mit denen viele Menschen zuerst vertraut wurden. Das macht Podman nicht automatisch sicher, verändert jedoch das standardmäßige Risikoprofil erheblich, insbesondere in Kombination mit User-Namespaces, SELinux und `crun`.

### containerd

containerd ist eine zentrale Runtime-Management-Komponente in vielen modernen Stacks. Sie wird unter Docker eingesetzt und ist außerdem eines der dominierenden Kubernetes-Runtime-Backends. Sie stellt leistungsfähige APIs bereit, verwaltet Images und Snapshots und delegiert die endgültige Prozesserstellung an eine Low-Level-Runtime. Bei Sicherheitsdiskussionen zu containerd sollte betont werden, dass der Zugriff auf den containerd-Socket oder auf `ctr`-/`nerdctl`-Funktionen genauso gefährlich sein kann wie der Zugriff auf die Docker-API, selbst wenn sich die Schnittstelle und der Workflow weniger „developer-friendly“ anfühlen.

### CRI-O

CRI-O ist stärker fokussiert als Docker Engine. Statt eine allgemeine Entwicklerplattform zu sein, ist es auf die saubere Implementierung der Kubernetes Container Runtime Interface ausgerichtet. Dadurch kommt es besonders häufig in Kubernetes-Distributionen und SELinux-lastigen Ökosystemen wie OpenShift zum Einsatz. Aus Sicherheitsperspektive ist dieser engere Fokus hilfreich, da er konzeptionelle Unübersichtlichkeit reduziert: CRI-O gehört eindeutig zur Ebene „Container für Kubernetes ausführen“ und ist keine Allzweckplattform.

### Incus, LXD und LXC

Incus-/LXD-/LXC-Systeme sollten von Docker-artigen Application-Containern getrennt betrachtet werden, da sie häufig als **System-Container** eingesetzt werden. Von einem System-Container wird normalerweise erwartet, dass er eher wie eine leichtgewichtige Maschine mit einem umfassenderen Userspace, dauerhaft laufenden Services, umfangreicherem Gerätezugriff und stärkerer Host-Integration wirkt. Die Isolationsmechanismen basieren weiterhin auf Kernel-Primitiven, aber die operativen Erwartungen sind andere. Fehlkonfigurationen sehen daher häufig weniger wie „fehlerhafte App-Container-Defaults“ und eher wie Fehler bei leichtgewichtiger Virtualisierung oder Host-Delegation aus.

### systemd-nspawn

systemd-nspawn nimmt eine interessante Position ein, da es systemd-nativ und sehr nützlich für Tests, Debugging und das Ausführen OS-ähnlicher Umgebungen ist. Es ist nicht die dominierende Cloud-native-Produktionsruntime, kommt aber in Labs und distributionsorientierten Umgebungen häufig genug vor, um erwähnt zu werden. Für die Sicherheitsanalyse erinnert es außerdem daran, dass sich das Konzept „Container“ über mehrere Ökosysteme und Betriebsmodelle erstreckt.

### Apptainer / Singularity

Apptainer (früher Singularity) ist in Forschungs- und HPC-Umgebungen weit verbreitet. Die Trust-Annahmen, der Benutzer-Workflow und das Ausführungsmodell unterscheiden sich in wichtigen Punkten von Docker-/Kubernetes-zentrierten Stacks. In diesen Umgebungen ist es insbesondere wichtig, Benutzern das Ausführen paketierter Workloads zu ermöglichen, ohne ihnen weitreichende privilegierte Container-Management-Rechte zu geben. Wenn ein Reviewer annimmt, jede Container-Umgebung sei im Grunde „Docker auf einem Server“, wird er diese Deployments erheblich falsch verstehen.

## Tooling zur Build-Zeit

Viele Sicherheitsdiskussionen behandeln ausschließlich die Laufzeit. Auch Build-Time-Tooling ist jedoch relevant, da es den Inhalt von Images, die Offenlegung von Build-Secrets und den Umfang des vertrauenswürdigen Kontexts bestimmt, der in das endgültige Artefakt eingebettet wird.

**BuildKit** und `docker buildx` sind moderne Build-Backends, die Funktionen wie Caching, Secret-Mounting, SSH-Forwarding und Multi-Platform-Builds unterstützen. Diese Funktionen sind nützlich, schaffen aus Sicherheitsperspektive jedoch auch Stellen, an denen Secrets in Image-Layer gelangen oder ein zu umfassender Build-Kontext Dateien offenlegen kann, die niemals hätten einbezogen werden dürfen. **Buildah** erfüllt eine ähnliche Rolle in OCI-nativen Ökosystemen, insbesondere im Umfeld von Podman, während **Kaniko** häufig in CI-Umgebungen eingesetzt wird, die dem Build-Workflow keinen privilegierten Docker-Daemon gewähren möchten.

Die zentrale Erkenntnis lautet, dass Image-Erstellung und Image-Ausführung unterschiedliche Phasen sind. Eine schwache Build-Pipeline kann jedoch bereits lange vor dem Start des Containers eine schwache Runtime-Sicherheitslage schaffen.

## Orchestrierung ist eine weitere Ebene, nicht die Runtime

Kubernetes sollte gedanklich nicht mit der Runtime selbst gleichgesetzt werden. Kubernetes ist der Orchestrator. Es plant Pods, speichert den gewünschten Zustand und formuliert Sicherheits-Policies über die Workload-Konfiguration. Der kubelet kommuniziert anschließend mit einer CRI-Implementierung wie containerd oder CRI-O, die wiederum eine Low-Level-Runtime wie `runc`, `crun`, `runsc` oder `kata-runtime` aufruft.

Diese Trennung ist wichtig, weil viele Menschen einen Schutz fälschlicherweise „Kubernetes“ zuschreiben, obwohl er tatsächlich von der Node-Runtime erzwungen wird. Oder sie machen „containerd-Defaults“ für ein Verhalten verantwortlich, das aus einer Pod-Spezifikation stammt. In der Praxis ist die endgültige Sicherheitslage eine Zusammensetzung: Der Orchestrator fordert etwas an, der Runtime-Stack übersetzt diese Anforderung und der Kernel erzwingt sie schließlich.

## Warum die Identifikation der Runtime während eines Assessments wichtig ist

Wenn Engine und Runtime frühzeitig identifiziert werden, lassen sich viele spätere Beobachtungen leichter interpretieren. Ein Rootless-Podman-Container deutet darauf hin, dass User-Namespaces wahrscheinlich eine Rolle spielen. Ein in eine Workload gemounteter Docker-Socket deutet darauf hin, dass eine API-basierte Privilege Escalation ein realistischer Angriffsweg ist. Ein CRI-O-/OpenShift-Node sollte unmittelbar an SELinux-Labels und Restricted-Workload-Policies denken lassen. Eine gVisor- oder Kata-Umgebung sollte dazu führen, vorsichtiger anzunehmen, dass ein klassischer `runc`-Breakout-PoC sich genauso verhält.

Deshalb sollten die ersten Schritte eines Container-Assessments immer darin bestehen, zwei einfache Fragen zu beantworten: **Welche Komponente verwaltet den Container** und **welche Runtime hat den Prozess tatsächlich gestartet**? Sobald diese Antworten klar sind, lässt sich der Rest der Umgebung normalerweise deutlich leichter analysieren.

## Runtime-Schwachstellen

Nicht jeder Container-Escape ist auf eine Fehlkonfiguration durch Betreiber zurückzuführen. Manchmal ist die Runtime selbst die verwundbare Komponente. Das ist wichtig, weil eine Workload trotz scheinbar sorgfältiger Konfiguration über einen Low-Level-Runtime-Fehler gefährdet sein kann.

Das klassische Beispiel ist **CVE-2019-5736** in `runc`. Dabei konnte ein bösartiger Container die `runc`-Binärdatei des Hosts überschreiben und anschließend auf einen späteren Aufruf von `docker exec` oder eine ähnliche Runtime-Invocation warten, um vom Angreifer kontrollierten Code auszuführen. Der Exploit-Pfad unterscheidet sich deutlich von einem einfachen Bind-Mount- oder Capability-Fehler, da er die Art und Weise ausnutzt, wie die Runtime bei der Verarbeitung von `exec` erneut in den Prozessbereich des Containers eintritt.<sup>[[1]](#references)</sup>

Ein minimaler Reproduktions-Workflow aus Red-Team-Perspektive lautet:
```bash
go build main.go
./main
```
Dann vom Host:
```bash
docker exec -it <container-name> /bin/sh
```
Die wichtigste Erkenntnis bezieht sich nicht auf die genaue historische Implementierung des Exploits, sondern auf die sicherheitsrelevante Schlussfolgerung: Wenn die Runtime-Version verwundbar ist, kann gewöhnliche Codeausführung innerhalb des Containers ausreichen, um den Host zu kompromittieren, selbst wenn die sichtbare Container-Konfiguration nicht offensichtlich unsicher wirkt.

Neuere Runtime-CVEs wie `CVE-2024-21626` in `runc`, BuildKit-Mount-Races und Parsing-Bugs in containerd unterstreichen denselben Punkt. Runtime-Version und Patchstand sind Teil der Sicherheitsgrenze und nicht bloß nebensächliche Wartungsdetails.

## References

- [1] [Ausbruch aus Docker über runC – Erklärung von CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
