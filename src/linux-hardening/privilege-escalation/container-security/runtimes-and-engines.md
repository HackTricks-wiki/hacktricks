# Container-Runtimes, Engines, Builder und Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Eine der größten Verwirrungsquellen in der Container-Sicherheit ist, dass mehrere völlig unterschiedliche Komponenten oft unter demselben Wort zusammengefasst werden. "Docker" kann sich auf ein Image-Format, ein CLI, einen Daemon, ein Build-System, einen Runtime-Stack oder einfach die Idee von Containern im Allgemeinen beziehen. Für Sicherheitsarbeit ist diese Mehrdeutigkeit problematisch, weil verschiedene Schichten für unterschiedliche Schutzmechanismen verantwortlich sind. Ein Escape, der durch ein schlechtes bind mount verursacht wird, ist nicht dasselbe wie ein Escape durch einen Low-Level-Runtime-Bug, und beides ist wiederum nicht dasselbe wie ein Fehler in der Cluster-Policy von Kubernetes.

Diese Seite trennt das Ökosystem nach Rollen, damit der Rest des Abschnitts präzise darüber sprechen kann, wo ein Schutz oder eine Schwäche tatsächlich liegt.

## OCI als gemeinsame Sprache

Moderne Linux-Container-Stacks interagieren oft, weil sie eine Reihe von OCI-Spezifikationen sprechen. Die **OCI Image Specification** beschreibt, wie Images und Layers dargestellt werden. Die **OCI Runtime Specification** beschreibt, wie der Runtime den Prozess starten soll, einschließlich namespaces, mounts, cgroups und Security-Einstellungen. Die **OCI Distribution Specification** standardisiert, wie Registries Inhalte bereitstellen.

Das ist wichtig, weil es erklärt, warum ein mit einem Tool gebautes Container-Image oft mit einem anderen ausgeführt werden kann und warum mehrere Engines denselben Low-Level-Runtime teilen können. Es erklärt auch, warum das Sicherheitsverhalten in verschiedenen Produkten ähnlich aussehen kann: Viele bauen dieselbe OCI-Runtime-Konfiguration und übergeben sie an dieselbe kleine Menge von Runtimes.

## Low-Level OCI Runtimes

Der Low-Level-Runtime ist die Komponente, die der Kernel-Grenze am nächsten ist. Er ist der Teil, der tatsächlich namespaces erstellt, cgroup-Einstellungen schreibt, capabilities und seccomp-Filter anwendet und schließlich den Container-Prozess mit `execve()` startet. Wenn Leute auf der mechanischen Ebene über "Container-Isolation" sprechen, meinen sie in der Regel diese Schicht, auch wenn sie es nicht explizit sagen.

### `runc`

`runc` ist der Referenz-OCI-Runtime und bleibt die bekannteste Implementierung. Er wird stark unter Docker, containerd und vielen Kubernetes-Deployments verwendet. Viel öffentliche Forschung und Exploit-Material zielt auf `runc`-ähnliche Umgebungen, einfach weil sie verbreitet sind und weil `runc` die Basis definiert, an die viele denken, wenn sie sich einen Linux-Container vorstellen. `runc` zu verstehen gibt dem Leser daher ein gutes mentales Modell für klassische Container-Isolation.

### `crun`

`crun` ist ein weiterer OCI-Runtime, in C geschrieben und in modernen Podman-Umgebungen weit verbreitet. Er wird oft für seine gute cgroup v2-Unterstützung, starke rootless-Ergonomie und geringeren Overhead gelobt. Aus Sicherheitssicht ist nicht entscheidend, dass er in einer anderen Sprache geschrieben ist, sondern dass er dieselbe Rolle spielt: Er ist die Komponente, die die OCI-Konfiguration in einen laufenden Prozessbaum unter dem Kernel übersetzt. Ein rootless Podman-Workflow fühlt sich häufig sicherer an, nicht weil `crun` alles magisch behebt, sondern weil der gesamte Stack darum herum tendenziell stärker auf user namespaces und Least Privilege setzt.

### `runsc` von gVisor

`runsc` ist der Runtime, der von gVisor verwendet wird. Hier ändert sich die Grenze wesentlich. Anstatt die meisten Syscalls wie üblich direkt an den Host-Kernel weiterzureichen, fügt gVisor eine Userspace-Kernel-Schicht ein, die große Teile der Linux-Schnittstelle emuliert oder vermittelt. Das Ergebnis ist kein normales `runc`-Container mit ein paar zusätzlichen Flags; es ist ein anderes Sandbox-Design, dessen Zweck es ist, die Angriffsfläche des Host-Kernels zu reduzieren. Kompatibilitäts- und Performance-Trade-offs sind Teil dieses Designs, daher sollten Umgebungen mit `runsc` anders dokumentiert werden als normale OCI-Runtime-Umgebungen.

### `kata-runtime`

Kata Containers verschieben die Grenze weiter, indem sie die Workload innerhalb einer leichtgewichtigen virtuellen Maschine starten. Administrativ kann dies weiterhin wie eine Container-Bereitstellung aussehen, und Orchestrierungs-Layer können sie auch so behandeln, aber die zugrunde liegende Isolationsgrenze ist näher an Virtualisierung als an einem klassischen Host-Kernel-geteilten Container. Das macht Kata nützlich, wenn stärkere Tenant-Isolation gewünscht wird, ohne container-zentrierte Workflows aufzugeben.

## Engines und Container-Manager

Wenn der Low-Level-Runtime die Komponente ist, die direkt mit dem Kernel spricht, ist die Engine oder der Manager die Komponente, mit der Benutzer und Betreiber normalerweise interagieren. Sie kümmert sich um Image-Pulls, Metadaten, Logs, Netzwerke, Volumes, Lifecycle-Operationen und API-Exposition. Diese Schicht ist enorm wichtig, weil viele Real-World-Kompromisse hier passieren: Zugriff auf einen Runtime-Socket oder Daemon-API kann einer Host-Übernahme gleichkommen, selbst wenn der Low-Level-Runtime selbst völlig unversehrt ist.

### Docker Engine

Docker Engine ist die bekannteste Container-Plattform für Entwickler und einer der Gründe, warum die Container-Vokabel so Docker-förmig wurde. Der typische Pfad ist das `docker` CLI zu `dockerd`, das wiederum niedrigere Komponenten wie `containerd` und einen OCI-Runtime koordiniert. Historisch waren Docker-Deployments oft **rootful**, und Zugriff auf den Docker-Socket war daher ein sehr mächtiges Primitive. Deshalb konzentriert sich so viel praktisches Privilege-Escalation-Material auf `docker.sock`: Wenn ein Prozess `dockerd` bitten kann, einen privilegierten Container zu erstellen, Host-Pfade zu mounten oder Host-Namespaces beizutreten, braucht er möglicherweise keinen Kernel-Exploit.

### Podman

Podman wurde um ein stärker daemonloses Modell herum entworfen. Operativ hilft das, die Idee zu verstärken, dass Container einfach Prozesse sind, die über Standard-Linux-Mechanismen verwaltet werden, anstatt über einen lang laufenden privilegierten Daemon. Podman hat außerdem eine deutlich stärkere **rootless**-Geschichte als die klassischen Docker-Deployments, die viele zuerst kennengelernt haben. Das macht Podman nicht automatisch sicher, verändert aber das Default-Risiko erheblich, insbesondere in Kombination mit user namespaces, SELinux und `crun`.

### containerd

containerd ist eine zentrale Runtime-Management-Komponente in vielen modernen Stacks. Es wird unter Docker verwendet und ist auch einer der dominanten Kubernetes-Runtime-Backends. Es stellt mächtige APIs bereit, verwaltet Images und Snapshots und delegiert die finale Prozess-Erzeugung an einen Low-Level-Runtime. Sicherheitsdiskussionen rund um containerd sollten betonen, dass Zugriff auf den containerd-Socket oder `ctr`/`nerdctl`-Funktionalität genauso gefährlich sein kann wie Zugriff auf die Docker-API, auch wenn die Schnittstelle und der Workflow weniger "entwicklerfreundlich" erscheinen.

### CRI-O

CRI-O ist fokussierter als Docker Engine. Anstatt eine Allzweck-Entwicklerplattform zu sein, ist es darum gebaut, das Kubernetes Container Runtime Interface sauber zu implementieren. Das macht es besonders häufig in Kubernetes-Distributionen und SELinux-lastigen Ökosystemen wie OpenShift. Aus Sicherheitssicht ist dieser engere Fokus nützlich, weil er konzeptionelle Unordnung reduziert: CRI-O ist sehr klar Teil der "Container für Kubernetes ausführen"-Schicht und nicht einer Alles-Plattform.

### Incus, LXD und LXC

Incus/LXD/LXC-Systeme sind von Docker-artigen Application-Containern zu trennen, weil sie oft als **System-Container** verwendet werden. Ein System-Container soll in der Regel eher wie eine leichtgewichtige Maschine mit einem volleren Userspace, langfristig laufenden Diensten, reichhaltiger Geräteexposition und stärkerer Host-Integration aussehen. Die Isolationsmechanismen sind weiterhin Kernel-Primitiven, aber die operativen Erwartungen sind anders. Folge: Fehlkonfigurationen hier sehen oft weniger wie "schlechte App-Container-Defaults" aus und mehr wie Fehler in leichtgewichtiger Virtualisierung oder Host-Delegation.

### systemd-nspawn

systemd-nspawn nimmt eine interessante Stelle ein, weil es systemd-nativ ist und sehr nützlich zum Testen, Debuggen und Ausführen von OS-ähnlichen Umgebungen. Es ist nicht der dominante cloud-native Produktionsruntime, aber es taucht oft genug in Labs und distribution-orientierten Umgebungen auf, dass es erwähnt werden sollte. Für die Sicherheitsanalyse ist es eine weitere Erinnerung daran, dass das Konzept "Container" mehrere Ökosysteme und Betriebsstile umfasst.

### Apptainer / Singularity

Apptainer (ehemals Singularity) ist in Forschung und HPC-Umgebungen verbreitet. Seine Trust-Annahmen, Benutzer-Workflows und das Ausführungsmodell unterscheiden sich in wichtigen Punkten von Docker/Kubernetes-zentrierten Stacks. Insbesondere geht es in diesen Umgebungen oft stark darum, Benutzern das Ausführen verpackter Workloads zu ermöglichen, ohne ihnen breite privilegierte Container-Management-Rechte zu geben. Wenn ein Prüfer davon ausgeht, jede Container-Umgebung sei im Grunde "Docker auf einem Server", wird er diese Deployments stark missverstehen.

## Build-Time Tooling

Viele Sicherheitsdiskussionen sprechen nur über run time, aber Build-Time-Tooling ist ebenfalls wichtig, weil es den Image-Inhalt, die Exposition von Build-Secrets und wie viel vertrauenswürdiger Kontext ins finale Artefakt eingebettet wird, bestimmt.

**BuildKit** und `docker buildx` sind moderne Build-Backends, die Funktionen wie Caching, Secret-Mounting, SSH-Forwarding und Multi-Platform-Builds unterstützen. Das sind nützliche Features, aber aus Sicherheitsperspektive schaffen sie auch Stellen, an denen Geheimnisse in Image-Layers leak können oder an denen ein zu breiter Build-Kontext Dateien offenlegt, die niemals hätten enthalten sein dürfen. **Buildah** spielt eine ähnliche Rolle in OCI-nativen Ökosystemen, besonders rund um Podman, während **Kaniko** oft in CI-Umgebungen verwendet wird, die dem Build-Pipeline keinen privilegierten Docker-Daemon gewähren wollen.

Die Schlüssellehre ist, dass Image-Erstellung und Image-Ausführung unterschiedliche Phasen sind, aber eine schwache Build-Pipeline kann eine schwache Runtime-Postur lange bevor der Container gestartet wird erzeugen.

## Orchestration ist eine andere Schicht, nicht der Runtime

Kubernetes sollte nicht gedanklich mit dem Runtime selbst gleichgesetzt werden. Kubernetes ist der Orchestrator. Es plant Pods, speichert den Desired State und drückt Sicherheitsrichtlinien über Workload-Konfiguration aus. Der kubelet spricht dann mit einer CRI-Implementierung wie containerd oder CRI-O, die wiederum einen Low-Level-Runtime wie `runc`, `crun`, `runsc` oder `kata-runtime` aufruft.

Diese Trennung ist wichtig, weil viele Leute fälschlicherweise einem Schutz "Kubernetes" zurechnen, obwohl er eigentlich vom Node-Runtime durchgesetzt wird, oder sie "containerd defaults" für ein Verhalten verantwortlich machen, das aus einer Pod-Spezifikation stammt. In der Praxis ist die finale Sicherheits-Postur eine Komposition: Der Orchestrator fordert etwas an, der Runtime-Stack übersetzt es und der Kernel setzt es schließlich durch.

## Warum Runtime-Identifikation während der Assessment wichtig ist

Wenn man Engine und Runtime früh identifiziert, werden viele spätere Beobachtungen leichter zu interpretieren. Ein rootless Podman-Container deutet darauf hin, dass user namespaces wahrscheinlich Teil der Geschichte sind. Ein in eine Workload gemounteter Docker-Socket legt nahe, dass API-getriebene Privilege-Escalation ein realistischer Pfad ist. Ein CRI-O/OpenShift-Node sollte einen sofort an SELinux-Labels und eingeschränkte Workload-Policy denken lassen. Eine gVisor- oder Kata-Umgebung sollte einen vorsichtiger machen, anzunehmen, dass ein klassischer `runc`-Breakout-PoC sich genauso verhält.

Deshalb sollte einer der ersten Schritte bei einer Container-Assessment immer die Beantwortung von zwei einfachen Fragen sein: **welche Komponente verwaltet den Container** und **welcher Runtime hat den Prozess tatsächlich gestartet**. Sobald diese Antworten klar sind, wird der Rest der Umgebung in der Regel viel leichter zu beurteilen.

## Runtime-Schwachstellen

Nicht jeder Container-Escape entsteht durch Administrator-Fehlkonfiguration. Manchmal ist der Runtime selbst die verwundbare Komponente. Das ist wichtig, weil eine Workload mit scheinbar sorgfältiger Konfiguration trotzdem durch einen Low-Level-Runtime-Fehler exponiert sein kann.

Das klassische Beispiel ist **CVE-2019-5736** in `runc`, bei dem ein bösartiger Container die Host-`runc`-Binary überschreiben und dann auf einen späteren `docker exec`- oder ähnlichen Runtime-Aufruf warten konnte, um Angreifer-kontrollierten Code auszuführen. Der Exploit-Pfad unterscheidet sich stark von einem einfachen bind-mount- oder Capability-Fehler, weil er ausnutzt, wie der Runtime beim Exec-Handling wieder in den Container-Prozessraum eintritt.

Ein minimaler Reproduktions-Workflow aus Sicht eines Red-Teams ist:
```bash
go build main.go
./main
```
Dann, vom Host aus:
```bash
docker exec -it <container-name> /bin/sh
```
Die zentrale Lehre ist nicht die genaue historische Exploit-Implementierung, sondern die Auswirkung für die Sicherheitsbewertung: Wenn die runtime-Version verwundbar ist, kann gewöhnliche Code-Ausführung im Container ausreichen, um den Host zu kompromittieren, selbst wenn die sichtbare Container-Konfiguration nicht offensichtlich schwach wirkt.

Jüngste runtime-CVEs wie `CVE-2024-21626` in `runc`, BuildKit mount races und containerd parsing bugs verstärken denselben Punkt. Die runtime-Version und der Patch-Stand sind Teil der Sicherheitsgrenze, nicht bloß Wartungsdetails.
{{#include ../../../banners/hacktricks-training.md}}
