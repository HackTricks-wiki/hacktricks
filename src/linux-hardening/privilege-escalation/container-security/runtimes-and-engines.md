# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Eine der größten Verwirrungsquellen in der Container-Security ist, dass mehrere völlig verschiedene Komponenten oft unter demselben Wort zusammengefasst werden. "Docker" kann ein Image-Format, ein CLI, ein Daemon, ein Build-System, ein Runtime-Stack oder einfach die Idee von Containern im Allgemeinen meinen. Für Security-Arbeit ist diese Mehrdeutigkeit problematisch, weil unterschiedliche Schichten für verschiedene Schutzmaßnahmen verantwortlich sind. Ein Escape, der durch ein schlechtes bind mount verursacht wird, ist nicht dasselbe wie ein Escape durch einen Low-Level-Runtime-Bug, und beides ist wiederum nicht dasselbe wie ein Cluster-Policy-Fehler in Kubernetes.

Diese Seite trennt das Ökosystem nach Rollen, damit der Rest des Abschnitts präzise darüber sprechen kann, wo ein Schutz oder eine Schwäche tatsächlich liegt.

## OCI As The Common Language

Moderne Linux-Container-Stacks interagieren oft, weil sie eine Reihe von OCI-Spezifikationen sprechen. Die **OCI Image Specification** beschreibt, wie Images und Layer repräsentiert werden. Die **OCI Runtime Specification** beschreibt, wie der Runtime den Prozess starten sollte, einschließlich namespaces, mounts, cgroups und security settings. Die **OCI Distribution Specification** standardisiert, wie Registries Inhalte bereitstellen.

Das ist wichtig, weil es erklärt, warum ein mit einem Tool gebautes Container-Image oft mit einem anderen ausgeführt werden kann und warum mehrere Engines denselben Low-Level-Runtime teilen können. Es erklärt auch, warum sich das Sicherheitsverhalten zwischen Produkten ähnlich anfühlen kann: viele von ihnen erstellen dieselbe OCI-Runtime-Konfiguration und übergeben sie an denselben kleinen Satz von Runtimes.

## Low-Level OCI Runtimes

Der Low-Level-Runtime ist die Komponente, die der Kernel-Grenze am nächsten ist. Sie ist der Teil, der tatsächlich namespaces erstellt, cgroup-Einstellungen schreibt, capabilities und seccomp filters anwendet und schließlich den Containerprozess via `execve()` startet. Wenn Leute über "Container-Isolation" auf mechanischer Ebene sprechen, meinen sie in der Regel diese Schicht, auch wenn sie es nicht explizit sagen.

### `runc`

`runc` ist der Referenz-OCI-Runtime und bleibt die bekannteste Implementierung. Es wird stark unter Docker, containerd und in vielen Kubernetes-Deployments genutzt. Viel öffentliche Forschung und Exploit-Material zielt auf `runc`-artige Umgebungen, einfach weil sie verbreitet sind und weil `runc` die Baseline definiert, an die viele denken, wenn sie an Linux-Container denken. `runc` zu verstehen gibt daher ein gutes mentales Modell für klassische Container-Isolation.

### `crun`

`crun` ist ein weiterer OCI-Runtime, in C geschrieben und in modernen Podman-Umgebungen weit verbreitet. Es wird oft für guten cgroup v2-Support, starke rootless-Ergonomie und geringeren Overhead gelobt. Aus Sicherheitssicht ist nicht die Sprache das Entscheidende, sondern dass es dieselbe Rolle spielt: es ist die Komponente, die die OCI-Konfiguration in einen laufenden Prozessbaum unter dem Kernel verwandelt. Ein rootless-Podman-Workflow fühlt sich oft sicherer an, nicht weil `crun` alles magisch behebt, sondern weil der umgebende Stack tendenziell stärker auf user namespaces und least privilege setzt.

### `runsc` From gVisor

`runsc` ist der Runtime, den gVisor benutzt. Hier verschiebt sich die Grenze spürbar. Anstatt die meisten Syscalls wie üblich direkt an den Host-Kernel weiterzureichen, fügt gVisor eine Userspace-Kernel-Schicht ein, die große Teile der Linux-Schnittstelle emuliert oder vermittelt. Das Ergebnis ist kein normales `runc`-Container mit ein paar zusätzlichen Flags; es ist ein anderes Sandbox-Design mit dem Ziel, die Angriffsfläche des Host-Kernels zu reduzieren. Kompatibilitäts- und Performance-Tradeoffs sind Teil dieses Designs, daher sollten Umgebungen mit `runsc` anders dokumentiert werden als normale OCI-Runtime-Umgebungen.

### `kata-runtime`

Kata Containers verschieben die Grenze weiter, indem sie die Workload innerhalb einer leichtgewichtigen virtuellen Maschine starten. Administrativ kann das weiterhin wie eine Container-Deployment aussehen, und Orchestrierungsebenen behandeln es möglicherweise genauso, aber die zugrundeliegende Isolationsgrenze ist näher an Virtualisierung als an einem klassischen Host-Kernel-geteilten Container. Das macht Kata nützlich, wenn stärkere Tenant-Isolation gewünscht ist, ohne container-zentrierte Workflows aufzugeben.

## Engines And Container Managers

Wenn der Low-Level-Runtime die Komponente ist, die direkt mit dem Kernel spricht, ist der Engine oder Manager die Komponente, mit der Benutzer und Operatoren normalerweise interagieren. Sie kümmert sich um image pulls, metadata, logs, networks, volumes, lifecycle-Operationen und API-Exposition. Diese Schicht ist enorm wichtig, weil viele reale Kompromisse hier passieren: Zugriff auf einen Runtime-Socket oder Daemon-API kann einem Host-Compromise gleichkommen, selbst wenn der Low-Level-Runtime selbst in Ordnung ist.

### Docker Engine

Docker Engine ist die bekannteste Container-Plattform für Entwickler und einer der Gründe, warum Container-Vokabular so Docker-geprägt wurde. Der typische Pfad ist `docker` CLI zu `dockerd`, das wiederum niedrigere Komponenten wie `containerd` und einen OCI-Runtime koordiniert. Historisch waren Docker-Deployments oft **rootful**, und Zugriff auf die Docker-Socket war daher ein sehr mächtiges Primitive. Deshalb konzentriert sich so viel praktisches Privilege-Escalation-Material auf `docker.sock`: wenn ein Prozess `dockerd` bitten kann, einen privilegierten Container zu erstellen, Host-Pfade zu mounten oder Host-Namespaces beizutreten, braucht er möglicherweise keinen Kernel-Exploit.

### Podman

Podman wurde um ein daemonloses Modell herum konzipiert. Operativ hilft das, die Idee zu verstärken, dass Container einfach Prozesse sind, die über Standard-Linux-Mechanismen verwaltet werden und nicht durch einen lang laufenden privilegierten Daemon. Podman hat außerdem eine deutlich stärkere rootless-Story als die klassischen Docker-Deployments, die viele zuerst kennengelernt haben. Das macht Podman nicht automatisch sicher, aber es verändert das Standard-Risiko-Profil deutlich, besonders in Kombination mit user namespaces, SELinux und `crun`.

### containerd

containerd ist eine Kernkomponente des Runtime-Managements in vielen modernen Stacks. Es wird unter Docker verwendet und ist auch eines der dominanten Kubernetes-Runtime-Backends. Es stellt mächtige APIs bereit, verwaltet Images und Snapshots und delegiert die finale Prozess-Erstellung an einen Low-Level-Runtime. Sicherheitsdiskussionen rund um containerd sollten betonen, dass Zugriff auf den containerd-Socket oder `ctr`/`nerdctl`-Funktionalität genauso gefährlich sein kann wie Zugriff auf die Docker-API, selbst wenn die Schnittstelle und der Workflow sich weniger "developer-friendly" anfühlen.

### CRI-O

CRI-O ist fokussierter als Docker Engine. Anstatt eine allgemeine Entwicklerplattform zu sein, ist es darauf ausgelegt, die Kubernetes Container Runtime Interface sauber zu implementieren. Das macht es besonders verbreitet in Kubernetes-Distributionen und SELinux-lastigen Ökosystemen wie OpenShift. Aus Sicherheitssicht ist dieser engere Fokus nützlich, weil er konzeptionelles Durcheinander reduziert: CRI-O ist sehr stark Teil der "run containers for Kubernetes"-Schicht und nicht einer Allzweckplattform.

### Incus, LXD, And LXC

Incus/LXD/LXC-Systeme sollte man von Docker-ähnlichen Application-Containern trennen, weil sie oft als system containers verwendet werden. Ein System-Container soll üblicherweise eher wie eine leichtgewichtige Maschine mit vollerer Userspace, lang laufenden Diensten, reicherer Geräte-Exposition und umfangreicherer Host-Integration wirken. Die Isolationsmechanismen sind immer noch Kernel-Primitiven, aber die operativen Erwartungen sind anders. Deshalb sehen Fehlkonfigurationen hier oft weniger wie "schlechte App-Container-Defaults" aus und mehr wie Fehler in leichter Virtualisierung oder Host-Delegation.

### systemd-nspawn

systemd-nspawn nimmt eine interessante Position ein, weil es systemd-nativ ist und sehr nützlich zum Testen, Debuggen und Ausführen OS-ähnlicher Umgebungen. Es ist nicht der dominante cloud-native Produktions-Runtime, aber es taucht oft genug in Labs und distribution-orientierten Umgebungen auf, dass es eine Erwähnung verdient. Für Sicherheitsanalysen ist es eine weitere Erinnerung daran, dass das Konzept "Container" mehrere Ökosysteme und Betriebsstile umfasst.

### Apptainer / Singularity

Apptainer (ehemals Singularity) ist in Forschung und HPC-Umgebungen verbreitet. Seine Trust-Annahmen, User-Workflows und das Ausführungsmodell unterscheiden sich in wichtigen Punkten von Docker/Kubernetes-zentrierten Stacks. Besonders in diesen Umgebungen ist oft wichtig, dass Nutzer Paket-Workloads ausführen können, ohne ihnen weitreichende privilegierte Container-Management-Rechte zu geben. Wenn ein Prüfer annimmt, jede Container-Umgebung sei grundsätzlich "Docker auf einem Server", wird er diese Deployments massiv missverstehen.

## Build-Time Tooling

Viele Security-Diskussionen sprechen nur über Run-Time, aber Build-Time-Tooling ist ebenfalls wichtig, weil es den Image-Inhalt, die Exposition von Build-Secrets und wie viel trusted context ins finale Artefakt eingebettet wird, bestimmt.

**BuildKit** und `docker buildx` sind moderne Build-Backends, die Features wie Caching, secret mounting, SSH forwarding und Multi-Platform-Builds unterstützen. Das sind nützliche Features, aber aus Sicherheitssicht schaffen sie auch Stellen, an denen Secrets in Image-Layer leak oder ein zu breiter Build-Context Dateien exponieren kann, die niemals eingeschlossen werden sollten. **Buildah** spielt eine ähnliche Rolle in OCI-nativen Ökosystemen, besonders rund um Podman, während **Kaniko** oft in CI-Umgebungen verwendet wird, die keinen privilegierten Docker-Daemon der Build-Pipeline geben wollen.

Die Kernbotschaft ist, dass Image-Erstellung und Image-Ausführung unterschiedliche Phasen sind, aber eine schwache Build-Pipeline kann bereits lange vor dem Start des Containers eine schwache Runtime-Postur erzeugen.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes sollte nicht gedanklich mit dem Runtime selbst gleichgesetzt werden. Kubernetes ist der Orchestrator. Es plant Pods, speichert Desired State und drückt Security-Policy durch Workload-Konfiguration aus. Der kubelet spricht dann mit einer CRI-Implementierung wie containerd oder CRI-O, die wiederum einen Low-Level-Runtime wie `runc`, `crun`, `runsc` oder `kata-runtime` aufruft.

Diese Trennung ist wichtig, weil viele Leute fälschlicherweise einen Schutz "Kubernetes" zuschreiben, obwohl er tatsächlich vom Node-Runtime durchgesetzt wird, oder sie "containerd defaults" verantwortlich machen für ein Verhalten, das aus einem Pod-Spec stammt. In der Praxis ist die finale Sicherheits-Postur eine Komposition: der Orchestrator fordert etwas an, der Runtime-Stack übersetzt es, und der Kernel setzt es schließlich durch.

## Why Runtime Identification Matters During Assessment

Wenn man Engine und Runtime früh identifiziert, werden viele spätere Beobachtungen leichter zu interpretieren. Ein rootless-Podman-Container deutet darauf hin, dass user namespaces wahrscheinlich Teil der Story sind. Eine Docker-Socket, die in eine Workload gemountet ist, legt nahe, dass API-getriebene Privilege-Escalation ein realistischer Pfad ist. Ein CRI-O/OpenShift-Node sollte sofort SELinux-Labels und eingeschränkte Workload-Policy ins Gedächtnis rufen. Eine gVisor- oder Kata-Umgebung sollte vorsichtiger machen, anzunehmen, dass ein klassischer `runc`-Breakout-PoC sich genauso verhält.

Deshalb sollte einer der ersten Schritte bei einer Container-Analyse immer sein, zwei einfache Fragen zu beantworten: **welche Komponente verwaltet den Container** und **welcher Runtime hat den Prozess tatsächlich gestartet**. Sobald diese Antworten klar sind, lässt sich der Rest der Umgebung meistens viel leichter beurteilen.

## Runtime Vulnerabilities

Nicht jeder Container-Escape entsteht durch Operator-Fehlkonfiguration. Manchmal ist der Runtime selbst die verwundbare Komponente. Das ist wichtig, weil eine Workload trotz scheinbar sorgfältiger Konfiguration durch einen Low-Level-Runtime-Fehler exponiert sein kann.

Das klassische Beispiel ist **CVE-2019-5736** in `runc`, bei dem ein bösartiger Container das Host-`runc`-Binary überschreiben und dann auf einen späteren `docker exec` oder eine ähnliche Runtime-Invocation warten konnte, um angreiferkontrollierten Code auszuführen. Der Exploit-Pfad unterscheidet sich stark von einem einfachen bind-mount- oder capability-Fehler, weil er ausnutzt, wie der Runtime beim Exec-Handling wieder in den Container-Prozessraum eintritt.

Ein minimaler Reproduktions-Workflow aus Red-Team-Perspektive ist:
```bash
go build main.go
./main
```
Dann, vom Host:
```bash
docker exec -it <container-name> /bin/sh
```
Die zentrale Lehre ist nicht die exakte historische Exploit-Implementierung, sondern die Konsequenz für die Bewertung: wenn die runtime version verwundbar ist, kann gewöhnliche Codeausführung innerhalb des Containers ausreichen, um den Host zu kompromittieren, selbst wenn die sichtbare Container-Konfiguration nicht offensichtlich schwach erscheint.

Jüngste runtime CVEs wie `CVE-2024-21626` in `runc`, BuildKit mount races und containerd parsing bugs bekräftigen denselben Punkt. Runtime version und patch level sind Teil der Sicherheitsgrenze, nicht bloß Wartungs-Kleinigkeiten.
