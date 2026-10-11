# Container-Runtimes, Engines, Builder und Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Eine der größten Ursachen für Verwirrung bei der Containersicherheit ist, dass mehrere völlig unterschiedliche Komponenten oft unter demselben Begriff zusammengefasst werden. „Docker“ kann sich auf ein Image-Format, eine CLI, einen Daemon, ein Build-System, einen Runtime-Stack oder einfach allgemein auf Container beziehen. Bei der Sicherheitsanalyse ist diese Mehrdeutigkeit ein Problem, denn verschiedene Schichten sind für verschiedene Schutzmaßnahmen verantwortlich. Ein Breakout aufgrund eines fehlerhaften Bind Mounts ist nicht dasselbe wie ein Breakout aufgrund eines Low-Level-Runtime-Bugs. Beides ist wiederum nicht dasselbe wie ein Fehler in einer Kubernetes-Cluster-Policy.

Diese Seite unterteilt das Ökosystem nach Aufgaben, damit im restlichen Abschnitt genau benannt werden kann, wo eine Schutzmaßnahme oder Schwachstelle tatsächlich angesiedelt ist.

## OCI als gemeinsame Sprache

Moderne Linux-Container-Stacks können oft miteinander interagieren, weil sie eine Reihe von OCI-Spezifikationen verwenden. Die **OCI Image Specification** beschreibt, wie Images und Layer dargestellt werden. Die **OCI Runtime Specification** beschreibt, wie die Runtime den Prozess starten soll, einschließlich Namespaces, Mounts, cgroups und Sicherheitseinstellungen. Die **OCI Distribution Specification** standardisiert, wie Registries Inhalte bereitstellen.

Das erklärt, warum ein mit einem Tool erstelltes Container-Image oft mit einem anderen ausgeführt werden kann und warum mehrere Engines dieselbe Low-Level-Runtime nutzen können. Außerdem wird dadurch verständlich, warum sich das Sicherheitsverhalten verschiedener Produkte ähneln kann: Viele davon erstellen dieselbe OCI-Runtime-Konfiguration und übergeben sie an dieselbe kleine Auswahl an Runtimes.

## Low-Level-OCI-Runtimes

Die Low-Level-Runtime ist die Komponente, die der Kernel-Grenze am nächsten ist. Sie erstellt tatsächlich Namespaces, schreibt cgroup-Einstellungen, wendet Capabilities und seccomp-Filter an und führt schließlich `execve()` für den Container-Prozess aus. Wenn von „Container-Isolation“ auf der technischen Ebene die Rede ist, ist meist diese Schicht gemeint, auch wenn das nicht ausdrücklich gesagt wird.

### `runc`

`runc` ist die OCI-Referenz-Runtime und nach wie vor die bekannteste Implementierung. Sie wird häufig unter Docker, containerd und in vielen Kubernetes-Deployments verwendet. Ein großer Teil der öffentlichen Forschung und Exploit-Materialien zielt auf Umgebungen mit `runc` ab, einfach weil sie weitverbreitet ist und weil `runc` den Maßstab setzt, den sich viele unter einem Linux-Container vorstellen. Wer `runc` versteht, erhält daher ein gutes mentales Modell für die klassische Container-Isolation.

### `crun`

`crun` ist eine weitere OCI-Runtime. Sie ist in C geschrieben und wird in modernen Podman-Umgebungen häufig eingesetzt. Sie wird oft für ihre gute cgroup-v2-Unterstützung, ihre Eignung für rootless-Betrieb und ihren geringeren Overhead gelobt. Aus Sicherheitssicht ist nicht entscheidend, dass sie in einer anderen Sprache geschrieben ist, sondern dass sie dieselbe Aufgabe erfüllt: Sie wandelt die OCI-Konfiguration in einen laufenden Prozessbaum unter dem Kernel um. Ein rootless-Podman-Workflow wirkt oft sicherer, nicht weil `crun` auf magische Weise alle Probleme löst, sondern weil der gesamte Stack stärker auf User Namespaces und das Prinzip der geringsten Rechte setzt.

### `runsc` von gVisor

`runsc` ist die von gVisor verwendete Runtime. Hier ändert sich die Bedeutung der Grenze deutlich. Anstatt die meisten Systemaufrufe wie üblich direkt an den Host-Kernel weiterzugeben, fügt gVisor eine Userspace-Kernel-Schicht ein, die große Teile der Linux-Schnittstelle emuliert oder vermittelt. Das Ergebnis ist kein normaler `runc`-Container mit ein paar zusätzlichen Flags, sondern ein anderes Sandbox-Design, dessen Ziel es ist, die Angriffsfläche des Host-Kernels zu verringern. Kompatibilitäts- und Performance-Kompromisse gehören zu diesem Design. Umgebungen mit `runsc` sollten daher anders dokumentiert werden als Umgebungen mit normalen OCI-Runtimes.

### `kata-runtime`

Kata Containers verschieben die Grenze noch weiter, indem sie die Workload in einer leichtgewichtigen virtuellen Maschine starten. Administrativ kann dies weiterhin wie ein Container-Deployment aussehen, und Orchestrierungsschichten können es ebenfalls so behandeln. Die zugrunde liegende Isolationsgrenze ähnelt jedoch eher der Virtualisierung als einem klassischen Container mit gemeinsam genutztem Host-Kernel. Kata eignet sich daher, wenn eine stärkere Mandantenisolation gewünscht ist, ohne auf containerorientierte Workflows zu verzichten.

## Engines und Container-Manager

Während die Low-Level-Runtime direkt mit dem Kernel kommuniziert, interagieren Benutzer und Betreiber üblicherweise mit der Engine oder dem Manager. Diese Komponente kümmert sich um Image-Pulls, Metadaten, Logs, Netzwerke, Volumes, Lifecycle-Operationen und die Bereitstellung von APIs. Diese Schicht ist besonders wichtig, weil viele reale Kompromittierungen hier stattfinden: Der Zugriff auf einen Runtime-Socket oder eine Daemon-API kann einer Kompromittierung des Hosts gleichkommen, selbst wenn die Low-Level-Runtime selbst einwandfrei funktioniert.

### Docker Engine

Docker Engine ist für Entwickler die bekannteste Container-Plattform und einer der Gründe dafür, dass die Container-Terminologie so stark von Docker geprägt ist. Der typische Ablauf führt von der `docker`-CLI zu `dockerd`, der seinerseits Low-Level-Komponenten wie `containerd` und eine OCI-Runtime koordiniert. Docker-Deployments liefen historisch oft **rootful**, weshalb der Zugriff auf den Docker-Socket ein sehr mächtiges Mittel ist. Darum konzentriert sich so viel praktische Privilege-Escalation-Literatur auf `docker.sock`: Wenn ein Prozess `dockerd` dazu bringen kann, einen privilegierten Container zu erstellen, Host-Pfade einzubinden oder Host-Namespaces beizutreten, braucht er möglicherweise gar keinen Kernel-Exploit.

Vergleiche Release-Nummern anhand ihrer Major-, Minor- und Patch-Komponenten, statt die Punkte zu entfernen: `18.09.1` ist älter als `18.09.2` und `18.09.4`, obwohl die Minor-Komponente mit einer Null aufgefüllt ist. Die [Docker-Release-Notes für 18.09](https://docs.docker.com/engine/release-notes/18.09/) dokumentieren den enthaltenen `runc`-Fix für CVE-2019-5736 in Version 18.09.2 und den Fix für Build-Referenzen für CVE-2019-13139 in Version 18.09.4. Diese Versionshinweise sind Anhaltspunkte, kein Beweis für einen erreichbaren Exploit. Dieselben Release-Notes weisen darauf hin, dass Daemon, Client und Runtime separat paketiert werden. Prüfe daher neben der Daemon-Version auch die installierte Runtime und Backports des Distributors. Eine Schwachstelle in Build-Referenzen setzt außerdem voraus, dass der betroffene Build-Workflow zugänglich ist und Angreifer kontrollierte Eingaben verarbeitet.

### Podman

Podman wurde für ein stärker daemonloses Modell entwickelt. Im Betrieb unterstützt das die Vorstellung, dass Container lediglich Prozesse sind, die über standardmäßige Linux-Mechanismen verwaltet werden, und nicht über einen einzelnen, dauerhaft laufenden privilegierten Daemon. Podman bietet außerdem deutlich bessere **rootless**-Funktionen als die klassischen Docker-Deployments, mit denen viele zuerst vertraut wurden. Dadurch ist Podman nicht automatisch sicher, aber das Standard-Risikoprofil ändert sich erheblich, besonders in Kombination mit User Namespaces, SELinux und `crun`.

### containerd

containerd ist eine zentrale Komponente zur Runtime-Verwaltung in vielen modernen Stacks. Sie wird unter Docker verwendet und zählt außerdem zu den dominierenden Kubernetes-Runtime-Backends. Sie stellt leistungsfähige APIs bereit, verwaltet Images und Snapshots und überlässt die endgültige Prozesserstellung einer Low-Level-Runtime. Bei Sicherheitsanalysen zu containerd sollte betont werden, dass der Zugriff auf den containerd-Socket oder auf `ctr`-/`nerdctl`-Funktionen genauso gefährlich sein kann wie der Zugriff auf die Docker-API, auch wenn die Schnittstelle und der Workflow weniger „entwicklerfreundlich“ wirken.

### CRI-O

CRI-O ist stärker spezialisiert als Docker Engine. Statt eine allgemeine Entwicklerplattform zu sein, wurde es für die saubere Implementierung der Kubernetes Container Runtime Interface entwickelt. Daher ist es besonders in Kubernetes-Distributionen und SELinux-lastigen Ökosystemen wie OpenShift verbreitet. Aus Sicherheitssicht ist dieser engere Fokus hilfreich, weil er die begriffliche Komplexität reduziert: CRI-O gehört eindeutig zur Schicht „Container für Kubernetes ausführen“ und ist keine Allzweckplattform.

Wenn ein Kubernetes-Node CRI-O verwendet, prüfe die **aktive CRI-O-Version des Nodes** und ob die aktuelle Identität Pods in einem Namespace erstellen kann, der dort eingeplant wird. [CVE-2022-0811](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) erlaubte es, mit präparierten Pod-Sysctl-Werten einen Kernel-Parameter des Hosts zu ändern und in betroffenen Versionen bis zur Ausführung mit Host-root-Rechten vorzudringen. Das Upstream-Advisory führt die gepatchten Versionen und Workarounds auf. Ein lokales `crio --version` kann eine Runtime übersehen, die in Minikube oder einem anderen Node-Container verschachtelt ist. Ein lesbares Minikube-Startprotokoll kann einen Versionshinweis liefern, ist aber ein historischer Beleg und kein Nachweis der aktiven Runtime oder ihres Patch-Status. Bestätige die tatsächliche Node-Runtime, die Berechtigung zum Erstellen von Pods, die Admission-Regeln sowie die relevanten Grenzen von seccomp und User Namespaces, bevor du dies als erreichbare Privilege Escalation einstufst.

Es gibt auch einen direkten lokalen Prüfpfad für `pinns`: Die [Entdecker weisen darauf hin, dass Kubernetes nicht erforderlich ist, um den fehlerhaften Helper aufzurufen](https://www.crowdstrike.com/en-us/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/). Prüfe, ob das aktuelle Konto ein root-eigenes Setuid-`pinns` ausführen kann, ob NoNewPrivs oder ein `nosuid`-Mount diesen Rechtewechsel verhindert und ob dem installierten **Helper-Build** der Fix fehlt. Das [Upstream-Advisory](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) führt die gepatchten Release-Versionen auf. Die angezeigte Version eines Daemons beweist jedoch nicht, welche Helper-Binärdatei installiert ist, und Backports des Distributors können die Angreifbarkeit ändern. Eine Setuid-Datei ist lediglich ein Kandidat. Überprüfe Herkunft und Konfiguration des Helpers sowie das Verhalten der Host-Sysctls, ohne ihn bei einer routinemäßigen Enumeration auszuführen.

### Incus, LXD und LXC

Incus-/LXD-/LXC-Systeme sollten von Docker-artigen Anwendungscontainern unterschieden werden, da sie häufig als **System-Container** eingesetzt werden. Von einem System-Container wird üblicherweise erwartet, dass er eher einer leichtgewichtigen Maschine ähnelt: mit einem umfangreicheren Userspace, dauerhaft laufenden Diensten, mehr Gerätezugriff und umfassenderer Host-Integration. Die Isolationsmechanismen beruhen zwar weiterhin auf Kernel-Primitiven, aber die betrieblichen Erwartungen sind andere. Fehlkonfigurationen ähneln hier daher oft weniger „schlechten Standardwerten für App-Container“ und eher Fehlern bei der leichtgewichtigen Virtualisierung oder der Delegation von Host-Rechten.

### systemd-nspawn

systemd-nspawn nimmt eine interessante Stellung ein, da es systemd-nativ und für Tests, Debugging sowie den Betrieb betriebssystemähnlicher Umgebungen sehr nützlich ist. Es ist nicht die vorherrschende Runtime in Cloud-nativen Produktionsumgebungen, kommt aber häufig genug in Labs und auf Distributionen ausgerichteten Umgebungen vor, um erwähnt zu werden. Bei einer Sicherheitsanalyse erinnert es daran, dass „Container“ verschiedene Ökosysteme und Betriebsweisen umfasst.

### Apptainer / Singularity

Apptainer (ehemals Singularity) ist in Forschung und HPC-Umgebungen verbreitet. Die Vertrauensannahmen, der Benutzer-Workflow und das Ausführungsmodell unterscheiden sich in wichtigen Punkten von Docker-/Kubernetes-zentrierten Stacks. Insbesondere ist es in diesen Umgebungen oft wichtig, Benutzern das Ausführen paketierter Workloads zu ermöglichen, ohne ihnen weitreichende privilegierte Rechte zur Container-Verwaltung zu geben. Wer annimmt, jede Container-Umgebung sei im Grunde „Docker auf einem Server“, wird diese Deployments gründlich missverstehen.

## Build-Tools

Viele Sicherheitsanalysen befassen sich nur mit der Laufzeit. Build-Tools sind jedoch ebenfalls wichtig, da sie den Inhalt der Images, die Offenlegung von Build-Secrets und den Umfang des vertrauenswürdigen Kontexts bestimmen, der in das endgültige Artefakt einfließt.

**BuildKit** und `docker buildx` sind moderne Build-Backends, die Funktionen wie Caching, Secret-Mounts, SSH-Forwarding und Multi-Plattform-Builds unterstützen. Diese Funktionen sind nützlich, schaffen aus Sicherheitssicht aber auch Stellen, an denen Secrets in Image-Layern leaken können oder ein zu weit gefasster Build-Kontext Dateien offenlegen kann, die niemals enthalten sein sollten. **Buildah** erfüllt eine ähnliche Aufgabe in OCI-nativen Ökosystemen, insbesondere in Verbindung mit Podman. **Kaniko** wird häufig in CI-Umgebungen eingesetzt, die der Build-Pipeline keinen privilegierten Docker-Daemon zur Verfügung stellen wollen.

Die zentrale Erkenntnis ist, dass Image-Erstellung und Image-Ausführung unterschiedliche Phasen sind. Eine schwache Build-Pipeline kann jedoch die Sicherheit der Laufzeit beeinträchtigen, lange bevor der Container gestartet wird.

## Orchestrierung ist eine weitere Schicht, nicht die Runtime

Kubernetes sollte nicht mit der Runtime selbst gleichgesetzt werden. Kubernetes ist der Orchestrator. Es plant Pods ein, speichert den gewünschten Zustand und legt Sicherheitsrichtlinien über die Workload-Konfiguration fest. Der kubelet kommuniziert dann mit einer CRI-Implementierung wie containerd oder CRI-O, die wiederum eine Low-Level-Runtime wie `runc`, `crun`, `runsc` oder `kata-runtime aufruft.

Diese Trennung ist wichtig, weil viele fälschlicherweise eine Schutzmaßnahme „Kubernetes“ zuschreiben, obwohl sie tatsächlich von der Node-Runtime durchgesetzt wird. Andere machen „containerd-Standardeinstellungen“ für ein Verhalten verantwortlich, das aus einer Pod-Spezifikation stammt. In der Praxis ist die endgültige Sicherheitslage das Ergebnis mehrerer Komponenten: Der Orchestrator fordert etwas an, der Runtime-Stack setzt die Anforderung um und der Kernel setzt sie letztlich durch.

## Warum die Identifizierung der Runtime bei einer Analyse wichtig ist

Wenn du Engine und Runtime früh identifizierst, lassen sich viele spätere Beobachtungen leichter einordnen. Ein rootless-Podman-Container deutet darauf hin, dass User Namespaces wahrscheinlich eine Rolle spielen. Ein in eine Workload eingebundener Docker-Socket lässt eine API-basierte Privilege Escalation als realistischen Angriffsweg erscheinen. Bei einem CRI-O-/OpenShift-Node solltest du sofort an SELinux-Labels und restriktive Workload-Richtlinien denken. Eine gVisor- oder Kata-Umgebung sollte dich vorsichtiger machen, wenn du davon ausgehst, dass ein klassischer `runc`-Breakout-PoC genauso funktioniert.

Deshalb sollten bei einer Container-Analyse immer zuerst zwei einfache Fragen beantwortet werden: **Welche Komponente verwaltet den Container** und **welche Runtime hat den Prozess tatsächlich gestartet**? Sobald diese Antworten klar sind, lässt sich der Rest der Umgebung meist deutlich einfacher beurteilen.

## Schwachstellen in Runtimes

Nicht jeder Container-Escape geht auf eine Fehlkonfiguration durch Betreiber zurück. Manchmal ist die Runtime selbst die verwundbare Komponente. Das ist wichtig, denn eine Workload kann mit einer scheinbar sorgfältigen Konfiguration laufen und trotzdem durch einen Low-Level-Runtime-Fehler gefährdet sein.

Das klassische Beispiel ist **CVE-2019-5736** in `runc`: Ein bösartiger Container konnte die `runc`-Binärdatei des Hosts überschreiben und dann warten, bis ein späteres `docker exec` oder ein ähnlicher Runtime-Aufruf schädlichen Code auslöst. Dieser Exploit-Pfad unterscheidet sich deutlich von einem einfachen Fehler bei Bind Mounts oder Capabilities, da er ausnutzt, wie die Runtime bei der Verarbeitung von `exec` erneut in den Prozessraum des Containers eintritt.<sup>[[1]](#references)</sup>

Ein minimaler Reproduktions-Workflow aus Red-Team-Sicht ist:

```bash
go build main.go
./main
```

Dann vom Host aus:

```bash
docker exec -it <container-name> /bin/sh
```

Die entscheidende Lehre ist nicht die genaue Implementierung des historischen Exploits, sondern die Bedeutung für die Sicherheitsbewertung: Ist die Runtime-Version verwundbar, kann gewöhnliche Codeausführung im Container ausreichen, um den Host zu kompromittieren – selbst wenn die sichtbare Containerkonfiguration nicht offensichtlich unsicher wirkt.

Aktuelle Runtime-CVEs wie `CVE-2024-21626` in `runc`, BuildKit-Mount-Races und Parsing-Fehler in containerd unterstreichen denselben Punkt. Runtime-Version und Patch-Stand sind Teil der Sicherheitsgrenze und nicht bloß unwichtige Wartungsdetails.

## References

- [1] [Ausbruch aus Docker über runC – CVE-2019-5736 erklärt](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
