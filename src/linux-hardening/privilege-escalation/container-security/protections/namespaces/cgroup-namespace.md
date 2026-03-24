# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Übersicht

Der cgroup namespace ersetzt nicht die cgroups und erzwingt nicht selbst Ressourcenlimits. Stattdessen ändert er **wie die cgroup-Hierarchie für den Prozess erscheint**. Anders ausgedrückt virtualisiert er die sichtbaren cgroup-Pfadinformationen, sodass die Workload eine containerbeschränkte Ansicht sieht statt der vollständigen Host-Hierarchie.

Dies ist hauptsächlich eine Sichtbarkeits- und Informationsreduzierungsfunktion. Sie hilft, die Umgebung selbstenthaltend erscheinen zu lassen und offenbart weniger über das cgroup-Layout des Hosts. Das mag unscheinbar wirken, ist aber trotzdem wichtig, weil unnötige Einsicht in die Host-Struktur Reconnaissance erleichtern und environment-dependent exploit chains vereinfachen kann.

## Funktionsweise

Ohne einen privaten cgroup namespace kann ein Prozess host-relative cgroup-Pfade sehen, die mehr von der Hierarchie der Maschine offenbaren, als nützlich ist. Mit einem privaten cgroup namespace werden `/proc/self/cgroup` und verwandte Beobachtungen stärker auf die containerinterne Ansicht lokalisiert. Das ist besonders hilfreich in modernen Runtime-Stacks, die möchten, dass die Workload eine sauberere Umgebung sieht, die weniger Informationen über den Host preisgibt.

## Labor

Sie können einen cgroup namespace mit folgendem Befehl untersuchen:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
Und vergleiche das Laufzeitverhalten mit:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Die Änderung betrifft hauptsächlich, was der Prozess sehen kann, nicht, ob cgroup enforcement vorhanden ist.

## Sicherheitsauswirkung

Die cgroup namespace ist am besten als eine **Sichtbarkeits-Härtungsschicht** zu verstehen. Allein verhindert sie einen breakout nicht, wenn der container beschreibbare cgroup mounts, weitreichende capabilities oder eine gefährliche cgroup v1-Umgebung hat. Wenn jedoch die host cgroup namespace geteilt wird, erfährt der Prozess mehr darüber, wie das System organisiert ist, und kann es einfacher finden, host-relative cgroup-Pfade mit anderen Beobachtungen abzugleichen.

Auch wenn diese namespace normalerweise nicht die Hauptrolle in container breakout writeups spielt, trägt sie dennoch zum übergeordneten Ziel bei, die Offenlegung von Host-Informationen zu minimieren.

## Missbrauch

Der unmittelbare Missbrauchswert liegt hauptsächlich in der Aufklärung. Wenn die host cgroup namespace geteilt wird, vergleiche die sichtbaren Pfade und suche nach hierarchie-Details, die Host-Informationen preisgeben:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Wenn beschreibbare cgroup-Pfade ebenfalls zugänglich sind, kombinieren Sie diese Sichtbarkeit mit einer Suche nach gefährlichen veralteten Schnittstellen:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Der Namespace selbst führt selten sofort zu einem Escape, macht es aber oft einfacher, die Umgebung zu kartieren, bevor cgroup-based abuse primitives getestet werden.

### Vollständiges Beispiel: Shared cgroup Namespace + Writable cgroup v1

Der cgroup Namespace allein reicht normalerweise nicht für einen Escape. Die praktische Eskalation tritt ein, wenn host-revealing cgroup paths mit beschreibbaren cgroup v1 interfaces kombiniert werden:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Wenn diese Dateien erreichbar und beschreibbar sind, pivot sofort in den vollständigen `release_agent` exploitation flow aus [cgroups.md](../cgroups.md). Die Auswirkung ist Codeausführung auf dem Host aus dem Container heraus.

Ohne beschreibbare cgroup-Schnittstellen ist die Auswirkung normalerweise auf reconnaissance beschränkt.

## Prüfungen

Zweck dieser Befehle ist es zu prüfen, ob der Prozess eine private cgroup-namespace-Ansicht hat oder mehr über die Host-Hierarchie erfährt, als er wirklich benötigt.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Was hier interessant ist:

- Wenn der Namespace-Identifier mit einem Host-Prozess übereinstimmt, der von Interesse ist, kann der cgroup namespace geteilt sein.
- Pfade in `/proc/self/cgroup`, die Host-Informationen offenlegen, sind für die Aufklärung nützlich, selbst wenn sie nicht direkt ausnutzbar sind.
- Wenn cgroup mounts außerdem beschreibbar sind, wird die Frage der Sichtbarkeit deutlich wichtiger.

Der cgroup namespace sollte eher als Schicht zur Härtung der Sichtbarkeit behandelt werden, statt als primärer Mechanismus zur Verhinderung von Escapes. Das unnötige Offenlegen der Host-cgroup-Struktur erhöht den Aufklärungswert für einen Angreifer.
{{#include ../../../../../banners/hacktricks-training.md}}
