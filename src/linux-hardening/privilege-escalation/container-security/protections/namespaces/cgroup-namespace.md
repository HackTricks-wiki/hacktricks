# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Übersicht

Der cgroup Namespace ersetzt die cgroups nicht und setzt selbst keine Ressourcenlimits durch. Stattdessen ändert er **wie die cgroup-Hierarchie für den Prozess erscheint**. Anders ausgedrückt virtualisiert er die sichtbaren cgroup-Pfadinformationen, sodass die Workload eine auf den Container begrenzte Ansicht statt der vollständigen Host-Hierarchie sieht.

Dies ist hauptsächlich eine Funktion zur Reduzierung der Sichtbarkeit und der Informationsmenge. Sie hilft, die Umgebung als eigenständig erscheinen zu lassen und offenbart weniger über das cgroup-Layout des Hosts. Das mag unscheinbar klingen, ist aber wichtig, weil unnötige Einsichten in die Host-Struktur die Aufklärung erleichtern und umgebungsspezifische Exploit-Ketten vereinfachen können.

## Funktionsweise

Ohne einen privaten cgroup Namespace kann ein Prozess host-relative cgroup-Pfade sehen, die mehr von der Maschinenhierarchie offenbaren, als sinnvoll ist. Mit einem privaten cgroup Namespace werden `/proc/self/cgroup` und verwandte Beobachtungen stärker auf die eigene Ansicht des Containers lokalisiert. Das ist besonders nützlich in modernen Runtime-Stacks, die der Workload eine sauberere, weniger Informationen über den Host preisgebende Umgebung zeigen möchten.

## Labor

Du kannst einen cgroup Namespace mit:
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

Das cgroup namespace ist am besten als eine **Sichtbarkeits-Härtungsschicht** zu verstehen. Für sich genommen wird es keinen breakout stoppen, wenn der container writable cgroup mounts, broad capabilities oder eine gefährliche cgroup v1-Umgebung hat. Wenn jedoch das host cgroup namespace geteilt ist, erfährt der Prozess mehr darüber, wie das System organisiert ist, und es kann ihm leichter fallen, host-relative cgroup paths mit anderen Beobachtungen in Einklang zu bringen.

Auch wenn dieser Namespace in container breakout writeups normalerweise nicht die Hauptrolle spielt, trägt er dennoch zum übergeordneten Ziel bei, host information leakage zu minimieren.

## Missbrauch

Der unmittelbare Missbrauchswert liegt hauptsächlich in reconnaissance. Wenn das host cgroup namespace geteilt ist, vergleiche die sichtbaren Pfade und suche nach host-revealing Hierarchie-Details:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Wenn beschreibbare cgroup-Pfade ebenfalls exponiert sind, kombiniere diese Sichtbarkeit mit einer Suche nach gefährlichen Legacy-Interfaces:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Der namespace selbst verschafft selten einen sofortigen escape, aber er erleichtert oft das Abbilden der Umgebung, bevor man cgroup-based abuse primitives testet.

### Vollständiges Beispiel: Gemeinsamer cgroup Namespace + schreibbares cgroup v1

Der cgroup namespace allein reicht normalerweise nicht für einen escape. Die praktische Eskalation erfolgt, wenn host-revealing cgroup paths mit writable cgroup v1 interfaces kombiniert werden:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Wenn diese Dateien erreichbar und beschreibbar sind, pivot sofort zum vollständigen `release_agent` exploitation flow aus [cgroups.md](../cgroups.md). Die Auswirkung ist host code execution aus dem Container heraus.

Ohne beschreibbare cgroup-Interfaces ist die Auswirkung normalerweise auf reconnaissance beschränkt.

## Prüfungen

Ziel dieser Befehle ist es zu prüfen, ob der Prozess eine private cgroup-Namespace-Ansicht hat oder mehr über die Host-Hierarchie erfährt, als er wirklich benötigt.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Was hier interessant ist:

- Wenn die Namespace-Kennung mit einem Host-Prozess übereinstimmt, der für dich relevant ist, kann der cgroup namespace geteilt sein.
- Host-aufdeckende Pfade in /proc/self/cgroup sind nützliche Aufklärungsinformationen, selbst wenn sie nicht direkt ausnutzbar sind.
- Wenn cgroup mounts außerdem beschreibbar sind, wird die Frage der Sichtbarkeit viel wichtiger.

Der cgroup namespace sollte eher als Schicht zur Härtung der Sichtbarkeit behandelt werden, statt als primärer Mechanismus zur Verhinderung von Escapes. Das unnötige Offenlegen der Host-cgroup-Struktur erhöht den Aufklärungswert für den Angreifer.
