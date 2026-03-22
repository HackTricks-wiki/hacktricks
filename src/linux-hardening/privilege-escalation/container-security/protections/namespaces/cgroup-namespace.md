# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Übersicht

Das cgroup namespace ersetzt nicht cgroups und erzwingt nicht selbst Ressourcenlimits. Stattdessen ändert es **wie die cgroup-Hierarchie für den Prozess erscheint**. Anders gesagt virtualisiert es die sichtbaren cgroup-Pfadinformationen, sodass die Workload eine container-spezifische Ansicht sieht statt der vollständigen Host-Hierarchie.

Dies ist hauptsächlich eine Funktion zur Sichtbarkeits- und Informationsreduktion. Sie hilft, die Umgebung als in sich geschlossen erscheinen zu lassen und offenbart weniger über das cgroup-Layout des Hosts. Das mag bescheiden klingen, ist aber wichtig, weil unnötige Einblicke in die Host-Struktur die Aufklärung unterstützen und umgebungsabhängige Exploit-Ketten vereinfachen können.

## Funktionsweise

Ohne ein privates cgroup namespace kann ein Prozess host-relative cgroup-Pfade sehen, die mehr von der Hierarchie der Maschine offenbaren, als nützlich ist. Mit einem privaten cgroup namespace werden `/proc/self/cgroup` und verwandte Beobachtungen stärker auf die eigene Sicht des Containers lokalisiert. Das ist besonders hilfreich in modernen Runtime-Stacks, die möchten, dass die Workload eine sauberere, weniger host-enthüllende Umgebung sieht.

## Labor

Sie können ein cgroup namespace mit folgendem Befehl untersuchen:
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
Die Änderung betrifft hauptsächlich, was der Prozess sehen kann, nicht, ob cgroup enforcement existiert.

## Sicherheitsauswirkung

Die cgroup namespace ist am besten als eine **Sichtbarkeits-Härtungsschicht** zu verstehen. Für sich genommen verhindert sie keinen breakout, wenn der Container beschreibbare cgroup mounts, weitreichende capabilities oder eine gefährliche cgroup v1-Umgebung hat. Wenn jedoch das host cgroup namespace geteilt ist, erfährt der Prozess mehr darüber, wie das System organisiert ist, und es kann ihm leichter fallen, host-relative cgroup paths mit anderen Beobachtungen in Einklang zu bringen.

Auch wenn dieses namespace in container breakout writeups normalerweise nicht die Hauptrolle spielt, trägt es dennoch zum übergeordneten Ziel bei, host information leakage zu minimieren.

## Missbrauch

Der unmittelbare Missbrauchswert liegt hauptsächlich in reconnaissance. Wenn das host cgroup namespace geteilt ist, vergleiche die sichtbaren Pfade und suche nach host-revealing Hierarchie-Details:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Wenn beschreibbare cgroup-Pfade ebenfalls offenliegen, kombiniere diese Sichtbarkeit mit einer Suche nach gefährlichen, veralteten Schnittstellen:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Der namespace selbst liefert selten sofortigen escape, macht aber oft die Umgebung leichter zu kartieren, bevor cgroup-based abuse primitives getestet werden.

### Vollständiges Beispiel: Shared cgroup Namespace + Writable cgroup v1

Der cgroup namespace allein reicht normalerweise nicht für escape. Die praktische Eskalation tritt ein, wenn host-revealing cgroup paths mit beschreibbaren cgroup v1 Interfaces kombiniert werden:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Wenn diese Dateien erreichbar und beschreibbar sind, pivot sofort in den vollständigen `release_agent`-Exploitation-Flow aus [cgroups.md](../cgroups.md). Die Auswirkung ist Host-Code-Ausführung von innerhalb des container.

Ohne beschreibbare cgroup interfaces ist die Auswirkung normalerweise auf reconnaissance beschränkt.

## Checks

Der Zweck dieser Befehle ist zu prüfen, ob der Prozess eine private cgroup namespace-Ansicht hat oder mehr über die Host-Hierarchie erfährt, als er wirklich benötigt.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Was hier interessant ist:

- Wenn die Namespace-Kennung mit einem Host-Prozess übereinstimmt, der für Sie relevant ist, kann das cgroup namespace geteilt sein.
- Hosts sichtbar machende Pfade in `/proc/self/cgroup` sind nützliche reconnaissance, selbst wenn sie nicht direkt ausnutzbar sind.
- Wenn cgroup mounts außerdem beschreibbar sind, wird die Sichtbarkeitsfrage deutlich wichtiger.

Das cgroup namespace sollte eher als eine Sichtbarkeits-Härtungsschicht behandelt werden als als ein primärer escape-prevention-Mechanismus. Das unnötige Offenlegen der Host-cgroup-Struktur erhöht den reconnaissance-Wert für den Angreifer.
{{#include ../../../../../banners/hacktricks-training.md}}
