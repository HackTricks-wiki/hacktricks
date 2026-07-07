# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Das cgroup namespace ersetzt cgroups nicht und erzwingt selbst keine Resource Limits. Stattdessen verändert es, **wie die cgroup hierarchy dem Prozess erscheint**. Mit anderen Worten: Es virtualisiert die sichtbaren cgroup-Pfadinformationen, sodass der Workload eine container-scoped Ansicht statt der vollständigen Host-Hierarchy sieht.

Das ist vor allem eine Visibility- und Informationsreduktionsfunktion. Sie hilft dabei, die Umgebung in sich geschlossen erscheinen zu lassen und verrät weniger über das cgroup-Layout des Hosts. Das klingt vielleicht bescheiden, ist aber dennoch wichtig, weil unnötige Sichtbarkeit in die Host-Struktur Reconnaissance erleichtern und environment-dependent exploit chains vereinfachen kann.

## Operation

Ohne ein privates cgroup namespace kann ein Prozess host-relative cgroup-Pfade sehen, die mehr von der Hierarchie des Systems preisgeben, als nützlich ist. Mit einem privaten cgroup namespace werden `/proc/self/cgroup` und verwandte Beobachtungen stärker auf die eigene Sicht des Containers lokalisiert. Das ist besonders hilfreich in modernen Runtime-Stacks, die wollen, dass der Workload eine sauberere, weniger host-offenlegende Umgebung sieht.

Die Virtualisierung betrifft auch `/proc/<pid>/mountinfo`, nicht nur `/proc/<pid>/cgroup`. Wenn du einen anderen Prozess aus einer anderen cgroup-namespace-Perspektive liest, werden Pfade außerhalb deiner namespace root mit führenden `../`-Komponenten angezeigt, was ein nützlicher Hinweis darauf ist, dass du oberhalb deines delegierten Subtree schaust. Eine praktische Nuance für Labs und post-exploitation ist, dass ein frisch erstelltes cgroup namespace oft ein **cgroupfs remount von innerhalb dieses namespace** benötigt, bevor `mountinfo` die neue root sauber widerspiegelt. Andernfalls siehst du möglicherweise weiterhin eine mount root wie `/..`, was bedeutet, dass das geerbte Mount immer noch eine Ansicht mit ancestor-rooting offenlegt, obwohl das namespace selbst bereits geändert wurde.

## Lab

Du kannst ein cgroup namespace mit Folgendem inspizieren:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Wenn du möchtest, dass `mountinfo` die neue cgroup-namespace root deutlicher anzeigt, mounte das cgroup filesystem innerhalb des neuen namespaces erneut und vergleiche dann noch einmal:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Und das Laufzeitverhalten vergleichen mit:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Die Änderung betrifft vor allem, was der Prozess sehen kann, nicht ob cgroup enforcement existiert.

## Security Impact

Das cgroup namespace sollte am besten als **Visibility-Hardening-Layer** verstanden werden. Allein verhindert es keinen Breakout, wenn der Container writable cgroup mounts, weitreichende capabilities oder eine gefährliche cgroup v1-Umgebung hat. Wenn jedoch das Host-cgroup-namespace geteilt wird, erfährt der Prozess mehr darüber, wie das System organisiert ist, und kann es leichter machen, Host-relative cgroup-Pfade mit anderen Beobachtungen abzugleichen.

Auf **cgroup v2** wird das namespace etwas wichtiger, weil die Delegation-Regeln strenger sind. Wenn die Hierarchie mit `nsdelegate` gemountet ist, behandelt der kernel cgroup namespaces als Delegation-Grenzen: übergeordnete control files sollen außerhalb der Reichweite des Delegatees bleiben, und Writes am Namespace-Root sind auf delegation-safe files wie `cgroup.procs`, `cgroup.threads` und `cgroup.subtree_control` beschränkt. Das macht das namespace zwar immer noch nicht selbst zu einem Escape-Primitive, aber es verändert, was ein kompromittierter Workload inspizieren kann und wo er sicher Sub-cgroups erstellen kann.

Auch wenn dieses namespace in Writeups zu container breakout normalerweise nicht die Hauptrolle spielt, trägt es dennoch zum übergeordneten Ziel bei, Host-Information leaks zu minimieren und cgroup delegation einzugrenzen.

## Abuse

Der unmittelbare Abuse-Wert liegt vor allem in Reconnaissance. Wenn das Host-cgroup-namespace geteilt wird, vergleiche die sichtbaren Pfade und suche nach Hierarchie-Details, die den Host offenbaren:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Wenn auch schreibbare cgroup-Pfade offengelegt sind, kombiniere diese Sichtbarkeit mit einer Suche nach gefährlichen Legacy-Interfaces:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Das Namespace selbst verschafft selten einen sofortigen Escape, macht die Umgebung aber oft leichter zu kartieren, bevor man cgroup-basierte Abuse-Primitives testet.

Ein schneller Reality-Check zur Laufzeit hilft auch, den Angriffsweg zu priorisieren. Docker bietet `--cgroupns=host|private`, während Podman `host`, `private`, `container:<id>` und `ns:<path>` unterstützt. Speziell bei Podman ist der Standard meist **`host` bei cgroup v1** und **`private` bei cgroup v2**, sodass schon die Identifizierung der cgroup-Version verrät, welche Namespace-Posture wahrscheinlicher ist, noch bevor du die vollständige OCI-Konfiguration prüfst.

### Modern v2 Recon: Is This A Delegated Subtree?

Auf modernen Hosts ist die interessante Frage oft nicht `release_agent`, sondern ob der aktuelle Prozess in einem delegierten **cgroup v2**-Subtree sitzt, mit genug Sichtbarkeit oder Schreibzugriff, um verschachtelte Gruppen zu erstellen:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Nützliche Interpretation:

- `cgroup2fs` bedeutet, dass du dich in der unified v2 hierarchy befindest, also sollten klassische v1-only `release_agent` chains nicht mehr deine erste Vermutung sein.
- `cgroup.controllers` zeigt, welche controllers vom parent verfügbar sind und damit, worauf der aktuelle subtree potenziell an children weitergeben könnte.
- `cgroup.subtree_control` zeigt, welche controllers tatsächlich für descendants aktiviert sind.
- `cgroup.events` stellt `populated=0/1` bereit, was praktisch ist, um zu beobachten, ob ein subtree leer geworden ist, aber es ist **kein** host-code-execution primitive wie v1 `release_agent`.

Wenn du bereits genug privilege hast, um direkt ein anderes process namespace zu inspizieren, vergleiche die views mit:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Vollständiges Beispiel: Shared cgroup Namespace + Writable cgroup v1

Der cgroup namespace allein reicht normalerweise nicht für einen escape. Die praktische escalation passiert, wenn host-revealing cgroup paths mit writable cgroup v1 interfaces kombiniert werden:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Wenn diese Dateien erreichbar und schreibbar sind, pivotiere sofort in den vollständigen `release_agent`-Exploitation-Flow aus [cgroups.md](../cgroups.md). Der Impact ist Host-Codeausführung von داخل dem Container.

Ohne schreibbare cgroup-Interfaces ist der Impact normalerweise auf Reconnaissance beschränkt.

## Checks

Der Zweck dieser Befehle ist zu prüfen, ob der Prozess eine private cgroup-namespace-Ansicht hat oder mehr über die Host-Hierarchie lernt, als er wirklich braucht.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Was hier interessant ist:

- Wenn der Namespace-Identifier zu einem Host-Prozess passt, der dich interessiert, kann der cgroup-Namespace geteilt sein.
- Host-offenbarende Pfade in `/proc/self/cgroup` oder ancestor-rooted Einträge in `mountinfo` sind nützliche reconnaissance, auch wenn sie nicht direkt ausnutzbar sind.
- Wenn `cgroup2fs` verwendet wird, konzentriere dich auf delegation, sichtbare controllers und schreibbare Subtrees, statt anzunehmen, dass alte v1-Primitives noch existieren.
- Wenn cgroup-Mounts ebenfalls schreibbar sind, wird die Sichtbarkeitsfrage noch viel wichtiger.

Der cgroup namespace sollte als visibility-hardening layer und nicht als primärer Mechanismus zur Verhinderung von escapes betrachtet werden. Das unnötige Offenlegen der Host-cgroup-Struktur erhöht den reconnaissance-Wert für den Angreifer.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
