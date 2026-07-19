# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Übersicht

Der cgroup Namespace ersetzt keine cgroups und erzwingt selbst keine Ressourcenlimits. Stattdessen ändert er, **wie die cgroup-Hierarchie** für den Prozess erscheint. Mit anderen Worten: Er virtualisiert die sichtbaren cgroup-Pfadinformationen, sodass die Workload eine auf den Container beschränkte Ansicht statt der vollständigen Host-Hierarchie sieht.

Dies ist hauptsächlich eine Funktion zur Sichtbarkeit und Informationsreduzierung. Sie trägt dazu bei, dass die Umgebung in sich abgeschlossen wirkt, und verrät weniger über das cgroup-Layout des Hosts. Das mag unbedeutend klingen, ist aber dennoch relevant, da unnötige Einblicke in die Host-Struktur die Reconnaissance unterstützen und umgebungsabhängige Exploit-Ketten vereinfachen können.

## Funktionsweise

Ohne einen privaten cgroup Namespace kann ein Prozess Host-relative cgroup-Pfade sehen, die mehr von der Hierarchie des Rechners offenlegen, als nützlich ist. Mit einem privaten cgroup Namespace werden `/proc/self/cgroup` und damit verbundene Beobachtungen stärker auf die eigene Ansicht des Containers beschränkt. Dies ist besonders hilfreich in modernen Runtime-Stacks, die der Workload eine übersichtlichere Umgebung bieten möchten, die weniger über den Host verrät.

Die Virtualisierung wirkt sich auch auf `/proc/<pid>/mountinfo` aus, nicht nur auf `/proc/<pid>/cgroup`. Wenn du einen anderen Prozess aus der Perspektive eines anderen cgroup Namespace liest, werden Pfade außerhalb des Namespace-Roots mit führenden `../`-Komponenten angezeigt. Das ist ein hilfreicher Hinweis darauf, dass du oberhalb deines delegierten Subtrees suchst. Eine wichtige Besonderheit für Labs und Post-Exploitation ist, dass ein frisch erstellter cgroup Namespace häufig ein **cgroupfs-Remount innerhalb dieses Namespace** benötigt, bevor `mountinfo` den neuen Root korrekt widerspiegelt. Andernfalls kann weiterhin ein Mount-Root wie `/..` sichtbar sein. Das bedeutet, dass der geerbte Mount noch immer eine Ansicht mit dem Root eines übergeordneten Verzeichnisses offenlegt, obwohl sich der Namespace selbst bereits geändert hat.

## Lab

Du kannst einen cgroup Namespace mit folgendem Befehl untersuchen:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Wenn du möchtest, dass `mountinfo` das neue cgroup-namespace-root deutlicher anzeigt, mounte das cgroup-Dateisystem aus dem neuen Namespace erneut und vergleiche anschließend noch einmal:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Und vergleiche das Laufzeitverhalten mit:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Die Änderung betrifft größtenteils, was der Prozess sehen kann, und nicht, ob eine cgroup-Durchsetzung vorhanden ist.

## Sicherheitsauswirkungen

Der cgroup namespace lässt sich am besten als **Visibility-Hardening-Schicht** verstehen. Für sich allein wird er keinen breakout verhindern, wenn der Container über beschreibbare cgroup mounts, weitreichende capabilities oder eine gefährliche cgroup v1-Umgebung verfügt. Wenn der host cgroup namespace jedoch gemeinsam genutzt wird, erhält der Prozess mehr Informationen darüber, wie das System organisiert ist, und kann host-relative cgroup paths möglicherweise leichter mit anderen Beobachtungen in Einklang bringen.

Unter **cgroup v2** gewinnt der namespace etwas mehr an Bedeutung, da die Delegation rules strenger sind. Wenn die Hierarchie mit `nsdelegate` gemountet wird, behandelt der Kernel cgroup namespaces als Delegation boundaries: Übergeordnete control files sollen außerhalb der Reichweite des Delegatees bleiben, und Schreibvorgänge am namespace root sind auf delegation-safe files wie `cgroup.procs`, `cgroup.threads` und `cgroup.subtree_control` beschränkt. Dadurch wird der namespace allein zwar noch nicht zu einem escape primitive, aber es ändert, was eine kompromittierte workload untersuchen kann und wo sie sicher sub-cgroups erstellen kann.

Auch wenn dieser namespace normalerweise nicht im Mittelpunkt von container breakout writeups steht, trägt er dennoch zum übergeordneten Ziel bei, den leak von Hostinformationen zu minimieren und die cgroup delegation einzuschränken.

## Missbrauch

Der unmittelbare Missbrauchswert liegt größtenteils in der reconnaissance. Wenn der host cgroup namespace gemeinsam genutzt wird, vergleiche die sichtbaren paths und suche nach host-revealing hierarchy details:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Wenn auch beschreibbare cgroup-Pfade offengelegt sind, kombiniere diese Sichtbarkeit mit einer Suche nach gefährlichen Legacy-Schnittstellen:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Der Namespace ermöglicht nur selten einen sofortigen Escape, erleichtert jedoch häufig die Kartierung der Umgebung, bevor cgroup-basierte Abuse-Primitives getestet werden.

Ein kurzer Runtime-Realitätscheck hilft ebenfalls dabei, den Attack Path zu priorisieren. Docker stellt `--cgroupns=host|private` bereit, während Podman `host`, `private`, `container:<id>` und `ns:<path>` unterstützt. Bei Podman ist der Standard normalerweise **`host` bei cgroup v1** und **`private` bei cgroup v2**. Allein die Identifizierung der cgroup-Version verrät dir daher bereits, welche Namespace-Konfiguration wahrscheinlicher ist, bevor du überhaupt die vollständige OCI config untersuchst.

### Modern v2 Recon: Ist dies ein delegierter Subtree?

Auf modernen Hosts lautet die interessante Frage häufig nicht `release_agent`, sondern ob sich der aktuelle Prozess innerhalb eines delegierten **cgroup v2**-Subtrees mit ausreichender Sichtbarkeit oder Schreibberechtigung befindet, um verschachtelte Gruppen zu erstellen:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Nützliche Interpretation:

- `cgroup2fs` bedeutet, dass du dich in der vereinheitlichten v2-Hierarchie befindest; klassische, nur für v1 geltende `release_agent`-Ketten sollten daher nicht deine erste Vermutung sein.
- `cgroup.controllers` zeigt, welche Controller vom übergeordneten Element verfügbar sind und daher auf welche Controller sich der aktuelle Teilbaum potenziell auf untergeordnete Elemente ausweiten kann.
- `cgroup.subtree_control` zeigt, welche Controller für nachgelagerte Elemente tatsächlich aktiviert sind.
- `cgroup.events` stellt `populated=0/1` bereit. Das ist nützlich, um zu beobachten, ob ein Teilbaum leer geworden ist, aber es ist **kein Primitive zur Ausführung von Code auf dem Host** wie `release_agent` in v1.

Wenn du bereits über ausreichende Berechtigungen verfügst, um den Namespace eines anderen Prozesses direkt zu untersuchen, vergleiche die Ansichten mit:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Vollständiges Beispiel: Gemeinsam genutzter cgroup-Namespace + beschreibbares cgroup v1

Der cgroup-Namespace allein reicht normalerweise nicht für einen escape aus. Die praktische Rechteausweitung erfolgt, wenn host-offenlegende cgroup-Pfade mit beschreibbaren cgroup v1-Schnittstellen kombiniert werden:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Wenn diese Dateien erreichbar und beschreibbar sind, wechsle sofort in den vollständigen `release_agent`-Exploitation-Flow aus [cgroups.md](../cgroups.md). Die Auswirkung ist Host-Codeausführung aus dem Container heraus.

Ohne beschreibbare cgroup-Schnittstellen ist die Auswirkung normalerweise auf Reconnaissance beschränkt.

## Prüfungen

Der Zweck dieser Befehle besteht darin festzustellen, ob der Prozess eine private Sicht auf den cgroup namespace hat oder mehr über die Host-Hierarchie erfährt, als er tatsächlich benötigt.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Was ist hier interessant:

- Wenn der Namespace-Identifier mit einem Host-Prozess übereinstimmt, der für dich relevant ist, kann der cgroup namespace gemeinsam genutzt werden.
- Host-revealing-Pfade in `/proc/self/cgroup` oder auf Vorfahren-Roots basierende Einträge in `mountinfo` sind nützliche reconnaissance, auch wenn sie nicht direkt ausnutzbar sind.
- Wenn `cgroup2fs` verwendet wird, solltest du dich auf Delegation, sichtbare Controller und beschreibbare Subtrees konzentrieren, statt davon auszugehen, dass alte v1-Primitives noch existieren.
- Wenn cgroup mounts ebenfalls beschreibbar sind, wird die Frage der Sichtbarkeit deutlich wichtiger.

Der cgroup namespace sollte eher als Layer zur Härtung der Sichtbarkeit und nicht als primärer Mechanismus zur Escape-Verhinderung betrachtet werden. Das unnötige Offenlegen der cgroup-Struktur des Hosts erhöht den reconnaissance-Wert für den Angreifer.

## Referenzen

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
