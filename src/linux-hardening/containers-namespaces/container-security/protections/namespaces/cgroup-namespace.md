# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der cgroup namespace ersetzt cgroups nicht und erzwingt selbst keine Ressourcenlimits. Stattdessen ändert er, **wie die cgroup-Hierarchie** für den Prozess erscheint. Anders gesagt virtualisiert er die sichtbaren cgroup-Pfadinformationen, sodass die Workload eine auf den Container begrenzte Ansicht statt der vollständigen Host-Hierarchie sieht.

Dies ist hauptsächlich eine Funktion zur Sichtbarkeit und Informationsreduzierung. Sie trägt dazu bei, dass die Umgebung in sich geschlossen wirkt und weniger über das cgroup-Layout des Hosts preisgibt. Das mag unbedeutend klingen, ist aber dennoch relevant, da unnötige Einblicke in die Host-Struktur die Reconnaissance unterstützen und umgebungsabhängige Exploit-Ketten vereinfachen können.

## Funktionsweise

Ohne einen privaten cgroup namespace kann ein Prozess cgroup-Pfade relativ zum Host sehen, die mehr von der Hierarchie des Systems offenlegen als notwendig. Mit einem privaten cgroup namespace werden `/proc/self/cgroup` und verwandte Beobachtungen stärker auf die eigene Ansicht des Containers beschränkt. Dies ist besonders hilfreich in modernen Runtime-Stacks, die der Workload eine sauberere Umgebung bieten möchten, die weniger über den Host preisgibt.

Die Virtualisierung wirkt sich auch auf `/proc/<pid>/mountinfo` aus, nicht nur auf `/proc/<pid>/cgroup`. Wenn du einen anderen Prozess aus der Perspektive eines anderen cgroup namespace liest, werden Pfade außerhalb des Namespace-Roots mit vorangestellten `../`-Komponenten angezeigt. Dies ist ein nützlicher Hinweis darauf, dass du oberhalb deines delegierten Subtrees schaust. Eine wichtige Nuance für Labs und Post-Exploitation ist, dass ein neu erstellter cgroup namespace häufig einen **cgroupfs remount innerhalb dieses Namespace** benötigt, bevor `mountinfo` den neuen Root sauber widerspiegelt. Andernfalls siehst du möglicherweise weiterhin einen Mount-Root wie `/..`. Das bedeutet, dass der geerbte Mount weiterhin eine Ansicht mit dem Root eines Vorfahren offenlegt, obwohl sich der Namespace selbst bereits geändert hat.<sup>[[1]](#references)</sup>

## Lab

Du kannst einen cgroup namespace mit folgendem Befehl untersuchen:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Wenn du möchtest, dass `mountinfo` das neue cgroup-namespace-root deutlicher anzeigt, remounte das cgroup-Dateisystem aus dem neuen Namespace heraus und vergleiche erneut:
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

Der cgroup namespace lässt sich am besten als **Sichtbarkeit-Hardening-Schicht** verstehen. Für sich allein verhindert er keinen breakout, wenn der Container über beschreibbare cgroup mounts, weitreichende capabilities oder eine gefährliche cgroup v1-Umgebung verfügt. Wenn der cgroup namespace des Hosts jedoch geteilt wird, erfährt der Prozess mehr darüber, wie das System organisiert ist, und kann host-relative cgroup-Pfade möglicherweise leichter mit anderen Beobachtungen in Einklang bringen.

Unter **cgroup v2** wird der namespace etwas wichtiger, weil die Delegation-Regeln strenger sind. Wenn die Hierarchie mit `nsdelegate` gemountet wird, behandelt der Kernel cgroup namespaces als Delegation-Grenzen: Übergeordnete Control-Dateien sollen außerhalb der Reichweite des Delegierten bleiben, und Schreibvorgänge am namespace-Root sind auf delegation-sichere Dateien wie `cgroup.procs`, `cgroup.threads` und `cgroup.subtree_control` beschränkt.<sup>[[2]](#references)</sup> Dies macht den namespace zwar nicht selbst zu einem Escape-Primitive, verändert aber, was ein kompromittiertes Workload untersuchen kann und wo es sicher Sub-cgroups erstellen kann.

Obwohl dieser namespace in Writeups zu container breakout normalerweise nicht im Mittelpunkt steht, trägt er dennoch zum übergeordneten Ziel bei, den Leak von Host-Informationen zu minimieren und die cgroup-Delegation einzuschränken.

## Missbrauch

Der unmittelbare Missbrauchswert liegt größtenteils in der Reconnaissance. Wenn der cgroup namespace des Hosts geteilt wird, vergleiche die sichtbaren Pfade und suche nach Details der Hierarchie, die Rückschlüsse auf den Host zulassen:
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
Der Namespace selbst ermöglicht nur selten einen sofortigen Escape, macht die Umgebung jedoch oft leichter kartierbar, bevor cgroup-basierte Abuse-Primitives getestet werden.

Ein kurzer Runtime-Realitätscheck hilft ebenfalls dabei, den Angriffsweg zu priorisieren. Docker stellt `--cgroupns=host|private` bereit, während Podman `host`, `private`, `container:<id>` und `ns:<path>` unterstützt. Bei Podman ist der Standard insbesondere normalerweise **`host` bei cgroup v1** und **`private` bei cgroup v2**. Daher verrät bereits die Identifizierung der cgroup-Version, welche Namespace-Konfiguration wahrscheinlicher ist, bevor du überhaupt die vollständige OCI-Konfiguration untersuchst.

### Moderne v2-Recon: Handelt es sich um einen delegierten Teilbaum?

Auf modernen Hosts lautet die interessante Frage oft nicht `release_agent`, sondern ob sich der aktuelle Prozess innerhalb eines delegierten **cgroup v2**-Teilbaums mit ausreichender Sichtbarkeit oder Schreibberechtigung befindet, um verschachtelte Gruppen zu erstellen:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Nützliche Interpretation:

- `cgroup2fs` bedeutet, dass du dich in der vereinheitlichten v2-Hierarchie befindest; klassische, nur für v1 geltende `release_agent`-Chains sollten daher nicht deine erste Vermutung sein.
- `cgroup.controllers` zeigt, welche Controller vom übergeordneten Element verfügbar sind und daher, auf welche Controller sich der aktuelle Subtree potenziell auf untergeordnete Elemente ausweiten könnte.
- `cgroup.subtree_control` zeigt, welche Controller tatsächlich für Descendants aktiviert sind.
- `cgroup.events` stellt `populated=0/1` bereit. Das ist praktisch, um zu beobachten, ob ein Subtree leer geworden ist, aber es ist **kein Primitive zur Ausführung von Code auf dem Host** wie der v1-`release_agent`.

Wenn du bereits über ausreichende Privilegien verfügst, um den Namespace eines anderen Prozesses direkt zu inspizieren, vergleiche die Ansichten mit:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Vollständiges Beispiel: Gemeinsamer cgroup Namespace + beschreibbares cgroup v1

Der cgroup Namespace allein reicht normalerweise nicht für einen escape aus. Die praktische Eskalation erfolgt, wenn host-offenlegende cgroup-Pfade mit beschreibbaren cgroup v1-Schnittstellen kombiniert werden:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Wenn diese Dateien erreichbar und beschreibbar sind, wechsle sofort in den vollständigen `release_agent`-Exploitation-Flow aus [cgroups.md](../cgroups.md). Die Auswirkung ist Host-Codeausführung aus dem Container heraus.

Ohne beschreibbare cgroup-Schnittstellen beschränkt sich die Auswirkung normalerweise auf Reconnaissance.

## Checks

Der Zweck dieser Befehle besteht darin festzustellen, ob der Prozess eine private Sicht auf den cgroup-Namespace hat oder mehr über die Host-Hierarchie erfährt, als tatsächlich erforderlich ist.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Was hier interessant ist:

- Wenn der Namespace-Bezeichner mit einem für Sie relevanten Host-Prozess übereinstimmt, kann der cgroup namespace gemeinsam genutzt werden.
- Host-revealing Pfade in `/proc/self/cgroup` oder auf Vorfahren-Root basierende Einträge in `mountinfo` sind nützliche Reconnaissance, auch wenn sie nicht direkt ausnutzbar sind.
- Wenn `cgroup2fs` verwendet wird, sollte der Fokus auf Delegation, sichtbaren Controllern und beschreibbaren Subtrees liegen, anstatt davon auszugehen, dass alte v1-Primitives weiterhin vorhanden sind.
- Wenn cgroup mounts ebenfalls beschreibbar sind, wird die Frage der Sichtbarkeit deutlich wichtiger.

Der cgroup namespace sollte eher als Visibility-Hardening-Schicht und nicht als primärer Mechanismus zur Verhinderung eines Escapes betrachtet werden. Das unnötige Offenlegen der cgroup-Struktur des Hosts erhöht den Reconnaissance-Wert für den Angreifer.

## Referenzen

- [1] [cgroup_namespaces(7) — Linux manual page](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [2] [Control Group v2 — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
