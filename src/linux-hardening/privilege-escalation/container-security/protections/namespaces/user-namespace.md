# Benutzer-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Übersicht

Der Benutzer-Namespace ändert die Bedeutung von Benutzer- und Gruppen-IDs, indem er dem Kernel erlaubt, IDs, die innerhalb des Namespace gesehen werden, auf andere IDs außerhalb zuzuordnen. Dies ist eine der wichtigsten modernen Container-Sicherheitsmaßnahmen, weil es direkt das größte historische Problem klassischer Container anspricht: **root innerhalb des Containers war früher unangenehm nah an root auf dem Host**.

Mit Benutzer-Namespaces kann ein Prozess als UID 0 innerhalb des Containers laufen und dennoch einem nicht-privilegierten UID-Bereich auf dem Host entsprechen. Das bedeutet, der Prozess kann für viele Aufgaben innerhalb des Containers wie root agieren, während er aus Sicht des Hosts deutlich weniger mächtig ist. Das löst nicht jedes Container-Sicherheitsproblem, ändert aber die Folgen einer Container-Kompromittierung erheblich.

## Funktionsweise

Ein Benutzer-Namespace verfügt über Mapping-Dateien wie `/proc/self/uid_map` und `/proc/self/gid_map`, die beschreiben, wie Namespace-IDs in übergeordnete IDs übersetzt werden. Wenn root innerhalb des Namespace auf eine nicht-privilegierte Host-UID abgebildet wird, haben Operationen, die echtes Host-root erfordern würden, nicht mehr dieselbe Tragweite. Deshalb sind Benutzer-Namespaces zentral für **rootless containers** und einer der größten Unterschiede zwischen älteren rootful container defaults und moderneren least-privilege designs.

Der Punkt ist subtil, aber entscheidend: root innerhalb des Containers wird nicht eliminiert, es wird **übersetzt**. Der Prozess erlebt lokal weiterhin eine root-ähnliche Umgebung, aber der Host sollte ihn nicht als vollwertigen root behandeln.

## Lab

Ein manueller Test ist:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Das bewirkt, dass der aktuelle Benutzer innerhalb des Namespaces als root erscheint, während er außerhalb auf dem Host weiterhin nicht root ist. Es ist eine der besten einfachen Demos, um zu verstehen, warum user namespaces so wertvoll sind.

In Containern kannst du die sichtbare Zuordnung vergleichen mit:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Die genaue Ausgabe hängt davon ab, ob die Engine user namespace remapping oder eine traditionellere rootful configuration verwendet.

Sie können die Zuordnung auch von der Host-Seite aus lesen mit:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Verwendung zur Laufzeit

Rootless Podman ist eines der deutlichsten Beispiele dafür, dass user namespaces als erstklassiger Sicherheitsmechanismus behandelt werden. Rootless Docker hängt ebenfalls davon ab. Docker's userns-remap support verbessert die Sicherheit auch in rootful daemon-Deployments, obwohl viele Deployments historisch aus Kompatibilitätsgründen deaktiviert blieben. Die Kubernetes-Unterstützung für user namespaces hat sich verbessert, aber Adoption und Defaults variieren je nach runtime, distro und cluster policy. Incus/LXC-Systeme stützen sich ebenfalls stark auf UID/GID shifting und idmapping-Ideen.

Der allgemeine Trend ist klar: Umgebungen, die user namespaces ernsthaft nutzen, liefern in der Regel eine bessere Antwort auf die Frage „Was bedeutet 'root' im Container eigentlich?“ als Umgebungen, die dies nicht tun.

## Erweiterte Mapping-Details

Wenn ein unprivilegierter Prozess in `uid_map` oder `gid_map` schreibt, wendet der Kernel strengere Regeln an als bei einem privilegierten Schreiber im Parent-namespace. Nur eingeschränkte Mappings sind erlaubt, und für `gid_map` muss der Schreiber normalerweise zuerst `setgroups(2)` deaktivieren:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Dieses Detail ist wichtig, weil es erklärt, warum die Einrichtung von user-namespace in rootless-Experimenten manchmal fehlschlägt und warum runtimes sorgfältige Hilfslogik zur UID/GID-Delegation benötigen.

Ein weiteres fortgeschrittenes Feature ist das **ID-mapped mount**. Anstatt die On-Disk-Besitzrechte zu ändern, wendet ein ID-mapped mount eine user-namespace-Mapping auf ein mount an, sodass Besitz durch diese Mount-Ansicht übersetzt erscheint. Dies ist besonders relevant in rootless- und modernen runtime-Setups, weil es erlaubt, gemeinsame Host-Pfade zu verwenden, ohne rekursive `chown`-Operationen. Aus Sicht der Sicherheit ändert das Feature, wie schreibbar ein bind mount von innen dem namespace erscheint, obwohl es die zugrunde liegende Dateisystem-Metadaten nicht umschreibt.

Schließlich: Wenn ein Prozess einen neuen user namespace erstellt oder ihm beitritt, erhält er innerhalb dieses namespace ein vollständiges Capability-Set. Das bedeutet nicht, dass er plötzlich host-weite Macht erlangt hat. Es bedeutet, dass diese Capabilities nur dort genutzt werden können, wo das namespace-Modell und andere Schutzmechanismen es erlauben. Daher kann `unshare -U` plötzlich Mount- oder namespace-lokale privilegierte Operationen ermöglichen, ohne die Host-Root-Grenze direkt verschwinden zu lassen.

## Fehlkonfigurationen

Die hauptsächliche Schwäche besteht schlicht darin, user namespaces in Umgebungen nicht zu verwenden, in denen sie möglich wären. Wenn container root zu direkt auf host root abgebildet wird, werden schreibbare host mounts und privilegierte Kernel-Operationen deutlich gefährlicher. Ein weiteres Problem ist das Erzwingen des Teilens des Host-User-Namespaces oder das Deaktivieren der Remapping-Funktion aus Kompatibilitätsgründen, ohne zu erkennen, wie sehr das die Vertrauensgrenze verändert.

User namespaces müssen auch im Zusammenhang mit dem restlichen Modell betrachtet werden. Selbst wenn sie aktiv sind, kann eine breite runtime-API-Exposition oder eine sehr schwache runtime-Konfiguration weiterhin Privilegieneskalation über andere Pfade erlauben. Ohne sie werden jedoch viele alte Breakout-Klassen viel leichter ausnutzbar.

## Missbrauch

Wenn der Container rootful ist ohne user namespace-Trennung, wird ein schreibbarer host bind mount deutlich gefährlicher, weil der Prozess tatsächlich als host root schreiben könnte. Gefährliche Capabilities werden dadurch ebenfalls relevanter. Der Angreifer muss nicht mehr so sehr gegen die Übersetzungsgrenze ankämpfen, weil diese kaum noch existiert.

Das Vorhandensein oder Fehlen eines user namespace sollte frühzeitig überprüft werden, wenn ein Container-Breakout-Pfad bewertet wird. Es beantwortet nicht alle Fragen, zeigt aber sofort, ob „root in container“ direkte Relevanz für den Host hat.

Das praktischste Missbrauchsmuster besteht darin, die Mapping zu bestätigen und dann sofort zu testen, ob host-mounted content mit host-relevanten Privilegien beschreibbar ist:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Wenn die Datei als real host root erstellt wird, ist die user namespace isolation für diesen Pfad de facto aufgehoben. Zu diesem Zeitpunkt werden klassische host-file abuses realistisch:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Eine sicherere Bestätigung bei einem live assessment besteht darin, eine harmlose Markierung zu schreiben, anstatt kritische Dateien zu verändern:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Diese Prüfungen sind wichtig, weil sie die eigentliche Frage schnell beantworten: Wird root in diesem Container hinreichend auf root des Hosts abgebildet, sodass ein beschreibbarer Host-Mount sofort zu einem Pfad zur Kompromittierung des Hosts wird?

### Vollständiges Beispiel: Wiedererlangen von Namespace-lokalen Capabilities

Wenn seccomp `unshare` erlaubt und die Umgebung ein frisches User-Namespace zulässt, kann der Prozess innerhalb dieses neuen Namespace möglicherweise wieder ein vollständiges Capability-Set erlangen:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Dies ist an sich kein host escape. Der Grund, warum es wichtig ist, ist, dass user namespaces privilegierte, namespace-lokale Aktionen wieder aktivieren können, die sich später mit schwachen Mounts, verwundbaren Kerneln oder schlecht exponierten Laufzeitoberflächen kombinieren.

## Überprüfungen

Diese Befehle sollen die wichtigste Frage auf dieser Seite beantworten: Worauf ist root innerhalb dieses Containers auf dem Host abgebildet?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- Wenn der Prozess UID 0 ist und die maps eine direkte oder sehr nahe host-root mapping zeigen, ist der Container deutlich gefährlicher.
- Wenn root auf einen unprivilegierten Host-Bereich abgebildet wird, ist das eine viel sicherere Ausgangsbasis und deutet in der Regel auf echte user namespace isolation hin.
- Die Mapping-Dateien sind wertvoller als `id` allein, weil `id` nur die namespace-lokale Identität anzeigt.

Wenn die Workload als UID 0 läuft und das Mapping zeigt, dass dies eng mit host root übereinstimmt, sollten Sie die übrigen Privilegien des Containers wesentlich strenger beurteilen.
