# Benutzer-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Übersicht

Der Benutzer-Namespace ändert die Bedeutung von Benutzer- und Gruppen-IDs, indem er dem Kernel erlaubt, IDs, die innerhalb des Namespace sichtbar sind, auf andere IDs außerhalb zuzuordnen. Dies ist eine der wichtigsten modernen Container-Schutzmaßnahmen, da sie direkt das größte historische Problem klassischer Container adressiert: **root im Container war früher unangenehm nahe an root auf dem Host**.

Mit Benutzer-Namespaces kann ein Prozess als UID 0 im Container laufen und gleichzeitig einem unprivilegierten UID-Bereich auf dem Host entsprechen. Das bedeutet, der Prozess kann sich für viele Aufgaben im Container wie root verhalten, während er aus Sicht des Hosts deutlich weniger Rechte besitzt. Das löst nicht jedes Container-Sicherheitsproblem, verändert aber die Folgen einer Kompromittierung des Containers erheblich.

## Funktionsweise

Ein Benutzer-Namespace verfügt über Zuordnungsdateien wie `/proc/self/uid_map` und `/proc/self/gid_map`, die beschreiben, wie Namespace-IDs in übergeordnete IDs übersetzt werden. Wenn root innerhalb des Namespace auf eine unprivilegierte Host-UID abgebildet wird, haben Operationen, die echtes Host-root erfordern würden, einfach nicht mehr die gleiche Bedeutung. Deshalb sind Benutzer-Namespaces zentral für rootless-Container und einer der größten Unterschiede zwischen älteren rootful-Container-Standardeinstellungen und moderneren Designs nach dem Prinzip des geringsten Privilegs.

Der Punkt ist subtil, aber entscheidend: root im Container wird nicht eliminiert, sondern **übersetzt**. Der Prozess erlebt weiterhin eine root-ähnliche Umgebung lokal, aber der Host sollte ihn nicht als vollständiges root behandeln.

## Labor

Ein manueller Test ist:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Das lässt den aktuellen Benutzer innerhalb des Namespace als root erscheinen, während er außerhalb des Hosts weiterhin nicht root ist. Es ist eine der besten einfachen Demonstrationen, um zu verstehen, warum user namespaces so wertvoll sind.

In Containern kannst du die sichtbare Zuordnung vergleichen mit:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Die genaue Ausgabe hängt davon ab, ob die Engine user namespace remapping verwendet oder eine traditionellere rootful-Konfiguration.

Sie können das Mapping auch von der Host-Seite mit:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Verwendung zur Laufzeit

Rootless Podman ist eines der klarsten Beispiele dafür, dass User-Namespaces als erstklassiger Sicherheitsmechanismus behandelt werden. Rootless Docker hängt ebenfalls davon ab. Dockers userns-remap-Unterstützung erhöht die Sicherheit bei rootful Daemon-Bereitstellungen, obwohl viele Deployments aus Kompatibilitätsgründen historisch oft deaktiviert blieben. Die Kubernetes-Unterstützung für User-Namespaces hat sich verbessert, aber Adoption und Voreinstellungen variieren je nach Runtime, Distribution und Cluster-Richtlinie. Incus/LXC-Systeme setzen ebenfalls stark auf UID/GID-Shifting und idmapping-Konzepte.

## Erweiterte Mapping-Details

Wenn ein unprivilegierter Prozess in `uid_map` oder `gid_map` schreibt, wendet der Kernel strengere Regeln an als bei einem privilegierten Schreiber im übergeordneten Namespace. Es sind nur eingeschränkte Mappings erlaubt, und für `gid_map` muss der Schreiber normalerweise zuerst `setgroups(2)` deaktivieren:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Dieses Detail ist wichtig, weil es erklärt, warum user-namespace-Setups in rootless-Experimenten manchmal fehlschlagen und warum runtimes eine sorgfältige Hilfslogik für die UID/GID-Delegation benötigen.

Ein weiteres fortgeschrittenes Feature ist das **ID-mapped mount**. Anstatt die on-disk Besitzrechte zu ändern, wendet ein ID-mapped mount eine user-namespace-Mapping auf ein Mount an, sodass die Besitzverhältnisse durch diese Mount-Ansicht übersetzt erscheinen. Das ist besonders relevant in rootless- und modernen runtime-Setups, weil es erlaubt, gemeinsam genutzte host-Pfade zu verwenden, ohne rekursive `chown`-Operationen. Sicherheitsbezogen ändert das Feature, wie schreibbar ein bind mount aus Sicht des namespace erscheint, obwohl es die zugrunde liegenden Dateisystem-Metadaten nicht umschreibt.

Schließlich: Wenn ein Prozess einen neuen user namespace erstellt oder betritt, erhält er innerhalb dieses Namespaces ein vollständiges Capability-Set. Das bedeutet nicht, dass er plötzlich host-weite Macht erlangt hat. Es bedeutet, dass diese Capabilities nur dort verwendet werden können, wo das Namespace-Modell und andere Schutzmechanismen es erlauben. Deshalb kann `unshare -U` plötzlich das Mounten oder namespace-lokale privilegierte Operationen möglich machen, ohne die host-root-Grenze direkt verschwinden zu lassen.

## Fehlkonfigurationen

Die Hauptschwäche besteht einfach darin, user namespaces in Umgebungen nicht zu verwenden, wo sie möglich wären. Wenn container root zu direkt auf host root abgebildet wird, werden beschreibbare host-Mounts und privilegierte Kernel-Operationen deutlich gefährlicher. Ein weiteres Problem ist, das Teilen des host user namespace zu erzwingen oder Remapping für Kompatibilität zu deaktivieren, ohne zu erkennen, wie sehr das die Vertrauensgrenze verändert.

User namespaces müssen auch im Zusammenhang mit dem restlichen Modell betrachtet werden. Selbst wenn sie aktiv sind, kann eine weitreichende runtime-API-Exposition oder eine sehr schwache runtime-Konfiguration privilege escalation über andere Pfade ermöglichen. Ohne sie hingegen werden viele alte breakout-Klassen deutlich leichter ausnutzbar.

## Missbrauch

Wenn der Container rootful ist ohne user namespace-Trennung, wird ein beschreibbares host bind mount erheblich gefährlicher, weil der Prozess tatsächlich als host root schreiben könnte. Gefährliche Capabilities werden ebenso bedeutsamer. Der Angreifer muss nicht mehr so stark gegen die Übersetzungsgrenze kämpfen, weil diese kaum existiert.

Das Vorhandensein oder Fehlen von user namespaces sollte frühzeitig geprüft werden, wenn ein container breakout-Pfad bewertet wird. Es beantwortet nicht jede Frage, aber es zeigt sofort, ob "root in container" direkte Host-Relevanz hat.

Das praktischste Missbrauchsmuster ist, die Mapping zu bestätigen und dann sofort zu testen, ob host-mounted Inhalte mit host-relevanten Privilegien schreibbar sind:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Wenn die Datei als real host root erstellt wird, ist die Isolierung des user namespace für diesen Pfad effektiv nicht vorhanden. An diesem Punkt werden klassische host-file abuses realistisch:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Eine sicherere Bestätigung bei einem Live-Assessment ist, einen harmlosen Marker zu schreiben, anstatt kritische Dateien zu verändern:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Diese Checks sind wichtig, weil sie die eigentliche Frage schnell beantworten: Wird root in diesem Container eng genug auf das Host-root abgebildet, sodass ein writable host mount sofort zu einem host compromise path wird?

### Vollständiges Beispiel: Wiedererlangen namespace-lokaler Capabilities

Wenn seccomp `unshare` erlaubt und die Umgebung ein frisches user namespace zulässt, kann der Prozess innerhalb dieses neuen Namespaces ein vollständiges Capability-Set zurückgewinnen:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Das ist für sich genommen kein host escape. Der Grund, warum es relevant ist, ist, dass user namespaces privilegierte namespace-lokale Aktionen wieder ermöglichen können, die sich später mit schwachen Mounts, verwundbaren Kerneln oder schlecht exponierten Laufzeitoberflächen kombinieren.

## Checks

Diese Befehle sollen die wichtigste Frage auf dieser Seite beantworten: Welche Entsprechung hat root innerhalb dieses Containers auf dem Host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Was hier interessant ist:

- Wenn der Prozess UID 0 ist und die maps eine direkte oder sehr nahe host-root-Abbildung zeigen, ist der Container deutlich gefährlicher.
- Wenn root auf einen unprivilegierten Host-Bereich abgebildet ist, ist das eine deutlich sicherere Ausgangslage und deutet normalerweise auf echte user namespace isolation hin.
- Die mapping files sind wertvoller als `id` allein, weil `id` nur die namespace-lokale Identität zeigt.

Wenn der Workload als UID 0 läuft und die Abbildung zeigt, dass dies eng dem host-root entspricht, solltest du die übrigen Privilegien des Containers deutlich strenger interpretieren.
{{#include ../../../../../banners/hacktricks-training.md}}
