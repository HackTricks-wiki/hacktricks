# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der User Namespace ändert die Bedeutung von User- und Group-IDs, indem der Kernel IDs, die innerhalb des Namespace sichtbar sind, auf andere IDs außerhalb davon abbildet. Dies ist eine der wichtigsten modernen Container-Schutzmaßnahmen, da sie direkt das größte historische Problem klassischer Container angeht: **root innerhalb des Containers war früher unangenehm nah an root auf dem Host**.

Mit User Namespaces kann ein Prozess als UID 0 innerhalb des Containers laufen und trotzdem einem unprivilegierten UID-Bereich auf dem Host entsprechen. Das bedeutet, dass sich der Prozess bei vielen Aufgaben innerhalb des Containers wie root verhalten kann, aus Sicht des Hosts jedoch deutlich weniger mächtig ist. Dies löst nicht jedes Container-Sicherheitsproblem, verändert aber die Folgen eines Container-Kompromisses erheblich.

## Funktionsweise

Ein User Namespace verfügt über Mapping-Dateien wie `/proc/self/uid_map` und `/proc/self/gid_map`, die beschreiben, wie Namespace-IDs auf IDs des übergeordneten Namespace abgebildet werden. Wenn root innerhalb des Namespace auf eine unprivilegierte Host-UID abgebildet wird, haben Operationen, die echtes root auf dem Host erfordern würden, schlicht nicht dasselbe Gewicht. Deshalb sind User Namespaces zentral für **rootless containers** und einer der größten Unterschiede zwischen älteren rootful container defaults und moderneren Least-Privilege-Designs.

Der Punkt ist subtil, aber entscheidend: root innerhalb des Containers wird nicht abgeschafft, sondern **übersetzt**. Der Prozess erlebt lokal weiterhin eine root-ähnliche Umgebung, aber der Host sollte ihn nicht als vollständiges root behandeln.

## Lab

Ein manueller Test ist:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Dadurch erscheint der aktuelle Benutzer innerhalb des Namespace als root, ohne außerhalb des Namespace weiterhin root auf dem Host zu sein. Dies ist eine der besten einfachen Demonstrationen, um zu verstehen, warum User-Namespaces so wertvoll sind.

In Containern kannst du das sichtbare Mapping vergleichen mit:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Die genaue Ausgabe hängt davon ab, ob die Engine User-Namespace-Remapping oder eine traditionellere rootful-Konfiguration verwendet.

Du kannst das Mapping auch von der Host-Seite aus mit folgendem Befehl auslesen:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Laufzeitverwendung

Rootless Podman ist eines der deutlichsten Beispiele dafür, dass User-Namespaces als erstklassiger Sicherheitsmechanismus behandelt werden. Rootless Docker hängt ebenfalls von ihnen ab. Dockers Unterstützung für `userns-remap` verbessert die Sicherheit auch bei rootful-Daemon-Deployments, obwohl sie aus Kompatibilitätsgründen in vielen Deployments historisch deaktiviert blieb. Die Unterstützung von Kubernetes für User-Namespaces wurde verbessert, aber Nutzung und Standardwerte unterscheiden sich je nach Runtime, Distro und Cluster-Richtlinie. Auch Incus/LXC-Systeme basieren stark auf UID/GID-Shifting- und Idmapping-Konzepten.

Der allgemeine Trend ist eindeutig: Umgebungen, die User-Namespaces ernsthaft einsetzen, beantworten die Frage „Was bedeutet Container-Root tatsächlich?“ normalerweise besser als Umgebungen, die dies nicht tun.

## Erweiterte Mapping-Details

Wenn ein unprivilegierter Prozess in `uid_map` oder `gid_map` schreibt, wendet der Kernel strengere Regeln an als bei einem privilegierten Writer im übergeordneten Namespace. Es sind nur begrenzte Mappings zulässig, und bei `gid_map` muss der Writer normalerweise zuerst `setgroups(2)` deaktivieren:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Dieses Detail ist wichtig, weil es erklärt, warum das Einrichten eines user namespace bei rootless-Experimenten manchmal fehlschlägt und warum Runtimes eine sorgfältige Helper-Logik für die UID/GID-Delegation benötigen.

Ein weiteres fortgeschrittenes Feature ist der **ID-mapped mount**. Statt den Besitz auf der Festplatte zu ändern, wendet ein ID-mapped mount ein user-namespace-Mapping auf einen Mount an, sodass der Besitz über diese Mount-Ansicht übersetzt erscheint. Das ist besonders in rootless- und modernen Runtime-Setups relevant, weil dadurch gemeinsam genutzte Host-Pfade verwendet werden können, ohne rekursive `chown`-Operationen auszuführen. Aus Sicherheitssicht verändert das Feature, wie schreibbar ein bind mount innerhalb des namespace erscheint, obwohl es die zugrunde liegenden Dateisystem-Metadaten nicht neu schreibt.

Denke schließlich daran, dass ein Prozess beim Erstellen oder Betreten eines neuen user namespace innerhalb **dieses namespace** einen vollständigen Capability-Satz erhält. Das bedeutet nicht, dass er plötzlich globale Berechtigungen auf dem Host erlangt hat. Es bedeutet, dass diese Capabilities nur dort verwendet werden können, wo das namespace-Modell und andere Schutzmechanismen dies erlauben. Aus diesem Grund kann `unshare -U` plötzlich das Mounten oder privilegierte, auf den namespace beschränkte Operationen ermöglichen, ohne dass dadurch die Root-Grenze des Hosts direkt verschwindet.

## Fehlkonfigurationen

Die größte Schwachstelle besteht schlicht darin, user namespaces in Umgebungen nicht zu verwenden, in denen sie praktikabel wären. Wenn Container-root zu direkt auf Host-root abgebildet wird, werden schreibbare Host-Mounts und privilegierte Kernel-Operationen deutlich gefährlicher. Ein weiteres Problem ist, das Teilen des user namespace des Hosts zu erzwingen oder das Remapping aus Kompatibilitätsgründen zu deaktivieren, ohne zu erkennen, wie stark dadurch die Trust Boundary verändert wird.

user namespaces müssen außerdem zusammen mit dem restlichen Modell betrachtet werden. Selbst wenn sie aktiv sind, können eine umfangreiche Runtime-API-Exposition oder eine sehr schwache Runtime-Konfiguration weiterhin eine Privilege Escalation über andere Pfade ermöglichen. Ohne sie lassen sich jedoch viele ältere Breakout-Klassen deutlich leichter ausnutzen.

## Missbrauch

Wenn der Container rootful und ohne user-namespace-Trennung ist, wird ein schreibbarer Host-bind mount deutlich gefährlicher, weil der Prozess möglicherweise tatsächlich als Host-root schreibt. Gefährliche Capabilities gewinnen ebenfalls an Bedeutung. Der Angreifer muss nicht mehr so stark gegen die Übersetzungsgrenze ankämpfen, weil diese praktisch kaum vorhanden ist.

Das Vorhandensein oder Fehlen eines user namespace sollte bei der Bewertung eines Container-Breakout-Pfads frühzeitig geprüft werden. Es beantwortet nicht jede Frage, zeigt aber sofort, ob „root im Container“ direkte Bedeutung für den Host hat.

Das praktischste Missbrauchsmuster besteht darin, das Mapping zu bestätigen und anschließend sofort zu testen, ob von Host eingebundene Inhalte mit für den Host relevanten Berechtigungen schreibbar sind:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Wenn die Datei als echter Host-root erstellt wird, ist die User-Namespace-Isolation für diesen Pfad effektiv nicht vorhanden. Ab diesem Punkt werden klassische Missbrauchswege von Host-Dateien realistisch:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Eine sicherere Bestätigung bei einem laufenden Assessment besteht darin, einen harmlosen Marker zu schreiben, statt kritische Dateien zu verändern:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Diese Checks sind wichtig, weil sie schnell die entscheidende Frage beantworten: Ist root in diesem Container dem root des Hosts so ähnlich zugeordnet, dass ein beschreibbarer Host-Mount unmittelbar zu einem Kompromittierungspfad des Hosts wird?

### Vollständiges Beispiel: Wiedererlangen von Namespace-lokalen Capabilities

Wenn seccomp `unshare` erlaubt und die Umgebung einen neuen User-Namespace zulässt, kann der Prozess innerhalb dieses neuen Namespace möglicherweise wieder einen vollständigen Capability-Satz erlangen:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Dies ist für sich genommen kein host escape. Der Grund, warum dies relevant ist: User namespaces können privilegierte, auf den jeweiligen Namespace beschränkte Aktionen erneut ermöglichen, die später mit schwachen Mounts, verwundbaren Kernels oder schlecht exponierten Runtime-Schnittstellen kombiniert werden.

## Checks

Diese Befehle sollen die wichtigste Frage auf dieser Seite beantworten: Auf welchen Benutzer auf dem Host wird root innerhalb dieses Containers abgebildet?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Was hier interessant ist:

- Wenn der Prozess UID 0 hat und die Maps eine direkte oder sehr nahe Zuordnung zu Host-root zeigen, ist der Container deutlich gefährlicher.
- Wenn root einer nicht privilegierten Host-Range zugeordnet wird, ist das eine wesentlich sicherere Ausgangsbasis und weist normalerweise auf eine echte User-Namespace-Isolation hin.
- Die Mapping-Dateien sind wertvoller als `id` allein, da `id` nur die Namespace-lokale Identität anzeigt.

Wenn die Workload als UID 0 ausgeführt wird und das Mapping zeigt, dass dies weitgehend Host-root entspricht, sollten Sie die übrigen Privilegien des Containers deutlich strenger bewerten.
{{#include ../../../../../banners/hacktricks-training.md}}
