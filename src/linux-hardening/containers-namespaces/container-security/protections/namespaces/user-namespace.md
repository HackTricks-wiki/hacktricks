# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der User Namespace ändert die Bedeutung von Benutzer- und Gruppen-IDs, indem der Kernel IDs innerhalb des Namespace auf andere IDs außerhalb davon abbilden lässt. Dies ist eine der wichtigsten modernen Container-Schutzmaßnahmen, da sie direkt das größte historische Problem klassischer Container angeht: **root innerhalb des Containers war früher unangenehm nah an root auf dem Host**.

Mit User Namespaces kann ein Prozess als UID 0 innerhalb des Containers ausgeführt werden und trotzdem einem nicht privilegierten UID-Bereich auf dem Host entsprechen. Das bedeutet, dass sich der Prozess bei vielen Aufgaben innerhalb des Containers wie root verhalten kann, aus Sicht des Hosts jedoch deutlich weniger mächtig ist. Dies löst nicht jedes Container-Sicherheitsproblem, verändert aber die Auswirkungen eines Container-Kompromisses erheblich.

## Funktionsweise

Ein User Namespace verfügt über Mapping-Dateien wie `/proc/self/uid_map` und `/proc/self/gid_map`, die beschreiben, wie Namespace-IDs in IDs des übergeordneten Namespace übersetzt werden. Wenn root innerhalb des Namespace auf eine nicht privilegierte Host-UID abgebildet wird, haben Vorgänge, die tatsächlich root auf dem Host erfordern würden, nicht dieselbe Tragweite. Deshalb sind User Namespaces zentral für **rootless containers** und einer der größten Unterschiede zwischen älteren rootful-Container-Standards und moderneren Least-Privilege-Designs.

Der Punkt ist subtil, aber entscheidend: root innerhalb des Containers wird nicht entfernt, sondern **übersetzt**. Der Prozess erlebt weiterhin lokal eine root-ähnliche Umgebung, aber der Host sollte ihn nicht als vollständigen root behandeln.

## Lab

Ein manueller Test ist:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Dadurch erscheint der aktuelle Benutzer innerhalb des Namespace als root, ist außerhalb davon auf dem Host jedoch weiterhin nicht root. Dies ist eines der besten einfachen Beispiele, um zu verstehen, warum user namespaces so wertvoll sind.

In Containern kannst du die sichtbare Zuordnung vergleichen mit:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Die genaue Ausgabe hängt davon ab, ob die Engine user namespace remapping oder eine eher traditionelle rootful-Konfiguration verwendet.

Du kannst das Mapping auch von der Host-Seite aus mit folgendem Befehl auslesen:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Laufzeitnutzung

Rootless Podman ist eines der deutlichsten Beispiele dafür, dass user namespaces als erstklassiger Sicherheitsmechanismus behandelt werden. Auch Rootless Docker ist von ihnen abhängig. Die Unterstützung von Docker für `userns-remap` verbessert die Sicherheit auch bei rootful Daemon-Bereitstellungen, obwohl sie in der Vergangenheit aus Kompatibilitätsgründen bei vielen Bereitstellungen deaktiviert blieb. Die Unterstützung von Kubernetes für user namespaces wurde verbessert, aber Verbreitung und Standardwerte unterscheiden sich je nach Runtime, Distribution und Cluster-Richtlinie. Incus/LXC-Systeme stützen sich ebenfalls stark auf das Verschieben von UID/GID und auf Konzepte des idmapping.

Der allgemeine Trend ist eindeutig: Umgebungen, die user namespaces ernsthaft einsetzen, beantworten die Frage „Was bedeutet Container-root tatsächlich?“ normalerweise besser als Umgebungen, die dies nicht tun.

## Erweiterte Mapping-Details

Wenn ein unprivilegierter Prozess in `uid_map` oder `gid_map` schreibt, wendet der Kernel strengere Regeln an als bei einem privilegierten Schreiber aus dem übergeordneten Namespace. Es sind nur begrenzte Mappings zulässig, und bei `gid_map` muss der Schreiber normalerweise zuerst `setgroups(2)` deaktivieren:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Dieses Detail ist wichtig, weil es erklärt, warum die Einrichtung von user namespaces bei rootless-Experimenten manchmal fehlschlägt und warum Runtimes eine sorgfältige Helper-Logik für die UID/GID-Delegation benötigen.

Eine weitere fortgeschrittene Funktion ist der **ID-mapped mount**. Anstatt die Besitzrechte auf der Festplatte zu ändern, wendet ein ID-mapped mount ein user-namespace-Mapping auf einen Mount an, sodass die Besitzrechte durch diese Mount-Ansicht übersetzt erscheinen. Dies ist besonders für rootless- und moderne Runtime-Setups relevant, da gemeinsam verwendete Host-Pfade dadurch ohne rekursive `chown`-Operationen genutzt werden können. Aus Sicherheitssicht verändert diese Funktion, wie schreibbar ein bind mount innerhalb des namespace erscheint, obwohl sie die zugrunde liegenden Metadaten des Dateisystems nicht neu schreibt.

Denke schließlich daran, dass ein Prozess beim Erstellen oder Betreten eines neuen user namespace innerhalb **dieses namespace** einen vollständigen Capability-Satz erhält. Das bedeutet nicht, dass er plötzlich globale Berechtigungen auf dem Host erhalten hat. Es bedeutet, dass diese Capabilities nur dort verwendet werden können, wo das namespace-Modell und andere Schutzmechanismen dies erlauben. Deshalb kann `unshare -U` plötzlich das Mounten oder privilegierte, auf den namespace beschränkte Operationen ermöglichen, ohne die Root-Grenze des Hosts direkt aufzuheben.

## Fehlkonfigurationen

Die größte Schwachstelle besteht schlicht darin, user namespaces in Umgebungen nicht zu verwenden, in denen dies möglich wäre. Wenn Container-root zu direkt auf Host-root abgebildet wird, werden schreibbare Host-Mounts und privilegierte Kernel-Operationen deutlich gefährlicher. Ein weiteres Problem ist, das Teilen des host user namespace zu erzwingen oder das Remapping aus Kompatibilitätsgründen zu deaktivieren, ohne zu erkennen, wie stark dies die Vertrauensgrenze verändert.

user namespaces müssen außerdem gemeinsam mit dem restlichen Modell betrachtet werden. Selbst wenn sie aktiv sind, können eine umfassende Runtime-API-Exponierung oder eine sehr schwache Runtime-Konfiguration weiterhin eine Privilege Escalation über andere Wege ermöglichen. Ohne sie lassen sich jedoch viele ältere Breakout-Klassen deutlich leichter ausnutzen.

## Missbrauch

Wenn der Container rootful und ohne user-namespace-Trennung ist, wird ein schreibbarer Host-bind mount deutlich gefährlicher, weil der Prozess möglicherweise tatsächlich als Host-root schreibt. Ebenso erhalten gefährliche Capabilities eine größere Bedeutung. Der Angreifer muss die Übersetzungsgrenze nicht mehr so stark überwinden, weil sie praktisch kaum vorhanden ist.

Das Vorhandensein oder Fehlen eines user namespace sollte bei der Bewertung eines Container-Breakout-Pfads frühzeitig überprüft werden. Dies beantwortet nicht jede Frage, zeigt aber sofort, ob „root im Container“ direkte Bedeutung für den Host hat.

Das praktischste Missbrauchsmuster besteht darin, das Mapping zu bestätigen und anschließend sofort zu prüfen, ob von Host eingebundene Inhalte mit für den Host relevanten Berechtigungen schreibbar sind:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Wenn die Datei als tatsächlicher Host-Root erstellt wird, ist die Isolation des User-Namespaces für diesen Pfad effektiv nicht vorhanden. Ab diesem Punkt werden klassische Ausnutzungen von Host-Dateien realistisch:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Eine sicherere Bestätigung bei einem laufenden Assessment besteht darin, einen harmlosen Marker zu schreiben, statt kritische Dateien zu verändern:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Diese Prüfungen sind wichtig, weil sie schnell die eigentliche Frage beantworten: Wird root in diesem Container so eng auf root des Hosts abgebildet, dass ein beschreibbarer Host-Mount unmittelbar zu einem Pfad für eine Kompromittierung des Hosts wird?

### Vollständiges Beispiel: Namespace-lokale Capabilities wiedererlangen

Wenn seccomp `unshare` zulässt und die Umgebung einen neuen User Namespace erlaubt, kann der Prozess innerhalb dieses neuen Namespace möglicherweise wieder einen vollständigen Capability-Satz erhalten:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Dies ist für sich genommen kein host escape. Der Grund, warum dies wichtig ist: User-Namespaces können privilegierte, auf den Namespace beschränkte Aktionen erneut ermöglichen, die später mit schwachen Mounts, verwundbaren Kernels oder unzureichend geschützten Runtime-Schnittstellen kombiniert werden.

## Prüfungen

Diese Befehle sollen die wichtigste Frage auf dieser Seite beantworten: Auf welchen Host-Benutzer wird root innerhalb dieses Containers abgebildet?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Was hier interessant ist:

- Wenn der Prozess UID 0 hat und die Maps eine direkte oder sehr nahe Zuordnung zu Host-Root zeigen, ist der Container deutlich gefährlicher.
- Wenn root einer nicht privilegierten Host-Range zugeordnet wird, ist das eine deutlich sicherere Ausgangsbasis und weist normalerweise auf eine echte User-Namespace-Isolierung hin.
- Die Mapping-Dateien sind wertvoller als `id` allein, da `id` nur die Namespace-lokale Identität anzeigt.

Wenn der Workload als UID 0 ausgeführt wird und das Mapping zeigt, dass dies weitgehend Host-Root entspricht, sollten Sie die übrigen Berechtigungen des Containers deutlich strenger bewerten.

{{#include ../../../../../banners/hacktricks-training.md}}
