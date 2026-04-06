# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux ist ein **etikettenbasiertes Mandatory Access Control (MAC)-System**. In der Praxis bedeutet das, dass selbst wenn DAC-Berechtigungen, Gruppen oder Linux capabilities für eine Aktion ausreichend erscheinen, der Kernel diese dennoch verweigern kann, weil der **Quellkontext** nicht berechtigt ist, auf den **Zielkontext** mit der angeforderten Klasse/Berechtigung zuzugreifen.

Ein Kontext sieht normalerweise so aus:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Aus privesc-Sicht ist der `type` (Domain für Prozesse, Typ für Objekte) normalerweise das wichtigste Feld:

- Ein Prozess läuft in einer **Domäne** wie `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Dateien und Sockets haben einen **Typ** wie `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Die Policy bestimmt, ob eine Domäne die andere lesen/schreiben/ausführen oder in sie übergehen darf

## Fast Enumeration

Wenn SELinux aktiviert ist, enumerate es frühzeitig, denn es kann erklären, warum gängige Linux privesc-Pfade fehlschlagen oder warum ein privilegierter Wrapper um ein „harmloses“ SELinux-Tool tatsächlich kritisch ist:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Nützliche Nachprüfungen:
```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```
Interessante Erkenntnisse:

- `Disabled` oder `Permissive`-Modus entfernt den Großteil des Nutzens von SELinux als Grenze.
- `unconfined_t` bedeutet normalerweise, dass SELinux vorhanden ist, diesen Prozess aber nicht nennenswert einschränkt.
- `default_t`, `file_t` oder offensichtlich falsche Labels auf benutzerdefinierten Pfaden deuten oft auf Fehlkennzeichnung oder unvollständige Bereitstellung hin.
- Lokale Überschreibungen in `file_contexts.local` haben Vorrang vor den Policy-Defaults, daher sorgfältig prüfen.

## Policy-Analyse

SELinux ist viel leichter anzugreifen oder zu umgehen, wenn man zwei Fragen beantworten kann:

1. **Auf welche Ressourcen kann meine aktuelle Domain zugreifen?**
2. **In welche Domains kann ich wechseln?**

Die dafür nützlichsten Tools sind `sepolicy` und **SETools** (`seinfo`, `sesearch`, `sedta`):
```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```
Das ist besonders nützlich, wenn ein Host **eingeschränkte Benutzer** verwendet, anstatt alle auf `unconfined_u` abzubilden. In diesem Fall suche nach:

- Benutzerzuordnungen mittels `semanage login -l`
- zulässige Rollen mittels `semanage user -l`
- erreichbare Admin-Domänen wie `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers`-Einträge mit `ROLE=` oder `TYPE=`

Wenn `sudo -l` Einträge wie diese enthält, ist SELinux Teil der Privilegien-Grenze:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Prüfe außerdem, ob `newrole` verfügbar ist:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` und `newrole` sind nicht automatisch ausnutzbar, aber wenn ein privilegierter Wrapper oder eine `sudoers`-Regel es dir erlaubt, eine bessere Rolle/Typ auszuwählen, werden sie zu hochgradig wertvollen escalation primitives.

## Dateien, Relabeling und High-Value-Fehlkonfigurationen

Der wichtigste praktische Unterschied zwischen gängigen SELinux-Tools ist:

- `chcon`: temporäre Label-Änderung für einen spezifischen Pfad
- `semanage fcontext`: persistente Pfad-zu-Label-Regel
- `restorecon` / `setfiles`: wendet die Policy/Standard-Labels wieder an

Das ist bei privesc sehr wichtig, weil **Relabeling nicht nur kosmetisch ist**. Es kann eine Datei von "durch die Richtlinie blockiert" in "lesbar/ausführbar durch einen privilegierten, eingeschränkten Dienst" verwandeln.

Prüfe lokale Relabel-Regeln und Abweichungen beim Relabeling:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Besonders wertvolle Befehle, nach denen man in `sudo -l`, root wrappers, Automatisierungsskripten oder file capabilities suchen sollte:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Besonders interessant:

- `semanage fcontext`: ändert dauerhaft, welches Label ein Pfad erhalten soll
- `restorecon` / `setfiles`: wendet diese Änderungen in größerem Maßstab erneut an
- `semodule -i`: lädt ein benutzerdefiniertes Policy-Modul
- `semanage permissive -a <domain_t>`: versetzt eine Domain in den permissive-Modus, ohne den gesamten Host umzuschalten
- `setsebool -P`: ändert Policy-Boolean-Werte dauerhaft
- `load_policy`: lädt die aktive Policy neu

Dies sind oft **Hilfsprimitive**, keine eigenständigen root exploits. Ihr Wert liegt darin, dass sie es Ihnen ermöglichen:

- eine Ziel-Domain permissive zu machen
- den Zugriff zwischen Ihrer Domain und einem geschützten Typ zu erweitern
- vom Angreifer kontrollierte Dateien so umzulabeln, dass ein privilegierter Service sie lesen oder ausführen kann
- einen eingeschränkten Service so weit abzuschwächen, dass ein vorhandener lokaler Bug ausnutzbar wird

Beispielchecks:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Wenn du als root ein Policy-Modul laden kannst, kontrollierst du normalerweise die SELinux-Grenze:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Das ist der Grund, warum `audit2allow`, `semodule` und `semanage permissive` während der post-exploitation als sensible Admin-Oberflächen behandelt werden sollten. Sie können stillschweigend eine blockierte Kette in eine funktionierende umwandeln, ohne die klassischen UNIX-Berechtigungen zu ändern.

## Audit-Hinweise

AVC denials sind oft ein offensives Signal, nicht nur defensives Rauschen. Sie sagen Ihnen:

- welches Zielobjekt/-typ Sie getroffen haben
- welche Berechtigung verweigert wurde
- welche Domain Sie derzeit kontrollieren
- ob eine kleine Policy-Änderung die Kette funktionieren lassen würde
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Wenn ein lokaler Exploit- oder Persistenzversuch wiederholt mit `EACCES` oder seltsamen "permission denied"-Fehlern fehlschlägt, obwohl die DAC-Berechtigungen wie Root aussehen, lohnt es sich in der Regel, SELinux zu überprüfen, bevor man den Vektor verwirft.

## SELinux-Benutzer

Zusätzlich zu normalen Linux-Benutzern gibt es SELinux-Benutzer. Jeder Linux-Benutzer wird als Teil der Policy einem SELinux-Benutzer zugeordnet, wodurch das System verschiedenen Konten unterschiedliche erlaubte Rollen und Domains zuweisen kann.

Kurze Prüfungen:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Auf vielen gängigen Systemen werden Benutzer auf `unconfined_u` abgebildet, was die praktische Wirkung der Benutzer-Einschränkung verringert. In gehärteten Umgebungen können eingeschränkte Benutzer jedoch `sudo`, `su`, `newrole` und `runcon` deutlich interessanter machen, weil **der Eskalationspfad davon abhängen kann, in eine bessere SELinux-Rolle/-Type zu wechseln und nicht nur darin besteht, UID 0 zu werden**.

## SELinux in Containern

Container-Runtimes starten üblicherweise Workloads in einer eingeschränkten Domäne wie `container_t` und kennzeichnen Container-Inhalte als `container_file_t`. Wenn ein Container-Prozess entkommt, aber weiterhin mit dem Container-Label läuft, können Schreibzugriffe auf dem Host trotzdem fehlschlagen, weil die Label-Grenze intakt geblieben ist.

Kurzes Beispiel:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Wichtige aktuelle Container-Operationen:

- `--security-opt label=disable` kann die Workload effektiv in einen unkonfinierten, container-bezogenen Typ wie `spc_t` verschieben
- Bind-Mounts mit `:z` / `:Z` lösen eine Neukennzeichnung des Host-Pfads für gemeinsame/private Container-Nutzung aus
- Weitreichende Neukennzeichnung von Host-Inhalten kann selbst ein Sicherheitsproblem darstellen

Diese Seite hält die Container-Inhalte kurz, um Duplikation zu vermeiden. Für container-spezifische Missbrauchsfälle und Laufzeitbeispiele siehe:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Referenzen

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
