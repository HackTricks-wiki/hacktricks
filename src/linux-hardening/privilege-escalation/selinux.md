# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux ist ein **label-based Mandatory Access Control (MAC)**-System. In der Praxis bedeutet das, dass selbst wenn DAC-Berechtigungen, Gruppen oder Linux-Capabilities für eine Aktion ausreichend erscheinen, der Kernel sie dennoch verweigern kann, weil der **source context** nicht berechtigt ist, auf den **target context** mit der angeforderten class/permission zuzugreifen.

Ein context sieht normalerweise so aus:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Aus privesc-Sicht ist der `type` (Domain für Prozesse, Typ für Objekte) meist das wichtigste Feld:

- Ein Prozess läuft in einer **Domain** wie `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Dateien und sockets haben einen **type** wie `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Die Policy entscheidet, ob eine Domain die andere lesen/schreiben/ausführen/transitionen darf

## Fast Enumeration

Wenn SELinux aktiviert ist, dann enumere es früh, weil es erklären kann, warum gängige Linux privesc-Pfade scheitern oder warum ein privilegierter Wrapper um ein "harmless" SELinux-Tool tatsächlich kritisch ist:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Nützliche weitere Prüfungen:
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

- `Disabled` oder `Permissive` Mode entfernt den Großteil des Werts von SELinux als Grenze.
- `unconfined_t` bedeutet meist, dass SELinux vorhanden ist, aber diesen Prozess nicht sinnvoll einschränkt.
- `default_t`, `file_t` oder offensichtlich falsche Labels auf benutzerdefinierten Pfaden deuten oft auf Fehl-Labeling oder unvollständiges Deployment hin.
- Lokale Overrides in `file_contexts.local` haben Vorrang vor den Policy-Defaults, daher sollten sie sorgfältig geprüft werden.

## Policy Analysis

SELinux ist viel einfacher anzugreifen oder zu umgehen, wenn du zwei Fragen beantworten kannst:

1. **Auf was kann mein aktueller domain zugreifen?**
2. **In welche domains kann ich wechseln?**

Die nützlichsten Tools dafür sind `sepolicy` und **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Das ist besonders nützlich, wenn ein Host **confined users** verwendet, anstatt alle auf `unconfined_u` abzubilden. In diesem Fall achte auf:

- User-Mappings via `semanage login -l`
- erlaubte Rollen via `semanage user -l`
- erreichbare Admin-Domains wie `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers`-Einträge mit `ROLE=` oder `TYPE=`

Wenn `sudo -l` Einträge wie diese enthält, ist SELinux Teil der Privilege Boundary:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Prüfe auch, ob `newrole` verfügbar ist:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` und `newrole` sind nicht automatisch ausnutzbar, aber wenn ein privilegierter Wrapper oder eine `sudoers`-Regel es dir erlaubt, eine bessere role/type auszuwählen, werden sie zu hochwertigen Privilege-Escalation-Primitives.

## Files, Relabeling, and High-Value Misconfigurations

Der wichtigste operative Unterschied zwischen gängigen SELinux-Tools ist:

- `chcon`: temporäre Label-Änderung auf einem bestimmten Pfad
- `semanage fcontext`: persistente path-to-label-Regel
- `restorecon` / `setfiles`: wendet die policy/default label erneut an

Das ist während privesc sehr wichtig, weil **relabeling nicht nur kosmetisch ist**. Es kann eine Datei von "durch policy blockiert" in "lesbar/ausführbar durch einen privilegierten confined service" verwandeln.

Prüfe auf lokale relabel-Regeln und relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Ein subtiler, aber nützlicher Punkt: Ein einfaches `restorecon` macht **nicht immer** ein verdächtiges Label vollständig rückgängig. Wenn der Zieltyp in `customizable_types` ist, kann `-F` nötig sein, um ein vollständiges Zurücksetzen zu erzwingen. Aus offensiver Sicht erklärt das, warum ein ungewöhnliches `chcon` manchmal ein oberflächliches „wir haben doch schon `restorecon` ausgeführt“-Cleanup überstehen kann.
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Wertvolle Befehle, nach denen in `sudo -l`, root-Wrappers, Automatisierungsskripten oder File Capabilities gesucht werden sollte:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Wenn eine MAC-Fähigkeit auftaucht, gleiche auch die [Linux capabilities page](linux-capabilities.md) ab; `cap_mac_admin` und `cap_mac_override` sind ungewöhnlich, aber direkt relevant, wenn SELinux Teil der Boundary ist.

Besonders interessant:

- `semanage fcontext`: ändert dauerhaft, welches Label ein Path erhalten soll
- `restorecon` / `setfiles`: wendet diese Änderungen in großem Maßstab erneut an
- `semodule -i`: lädt ein benutzerdefiniertes Policy-Modul
- `semanage permissive -a <domain_t>`: macht eine Domain permissive, ohne den ganzen Host umzustellen
- `setsebool -P`: ändert Policy-Booleans dauerhaft
- `load_policy`: lädt die aktive Policy neu

Das sind oft **helper primitives**, keine eigenständigen Root-Exploits. Ihr Wert liegt darin, dass sie dir erlauben:

- eine Ziel-Domain permissive zu machen
- den Zugriff zwischen deiner Domain und einem geschützten Type zu erweitern
- vom Angreifer kontrollierte Dateien neu zu labeln, damit ein privilegierter Service sie lesen oder ausführen kann
- einen eingeschränkten Service so weit zu schwächen, dass ein bestehender lokaler Bug ausnutzbar wird

Beispielprüfungen:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Wenn du ein Policy-Modul als root laden kannst, kontrollierst du normalerweise die SELinux-Grenze:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Deshalb sollten `audit2allow`, `semodule` und `semanage permissive` während der post-exploitation als sensible Admin-Surfaces behandelt werden. Sie können eine blockierte Kette lautlos in eine funktionierende umwandeln, ohne klassische UNIX-Berechtigungen zu ändern.

## Hidden Denials and Module Extraction

Eine sehr häufige offensive Frustration ist eine Kette, die mit einem unscheinbaren `EACCES` fehlschlägt, während die erwartete AVC-Denial nie erscheint. `dontaudit`-Rules können genau die Berechtigung verbergen, die du brauchst. Wenn du `semodule` über `sudo` oder einen anderen privilegierten Wrapper ausführen kannst, kann das vorübergehende Deaktivieren von `dontaudit` einen lautlosen Fehler in einen präzisen Policy-Hinweis verwandeln:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Dies ist auch nützlich, um zu überprüfen, was lokale Admins bereits geändert haben. Ein kleines custom module oder eine one-domain permissive rule ist oft der Grund dafür, dass sich ein Ziel-Service deutlich lockerer verhält, als es die base policy vermuten lässt.

## Audit Clues

AVC denials sind oft offensives Signal, nicht nur defensives Rauschen. Sie sagen dir:

- welches target object/type du getroffen hast
- welche permission verweigert wurde
- welchen domain du aktuell kontrollierst
- ob eine kleine policy Änderung die chain zum Laufen bringen würde
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Wenn ein lokaler Exploit oder ein Persistence-Versuch immer wieder mit `EACCES` oder seltsamen "permission denied"-Fehlern scheitert, obwohl die DAC-Berechtigungen wie root aussehen, lohnt es sich normalerweise, SELinux zu prüfen, bevor du den Vektor verwirfst.

## SELinux Users

Es gibt SELinux users zusätzlich zu den normalen Linux users. Jeder Linux user wird im Rahmen der policy einem SELinux user zugeordnet, wodurch das System unterschiedlichen Accounts verschiedene erlaubte roles und domains zuweisen kann.

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Auf vielen gängigen Systemen werden Benutzer auf `unconfined_u` abgebildet, wodurch sich die praktische Auswirkung von user confinement verringert. Auf gehärteten Deployments können jedoch confined users `sudo`, `su`, `newrole` und `runcon` deutlich interessanter machen, weil **der escalation path davon abhängen kann, in eine bessere SELinux role/type zu wechseln, nicht nur davon, UID 0 zu werden**. Denk außerdem daran, dass manche confined users `sudo`/`su` überhaupt nicht aufrufen können, sofern die policy den zugrunde liegenden setuid-Transition nicht ausdrücklich erlaubt. Daher kann ein Host mit `staff_u` + `sysadm_r` eine scheinbar kleine `sudo ROLE=` / `TYPE=`-Regel zur eigentlichen privilege boundary machen.

## SELinux in Containers

Container runtimes starten Workloads häufig in einer confined domain wie `container_t` und labeln Container-Inhalte als `container_file_t`. Wenn ein Container-Prozess entkommt, aber weiterhin mit dem Container-Label läuft, können Host-Writes trotzdem fehlschlagen, weil die label boundary intakt geblieben ist.

Quick example:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Der `c647,c780`-Teil ist nicht Dekoration. In vielen Container-Deployments weisen Runtimes MCS-Kategorien dynamisch zu, damit zwei Prozesse, die als `container_t` laufen, trotzdem voneinander getrennt bleiben. Wenn ein Escape dich in einen Host-Namespace bringt, aber die ursprüngliche Kategorie-Menge beibehält, können Kategorie-Mismatches weiterhin erklären, warum einige Host-Pfade nicht lesbar oder nicht beschreibbar bleiben.

Wichtige moderne Container-Operationen:

- `--security-opt label=disable` kann den Workload effektiv in einen unconfined Container-bezogenen Typ wie `spc_t` verschieben
- bind mounts mit `:z` / `:Z` lösen ein Relabeling des Host-Pfads für gemeinsame/private Container-Nutzung aus
- weitreichendes Relabeling von Host-Inhalten kann für sich genommen zu einem Sicherheitsproblem werden

Diese Seite hält den Container-Content kurz, um Duplikate zu vermeiden. Für die container-spezifischen Abuse-Fälle und Runtime-Beispiele siehe:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
