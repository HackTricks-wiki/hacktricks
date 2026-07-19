# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux ist ein **labelbasiertes Mandatory Access Control (MAC)**-System. In der Praxis bedeutet dies, dass der Kernel eine Aktion weiterhin verweigern kann, selbst wenn DAC-Berechtigungen, Gruppen oder Linux capabilities dafür ausreichend erscheinen, weil der **Quellkontext** mit der angeforderten Klasse/Berechtigung nicht auf den **Zielkontext** zugreifen darf.

Ein Kontext sieht normalerweise folgendermaßen aus:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Aus der Perspektive von `privesc` ist der `type` (Domain für Prozesse, type für Objekte) normalerweise das wichtigste Feld:

- Ein Prozess läuft in einer **Domain** wie `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Dateien und Sockets haben einen **type** wie `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Die Policy entscheidet, ob eine Domain die andere lesen, schreiben, ausführen oder zu ihr übergehen kann

## Schnelle Enumeration

Wenn SELinux aktiviert ist, sollte es früh enumeriert werden, da es erklären kann, warum gewöhnliche Linux-privesc-Pfade fehlschlagen oder warum ein privilegierter Wrapper um ein „harmloses“ SELinux-Tool tatsächlich kritisch ist:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Nützliche weiterführende Prüfungen:
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
Interessante Befunde:

- Der Modus `Disabled` oder `Permissive` macht den Nutzen von SELinux als Grenze weitgehend zunichte.
- `unconfined_t` bedeutet normalerweise, dass SELinux vorhanden ist, den betreffenden Prozess jedoch nicht wirksam einschränkt.
- `default_t`, `file_t` oder offensichtlich falsche Labels auf benutzerdefinierten Pfaden weisen häufig auf eine falsche Beschriftung oder eine unvollständige Bereitstellung hin.
- Lokale Überschreibungen in `file_contexts.local` haben Vorrang vor den Standardwerten der Richtlinie. Überprüfe sie daher sorgfältig.

## Richtlinienanalyse

SELinux lässt sich wesentlich leichter angreifen oder umgehen, wenn du zwei Fragen beantworten kannst:

1. **Auf welche Ressourcen kann meine aktuelle Domäne zugreifen?**
2. **In welche Domänen kann ich wechseln?**

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
Dies ist besonders nützlich, wenn ein Host **confined users** verwendet, anstatt alle auf `unconfined_u` abzubilden. Suche in diesem Fall nach:

- user mappings über `semanage login -l`
- zulässigen Rollen über `semanage user -l`
- erreichbaren Admin-Domains wie `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers`-Einträgen mit `ROLE=` oder `TYPE=`

Wenn `sudo -l` Einträge wie diesen enthält, ist SELinux Teil der Privilegiengrenze:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Prüfe außerdem, ob `newrole` verfügbar ist:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` und `newrole` sind nicht automatisch ausnutzbar. Wenn jedoch ein privilegierter Wrapper oder eine `sudoers`-Regel die Auswahl einer besseren Rolle/eines besseren Typs erlaubt, werden sie zu besonders wertvollen Privilege-Escalation-Primitiven.

## Dateien, Relabeling und besonders wertvolle Fehlkonfigurationen

Der wichtigste operative Unterschied zwischen gängigen SELinux-Tools ist:

- `chcon`: temporäre Label-Änderung für einen bestimmten Pfad
- `semanage fcontext`: persistente Pfad-zu-Label-Regel
- `restorecon` / `setfiles`: Policy-/Standardlabel erneut anwenden

Das ist bei privesc besonders wichtig, weil **Relabeling nicht nur kosmetisch ist**. Es kann eine Datei von „durch die Policy blockiert“ in „für einen privilegierten, eingeschränkten Service lesbar/ausführbar“ umwandeln.

Prüfe lokale Relabel-Regeln und Abweichungen bei Relabels:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Ein subtiles, aber nützliches Detail: Ein einfaches `restorecon` setzt ein verdächtiges Label **nicht immer vollständig zurück**. Wenn sich der Zieltyp in `customizable_types` befindet, müssen Sie möglicherweise `-F` verwenden, um einen vollständigen Reset zu erzwingen. Aus offensiver Sicht erklärt dies, warum ein ungewöhnliches `chcon` manchmal eine oberflächliche Bereinigung nach dem Motto „wir haben bereits restorecon ausgeführt“ überstehen kann.
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Besonders wertvolle Befehle, nach denen in `sudo -l`, root wrappers, Automatisierungsskripten oder Datei-Capabilities gesucht werden sollte:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Wenn eine der beiden MAC-Capabilities auftaucht, prüfe zusätzlich die [Linux capabilities page](linux-capabilities.md); `cap_mac_admin` und `cap_mac_override` sind ungewöhnlich, aber direkt relevant, wenn SELinux Teil der Grenze ist.

Besonders interessant:

- `semanage fcontext`: ändert dauerhaft, welches Label ein Pfad erhalten soll
- `restorecon` / `setfiles`: wendet diese Änderungen in großem Maßstab erneut an
- `semodule -i`: lädt ein benutzerdefiniertes policy module
- `semanage permissive -a <domain_t>`: versetzt eine einzelne Domain in den permissive-Modus, ohne den gesamten Host umzuschalten
- `setsebool -P`: ändert policy booleans dauerhaft
- `load_policy`: lädt die aktive Policy neu

Dabei handelt es sich häufig um **helper primitives**, nicht um eigenständige root exploits. Ihr Wert besteht darin, dass sie Folgendes ermöglichen:

- eine Ziel-Domain in den permissive-Modus zu versetzen
- den Zugriff zwischen deiner Domain und einem geschützten Typ auszuweiten
- von Angreifern kontrollierte Dateien neu zu labeln, damit ein privilegierter Dienst sie lesen oder ausführen kann
- einen confined service so weit zu schwächen, dass eine bereits vorhandene lokale Schwachstelle ausnutzbar wird

Beispielprüfungen:
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
Deshalb sollten `audit2allow`, `semodule` und `semanage permissive` während der post-exploitation als sensible Admin-Oberflächen behandelt werden. Sie können eine blockierte Kette stillschweigend in eine funktionierende umwandeln, ohne klassische UNIX-Berechtigungen zu ändern.

## Verborgene Denials und Modulextraktion

Eine sehr häufige offensive Frustration ist eine Kette, die mit einem nichtssagenden `EACCES` fehlschlägt, während der erwartete AVC denial nicht erscheint. `dontaudit`-Regeln können genau die benötigte Berechtigung verbergen. Wenn du `semodule` über `sudo` oder einen anderen privilegierten Wrapper ausführen kannst, kann das vorübergehende Deaktivieren von `dontaudit` einen stillen Fehler in einen präzisen Policy-Hinweis umwandeln:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Dies ist auch nützlich, um zu überprüfen, was lokale Administratoren bereits geändert haben. Ein kleines benutzerdefiniertes Modul oder eine permissive Regel für eine einzelne Domain ist häufig der Grund dafür, dass sich ein Zieldienst wesentlich weniger restriktiv verhält, als die Basispolicy vermuten lässt.

## Audit-Hinweise

AVC-Denials sind häufig ein offensives Signal und nicht nur defensives Rauschen. Sie zeigen dir:

- welches Zielobjekt bzw. welcher Typ getroffen wurde
- welche Berechtigung verweigert wurde
- welche Domain du derzeit kontrollierst
- ob eine kleine Policy-Änderung die Chain funktionieren lassen würde
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Wenn ein lokaler Exploit oder ein Persistence-Versuch mit `EACCES` oder ungewöhnlichen „permission denied“-Fehlern weiterhin fehlschlägt, obwohl die DAC-Berechtigungen nach Root aussehen, sollte SELinux normalerweise überprüft werden, bevor der Vektor verworfen wird.

## SELinux Users

Zusätzlich zu regulären Linux-Benutzern gibt es SELinux-Benutzer. Jeder Linux-Benutzer wird im Rahmen der Policy einem SELinux-Benutzer zugeordnet. Dadurch kann das System für verschiedene Accounts unterschiedliche erlaubte Rollen und Domains durchsetzen.

Schnelle Prüfungen:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Auf vielen gängigen Systemen werden Benutzer `unconfined_u` zugeordnet, wodurch die praktischen Auswirkungen der Benutzerbeschränkung reduziert werden. Bei gehärteten Deployments können eingeschränkte Benutzer `sudo`, `su`, `newrole` und `runcon` jedoch deutlich interessanter machen, da **der Eskalationspfad davon abhängen kann, eine geeignetere SELinux-Rolle bzw. einen geeigneteren Typ anzunehmen, und nicht nur davon, zu UID 0 zu werden**. Denke außerdem daran, dass einige eingeschränkte Benutzer `sudo`/`su` überhaupt nicht ausführen können, sofern die Policy den zugrunde liegenden setuid-Übergang nicht ausdrücklich erlaubt. Daher kann ein Host mit `staff_u` + `sysadm_r` eine scheinbar geringfügige `sudo ROLE=` / `TYPE=`-Regel zur tatsächlichen Privilegiengrenze machen.

## SELinux in Containern

Container-Runtimes starten Workloads üblicherweise in einer eingeschränkten Domain wie `container_t` und versehen Container-Inhalte mit dem Label `container_file_t`. Wenn ein Container-Prozess ausbricht, aber weiterhin mit dem Container-Label läuft, können Schreibvorgänge auf dem Host dennoch fehlschlagen, da die Label-Grenze intakt geblieben ist.

Kurzes Beispiel:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Der Teil `c647,c780` ist keine Dekoration. In vielen Container-Deployments weisen Runtimes dynamisch MCS-Kategorien zu, sodass zwei als `container_t` laufende Prozesse weiterhin voneinander getrennt sind. Wenn ein Escape in einem Host-Namespace landet, aber den ursprünglichen Kategoriensatz beibehält, können Kategorieabweichungen weiterhin erklären, warum einige Host-Pfade nicht lesbar oder beschreibbar sind.

Bemerkenswerte moderne Container-Operationen:

- `--security-opt label=disable` kann die Workload effektiv in einen nicht eingeschränkten, Container-bezogenen Typ wie `spc_t` verschieben
- Bind-Mounts mit `:z` / `:Z` lösen ein Relabeling des Host-Pfads für die gemeinsame bzw. private Container-Nutzung aus
- Ein weitreichendes Relabeling von Host-Inhalten kann selbst zu einem Sicherheitsproblem werden

Diese Seite hält den Container-Inhalt kurz, um Duplikate zu vermeiden. Informationen zu den containerspezifischen Missbrauchsfällen und Runtime-Beispielen finden Sie unter:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Referenzen

- [Red Hat-Dokumentation: SELinux verwenden](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Tools zur Policy-Analyse für SELinux](https://github.com/SELinuxProject/setools)
- [Eingeschränkte und nicht eingeschränkte Benutzer verwalten – RHEL-9-Dokumentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
