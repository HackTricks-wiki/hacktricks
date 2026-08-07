# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux ist ein **label-basiertes Mandatory Access Control (MAC)**-System. In der Praxis bedeutet das, dass der Kernel eine Aktion weiterhin verweigern kann, selbst wenn DAC-Berechtigungen, Gruppen oder Linux capabilities dafür ausreichend erscheinen, weil der **Quellkontext** nicht auf den **Zielkontext** mit der angeforderten Klasse/Berechtigung zugreifen darf.

Ein Kontext sieht normalerweise so aus:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Aus der Perspektive von `privesc` ist der `type` (Domain für Prozesse, Typ für Objekte) normalerweise das wichtigste Feld:

- Ein Prozess läuft in einer **domain** wie `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Dateien und Sockets haben einen **type** wie `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Die Policy entscheidet, ob eine Domain die andere lesen, schreiben, ausführen oder zu ihr wechseln darf

## Fast Enumeration

Wenn SELinux aktiviert ist, sollte es früh enumeriert werden, da es erklären kann, warum übliche Linux-privesc-Pfade fehlschlagen oder warum ein privilegierter Wrapper um ein scheinbar „harmloses“ SELinux-Tool tatsächlich kritisch ist:
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
Interessante Erkenntnisse:

- Der Modus `Disabled` oder `Permissive` nimmt SELinux als Grenze den größten Teil seines Nutzens.
- `unconfined_t` bedeutet normalerweise, dass SELinux vorhanden ist, den betreffenden Prozess aber nicht wesentlich einschränkt.
- `default_t`, `file_t` oder offensichtlich falsche Labels auf benutzerdefinierten Pfaden weisen häufig auf eine fehlerhafte Kennzeichnung oder eine unvollständige Bereitstellung hin.
- Lokale Überschreibungen in `file_contexts.local` haben Vorrang vor den Standardwerten der Policy. Prüfe sie daher sorgfältig.

## Richtlinienanalyse

SELinux lässt sich wesentlich leichter angreifen oder umgehen, wenn du zwei Fragen beantworten kannst:

1. **Auf welche Ressourcen kann meine aktuelle Domäne zugreifen?**
2. **In welche Domänen kann ich wechseln?**

Die nützlichsten Tools dafür sind `sepolicy` und **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)</sup>
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
Dies ist besonders nützlich, wenn ein Host **eingeschränkte Benutzer** verwendet, anstatt alle auf `unconfined_u` abzubilden. Suche in diesem Fall nach:<sup>[[3]](#references)</sup>

- user mappings über `semanage login -l`
- erlaubten Rollen über `semanage user -l`
- erreichbaren Admin-Domains wie `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers`-Einträgen mit `ROLE=` oder `TYPE=`

Wenn `sudo -l` Einträge wie diesen enthält, ist SELinux Teil der Privilege Boundary:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Prüfe außerdem, ob `newrole` verfügbar ist:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` und `newrole` sind nicht automatisch ausnutzbar. Wenn jedoch ein privilegierter Wrapper oder eine `sudoers`-Regel die Auswahl einer besseren Rolle/eines besseren Typs erlaubt, werden sie zu hochwertigen Escalation-Primitives.

## Dateien, Relabeling und hochwertige Fehlkonfigurationen

Der wichtigste operative Unterschied zwischen den gängigen SELinux-Tools ist:<sup>[[1]](#references)</sup>

- `chcon`: temporäre Änderung des Labels eines bestimmten Pfads
- `semanage fcontext`: persistente Pfad-zu-Label-Regel
- `restorecon` / `setfiles`: erneute Anwendung des Policy-/Standard-Labels

Das ist während der privesc besonders relevant, weil **Relabeling nicht nur kosmetischer Natur ist**. Dadurch kann eine Datei von „durch die Policy blockiert“ zu „für einen privilegierten confined Service lesbar/ausführbar“ werden.

Prüfe lokale Relabel-Regeln und Relabel-Abweichungen:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Ein subtiles, aber nützliches Detail: Einfaches `restorecon` setzt ein verdächtiges Label **nicht immer vollständig zurück**. Wenn sich der Zieltyp in `customizable_types` befindet, müssen Sie möglicherweise `-F` verwenden, um einen vollständigen Reset zu erzwingen. Aus offensiver Sicht erklärt dies, warum ein ungewöhnliches `chcon` manchmal eine oberflächliche Bereinigung nach dem Motto „wir haben restorecon bereits ausgeführt“ überstehen kann.
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Besonders relevante Befehle, nach denen in `sudo -l`, Root-Wrappern, Automatisierungsskripten oder File-Capabilities gesucht werden sollte:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Wenn eine der beiden MAC capabilities auftaucht, prüfe zusätzlich die [Linux capabilities page](linux-capabilities.md); `cap_mac_admin` und `cap_mac_override` sind ungewöhnlich, aber direkt relevant, wenn SELinux Teil der Grenze ist.

Besonders interessant:

- `semanage fcontext`: ändert dauerhaft, welches Label ein Pfad erhalten soll
- `restorecon` / `setfiles`: wendet diese Änderungen in großem Maßstab erneut an
- `semodule -i`: lädt ein benutzerdefiniertes policy module
- `semanage permissive -a <domain_t>`: macht eine Domain permissive, ohne den gesamten Host umzustellen
- `setsebool -P`: ändert policy booleans dauerhaft
- `load_policy`: lädt die aktive policy erneut

Das sind oft **Hilfsprimitiven** und keine eigenständigen root exploits. Ihr Wert besteht darin, dass sie Folgendes ermöglichen:

- eine Ziel-Domain permissive machen
- den Zugriff zwischen deiner Domain und einem geschützten Typ erweitern
- von einem Angreifer kontrollierte Dateien neu labeln, damit ein privilegierter Dienst sie lesen oder ausführen kann
- einen confined service so weit schwächen, dass ein vorhandener lokaler Bug ausnutzbar wird

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
Deshalb sollten `audit2allow`, `semodule` und `semanage permissive` während der post-exploitation als sensible Admin-Oberflächen behandelt werden. Sie können eine blockierte Kette unbemerkt in eine funktionierende umwandeln, ohne klassische UNIX-Berechtigungen zu ändern.

## Verborgene Denials und Module Extraction

Eine sehr häufige offensive Frustration ist eine Kette, die mit einem nichtssagenden `EACCES` fehlschlägt, während der erwartete AVC-Denial nicht erscheint. `dontaudit`-Regeln können die genau benötigte Berechtigung verbergen. Wenn du `semodule` über `sudo` oder einen anderen privilegierten Wrapper ausführen kannst, kann das vorübergehende Deaktivieren von `dontaudit` einen stillen Fehler in einen präzisen Hinweis auf die Policy verwandeln:<sup>[[4]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Dies ist auch nützlich, um zu überprüfen, was lokale Administratoren bereits geändert haben. Ein kleines benutzerdefiniertes Modul oder eine auf eine Domain beschränkte permissive rule ist häufig der Grund dafür, dass sich ein Zieldienst deutlich weniger restriktiv verhält, als die base policy vermuten lässt.

## Audit-Hinweise

AVC denials sind häufig ein offensives Signal und nicht nur defensives Rauschen. Sie zeigen dir:

- welches target object bzw. welcher type getroffen wurde
- welche permission verweigert wurde
- welche domain du derzeit kontrollierst
- ob eine kleine policy-Änderung die chain funktionsfähig machen würde
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Wenn ein lokaler Exploit oder ein Persistenzversuch trotz scheinbar ausreichender Root-DAC-Berechtigungen weiterhin mit `EACCES` oder ungewöhnlichen „permission denied“-Fehlern fehlschlägt, sollte SELinux normalerweise überprüft werden, bevor der Vektor verworfen wird.

## SELinux Users

Zusätzlich zu regulären Linux-Benutzern gibt es SELinux users. Jeder Linux-Benutzer wird im Rahmen der Policy einem SELinux user zugeordnet. Dadurch kann das System für verschiedene Accounts unterschiedliche erlaubte Rollen und Domains durchsetzen.<sup>[[3]](#references)</sup>

Kurze Prüfungen:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Auf vielen gängigen Systemen werden Benutzer `unconfined_u` zugeordnet, wodurch die praktische Wirkung der Benutzereinschränkung reduziert wird. In gehärteten Deployments können eingeschränkte Benutzer `sudo`, `su`, `newrole` und `runcon` jedoch wesentlich interessanter machen, da **der Escalation-Pfad davon abhängen kann, eine bessere SELinux-Rolle bzw. einen besseren SELinux-Typ anzunehmen, und nicht nur davon, UID 0 zu erhalten**. Denkt außerdem daran, dass einige eingeschränkte Benutzer `sudo`/`su` überhaupt nicht aufrufen können, sofern die Policy den zugrunde liegenden setuid-Übergang nicht ausdrücklich erlaubt. Ein Host mit `staff_u` + `sysadm_r` kann daher eine scheinbar unbedeutende Regel `sudo ROLE=` / `TYPE=` zur eigentlichen Privilege-Grenze machen.<sup>[[3]](#references)</sup>

## SELinux in Containern

Container-Runtimes starten Workloads üblicherweise in einer eingeschränkten Domain wie `container_t` und kennzeichnen Container-Inhalte mit `container_file_t`. Wenn ein Container-Prozess entkommt, aber weiterhin mit dem Container-Label läuft, können Schreibvorgänge auf dem Host trotzdem fehlschlagen, da die Label-Grenze intakt geblieben ist.

Kurzes Beispiel:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Der Teil `c647,c780` ist keine Dekoration. In vielen container deployments weisen runtimes dynamisch MCS-Kategorien zu, sodass zwei Prozesse, die unter `container_t` ausgeführt werden, weiterhin voneinander getrennt sind. Wenn ein Escape in einem Host-Namespace landet, aber den ursprünglichen Kategoriensatz beibehält, können Kategorieabweichungen weiterhin erklären, warum einige Host-Pfade nicht lesbar oder nicht beschreibbar sind.

Bemerkenswerte moderne container operations:

- `--security-opt label=disable` kann die Workload effektiv in einen unconfined container-related type wie `spc_t` verschieben
- bind mounts mit `:z` / `:Z` lösen ein Relabeling des Host-Pfads für die gemeinsame/private Nutzung durch Container aus
- ein weitreichendes Relabeling von Host-Inhalten kann selbst zu einem security issue werden

Diese Seite hält den Container-Inhalt kurz, um Duplikationen zu vermeiden. Für container-spezifische abuse cases und runtime examples siehe:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Referenzen

- [1] [Red Hat docs: SELinux verwenden](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Tools zur Policy-Analyse für SELinux](https://github.com/SELinuxProject/setools)
- [3] [Eingeschränkte und uneingeschränkte Benutzer verwalten - RHEL-9-Dokumentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/semodule.8.html)

{{#include ../../banners/hacktricks-training.md}}
