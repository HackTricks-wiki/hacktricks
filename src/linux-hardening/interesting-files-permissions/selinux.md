# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux ist ein **labelbasiertes Mandatory Access Control (MAC)**-System. In der Praxis bedeutet das, dass der Kernel eine Aktion weiterhin verweigern kann, selbst wenn DAC-Berechtigungen, Gruppen oder Linux capabilities dafür ausreichend erscheinen, weil der **Quellenkontext** nicht berechtigt ist, mit der angeforderten Klasse/Berechtigung auf den **Zielkontext** zuzugreifen.<sup>[[1]](#references)</sup>

Ein Kontext sieht normalerweise so aus:<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Aus Sicht von `privesc` ist der `type` (die Domain für Prozesse, der Typ für Objekte) normalerweise das wichtigste Feld:<sup>[[1]](#references)</sup>

- Ein Prozess läuft in einer **Domain** wie `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Dateien und Sockets haben einen **Typ** wie `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Die Policy entscheidet, ob eine Domain die andere lesen/schreiben/ausführen oder zu ihr wechseln kann

## Schnelle Enumeration

Wenn SELinux aktiviert ist, sollte es früh enumeriert werden, da dies erklären kann, warum gängige Linux-`privesc`-Pfade fehlschlagen oder warum ein privilegierter Wrapper um ein „harmloses“ SELinux-Tool tatsächlich kritisch ist:<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Nützliche weiterführende Überprüfungen:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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
Interessante Erkenntnisse:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- Der Modus `Disabled` oder `Permissive` nimmt SELinux als Grenze größtenteils seinen Nutzen.
- `unconfined_t` bedeutet normalerweise, dass SELinux vorhanden ist, den betreffenden Prozess aber nicht sinnvoll einschränkt.
- `default_t`, `file_t` oder offensichtlich falsche Labels auf benutzerdefinierten Pfaden weisen häufig auf eine falsche Label-Zuweisung oder eine unvollständige Bereitstellung hin.
- Lokale Überschreibungen in `file_contexts.local` haben Vorrang vor den Standardwerten der Policy, daher sollten sie sorgfältig geprüft werden.

## Policy-Analyse

SELinux lässt sich deutlich leichter angreifen oder umgehen, wenn du zwei Fragen beantworten kannst:

1. **Auf welche Ressourcen kann meine aktuelle Domain zugreifen?**
2. **In welche Domains kann ich wechseln?**

Die nützlichsten Tools dafür sind `sepolicy` und **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>
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
Dies ist besonders nützlich, wenn ein Host **eingeschränkte Benutzer** verwendet, anstatt alle auf `unconfined_u` abzubilden. Suchen Sie in diesem Fall nach:<sup>[[3]](#references)</sup>

- Benutzerzuordnungen über `semanage login -l`
- zulässigen Rollen über `semanage user -l`
- erreichbaren Admin-Domains wie `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers`-Einträgen mit `ROLE=` oder `TYPE=`

Wenn `sudo -l` Einträge wie diesen enthält, ist SELinux Teil der Privilegiengrenze:<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Prüfe außerdem, ob `newrole` verfügbar ist:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` und `newrole` sind nicht automatisch ausnutzbar. Wenn jedoch ein privilegierter Wrapper oder eine `sudoers`-Regel die Auswahl einer besseren Rolle bzw. eines besseren Typs ermöglicht, werden sie zu wertvollen Eskalationsprimitiven.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Dateien, Neulabeln und Fehlkonfigurationen mit hohem Wert

Der wichtigste operative Unterschied zwischen den gängigen SELinux-Tools ist:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: temporäre Labeländerung für einen bestimmten Pfad
- `semanage fcontext`: persistente Pfad-zu-Label-Regel
- `restorecon` / `setfiles`: das Policy-/Standardlabel erneut anwenden

Dies ist während der privesc besonders wichtig, weil **Neulabeln nicht nur kosmetischer Natur ist**. Dadurch kann eine Datei von „durch die Policy blockiert“ zu „für einen privilegierten eingeschränkten Service lesbar/ausführbar“ werden.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Prüfe lokale Neulabel-Regeln und Abweichungen bei der Labelzuweisung:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Ein subtiles, aber nützliches Detail: Einfaches `restorecon` setzt ein verdächtiges Label **nicht immer vollständig zurück**. Wenn sich der Zieltyp in `customizable_types` befindet, benötigen Sie möglicherweise `-F`, um einen vollständigen Reset zu erzwingen. Aus offensiver Sicht erklärt dies, warum ein ungewöhnliches `chcon` manchmal eine oberflächliche Bereinigung nach dem Motto „wir haben restorecon bereits ausgeführt“ überstehen kann.<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Besonders interessante Befehle, nach denen in `sudo -l`, Root-Wrappern, Automatisierungsskripten oder Datei-Capabilities gesucht werden sollte:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Wenn eine der beiden MAC-Capabilities auftaucht, prüfe auch die [Linux capabilities page](linux-capabilities.md); die Dokumentation zu Linux capabilities beschreibt `cap_mac_admin` und `cap_mac_override` als Smack-spezifisch. Gehe daher nicht davon aus, dass ihre Namen allein SELinux umgehen.<sup>[[5]](#references)</sup>

Besonders interessant:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: ändert dauerhaft, welches Label ein Pfad erhalten soll
- `restorecon` / `setfiles`: wendet diese Änderungen in großem Maßstab erneut an
- `semodule -i`: lädt ein benutzerdefiniertes Policy-Modul
- `semanage permissive -a <domain_t>`: versetzt eine einzelne Domain in den permissive-Modus, ohne den gesamten Host umzustellen
- `setsebool -P`: ändert Policy-Booleans dauerhaft
- `load_policy`: lädt die aktive Policy neu

Dies sind häufig **Hilfsprimitive** und keine eigenständigen Root-Exploits. Ihr Wert besteht darin, dass sie dir Folgendes ermöglichen:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- eine Ziel-Domain in den permissive-Modus zu versetzen
- den Zugriff zwischen deiner Domain und einem geschützten Typ auszuweiten
- von Angreifern kontrollierte Dateien neu zu labeln, damit ein privilegierter Dienst sie lesen oder ausführen kann
- einen confined Dienst so weit zu schwächen, dass ein bestehender lokaler Bug ausnutzbar wird

Beispielprüfungen:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Wenn du als root ein Policy-Modul laden kannst, kontrollierst du normalerweise die SELinux-Grenze:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Deshalb sollten `audit2allow`, `semodule` und `semanage permissive` während der post-exploitation als sensible administrative Angriffsflächen behandelt werden. Sie können eine blockierte Kette stillschweigend in eine funktionierende umwandeln, ohne klassische UNIX-Berechtigungen zu ändern.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Verborgene Denials und Modul-Extraktion

Eine sehr häufige offensive Frustration ist eine Kette, die mit einem nichtssagenden `EACCES` fehlschlägt, während die erwartete AVC denial nie erscheint. `dontaudit`-Regeln können genau die benötigte Berechtigung verbergen. Wenn du `semodule` über `sudo` oder einen anderen privilegierten Wrapper ausführen kannst, kann das vorübergehende Deaktivieren von `dontaudit` einen stillen Fehler in einen präzisen Hinweis auf die Policy verwandeln:<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Dies ist auch nützlich, um zu überprüfen, was lokale Administratoren bereits geändert haben. Ein kleines benutzerdefiniertes Modul oder eine permissive Regel für eine einzelne Domain ist oft der Grund dafür, dass sich ein Zieldienst deutlich weniger restriktiv verhält, als es die Basispolicy vermuten lässt.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Prüfhinweise

AVC-Denials sind oft ein offensives Signal und nicht nur defensives Rauschen. Sie zeigen dir:<sup>[[1]](#references)[[15]](#references)</sup>

- welches Zielobjekt/welcher Zieltyp betroffen war
- welche Berechtigung verweigert wurde
- welche Domain du derzeit kontrollierst
- ob eine kleine Policy-Änderung die Chain funktionsfähig machen würde
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Wenn ein lokaler Exploit oder ein Persistenzversuch weiterhin mit `EACCES` oder seltsamen „permission denied“-Fehlern fehlschlägt, obwohl die DAC-Berechtigungen nach Root aussehen, sollte man SELinux prüfen, bevor man den Vektor verwirft.<sup>[[1]](#references)</sup>

## SELinux-Benutzer

Zusätzlich zu regulären Linux-Benutzern gibt es SELinux-Benutzer. Jeder Linux-Benutzer wird im Rahmen der Policy einem SELinux-Benutzer zugeordnet, wodurch das System für verschiedene Konten unterschiedliche zulässige Rollen und Domains festlegen kann.<sup>[[3]](#references)</sup>

Schnellprüfungen:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Auf vielen gängigen Systemen werden Benutzer `unconfined_u` zugeordnet, wodurch die praktische Wirkung der Benutzer-Einschränkung reduziert wird. Bei gehärteten Deployments können eingeschränkte Benutzer `sudo`, `su`, `newrole` und `runcon` jedoch deutlich interessanter machen, da **der Eskalationspfad davon abhängen kann, eine bessere SELinux-Rolle bzw. einen besseren SELinux-Typ anzunehmen, und nicht nur davon, zu UID 0 zu werden**. Beachten Sie außerdem, dass einige eingeschränkte Benutzer `sudo`/`su` überhaupt nicht aufrufen können, sofern die Policy den zugrunde liegenden setuid-Übergang nicht ausdrücklich erlaubt. Ein Host mit `staff_u` + `sysadm_r` kann daher eine scheinbar unbedeutende `sudo ROLE=` / `TYPE=`-Regel zur eigentlichen Privilegiengrenze machen.<sup>[[3]](#references)</sup>

## SELinux in Containern

Container-Runtimes starten Workloads üblicherweise in einer eingeschränkten Domain wie `container_t` und versehen Container-Inhalte mit dem Label `container_file_t`. Falls ein Container-Prozess ausbricht, aber weiterhin mit dem Container-Label läuft, können Schreibvorgänge auf dem Host trotzdem fehlschlagen, da die Label-Grenze intakt geblieben ist.<sup>[[1]](#references)[[17]](#references)</sup>

Kurzes Beispiel:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Der Teil `c647,c780` ist keine Dekoration. In vielen Container-Bereitstellungen weisen Runtimes dynamisch MCS-Kategorien zu, sodass zwei Prozesse, die als `container_t` ausgeführt werden, weiterhin voneinander getrennt sind. Wenn ein Escape Sie in einen Host-Namespace bringt, aber den ursprünglichen Kategorie-Satz beibehält, können Kategorie-Abweichungen weiterhin erklären, warum einige Host-Pfade nicht lesbar oder beschreibbar bleiben.<sup>[[17]](#references)</sup>

Bemerkenswerte moderne Container-Operationen:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` deaktiviert die SELinux-Label-Trennung für den Container
- Bind-Mounts mit `:z` / `:Z` lösen eine erneute Label-Zuweisung des Host-Pfads für die gemeinsame/private Container-Nutzung aus
- Eine weitreichende erneute Label-Zuweisung von Host-Inhalten kann selbst zu einem Sicherheitsproblem werden

Diese Seite hält den Container-Inhalt kurz, um Duplikate zu vermeiden. Die containerspezifischen Missbrauchsfälle und Runtime-Beispiele finden Sie hier:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Red-Hat-Dokumentation: SELinux verwenden](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Tools zur Policy-Analyse für SELinux](https://github.com/SELinuxProject/setools)
- [3] [Eingeschränkte und uneingeschränkte Benutzer verwalten – RHEL-9-Dokumentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Podman-run-Dokumentation](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Warum Sie Multi-Category Security für Ihre Linux-Container verwenden sollten](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman-top-Dokumentation](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}
