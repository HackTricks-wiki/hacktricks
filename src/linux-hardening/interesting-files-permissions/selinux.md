# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux ist ein **labelbasiertes Mandatory Access Control (MAC)**-System. In der Praxis bedeutet das: Selbst wenn DAC-Berechtigungen, Gruppen oder Linux capabilities für eine Aktion ausreichend erscheinen, kann der Kernel sie dennoch verweigern, weil der **Quellkontext** nicht auf den **Zielkontext** mit der angeforderten Klasse/Berechtigung zugreifen darf.<sup>[[1]](#references)</sup>

Ein Kontext sieht üblicherweise so aus:<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Aus privesc-Sicht ist `type` (domain für Prozesse, type für Objekte) in der Regel das wichtigste Feld:<sup>[[1]](#references)</sup>

- Ein Prozess läuft in einer **Domain** wie `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Dateien und Sockets haben einen **Typ** wie `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Die Policy entscheidet, ob eine Domain die andere lesen, beschreiben, ausführen oder zu ihr wechseln darf

## Schnelle Enumeration

Wenn SELinux aktiviert ist, sollte es früh enumeriert werden, da sich dadurch erklären lässt, warum gängige Linux-privesc-Pfade fehlschlagen oder warum ein privilegierter Wrapper um ein „harmloses“ SELinux-Tool tatsächlich kritisch ist:<sup>[[1]](#references)</sup>

```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```

Nützliche Folgeprüfungen:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>

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

- Der Modus `Disabled` oder `Permissive` nimmt SELinux einen Großteil seiner Wirkung als Sicherheitsgrenze.
- `unconfined_t` bedeutet in der Regel, dass SELinux zwar vorhanden ist, den Prozess aber nicht wirksam einschränkt.
- `default_t`, `file_t` oder offensichtlich falsche Labels auf benutzerdefinierten Pfaden weisen oft auf eine fehlerhafte Kennzeichnung oder unvollständige Bereitstellung hin.
- Lokale Überschreibungen in `file_contexts.local` haben Vorrang vor den Richtlinienstandards und sollten daher sorgfältig geprüft werden.

## Richtlinienanalyse

SELinux lässt sich viel leichter angreifen oder umgehen, wenn du zwei Fragen beantworten kannst:

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

Dies ist besonders nützlich, wenn ein Host **eingeschränkte Benutzer** verwendet, anstatt alle `unconfined_u` zuzuordnen. In diesem Fall solltest du Folgendes prüfen:<sup>[[3]](#references)</sup>

- Benutzerzuordnungen über `semanage login -l`
- erlaubte Rollen über `semanage user -l`
- erreichbare Admin-Domains wie `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers`-Einträge mit `ROLE=` oder `TYPE=`

Wenn `sudo -l` Einträge wie diesen enthält, gehört SELinux zur Privilegiengrenze:<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

Prüfe außerdem, ob `newrole` verfügbar ist:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon` und `newrole` sind nicht automatisch ausnutzbar. Wenn jedoch ein privilegierter Wrapper oder eine `sudoers`-Regel die Auswahl einer geeigneteren Rolle/eines geeigneteren Typs ermöglicht, werden sie zu wertvollen Privilegieneskalationsprimitiven.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### Schreibbare Transition-Einstiegspunkte prüfen

Ein Transition-Graph ist lediglich ein Hinweis auf die Policy. Um daraus einen Angriffsweg zu machen, ermittle den ausführbaren Typ, der in eine nützlichere Domain wechselt, und prüfe anschließend, ob du eine Datei mit diesem Label ändern oder sie über ihr übergeordnetes Verzeichnis ersetzen kannst.<sup>[[9]](#references)[[20]](#references)</sup> Eine automatische `execve`-Transition erfordert eine passende `type_transition`-Regel, Execute-Zugriff auf die Quelldomain, `entrypoint`-Zugriff auf die Zieldomain und die Berechtigung, zwischen den Domains zu wechseln.<sup>[[20]](#references)</sup> Die Zieldomain kann SELinux-Zugriff erhalten, aber die Ausführung selbst ändert nicht die Linux-UID; prüfe [SUID/SGID and ACLs](suid-sgid-and-acl-triage.md) separat.<sup>[[20]](#references)[[21]](#references)</sup>

Verwende den gemeldeten Einstiegspunkt-Typ, um die zugrunde liegenden Regeln zu prüfen, und untersuche anschließend den Pfad und sein übergeordnetes Verzeichnis auf Schreibzugriff.<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

Korrelieren Sie den Entry-Point-Typ mit einem tatsächlichen ausführbaren Pfad. Prüfen Sie DAC, ACLs, SELinux-Schreibberechtigungen für die Datei oder das übergeordnete Verzeichnis, das Dateilabel und alle bedingten Booleans, bevor Sie davon ausgehen, dass eine Policy-Kante erreichbar ist.<sup>[[20]](#references)[[22]](#references)</sup> Wird ein Pfad ersetzt statt direkt bearbeitet, prüfen Sie den Kontext des neuen Inodes: Dateisystem-Labels werden als Extended Attributes gespeichert, und der Ersatz übernimmt möglicherweise nicht den Entry-Point-Typ.<sup>[[21]](#references)</sup> SELinux-fähige Programme können mit `setexeccon` einen Übergang anfordern. Das Fehlen einer automatischen `type_transition`-Regel schließt daher nicht jeden Übergang aus.<sup>[[20]](#references)</sup>

## Dateien, Relabeling und besonders kritische Fehlkonfigurationen

Der wichtigste praktische Unterschied zwischen gängigen SELinux-Tools ist:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: temporäre Label-Änderung für einen bestimmten Pfad
- `semanage fcontext`: dauerhafte Pfad-zu-Label-Regel
- `restorecon` / `setfiles`: Policy- bzw. Standard-Label erneut anwenden

Das ist bei privesc besonders wichtig, denn **Relabeling ist nicht nur kosmetisch**. Es kann eine Datei von „durch die Policy blockiert“ zu „für einen privilegierten, eingeschränkten Dienst lesbar/ausführbar“ machen.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Prüfen Sie lokale Relabel-Regeln und Abweichungen bei Labels:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

Ein subtiler, aber nützlicher Hinweis: Ein einfaches `restorecon` setzt ein verdächtiges Label **nicht immer vollständig zurück**. Wenn der Zieltyp in `customizable_types` enthalten ist, musst du möglicherweise `-F` verwenden, um einen vollständigen Reset zu erzwingen. Aus offensiver Sicht erklärt das, warum ein ungewöhnliches `chcon` manchmal eine beiläufige Bereinigung nach dem Motto „Wir haben `restorecon` bereits ausgeführt“ überstehen kann.<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

Besonders lohnende Befehle, nach denen man in `sudo -l`, root wrappers, Automatisierungsskripten oder Dateifähigkeiten suchen sollte:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

Wenn eine der beiden MAC-Fähigkeiten auftaucht, prüfe auch die [Linux capabilities page](linux-capabilities.md); die Dokumentation zu Linux capabilities beschreibt `cap_mac_admin` und `cap_mac_override` als Smack-spezifisch. Gehe also nicht davon aus, dass diese Namen allein SELinux umgehen.<sup>[[5]](#references)</sup>

Besonders interessant:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: ändert dauerhaft, welches Label ein Pfad erhalten soll
- `restorecon` / `setfiles`: wendet diese Änderungen massenhaft erneut an
- `semodule -i`: lädt ein benutzerdefiniertes policy module
- `semanage permissive -a <domain_t>`: setzt eine einzelne Domain auf permissive, ohne den gesamten Host umzustellen
- `setsebool -P`: ändert policy booleans dauerhaft
- `load_policy`: lädt die aktive policy neu

Oft sind dies **helper primitives**, keine eigenständigen root exploits. Ihr Nutzen besteht darin, dass sie Folgendes ermöglichen:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- eine Ziel-Domain auf permissive setzen
- den Zugriff zwischen deiner Domain und einem geschützten Typ erweitern
- vom Angreifer kontrollierte Dateien neu labeln, damit ein privilegierter Dienst sie lesen oder ausführen kann
- einen eingeschränkten Dienst so weit schwächen, dass eine vorhandene lokale Schwachstelle ausnutzbar wird

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

Deshalb sollten `audit2allow`, `semodule` und `semanage permissive` während der Post-Exploitation als sensible Admin-Schnittstellen behandelt werden. Sie können eine blockierte Kette unbemerkt funktionsfähig machen, ohne die klassischen UNIX-Berechtigungen zu ändern.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Verborgene Verweigerungen und Modulextraktion

Ein häufiges Ärgernis bei offensiven Tests ist eine Kette, die mit einem nichtssagenden `EACCES` fehlschlägt, während die erwartete AVC-Verweigerung nicht erscheint. `dontaudit`-Regeln können die genaue Berechtigung verbergen, die Sie benötigen. Wenn Sie `semodule` über `sudo` oder einen anderen privilegierten Wrapper ausführen können, lässt sich durch vorübergehendes Deaktivieren von `dontaudit` ein stiller Fehler in einen präzisen Hinweis auf die Richtlinie verwandeln:<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

Dies ist auch nützlich, um zu überprüfen, was lokale Administratoren bereits geändert haben. Ein kleines benutzerdefiniertes Modul oder eine permissive Regel für eine einzelne Domain ist oft der Grund dafür, dass sich ein Zieldienst deutlich weniger restriktiv verhält, als die Basispolicy vermuten lässt.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Audit-Hinweise

AVC-Denials sind oft ein offensives Signal und nicht nur defensives Rauschen. Sie verraten dir:<sup>[[1]](#references)[[15]](#references)</sup>

- welches Zielobjekt/welchen Typ du getroffen hast
- welche Berechtigung verweigert wurde
- welche Domain du derzeit kontrollierst
- ob eine kleine Policy-Änderung die Angriffskette zum Funktionieren bringen würde

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

Wenn ein lokaler Exploit- oder Persistenzversuch trotz DAC-Berechtigungen, die nach root aussehen, immer wieder mit `EACCES` oder seltsamen „permission denied“-Fehlern scheitert, lohnt es sich meist, SELinux zu prüfen, bevor man den Angriffsvektor verwirft.<sup>[[1]](#references)</sup>

## SELinux-Benutzer

Zusätzlich zu regulären Linux-Benutzern gibt es SELinux-Benutzer. Jeder Linux-Benutzer ist im Rahmen der Richtlinie einem SELinux-Benutzer zugeordnet. Dadurch kann das System verschiedenen Konten unterschiedliche Rollen und Domains zuweisen.<sup>[[3]](#references)</sup>

Schnellprüfungen:<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Auf vielen gängigen Systemen werden Benutzer `unconfined_u` zugeordnet, wodurch die praktische Wirkung der Benutzerbeschränkung abnimmt. Bei gehärteten Deployments können eingeschränkte Benutzer `sudo`, `su`, `newrole` und `runcon` jedoch deutlich interessanter machen, denn **der Eskalationspfad kann davon abhängen, eine bessere SELinux-Rolle/einen besseren SELinux-Typ anzunehmen, nicht nur davon, UID 0 zu werden**. Beachte außerdem, dass manche eingeschränkten Benutzer `sudo`/`su` gar nicht aufrufen können, sofern die Richtlinie den zugrunde liegenden setuid-Übergang nicht ausdrücklich erlaubt. Ein Host mit `staff_u` + `sysadm_r` kann daher eine scheinbar geringfügige `sudo ROLE=` / `TYPE=`-Regel zur eigentlichen Berechtigungsgrenze machen.<sup>[[3]](#references)</sup>

## SELinux in Containern

Container-Runtimes starten Workloads häufig in einer eingeschränkten Domain wie `container_t` und kennzeichnen Container-Inhalte mit `container_file_t`. Entkommt ein Container-Prozess, läuft aber weiterhin mit dem Container-Label, können Schreibzugriffe auf den Host dennoch scheitern, weil die Label-Grenze intakt geblieben ist.<sup>[[1]](#references)[[17]](#references)</sup>

Kurzes Beispiel:<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

Der Abschnitt `c647,c780` ist keine Dekoration. In vielen Container-Deployments weisen Runtimes dynamisch MCS-Kategorien zu, sodass zwei Prozesse, die als `container_t` laufen, weiterhin voneinander getrennt sind. Landest du nach einem Escape in einem Host-Namespace, behältst aber die ursprüngliche Kategoriegruppe bei, können Kategorieabweichungen immer noch erklären, warum einige Host-Pfade nicht lesbar oder beschreibbar sind.<sup>[[17]](#references)</sup>

Bemerkenswerte moderne Container-Operationen:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` deaktiviert die SELinux-Label-Trennung für den Container
- Bind-Mounts mit `:z` / `:Z` lösen ein Relabeling des Host-Pfads für die gemeinsame/private Verwendung durch Container aus
- Ein umfassendes Relabeling von Host-Inhalten kann selbst zu einem Sicherheitsproblem werden

Diese Seite hält den Container-Inhalt kurz, um Dopplungen zu vermeiden. Die containerspezifischen Missbrauchsfälle und Runtime-Beispiele findest du hier:

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
- [17] [Warum du Multi-Category Security für deine Linux-Container verwenden solltest](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman-top-Dokumentation](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/selinux.8.html)
- [20] [SELinux-Notebook: Domain- und Objektübergänge](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10: SELinux verwenden](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [SETools-sesearch(1)-Handbuch](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
