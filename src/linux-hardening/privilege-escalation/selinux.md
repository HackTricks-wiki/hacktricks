# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux ist ein **etikettenbasiertes Mandatory Access Control (MAC)-System**. In der Praxis bedeutet das, dass selbst wenn DAC-Berechtigungen, Gruppen oder Linux capabilities für eine Aktion ausreichend erscheinen, der Kernel sie trotzdem ablehnen kann, weil der **Quellkontext** nicht berechtigt ist, auf den **Zielkontext** mit der angeforderten Klasse/Berechtigung zuzugreifen.

Ein Kontext sieht üblicherweise so aus:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Aus Sicht der privesc ist der `type` (Domäne für Prozesse, Typ für Objekte) in der Regel das wichtigste Feld:

- Ein Prozess läuft in einer **Domäne** wie `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Dateien und Sockets haben einen **Typ** wie `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Die Policy entscheidet, ob eine Domäne die andere lesen/schreiben/ausführen oder zu ihr wechseln kann

## Fast Enumeration

Wenn SELinux aktiviert ist, enumerate es früh, da es erklären kann, warum gängige Linux privesc-Pfade fehlschlagen oder warum ein privilegierter Wrapper um ein "harmloses" SELinux-Tool tatsächlich kritisch ist:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Weiterführende Prüfungen:
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

- `Disabled` oder `Permissive`-Modus nehmen SELinux den größten Teil seines Werts als Sicherheitsgrenze.
- `unconfined_t` bedeutet normalerweise, dass SELinux vorhanden ist, den Prozess aber nicht nennenswert einschränkt.
- `default_t`, `file_t` oder offensichtlich falsche Labels auf benutzerdefinierten Pfaden deuten häufig auf Fehlkennzeichnung oder unvollständige Bereitstellung hin.
- Lokale Überschreibungen in `file_contexts.local` haben Vorrang vor Policy-Standardeinstellungen; prüfen Sie sie daher sorgfältig.

## Policy-Analyse

SELinux lässt sich deutlich leichter angreifen oder umgehen, wenn Sie zwei Fragen beantworten können:

1. **Worauf kann meine aktuelle Domain zugreifen?**
2. **In welche Domains kann ich wechseln?**

Die nützlichsten Werkzeuge dafür sind `sepolicy` und **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Das ist besonders nützlich, wenn ein Host **confined users** verwendet, anstatt alle auf `unconfined_u` abzubilden. In diesem Fall suche nach:

- Benutzerzuordnungen über `semanage login -l`
- erlaubten Rollen über `semanage user -l`
- erreichbaren Admin-Domänen wie `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers`-Einträgen, die `ROLE=` oder `TYPE=` verwenden

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
`runcon` and `newrole` sind nicht automatisch ausnutzbar, aber wenn ein privilegiertes Wrapper-Programm oder eine `sudoers`-Regel es dir erlaubt, eine bessere Rolle/Typ auszuwählen, werden sie zu wertvollen Eskalationsprimitiven.

## Dateien, Neukennzeichnung und sicherheitskritische Fehlkonfigurationen

Der wichtigste praktische Unterschied zwischen gängigen SELinux-Tools ist:

- `chcon`: temporäre Label-Änderung für einen bestimmten Pfad
- `semanage fcontext`: persistente Pfad-zu-Label-Regel
- `restorecon` / `setfiles`: wendet die Policy/Standard-Label erneut an

Das ist bei privesc sehr wichtig, weil **Neukennzeichnung nicht nur kosmetisch ist**. Sie kann eine Datei von "durch Policy blockiert" in "lesbar/ausführbar von einem privilegierten eingeschränkten Dienst" verwandeln.

Überprüfe lokale Relabel-Regeln und Abweichungen bei der Neukennzeichnung:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Befehle mit hohem Wert, nach denen man in `sudo -l`, root wrappers, automation scripts oder file capabilities suchen sollte:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Besonders interessant:

- `semanage fcontext`: ändert dauerhaft, welches Label ein Pfad erhalten soll
- `restorecon` / `setfiles`: wendet diese Änderungen großflächig erneut an
- `semodule -i`: lädt ein benutzerdefiniertes Policy-Modul
- `semanage permissive -a <domain_t>`: macht eine Domain permissiv, ohne den gesamten Host umzuschalten
- `setsebool -P`: ändert Policy-Booleans dauerhaft
- `load_policy`: lädt die aktive Policy neu

Dies sind oft **Hilfsprimitive**, keine eigenständigen Root-Exploits. Ihr Wert liegt darin, dass sie es Ihnen ermöglichen:

- eine Ziel-Domain permissiv machen
- den Zugriff zwischen Ihrer Domain und einem geschützten Typ erweitern
- angreiferkontrollierte Dateien umlabeln, damit ein privilegierter Dienst sie lesen oder ausführen kann
- einen eingeschränkten Dienst so schwächen, dass ein vorhandener lokaler Fehler ausnutzbar wird

Beispielprüfungen:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Wenn Sie als root ein Policy-Modul laden können, kontrollieren Sie in der Regel die SELinux-Grenze:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Deshalb sollten `audit2allow`, `semodule` und `semanage permissive` während der post-exploitation als sensible Admin-Oberflächen behandelt werden. Sie können eine blockierte Kette stillschweigend in eine funktionierende umwandeln, ohne die klassischen UNIX-Berechtigungen zu ändern.

## Audit-Hinweise

AVC denials sind oft ein offensives Signal, nicht nur defensives Rauschen. Sie sagen dir:

- welches Zielobjekt/-typ du getroffen hast
- welche Berechtigung verweigert wurde
- welche Domain du derzeit kontrollierst
- ob eine kleine Policy-Änderung die Kette funktionieren lassen würde
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Wenn ein lokaler Exploit oder Persistenzversuch wiederholt mit `EACCES` oder seltsamen "permission denied"-Fehlern fehlschlägt, obwohl die DAC-Berechtigungen wie Root-Berechtigungen aussehen, lohnt es sich in der Regel, SELinux zu prüfen, bevor man den Vektor verwirft.

## SELinux-Benutzer

Zusätzlich zu normalen Linux-Benutzern gibt es SELinux-Benutzer. Jeder Linux-Benutzer wird im Rahmen der Richtlinie einem SELinux-Benutzer zugeordnet, was dem System ermöglicht, verschiedenen Konten unterschiedliche erlaubte Rollen und Domains aufzuerlegen.

Schnelle Prüfungen:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Auf vielen Mainstream-Systemen werden Benutzer dem `unconfined_u` zugeordnet, was die praktische Wirkung der Benutzer-Einschränkung reduziert. Auf gehärteten Deployments können eingeschränkte Benutzer jedoch `sudo`, `su`, `newrole` und `runcon` deutlich interessanter machen, weil **der Eskalationspfad davon abhängen kann, in eine bessere SELinux-Rolle/Typ zu wechseln und nicht nur `UID 0` zu werden**.

## SELinux in Containers

Container-Runtimes starten üblicherweise Workloads in einer eingeschränkten Domain wie `container_t` und kennzeichnen Container-Inhalte als `container_file_t`. Wenn ein Container-Prozess entkommt, aber weiterhin mit dem Container-Label läuft, können Schreibzugriffe auf dem Host dennoch fehlschlagen, weil die Label-Grenze intakt geblieben ist.

Kurzes Beispiel:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Moderne Container-Operationen, die es zu beachten gilt:

- `--security-opt label=disable` kann die Workload effektiv in einen nicht eingeschränkten, containerbezogenen Typ wie `spc_t` verschieben
- bind mounts mit `:z` / `:Z` veranlassen ein Relabeling des Host-Pfads für gemeinsame/private Container-Nutzung
- Breites Relabeling von Host-Inhalten kann an sich zu einem Sicherheitsproblem werden

Diese Seite hält den Container-Inhalt kurz, um Duplikation zu vermeiden. Für container-spezifische Missbrauchsfälle und Laufzeitbeispiele siehe:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Referenzen

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
