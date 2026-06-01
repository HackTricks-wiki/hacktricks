# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux is 'n **etiket-gebaseerde Mandatory Access Control (MAC)** stelsel. In die praktyk beteken dit dat selfs al lyk DAC-toestemmings, groepe, of Linux capabilities genoeg vir 'n aksie, die kernel dit steeds kan weier omdat die **source context** nie toegelaat word om toegang te kry tot die **target context** met die aangevraagde class/permission nie.

'n context lyk gewoonlik so:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Van 'n privesc-perspektief is die `type` (domain vir prosesse, type vir objekte) gewoonlik die belangrikste veld:

- ’n Proses loop in ’n **domain** soos `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Lêers en sockets het ’n **type** soos `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Beleid besluit of een domain die ander kan lees/skryf/uitvoer/transition na

## Fast Enumeration

As SELinux geaktiveer is, enumereer dit vroeg, want dit kan verduidelik hoekom algemene Linux privesc paths misluk of hoekom ’n geprivilegieerde wrapper rondom ’n "harmless" SELinux tool eintlik krities is:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Nuttige opvolgkontroles:
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
Interessante bevindings:

- `Disabled` of `Permissive` mode verwyder die meeste van die waarde van SELinux as 'n grens.
- `unconfined_t` beteken gewoonlik SELinux is teenwoordig maar beperk daardie proses nie betekenisvol nie.
- `default_t`, `file_t`, of duidelik verkeerde labels op custom paths dui dikwels op mislabeling of onvolledige deployment.
- Local overrides in `file_contexts.local` kry voorkeur bo policy defaults, so review hulle versigtig.

## Policy Analysis

SELinux is baie makliker om aan te val of te bypass wanneer jy twee vrae kan beantwoord:

1. **What can my current domain access?**
2. **What domains can I transition into?**

Die nuttigste tools hiervoor is `sepolicy` en **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Dit is veral nuttig wanneer 'n gasheer **confined users** gebruik eerder as om almal na `unconfined_u` te karteer. In daardie geval, soek na:

- user mappings via `semanage login -l`
- toegelate roles via `semanage user -l`
- bereikbare admin domains soos `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers` inskrywings wat `ROLE=` of `TYPE=` gebruik

As `sudo -l` inskrywings soos hierdie bevat, is SELinux deel van die privilege boundary:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Kontroleer ook of `newrole` beskikbaar is:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` en `newrole` is nie outomaties uitbuitbaar nie, maar as 'n bevoorregte wrapper of 'n `sudoers`-reël jou toelaat om 'n beter role/type te kies, word hulle hoë-waarde eskalasie-primitive.

## Files, Relabeling, and High-Value Misconfigurations

Die belangrikste operasionele verskil tussen algemene SELinux tools is:

- `chcon`: tydelike label-verandering op 'n spesifieke path
- `semanage fcontext`: permanente path-to-label-reël
- `restorecon` / `setfiles`: pas die policy/default label weer toe

Dit maak baie saak tydens privesc omdat **relabeling nie net kosmeties is nie**. Dit kan 'n file van "geblokkeer deur policy" na "leesbaar/uitvoerbaar deur 'n bevoorregte confined service" verander.

Kontroleer vir local relabel-reëls en relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Een subtiele maar nuttige detail: gewone `restorecon` keer **nie altyd heeltemal 'n verdagte label terug nie**. As die teikentipe in `customizable_types` is, kan jy `-F` nodig hê om 'n volledige reset af te dwing. Vanuit 'n offensiewe perspektief verduidelik dit hoekom 'n ongewone `chcon` soms 'n oppervlakkige "ons het reeds `restorecon` gedraai" skoonmaak kan oorleef.
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Hoëwaarde-opdragte om na te soek in `sudo -l`, root wrappers, automation scripts, of file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
As enige MAC-vermoë opduik, kruis-tjek ook die [Linux capabilities page](linux-capabilities.md); `cap_mac_admin` en `cap_mac_override` is ongewoon maar direk relevant wanneer SELinux deel van die grens is.

Veral interessant:

- `semanage fcontext`: verander permanent watter label ’n pad moet ontvang
- `restorecon` / `setfiles`: pas daardie veranderinge weer op skaal toe
- `semodule -i`: laai ’n pasgemaakte policy module
- `semanage permissive -a <domain_t>`: maak een domain permissive sonder om die hele host om te skakel
- `setsebool -P`: verander policy booleans permanent
- `load_policy`: herlaai die aktiewe policy

Hierdie is dikwels **helper primitives**, nie selfstandige root exploits nie. Hulle waarde is dat hulle jou laat:

- maak ’n teikendomain permissive
- verbreed toegang tussen jou domain en ’n beskermde type
- herlabel attacker-controlled files sodat ’n bevoorregte service hulle kan lees of execute
- verswak ’n confined service genoeg sodat ’n bestaande local bug exploiteerbaar word

Voorbeeld-kontroles:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
As jy ’n policy module as root kan laai, beheer jy gewoonlik die SELinux-grens:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Dit is hoekom `audit2allow`, `semodule`, en `semanage permissive` as sensitiewe admin-oppervlaktes tydens post-exploitation behandel moet word. Hulle kan stilweg ’n geblokkeerde ketting in ’n werkende een verander sonder om klassieke UNIX-toestemmings te verander.

## Verborge Weierings en Module-onttrekking

’n Baie algemene offensiewe frustrasie is ’n ketting wat faal met ’n vae `EACCES` terwyl die verwagte AVC-weiering nooit verskyn nie. `dontaudit`-reëls kan die presiese toestemming wat jy nodig het, versteek. As jy `semodule` deur `sudo` of ’n ander geprivilegieerde wrapper kan uitvoer, kan die tydelike deaktivering van `dontaudit` ’n stil mislukking in ’n presiese beleidsaanwyser verander:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Dit is ook nuttig om te hersien wat plaaslike admins reeds verander het. ’n Klein custom module of ’n een-domein permissive rule is dikwels die rede waarom ’n teikendienst baie losser optree as wat die base policy sou voorstel.

## Audit Clues

AVC denials is dikwels offensive signal, nie net defensive noise nie. Hulle sê vir jou:

- watter target object/type jy getref het
- watter permission geweier is
- watter domain jy tans beheer
- of ’n klein policy change die chain sou laat werk
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
As `EACCES` of vreemde "permission denied"-foute aanhou faal met ’n local exploit of persistence attempt, ondanks root-agtige DAC permissions, is SELinux gewoonlik die moeite werd om te check voordat jy die vector weggooi.

## SELinux Users

Daar is SELinux users benewens gewone Linux users. Elke Linux user word as deel van die policy na ’n SELinux user gemap, wat die system in staat stel om verskillende toegelate roles en domains op verskillende accounts af te dwing.

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Op baie hoofstroomstelsels word gebruikers na `unconfined_u` gemap, wat die praktiese impak van user confinement verminder. Op verharde ontplooiings kan confined users egter `sudo`, `su`, `newrole`, en `runcon` baie interessanter maak omdat **die escalasiepad daarvan kan afhang om in ’n beter SELinux role/type in te gaan, nie net van die verkryging van UID 0 nie**. Onthou ook dat sommige confined users glad nie `sudo`/`su` kan aanroep tensy policy uitdruklik die onderliggende setuid transition toelaat nie, so ’n host wat `staff_u` + `sysadm_r` gebruik, kan ’n skynbaar klein `sudo ROLE=` / `TYPE=` reël in die werklike privilege boundary verander.

## SELinux in Containers

Container runtimes begin gewoonlik workloads in ’n confined domain soos `container_t` en label container content as `container_file_t`. As ’n container process ontsnap maar steeds met die container label loop, kan host writes nog steeds misluk omdat die label boundary intact gebly het.

Quick example:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Die `c647,c780` deel is nie versiering nie. In baie container-ontplooiings ken runtimes MCS-kategorieë dinamies toe sodat twee prosesse wat as `container_t` loop, steeds van mekaar geskei bly. As ’n escape jou in ’n host namespace laat beland maar die oorspronklike kategorie-stel behou, kan kategorie-ongelykhede steeds verduidelik hoekom sommige host paths onleesbaar of onskryfbaar bly.

Moderne container-bedrywighede wat die moeite werd is om te noem:

- `--security-opt label=disable` kan die workload effektief na ’n unconfined container-verwante type soos `spc_t` skuif
- bind mounts met `:z` / `:Z` aktiveer herlabeling van die host path vir shared/private container use
- breë herlabeling van host content kan op sigself ’n sekuriteitsissue word

Hierdie bladsy hou die container-content kort om duplisering te vermy. Vir die container-spesifieke abuse cases en runtime-voorbeelde, kyk:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
