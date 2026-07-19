# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux is ’n **label-based Mandatory Access Control (MAC)**-stelsel. In die praktyk beteken dit dat selfs al lyk DAC-permissies, groepe of Linux-capabilities voldoende vir ’n aksie, die kernel dit steeds kan weier omdat die **source context** nie toegelaat word om toegang tot die **target context** met die aangevraagde klas/permissie te verkry nie.

’n Konteks lyk gewoonlik soos:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Vanuit ’n privesc-perspektief is die `type` (domain vir prosesse, type vir objekte) gewoonlik die belangrikste veld:

- ’n Proses loop in ’n **domain** soos `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Lêers en sockets het ’n **type** soos `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy bepaal of een domain die ander een kan lees/skryf/uitvoer/na kan transition

## Vinnige Enumeration

As SELinux geaktiveer is, enumerate dit vroeg, want dit kan verduidelik waarom algemene Linux-privesc-paaie misluk of waarom ’n bevoorregte wrapper rondom ’n "onskadelike" SELinux-tool eintlik krities is:
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

- `Disabled`- of `Permissive`-modus verwyder die meeste van SELinux se waarde as 'n grens.
- `unconfined_t` beteken gewoonlik dat SELinux teenwoordig is, maar nie daardie proses betekenisvol beperk nie.
- `default_t`, `file_t`, of ooglopend verkeerde labels op pasgemaakte paths dui dikwels op verkeerde labeling of 'n onvolledige ontplooiing.
- Plaaslike overrides in `file_contexts.local` geniet voorkeur bo policy-standaarde, dus moet hulle noukeurig nagegaan word.

## Beleidsontleding

SELinux is baie makliker om aan te val of te omseil wanneer jy twee vrae kan beantwoord:

1. **Waartoe het my huidige domain toegang?**
2. **Na watter domains kan ek oorskakel?**

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
Dit is veral nuttig wanneer ’n host **confined users** gebruik eerder as om almal na `unconfined_u` te karteer. Kyk in daardie geval na:

- gebruikerskoppelings via `semanage login -l`
- toegelate rolle via `semanage user -l`
- bereikbare administratordomeine soos `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers`-inskrywings wat `ROLE=` of `TYPE=` gebruik

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
`runcon` en `newrole` is nie outomaties exploitable nie, maar indien ’n bevoorregte wrapper of ’n `sudoers`-reël jou toelaat om ’n beter rol/tipe te kies, word hulle waardevolle eskalasie-primitiewe.

## Lêers, Heretikettering en Waardevolle Misconfigurations

Die belangrikste operasionele verskil tussen algemene SELinux-tools is:

- `chcon`: tydelike etiketverandering op ’n spesifieke pad
- `semanage fcontext`: persistente pad-na-etiket-reël
- `restorecon` / `setfiles`: pas die policy-/versteketiket weer toe

Dit is baie belangrik tydens privesc, omdat **heretikettering nie net kosmeties is nie**. Dit kan ’n lêer verander van "deur policy geblokkeer" na "leesbaar/uitvoerbaar deur ’n bevoorregte confined service".

Kyk vir plaaslike heretiketteringsreëls en heretiketteringsdrift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Een subtiele maar nuttige detail: gewone `restorecon` stel **nie altyd ’n verdagte label volledig terug nie**. As die teikentipe in `customizable_types` is, moet jy moontlik `-F` gebruik om ’n volledige terugstelling af te dwing. Vanuit ’n aanvallende perspektief verduidelik dit waarom ’n ongewone `chcon` soms ’n terloopse "ons het reeds restorecon uitgevoer"-skoonmaak kan oorleef.
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Opdragte met hoë waarde om in `sudo -l`, root wrappers, outomatiseringskripte of lêervermoëns op te spoor:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
As enige MAC capability verskyn, kontroleer ook die [Linux capabilities page](linux-capabilities.md); `cap_mac_admin` en `cap_mac_override` is ongewoon, maar direk relevant wanneer SELinux deel van die grens is.

Veral interessant:

- `semanage fcontext`: verander permanent watter label 'n path moet ontvang
- `restorecon` / `setfiles`: pas hierdie veranderinge op groot skaal weer toe
- `semodule -i`: laai 'n custom policy module
- `semanage permissive -a <domain_t>`: maak een domain permissive sonder om die hele host te verander
- `setsebool -P`: verander policy booleans permanent
- `load_policy`: laai die aktiewe policy weer

Hierdie is dikwels **helper primitives**, nie selfstandige root exploits nie. Die waarde daarvan is dat hulle jou toelaat om:

- 'n target domain permissive te maak
- toegang tussen jou domain en 'n beskermde type uit te brei
- attacker-controlled files te herlabel sodat 'n privileged service dit kan lees of uitvoer
- 'n confined service genoeg te verswak sodat 'n bestaande local bug exploitable word

Voorbeeldkontroles:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
As jy 'n beleidsmodule as root kan laai, beheer jy gewoonlik die SELinux-grens:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Daarom moet `audit2allow`, `semodule` en `semanage permissive` as sensitiewe administratiewe oppervlaktes tydens post-exploitation behandel word. Hulle kan ’n geblokkeerde chain stilweg in ’n werkende een omskep sonder om klassieke UNIX-permissions te verander.

## Verborge Denials en Module Extraction

’n Baie algemene offensiewe frustrasie is ’n chain wat met ’n vae `EACCES` misluk terwyl die verwagte AVC denial nooit verskyn nie. `dontaudit`-reëls kan die presiese permission wat jy benodig, versteek. As jy `semodule` deur `sudo` of ’n ander bevoorregte wrapper kan uitvoer, kan die tydelike deaktivering van `dontaudit` ’n stille mislukking in ’n presiese policy clue omskep:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Dit is ook nuttig om na te gaan wat plaaslike admins reeds verander het. ’n Klein custom module of ’n permissive rule vir een domain is dikwels die rede waarom ’n target service baie minder beperk optree as wat die base policy sou aandui.

## Ouditleidrade

AVC denials is dikwels ’n offensiewe sein, nie net defensiewe geraas nie. Dit wys jou:

- watter target object/type jy getref het
- watter permission geweier is
- watter domain jy tans beheer
- of ’n klein policy-verandering die chain sou laat werk
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
As ’n plaaslike exploit- of persistence-poging aanhou misluk met `EACCES` of vreemde "permission denied"-foute ondanks DAC-toestemmings wat soos root lyk, is SELinux gewoonlik die moeite werd om na te gaan voordat jy die vector laat vaar.

## SELinux-gebruikers

Daar is SELinux-gebruikers benewens gewone Linux-gebruikers. Elke Linux-gebruiker word as deel van die policy aan ’n SELinux-gebruiker gekoppel, wat die stelsel toelaat om verskillende toegelate rolle en domains op verskillende rekeninge af te dwing.

Vinnige kontroles:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Op baie hoofstroomstelsels word gebruikers aan `unconfined_u` gekoppel, wat die praktiese impak van gebruikersbeperking verminder. Op geharde ontplooiings kan beperkte gebruikers egter `sudo`, `su`, `newrole` en `runcon` baie interessanter maak, omdat **die escalation path kan afhang van die betreding van ’n beter SELinux-rol/tipe, nie slegs daarvan om UID 0 te word nie**. Onthou ook dat sommige beperkte gebruikers glad nie `sudo`/`su` kan uitvoer nie, tensy die beleid die onderliggende setuid-oorgang uitdruklik toelaat. ’n Gasheer wat `staff_u` + `sysadm_r` gebruik, kan dus ’n oënskynlik geringe `sudo ROLE=` / `TYPE=`-reël in die werklike privilege boundary verander.

## SELinux in Containers

Container runtimes begin werkladings gewoonlik in ’n beperkte domein soos `container_t` en merk container-inhoud as `container_file_t`. Indien ’n container-proses ontsnap maar steeds met die container-label loop, kan skryfaksies na die gasheer steeds misluk omdat die label-grens behoue gebly het.

Vinnige voorbeeld:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Die `c647,c780`-deel is nie versiering nie. In baie container-ontplooiings ken runtimes MCS-kategorieë dinamies toe sodat twee prosesse wat as `container_t` loop, steeds van mekaar geskei word. As ’n escape jou in ’n host namespace plaas, maar die oorspronklike kategorieversameling behou, kan kategorie-wanpassings steeds verduidelik waarom sommige host-paaie onleesbaar of onskryfbaar bly.

Moderne container-bedrywighede wat die moeite werd is om op te let:

- `--security-opt label=disable` kan die workload effektief na ’n onbeperkte container-verwante tipe soos `spc_t` skuif
- bind mounts met `:z` / `:Z` aktiveer relabeling van die host-pad vir gedeelde/private container-gebruik
- om host-inhoud breedweg te relabel, kan op sigself ’n security issue word

Hierdie bladsy hou die container-inhoud kort om duplisering te vermy. Vir die container-spesifieke misbruikgevalle en runtime-voorbeelde, kyk na:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Verwysings

- [Red Hat-dokumentasie: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Bestuur van beperkte en onbeperkte gebruikers - RHEL 9-dokumentasie](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux-manbladsy](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
