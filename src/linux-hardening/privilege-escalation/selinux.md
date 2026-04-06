# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux is 'n **etiketgebaseerde verpligte toegangsbeheer (MAC)** stelsel. In die praktyk beteken dit dat selfs al lyk DAC-permissies, groepe, of Linux capabilities voldoende vir 'n aksie, kan die kernel dit steeds weier omdat die **bron konteks** nie toegelaat word om toegang te kry tot die **teiken konteks** met die versoekte klas/toestemming.

'n konteks lyk gewoonlik soos:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Vanuit 'n privesc-perspektief is die `type` (domein vir prosesse, tipe vir voorwerpe) gewoonlik die belangrikste veld:

- 'n proses hardloop in 'n **domein** soos `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Lêers en sokette het 'n **tipe** soos `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Beleid bepaal of een domein die ander kan lees/skryf/uitvoer/oorgaan na die ander

## Vinnige enumerasie

As SELinux aangeskakel is, enumereer dit vroeg omdat dit kan verduidelik waarom algemene Linux privesc-paaie misluk of waarom 'n bevoorregte wrapper rondom 'n "harmless" SELinux-hulpmiddel eintlik kritiek is:
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

- `Disabled` of `Permissive` modus verwyder die meeste van die waarde van SELinux as 'n grens.
- `unconfined_t` beteken gewoonlik SELinux is teenwoordig maar beperk daardie proses nie betekenisvol nie.
- `default_t`, `file_t`, of voor die hand liggend verkeerde etikette op pasgemaakte paaie dui dikwels op verkeerde etikettering of onvolledige implementering.
- Plaaslike oorskrywings in `file_contexts.local` het voorrang bo beleids-standaarde; hersien dit dus deeglik.

## Beleid-analise

SELinux is baie makliker om aan te val of te omseil wanneer jy twee vrae kan beantwoord:

1. **Tot wat het my huidige domein toegang?**
2. **Na watter domeine kan ek oorskakel?**

Die nuttigste hulpmiddels hiervoor is `sepolicy` en **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Dit is veral nuttig wanneer 'n gasheer **beperkte gebruikers** gebruik eerder as om almal aan `unconfined_u` toe te ken. In daardie geval, kyk na:

- gebruikerstoewysings via `semanage login -l`
- toegelate rolle via `semanage user -l`
- admin-domeine wat bereikbaar is, soos `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers`-inskrywings wat `ROLE=` of `TYPE=` gebruik

As `sudo -l` inskrywings soos hierdie bevat, is SELinux deel van die privilegiegrens:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Kontroleer ook of `newrole` beskikbaar is:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` and `newrole` are not automatically exploitable, but if a privileged wrapper or a `sudoers` rule lets you select a better role/type, they become high-value escalation primitives.

## Lêers, heretikettering, en hoë-waarde wankonfigurasies

Die belangrikste operasionele verskil tussen algemene SELinux-gereedskap is:

- `chcon`: tydelike etiketwysiging op 'n spesifieke pad
- `semanage fcontext`: permanente pad-na-etiket reël
- `restorecon` / `setfiles`: pas die beleid/standaard-etiket weer toe

Dit maak baie saak tydens privesc omdat **heretikettering nie net kosmeties is nie**. Dit kan 'n lêer verander van "blocked by policy" na "readable/executable by a privileged confined service".

Kontroleer vir lokale heretiketteringsreëls en heretiketteringsdryf:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Hoë-waarde opdragte om in `sudo -l`, root wrappers, automatiseringsskripte, of lêervermoëns te soek:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Veral interessant:

- `semanage fcontext`: verander permanent watter etiket 'n pad moet ontvang
- `restorecon` / `setfiles`: pas daardie veranderinge op skaal weer toe
- `semodule -i`: laai 'n pasgemaakte beleidsmodule
- `semanage permissive -a <domain_t>`: maak een domein permissief sonder om die hele gasheer om te skakel
- `setsebool -P`: verander beleid booleans permanent
- `load_policy`: herlaai die aktiewe beleid

These are often **helper primitives**, not standalone root exploits. Hul waarde is dat hulle jou toelaat om:

- maak 'n teiken-domein permissief
- verbreed toegang tussen jou domein en 'n beskermde tipe
- heretiketteer aanvallerkontroleerde lêers sodat 'n bevoorregte diens dit kan lees of uitvoer
- verswak 'n ingeperkte diens genoeg dat 'n bestaande plaaslike fout uitbuitbaar raak

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
Dit is hoekom `audit2allow`, `semodule`, en `semanage permissive` as sensitiewe admin-oppervlakke tydens post-exploitation beskou moet word. Hulle kan stilweg 'n geblokkeerde ketting in 'n werkende een omskakel sonder om klassieke UNIX-permissies te verander.

## Oudit-aanwysers

AVC-weierings is dikwels 'n offensiewe sein, nie net verdedigende geraas nie. Hulle vertel jou:

- watter teiken-objek/tipe jy getref het
- watter toestemming geweier is
- watter domein jy tans beheer
- of 'n klein beleidsverandering die ketting werkend sou maak
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
As 'n plaaslike exploit of persistence-poging steeds faal met `EACCES` of vreemde "permission denied" foute ondanks root-lookende DAC-permissies, is SELinux gewoonlik die moeite werd om te kontroleer voordat jy die vektor verwerp.

## SELinux Gebruikers

Daar is SELinux-gebruikers benewens gewone Linux-gebruikers. Elke Linux-gebruiker word as deel van die beleid aan 'n SELinux-gebruiker gekoppel, wat die stelsel toelaat om verskillende toegelate rolle en domeine op verskillende rekeninge af te dwing.

Vinnige kontroles:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Op baie algemene stelsels word gebruikers na `unconfined_u` gemap, wat die praktiese impak van gebruikersinsluiting verminder. Op geharde implementasies kan ingeperkte gebruikers egter `sudo`, `su`, `newrole` en `runcon` baie meer interessant maak, omdat **die eskalasiepad moontlik afhang van om 'n beter SELinux-rol/tipe te bereik, nie net van die word van UID 0 nie**.

## SELinux in Containers

Container runtimes lanceer gewoonlik werkbelastings in 'n ingeperkte domein soos `container_t` en merk container-inhoud as `container_file_t`. As 'n container-proses ontsnap maar steeds met die container-etiket loop, kan skryfaksies op die gasheer steeds misluk omdat die etiketgrens intak gebly het.

Kort voorbeeld:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Moderne containerbedrywighede om op te let:

- `--security-opt label=disable` kan die werklading effektief skuif na 'n onbeperkte container-verwante tipe soos `spc_t`
- bind mounts met `:z` / `:Z` veroorsaak heretikettering van die gasheerpad vir gedeelde/private containergebruik
- breë heretikettering van gasheerinhoud kan op sigself 'n sekuriteitsprobleem word

Hierdie bladsy hou die containerinhoud kort om duplikasie te vermy. Vir container-spesifieke misbruikgevalle en runtime-voorbeelde, sien:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Verwysings

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
