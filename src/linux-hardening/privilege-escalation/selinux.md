# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux is a **etiketgebaseerde Verpligte Toegangsbeheer (MAC)** stelsel. In praktyk beteken dit dat selfs al lyk DAC permissions, groups, or Linux capabilities voldoende vir 'n aksie, kan die kernel dit steeds weier omdat die **bron-konteks** nie toegelaat word om toegang tot die **teiken-konteks** te kry met die versoekte klas/toestemming nie.

A context usually looks like:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Vanuit 'n privesc-perspektief is die `type` (domein vir prosesse, tipe vir voorwerpe) gewoonlik die belangrikste veld:

- 'n proses loop in 'n **domein** soos `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Lêers en sockets het 'n **tipe** soos `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Beleid bepaal of een domein die ander kan lees/skryf/uitvoer/oorskakel

## Vinnige enumerasie

As SELinux aangeskakel is, enumereer dit vroeg omdat dit kan verduidelik waarom algemene Linux privesc-paaie misluk of waarom 'n privileged wrapper rondom 'n "harmless" SELinux-instrument eintlik kritiek is:
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
Interessante bevindinge:

- `Disabled` or `Permissive` modus verwyder die meeste van die waarde van SELinux as 'n grens.
- `unconfined_t` beteken gewoonlik dat SELinux teenwoordig is maar nie daardie proses beduidend beperk nie.
- `default_t`, `file_t`, or obviously wrong labels on custom paths dui dikwels op verkeerde etikettering of onvolledige implementering.
- Plaaslike oorskrywings in `file_contexts.local` het voorrang bo beleid-standaarde, hersien dit dus noukeurig.

## Beleidsontleding

SELinux is baie makliker om aan te val of om te omseil wanneer jy twee vrae kan beantwoord:

1. **Tot wat kan my huidige domein toegang hê?**
2. **Na watter domeine kan ek oorskakel?**

Die nuttigste gereedskap hiervoor is `sepolicy` en **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Dit is veral nuttig wanneer 'n gasheer **beperkte gebruikers** gebruik in plaas daarvan om almal aan `unconfined_u` toe te wys. In daardie geval, kyk vir:

- gebruiker-toewysings via `semanage login -l`
- toegestane rolle via `semanage user -l`
- bereikbare admin-domeine soos `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers` inskrywings wat `ROLE=` of `TYPE=` gebruik

As `sudo -l` inskrywings soos hierdie bevat, is SELinux deel van die bevoegdheidsgrens:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Kontroleer ook of `newrole` beskikbaar is:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` en `newrole` is nie outomaties benutbaar nie, maar as 'n bevoorregte wrapper of 'n `sudoers`-reël jou toelaat om 'n beter rol/tipe te kies, word hulle hoë-waarde eskalasie-primitiewe.

## Lêers, Heretikettering en Hoë-waarde Miskonfigurasies

Die belangrikste operasionele verskil tussen algemene SELinux-instrumente is:

- `chcon`: tydelike etiketverandering op 'n spesifieke pad
- `semanage fcontext`: permanente pad-na-etiket reël
- `restorecon` / `setfiles`: pas die beleid/standaard-etiket weer toe

Dit maak baie saak tydens privesc omdat **heretikettering nie net kosmeties is nie**. Dit kan 'n lêer verander van "deur die beleid geblokkeer" na "leesbaar/uitvoerbaar deur 'n bevoorregte begrensde diens".

Kontroleer vir plaaslike heretiketteringsreëls en heretiketteringsverskuiwing:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Hoë-waarde opdragte om in `sudo -l`, root wrappers, automation scripts, of file capabilities te soek:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Veral interessant:

- `semanage fcontext`: verander volhoubaar watter etiket 'n pad behoort te kry
- `restorecon` / `setfiles`: pas daardie veranderinge opnuut toe op skaal
- `semodule -i`: laai 'n pasgemaakte beleidsmodule
- `semanage permissive -a <domain_t>`: maak een domein permissive sonder om die hele gasheer in permissive-modus te plaas
- `setsebool -P`: verander beleidsbooleane permanent
- `load_policy`: herlaai die aktiewe beleid

Hierdie is dikwels **helper primitives**, nie standalone root exploits nie. Hul waarde is dat hulle jou toelaat om:

- maak 'n teiken-domein permissive
- brei toegang uit tussen jou domein en 'n beskermde tipe
- herlabel aanvaller-beheerde lêers sodat 'n geprivilegieerde diens hulle kan lees of uitvoer
- verweek 'n ingeperkte diens genoeg dat 'n bestaande plaaslike fout uitbuitbaar raak

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
Daarom moet `audit2allow`, `semodule` en `semanage permissive` as sensitiewe admin-oppervlakke tydens post-exploitation beskou word. Hulle kan stilweg 'n geblokkeerde ketting in 'n werkende een omskakel sonder om klassieke UNIX-permissies te verander.

## Oudit leidrade

AVC-weierings is dikwels 'n offensiewe sein, nie net verdedigende geraas nie. Hulle wys jou:

- watter teikenobjek/-tipe jy getref het
- watter toestemming geweier is
- watter domein jy tans beheer
- of 'n klein beleidsverandering die ketting sou laat werk
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
As 'n local exploit of persistence attempt steeds misluk met `EACCES` of vreemde "permission denied" foute ondanks root-looking DAC permissions, is dit gewoonlik die moeite werd om SELinux te ondersoek voordat jy die vector laat vaar.

## SELinux-gebruikers

Daar is SELinux-gebruikers benewens gewone Linux-gebruikers. Elke Linux-gebruiker word as deel van die beleid aan 'n SELinux-gebruiker gekoppel, wat die stelsel toelaat om verskillende toegelate rolle en domeine op verskillende rekeninge af te dwing.

Vinnige kontrole:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Op baie hoofstroom-stelsels word gebruikers aan `unconfined_u` gekoppel, wat die praktiese impak van gebruikersbeperking verminder. Op geharde ontplooiings kan beperkte gebruikers egter `sudo`, `su`, `newrole`, en `runcon` baie meer interessant maak omdat **die eskalasiepad mag afhang van om 'n beter SELinux-rol/tipe te betree, nie net om UID 0 te word nie**.

## SELinux in Containers

Container runtimes lanceer gewoonlik werksladinge in 'n beperkte domein soos `container_t` en merk container-inhoud as `container_file_t`. As 'n container-proses ontsnap maar steeds met die container-label loop, kan skrywings na die host steeds misluk omdat die label-grens ongeskonde gebly het.

Kort voorbeeld:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Moderne container-operasies om op te let:

- `--security-opt label=disable` kan effektief die werkvrag na 'n nie-beperkte, container-verwante tipe soos `spc_t` skuif
- bind mounts met `:z` / `:Z` veroorsaak die heretikettering van die gasheerpad vir gedeelde/private container-gebruik
- breë heretikettering van gasheerinhoud kan op sigself 'n sekuriteitsprobleem word

Hierdie bladsy hou die container-inhoud kort om duplikasie te voorkom. Vir container-spesifieke misbruikgevalle en runtime-voorbeelde, check:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Verwysings

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
