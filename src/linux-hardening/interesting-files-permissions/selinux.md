# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux is ’n **etiketgebaseerde Mandatory Access Control (MAC)**-stelsel. In praktyk beteken dit dat selfs al lyk DAC-toestemmings, groepe of Linux capabilities voldoende vir ’n aksie, die kernel dit steeds kan weier omdat die **source context** nie toegelaat word om toegang tot die **target context** met die aangevraagde klas/toestemming te verkry nie.<sup>[[1]](#references)</sup>

’n Context lyk gewoonlik soos:<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Vanuit 'n privesc-perspektief is die `type` (domain vir prosesse, type vir objekte) gewoonlik die belangrikste veld:<sup>[[1]](#references)</sup>

- 'n Proses loop in 'n **domain** soos `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Lêers en sockets het 'n **type** soos `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy bepaal of een domain die ander kan lees/skryf/uitvoer of daarheen kan transition

## Vinnige Enumerasie

As SELinux geaktiveer is, enumereer dit vroeg, want dit kan verduidelik waarom algemene Linux-privesc-paaie misluk of waarom 'n bevoorregte wrapper rondom 'n "onskadelike" SELinux-hulpmiddel eintlik krities is:<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Nuttige opvolgkontroles:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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
Interessante bevindings:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- `Disabled`- of `Permissive`-modus verwyder die meeste van SELinux se waarde as ’n grens.
- `unconfined_t` beteken gewoonlik dat SELinux teenwoordig is, maar nie daardie proses betekenisvol beperk nie.
- `default_t`, `file_t` of ooglopend verkeerde labels op pasgemaakte paths dui dikwels op verkeerde labeling of ’n onvolledige ontplooiing.
- Plaaslike overrides in `file_contexts.local` kry voorkeur bo policy-verstekwaardes, dus moet jy dit noukeurig hersien.

## Beleidsanalise

SELinux is baie makliker om aan te val of te omseil wanneer jy twee vrae kan beantwoord:

1. **Waartoe kan my huidige domein toegang verkry?**
2. **Na watter domeine kan ek oorskakel?**

Die nuttigste tools hiervoor is `sepolicy` en **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>
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
Dit is veral nuttig wanneer ’n host **confined users** gebruik eerder as om almal na `unconfined_u` te karteer. Kyk in daardie geval na:<sup>[[3]](#references)</sup>

- user mappings via `semanage login -l`
- toegelate roles via `semanage user -l`
- bereikbare admin domains soos `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers`-inskrywings wat `ROLE=` of `TYPE=` gebruik

As `sudo -l` inskrywings soos hierdie bevat, is SELinux deel van die privilege boundary:<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Kontroleer ook of `newrole` beskikbaar is:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` en `newrole` is nie outomaties exploitable nie, maar as ’n bevoorregte wrapper of ’n `sudoers`-reël jou toelaat om ’n beter rol/t tipe te kies, word hulle hoëwaarde-escalation primitives.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Lêers, Heretikettering en Hoëwaarde-wanopstellings

Die belangrikste operasionele verskil tussen algemene SELinux-nutsgoed is:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: tydelike etiketverandering op ’n spesifieke pad
- `semanage fcontext`: volgehoue pad-na-etiket-reël
- `restorecon` / `setfiles`: pas die beleid/versteketiket weer toe

Dit is baie belangrik tydens privesc omdat **heretikettering nie net kosmeties is nie**. Dit kan ’n lêer verander van "deur die beleid geblokkeer" na "leesbaar/uitvoerbaar deur ’n bevoorregte confined diens".<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Kontroleer plaaslike heretiketteringsreëls en heretiketteringsafwyking:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Een subtiele maar nuttige detail: gewone `restorecon` keer **nie altyd 'n verdagte label volledig terug nie**. As die teikentipe in `customizable_types` is, moet jy moontlik `-F` gebruik om 'n volledige terugstelling af te dwing. Vanuit 'n offensiewe perspektief verduidelik dit waarom 'n ongewone `chcon` soms 'n oppervlakkige "ons het reeds restorecon uitgevoer"-opruiming kan oorleef.<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Hoëwaarde-opdragte om in `sudo -l`, root wrappers, outomatiseringsskrifte of lêervermoëns op te spoor:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
As enige van die MAC-capabilities verskyn, kruisverifieer ook die [Linux capabilities page](linux-capabilities.md); die Linux capabilities-dokumentasie beskryf `cap_mac_admin` en `cap_mac_override` as Smack-spesifiek, dus moenie aanvaar dat hul name alleen SELinux omseil nie.<sup>[[5]](#references)</sup>

Besonder interessant:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: verander permanent watter label ’n path moet ontvang
- `restorecon` / `setfiles`: pas hierdie veranderinge op groot skaal weer toe
- `semodule -i`: laai ’n custom policy module
- `semanage permissive -a <domain_t>`: maak een domain permissive sonder om die hele host om te skakel
- `setsebool -P`: verander policy booleans permanent
- `load_policy`: laai die aktiewe policy weer

Dit is dikwels **helper primitives**, nie standalone root exploits nie. Hul waarde is dat hulle jou toelaat om:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- ’n target domain permissive te maak
- access tussen jou domain en ’n beskermde type uit te brei
- attacker-controlled files te relabel sodat ’n privileged service dit kan lees of uitvoer
- ’n confined service genoeg te verswak sodat ’n bestaande local bug exploitable word

Voorbeeldkontroles:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
As jy ’n beleidsmodule as root kan laai, beheer jy gewoonlik die SELinux-grens:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Daarom moet `audit2allow`, `semodule` en `semanage permissive` as sensitiewe admin-oppervlakke tydens post-exploitation hanteer word. Hulle kan ’n geblokkeerde ketting stilweg in ’n werkende een omskep sonder om klassieke UNIX-toestemmings te verander.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Hidden Denials and Module Extraction

’n Baie algemene offensiewe frustrasie is ’n ketting wat met ’n vae `EACCES` misluk, terwyl die verwagte AVC-denial nooit verskyn nie. `dontaudit`-reëls kan die presiese toestemming wat jy benodig, versteek. As jy `semodule` deur `sudo` of ’n ander bevoorregte wrapper kan uitvoer, kan die tydelike deaktivering van `dontaudit` ’n stille mislukking in ’n presiese beleidsaanwysing verander:<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Dit is ook nuttig om na te gaan wat plaaslike admins reeds verander het. ’n Klein pasgemaakte module of ’n permissive rule vir een domein is dikwels die rede waarom ’n teikendiens baie minder beperk optree as wat die basisbeleid sou aandui.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Oudit-aanwysings

AVC-denials is dikwels ’n aanvallende sein, nie net defensiewe geraas nie. Hulle wys jou:<sup>[[1]](#references)[[15]](#references)</sup>

- watter teikenobjek/-tipe jy bereik het
- watter permission geweier is
- watter domain jy tans beheer
- of ’n klein beleidsverandering die chain sou laat werk
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
As ’n plaaslike exploit of persistence-poging aanhou misluk met `EACCES` of vreemde "permission denied"-foute ondanks root-agtige DAC-permissies, is SELinux gewoonlik die moeite werd om na te gaan voordat die vektor laat vaar word.<sup>[[1]](#references)</sup>

## SELinux-gebruikers

Daar is SELinux-gebruikers benewens gewone Linux-gebruikers. Elke Linux-gebruiker word as deel van die beleid aan ’n SELinux-gebruiker gekoppel, wat die stelsel toelaat om verskillende toegelate rolle en domeine aan verskillende rekeninge toe te wys.<sup>[[3]](#references)</sup>

Vinnige kontroles:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Op baie hoofstroomstelsels word gebruikers aan `unconfined_u` gekoppel, wat die praktiese impak van gebruikersbeperking verminder. In geharde ontplooiings kan beperkte gebruikers egter `sudo`, `su`, `newrole` en `runcon` baie interessanter maak, omdat **die eskaleringspad daarvan kan afhang om ’n beter SELinux-rol/-tipe binne te gaan, nie slegs om UID 0 te word nie**. Onthou ook dat sommige beperkte gebruikers glad nie `sudo`/`su` kan uitvoer nie, tensy die beleid die onderliggende setuid-oorgang uitdruklik toelaat. ’n Gasheer wat `staff_u` + `sysadm_r` gebruik, kan dus ’n oënskynlik geringe `sudo ROLE=` / `TYPE=`-reël in die werklike privilegiegrens verander.<sup>[[3]](#references)</sup>

## SELinux in Containers

Container-runtimes begin werkladings gewoonlik in ’n beperkte domein soos `container_t` en ken die label `container_file_t` aan container-inhoud toe. As ’n container-proses ontsnap, maar steeds met die container-label loop, kan skryfbewerkings op die gasheer steeds misluk omdat die labelgrens ongeskonde gebly het.<sup>[[1]](#references)[[17]](#references)</sup>

Vinnige voorbeeld:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Die `c647,c780`-gedeelte is nie versiering nie. In baie container deployments ken runtimes MCS categories dinamies toe sodat twee prosesse wat as `container_t` loop, steeds van mekaar geskei word. As 'n escape jou in 'n host namespace laat beland, maar die oorspronklike category set behou, kan category mismatches steeds verduidelik waarom sommige host paths onleesbaar of onskryfbaar bly.<sup>[[17]](#references)</sup>

Moderne container-bedrywighede wat die moeite werd is om op te let:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` skakel SELinux label-separasie vir die container af
- bind mounts met `:z` / `:Z` aktiveer relabeling van die host path vir gedeelde/private container-gebruik
- breë relabeling van host-inhoud kan op sy eie 'n sekuriteitskwessie word

Hierdie bladsy hou die container-inhoud kort om duplisering te vermy. Vir die container-spesifieke abuse cases en runtime-voorbeelde, kyk na:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Red Hat-dokumentasie: Gebruik van SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Policy-analise-nutsgoed vir SELinux](https://github.com/SELinuxProject/setools)
- [3] [Bestuur van confined en unconfined users - RHEL 9-dokumentasie](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Podman run-dokumentasie](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Waarom jy Multi-Category Security vir jou Linux-containers behoort te gebruik](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman top-dokumentasie](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}
