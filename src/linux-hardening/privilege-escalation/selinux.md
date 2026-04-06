# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux ni mfumo wa **Mandatory Access Control (MAC) unaotegemea lebo**. Kwa vitendo, hili lina maana kwamba hata kama ruhusa za DAC, vikundi, au Linux capabilities zinaonekana za kutosha kwa kitendo fulani, kernel bado inaweza kukataa kwa sababu **muktadha wa chanzo** haukuruhusiwa kufikia **muktadha wa lengo** kwa darasa/ruhusa iliyohitajika.

Muktadha kwa kawaida unaonekana kama:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Kutoka kwa mtazamo wa privesc, `type` (domain kwa ajili ya michakato, type kwa ajili ya vitu) mara nyingi ni uwanja muhimu zaidi:

- Mchakato unaendesha ndani ya **domain** kama `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Faili na sockets zina **type** kama `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Sera inaamua kama domain moja inaweza kusoma/kuandika/kutekeleza/kuhamia kwa nyingine

## Uorodheshaji wa haraka

Ikiwa SELinux imewezeshwa, iorodheshe mapema kwa sababu inaweza kueleza kwanini njia za kawaida za privesc za Linux zinashindwa au kwa nini wrapper yenye ruhusa za juu unaozunguka zana ya SELinux "harmless" ni muhimu sana:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Ukaguzi muhimu wa ufuatiliaji:
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
Matokeo ya kuvutia:

- `Disabled` au `Permissive` mode huondoa thamani kubwa ya SELinux kama kizuizi.
- `unconfined_t` kwa kawaida inaonyesha SELinux ipo lakini haizuizi mchakato huo kwa njia ya maana.
- `default_t`, `file_t`, au lebo zilizo wazi kuwa zisizo sahihi kwenye njia zilizobinafsishwa mara nyingi zinaonyesha lebo zisizofaa au utekelezaji usio kamilifu.
- Marekebisho ya kienyeji katika `file_contexts.local` yanapata kipaumbele juu ya chaguo-msingi za sera, hivyo yapitie kwa makini.

## Uchambuzi wa Sera

SELinux ni rahisi kushambuliwa au kupitishwa unapoweza kujibu maswali mawili:

1. **Nini domain yangu ya sasa inaweza kufikia?**
2. **Ni domains gani ninaweza kuhamia?**

Zana muhimu zaidi kwa hili ni `sepolicy` na **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Hii ni hasa muhimu wakati host inapotumia **confined users** badala ya kuwaratibu wote kwa `unconfined_u`. Katika hali hiyo, angalia:

- mepangilio ya watumiaji kupitia `semanage login -l`
- roles zilizoruhusiwa kupitia `semanage user -l`
- admin domains zinazoweza kufikiwa kama `sysadm_t`, `secadm_t`, `webadm_t`
- entry za `sudoers` zinazotumia `ROLE=` au `TYPE=`

Iwapo `sudo -l` inaingizo kama haya, SELinux ni sehemu ya mipaka ya ruhusa:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Pia angalia ikiwa `newrole` inapatikana:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` na `newrole` hazitumiwi moja kwa moja kama exploitable, lakini ikiwa wrapper yenye ruhusa au sheria ya `sudoers` itakuwezesha kuchagua role/type bora, zinakuwa high-value escalation primitives.

## Faili, Kubadilisha Lebo (Relabeling), na Mipangilio Mbaya Zenye Thamani Kuu

Tofauti muhimu zaidi ya kiutendaji kati ya zana za kawaida za SELinux ni:

- `chcon`: mabadiliko ya lebo ya muda kwenye njia maalum
- `semanage fcontext`: kanuni ya kudumu ya uhusiano kati ya njia na lebo
- `restorecon` / `setfiles`: tumia tena sera/lebo ya default

Hii ni muhimu sana wakati wa privesc kwa sababu **kubadilisha lebo si tu kwa mapambo**. Inaweza kubadilisha faili kutoka "imezuiwa na sera" kuwa "inasomwa/inaweza kutekelezwa na service iliyofungiwa yenye ruhusa".

Angalia sheria za kubadilisha lebo za ndani na mwelekeo wa mabadiliko ya lebo:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Amri za thamani kubwa za kutafuta katika `sudo -l`, root wrappers, automation scripts, au file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Hasa ya kuvutia:

- `semanage fcontext`: hubadilisha kwa kudumu lebo ambayo path inapaswa kupokea
- `restorecon` / `setfiles`: hurudia kutumia mabadiliko hayo kwa kiwango kikubwa
- `semodule -i`: inapakia module ya sera maalum
- `semanage permissive -a <domain_t>`: hufanya domain moja permissive bila kugeuza mashine yote
- `setsebool -P`: hubadilisha kwa kudumu policy booleans
- `load_policy`: inarudisha sera inayotumika

Hivi mara nyingi ni **helper primitives**, sio root exploits pekee. Thamani yao ni kwamba zinakuwezesha:

- kufanya domain lengwa permissive
- kupanua ufikiaji kati ya domain yako na protected type
- kurelabeli faili zilizodhibitiwa na mshambuliaji ili huduma yenye hadhi iweze kuzisoma au kuzitekeleza
- kuudhoofisha huduma iliyofungwa vya kutosha ili mdudu wa ndani uliopo uweze kutumika

Mifano ya ukaguzi:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Ikiwa unaweza kupakia module ya sera kama root, kwa kawaida unadhibiti mipaka ya SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Hivyo, `audit2allow`, `semodule`, na `semanage permissive` zinapaswa kutendewa kama kiolesura nyeti cha msimamizi wakati wa post-exploitation. Zinaweza kwa ukimya kugeuza chain iliyozuiwa kuwa inafanya kazi bila kubadilisha idhini za UNIX za jadi.

## Dalili za Ukaguzi

AVC denials mara nyingi ni ishara za kushambulia, si kelele za kujikinga tu. Zinakuambia:

- ni kipengee au aina gani cha lengo ulilofikia
- ruhusa gani ilinyimwa
- ni domain gani unadhibiti kwa sasa
- ikiwa mabadiliko madogo ya sera yangefanya chain ifanye kazi
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
If a local exploit or persistence attempt keeps failing with `EACCES` or strange "permission denied" errors despite root-looking DAC permissions, SELinux is usually worth checking before discarding the vector.

## Watumiaji wa SELinux

Kuna watumiaji wa SELinux pamoja na watumiaji wa kawaida wa Linux. Kila mtumiaji wa Linux ameambatanishwa na mtumiaji wa SELinux kama sehemu ya sera, ambayo inaruhusu mfumo kulazimisha majukumu na domains tofauti yaliyokubaliwa kwa akaunti mbalimbali.

Ukaguzi wa haraka:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Katika mifumo mingi ya kawaida, watumiaji wamepangiwa `unconfined_u`, jambo ambalo linapunguza athari za vitendo za kufungiwa kwa watumiaji. Hata hivyo, kwenye deployments zilizoimarishwa, watumiaji waliofungwa wanaweza kufanya `sudo`, `su`, `newrole`, na `runcon` kuwa za kuvutia zaidi kwa sababu **njia ya kuinua ruhusa inaweza kutegemea kuingia kwenye role/type bora ya SELinux, si tu kuwa UID 0**.

## SELinux katika kontena

Container runtimes kawaida huanzisha workloads katika domain iliyofungwa kama `container_t` na kuweka lebo kwenye yaliyomo ya container kama `container_file_t`. Ikiwa mchakato wa container unatoroka lakini bado unaendesha kwa lebo ya container, uandishi kwenye host bado unaweza kushindwa kwa sababu mpaka wa lebo uliendelea kuwa mkamilifu.

Mfano mfupi:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Operesheni za kisasa za container zinazostahili kutajwa:

- `--security-opt label=disable` inaweza kwa ufanisi kuhamisha mzigo wa kazi kwenda kwa aina isiyofungwa inayohusiana na container kama `spc_t`
- bind mounts with `:z` / `:Z` husababisha relabeling ya host path kwa matumizi ya shared/private container
- relabeling kubwa ya maudhui ya host inaweza kuwa tatizo la usalama kwa hiyo yenyewe

Ukurasa huu unafupisha yaliyomo kuhusu container ili kuepuka rudufu. Kwa visa vya matumizi mabaya maalum ya container na mifano ya runtime, angalia:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Marejeo

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
