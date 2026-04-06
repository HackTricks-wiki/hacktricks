# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux ni mfumo wa **udhibiti wa upatikanaji wa lazima (Mandatory Access Control, MAC) unaotegemea lebo**. Katika vitendo, hii inamaanisha kwamba hata kama ruhusa za DAC, groups, au Linux capabilities zinaonekana kutosha kwa kitendo, kernel bado inaweza kukataa kwa sababu **muktadha wa chanzo** haukuruhusiwa kufikia **muktadha wa lengo** kwa class/permission iliyohitajika.

Muktadha kawaida huonekana kama:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Kutoka kwa mtazamo wa privesc, `type` (domain kwa michakato, type kwa vitu) mara nyingi ni uwanja muhimu zaidi:

- Mchakato huendeshwa katika **domain** kama `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Faili na sockets zina **type** kama `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy inaamua kama domain moja inaweza read/write/execute/transition kwa nyingine

## Uorodheshaji wa Haraka

Ikiwa SELinux imewezeshwa, orodhesha mapema kwa sababu inaweza kueleza kwa nini njia za kawaida za privesc kwenye Linux zinashindwa au kwa nini wrapper mwenye ruhusa karibu na zana "harmless" ya SELinux ni muhimu sana:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Mikaguzi muhimu ya kufuatilia:
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

- `Disabled` au `Permissive` mode huondoa sehemu kubwa ya thamani ya SELinux kama mipaka.
- `unconfined_t` kwa kawaida inaonyesha SELinux ipo lakini haizuizi mchakato huo kwa ufanisi.
- `default_t`, `file_t`, au lebo zilizo waziwazi si sahihi kwenye njia za kawaida mara nyingi zinaonyesha utambulisho mbaya au utekelezaji usio kamili.
- Mabadiliko ya ndani katika `file_contexts.local` hupata kipaumbele kuliko chaguo-msingi za sera, hivyo yaangalie kwa umakini.

## Uchambuzi wa Sera

SELinux ni rahisi kushambuliwa au kupitishwa wakati unaweza kujibiwa maswali mawili:

1. **Je, domain yangu ya sasa inaweza kufikia nini?**
2. **Ni domains gani ninaweza kuhamia?**

Vyombo muhimu zaidi kwa hili ni `sepolicy` na **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Hii ni muhimu hasa wakati host anatumia **watumiaji waliofungwa** badala ya kumepanga kila mtu kwa `unconfined_u`. Katika hali hiyo, angalia:

- ramani za watumiaji kupitia `semanage login -l`
- nyadhifa zinazoruhusiwa kupitia `semanage user -l`
- domaini za admin zinazoweza kufikiwa kama `sysadm_t`, `secadm_t`, `webadm_t`
- viingizo za `sudoers` vinavyotumia `ROLE=` au `TYPE=`

Ikiwa `sudo -l` ina viingizo kama hivi, SELinux ni sehemu ya mpaka wa ruhusa:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Pia angalia ikiwa `newrole` inapatikana:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` na `newrole` hazitumiki moja kwa moja kama njia za kutekeleza exploit, lakini ikiwa wrapper yenye ruhusa au sheria ya `sudoers` inakuruhusu kuchagua role/type bora, zinageuka kuwa primitives za escalation zenye thamani kubwa.

## Faili, Kurelabel, na Misconfigurations Zenye Thamani Kuu

Tofauti muhimu kiutendaji kati ya zana za kawaida za SELinux ni:

- `chcon`: mabadiliko ya lebo ya muda kwenye njia maalum
- `semanage fcontext`: sheria ya kudumu ya ramani ya njia hadi lebo
- `restorecon` / `setfiles`: tumia tena sera/lebo ya default

Hii ni muhimu sana wakati wa privesc kwa sababu **kurelabel si mapambo tu**. Inaweza kubadilisha faili kutoka "imezuiliwa na sera" hadi "inasomwa/inaweza kutekelezwa na huduma iliyofungwa yenye ruhusa".

Angalia sheria za kurelabel za ndani na mabadiliko ya kurelabel:
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
Haswa zinavutia:

- `semanage fcontext`: hubadilisha kwa kudumu lebo ambayo path inapaswa kupokea
- `restorecon` / `setfiles`: hurejesha tena mabadiliko hayo kwa kiwango kikubwa
- `semodule -i`: inapakia moduli ya sera iliyobinafsishwa
- `semanage permissive -a <domain_t>`: hufanya domain moja permissive bila kubadilisha host nzima
- `setsebool -P`: hubadilisha kwa kudumu boolean za sera
- `load_policy`: inarudisha upya sera inayotumika

Hizi mara nyingi ni **vitu vya msaada**, si root exploits zinazojiendesha peke yake. Thamani yao ni kwamba zinakuwezesha:

- kufanya domain lengwa kuwa permissive
- kupanua ufikiaji kati ya domain yako na protected type
- kulebeli upya attacker-controlled files ili huduma yenye privileges iweze kuzisoma au kuziendesha
- kudhoofisha huduma iliyofungiwa kiasi kwamba bug ya ndani iliyopo inaweza kutumika

Mifano ya ukaguzi:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Ikiwa unaweza kupakia moduli ya sera kama root, kwa kawaida unadhibiti mipaka ya SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Ndiyo maana `audit2allow`, `semodule`, na `semanage permissive` zinapaswa kutendewa kama maeneo nyeti ya usimamizi wakati wa post-exploitation. Zinaweza kimya kimya kugeuza mlolongo uliokataliwa kuwa mlolongo unaofanya kazi bila kubadilisha ruhusa za jadi za UNIX.

## Dalili za ukaguzi

Kukataa kwa AVC mara nyingi ni ishara ya kushambulia, sio tu kelele za kujilinda. Zinakuambia:

- ni kitu/aina gani ya lengo uliilenga
- ruhusa gani iliyokataliwa
- domain gani unadhibiti kwa sasa
- ikiwa mabadiliko madogo ya sera yangefanya mlolongo ufanye kazi
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Ikiwa local exploit au persistence attempt inaendelea kushindwa kwa `EACCES` au makosa ya kushangaza ya "permission denied" licha ya ruhusa za DAC zinazoonekana kuwa za root, mara nyingi inafaa kuangalia SELinux kabla ya kukataa vector.

## Watumiaji wa SELinux

Kuna watumiaji wa SELinux pamoja na watumiaji wa kawaida wa Linux. Kila mtumiaji wa Linux ameandikwa kwa mtumiaji wa SELinux kama sehemu ya policy, jambo ambalo linamruhusu mfumo kushinikiza roles na domains tofauti zinazoruhusiwa kwa akaunti tofauti.

Ukaguzi wa haraka:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Kwenye mifumo mingi ya kawaida, watumiaji wamewekwa kwenye `unconfined_u`, jambo linalopunguza athari halisi za kufungwa kwa watumiaji. Hata hivyo, kwenye deployments zilizothibitishwa (hardened), watumiaji waliofungwa wanaweza kufanya `sudo`, `su`, `newrole`, na `runcon` kuwa ya kuvutia zaidi kwa sababu **njia ya kupandisha hadhi inaweza kutegemea kuingia katika role/type bora ya SELinux, si tu kuwa UID 0**.

## SELinux katika Containers

Runtimes za container kwa kawaida huanzisha workloads katika domain iliyofungwa kama `container_t` na kuweka lebo kwenye yaliyomo ya container kama `container_file_t`. Ikiwa mchakato wa container utatoroka lakini bado utaendelea kukimbia ukiwa na lebo ya container, uandishi kwenye host unaweza kushindwa kwa sababu mpaka wa lebo ulidumu.

Mfano mfupi:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Operesheni za container za kisasa zinazostahili kuzingatiwa:

- `--security-opt label=disable` inaweza kwa ufanisi kuhamisha mzigo wa kazi kwa aina ya container isiyofungwa kama `spc_t`
- bind mounts with `:z` / `:Z` huchochea relabeling ya host path kwa matumizi ya shared/private container
- broad relabeling ya yaliyomo kwenye host inaweza kuwa tatizo la usalama peke yake

Ukurasa huu unabaki na maudhui ya container mafupi ili kuepuka kurudia. Kwa kesi za matumizi mabaya maalum za container na mifano ya runtime, angalia:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Marejeo

- [Red Hat docs: Kutumia SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Zana za uchambuzi wa sera kwa SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
