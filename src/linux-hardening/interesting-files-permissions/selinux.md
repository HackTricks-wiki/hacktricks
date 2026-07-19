# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux ni mfumo wa **Mandatory Access Control (MAC) unaotegemea labels**. Kwa vitendo, hii inamaanisha kwamba hata kama ruhusa za DAC, groups, au Linux capabilities zinaonekana kutosha kwa kitendo fulani, kernel bado inaweza kukikataa kwa sababu **source context** hairuhusiwi kufikia **target context** kwa class/permission iliyoombwa.

Context kwa kawaida huonekana hivi:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Kwa mtazamo wa `privesc`, `type` (domain kwa processes, type kwa objects) kwa kawaida ndiyo field muhimu zaidi:

- Process huendeshwa katika **domain** kama `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Files na sockets huwa na **type** kama `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy huamua ikiwa domain moja inaweza kusoma/kuandika/kutekeleza/kufanya transition kwenda nyingine

## Uchunguzi wa Haraka

Ikiwa SELinux imewezeshwa, ifanyie enumeration mapema kwa sababu inaweza kueleza kwa nini njia za kawaida za Linux privesc zinashindwa au kwa nini wrapper yenye privileges inayozunguka SELinux tool "isiyo na madhara" kwa kweli ni muhimu:
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
Mambo ya kuvutia yaliyobainika:

- Hali ya `Disabled` au `Permissive` huondoa sehemu kubwa ya thamani ya SELinux kama boundary.
- `unconfined_t` kwa kawaida inamaanisha SELinux ipo, lakini haiweki vizuizi vya maana kwa process hiyo.
- `default_t`, `file_t`, au labels zilizo wazi kuwa si sahihi kwenye custom paths mara nyingi huashiria labeling isiyo sahihi au deployment isiyokamilika.
- Overrides za ndani kwenye `file_contexts.local` huwa na kipaumbele kuliko policy defaults, kwa hivyo zipitie kwa uangalifu.

## Uchambuzi wa Policy

SELinux huwa rahisi zaidi ku-attack au ku-bypass unapoweza kujibu maswali mawili:

1. **Domain yangu ya sasa inaweza kufikia nini?**
2. **Ni domains zipi ninazoweza ku-transition kwenda?**

Tools muhimu zaidi kwa hili ni `sepolicy` na **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Hii ni muhimu hasa wakati host inatumia **confined users** badala ya kuwapa wote mapping ya `unconfined_u`. Katika hali hiyo, tafuta:

- user mappings kupitia `semanage login -l`
- roles zinazoruhusiwa kupitia `semanage user -l`
- admin domains zinazoweza kufikiwa kama `sysadm_t`, `secadm_t`, `webadm_t`
- maingizo ya `sudoers` yanayotumia `ROLE=` au `TYPE=`

Ikiwa `sudo -l` ina maingizo kama haya, SELinux ni sehemu ya mpaka wa mapendeleo:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Pia angalia ikiwa `newrole` inapatikana:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` na `newrole` haziwezi kutumiwa vibaya moja kwa moja, lakini ikiwa privileged wrapper au sheria ya `sudoers` inakuruhusu kuchagua role/type bora, huwa primitives muhimu sana za escalation.

## Files, Relabeling, na High-Value Misconfigurations

Tofauti muhimu zaidi ya kiutendaji kati ya SELinux tools za kawaida ni:

- `chcon`: hubadilisha label kwa muda kwenye path maalum
- `semanage fcontext`: sheria endelevu ya path-to-label
- `restorecon` / `setfiles`: hutumia tena label ya policy/default

Hili ni muhimu sana wakati wa privesc kwa sababu **relabeling si suala la mwonekano tu**. Inaweza kubadilisha file kutoka "imezuiwa na policy" kuwa "inaweza kusomwa/kuendeshwa na service ya privileged confined".

Kagua local relabel rules na relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Jambo moja dogo lakini muhimu: `restorecon` ya kawaida **si kila mara hurudisha kikamilifu label yenye kutia shaka**. Ikiwa aina lengwa iko kwenye `customizable_types`, huenda ukahitaji `-F` ili kulazimisha uwekaji upya kamili. Kwa mtazamo wa offensive, hii inaeleza kwa nini `chcon` isiyo ya kawaida inaweza wakati mwingine kuendelea kuwepo baada ya usafishaji wa kawaida wa "tayari tuliendesha restorecon".
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Amri zenye thamani kubwa za kutafuta katika `sudo -l`, root wrappers, automation scripts, au file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Ikiwa MAC capability yoyote itaonekana, kagua pia [ukurasa wa Linux capabilities](linux-capabilities.md); `cap_mac_admin` na `cap_mac_override` si za kawaida, lakini zinahusiana moja kwa moja na SELinux inapokuwa sehemu ya boundary.

Vinavyovutia hasa:

- `semanage fcontext`: hubadilisha kwa kudumu label ambayo path inapaswa kupokea
- `restorecon` / `setfiles`: hutumia tena mabadiliko hayo kwa kiwango kikubwa
- `semodule -i`: hupakia custom policy module
- `semanage permissive -a <domain_t>`: hufanya domain moja kuwa permissive bila kubadilisha host nzima
- `setsebool -P`: hubadilisha policy booleans kwa kudumu
- `load_policy`: hupakia tena policy inayotumika

Hivi mara nyingi ni **helper primitives**, si root exploits zinazojitegemea. Thamani yake ni kwamba zinakuwezesha:

- kufanya target domain kuwa permissive
- kupanua access kati ya domain yako na protected type
- kubadilisha label za files zinazodhibitiwa na attacker ili privileged service iweze kuzisoma au kuzitekeleza
- kudhoofisha confined service kiasi kwamba bug ya ndani iliyopo iweze kutumiwa

Mifano ya ukaguzi:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Ikiwa unaweza kupakia policy module ukiwa root, kwa kawaida unadhibiti mpaka wa SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Ndiyo sababu `audit2allow`, `semodule`, na `semanage permissive` zinapaswa kuchukuliwa kama admin surfaces nyeti wakati wa post-exploitation. Zinaweza kubadilisha kimya kimya chain iliyozuiwa kuwa inayofanya kazi bila kubadilisha UNIX permissions za kawaida.

## Denials Zilizofichwa na Utoaji wa Module

Changamoto ya kawaida sana ya offensive ni chain inayoshindwa kwa `EACCES` isiyoeleza mengi, huku AVC denial inayotarajiwa haionekani kamwe. Rules za `dontaudit` zinaweza kuwa zinaficha permission hususa unayohitaji. Ikiwa unaweza kuendesha `semodule` kupitia `sudo` au wrapper nyingine yenye privileged access, kuzima `dontaudit` kwa muda kunaweza kubadilisha failure isiyo na maelezo kuwa policy clue sahihi:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Hii pia ni muhimu kwa kukagua kile ambacho local admins tayari wamebadilisha. Custom module ndogo au one-domain permissive rule mara nyingi huwa ndiyo sababu target service inafanya kazi kwa uhuru zaidi kuliko inavyopendekezwa na base policy.

## Vidokezo vya Ukaguzi

AVC denials mara nyingi ni signal ya offensive, si defensive noise pekee. Zinakuonyesha:

- ni target object/type gani uliyofikia
- ni permission gani iliyokataliwa
- ni domain gani unayodhibiti kwa sasa
- ikiwa policy change ndogo ingewezesha chain kufanya kazi
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Ikiwa exploit ya ndani au jaribio la persistence linaendelea kushindikana kwa `EACCES` au hitilafu zisizo za kawaida za "permission denied" licha ya kuwa na ruhusa za DAC zinazoonekana kama za root, SELinux kwa kawaida inafaa kukaguliwa kabla ya kuacha vector hiyo.

## Users wa SELinux

Kuna users wa SELinux pamoja na users wa kawaida wa Linux. Kila user wa Linux huunganishwa na user wa SELinux kama sehemu ya policy, jambo linalowezesha mfumo kuweka roles na domains tofauti zinazoruhusiwa kwa accounts tofauti.

Ukaguzi wa haraka:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Kwenye mifumo mingi maarufu, users hupangiwa `unconfined_u`, hali inayopunguza athari za kivitendo za user confinement. Hata hivyo, kwenye deployments zilizoimarishwa kiusalama, users waliofungwa wanaweza kufanya `sudo`, `su`, `newrole`, na `runcon` ziwe muhimu zaidi kwa sababu **njia ya escalation inaweza kutegemea kuingia kwenye SELinux role/type bora zaidi, si kuwa UID 0 pekee**. Pia kumbuka kuwa baadhi ya users waliofungwa hawawezi kutumia `sudo`/`su` kabisa isipokuwa policy iruhusu wazi underlying setuid transition, hivyo host inayotumia `staff_u` + `sysadm_r` inaweza kubadilisha rule inayoonekana kuwa ndogo ya `sudo ROLE=` / `TYPE=` kuwa mpaka halisi wa privilege.

## SELinux ndani ya Containers

Container runtimes kwa kawaida huanzisha workloads katika domain iliyofungwa kama `container_t` na kuweka container content lebo ya `container_file_t`. Ikiwa container process itatoroka lakini bado inaendelea kutumia container label, writes za host bado zinaweza kushindikana kwa sababu label boundary bado iko salama.

Mfano wa haraka:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Sehemu ya `c647,c780` si mapambo. Katika deployments nyingi za containers, runtimes huweka kategoria za MCS kwa njia ya dynamically ili processes mbili zinazoendesha kama `container_t` bado zitenganishwe. Ikiwa escape itakupeleka kwenye namespace ya host lakini ikaendelea kuhifadhi seti ya kategoria ya awali, kutolingana kwa kategoria bado kunaweza kueleza kwa nini baadhi ya paths za host zinabaki zisizosomeka au zisizoandikika.

Operesheni za kisasa za containers zinazofaa kuzingatiwa:

- `--security-opt label=disable` inaweza kwa ufanisi kuhamisha workload kwenda kwenye type isiyozuiliwa inayohusiana na containers, kama vile `spc_t`
- bind mounts zenye `:z` / `:Z` huanzisha relabeling ya path ya host kwa matumizi ya shared/private container
- relabeling pana ya maudhui ya host inaweza yenyewe kuwa security issue

Ukurasa huu unaweka maudhui kuhusu containers kuwa mafupi ili kuepuka duplication. Kwa abuse cases maalum za containers na mifano ya runtime, angalia:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Marejeo

- [Red Hat docs: Kutumia SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Zana za policy analysis za SELinux](https://github.com/SELinuxProject/setools)
- [Kusimamia users walio confined na wasio confined - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
