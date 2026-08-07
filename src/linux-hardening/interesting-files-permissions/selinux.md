# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux ni mfumo wa **Mandatory Access Control (MAC)** unaotegemea **labels**. Kwa vitendo, hii inamaanisha kwamba hata kama ruhusa za DAC, groups, au Linux capabilities zinaonekana kutosha kwa kitendo fulani, kernel bado inaweza kukikataa kwa sababu **source context** hairuhusiwi kufikia **target context** kwa class/permission iliyoombwa.

Context kwa kawaida huonekana hivi:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Kwa mtazamo wa privesc, `type` (domain kwa processes, type kwa objects) kwa kawaida ndiyo field muhimu zaidi:

- Process huendeshwa katika **domain** kama vile `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Files na sockets zina **type** kama vile `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy huamua ikiwa domain moja inaweza kusoma/kuandika/kutekeleza/kubadilisha kuwa nyingine

## Fast Enumeration

Ikiwa SELinux imewezeshwa, ifanyie Enumeration mapema kwa sababu inaweza kueleza kwa nini njia za kawaida za Linux privesc zinashindwa au kwa nini wrapper yenye privileged inayozunguka SELinux tool "isiyo na madhara" kwa kweli ni muhimu sana:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Ukaguzi muhimu wa kufuatilia:
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
Matokeo muhimu:

- Modi ya `Disabled` au `Permissive` huondoa sehemu kubwa ya thamani ya SELinux kama mpaka.
- `unconfined_t` kwa kawaida humaanisha kuwa SELinux ipo, lakini haimzuii kwa maana halisi mchakato huo.
- `default_t`, `file_t`, au labels zilizo wazi kuwa si sahihi kwenye paths maalum mara nyingi huashiria mislabeling au deployment isiyokamilika.
- Overrides za ndani katika `file_contexts.local` huwa na kipaumbele kuliko policy defaults, kwa hivyo zipitie kwa makini.

## Uchambuzi wa Policy

SELinux ni rahisi zaidi kushambulia au ku-bypass unapoweza kujibu maswali mawili:

1. **Ni nini ambacho domain yangu ya sasa inaweza kufikia?**
2. **Ni domains zipi ninazoweza kuhamia?**

Tools muhimu zaidi kwa hili ni `sepolicy` na **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)</sup>
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
Hii ni muhimu hasa wakati host inatumia **confined users** badala ya kuwapa wote mapping ya `unconfined_u`. Katika hali hiyo, tafuta:<sup>[[3]](#references)</sup>

- user mappings kupitia `semanage login -l`
- roles zinazoruhusiwa kupitia `semanage user -l`
- admin domains zinazoweza kufikiwa kama vile `sysadm_t`, `secadm_t`, `webadm_t`
- entries za `sudoers` zinazotumia `ROLE=` au `TYPE=`

Ikiwa `sudo -l` ina entries kama hii, SELinux ni sehemu ya privilege boundary:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Pia angalia ikiwa `newrole` inapatikana:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` na `newrole` haziwezi kutumiwa vibaya kiotomatiki, lakini ikiwa wrapper yenye privileged au sheria ya `sudoers` inakuruhusu kuchagua role/type bora zaidi, huwa primitives zenye thamani kubwa za escalation.

## Files, Relabeling, na Misconfigurations zenye Thamani Kubwa

Tofauti muhimu zaidi ya kiutendaji kati ya zana za kawaida za SELinux ni:<sup>[[1]](#references)</sup>

- `chcon`: mabadiliko ya muda ya label kwenye path maalum
- `semanage fcontext`: sheria endelevu ya path-to-label
- `restorecon` / `setfiles`: tumia tena policy/default label

Hili ni muhimu sana wakati wa privesc kwa sababu **relabeling si jambo la urembo tu**. Inaweza kubadilisha file kutoka "imezuiwa na policy" kuwa "inasomeka/inatekelezeka na service yenye privileged na iliyofungwa".

Kagua sheria za relabel za ndani na relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Jambo moja lisilo dhahiri lakini lenye manufaa: `restorecon` ya kawaida **hairejeshi kila mara lebo yenye kutia shaka kikamilifu**. Ikiwa aina inayolengwa iko katika `customizable_types`, huenda ukahitaji `-F` ili kulazimisha urejeshaji kamili. Kwa mtazamo wa offensive, hii inaeleza kwa nini `chcon` isiyo ya kawaida wakati mwingine inaweza kusalia baada ya usafishaji wa kawaida wa "tayari tuliendesha restorecon".
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
Ikiwa uwezo wowote wa MAC utaonekana, kagua pia [Linux capabilities page](linux-capabilities.md); `cap_mac_admin` na `cap_mac_override` si za kawaida, lakini zina umuhimu wa moja kwa moja wakati SELinux ni sehemu ya boundary.

Vinavyovutia hasa:

- `semanage fcontext`: hubadilisha kwa kudumu label ambayo path inapaswa kupokea
- `restorecon` / `setfiles`: hutumia tena mabadiliko hayo kwa kiwango kikubwa
- `semodule -i`: hupakia policy module maalum
- `semanage permissive -a <domain_t>`: hufanya domain moja iwe permissive bila kubadilisha host nzima
- `setsebool -P`: hubadilisha policy booleans kwa kudumu
- `load_policy`: hupakia tena policy inayotumika

Mara nyingi hizi ni **helper primitives**, si root exploits zinazojitegemea. Thamani yake ni kwamba zinakuwezesha:

- kufanya target domain iwe permissive
- kupanua access kati ya domain yako na protected type
- kubadilisha label za files zinazodhibitiwa na attacker ili service yenye privileges iweze kuzisoma au kuzitekeleza
- kudhoofisha confined service kiasi cha kufanya local bug iliyopo iwe exploitable

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
Ndiyo sababu `audit2allow`, `semodule`, na `semanage permissive` zinapaswa kuchukuliwa kuwa admin surfaces nyeti wakati wa post-exploitation. Zinaweza kubadilisha chain iliyozuiwa kuwa inayofanya kazi bila kubadilisha UNIX permissions za kawaida.

## Denials Zilizofichwa na Module Extraction

Kero ya kawaida sana ya offensive ni chain inayoshindwa kwa `EACCES` isiyoeleza mengi, huku AVC denial iliyotarajiwa haionekani kamwe. Sheria za `dontaudit` zinaweza kuwa zinaficha permission hususa unayohitaji. Ikiwa unaweza kuendesha `semodule` kupitia `sudo` au privileged wrapper nyingine, kuzima `dontaudit` kwa muda kunaweza kubadilisha failure ya kimya kuwa policy clue sahihi:<sup>[[4]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Hii pia ni muhimu kwa kukagua kile ambacho local admins tayari wamebadilisha. Custom module ndogo au permissive rule ya domain moja mara nyingi ndiyo sababu target service inafanya kazi kwa ulegevu zaidi kuliko inavyopendekezwa na base policy.

## Vidokezo vya Audit

AVC denials mara nyingi ni offensive signal, si defensive noise tu. Zinakuambia:

- ni target object/type gani uliyofikia
- ni permission gani ilikataliwa
- ni domain gani unayo-control kwa sasa
- kama policy change ndogo ingefanya chain ifanye kazi
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Ikiwa local exploit au jaribio la persistence linaendelea kushindikana kwa `EACCES` au hitilafu za ajabu za "permission denied" licha ya kuwepo kwa ruhusa za DAC zinazoonekana kuwa za root, kwa kawaida inafaa kuangalia SELinux kabla ya kuachana na vector hiyo.

## SELinux Users

Kuna SELinux users pamoja na Linux users wa kawaida. Kila Linux user huunganishwa na SELinux user kama sehemu ya policy, jambo linaloiruhusu system kuweka roles na domains tofauti zinazoruhusiwa kwa accounts tofauti.<sup>[[3]](#references)</sup>

Ukaguzi wa haraka:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Kwenye mifumo mingi ya kawaida, users hu-mapishwa kwa `unconfined_u`, jambo linalopunguza athari ya kivitendo ya user confinement. Hata hivyo, kwenye deployments zilizo-hardening, users walio-confined wanaweza kufanya `sudo`, `su`, `newrole`, na `runcon` ziwe muhimu zaidi kwa sababu **escalation path inaweza kutegemea kuingia kwenye SELinux role/type bora zaidi, si kuwa UID 0 pekee**. Pia kumbuka kwamba baadhi ya users walio-confined hawawezi kuendesha `sudo`/`su` kabisa isipokuwa policy iruhusu wazi underlying setuid transition, hivyo host inayotumia `staff_u` + `sysadm_r` inaweza kubadilisha rule inayoonekana kuwa ndogo ya `sudo ROLE=` / `TYPE=` kuwa mpaka halisi wa privilege.<sup>[[3]](#references)</sup>

## SELinux katika Containers

Container runtimes kwa kawaida huzindua workloads kwenye domain iliyo-confined kama `container_t` na kuweka label ya container content kama `container_file_t`. Ikiwa container process itatoroka lakini bado ikaendelea kutumia container label, writes za host bado zinaweza kushindikana kwa sababu label boundary imebaki thabiti.

Mfano mfupi:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Sehemu ya `c647,c780` si mapambo. Katika container deployments nyingi, runtimes huweka MCS categories kwa nguvu ili processes mbili zinazoendesha kama `container_t` bado zitenganishwe. Ikiwa escape itakupeleka kwenye host namespace lakini ikaacha category set ya awali, category mismatches bado zinaweza kueleza kwa nini baadhi ya host paths zinabaki hazisomeki au haziandikiki.

Container operations za kisasa zinazofaa kuzingatiwa:

- `--security-opt label=disable` inaweza kuhamisha workload kwa ufanisi kwenda kwenye unconfined container-related type kama `spc_t`
- bind mounts zenye `:z` / `:Z` huanzisha relabeling ya host path kwa matumizi ya shared/private container
- relabeling pana ya host content inaweza yenyewe kuwa security issue

Ukurasa huu unaweka container content kwa ufupi ili kuepuka marudio. Kwa container-specific abuse cases na runtime examples, angalia:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Marejeo

- [1] [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [3] [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)

{{#include ../../banners/hacktricks-training.md}}
