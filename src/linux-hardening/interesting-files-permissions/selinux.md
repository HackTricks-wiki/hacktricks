# SELinux

SELinux ni mfumo wa **Mandatory Access Control (MAC)** unaotegemea **labels**. Kwa vitendo, hii inamaanisha kwamba hata kama ruhusa za DAC, groups, au Linux capabilities zinaonekana kutosha kwa kitendo fulani, kernel bado inaweza kukikataa kwa sababu **source context** hairuhusiwi kufikia **target context** kwa class/permission iliyoombwa.<sup>[[1]](#references)</sup>

Context kwa kawaida huonekana kama:<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Kwa mtazamo wa privesc, `type` (domain kwa michakato, type kwa objects) kwa kawaida ndiyo field muhimu zaidi:<sup>[[1]](#references)</sup>

- Mchakato huendeshwa katika **domain** kama `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Files na sockets huwa na **type** kama `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy huamua ikiwa domain moja inaweza kusoma/kuandika/kutekeleza au kufanya transition kwenda kwenye nyingine

## Enumeration ya Haraka

Ikiwa SELinux imewezeshwa, ichunguze mapema kwa sababu inaweza kueleza kwa nini njia za kawaida za Linux privesc zinashindwa au kwa nini wrapper yenye privileges inayozunguka SELinux tool "isiyo na madhara" kwa kweli ni muhimu sana:<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Ukaguzi muhimu wa ufuatiliaji:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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
Mambo ya kuvutia yaliyopatikana:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- Hali ya `Disabled` au `Permissive` huondoa sehemu kubwa ya thamani ya SELinux kama boundary.
- `unconfined_t` kwa kawaida humaanisha kuwa SELinux ipo, lakini haiweki vizuizi vya maana kwa mchakato huo.
- `default_t`, `file_t`, au labels zilizo wazi kuwa si sahihi kwenye paths maalum mara nyingi huashiria mislabeling au deployment ambayo haijakamilika.
- Overrides za ndani kwenye `file_contexts.local` huwa na kipaumbele kuliko policy defaults, kwa hivyo zichunguze kwa makini.

## Uchambuzi wa Policy

SELinux ni rahisi zaidi kushambulia au ku-bypass unapoweza kujibu maswali mawili:

1. **Domain yangu ya sasa inaweza kufikia nini?**
2. **Ni domains zipi ninazoweza ku-transition kuingia?**

Tools muhimu zaidi kwa hili ni `sepolicy` na **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>
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
Hii ni muhimu hasa wakati host inatumia **confined users** badala ya kuwapa wote `unconfined_u`. Katika hali hiyo, tafuta:<sup>[[3]](#references)</sup>

- user mappings kupitia `semanage login -l`
- roles zinazoruhusiwa kupitia `semanage user -l`
- admin domains zinazoweza kufikiwa kama vile `sysadm_t`, `secadm_t`, `webadm_t`
- entries za `sudoers` zinazotumia `ROLE=` au `TYPE=`

Ikiwa `sudo -l` ina entries kama hii, SELinux ni sehemu ya mpaka wa privilege:<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Pia angalia kama `newrole` inapatikana:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` na `newrole` hazitumiki moja kwa moja kwa exploit, lakini ikiwa wrapper yenye privileged au sheria ya `sudoers` inakuruhusu kuchagua role/type bora zaidi, huwa primitives zenye thamani kubwa za escalation.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Files, Relabeling, and High-Value Misconfigurations

Tofauti muhimu zaidi ya kiutendaji kati ya tools za kawaida za SELinux ni:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: mabadiliko ya muda ya label kwenye path maalum
- `semanage fcontext`: sheria endelevu ya path-to-label
- `restorecon` / `setfiles`: tumia tena policy/default label

Hili ni muhimu sana wakati wa privesc kwa sababu **relabeling si suala la mwonekano tu**. Inaweza kubadilisha file kutoka "limezuiwa na policy" kuwa "linaweza kusomwa/kutekelezwa na service ya privileged iliyofungiwa".<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Chunguza sheria za local relabel na relabel drift:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Jambo moja lisilo dhahiri lakini lenye manufaa: `restorecon` ya kawaida **hairejeshi kila mara kikamilifu label yenye kutiliwa shaka**. Ikiwa aina lengwa iko kwenye `customizable_types`, huenda ukahitaji `-F` ili kulazimisha uwekaji upya kamili. Kwa mtazamo wa offensive, hii inaeleza kwa nini `chcon` isiyo ya kawaida wakati mwingine inaweza kubaki baada ya usafishaji wa kawaida wa "tayari tuliendesha restorecon".<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Amri muhimu sana za kutafuta katika `sudo -l`, root wrappers, automation scripts, au file capabilities:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Ikiwa uwezo wowote kati ya hiyo miwili ya MAC utaonekana, pia kagua [Linux capabilities page](linux-capabilities.md); nyaraka za Linux capabilities zinaeleza `cap_mac_admin` na `cap_mac_override` kuwa maalum kwa Smack, kwa hiyo usidhani kwamba majina yao pekee yanapita SELinux.<sup>[[5]](#references)</sup>

Vinavyovutia hasa:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: hubadilisha kwa kudumu label ambayo path inapaswa kupokea
- `restorecon` / `setfiles`: hutumia tena mabadiliko hayo kwa kiwango kikubwa
- `semodule -i`: hupakia custom policy module
- `semanage permissive -a <domain_t>`: hufanya domain moja iwe permissive bila kubadilisha host nzima
- `setsebool -P`: hubadilisha policy booleans kwa kudumu
- `load_policy`: hupakia upya policy inayotumika

Hivi mara nyingi ni **helper primitives**, si root exploits zinazojitegemea. Thamani yake ni kwamba vinakuruhusu:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- kufanya target domain iwe permissive
- kupanua access kati ya domain yako na protected type
- kubadilisha label za files zinazodhibitiwa na attacker ili service yenye privileged access iweze kuzisoma au kuzitekeleza
- kudhoofisha confined service kiasi kwamba bug ya ndani iliyopo iweze kutumiwa

Mifano ya ukaguzi:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Ikiwa unaweza kupakia policy module kama root, kwa kawaida unadhibiti SELinux boundary:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Ndiyo maana `audit2allow`, `semodule`, na `semanage permissive` zinapaswa kuchukuliwa kama admin surfaces nyeti wakati wa post-exploitation. Zinaweza kubadilisha kimya kimya chain iliyozuiwa kuwa inayofanya kazi bila kubadilisha ruhusa za kawaida za UNIX.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Denials Zilizofichwa na Utoaji wa Modules

Kero ya kawaida sana ya offensive ni chain inayoshindwa kwa `EACCES` isiyoeleza mengi, huku AVC denial iliyotarajiwa haionekani kamwe. Sheria za `dontaudit` zinaweza kuwa zinaficha ruhusa halisi unayohitaji. Ikiwa unaweza kuendesha `semodule` kupitia `sudo` au wrapper nyingine yenye privileges, kuzima `dontaudit` kwa muda kunaweza kubadilisha failure isiyoonekana kuwa kidokezo sahihi cha policy:<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Hii pia ni muhimu kwa kukagua kile ambacho local admins tayari wamebadilisha. Module ndogo maalum au rule ya permissive ya domain moja mara nyingi ndiyo sababu target service hufanya kazi kwa ulegevu zaidi kuliko inavyopendekezwa na base policy.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Dalili za Ukaguzi

AVC denials mara nyingi ni offensive signal, si kelele za defensive pekee. Zinakuambia:<sup>[[1]](#references)[[15]](#references)</sup>

- ni object/type gani ya target uliyofikia
- ni permission gani iliyokataliwa
- ni domain gani unayoidhibiti kwa sasa
- ikiwa policy change ndogo ingefanya chain ifanye kazi
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Ikiwa local exploit au jaribio la persistence linaendelea kushindikana kwa `EACCES` au hitilafu za ajabu za "permission denied" licha ya kuwa na ruhusa za DAC zinazoonekana kama za root, SELinux kwa kawaida inafaa kuchunguzwa kabla ya kuacha vector hiyo.<sup>[[1]](#references)</sup>

## Watumiaji wa SELinux

Kuna watumiaji wa SELinux pamoja na watumiaji wa kawaida wa Linux. Kila mtumiaji wa Linux huunganishwa na mtumiaji wa SELinux kama sehemu ya policy, jambo linalowezesha mfumo kuweka roles na domains tofauti zinazoruhusiwa kwa akaunti tofauti.<sup>[[3]](#references)</sup>

Ukaguzi wa haraka:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Kwenye mifumo mingi maarufu, users huwekwa kwenye `unconfined_u`, hali inayopunguza athari ya kivitendo ya user confinement. Hata hivyo, kwenye deployments zilizoimarishwa kiusalama, users walio-confined wanaweza kufanya `sudo`, `su`, `newrole`, na `runcon` zivutie zaidi kwa sababu **escalation path inaweza kutegemea kuingia kwenye SELinux role/type bora zaidi, si tu kuwa UID 0**. Pia kumbuka kuwa baadhi ya users walio-confined hawawezi kutumia `sudo`/`su` kabisa isipokuwa policy iruhusu wazi underlying setuid transition, hivyo host inayotumia `staff_u` + `sysadm_r` inaweza kugeuza rule inayoonekana kuwa ndogo ya `sudo ROLE=` / `TYPE=` kuwa mpaka halisi wa privileges.<sup>[[3]](#references)</sup>

## SELinux katika Containers

Container runtimes kwa kawaida huzindua workloads katika domain iliyo-confined kama `container_t` na kuweka label ya container content kuwa `container_file_t`. Ikiwa container process itatoroka lakini bado ikaendelea kutumia container label, writes za host huenda bado zikashindikana kwa sababu mpaka wa label uliendelea kubaki thabiti.<sup>[[1]](#references)[[17]](#references)</sup>

Mfano wa haraka:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Sehemu ya `c647,c780` si mapambo. Katika deployments nyingi za container, runtimes huweka kwa nguvu MCS categories ili processes mbili zinazoendesha kama `container_t` bado zitenganishwe. Ikiwa escape itakupeleka kwenye host namespace lakini ikaacha category set ya awali, kutolingana kwa categories bado kunaweza kueleza kwa nini baadhi ya host paths zinabaki zisizosomeka au zisizoandikika.<sup>[[17]](#references)</sup>

Container operations za kisasa zinazofaa kuzingatiwa:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` huzima utenganishaji wa SELinux label kwa container
- bind mounts zenye `:z` / `:Z` huanzisha relabeling ya host path kwa matumizi ya container ya pamoja/ya faragha
- relabeling pana ya host content inaweza yenyewe kuwa security issue

Ukurasa huu unaweka container content kwa ufupi ili kuepuka duplication. Kwa abuse cases na runtime examples maalum za container, angalia:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Red Hat docs: Kutumia SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Zana za policy analysis za SELinux](https://github.com/SELinuxProject/setools)
- [3] [Kusimamia users walio confined na wasio confined - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Linux manual page](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Linux manual page](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Linux manual page](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Linux manual page](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Linux manual page](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Linux manual page](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Linux manual page](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Podman run documentation](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Kwa nini unapaswa kutumia Multi-Category Security kwa Linux containers](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman top documentation](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Linux manual page](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}
