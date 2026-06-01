# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux ni mfumo wa **label-based Mandatory Access Control (MAC)**. Kwa vitendo, hii inamaanisha kwamba hata kama ruhusa za DAC, groups, au Linux capabilities zinaonekana kutosha kwa kitendo fulani, kernel bado inaweza kukikataa kwa sababu **source context** hairuhusiwi kufikia **target context** kwa class/permission iliyoombwa.

A context kwa kawaida huonekana kama:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Kutoka kwa mtazamo wa privesc, `type` (domain kwa processes, type kwa objects) kwa kawaida ndio sehemu muhimu zaidi:

- Process inaendeshwa ndani ya **domain** kama `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Files na sockets zina **type** kama `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy huamua kama domain moja inaweza kusoma/kuandika/kuexecute/kubadilika kwenda nyingine

## Fast Enumeration

Kama SELinux imewashwa, ienumerate mapema kwa sababu inaweza kueleza kwa nini common Linux privesc paths hushindwa au kwa nini privileged wrapper kuzunguka "harmless" SELinux tool kwa kweli ni critical:
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

- Mode ya `Disabled` au `Permissive` huondoa sehemu kubwa ya thamani ya SELinux kama boundary.
- `unconfined_t` kwa kawaida humaanisha SELinux ipo lakini haizuii mchakato huo kwa maana yoyote ya kweli.
- `default_t`, `file_t`, au labels zilizo wazi kuwa si sahihi kwenye paths za custom mara nyingi huonyesha mislabeling au deployment isiyokamilika.
- Local overrides katika `file_contexts.local` zina kipaumbele juu ya policy defaults, kwa hiyo zichunguze kwa makini.

## Policy Analysis

SELinux ni rahisi zaidi kushambulia au bypass unapoweza kujibu maswali mawili:

1. **Domain yangu ya sasa inaweza kufikia nini?**
2. **Naweza transition kuingia domains zipi?**

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
Hii ni muhimu hasa wakati host inatumia **confined users** badala ya ku-map kila mtu kuwa `unconfined_u`. Katika hali hiyo, tafuta:

- user mappings kupitia `semanage login -l`
- allowed roles kupitia `semanage user -l`
- reachable admin domains kama `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers` entries zinazotumia `ROLE=` au `TYPE=`

Kama `sudo -l` ina entries kama hizi, SELinux ni sehemu ya privilege boundary:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Pia pia angalia kama `newrole` inapatikana:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` na `newrole` haziwezi kutumiwa kiotomatiki, lakini ikiwa wrapper yenye privilege au `sudoers` rule inakuruhusu kuchagua role/type bora zaidi, zinakuwa high-value escalation primitives.

## Files, Relabeling, and High-Value Misconfigurations

Tofauti muhimu zaidi ya kiutendaji kati ya common SELinux tools ni:

- `chcon`: badiliko la muda la label kwenye path maalum
- `semanage fcontext`: persistent path-to-label rule
- `restorecon` / `setfiles`: tumia tena policy/default label

Hii ina umuhimu mkubwa sana wakati wa privesc kwa sababu **relabeling si cosmetic tu**. Inaweza kubadilisha file kutoka "blocked by policy" hadi "readable/executable by a privileged confined service".

Angalia local relabel rules na relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Kipengele kimoja cha hila lakini muhimu: `restorecon` ya kawaida **haiti kila wakati lebo ya kushukiwa kikamilifu**. Ikiwa aina lengwa iko kwenye `customizable_types`, unaweza kuhitaji `-F` ili kulazimisha kuweka upya kamili. Kutoka kwa mtazamo wa ushambuliaji, hii inaeleza kwa nini `chcon` isiyo ya kawaida wakati mwingine inaweza kuendelea kuwepo baada ya usafishaji wa kawaida wa "tayari tuliendesha restorecon".
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
Ikiwa uwezo wowote wa MAC unaonekana, pia kagua ukurasa wa [Linux capabilities page](linux-capabilities.md); `cap_mac_admin` na `cap_mac_override` ni za kawaida kidogo lakini zinahusiana moja kwa moja wakati SELinux ni sehemu ya mpaka.

Inayovutia hasa:

- `semanage fcontext`: hubadilisha kwa kudumu lebo ambayo path inapaswa kupokea
- `restorecon` / `setfiles`: hurudisha mabadiliko hayo kwa kiwango kikubwa
- `semodule -i`: hupakia custom policy module
- `semanage permissive -a <domain_t>`: huifanya domain moja kuwa permissive bila kubadilisha host nzima
- `setsebool -P`: hubadilisha policy booleans kwa kudumu
- `load_policy`: hupakia upya active policy

Hizi mara nyingi ni **helper primitives**, si root exploits pekee. Thamani yake ni kwamba zinakuruhusu:

- kufanya target domain iwe permissive
- kupanua access kati ya domain yako na protected type
- kufanya relabel ya attacker-controlled files ili service yenye privileges iweze kuzisoma au kuzitekeleza
- kudhoofisha confined service kiasi kwamba local bug iliyopo inaweza kuwa exploitable

Example checks:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Ikiwa unaweza kupakia policy module kama root, kwa kawaida unadhibiti mpaka wa SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Ndiyo maana `audit2allow`, `semodule`, na `semanage permissive` zinapaswa kutibiwa kama sensitive admin surfaces wakati wa post-exploitation. Zinaweza kubadilisha kimya kimya chain iliyozuiwa kuwa inayofanya kazi bila kubadilisha classic UNIX permissions.

## Hidden Denials and Module Extraction

Kero ya kawaida sana ya offensive ni chain inayoshindwa kwa `EACCES` isiyo na maelezo wakati AVC denial inayotarajiwa haionekani kamwe. `dontaudit` rules zinaweza kuwa zinaficha permission halisi unayohitaji. Ikiwa unaweza kuendesha `semodule` kupitia `sudo` au wrapper nyingine yenye privileges, kuzima kwa muda `dontaudit` kunaweza kubadilisha silent failure kuwa policy clue sahihi:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Hii pia ni muhimu kwa kukagua kile ambacho local admins tayari walibadilisha. Small custom module au one-domain permissive rule mara nyingi ndicho chanzo cha target service kufanya kazi kwa njia iliyo loose zaidi kuliko base policy ingependekeza.

## Audit Clues

AVC denials mara nyingi ni offensive signal, si defensive noise tu. Zinakuambia:

- ni target object/type gani uligonga
- ni permission gani iliyokataliwa
- ni domain gani unadhibiti sasa
- kama mabadiliko madogo ya policy yangefanya chain ifanye kazi
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Ikiwa local exploit au jaribio la persistence linaendelea kushindwa kwa `EACCES` au errors za ajabu za "permission denied" licha ya DAC permissions zinazoonekana kama root, SELinux kwa kawaida inafaa kukaguliwa kabla ya kutupa hiyo vector.

## SELinux Users

Kuna SELinux users pamoja na regular Linux users. Kila Linux user hupangwa kwenye SELinux user kama sehemu ya policy, ambayo huwezesha system kuweka roles na domains tofauti zinazoruhusiwa kwa accounts tofauti.

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Kwenye mifumo mingi ya kawaida, watumiaji huwekwa kwenye `unconfined_u`, jambo linalopunguza athari ya vitendo ya confinement ya user. Hata hivyo, kwenye deployments zilizohardened, users walio confined wanaweza kufanya `sudo`, `su`, `newrole`, na `runcon` kuwa za kuvutia zaidi kwa sababu **njia ya escalation inaweza kutegemea kuingia kwenye SELinux role/type bora zaidi, si tu kuwa UID 0**. Pia kumbuka kuwa baadhi ya users walio confined hawawezi kuinvoke `sudo`/`su` kabisa isipokuwa policy iruhusu wazi setuid transition ya msingi, hivyo host inayotumia `staff_u` + `sysadm_r` inaweza kugeuza sheria inayoonekana ndogo ya `sudo ROLE=` / `TYPE=` kuwa mpaka halisi wa privilege.

## SELinux in Containers

Container runtimes kwa kawaida huzindua workloads kwenye domain iliyoconfined kama `container_t` na ku-label content ya container kama `container_file_t`. Ikiwa container process itatoroka lakini bado inatumia container label, writes kwenye host bado zinaweza kushindwa kwa sababu mpaka wa label ulibaki salama.

Mfano wa haraka:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Sehemu ya `c647,c780` si mapambo. Katika deployments nyingi za container, runtimes huweka MCS categories kwa njia ya dynamic ili kwamba processes mbili zinazofanya kazi kama `container_t` bado zitenganishwe kutoka kwa kila moja. Ikiwa escape inakuweka ndani ya host namespace lakini inahifadhi original category set, category mismatches bado zinaweza kueleza kwa nini baadhi ya host paths hubaki kutosomeka au kutowezekana kuandikwa.

Modern container operations zinazostahili kuzingatiwa:

- `--security-opt label=disable` inaweza kwa vitendo kuhamisha workload kwenda kwenye unconfined container-related type kama `spc_t`
- bind mounts zenye `:z` / `:Z` huchochea relabeling ya host path kwa matumizi ya shared/private container
- broad relabeling ya host content inaweza kuwa security issue yenyewe

Ukurasa huu unaweka container content fupi ili kuepuka duplication. Kwa container-specific abuse cases na runtime examples, angalia:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
