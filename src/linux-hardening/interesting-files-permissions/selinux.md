# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux ni mfumo wa **Mandatory Access Control (MAC)** unaotegemea lebo. Kwa vitendo, hii inamaanisha kwamba hata kama ruhusa za DAC, vikundi, au uwezo wa Linux vinaonekana kutosha kutekeleza kitendo fulani, kernel bado inaweza kukikataa kwa sababu **muktadha chanzo** hauruhusiwi kufikia **muktadha lengwa** kwa darasa/ruhusa iliyoombwa.<sup>[[1]](#references)</sup>

Muktadha kwa kawaida huonekana hivi:<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Kwa mtazamo wa privesc, `type` (domain kwa michakato, type kwa objects) kwa kawaida ndiyo sehemu muhimu zaidi:<sup>[[1]](#references)</sup>

- Mchakato huendeshwa katika **domain** kama vile `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Faili na sockets huwa na **type** kama vile `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy huamua kama domain moja inaweza kusoma/kuandika/kuendesha au kuhamia kwenye nyingine

## Uchunguzi wa Haraka

Ikiwa SELinux imewezeshwa, ifanye uchunguzi mapema kwa sababu inaweza kueleza kwa nini njia za kawaida za Linux privesc hazifanyi kazi au kwa nini wrapper yenye ruhusa za juu inayozunguka zana ya SELinux inayoonekana kuwa “isiyo na madhara” ni muhimu sana:<sup>[[1]](#references)</sup>

```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```

Ukaguzi muhimu wa kufuatilia:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>

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

Matokeo muhimu:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- Hali ya `Disabled` au `Permissive` huondoa sehemu kubwa ya thamani ya SELinux kama mpaka wa usalama.
- `unconfined_t` kwa kawaida humaanisha SELinux ipo, lakini haidhibiti mchakato huo kwa kiwango cha maana.
- `default_t`, `file_t`, au lebo zisizo sahihi waziwazi kwenye njia maalum mara nyingi huashiria uwekaji wa lebo usio sahihi au usanidi usiokamilika.
- Mibatilisho ya ndani katika `file_contexts.local` hutangulizwa kuliko chaguo-msingi za policy, kwa hivyo ichunguze kwa makini.

## Uchambuzi wa Policy

SELinux huwa rahisi zaidi kushambulia au kukwepa unapoweza kujibu maswali mawili:

1. **Domain yangu ya sasa inaweza kufikia nini?**
2. **Ni domain gani ninazoweza kuhamia?**

Zana muhimu zaidi kwa hili ni `sepolicy` na **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>

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

Hili ni muhimu hasa wakati host inatumia **watumiaji waliozuiliwa** badala ya kumweka kila mtu kwenye `unconfined_u`. Katika hali hiyo, tafuta:<sup>[[3]](#references)</sup>

- mappings za watumiaji kupitia `semanage login -l`
- roles zinazoruhusiwa kupitia `semanage user -l`
- admin domains zinazoweza kufikiwa kama `sysadm_t`, `secadm_t`, `webadm_t`
- entries za `sudoers` zinazotumia `ROLE=` au `TYPE=`

Ikiwa `sudo -l` ina entries kama hii, SELinux ni sehemu ya mpaka wa ruhusa za juu:<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

Pia angalia kama `newrole` inapatikana:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon` na `newrole` haziwezi kutumiwa moja kwa moja kufanya exploit, lakini ikiwa wrapper yenye mamlaka ya juu au sheria ya `sudoers` inakuruhusu kuchagua role/type inayofaa zaidi, huwa primitive muhimu sana za privilege escalation.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### Kagua entrypoint za transition zinazoweza kuandikwa

Grafu ya transition ni kidokezo tu cha policy. Ili kuigeuza kuwa njia ya attack, tambua executable type inayoingia kwenye domain yenye manufaa zaidi, kisha kagua ikiwa unaweza kurekebisha executable yenye label hiyo au kuibadilisha kupitia parent directory yake.<sup>[[9]](#references)[[20]](#references)</sup> Transition ya `execve` ya kiotomatiki inahitaji sheria inayotumika ya `type_transition`, ruhusa ya source-domain kutekeleza, ruhusa ya target-domain ya `entrypoint`, na ruhusa ya kufanya transition kati ya domains.<sup>[[20]](#references)</sup> Target domain inaweza kupata ufikiaji wa SELinux, lakini utekelezaji wenyewe haubadilishi Linux UID; kagua [SUID/SGID and ACLs](suid-sgid-and-acl-triage.md) kando.<sup>[[20]](#references)[[21]](#references)</sup>

Tumia entrypoint type iliyoripotiwa kukagua sheria husika, kisha kagua path na parent yake ili kubaini kama zina ruhusa ya kuandikwa.<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

Linganisha aina ya entrypoint na njia halisi ya executable. Kagua DAC, ACL, ruhusa ya kuandika ya SELinux kwenye faili au saraka mama, lebo ya faili, na boolean yoyote yenye masharti kabla ya kuchukulia edge ya policy kuwa inaweza kufikiwa.<sup>[[20]](#references)[[22]](#references)</sup> Ikiwa njia inabadilishwa badala ya kuhaririwa moja kwa moja, thibitisha context ya inode mpya: lebo za filesystem huhifadhiwa kama extended attributes, na faili iliyobadilishwa inaweza isibaki na aina ya entrypoint.<sup>[[21]](#references)</sup> Programu zinazotambua SELinux zinaweza kuomba transition kwa kutumia `setexeccon`, kwa hivyo kutokuwepo kwa rule ya kiotomatiki ya `type_transition` hakumaanishi kuwa transition zote haziwezekani.<sup>[[20]](#references)</sup>

## Faili, Kubadilisha Lebo, na Mipangilio Potofu Yenye Thamani Kubwa

Tofauti muhimu zaidi ya kiutendaji kati ya zana za kawaida za SELinux ni:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: mabadiliko ya muda ya lebo kwenye njia mahususi
- `semanage fcontext`: kanuni ya kudumu ya njia-kwa-lebo
- `restorecon` / `setfiles`: tumia tena lebo ya policy/chaguomsingi

Hili ni muhimu sana wakati wa privesc kwa sababu **kubadilisha lebo si suala la mwonekano tu**. Kunaweza kubadilisha faili kutoka "imezuiwa na policy" hadi "inaweza kusomwa/kuendeshwa na huduma yenye ruhusa za juu iliyowekewa mipaka".<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Kagua kanuni za kubadilisha lebo za ndani na mkengeuko wa lebo:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

Jambo moja fiche lakini lenye manufaa: `restorecon` ya kawaida **hairejeshi kila wakati lebo yenye kutia shaka kikamilifu**. Ikiwa aina lengwa iko kwenye `customizable_types`, huenda ukahitaji `-F` ili kulazimisha urejeshaji kamili. Kwa mtazamo wa mashambulizi, hii inaeleza kwa nini `chcon` isiyo ya kawaida inaweza wakati mwingine kubaki licha ya usafishaji wa haraka wa “tayari tumeendesha restorecon”.<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

Amri muhimu za kutafuta katika `sudo -l`, root wrappers, scripts za automation, au file capabilities:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

Ikiwa uwezo wowote wa MAC utaonekana, linganisha pia na [ukurasa wa Linux capabilities](linux-capabilities.md); nyaraka za Linux capabilities zinaeleza kuwa `cap_mac_admin` na `cap_mac_override` ni maalum kwa Smack, kwa hivyo usidhani kwamba majina yake pekee yanakwepa SELinux.<sup>[[5]](#references)</sup>

Vinavyovutia hasa:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: hubadilisha kwa kudumu lebo ambayo njia inapaswa kupewa
- `restorecon` / `setfiles`: hutumia tena mabadiliko hayo kwa kiwango kikubwa
- `semodule -i`: hupakia moduli maalum ya policy
- `semanage permissive -a <domain_t>`: hufanya domain moja iwe permissive bila kubadilisha hali ya host nzima
- `setsebool -P`: hubadilisha booleans za policy kwa kudumu
- `load_policy`: hupakia upya policy inayotumika

Hivi mara nyingi ni **primitive za usaidizi**, si root exploits zinazojitegemea. Umuhimu wake ni kwamba vinakuwezesha:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- kufanya domain lengwa iwe permissive
- kupanua ufikiaji kati ya domain yako na aina iliyolindwa
- kuweka upya lebo za faili zinazodhibitiwa na mshambuliaji ili huduma yenye mapendeleo iweze kuzisoma au kuzitekeleza
- kudhoofisha huduma iliyowekewa vizuizi kiasi cha kufanya hitilafu ya ndani iliyopo iweze kutumiwa

Ukaguzi wa mfano:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```

Ukiweza kupakia moduli ya policy ukiwa root, kwa kawaida unadhibiti mpaka wa SELinux:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>

```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```

Ndiyo maana `audit2allow`, `semodule`, na `semanage permissive` zinapaswa kuchukuliwa kama sehemu nyeti za usimamizi wakati wa post-exploitation. Zinaweza kubadilisha kimyakimya mnyororo uliozuiwa kuwa unaofanya kazi bila kubadilisha ruhusa za kawaida za UNIX.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Kukataliwa kwa Ruhusa Kufaako na Utoaji wa Moduli

Kero ya kawaida sana katika mashambulizi ni mnyororo kushindwa kwa `EACCES` isiyoeleweka huku AVC denial inayotarajiwa isionekane. Sheria za `dontaudit` huenda zinaficha ruhusa husika unayohitaji. Ikiwa unaweza kuendesha `semodule` kupitia `sudo` au wrapper nyingine yenye upendeleo, kuzima `dontaudit` kwa muda kunaweza kubadilisha hitilafu isiyoeleweka kuwa dokezo sahihi kuhusu sera:<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

Hii pia ni muhimu kwa kukagua mabadiliko ambayo wasimamizi wa ndani wamefanya tayari. Moduli ndogo maalum au sheria ya permissive ya domain moja mara nyingi ndiyo sababu huduma lengwa hufanya kazi kwa uhuru zaidi kuliko inavyodokeza sera msingi.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Dalili za Ukaguzi

Kukataliwa kwa AVC mara nyingi ni ishara muhimu kwa mashambulizi, si kelele za kujilinda tu. Hukueleza:<sup>[[1]](#references)[[15]](#references)</sup>

- ni kitu/aina gani lengwa ulichokifikia
- ruhusa gani ilikataliwa
- ni domain gani unayodhibiti kwa sasa
- kama mabadiliko madogo ya sera yangewezesha mnyororo kufanya kazi

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

Ikiwa exploit ya ndani au jaribio la persistence linaendelea kushindwa kwa `EACCES` au makosa ya ajabu ya "permission denied" licha ya ruhusa za DAC zinazoonekana kuwa za root, kwa kawaida inafaa kukagua SELinux kabla ya kuachana na vector.<sup>[[1]](#references)</sup>

## Watumiaji wa SELinux

Kuna watumiaji wa SELinux pamoja na watumiaji wa kawaida wa Linux. Kila mtumiaji wa Linux huunganishwa na mtumiaji wa SELinux kama sehemu ya sera, jambo linalowezesha mfumo kuweka roles na domains tofauti zinazoruhusiwa kwa akaunti tofauti.<sup>[[3]](#references)</sup>

Ukaguzi wa haraka:<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Kwenye mifumo mingi inayotumika sana, watumiaji huunganishwa na `unconfined_u`, jambo linalopunguza athari ya vitendo ya kuwekewa mipaka kwa watumiaji. Hata hivyo, kwenye mifumo iliyoimarishwa, watumiaji waliowekewa mipaka wanaweza kufanya `sudo`, `su`, `newrole`, na `runcon` kuwa muhimu zaidi kwa sababu **njia ya kupata mamlaka ya juu inaweza kutegemea kuingia kwenye role/type bora ya SELinux, si kuwa UID 0 pekee**. Pia kumbuka kwamba baadhi ya watumiaji waliowekewa mipaka hawawezi kutumia `sudo`/`su` kabisa isipokuwa policy iruhusu wazi mabadiliko ya setuid yaliyo chini yake; kwa hiyo, host inayotumia `staff_u` + `sysadm_r` inaweza kugeuza kanuni inayoonekana kuwa ndogo ya `sudo ROLE=` / `TYPE=` kuwa mpaka halisi wa mamlaka.<sup>[[3]](#references)</sup>

## SELinux katika Containers

Container runtimes kwa kawaida huanzisha workloads katika domain iliyowekewa mipaka kama `container_t` na kuweka lebo ya maudhui ya container kama `container_file_t`. Ikiwa mchakato wa container utatoroka lakini bado ukaendelea kutumia lebo ya container, uandishi kwenye host bado unaweza kushindwa kwa sababu mpaka wa lebo haukubadilika.<sup>[[1]](#references)[[17]](#references)</sup>

Mfano wa haraka:<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

Sehemu ya `c647,c780` si mapambo. Katika deployments nyingi za container, runtimes huweka MCS categories kwa nguvu ili michakato miwili inayoendeshwa kama `container_t` bado itenganishwe. Ikiwa escape itakupeleka kwenye host namespace lakini ikahifadhi seti ya categories za awali, kutolingana kwa categories bado kunaweza kueleza kwa nini baadhi ya host paths haziwezi kusomeka au kuandikika.<sup>[[17]](#references)</sup>

Mambo muhimu ya kisasa kuhusu uendeshaji wa container:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` huzima utenganishaji wa SELinux label kwa container
- bind mounts zenye `:z` / `:Z` husababisha relabeling ya host path kwa matumizi ya pamoja/ya faragha ya container
- relabeling pana ya maudhui ya host inaweza yenyewe kuwa suala la usalama

Ukurasa huu unaeleza kwa ufupi maudhui ya container ili kuepuka marudio. Kwa hali za abuse zinazohusu container pekee na mifano ya runtime, angalia:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}



## References

- [1] [Nyaraka za Red Hat: Kutumia SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Zana za uchanganuzi wa sera za SELinux](https://github.com/SELinuxProject/setools)
- [3] [Kusimamia watumiaji waliozuiliwa na wasiozuiliwa - nyaraka za RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Nyaraka za Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Kwa nini unapaswa kutumia Multi-Category Security kwa containers zako za Linux](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Nyaraka za Podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
- [20] [Daftari la SELinux: Mabadiliko ya Domain na Object](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10: Kutumia SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [Mwongozo wa SETools sesearch(1)](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
