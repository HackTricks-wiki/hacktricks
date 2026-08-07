# Namespace ya Mtumiaji

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

User namespace hubadilisha maana ya user na group IDs kwa kuruhusu kernel ku-map IDs zinazoonekana ndani ya namespace kwenda kwenye IDs tofauti zilizo nje yake. Hii ni mojawapo ya protections muhimu zaidi za kisasa za containers kwa sababu inashughulikia moja kwa moja tatizo kubwa la kihistoria katika classic containers: **root ndani ya container ilikuwa karibu kupita kiasi na root kwenye host**.

Kwa kutumia user namespaces, process inaweza kuendeshwa kama UID 0 ndani ya container na bado ihusishwe na unprivileged UID range kwenye host. Hii inamaanisha kwamba process inaweza kufanya kazi kama root kwa tasks nyingi za ndani ya container, huku ikiwa na uwezo mdogo zaidi kwa mtazamo wa host. Hii haisuluhishi kila tatizo la container security, lakini inabadilisha kwa kiasi kikubwa madhara ya container compromise.

## Uendeshaji

User namespace huwa na mapping files kama `/proc/self/uid_map` na `/proc/self/gid_map` zinazoeleza jinsi namespace IDs zinavyotafsiriwa kuwa parent IDs. Ikiwa root ndani ya namespace ime-map kuwa unprivileged host UID, basi operations ambazo zingehitaji host root halisi hazibebi uzito uleule. Hii ndiyo sababu user namespaces ni msingi wa **rootless containers**, na kwa nini ni mojawapo ya tofauti kubwa kati ya default za zamani za rootful containers na miundo ya kisasa zaidi ya least-privilege.

Jambo hili ni la hila lakini muhimu sana: root ndani ya container haijaondolewa, bali **imetafsiriwa**. Process bado hupata mazingira yanayofanana na root locally, lakini host haipaswi kuichukulia kama root kamili.

## Lab

Jaribio la manual ni:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Hii hufanya user wa sasa aonekane kama root ndani ya namespace, huku bado akiwa si root wa host nje yake. Ni mojawapo ya demos rahisi bora za kuelewa kwa nini user namespaces ni muhimu sana.

Katika containers, unaweza kulinganisha mapping inayoonekana kwa:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Matokeo kamili yanategemea ikiwa engine inatumia user namespace remapping au usanidi wa jadi wa rootful.

Unaweza pia kusoma mapping kutoka upande wa host kwa kutumia:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Matumizi ya Runtime

Rootless Podman ni mojawapo ya mifano iliyo wazi zaidi ya user namespaces kutumiwa kama security mechanism ya msingi. Rootless Docker pia inazitegemea. Docker's userns-remap support huboresha usalama katika rootful daemon deployments pia, ingawa kihistoria deployments nyingi ziliiacha ikiwa imezimwa kwa sababu za compatibility. Support ya Kubernetes kwa user namespaces imeboreshwa, lakini adoption na defaults hutofautiana kulingana na runtime, distro, na cluster policy. Mifumo ya Incus/LXC pia hutegemea kwa kiasi kikubwa UID/GID shifting na mawazo ya idmapping.

Mwelekeo wa jumla uko wazi: environments zinazotumia user namespaces kwa umakini kwa kawaida hutoa jibu bora kwa swali "container root inamaanisha nini hasa?" kuliko environments ambazo hazitumii.

## Maelezo ya Juu ya Mapping

Wakati unprivileged process inaandika kwenye `uid_map` au `gid_map`, kernel hutumia rules kali zaidi kuliko inavyofanya kwa privileged parent namespace writer. Mappings chache tu ndizo zinazoruhusiwa, na kwa `gid_map` writer kwa kawaida anahitaji kuzima `setgroups(2)` kwanza:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Maelezo haya ni muhimu kwa sababu yanaeleza kwa nini usanidi wa user namespace wakati mwingine hushindwa katika majaribio ya rootless, na kwa nini runtimes zinahitaji helper logic makini kuhusu ugawaji wa UID/GID.

Kipengele kingine cha hali ya juu ni **ID-mapped mount**. Badala ya kubadilisha umiliki kwenye diski, ID-mapped mount hutumia user-namespace mapping kwenye mount ili umiliki uonekane umetafsiriwa kupitia mwonekano huo wa mount. Hili ni muhimu hasa katika usanidi wa rootless na runtimes za kisasa kwa sababu huwezesha shared host paths kutumiwa bila kutekeleza operesheni za `chown` za kujirudia. Kwa upande wa usalama, kipengele hiki hubadilisha jinsi bind mount inavyoonekana kuwa writable kutoka ndani ya namespace, ingawa hakiandiki upya metadata ya msingi ya filesystem.

Mwisho, kumbuka kwamba process inapounda au kuingia kwenye user namespace mpya, hupokea seti kamili ya capabilities **ndani ya namespace hiyo**. Hii haimaanishi kwamba ghafla imepata nguvu za host-global. Inamaanisha kwamba capabilities hizo zinaweza kutumiwa tu pale ambapo namespace model na protections nyingine zinaruhusu. Hii ndiyo sababu `unshare -U` inaweza ghafla kufanya mounting au privileged operations za ndani ya namespace ziwezekane bila kufanya moja kwa moja mpaka wa host root kutoweka.

## Usanidi usio sahihi

Udhaifu mkuu ni kutotumia user namespaces katika mazingira ambako zingefaa kutumiwa. Ikiwa container root imepangwa moja kwa moja sana na host root, writable host mounts na privileged kernel operations huwa hatari zaidi. Tatizo lingine ni kulazimisha host user namespace sharing au kuzima remapping kwa ajili ya compatibility bila kutambua jinsi hilo linavyobadilisha trust boundary.

User namespaces pia zinahitaji kuzingatiwa pamoja na sehemu nyingine za model. Hata zinapokuwa active, broad runtime API exposure au runtime configuration dhaifu sana bado inaweza kuruhusu privilege escalation kupitia paths nyingine. Lakini bila hizo, breakout classes nyingi za zamani huwa rahisi zaidi ku-exploit.

## Matumizi mabaya

Ikiwa container ni rootful bila user namespace separation, writable host bind mount huwa hatari zaidi kwa kiwango kikubwa kwa sababu process inaweza kweli kuwa inaandika kama host root. Capabilities hatari pia huwa na maana kubwa zaidi. Attacker hahitaji tena kupambana kwa kiwango kikubwa dhidi ya translation boundary kwa sababu translation boundary karibu haipo.

Kuwepo au kutokuwepo kwa user namespace kunapaswa kuchunguzwa mapema wakati wa kutathmini container breakout path. Hakuleti majibu kwa kila swali, lakini huonyesha mara moja ikiwa "root in container" ina umuhimu wa moja kwa moja kwa host.

Abuse pattern inayotumika zaidi ni kuthibitisha mapping na kisha kujaribu mara moja ikiwa maudhui yaliyomountiwa kutoka host yanaweza kuandikwa kwa host-relevant privileges:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Ikiwa faili litatengenezwa likiwa na root halisi wa host, user namespace isolation haipo kwa uhalisia kwenye path hiyo. Wakati huo, matumizi mabaya ya host-file ya kawaida yanawezekana kwa uhalisia:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Uthibitisho salama zaidi wakati wa live assessment ni kuandika marker isiyo na madhara badala ya kurekebisha faili muhimu:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Ukaguzi huu ni muhimu kwa sababu unajibu swali halisi kwa haraka: je, root iliyo ndani ya container hii ina-map kwa ukaribu wa kutosha na root ya host kiasi kwamba writable host mount inakuwa mara moja njia ya host compromise?

### Mfano Kamili: Kupata Tena Capabilities za Ndani ya Namespace

Ikiwa seccomp inaruhusu `unshare` na mazingira yanawezesha user namespace mpya, process inaweza kupata tena full capability set ndani ya namespace hiyo mpya:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Hii pekee yake si host escape. Sababu ya umuhimu wake ni kwamba user namespaces zinaweza kuwezesha tena privileged namespace-local actions ambazo baadaye huunganishwa na weak mounts, kernels zilizo hatarini, au runtime surfaces zilizowekwa wazi isivyofaa.

## Ukaguzi

Amri hizi zinalenga kujibu swali muhimu zaidi kwenye ukurasa huu: root ndani ya container hii ina-mapishwa kuwa nani kwenye host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Kinachovutia hapa:

- Ikiwa mchakato ni UID 0 na maps zinaonyesha mapping ya moja kwa moja au iliyo karibu sana na host root, container ni hatari zaidi.
- Ikiwa root ina-mapia kwenye host range isiyo na privileged, hiyo ni baseline salama zaidi na kwa kawaida huashiria user namespace isolation halisi.
- Faili za mapping zina thamani zaidi kuliko `id` pekee, kwa sababu `id` huonyesha tu utambulisho wa ndani wa namespace.

Ikiwa workload inaendeshwa kama UID 0 na mapping inaonyesha kwamba hii inalingana kwa karibu na host root, unapaswa kutafsiri privileges zilizobaki za container kwa ukali zaidi.

{{#include ../../../../../banners/hacktricks-training.md}}
