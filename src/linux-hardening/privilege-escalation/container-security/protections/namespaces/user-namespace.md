# Namespace ya Mtumiaji

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Namespace ya mtumiaji hubadilisha maana ya user na group IDs kwa kumruhusu kernel kuoanisha IDs zinazoonekana ndani ya namespace na IDs tofauti nje yake. Hii ni mojawapo ya kinga muhimu zaidi za kisasa za container kwa sababu inashughulikia moja kwa moja tatizo kubwa la kihistoria katika classic containers: **root ndani ya container ilikuwa kwa kiasi kisichofaa karibu sana na root kwenye host**.

Kwa namespaces za mtumiaji, mchakato unaweza kuendeshwa kama UID 0 ndani ya container na bado kueleweka kama safu ya UID isiyo ya mamlaka kwenye host. Hii inamaanisha mchakato unaweza kujiweka kama root kwa kazi nyingi ndani ya container huku ikiwa na nguvu ndogo sana kutoka kwa mtazamo wa host. Hii haisuluhishi kila tatizo la usalama la container, lakini hubadilisha kwa kiasi kikubwa matokeo ya uvunjaji wa usalama wa container.

## Uendeshaji

Namespace ya mtumiaji ina faili za mapping kama `/proc/self/uid_map` na `/proc/self/gid_map` zinazofafanua jinsi namespace IDs zinavyotafsiriwa kuwa parent IDs. Ikiwa root ndani ya namespace ina mapping kwa host UID isiyo ya mamlaka, basi operesheni ambazo zingehitaji root halisi wa host hazina uzito ule ule. Hivyo namespaces za mtumiaji zina umuhimu mkubwa kwa **rootless containers** na ni moja ya tofauti kuu kati ya default za zamani za rootful containers na miundo ya kisasa inayofuata least-privilege.

Hoja ni ndogo lakini muhimu: root ndani ya container haiondolewa, bali **imetafsiriwa**. Mchakato bado unaona mazingira yanayofanana na root kwa ndani, lakini host haipaswi kuuitendea kama root kamili.

## Maabara

Jaribio la mkono ni:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Hii inafanya mtumiaji wa sasa aonekane kama root ndani ya namespace, huku bado si root wa host nje yake. Ni mojawapo ya demo rahisi bora za kuelewa kwa nini user namespaces ni muhimu sana.

Katika containers, unaweza kulinganisha mapping inayoonekana na:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Matokeo halisi yanategemea ikiwa engine inatumia user namespace remapping au usanidi wa rootful wa jadi.

Unaweza pia kusoma mapping kutoka upande wa host kwa:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Runtime Usage

Rootless Podman ni mojawapo ya mifano wazi zaidi ya namespaces za watumiaji kutendewa kama mekanismu ya usalama ya daraja la kwanza. Rootless Docker pia inategemea haya. Msaada wa Docker wa userns-remap unaboresha usalama hata katika deployments za daemon zenye root, ingawa kihistoria deployments nyingi ziliiacha zimezimwa kwa sababu za utangamano. Msaada wa Kubernetes kwa namespaces za watumiaji umeboreshwa, lakini utoaji na chaguo-msingi hutofautiana kulingana na runtime, distro, na sera ya klasta. Mifumo ya Incus/LXC pia inategemea sana UID/GID shifting and idmapping ideas.

Mwelekeo wa jumla ni wazi: mazingira yanayotumia namespaces za watumiaji kwa uzito mara nyingi hutoa jibu bora kwa "what does container root actually mean?" kuliko mazingira yasiyotumia.

## Advanced Mapping Details

When an unprivileged process writes to `uid_map` or `gid_map`, the kernel applies stricter rules than it does for a privileged parent namespace writer. Only limited mappings are allowed, and for `gid_map` the writer usually needs to disable `setgroups(2)` first:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Maelezo haya ni muhimu kwa sababu yanaeleza kwa nini usanidi wa user-namespace wakati mwingine hufeli katika majaribio ya rootless na kwa nini runtimes zinahitaji mantiki ya msaada kwa uangalifu kuhusu ugawaji wa UID/GID.

Sifa nyingine ya juu ni the **ID-mapped mount**. Badala ya kubadilisha umiliki uliopo kwenye diski, ID-mapped mount inaweka ramani ya user-namespace kwenye mount ili umiliki ukaonekana umefasiriwa kupitia mtazamo wa mount huo. Hii ni muhimu hasa katika majaribio ya rootless na usanidi wa runtime za kisasa kwa sababu inaruhusu kutumia paths za host zilizoshirikiwa bila kuendesha operesheni za kurudia za `chown`. Kimsingi kwa usalama, sifa hii hubadilisha jinsi bind mount inavyoonekana kuwa inayoweza kuandikwa kutoka ndani ya namespace, ingawa haitarekebishi metadata ya mfumo wa faili chini yake.

Mwisho, kumbuka kwamba wakati mchakato unapotengeneza au kuingia katika user namespace mpya, unapata set kamili ya capabilities **ndani ya namespace hiyo**. Hiyo haimaanishi ghafla imepata nguvu za host-global. Ina maana kwamba capabilities hizo zinaweza kutumika tu pale ambapo muundo wa namespace na kinga nyingine zinazoruhusu. Hii ndiyo sababu `unshare -U` inaweza ghafla kuwezesha mounting au operesheni zenye hadhi ndani ya namespace bila kuondoa mpaka wa host root moja kwa moja.

## Mipangilio potofu

Udhaifu mkubwa ni kuto kutumia user namespaces katika mazingira ambako yangekuwa yanayowezekana. Ikiwa container root inatafsiriwa moja kwa moja kama host root, writable host mounts na operesheni za kernel zenye hadhi zinakuwa hatari zaidi. Tatizo jingine ni kulazimisha kushirikisha host user namespace au kuzima remapping kwa ajili ya compatibility bila kutambua jinsi inavyobadilisha trust boundary.

User namespaces pia zinapaswa kuzingatiwa pamoja na sehemu nyingine za muundo. Hata pale zinapokuwa zikiendeshwa, API kubwa ya runtime au usanidi dhaifu wa runtime bado vinaweza kuruhusu escalation ya dhamana kupitia njia nyingine. Lakini bila yao, aina nyingi za breakout za zamani zinakuwa rahisi zaidi kutumika.

## Matumizi mabaya

Iki container ni rootful bila utofauti wa user namespace, writable host bind mount inakuwa hatari sana kwa sababu mchakato anaweza kweli kuandika kama host root. Capabilities hatari pia zinakuwa na maana zaidi. Mshambulizi hatahitaji tena kupigana kwa nguvu dhidi ya translation boundary kwa sababu translation boundary karibu haipo.

Uwepo au kukosekana kwa user namespace unapaswa kukaguliwa mapema wakati wa kutathmini container breakout path. Haitaelezea kila swali, lakini mara moja inaonyesha kama "root in container" ina umuhimu wa moja kwa moja kwa host.

Mfano wa matumizi mabaya yenye vitendo zaidi ni kuthibitisha ramani kisha mara moja kujaribu ikiwa maudhui yaliyopachikwa kwenye host yanaweza kuandikwa kwa vibali vinavyohusiana na host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Ikiwa faili imeundwa kama real host root, user namespace isolation kwa ufanisi haipo kwa path hiyo. Wakati huo, classic host-file abuses zinakuwa halisi:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Uthibitisho salama zaidi katika tathmini hai ni kuandika alama isiyo hatari badala ya kubadilisha faili muhimu:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Haya ukaguzi ni muhimu kwa sababu yanajibu swali halisi haraka: je, root ndani ya container hii inaendana vya kutosha na root ya host kiasi kwamba mount ya host inayoweza kuandikwa mara moja inakuwa njia ya kukiuka usalama wa host?

### Mfano Kamili: Kupata Tena capabilities za ndani ya namespace

Ikiwa seccomp inaruhusu `unshare` na mazingira yanaruhusu namespace mpya ya user, mchakato unaweza kupata tena seti kamili ya capabilities ndani ya namespace mpya hiyo:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Hii yenyewe si host escape. Sababu inayofanya iwe muhimu ni kwamba user namespaces zinaweza kuwasha tena vitendo vya privileged namespace-local ambavyo baadaye vinaweza kuchanganyika na weak mounts, vulnerable kernels, au runtime surfaces zilizofichuliwa vibaya.

## Checks

Amri hizi zinalenga kujibu swali muhimu zaidi kwenye ukurasa huu: root ndani ya container inamaanisha nini kwenye host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Kinachovutia hapa:

- Ikiwa mchakato ni UID 0 na maps zinaonyesha host-root mapping ya moja kwa moja au ya karibu sana, container ni hatari zaidi.
- Ikiwa root inamap kwa unprivileged host range, hiyo ni msingi salama zaidi na kawaida inaonyesha user namespace isolation halisi.
- Mapping files ni ya thamani zaidi kuliko `id` pekee, kwa sababu `id` inaonyesha tu utambulisho la namespace-local.

Ikiwa workload inaendesha kama UID 0 na mapping inaonyesha kwamba hii inalingana kwa karibu na host root, unapaswa kutafsiri privileges zingine za container kwa ukali zaidi.
