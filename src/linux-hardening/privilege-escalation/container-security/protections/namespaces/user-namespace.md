# Namespace ya Mtumiaji

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Namespace ya mtumiaji hubadilisha maana ya user na group IDs kwa kuruhusu kernel kuoanisha IDs zinazotazamwa ndani ya namespace na IDs tofauti nje yake. Hii ni moja ya kinga muhimu zaidi za kisasa za container kwa sababu inashughulikia moja kwa moja tatizo kubwa la kihistoria katika containers za kawaida: **root ndani ya container alikuwa karibu mno na root kwenye host**.

Kwa namespace za mtumiaji, mchakato unaweza kuendesha kama UID 0 ndani ya container na bado kuendana na safu ya UID isiyo na ruhusa kwenye host. Hii ina maana mchakato unaweza kutenda kama root kwa kazi nyingi ndani ya container huku ukiwa na nguvu ndogo zaidi kwa mtazamo wa host. Hii haiutulizi kila tatizo la usalama la container, lakini inabadilisha kwa kiasi kikubwa matokeo ya kuathiriwa kwa container.

## Uendeshaji

Namespace ya mtumiaji ina faili za ramani kama `/proc/self/uid_map` na `/proc/self/gid_map` zinazoelezea jinsi IDs za namespace zinavyotafsiriwa hadi parent IDs. Ikiwa root ndani ya namespace inarudishwa kwenye UID ya host isiyo na ruhusa, basi operesheni ambazo zingehitaji root halisi wa host hazina uzito ule ule. Hili ndilo sababu namespace za mtumiaji ni muhimu kwa **rootless containers** na ni moja ya tofauti kubwa kati ya default za zamani za rootful containers na miundo ya kisasa yenye kanuni ya least-privilege.

Hoja ni nyeti lakini muhimu: root ndani ya container haionekani kuondolewa, bali **hubadilishwa**. Mchakato bado unapata mazingira yanayofanana na ya root kwa ndani, lakini host haipaswi kuichukulia kama root kamili.

## Maabara

Jaribio la mkono ni:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Hii inafanya mtumiaji wa sasa aonekane kama root ndani ya namespace huku bado asiyekuwa host root nje yake. Ni mojawapo ya demo rahisi bora za kuelewa kwa nini user namespaces ni za thamani sana.

Katika containers, unaweza kulinganisha visible mapping na:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Matokeo halisi hutegemea ikiwa engine inatumia user namespace remapping au usanidi wa jadi wa rootful.

Unaweza pia kusoma mapping kutoka upande wa host kwa:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Matumizi Wakati wa Uendeshaji

Rootless Podman ni mojawapo ya mifano wazi kabisa ya user namespaces kutumiwa kama mekanismi ya usalama ya daraja la kwanza. Rootless Docker pia inategemea hizo. Msaada wa Docker's userns-remap unaboresha usalama katika deployments za rootful daemon pia, ingawa kihistoria deployments nyingi zilikuwa zimezimwa kwa sababu za ulinganifu. Msaada wa Kubernetes kwa user namespaces umeboreshwa, lakini uenezi na mipangilio ya msingi yanatofautiana kulingana na runtime, distro, na sera za cluster. Mifumo ya Incus/LXC pia inategemea kwa kiasi kikubwa kubadilisha UID/GID na mawazo ya idmapping.

Mwelekeo mkuu ni wazi: mazingira yanayotumia user namespaces kwa umakini mara nyingi hutoa jibu bora zaidi kwa "root ya container kwa kweli inamaanisha nini?" kuliko yale ambayo hayatumii.

## Maelezo ya Ramani Zinazoendelea

Wakati mchakato usio na ruhusa unaandika kwenye `uid_map` au `gid_map`, kernel inatumia kanuni kali zaidi kuliko anazotumia kwa mwandishi mwenye ruhusa wa parent namespace. Ramani zilizopunguzwa tu zinazoruhusiwa, na kwa `gid_map` mwandishi mara nyingi anahitaji kwanza kuzima `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Maelezo haya ni muhimu kwa sababu yanaeleza kwa nini user-namespace setup mara nyingine huweza kushindwa katika rootless experiments na kwa nini runtimes zinahitaji mantiki ya msaada kwa uangalifu inayohusiana na UID/GID delegation.

Another advanced feature is the **ID-mapped mount**. Instead of changing on-disk ownership, an ID-mapped mount applies a user-namespace mapping to a mount so that ownership appears translated through that mount view. This is especially relevant in rootless and modern runtime setups because it allows shared host paths to be used without recursive `chown` operations. Security-wise, the feature changes how writable a bind mount appears from inside the namespace, even though it does not rewrite the underlying filesystem metadata.

Mwisho, kumbuka kwamba wakati mchakato unaunda au kuingia kwenye user namespace mpya, unapata seti kamili ya capability set **inside that namespace**. Hii haimaanishi ghafla imepata host-global power. Ina maana kwamba zile capabilities zinaweza kutumika tu pale ambapo namespace model na kinga nyingine zinaviruhusu. Hii ndiyo sababu `unshare -U` inaweza ghafla kufanya mounting au namespace-local privileged operations kuwa zawezekana bila kuondoa moja kwa moja mipaka ya host root.

## Makosa ya usanidi

Udhaifu mkubwa ni kwa urahisi kutojumuisha user namespaces katika mazingira ambapo zingeweza kutumika. Ikiwa container root maps too directly to host root, writable host mounts na privileged kernel operations zinakuwa hatari zaidi. Tatizo jingine ni kulazimisha host user namespace sharing au kuzima remapping kwa ajili ya compatibility bila kutambua jinsi hiyo inavyobadilisha trust boundary.

User namespaces pia zinapaswa kuzingatiwa pamoja na sehemu nyingine za modeli. Hata zikipotumika, a broad runtime API exposure au runtime configuration dhaifu sana bado inaweza kuruhusu privilege escalation kupitia njia nyingine. Lakini bila wao, mengi ya breakout classes za zamani yanakuwa rahisi zaidi kutumika.

## Matumizi mabaya

Ikiwa container ni rootful bila user namespace separation, writable host bind mount inakuwa hatari zaidi kwa kiasi kikubwa kwa sababu mchakato unaweza kwa kweli kuandika kama host root. Dangerous capabilities pia zinakuwa muhimu zaidi. Mshambuliaji haahitaji tena kupambana sana dhidi ya translation boundary kwa sababu translation boundary karibu haipo.

Uwepo au kutokuwepo kwa user namespace unapaswa kuangaliwa mapema wakati wa kutathmini container breakout path. Hii haiwezi kujibu kila swali, lakini inaonyesha mara moja kama "root in container" ina umuhimu wa moja kwa moja kwa host.

Mfumo wa matumizi mabaya unaofaa zaidi ni kuthibitisha mapping kisha mara moja kujaribu kama host-mounted content inaweza kuandikwa kwa host-relevant privileges:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Iwapo faili imeundwa kama real host root, user namespace isolation kwa ufanisi haipo kwa njia hiyo. Wakati huo, classic host-file abuses zinawezekana:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Uthibitisho salama zaidi katika tathmini ya moja kwa moja ni kuandika alama isiyo hatari badala ya kubadilisha faili muhimu:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Mikaguzi hii ni muhimu kwa sababu zinajibu swali halisi haraka: je, root katika container hii inaendana vya kutosha na host root kiasi kwamba writable host mount mara moja inakuwa host compromise path?

### Mfano Kamili: Kurejesha Namespace-Local Capabilities

Ikiwa seccomp inaruhusu `unshare` na mazingira yanaruhusu user namespace mpya, mchakato unaweza kurejesha seti kamili ya capabilities ndani ya namespace mpya hiyo:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Hii yenyewe si host escape. Sababu inayoifanya iwe muhimu ni kwamba user namespaces zinaweza kuruhusu tena privileged namespace-local actions ambazo baadaye zinaweza kuchanganyika na weak mounts, vulnerable kernels, au runtime surfaces zilizo wazi vibaya.

## Ukaguzi

Amri hizi zinalenga kujibu swali muhimu zaidi katika ukurasa huu: root ndani ya container anamaanisha nini kwenye host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Kinachovutia hapa:

- Ikiwa mchakato ni UID 0 na maps zinaonyesha host-root mapping moja kwa moja au karibu sana, container ni hatari zaidi.
- Ikiwa root anaramishwa kwa host range isiyo na vibali, hiyo ni msingi salama zaidi na kwa kawaida inaonyesha user namespace isolation halisi.
- Mafaili ya mapping yana thamani zaidi kuliko `id` pekee, kwa sababu `id` inaonyesha tu utambulisho wa namespace-local.

Ikiwa workload inaendesha kama UID 0 na mapping inaonyesha kuwa hii inalingana kwa karibu na host root, unapaswa kutafsiri ruhusa nyingine za container kwa umakini zaidi.
{{#include ../../../../../banners/hacktricks-training.md}}
