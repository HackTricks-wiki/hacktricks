# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

User namespace hubadilisha maana ya user na group IDs kwa kuruhusu kernel kufanya mapping ya IDs zinazoonekana ndani ya namespace kwenda kwenye IDs tofauti zilizo nje yake. Hii ni mojawapo ya protections muhimu zaidi za kisasa za containers kwa sababu inashughulikia moja kwa moja tatizo kubwa la kihistoria katika classic containers: **root aliye ndani ya container hapo awali alikuwa karibu sana kwa njia isiyofaa na root wa host**.

Kwa kutumia user namespaces, process inaweza kuendeshwa kama UID 0 ndani ya container na bado ihusiane na range ya UID isiyo na privileges kwenye host. Hii inamaanisha kuwa process inaweza kufanya kazi kama root kwa tasks nyingi za ndani ya container, huku ikiwa na nguvu ndogo zaidi kwa mtazamo wa host. Hii haisuluhishi kila tatizo la container security, lakini inabadilisha kwa kiasi kikubwa madhara ya container compromise.

## Operation

User namespace huwa na mapping files kama `/proc/self/uid_map` na `/proc/self/gid_map` zinazoeleza jinsi namespace IDs zinavyotafsiriwa kuwa parent IDs. Ikiwa root aliye ndani ya namespace ana-mapishwa kwenye host UID isiyo na privileges, basi operations ambazo zingehitaji root halisi wa host hazina uzito uleule. Hii ndiyo sababu user namespaces ni msingi wa **rootless containers**, na kwa nini ni mojawapo ya tofauti kubwa kati ya rootful container defaults za zamani na designs za kisasa za least-privilege.

Jambo hili ni subtle lakini muhimu sana: root aliye ndani ya container haondolewi, bali **hutafsiriwa**. Process bado hupata environment inayofanana na ya root ndani ya container, lakini host haipaswi kuichukulia kama root kamili.

## Lab

Jaribio la manual ni:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Hii humfanya mtumiaji wa sasa aonekane kama root ndani ya namespace, huku bado akiwa si root wa host nje ya namespace. Ni mojawapo ya mifano rahisi bora ya kuelewa kwa nini user namespaces ni muhimu sana.

Katika containers, unaweza kulinganisha mapping inayoonekana kwa kutumia:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Matokeo halisi yanategemea ikiwa engine inatumia user namespace remapping au configuration ya kawaida zaidi ya rootful.

Unaweza pia kusoma mapping kutoka upande wa host kwa kutumia:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Matumizi ya Runtime

Rootless Podman ni mojawapo ya mifano iliyo wazi zaidi ya user namespaces kutumiwa kama security mechanism ya msingi. Rootless Docker pia hutegemea user namespaces. Usaidizi wa Docker wa `userns-remap` huboresha usalama katika deployments za rootful daemon pia, ingawa kihistoria deployments nyingi ziliuacha ukiwa umezimwa kwa sababu za compatibility. Usaidizi wa Kubernetes kwa user namespaces umeboreshwa, lakini adoption na defaults hutofautiana kulingana na runtime, distro, na cluster policy. Mifumo ya Incus/LXC pia hutegemea sana mawazo ya UID/GID shifting na idmapping.

Mwelekeo wa jumla uko wazi: mazingira yanayotumia user namespaces kwa umakini kwa kawaida hutoa jibu bora zaidi kwa swali la “container root humaanisha nini hasa?” kuliko mazingira yasiyotumia.

## Maelezo ya Juu ya Mapping

Wakati process isiyo na privileges inaandika kwenye `uid_map` au `gid_map`, kernel hutumia sheria kali zaidi kuliko inavyofanya kwa writer mwenye privileges katika parent namespace. Ni mappings chache tu zinazoruhusiwa, na kwa `gid_map` writer kwa kawaida huhitaji kuzima `setgroups(2)` kwanza:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Maelezo haya ni muhimu kwa sababu yanaeleza kwa nini usanidi wa user-namespace wakati mwingine hushindwa katika majaribio ya rootless na kwa nini runtimes zinahitaji helper logic makini kuhusu delegated ya UID/GID.

Kipengele kingine cha hali ya juu ni **ID-mapped mount**. Badala ya kubadilisha umiliki kwenye diski, ID-mapped mount hutumia mapping ya user-namespace kwenye mount ili umiliki uonekane umetafsiriwa kupitia mtazamo huo wa mount. Hili ni muhimu hasa katika usanidi wa rootless na runtimes za kisasa kwa sababu huruhusu shared host paths kutumiwa bila kutekeleza operesheni za kurudia za `chown`. Kwa upande wa usalama, kipengele hiki hubadilisha jinsi bind mount inavyoonekana kuwa writable kutoka ndani ya namespace, ingawa hakibadilishi metadata ya msingi ya filesystem.

Hatimaye, kumbuka kwamba mchakato unapounda au kuingia kwenye user namespace mpya, hupokea full capability set **ndani ya namespace hiyo**. Hii haimaanishi kwamba ghafla umepata uwezo wa host-global. Inamaanisha kwamba capabilities hizo zinaweza kutumika tu pale ambapo namespace model na protections nyingine zinaruhusu. Hii ndiyo sababu `unshare -U` inaweza kufanya mounting au privileged operations za ndani ya namespace ziwezekane ghafla bila kuondoa moja kwa moja mpaka wa host root.

## Mipangilio Isiyo Sahihi

Udhaifu mkuu ni kutotumia user namespaces katika mazingira ambayo matumizi yake yangewezekana. Ikiwa container root inamapping moja kwa moja sana hadi host root, writable host mounts na privileged kernel operations huwa hatari zaidi. Tatizo lingine ni kulazimisha host user namespace sharing au kuzima remapping kwa ajili ya compatibility bila kutambua kiasi ambacho hilo hubadilisha trust boundary.

User namespaces pia zinapaswa kuzingatiwa pamoja na sehemu nyingine za model. Hata zinapokuwa active, broad runtime API exposure au runtime configuration dhaifu sana bado inaweza kuruhusu privilege escalation kupitia njia nyingine. Lakini bila hizo, breakout classes nyingi za zamani huwa rahisi zaidi ku-exploit.

## Matumizi Mabaya

Ikiwa container ni rootful bila user namespace separation, writable host bind mount huwa hatari zaidi kwa kiasi kikubwa kwa sababu mchakato unaweza kuwa unaandika kweli kama host root. Dangerous capabilities pia huwa na maana kubwa zaidi. Attacker hahitaji tena kupambana kwa kiwango kilekile dhidi ya translation boundary kwa sababu translation boundary karibu haipo.

Uwepo au kutokuwepo kwa user namespace kunapaswa kukaguliwa mapema wakati wa kutathmini container breakout path. Hakujibu kila swali, lakini huonyesha mara moja kama "root in container" ina umuhimu wa moja kwa moja kwa host.

Muundo wa matumizi mabaya unaotumika zaidi ni kuthibitisha mapping, kisha kujaribu mara moja kama content iliyomountiwa kutoka host inaweza kuandikwa kwa host-relevant privileges:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Ikiwa faili limeundwa likiwa na umiliki wa root halisi wa host, utenganishaji wa user namespace haupo kwa vitendo kwenye njia hiyo. Wakati huo, matumizi mabaya ya kawaida ya mafaili ya host yanawezekana:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Uthibitishaji salama zaidi wakati wa assessment inayoendelea ni kuandika alama isiyo na madhara badala ya kurekebisha faili muhimu:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Ukaguzi huu ni muhimu kwa sababu unajibu haraka swali halisi: je, root iliyo ndani ya hii container inalingana kwa ukaribu wa kutosha na root ya host kiasi kwamba mount ya host inayoweza kuandikwa inakuwa moja kwa moja njia ya ku-compromise host?

### Full Example: Regaining Namespace-Local Capabilities

Ikiwa seccomp inaruhusu `unshare` na mazingira yanaruhusu user namespace mpya, process inaweza kupata tena seti kamili ya capabilities ndani ya namespace hiyo mpya:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Hii pekee yake si host escape. Sababu ya umuhimu wake ni kwamba user namespaces zinaweza kuwezesha tena vitendo vya privileged vinavyohusisha namespace husika, ambavyo baadaye vinaweza kuunganishwa na mounts dhaifu, kernels zilizo na vulnerabilities, au runtime surfaces zilizoachwa wazi isivyofaa.

## Ukaguzi

Amri hizi zinalenga kujibu swali muhimu zaidi kwenye ukurasa huu: root aliye ndani ya container hii ana-mapishwa kwa mtumiaji gani kwenye host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Kinachovutia hapa:

- Ikiwa mchakato ni UID 0 na maps zinaonyesha mapping ya moja kwa moja au iliyo karibu sana na host root, container ni hatari zaidi.
- Ikiwa root ina-map kwenda kwenye host range isiyo na privileged, huo ni msingi salama zaidi na kwa kawaida huashiria user namespace isolation halisi.
- Faili za mapping zina thamani zaidi kuliko `id` pekee, kwa sababu `id` huonyesha tu utambulisho wa ndani wa namespace.

Ikiwa workload inaendeshwa kama UID 0 na mapping inaonyesha kwamba hii inalingana kwa karibu na host root, unapaswa kutafsiri privileges nyingine za container kwa ukali zaidi.
{{#include ../../../../../banners/hacktricks-training.md}}
