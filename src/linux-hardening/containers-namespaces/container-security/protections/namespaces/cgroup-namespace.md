# Namespace ya cgroup

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Namespace ya cgroup haibadilishi cgroups wala haiweki vikomo vya rasilimali yenyewe. Badala yake, hubadilisha **jinsi hierarchy ya cgroup inavyoonekana** kwa process. Kwa maneno mengine, huvirtualize taarifa ya path ya cgroup inayoonekana ili workload ione mwonekano uliowekewa container badala ya hierarchy kamili ya host.

Hiki hasa ni kipengele cha kupunguza mwonekano na taarifa. Husaidia kufanya mazingira yaonekane yamejitegemea na kufichua kidogo kuhusu mpangilio wa cgroup wa host. Hilo linaweza kuonekana kuwa dogo, lakini bado ni muhimu kwa sababu mwonekano usio wa lazima wa muundo wa host unaweza kusaidia reconnaissance na kurahisisha exploit chains zinazotegemea mazingira.

## Uendeshaji

Bila private cgroup namespace, process inaweza kuona paths za cgroup zinazohusiana na host na kufichua sehemu kubwa ya hierarchy ya mashine kuliko inavyohitajika. Kwa private cgroup namespace, `/proc/self/cgroup` na observations zinazohusiana huwa zimewekewa mipaka zaidi kwenye mwonekano wa container yenyewe. Hii husaidia hasa kwenye modern runtime stacks zinazotaka workload ione mazingira safi zaidi na yanayofichua machache kuhusu host.

Virtualization hii pia huathiri `/proc/<pid>/mountinfo`, si `/proc/<pid>/cgroup` pekee. Unaposoma process nyingine kutoka kwenye mtazamo tofauti wa cgroup-namespace, paths zilizo nje ya namespace root yako huonyeshwa zikiwa na components za mwanzo za `../`, jambo linalotoa clue muhimu kwamba unaangalia juu ya delegated subtree yako. Nuance muhimu kwa labs na post-exploitation ni kwamba cgroup namespace mpya iliyoundwa mara nyingi huhitaji **cgroupfs remount kutoka ndani ya namespace hiyo** kabla ya `mountinfo` kuonyesha root mpya kwa usahihi. Vinginevyo, bado unaweza kuona mount root kama `/..`, ikimaanisha kuwa mount iliyorithiwa bado inafichua mwonekano wenye root kwenye ancestor hata ingawa namespace yenyewe tayari imebadilika.<sup>[[1]](#references)</sup>

## Lab

Unaweza kukagua cgroup namespace kwa:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Ikiwa unataka `mountinfo` ionyeshe root mpya ya cgroup-namespace kwa uwazi zaidi, fanya remount ya cgroup filesystem ukiwa ndani ya namespace mpya kisha ulinganishe tena:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Na linganisha tabia ya runtime na:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Mabadiliko yanahusu zaidi kile ambacho process inaweza kuona, si kama cgroup enforcement ipo.

## Athari za Usalama

cgroup namespace inaeleweka vyema zaidi kama **visibility-hardening layer**. Kwa yenyewe, haitazuia breakout ikiwa container ina cgroup mounts zinazoandikika, capabilities pana, au mazingira hatari ya cgroup v1. Hata hivyo, ikiwa host cgroup namespace imeshirikiwa, process hujifunza zaidi kuhusu jinsi mfumo ulivyopangwa na inaweza kupata urahisi zaidi wa kuoanisha cgroup paths zinazohusiana na host na observations nyingine.

Kwenye **cgroup v2**, namespace huanza kuwa muhimu zaidi kidogo kwa sababu delegation rules ni kali zaidi. Ikiwa hierarchy ime-mountiwa kwa `nsdelegate`, kernel huchukulia cgroup namespaces kama mipaka ya delegation: control files za ancestor zinapaswa kubaki nje ya uwezo wa kufikiwa na delegatee, na writes kwenye namespace root huzuiwa kwenye files salama kwa delegation kama `cgroup.procs`, `cgroup.threads`, na `cgroup.subtree_control`.<sup>[[2]](#references)</sup> Hii bado haifanyi namespace kuwa escape primitive yenyewe, lakini hubadilisha kile ambacho workload iliyo-compromise inaweza kukagua na mahali ambapo inaweza kuunda sub-cgroups kwa usalama.

Kwa hiyo, ingawa namespace hii kwa kawaida si nyota kuu katika writeups za container breakout, bado inachangia lengo pana la kupunguza host information leakage na kuzuia cgroup delegation.

## Abuse

Thamani ya abuse ya haraka ni reconnaissance. Ikiwa host cgroup namespace imeshirikiwa, linganisha paths zinazoonekana na utafute maelezo ya hierarchy yanayofichua host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Ikiwa paths za cgroup zenye ruhusa ya kuandikwa pia zimefichuliwa, changanya mwonekano huo na utafutaji wa legacy interfaces hatari:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Namespace yenyewe mara chache hutoa escape ya papo hapo, lakini mara nyingi hufanya mazingira yawe rahisi zaidi kuchora ramani kabla ya kujaribu primitives za abuse zinazotegemea cgroup.

Ukaguzi wa haraka wa uhalisia wa runtime pia husaidia kuweka kipaumbele kwenye njia ya attack. Docker hutoa `--cgroupns=host|private`, huku Podman ikiunga mkono `host`, `private`, `container:<id>`, na `ns:<path>`. Kwenye Podman hasa, default kwa kawaida ni **`host` kwenye cgroup v1** na **`private` kwenye cgroup v2**, kwa hivyo kutambua tu toleo la cgroup tayari hukuambia ni mkao gani wa namespace unaowezekana zaidi kabla hata hujakagua OCI config kamili.

### Modern v2 Recon: Je Hii Ni Subtree Iliyodelegiwa?

Kwenye hosts za kisasa, swali la kuvutia mara nyingi si `release_agent`, bali ni ikiwa process ya sasa iko ndani ya subtree ya **cgroup v2** iliyodelegiwa yenye visibility au write access ya kutosha kujenga groups zilizowekwa ndani yake:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Tafsiri muhimu:

- `cgroup2fs` inamaanisha uko kwenye unified v2 hierarchy, kwa hivyo classic v1-only `release_agent` chains hazipaswi kuwa dhana yako ya kwanza.
- `cgroup.controllers` huonyesha controllers zinazopatikana kutoka kwa parent, na hivyo kile ambacho current subtree inaweza potential kueneza kwa children.
- `cgroup.subtree_control` huonyesha controllers ambazo zimewezeshwa kwa descendants.
- `cgroup.events` hufichua `populated=0/1`, ambayo ni muhimu kwa kufuatilia ikiwa subtree imekuwa tupu, lakini **si** host-code-execution primitive kama v1 `release_agent`.

Ikiwa tayari una privileges za kutosha za kukagua process namespace nyingine moja kwa moja, linganisha views kwa kutumia:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Mfano Kamili: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace pekee kwa kawaida haitoshi kufanya escape. Escalation ya kivitendo hutokea wakati cgroup paths zinazoonyesha host zinapounganishwa na interfaces za cgroup v1 zinazoandikika:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Ikiwa faili hizo zinaweza kufikiwa na kuandikwa, pivot mara moja kwenye mtiririko kamili wa exploitation wa `release_agent` kutoka [cgroups.md](../cgroups.md). Athari yake ni host code execution kutoka ndani ya container.

Bila cgroup interfaces zinazoweza kuandikwa, athari kwa kawaida huwa ni reconnaissance pekee.

## Checks

Lengo la commands hizi ni kubaini ikiwa process ina private cgroup namespace view au inajifunza zaidi kuhusu host hierarchy kuliko inavyohitaji.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Ni nini cha kuvutia hapa:

- Ikiwa kitambulishi cha namespace kinalingana na host process unayoihitaji, cgroup namespace inaweza kuwa imeshirikiwa.
- Njia zinazoonyesha host katika `/proc/self/cgroup` au entries za `mountinfo` zilizo na mizizi kwenye ancestor ni muhimu kwa reconnaissance hata wakati haziwezi kutumiwa moja kwa moja.
- Ikiwa `cgroup2fs` inatumika, lenga delegation, controllers zinazoonekana, na subtrees zinazoweza kuandikwa badala ya kudhani kuwa vijenzi vya zamani vya v1 bado vipo.
- Ikiwa cgroup mounts pia zinaweza kuandikwa, suala la visibility huwa muhimu zaidi.

Cgroup namespace inapaswa kuchukuliwa kama layer ya kuimarisha visibility badala ya kuwa mechanism kuu ya kuzuia escape. Kufichua muundo wa host cgroup bila ulazima huongeza thamani ya reconnaissance kwa attacker.

## Marejeleo

- [1] [cgroup_namespaces(7) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [2] [Control Group v2 — nyaraka za Linux Kernel](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
