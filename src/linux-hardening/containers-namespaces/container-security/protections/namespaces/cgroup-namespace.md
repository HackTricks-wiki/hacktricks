# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

cgroup namespace haibadilishi cgroups wala haiweki yenyewe mipaka ya rasilimali. Badala yake, hubadilisha **jinsi hierarchy ya cgroup inavyoonekana** kwa process. Kwa maneno mengine, hu-virtualize taarifa za njia za cgroup zinazoonekana, ili workload ione mwonekano unaohusishwa na container badala ya hierarchy kamili ya host.

Hiki hasa ni kipengele cha kupunguza mwonekano na taarifa. Husaidia kufanya mazingira yaonekane kuwa yamejitenga na kufichua machache kuhusu mpangilio wa cgroup wa host. Huenda hilo likaonekana kuwa jambo dogo, lakini bado ni muhimu kwa sababu mwonekano usio wa lazima wa muundo wa host unaweza kusaidia reconnaissance na kurahisisha exploit chains zinazotegemea mazingira.

## Uendeshaji

Bila cgroup namespace ya kibinafsi, process inaweza kuona njia za cgroup zinazohusiana na host, ambazo hufichua sehemu kubwa ya hierarchy ya mashine kuliko inavyohitajika. Ikiwa kuna cgroup namespace ya kibinafsi, `/proc/self/cgroup` na taarifa nyingine zinazohusiana huwa zimewekewa mipaka zaidi kwa mwonekano wa container yenyewe. Hii husaidia hasa katika runtime stacks za kisasa zinazotaka workload ione mazingira safi zaidi na yasiyofichua sana taarifa za host.

Virtualization hii pia huathiri `/proc/<pid>/mountinfo`, na si `/proc/<pid>/cgroup` pekee. Unaposoma process nyingine kutoka kwenye mtazamo tofauti wa cgroup namespace, njia zilizo nje ya namespace root yako huonyeshwa zikiwa na vipengele vya mwanzo vya `../`, ambavyo ni kidokezo muhimu kwamba unaangalia juu ya subtree uliyopewa. Jambo muhimu kwa labs na post-exploitation ni kwamba cgroup namespace iliyoundwa hivi karibuni mara nyingi huhitaji **cgroupfs remount kutoka ndani ya namespace hiyo** kabla `mountinfo` haijaonyesha root mpya kwa usahihi. Vinginevyo, bado unaweza kuona mount root kama `/..`, jambo linalomaanisha kuwa mount iliyorithiwa bado inaonyesha mwonekano wenye root kwenye ancestor, ingawa namespace yenyewe tayari imebadilika.

## Lab

Unaweza kukagua cgroup namespace kwa:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Ikiwa unataka `mountinfo` ionyeshe root mpya ya cgroup-namespace kwa uwazi zaidi, fanya remount ya cgroup filesystem kutoka ndani ya namespace mpya kisha linganisha tena:
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
Mabadiliko yanahusu zaidi kile ambacho process inaweza kuona, si kuhusu kama cgroup enforcement ipo.

## Athari za Usalama

cgroup namespace inaeleweka vyema kama **visibility-hardening layer**. Yenyewe haiwezi kuzuia breakout ikiwa container ina writable cgroup mounts, broad capabilities, au mazingira hatari ya cgroup v1. Hata hivyo, ikiwa host cgroup namespace imeshirikiwa, process hujifunza zaidi kuhusu jinsi mfumo ulivyopangwa na inaweza kupata urahisi zaidi wa kuoanisha cgroup paths zinazohusiana na host na observations nyingine.

Kwenye **cgroup v2**, namespace huanza kuwa muhimu zaidi kwa kiasi fulani kwa sababu delegation rules ni kali zaidi. Ikiwa hierarchy ime-mountiwa kwa `nsdelegate`, kernel huchukulia cgroup namespaces kama mipaka ya delegation: ancestor control files zinapaswa kubaki nje ya uwezo wa delegatee, na writes kwenye namespace root zinazuiwa isipokuwa kwa files salama kwa delegation kama vile `cgroup.procs`, `cgroup.threads`, na `cgroup.subtree_control`. Hii bado haifanyi namespace kuwa escape primitive yenyewe, lakini hubadilisha kile ambacho compromised workload inaweza kukagua na mahali inapoweza kuunda sub-cgroups kwa usalama.

Kwa hiyo, ingawa namespace hii kwa kawaida si mhusika mkuu katika container breakout writeups, bado huchangia katika lengo pana la kupunguza host information leakage na kuzuia cgroup delegation.

## Abuse

Thamani ya moja kwa moja ya abuse inahusu zaidi reconnaissance. Ikiwa host cgroup namespace imeshirikiwa, linganisha paths zinazoonekana na utafute maelezo ya hierarchy yanayofichua host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Ikiwa cgroup paths zinazoweza kuandikwa pia zimefichuliwa, changanya mwonekano huo na utafutaji wa interfaces hatari za legacy:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Namespace yenyewe mara chache husababisha escape ya papo kwa papo, lakini mara nyingi hurahisisha kuchora ramani ya mazingira kabla ya kujaribu primitives za matumizi mabaya yanayotegemea cgroup.

Ukaguzi wa haraka wa hali halisi ya runtime pia husaidia kuweka kipaumbele kwenye njia ya attack. Docker hufichua `--cgroupns=host|private`, huku Podman ikiunga mkono `host`, `private`, `container:<id>`, na `ns:<path>`. Kwenye Podman hasa, chaguo-msingi kwa kawaida ni **`host` kwenye cgroup v1** na **`private` kwenye cgroup v2**, hivyo kutambua tu toleo la cgroup tayari kunakuambia ni posture ipi ya namespace inayowezekana zaidi kabla hata hujakagua OCI config yote.

### Modern v2 Recon: Je, Hii Ni Delegated Subtree?

Kwenye hosts za kisasa, swali muhimu mara nyingi si `release_agent`, bali ikiwa process ya sasa iko ndani ya subtree ya **cgroup v2** iliyokabidhiwa, yenye visibility au write access ya kutosha kujenga nested groups:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Tafsiri muhimu:

- `cgroup2fs` inamaanisha uko kwenye hierarchy ya v2 iliyounganishwa, kwa hivyo chains za kawaida za `release_agent` za v1 pekee hazipaswi kuwa makadirio yako ya kwanza.
- `cgroup.controllers` huonyesha controllers zinazopatikana kutoka kwa parent, na hivyo ni controllers zipi subtree ya sasa inaweza kusambaza kwa children.
- `cgroup.subtree_control` huonyesha controllers ambazo zimewezeshwa kwa descendants.
- `cgroup.events` hufichua `populated=0/1`, jambo linalofaa kufuatilia ikiwa subtree imekuwa tupu, lakini **si primitive ya host-code-execution** kama `release_agent` ya v1.

Ikiwa tayari una privilege ya kutosha kukagua process namespace nyingine moja kwa moja, linganisha views kwa kutumia:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Mfano Kamili: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace pekee kwa kawaida haitoshi kwa escape. escalation ya kiutendaji hutokea wakati paths za cgroup zinazoonyesha host zinapounganishwa na interfaces za cgroup v1 zinazoweza kuandikwa:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Ikiwa hizo files zinaweza kufikiwa na kuandikwa, pivot mara moja kwenye mtiririko kamili wa exploitation wa `release_agent` kutoka [cgroups.md](../cgroups.md). Athari ni host code execution kutoka ndani ya container.

Bila cgroup interfaces zinazoandikika, athari kwa kawaida huwa limited kwenye reconnaissance.

## Ukaguzi

Lengo la commands hizi ni kubaini ikiwa process ina private cgroup namespace view au inajifunza zaidi kuhusu host hierarchy kuliko inavyohitaji.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Kinachovutia hapa:

- Ikiwa kitambulisho cha namespace kinalingana na host process unayoihitaji, cgroup namespace inaweza kuwa shared.
- Njia zinazoonyesha host katika `/proc/self/cgroup` au entries zenye mizizi kwa ancestor katika `mountinfo` ni muhimu kwa reconnaissance hata wakati hazitumiki moja kwa moja.
- Ikiwa `cgroup2fs` inatumika, lenga delegation, controllers zinazoonekana, na subtrees zinazoweza kuandikwa badala ya kudhani kuwa primitives za zamani za v1 bado zipo.
- Ikiwa cgroup mounts pia zinaweza kuandikwa, swali la visibility linakuwa muhimu zaidi.

Cgroup namespace inapaswa kuchukuliwa kama layer ya visibility-hardening badala ya mechanism kuu ya kuzuia escape. Kuonyesha muundo wa host cgroup bila sababu huongeza thamani ya reconnaissance kwa attacker.

## Marejeleo

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
