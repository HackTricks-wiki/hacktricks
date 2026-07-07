# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

cgroup namespace haibadilishi cgroups na yenyewe haitekelezi resource limits. Badala yake, hubadilisha **jinsi cgroup hierarchy inaonekana** kwa process. Kwa maneno mengine, huvirtualize taarifa ya cgroup path inayoonekana ili workload ione container-scoped view badala ya full host hierarchy.

Hii hasa ni feature ya visibility na information-reduction. Husaidia kufanya environment ionekane self-contained na kufichua kidogo zaidi kuhusu cgroup layout ya host. Hilo linaweza kuonekana dogo, lakini bado ni muhimu kwa sababu visibility isiyo ya lazima kwenye host structure inaweza kusaidia reconnaissance na kurahisisha environment-dependent exploit chains.

## Operation

Bila private cgroup namespace, process inaweza kuona host-relative cgroup paths zinazofichua hierarchy zaidi ya machine kuliko inavyofaa. Ukiwa na private cgroup namespace, `/proc/self/cgroup` na observations zinazohusiana huwa localized zaidi kwenye view ya container yenyewe. Hii inasaidia hasa katika modern runtime stacks zinazotaka workload ione environment iliyo safi zaidi na isiyofichua host sana.

Virtualization pia huathiri `/proc/<pid>/mountinfo`, si `/proc/<pid>/cgroup` pekee. Unaposoma process nyingine kutoka perspective tofauti ya cgroup-namespace, paths zilizo nje ya namespace root yako huonyeshwa zikiwa na leading `../` components, ambayo ni clue nzuri kwamba unaangalia juu ya delegated subtree yako. Nuance muhimu kwa labs na post-exploitation ni kwamba cgroup namespace mpya mara nyingi huhitaji **cgroupfs remount kutoka ndani ya namespace hiyo** kabla `mountinfo` haijaonyesha root mpya kwa usafi. Vinginevyo unaweza bado kuona mount root kama `/..`, ambayo inamaanisha inherited mount bado inaonyesha view iliyooteshwa kwenye ancestor-rooted view ingawa namespace yenyewe tayari imebadilika.

## Lab

Unaweza kukagua cgroup namespace kwa:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Ikiwa unataka `mountinfo` ionyeshe root mpya ya cgroup-namespace kwa uwazi zaidi, remount cgroup filesystem kutoka ndani ya namespace mpya na linganisha tena:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Na ulinganishe tabia ya runtime na:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Mabadiliko hayo yanahusu zaidi kile ambacho mchakato unaweza kuona, si kama cgroup enforcement ipo.

## Athari za Usalama

cgroup namespace inaeleweka vyema kama **visibility-hardening layer**. Pekee yake haitazuia breakout ikiwa container ina writable cgroup mounts, broad capabilities, au mazingira hatari ya cgroup v1. Hata hivyo, ikiwa host cgroup namespace inashirikiwa, mchakato hujifunza zaidi kuhusu jinsi system imepangwa na huenda ukaona rahisi kulinganisha host-relative cgroup paths na uchunguzi mwingine.

Kwenye **cgroup v2**, namespace inaanza kuwa muhimu zaidi kwa sababu delegation rules ni kali zaidi. Ikiwa hierarchy ime-mountwa kwa `nsdelegate`, kernel hutibu cgroup namespaces kama delegation boundaries: ancestor control files zinapaswa kubaki nje ya reach ya delegatee, na writes katika namespace root zimewekewa kikomo kwa delegation-safe files kama `cgroup.procs`, `cgroup.threads`, na `cgroup.subtree_control`. Hii bado haifanyi namespace kuwa escape primitive yenyewe, lakini inabadilisha kile ambacho compromised workload inaweza kukagua na mahali ambapo inaweza kuunda sub-cgroups kwa usalama.

Kwa hiyo ingawa namespace hii kwa kawaida si nyota ya writeups za container breakout, bado huchangia kwenye lengo pana la kupunguza host information leakage na kuzuia cgroup delegation.

## Abuse

Thamani ya abuse ya haraka zaidi ni mostly reconnaissance. Ikiwa host cgroup namespace inashirikiwa, linganisha visible paths na uangalie host-revealing hierarchy details:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Ikiwa njia za cgroup zinazoweza kuandikwa pia zimeonyeshwa, changanya uonekanaji huo na utafutaji wa interfaces za urithi hatari:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Namespace yenyewe mara chache hutoa escape ya papo hapo, lakini mara nyingi hufanya mazingira kuwa rahisi kuyachora kabla ya kujaribu cgroup-based abuse primitives.

Ukaguzi wa haraka wa runtime reality pia husaidia kuipa kipaumbele njia ya attack. Docker huonyesha `--cgroupns=host|private`, wakati Podman inaunga mkono `host`, `private`, `container:<id>`, na `ns:<path>`. Kwenye Podman hasa, default huwa kawaida ni **`host` kwenye cgroup v1** na **`private` kwenye cgroup v2**, hivyo kutambua tu cgroup version tayari hukuambia ni namespace posture gani ina uwezekano mkubwa kabla hata hujachunguza kamili OCI config.

### Modern v2 Recon: Is This A Delegated Subtree?

Kwenye hosts za kisasa swali la kuvutia mara nyingi si `release_agent`, bali ni kama mchakato wa sasa umekaa ndani ya delegated **cgroup v2** subtree yenye visibility au write access ya kutosha kujenga nested groups:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Tafsiri muhimu:

- `cgroup2fs` maana yake uko katika hierarchy ya unified v2, kwa hiyo classic v1-only `release_agent` chains zinapaswa kuacha kuwa chaguo lako la kwanza.
- `cgroup.controllers` inaonyesha controllers zipi zinapatikana kutoka kwa parent na kwa hiyo current subtree inaweza kusambaa hadi watoto ipasavyo.
- `cgroup.subtree_control` inaonyesha controllers zipi kwa kweli zimewezeshwa kwa descendants.
- `cgroup.events` inaonyesha `populated=0/1`, ambayo ni muhimu kwa kufuatilia kama subtree imekuwa tupu, lakini si primitive ya host-code-execution kama v1 `release_agent`.

Ikiwa tayari una privilege ya kutosha kukagua namespace ya process nyingine moja kwa moja, linganisha views kwa:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Mfano Kamili: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace pekee kwa kawaida haitoshi kwa escape. Uongezaji wa vitendo hutokea wakati njia za cgroup zinazoonyesha host zinapounganishwa na writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Ikiwa faili hizo zinafikiwa na zinaweza kuandikwa, pivot mara moja kwenda kwenye full `release_agent` exploitation flow kutoka [cgroups.md](../cgroups.md). Athari ni host code execution kutoka ndani ya container.

Bila writable cgroup interfaces, athari huwa kwa kawaida imepunguzwa hadi reconnaissance.

## Checks

Lengo la amri hizi ni kuona kama process ina private cgroup namespace view au inajifunza zaidi kuhusu host hierarchy kuliko inavyohitaji.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Kinachovutia hapa ni:

- Ikiwa namespace identifier inalingana na host process unayojali, cgroup namespace inaweza kuwa shared.
- Host-revealing paths katika `/proc/self/cgroup` au ancestor-rooted entries katika `mountinfo` ni useful reconnaissance hata wakati hazitumiwi moja kwa moja kwa exploitation.
- Ikiwa `cgroup2fs` inatumika, zingatia delegation, visible controllers, na writable subtrees badala ya kudhani bado zipo old v1 primitives.
- Ikiwa cgroup mounts pia ni writable, swali la visibility linakuwa muhimu zaidi.

cgroup namespace inapaswa kutazamwa kama visibility-hardening layer badala ya primary escape-prevention mechanism. Kufichua host cgroup structure bila lazima huongeza reconnaissance value kwa attacker.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
