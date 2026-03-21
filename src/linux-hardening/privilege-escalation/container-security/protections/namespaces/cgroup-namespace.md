# Namespace ya cgroup

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

cgroup namespace haitambuli cgroups na pia haitekelezi vikwazo vya rasilimali yenyewe. Badala yake, hubadilisha **jinsi urutibu wa cgroup unavyoonekana** kwa mchakato. Kwa maneno mengine, inafanya virtualized taarifa za njia za cgroup zinazoweza kuonekana ili workload ione mtazamo wa container pekee badala ya hierarchy kamili ya host.

Hii ni kwa kiasi kikubwa kipengele cha uonekano na kupunguza taarifa. Inasaidia kufanya mazingira yaonekane kama yanayojitegemea na kuonyesha kidogo kuhusu mpangilio wa cgroup wa host. Hii inaweza kuonekana ndogo, lakini bado ni muhimu kwa sababu muonekano usiohitajika wa muundo wa host unaweza kusaidia reconnaissance na kurahisisha environment-dependent exploit chains.

## Uendeshaji

Bila cgroup namespace binafsi, mchakato unaweza kuona njia za cgroup zinazolingana na host ambazo zinafunua sehemu zaidi za hierarchy ya mashine kuliko inavyohitajika. Kwa cgroup namespace binafsi, `/proc/self/cgroup` na uchunguzi unaohusiana unakuwa wa karibu zaidi na mtazamo wa container wenyewe. Hii ni hasa yenye msaada katika runtime stacks za kisasa ambazo zinataka workload ione mazingira safi, yasiyofunua sana host.

## Maabara

Unaweza kuchunguza cgroup namespace kwa:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
Na linganisha tabia ya wakati wa utekelezaji na:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Mabadiliko haya yanahusu zaidi kile mchakato kinaweza kuona, sio kuhusu kama cgroup enforcement inapatikana.

## Athari za Usalama

The cgroup namespace is best understood as a **tabaka la kuimarisha uonekano**. Peke yake haitazuia breakout ikiwa container ina writable cgroup mounts, broad capabilities, au mazingira hatarishi ya cgroup v1. Walakini, ikiwa host cgroup namespace imegawanywa, mchakato unajifunza zaidi kuhusu jinsi mfumo ulivyopangwa na unaweza kupata urahisi kuoanisha host-relative cgroup paths na maoni mengine.

Kwa hivyo, ingawa namespace hii kawaida si nyota ya container breakout writeups, bado inachangia kwa lengo pana la kupunguza host information leakage.

## Matumizi Mabaya

Thamani ya matumizi mabaya ya papo hapo ni hasa reconnaissance. Ikiwa host cgroup namespace imegawanywa, linganisha visible paths na tazama host-revealing hierarchy details:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Ikiwa njia za cgroup zinazoweza kuandikwa pia zimefunuliwa, changanya uwazi huo na utafutaji wa miingiliano ya urithi hatarishi:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Namespace yenyewe nadra hutoa escape mara moja, lakini mara nyingi inafanya mazingira kuwa rahisi kuchunguza kabla ya kujaribu cgroup-based abuse primitives.

### Mfano Kamili: Namespace ya cgroup Iliyoshirikiwa + cgroup v1 Inayoweza Kuandikwa

cgroup namespace peke yake kwa kawaida haitoshi kwa escape. Kuongezeka kwa mamlaka kwa vitendo hutokea wakati host-revealing cgroup paths zinapochanganywa na writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Ikiwa faili hizo zinaweza kufikiwa na kuandikwa, pivot mara moja hadi kwenye mtiririko kamili wa matumizi ya `release_agent` kutoka kwa [cgroups.md](../cgroups.md). Athari ni utekelezaji wa msimbo kwenye host kutoka ndani ya container.

Bila writable cgroup interfaces, athari kwa kawaida ni ndogo na inajumuisha tu ukusanyaji wa taarifa.

## Ukaguzi

Lengo la amri hizi ni kuona ikiwa mchakato una private cgroup namespace view au ikiwa unapata zaidi kuhusu hierarchy ya host kuliko kinachohitajika.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
- Ikiwa kitambulisho cha namespace kinalingana na mchakato wa host unayemjali, cgroup namespace inaweza kushirikiwa.
- Njia zinazofichua host katika `/proc/self/cgroup` ni muhimu kwa reconnaissance hata wakati hazitoweza kutumika moja kwa moja.
- Ikiwa cgroup mounts pia zinaweza kuandikwa, swali la uonekano linakuwa muhimu zaidi.

cgroup namespace inapaswa kuchukuliwa kama tabaka la kuimarisha uonekano badala ya kama mekanismo kuu la kuzuia kutoroka. Kufichua muundo wa host cgroup bila sababu huongeza thamani ya reconnaissance kwa mshambuliaji.
