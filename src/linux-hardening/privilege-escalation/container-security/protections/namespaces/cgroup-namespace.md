# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

The cgroup namespace does not replace cgroups and does not itself enforce resource limits. Badala yake, hubadilisha **jinsi hierarki ya cgroup inavyoonekana** kwa mchakato. Kwa maneno mengine, inaifanya kuwa virtual taarifa za njia za cgroup zinazoweza kuonekana ili workload ione mtazamo unaolengwa kwa container badala ya hierarki kamili ya host.

Hii ni hasa kipengele cha uonekano na kupunguza taarifa. Husaidia kufanya mazingira yaonekane yenye kujitegemea na kuonyesha kidogo kuhusu mpangilio wa cgroup wa host. Hiyo inaweza kuonekana ndogo, lakini bado ni muhimu kwa sababu uonekano usiohitajika wa muundo wa host unaweza kusaidia reconnaissance na kurahisisha environment-dependent exploit chains.

## Uendeshaji

Bila cgroup namespace binafsi, mchakato unaweza kuona njia za cgroup zinazohusiana na host ambazo zinafunua sehemu zaidi ya hierarki ya mashine kuliko inavyotakiwa. Kwa cgroup namespace binafsi, `/proc/self/cgroup` na uchunguzi unaohusiana unakuwa uliolengwa zaidi kwa mtazamo wa container wenyewe. Hii ni muhimu hasa katika modern runtime stacks ambazo zinataka workload ione mazingira safi zaidi, yasiyonafunua sana host.

## Maabara

Unaweza kuchunguza cgroup namespace kwa kutumia:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
Na linganisha tabia za runtime na:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Mabadiliko haya yanahusu zaidi kile mchakato kinaweza kuona, sio kuhusu kama utekeleshaji wa cgroup upo.

## Security Impact

The cgroup namespace inafahamika vizuri zaidi kama **tabaka la kuimarisha uonekano**. Peke yake haitazuia breakout ikiwa container ina writable cgroup mounts, broad capabilities, au mazingira hatarishi ya cgroup v1. Hata hivyo, ikiwa host cgroup namespace inashirikiwa, mchakato unapata maarifa zaidi kuhusu jinsi mfumo ulivyopangwa na unaweza kupata rahisi kulinganisha host-relative cgroup paths na uchunguzi mwingine.

Kwa hivyo ingawa namespace hii kawaida si nyota wa container breakout writeups, bado inachangia lengo kubwa la kupunguza host information leakage.

## Abuse

Thamani ya matumizi mbaya mara moja ni hasa reconnaissance. Ikiwa host cgroup namespace inashirikiwa, linganisha visible paths na tafuta maelezo ya hierarchy yanayofichua host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Ikiwa cgroup paths zinazoweza kuandikwa pia zimefunuliwa, changanya ule muonekano na utafutaji wa interfaces za zamani zenye hatari:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
The namespace yenyewe nadra hutoa escape mara moja, lakini mara nyingi inafanya mazingira kuwa rahisi kuorodhesha kabla ya kujaribu cgroup-based abuse primitives.

### Mfano Kamili: Shared cgroup Namespace + Writable cgroup v1

Cgroup namespace peke yake kwa kawaida si ya kutosha kwa escape. Escalation ya vitendo hutokea wakati host-revealing cgroup paths zinapochanganywa na writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Ikiwa faili hizo zinaweza kufikiwa na kuandikwa, pivot mara moja katika full `release_agent` exploitation flow kutoka [cgroups.md](../cgroups.md). Athari ni host code execution kutoka ndani ya container.

Bila writable cgroup interfaces, athari kwa kawaida inakuwa imezuilika kwa reconnaissance.

## Ukaguzi

Madhumuni ya amri hizi ni kuona kama mchakato una private cgroup namespace view au unapata habari zaidi kuhusu host hierarchy kuliko kinachohitajika.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
- Ikiwa kitambulisho cha namespace kinalingana na mchakato wa host unachoujali, cgroup namespace inaweza kushirikiwa.
- Njia zinazofichua host katika `/proc/self/cgroup` ni muhimu kwa uchunguzi hata pale hazitoweza kutumiwa moja kwa moja.
- Ikiwa cgroup mounts pia yanaweza kuandikwa, swali la uonekano linakuwa muhimu zaidi.

cgroup namespace inapaswa kutumiwa kama tabaka la kupunguza uonekano badala ya kuwa mekanismo kuu wa kuzuia kutoroka. Kufichua muundo wa cgroup wa host bila sababu kunaongeza thamani ya uchunguzi kwa mshambuliaji.
{{#include ../../../../../banners/hacktricks-training.md}}
