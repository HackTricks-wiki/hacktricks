# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

UTS namespace hutenga **hostname** na **NIS domain name** zinazoonekana na process. Kwa mtazamo wa kwanza, hii inaweza kuonekana kuwa jambo dogo ikilinganishwa na mount, PID, au user namespaces, lakini ni sehemu ya kinachofanya container ionekane kama host yake yenyewe. Ndani ya namespace, workload inaweza kuona na wakati mwingine kubadilisha hostname iliyo ya ndani ya namespace hiyo badala ya kuwa ya kimataifa kwa mashine nzima.

Peke yake, hii kwa kawaida si kiini cha tukio la breakout. Hata hivyo, host UTS namespace inaposhirikiwa, process yenye privileges za kutosha inaweza kuathiri settings zinazohusiana na utambulisho wa host, jambo ambalo linaweza kuwa muhimu kiutendaji na mara kwa mara pia kwa upande wa security.

## Lab

Unaweza kuunda UTS namespace kwa:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Mabadiliko ya hostname hubaki ndani ya namespace hiyo na hayabadilishi hostname ya jumla ya host. Hii ni mifano rahisi lakini yenye ufanisi ya kuonyesha sifa ya isolation.

## Matumizi ya Runtime

Containers za kawaida hupata UTS namespace iliyotengwa. Docker na Podman zinaweza kujiunga na UTS namespace ya host kupitia `--uts=host`, na mifumo mingine ya runtime na orchestration inaweza pia kutumia miundo kama hiyo ya kushiriki host. Hata hivyo, mara nyingi UTS isolation ya kibinafsi huwa sehemu ya usanidi wa kawaida wa container na huhitaji uangalizi mdogo kutoka kwa operator.

## Athari za Usalama

Ingawa UTS namespace kwa kawaida si mojawapo ya namespaces hatari zaidi kushirikishwa, bado huchangia katika integrity ya mpaka wa container. Ikiwa UTS namespace ya host imefichuliwa na process ina privileges zinazohitajika, inaweza kuwa na uwezo wa kubadilisha taarifa zinazohusiana na hostname ya host. Hilo linaweza kuathiri monitoring, logging, assumptions za kiutendaji, au scripts zinazofanya maamuzi ya trust kulingana na data ya utambulisho wa host.

## Matumizi Mabaya

Ikiwa UTS namespace ya host imeshirikishwa, swali la kivitendo ni iwapo process inaweza kurekebisha settings za utambulisho wa host badala ya kuzisoma tu:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Iwapo container pia ina privilege muhimu, jaribu ikiwa hostname inaweza kubadilishwa:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Hili kimsingi ni suala la integrity na operational impact badala ya full escape, lakini bado linaonyesha kuwa container inaweza kuathiri moja kwa moja property ya host-global.

Impact:

- host identity tampering
- logs, monitoring, au automation inayotegemea hostname kuchanganyikiwa
- kwa kawaida si full escape yenyewe isipokuwa ikiunganishwa na weaknesses nyingine

Kwenye mazingira ya Docker-style, pattern muhimu ya detection upande wa host ni:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Containers zinazoonyesha `UTSMode=host` zinashiriki UTS namespace ya host na zinapaswa kukaguliwa kwa umakini zaidi ikiwa pia zina capabilities zinazoziruhusu kuita `sethostname()` au `setdomainname()`.

## Ukaguzi

Amri hizi zinatosha kubaini ikiwa workload ina mwonekano wake wa hostname au inashiriki UTS namespace ya host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Kinachovutia hapa:

- Kulinganisha vitambulisho vya namespace na mchakato wa host kunaweza kuashiria kushirikiwa kwa host UTS.
- Ikiwa kubadilisha hostname kunaathiri zaidi ya container yenyewe, workload ina ushawishi mkubwa zaidi juu ya utambulisho wa host kuliko inavyopaswa.
- Kwa kawaida, hili ni jambo lenye kipaumbele cha chini kuliko masuala ya PID, mount, au user namespace, lakini bado linathibitisha kiwango halisi cha isolation ya mchakato.

Katika mazingira mengi, UTS namespace inapaswa kuzingatiwa kama layer ya ziada ya isolation. Si mara nyingi huwa jambo la kwanza kuchunguza wakati wa breakout, lakini bado ni sehemu ya uthabiti na usalama wa jumla wa mwonekano wa container.

{{#include ../../../../../banners/hacktricks-training.md}}
