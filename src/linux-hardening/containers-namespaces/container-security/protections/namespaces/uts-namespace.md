# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

UTS namespace hutenganisha **hostname** na **NIS domain name** zinazoonekana kwa process. Kwa mtazamo wa kwanza, hii inaweza kuonekana kuwa ndogo ikilinganishwa na mount, PID, au user namespaces, lakini ni sehemu ya kinachofanya container ionekane kama host yake yenyewe. Ndani ya namespace, workload inaweza kuona na wakati mwingine kubadilisha hostname ambayo ni ya namespace hiyo badala ya kuwa ya kimataifa kwa mashine nzima.

Peke yake, hii kwa kawaida si kiini cha breakout story. Hata hivyo, host UTS namespace ikishirikiwa, process yenye privileges za kutosha inaweza kuathiri mipangilio inayohusiana na utambulisho wa host, jambo ambalo linaweza kuwa muhimu kiutendaji na mara chache kiusalama.

## Lab

Unaweza kuunda UTS namespace kwa:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Mabadiliko ya hostname hubaki ya ndani kwa namespace hiyo na hayabadilishi hostname ya global ya host. Hili ni onyesho rahisi lakini lenye ufanisi la sifa ya isolation.

## Matumizi ya Runtime

Containers za kawaida hupata UTS namespace iliyotengwa. Docker na Podman zinaweza kujiunga na UTS namespace ya host kupitia `--uts=host`, na mifumo mingine ya runtime na orchestration inaweza kuwa na mifumo kama hiyo ya kushiriki host. Hata hivyo, mara nyingi private UTS isolation ni sehemu ya kawaida ya usanidi wa container na huhitaji uangalizi mdogo kutoka kwa operator.

## Athari za Usalama

Ingawa UTS namespace kwa kawaida si mojawapo ya namespaces hatari zaidi kushirikiwa, bado huchangia katika uadilifu wa mpaka wa container. Ikiwa UTS namespace ya host imefichuliwa na process ina privileges zinazohitajika, inaweza kuwa na uwezo wa kubadilisha taarifa zinazohusiana na hostname ya host. Hilo linaweza kuathiri monitoring, logging, dhana za uendeshaji, au scripts zinazofanya maamuzi ya trust kulingana na data ya utambulisho wa host.

## Abuse

Ikiwa UTS namespace ya host imeshirikiwa, swali la kiutendaji ni kama process inaweza kurekebisha mipangilio ya utambulisho wa host badala ya kuisoma tu:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Ikiwa container pia ina privilege inayohitajika, jaribu ikiwa hostname inaweza kubadilishwa:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Hili kimsingi ni suala la uadilifu na athari za kiutendaji badala ya escape kamili, lakini bado linaonyesha kuwa container inaweza kuathiri moja kwa moja sifa ya kimataifa ya host.

Athari:

- kubadilisha utambulisho wa host
- kuchanganya logs, monitoring, au automation zinazoamini hostname
- kwa kawaida si escape kamili peke yake isipokuwa ikiunganishwa na udhaifu mwingine

Kwenye mazingira ya mtindo wa Docker, pattern muhimu ya detection upande wa host ni:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Containers zinazoonyesha `UTSMode=host` zinashiriki UTS namespace ya host na zinapaswa kuchunguzwa kwa makini zaidi ikiwa pia zina capabilities zinazoziruhusu kuita `sethostname()` au `setdomainname()`.

## Ukaguzi

Amri hizi zinatosha kuona ikiwa workload ina mwonekano wake wa hostname au inashiriki UTS namespace ya host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Kinachovutia hapa:

- Kulinganisha vitambulisho vya namespace na process ya host kunaweza kuashiria kushirikishwa kwa UTS ya host.
- Ikiwa kubadilisha hostname kunaathiri zaidi ya container yenyewe, workload ina ushawishi mkubwa zaidi kuliko inavyopaswa kwenye utambulisho wa host.
- Kwa kawaida hili ni finding yenye kipaumbele cha chini kuliko masuala ya PID, mount, au user namespace, lakini bado linathibitisha kiwango halisi cha isolation cha process.

Katika mazingira mengi, UTS namespace inapaswa kuchukuliwa hasa kama layer ya kusaidia isolation. Ni mara chache huwa jambo la kwanza kufuatilia katika breakout, lakini bado ni sehemu ya consistency na usalama wa jumla wa mwonekano wa container.
{{#include ../../../../../banners/hacktricks-training.md}}
