# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

UTS namespace hufanya izoleshini ya **hostname** na **NIS domain name** zinazoweza kuonekana na process. Kuangalia kwa mara ya kwanza kunaweza kuonekana kama jambo dogo ikilinganishwa na mount, PID, au user namespaces, lakini ni sehemu ya kile kinachofanya container ionekane kama host yake mwenyewe. Ndani ya namespace, the workload inaweza kuona na wakati mwingine kubadilisha hostname ambayo ni local kwa namespace hiyo badala ya kuwa global kwa machine.

Peke yake, hii kwa kawaida si kitu kikuu katika hadithi ya breakout. Hata hivyo, mara host UTS namespace inapo gawanywa, process yenye vibali vya kutosha inaweza kuathiri mipangilio inayohusiana na utambulisho wa host, jambo ambalo linaweza kuwa muhimu kivitendo na mara kwa mara kwa usalama.

## Maabara

Unaweza kuunda UTS namespace kwa kutumia:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Mabadiliko ya hostname yanabaki ndani ya namespace hiyo na hayabadili hostname ya kimataifa ya host. Hii ni mfano rahisi lakini wenye ufanisi wa sifa ya kutengwa.

## Matumizi ya Runtime

Containers za kawaida hupata namespace ya UTS iliyotengwa. Docker na Podman zinaweza kujiunga na host UTS namespace kupitia `--uts=host`, na mifumo sawa ya kushirikisha host inaweza kuonekana katika runtimes na orchestration systems nyingine. Hata hivyo, mara nyingi private UTS isolation ni sehemu tu ya usanidi wa kawaida wa container na inahitaji uangalizi mdogo wa operator.

## Athari za Usalama

Ingawa UTS namespace kawaida siyo hatari zaidi kushiriki, bado inachangia uadilifu wa boundary ya container. Ikiwa host UTS namespace itaonekana na process ina privileges zinazohitajika, inaweza kubadilisha taarifa zinazohusiana na hostname ya host. Hiyo inaweza kuathiri monitoring, logging, dhana za utendakazi, au scripts zinazofanya maamuzi ya kuaminiana kulingana na host identity data.

## Matumizi mabaya

Ikiwa host UTS namespace imeshirikiwa, swali la vitendo ni kama process inaweza kubadilisha settings za utambulisho wa host badala ya kuzisoma tu:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Ikiwa container pia ina ruhusa inayohitajika, jaribu kama hostname inaweza kubadilishwa:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Hii kwa msingi ni suala la uadilifu na athari za uendeshaji badala ya full escape, lakini bado inaonyesha kwamba container inaweza kuathiri moja kwa moja host-global property.

Athari:

- Kuingilia utambulisho wa host
- Kuchanganya logi, ufuatiliaji, au michakato ya kiotomatiki inayomwamini hostname
- Kwa kawaida si full escape peke yake isipokuwa ikichanganywa na udhaifu mwingine

Katika mazingira ya aina ya Docker, mfano wa utambuzi upande wa host unaofaa ni:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Makontena zinazoonyesha `UTSMode=host` zinashiriki UTS namespace ya mwenyeji na zinapaswa kukaguliwa kwa umakini zaidi ikiwa pia zina capabilities zinazowawezesha kuita `sethostname()` au `setdomainname()`.

## Checks

Amri hizi zinatosha kuona kama workload ina mtazamo wake wa hostname au inashiriki UTS namespace ya mwenyeji.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Kinachovutia hapa:

- Kulinganisha vitambulisho vya namespace na mchakato wa host kunaweza kuonyesha kushiriki UTS ya host.
- Ikiwa kubadilisha hostname kunaathiri zaidi ya container yenyewe, workload ina ushawishi mkubwa zaidi juu ya utambulisho wa host kuliko inavyostahili.
- Hii kawaida huwa ugunduzi wa kipaumbele cha chini kuliko masuala ya PID, mount, au user namespace, lakini bado inathibitisha ni kwa kiwango gani mchakato umewekwa peke yake.

Katika mazingira mengi, UTS namespace inafaa kuonekana kama tabaka la msaada la kutenganisha. Ni nadra kuwa kitu cha kwanza unachokifuatilia katika breakout, lakini bado ni sehemu ya uthabiti na usalama wa mtazamo wa container.
{{#include ../../../../../banners/hacktricks-training.md}}
