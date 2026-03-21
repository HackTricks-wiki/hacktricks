# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

The UTS namespace inatenganisha the **hostname** na **NIS domain name** vinavyoonekana na mchakato. Kwa mtazamo wa kwanza inaweza kuonekana ya kawaida ikilinganishwa na mount, PID, au user namespaces, lakini ni sehemu ya kile kinachofanya container ionekane kuwa mwenyeji wake mwenyewe. Ndani ya namespace, the workload inaweza kuona na wakati mwingine kubadilisha hostname ambayo ni ya ndani kwa namespace hiyo badala ya kuwa ya global kwa mashine.

Peke yake, hii kawaida si sehemu kuu ya hadithi ya kutoroka. Hata hivyo, mara host UTS namespace inaposhirikiwa, mchakato mwenye vibali vya kutosha unaweza kuathiri mipangilio inayohusiana na utambulisho wa host, ambazo zinaweza kuwa muhimu kimaoperesheni na wakati mwingine kiusalama.

## Lab

You can create a UTS namespace with:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Mabadiliko ya hostname yanabaki ndani ya namespace hiyo na hayabadili hostname ya mfumo wa mwenyeji. Hii ni onyesho rahisi lakini lenye ufanisi la sifa ya kutengwa.

## Matumizi ya Runtime

Containers za kawaida hupata UTS namespace iliyotengwa. Docker na Podman zinaweza kujiunga na host UTS namespace kupitia `--uts=host`, na mifumo sawa ya kushiriki mwenyeji inaweza kuonekana katika runtimes na orchestration systems nyingine. Hata hivyo, kwa wakati mwingi, kutengwa kwa UTS binafsi ni sehemu ya usanidi wa kawaida wa container na kunahitaji uangalizi mdogo kutoka kwa mwendeshaji.

## Athari za Usalama

Ingawa UTS namespace siyo mara nyingi yenye hatari zaidi kushiriki, bado inachangia uadilifu wa mpaka wa container. Ikiwa UTS namespace ya mwenyeji inafichuka na mchakato una vibali vinavyohitajika, unaweza kuweza kubadilisha taarifa zinazohusiana na hostname ya mwenyeji. Hiyo inaweza kuathiri ufuatiliaji, uandishi wa kumbukumbu, dhana za uendeshaji, au skripti ambazo zinafanya maamuzi ya kuamini kwa msingi wa data ya utambulisho wa mwenyeji.

## Matumizi Mabaya

Ikiwa UTS namespace ya mwenyeji imeshirikiwa, swali la vitendo ni je, mchakato unaweza kubadilisha mipangilio ya utambulisho wa mwenyeji badala ya tu kuisoma:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Ikiwa container pia ina privilege inayohitajika, jaribu kama hostname inaweza kubadilishwa:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Hili kwa msingi ni suala la uadilifu na la athari za uendeshaji kuliko full escape, lakini bado linaonyesha kuwa container inaweza kuathiri moja kwa moja host-global property.

Impact:

- kupotosha utambulisho wa host
- kuingiza mkanganyiko kwenye logs, monitoring, au automation ambazo zinaamini hostname
- kawaida sio full escape yenyewe isipokuwa ikichanganywa na udhaifu mwingine

On Docker-style environments, a useful host-side detection pattern is:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Kontena zinazonyesha `UTSMode=host` zinashiriki namespace ya UTS ya mwenyeji na zinapaswa kukaguliwa kwa uangalifu zaidi ikiwa pia zina capabilities zinazowaruhusu kuita `sethostname()` au `setdomainname()`.

## Ukaguzi

Amri hizi zinatosha kuona je workload ina mtazamo wake wa hostname au inashiriki namespace ya UTS ya mwenyeji.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Kinachovutia hapa:

- Kufananisha namespace identifiers na mchakato wa mwenyeji kunaweza kuashiria kushirikiwa kwa UTS ya mwenyeji.
- Ikiwa kubadilisha hostname kunathiri zaidi ya container yenyewe, workload ina ushawishi mkubwa juu ya utambulisho wa mwenyeji kuliko inavyostahili.
- Hii kawaida ni ugunduzi wa kipaumbele cha chini kuliko masuala ya PID, mount, au user namespace, lakini bado inathibitisha jinsi mchakato ulivyo pekee yake.

Katika mazingira mengi, UTS namespace inafikiriwa vizuri zaidi kama tabaka la msaada la kutenganisha. Mara chache ndio kitu cha kwanza unachokimbilia katika breakout, lakini bado ni sehemu ya uthabiti na usalama wa mtazamo wa container.
