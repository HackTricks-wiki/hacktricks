# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

time namespace inafanya virtualize saa zilizochaguliwa, hasa **`CLOCK_MONOTONIC`** na **`CLOCK_BOOTTIME`**. Ni namespace mpya na maalum kuliko mount, PID, network, au user namespaces, na mara chache ndio jambo la kwanza linalowajia operator wakati wa kujadili container hardening. Hata hivyo, ni sehemu ya familia ya namespaces za kisasa na inastahili kueleweka kwa dhana.

Lengo kuu ni kumruhusu mchakato kuona offsets zilizodhibitiwa kwa saa fulani bila kubadilisha mtazamo wa wakati wa host kwa ujumla. Hii ni muhimu kwa workflows za checkpoint/restore, deterministic testing, na baadhi ya tabia za runtime za juu. Mara nyingi si udhibiti mkubwa wa izolatsiooni kwa namna ile ile kama mount au user namespaces, lakini bado inachangia kufanya mazingira ya mchakato kuwa yenye kujitegemea zaidi.

## Maabara

Ikiwa kernel ya host na userspace vinaiunga mkono, unaweza kuchunguza namespace kwa kutumia:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Msaada unabadilika kulingana na toleo la kernel na la zana, kwa hiyo ukurasa huu ni zaidi kuhusu kuelewa utaratibu badala ya kutegemea uonekane katika kila mazingira ya maabara.

### Offsets za Wakati

Namespaces za wakati za Linux huvirtualisa (virtualize) offsets za `CLOCK_MONOTONIC` na `CLOCK_BOOTTIME`. Offsets za sasa kwa kila namespace zinaonyeshwa kupitia `/proc/<pid>/timens_offsets`, ambazo kwenye kernels zinazounga mkono zinaweza pia kubadilishwa na mchakato uliobeba `CAP_SYS_TIME` ndani ya namespace husika:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Faili ina tofauti za nanosekunde. Kurekebisha `monotonic` kwa siku mbili kunabadilisha maoni yanayofanana na uptime ndani ya namespace hiyo bila kubadilisha saa ya kuta ya host.

### `unshare` Bendera za msaidizi

Matoleo ya hivi karibuni ya `util-linux` yanatoa bendera za urahisi ambazo zinaandika offsets kiotomatiki:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Bendera hizi kwa ujumla ni maboresho ya utumiaji, lakini pia zinafanya iwe rahisi kutambua kipengele hiki katika nyaraka na majaribio.

## Matumizi ya Runtime

Time namespaces ni mpya zaidi na hazitumiki kwa kiwango sawa na mount au PID namespaces. OCI Runtime Specification v1.1 iliongeza msaada wa wazi kwa `time` namespace na uwanja `linux.timeOffsets`, na matoleo mapya ya `runc` hutekeleza sehemu hiyo ya mfano. Sehemu ndogo ya OCI inavyoonekana:
```json
{
"linux": {
"namespaces": [
{ "type": "time" }
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
This matters because it turns time namespacing from a niche kernel primitive into something that runtimes can request portably.

## Security Impact

Kuna hadithi chache za breakout za jadi zinazolenga time namespace ikilinganishwa na aina nyingine za namespace. Hatari hapa kawaida si kwamba time namespace kwa moja kwa moja inaruhusu escape, bali kwamba wasomaji wanaiangalia kabisa na kwa hivyo kupoteza jinsi runtimes za hali ya juu zinaweza kuunda tabia za mchakato. Katika mazingira maalum, mtazamo wa saa uliobadilishwa unaweza kuathiri checkpoint/restore, observability, au dhana za forensic.

## Abuse

Kawaida hakuna breakout primitive ya moja kwa moja hapa, lakini tabia ya saa iliyobadilishwa bado inaweza kuwa muhimu kuelewa mazingira ya utekelezaji na kutambua vipengele vya runtime vya hali ya juu:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Ikiwa unalinganisha michakato miwili, tofauti hapa zinaweza kusaidia kueleza tabia isiyo ya kawaida ya muda, artifacts za checkpoint/restore, au kutokubaliana kwa logging maalum kwa mazingira.

Impact:

- karibu kila wakati reconnaissance au kuelewa mazingira
- inasaidia kueleza matatizo ya logging, uptime, au checkpoint/restore
- sio kawaida kuwa njia ya moja kwa moja ya container-escape yenyewe

Ni muhimu kufahamu kwamba time namespaces hazifanyi virtualize `CLOCK_REALTIME`, hivyo zenyewe hazimruhusu mshambuliaji kudanganya saa ya mfumo wa mwenyeji au kuvunja moja kwa moja ukaguzi wa muda wa kuisha wa vyeti kwa mfumo mzima. Thamani yao iko hasa katika kuchanganya mantiki inayotegemea monotonic-time, kuiga mende maalum ya mazingira, au kuelewa tabia ya runtime ya kiwango cha juu.

## Checks

These checks are mostly about confirming whether the runtime is using a private time namespace at all.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Kitakachovutia hapa:

- Katika mazingira mengi, thamani hizi hazitasababisha ugunduzi wa usalama mara moja, lakini zinakuonyesha ikiwa kipengele maalumu cha runtime kinatumika.
- Ikiwa unalinganisha michakato miwili, tofauti hapa zinaweza kuelezea utata wa muda au tabia ya checkpoint/restore.

Kwa container breakouts nyingi, the time namespace sio udhibiti wa kwanza utakaochunguza. Hata hivyo, sehemu kamili ya container-security inapaswa kuitaja kwa sababu ni sehemu ya modern kernel model na mara kwa mara ina umuhimu katika advanced runtime scenarios.
