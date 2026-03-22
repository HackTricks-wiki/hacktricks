# Namespace ya Wakati

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Namespace ya wakati hufanya virtualize saa fulani zilizochaguliwa, hasa **`CLOCK_MONOTONIC`** na **`CLOCK_BOOTTIME`**. Ni namespace mpya na maalum zaidi kuliko mount, PID, network, au user namespaces, na si mara nyingi jambo la kwanza msimamizi anafikiria anapozungumzia container hardening. Hata hivyo, ni sehemu ya familia ya namespace za kisasa na inafaa kueleweka kimsingi.

Madhumuni yake kuu ni kumruhusu mchakato kuona offsets zilizodhibitiwa kwa saa fulani bila kubadilisha mtazamo wa wakati wa host kwa ujumla. Hii ni muhimu kwa workflows za checkpoint/restore, upimaji wa deterministic, na baadhi ya tabia za runtime za kiwango cha juu. Si kawaida kuwa udhibiti mkubwa wa kutengwa kama mount au user namespaces, lakini bado huchangia kufanya mazingira ya mchakato kuwa ya kujitegemea zaidi.

## Maabara

Ikiwa kernel na userspace ya host vinaunga mkono, unaweza kuchunguza namespace kwa:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Uungaji mkono unatofautiana kulingana na toleo la kernel na zana, hivyo ukurasa huu unalenga zaidi kuelewa utaratibu kuliko kutegemea utaonekana katika kila mazingira ya maabara.

### Mabadiliko ya Muda

Linux time namespaces huvirtualiza offsets za `CLOCK_MONOTONIC` na `CLOCK_BOOTTIME`. Offsets za sasa kwa kila namespace zinaonyeshwa kupitia `/proc/<pid>/timens_offsets`, ambazo kwenye kernels zinazounga mkono pia zinaweza kubadilishwa na mchakato unaoshikilia `CAP_SYS_TIME` ndani ya namespace husika:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Faili ina tofauti za nanosekundi. Kurekebisha `monotonic` kwa siku mbili kunabadilisha uchunguzi unaofanana na uptime ndani ya namespace hiyo bila kubadilisha saa ya kuta ya host.

### Bendera za msaada za `unshare`

Matoleo ya hivi karibuni ya `util-linux` yanatoa bendera za urahisi ambazo zinaandika offsets kiotomatiki:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Bendera hizi kwa ujumla ni kuboresha utumiaji, lakini pia zinafanya iwe rahisi kutambua kipengele katika nyaraka na katika majaribio.

## Matumizi ya Runtime

namespaces za `time` ni mpya zaidi na hazitumiki kwa upana kama namespaces za mount au PID. OCI Runtime Specification v1.1 iliongeza msaada wazi kwa namespace ya `time` na field ya `linux.timeOffsets`, na matoleo mapya ya `runc` yanautekeleza sehemu hiyo ya modeli. Mfano mdogo wa OCI unaonekana kama:
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
Hii ni muhimu kwa sababu inabadilisha time namespacing kutoka primitive maalum ya kernel kuwa kitu ambacho runtimes zinaweza kuomba kwa njia portabli.

## Athari za Usalama

Kuna simulizi chache za classic breakout zinazozunguka time namespace ikilinganishwa na aina nyingine za namespace. Hatari hapa kwa kawaida sio kwamba time namespace inatoa escape moja kwa moja, bali kwamba wasomaji wanaisahau kabisa na kwa hivyo wanakosa jinsi runtimes za hali ya juu zinaweza kuunda tabia za mchakato. Katika mazingira maalum, matazamo ya saa yaliyobadilishwa yanaweza kuathiri checkpoint/restore, observability, au forensic assumptions.

## Matumizi Mabaya

Kawaida hakuna breakout primitive ya moja kwa moja hapa, lakini tabia ya saa iliyobadilishwa bado inaweza kuwa muhimu kwa kuelewa mazingira ya utekelezaji na kutambua sifa za runtime za hali ya juu:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Ikiwa unalinganisha michakato miwili, tofauti hapa zinaweza kusaidia kufafanua tabia isiyo ya kawaida ya muda, artefakti za checkpoint/restore, au utofauti wa logging ulio maalum kwa mazingira.

Athari:

- karibu daima reconnaissance au uelewa wa mazingira
- inafaa kufafanua logging, uptime, au anomali za checkpoint/restore
- si kawaida kuwa mekanismo ya moja kwa moja ya container-escape yenyewe

Kipengele muhimu cha matumizi mabaya ni kwamba time namespaces hazivirtualizi `CLOCK_REALTIME`, hivyo zenyewe hazimiruhusu mshambuliaji kuibadilisha saa ya host au kuvunja moja kwa moja certificate-expiry checks kwa mfumo mzima. Thamani yao iko hasa katika kuchanganya mantiki inayotegemea monotonic-time, kuiga upya bug zilizojikita kwa mazingira, au kuelewa tabia ya runtime za kiwango cha juu.

## Ukaguzi

Mikaguzi hii ni zaidi kuhusu kuthibitisha kama runtime inatumia private time namespace kabisa.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
- Katika mazingira mengi, thamani hizi hazitatoa hitimisho la usalama papo hapo, lakini zinakuambia ikiwa kipengele maalum cha runtime kinatumika.
- Ikiwa unalinganisha mchakato miwili, tofauti hapa zinaweza kuelezea muda unaochanganya au tabia ya checkpoint/restore.

Kwa wengi wa container breakouts, the time namespace si udhibiti wa kwanza utakaochunguza. Hata hivyo, sehemu kamili ya container-security inapaswa kuitaja kwa sababu ni sehemu ya modern kernel model na mara nyingine ina umuhimu katika advanced runtime scenarios.
{{#include ../../../../../banners/hacktricks-training.md}}
