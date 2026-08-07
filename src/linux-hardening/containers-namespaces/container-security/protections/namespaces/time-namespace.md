# Namespace ya Muda

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Time namespace hubadilisha clocks zilizochaguliwa za aina ya monotonic badala ya kubadilisha saa ya ukutani ya host. Kwa vitendo, hii inamaanisha offsets binafsi za **`CLOCK_MONOTONIC`** na **`CLOCK_BOOTTIME`**, pamoja na views zinazohusiana kwa karibu za **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`**, na **`CLOCK_BOOTTIME_ALARM`**. Haibadilishi **`CLOCK_REALTIME`**, hivyo `date` na logic ya certificate-expiry bado huona saa ya ukutani ya host isipokuwa mechanism nyingine iingilie.<sup>[[1]](#references)</sup>

Kusudi kuu ni kuipa process uwezo wa kuona offsets zinazodhibitiwa za elapsed-time bila kubadilisha mtazamo wa muda wa host kwa ujumla. Hii ni muhimu kwa workflows za checkpoint/restore, deterministic testing, na tabia za hali ya juu za runtime. Kwa kawaida si control kuu ya isolation kwa kiwango sawa na mount au user namespaces, lakini bado husaidia kufanya mazingira ya process yajitegemee zaidi.

Kwa mtazamo wa offensive, namespace hii kwa kawaida ni muhimu zaidi kwa **reconnaissance, timer skew, na kuelewa runtime** kuliko kwa breakout ya moja kwa moja. Hata hivyo, ni muhimu kwa sababu container runtimes na workflows za checkpoint/restore zinazidi kuwa na uwezo wa kuiomba explicitly.

## Maabara

Ikiwa kernel ya host na userspace zina-support, unaweza kukagua namespace kwa kutumia:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```
Usaidizi hutofautiana kulingana na matoleo ya kernel na tools, kwa hiyo ukurasa huu unahusu zaidi kuelewa utaratibu kuliko kutarajia uonekane katika kila mazingira ya lab. Jambo muhimu la kuzingatia ni kwamba `date` inapaswa bado kuakisi saa ya ukutani ya host, ilhali thamani zinazotegemea monotonic/boottime ndizo hubadilika wakati offsets zisizo sifuri zinapowekwa.

### Nuance ya Uundaji

Time namespaces zina utofauti kidogo ikilinganishwa na mount, PID, au network namespaces:<sup>[[1]](#references)</sup>

- `unshare(CLONE_NEWTIME)` huunda time namespace mpya kwa **children wa baadaye**.
- Task inayoita hubaki katika time namespace yake ya sasa.
- Kwa hiyo, `/proc/<pid>/ns/time_for_children` mara nyingi huwa muhimu zaidi kuliko `/proc/<pid>/ns/time` wakati wa kuchunguza runtime setup.

Dirisha la uandishi pia ni maalum. Offsets katika `/proc/<pid>/timens_offsets` lazima ziandikwe kabla time namespace mpya haijajazwa kikamilifu na tasks zinazoendesha; kwa vitendo, runtimes hufanya hivi wakati wa setup window fupi kati ya kuunda namespace na kuanzisha payload ya mwisho. Mara task inapokuwa tayari inaendesha humo, majaribio ya baadaye ya kuandika hushindikana kwa `EACCES`. Hii ndiyo sababu runtimes za kiwango cha chini hushughulikia setup ya time namespace kama hatua ya mapema ya bootstrap badala ya kujaribu kurekebisha offsets kutoka ndani ya container process ambayo tayari imeanzishwa.<sup>[[1]](#references)</sup>

### Time Offsets

Linux time namespaces hufichua offsets za kila namespace kupitia `/proc/<pid>/timens_offsets`. Muundo wake ni seti ya majina au IDs za clocks pamoja na deltas za sekunde/nanosekunde zinazohusiana na initial time namespace.<sup>[[1]](#references)</sup>

Kwa vitendo, workflow ya kuaminika zaidi kwa mtumiaji ni kuiacha `unshare` ikuandikie offsets hizo:
```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Jambo muhimu si syntax halisi ya command, bali tabia yake: container inaweza kuona mwonekano tofauti unaofanana na uptime bila kubadilisha wall clock ya host.

### `unshare` Helper Flags

Matoleo ya hivi karibuni ya `util-linux` yanatoa flags za convenience zinazoandika offsets kiotomatiki wakati wa kuunda namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Flags hizi hasa ni uboreshaji wa usability, lakini pia hurahisisha kutambua feature hii katika documentation, test harnesses, na runtime wrappers.

## Matumizi ya Runtime

Time namespaces ni mpya zaidi na hazijatumika kwa upana sawa na mount au PID namespaces. OCI Runtime Specification v1.1 iliongeza support ya moja kwa moja kwa `time` namespace na field ya `linux.timeOffsets`, na runtimes za kisasa zinaweza kuhamisha data hiyo hadi kwenye kernel bootstrap flow. OCI fragment ya msingi inaonekana hivi:
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
Hili ni muhimu kwa sababu linabadilisha time namespacing kutoka kernel primitive ya matumizi maalum kuwa kitu ambacho runtimes zinaweza kuomba kwa njia inayofanya kazi kwenye mifumo mbalimbali. Pia linaeleza kwa nini runtime internals zinahitaji hatua ya wazi ya synchronization: offset lazima iandikwe kwenye `/proc/<pid>/timens_offsets` kabla payload ya container haijaingia kikamilifu kwenye namespace mpya.

Stacks za checkpoint/restore kama CRIU ni miongoni mwa sababu kuu za kuwepo kwa kipengele hiki. Bila time namespaces, kurejesha workload iliyositishwa kungesababisha monotonic na boot-time clocks kuruka kwa muda ambao workload ilikaa imesimamishwa.<sup>[[2]](#references)</sup>

## Athari za Usalama

Kuna hadithi chache za kawaida za breakout zinazolenga time namespace ikilinganishwa na aina nyingine za namespaces. Hatari hapa kwa kawaida si kwamba time namespace inawezesha escape moja kwa moja, bali ni kwamba wasomaji huipuuza kabisa na hivyo kushindwa kuelewa jinsi runtimes za hali ya juu zinavyoweza kuunda tabia ya process.

Katika mazingira maalum, maoni yaliyobadilishwa ya monotonic au boottime yanaweza kuathiri:

- tabia ya timeout na retry
- watchdogs na lease logic
- tabia ya `timerfd`, `nanosleep`, na `clock_nanosleep`
- checkpoint/restore forensics
- telemetry ya elapsed-time na heuristics zinazotegemea uptime

Kwa hiyo, ingawa hii si namespace ya kwanza unayotumia vibaya mara nyingi, inaweza kabisa kueleza tabia ya muda "isiyowezekana" wakati wa assessment.

## Matumizi Mabaya

Kwa kawaida hakuna breakout primitive ya moja kwa moja hapa, lakini tabia iliyobadilishwa ya clock bado inaweza kuwa muhimu kwa kuelewa execution environment, kutambua vipengele vya advanced runtime, na kubaini logic inayotegemea timer ambayo hupimwa dhidi ya monotonic clocks badala ya wall clock time:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Ikiwa unalinganisha processes mbili, tofauti hizi zinaweza kusaidia kueleza tabia zisizo za kawaida za muda, artifacts za checkpoint/restore, au kutolingana kwa logging kwa kutegemea mazingira.

Mielekeo ya vitendo inayohusiana na attacker:

- kuchanganya mantiki ya backoff, sleep, au watchdog iliyotekelezwa kwa kutumia monotonic clocks
- kueleza kwa nini `/proc/uptime` na tabia inayoendeshwa na timers hazikubaliani na matarajio ya wall-clock ya host
- kutambua workflows za CRIU/checkpoint-restore na vipengele vingine vya advanced runtime
- kugundua mazingira ambayo kujiunga na target time namespace kwa `nsenter -T -t <pid> -- ...` kunaweza kuiga tabia ya timer ya ndani ya container kwa debugging au post-exploitation

Athari:

- karibu kila mara ni reconnaissance au kuelewa mazingira
- ni muhimu kwa kueleza hitilafu za logging, uptime, au checkpoint/restore
- ni muhimu kwa kuchanganua sleeps, retries, na timers zinazotegemea monotonic time
- kwa kawaida si mechanism ya moja kwa moja ya container-escape yenyewe

Nuance muhimu ya abuse ni kwamba time namespaces hazibadilishi `CLOCK_REALTIME`, kwa hivyo zenyewe hazimruhusu attacker kughushi wall clock ya host au kuvuruga moja kwa moja ukaguzi wa certificate-expiry katika mfumo mzima. Thamani yake kubwa iko katika kuchanganya logic inayotegemea monotonic time, kuiga bugs zinazotegemea mazingira, au kuelewa tabia ya advanced runtime.

## Checks

Checks hizi kwa kiasi kikubwa zinahusu kuthibitisha ikiwa runtime inatumia private time namespace kabisa na ikiwa iliweka offsets zisizo sifuri.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```
Kinachovutia hapa:

- Katika mazingira mengi, thamani hizi hazitasababisha security finding ya mara moja, lakini zinakuonyesha ikiwa runtime feature maalum inatumika.
- Ikiwa `time_for_children` inatofautiana na `time`, caller huenda ameandaa time namespace ya child pekee ambayo yeye mwenyewe hajaingia.
- Ikiwa `date` inalingana na ya host, lakini thamani zinazotegemea monotonic/boottime hazilingani, huenda unaangalia time namespacing badala ya wall-clock tampering.
- Ikiwa unalinganisha processes mbili, tofauti hizi zinaweza kueleza timing inayochanganya au tabia ya checkpoint/restore.

Kwa container breakout nyingi, time namespace si control ya kwanza utakayochunguza. Hata hivyo, sehemu kamili ya container security inapaswa kuitaja kwa sababu ni sehemu ya kernel model ya kisasa na mara nyingine huwa muhimu katika mazingira ya advanced runtime.

## Marejeo

- [1] [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces: Per-Container Clock Offsets for CLOCK_MONOTONIC / CLOCK_BOOTTIME - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
