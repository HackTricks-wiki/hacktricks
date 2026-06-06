# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

time namespace huvirtualize saa za saa za monotonic zilizochaguliwa badala ya host wall clock. Kwa vitendo hii inamaanisha private offsets kwa **`CLOCK_MONOTONIC`** na **`CLOCK_BOOTTIME`**, pamoja na **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`**, na **`CLOCK_BOOTTIME_ALARM`** zinazohusiana kwa karibu. Haivirtualize **`CLOCK_REALTIME`**, kwa hiyo `date` na logic ya certificate-expiry bado huona host wall clock isipokuwa mechanism nyingine iingilie kati.

Lengo kuu ni kuruhusu process kuona controlled elapsed-time offsets bila kubadilisha global time view ya host. Hii ni muhimu kwa checkpoint/restore workflows, deterministic testing, na advanced runtime behavior. Kwa kawaida si control ya isolation inayojulikana sana kama mount au user namespaces, lakini bado huchangia kufanya mazingira ya process yawe self-contained zaidi.

Kutoka kwa mtazamo wa offensive, namespace hii kwa kawaida ni muhimu zaidi kwa **reconnaissance, timer skew, na runtime understanding** kuliko kwa direct breakout. Hata hivyo, ni muhimu kwa sababu more container runtimes na checkpoint/restore workflows sasa zinaweza kuiomba explicitly.

## Lab

Ikiwa host kernel na userspace zina support hiyo, unaweza inspect namespace kwa:
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
Msaada hutofautiana kulingana na kernel na versions za tool, kwa hiyo ukurasa huu zaidi unahusu kuelewa mechanism kuliko kutarajia ionekane katika kila lab environment. Uangalizi muhimu ni kwamba `date` bado inapaswa kuonyesha host wall clock, wakati thamani zinazotokana na monotonic/boottime ndio hubadilika offsets zisizo sifuri zinaposanidiwa.

### Creation Nuance

Time namespaces ni za kipekee kidogo ukilinganisha na mount, PID, au network namespaces:

- `unshare(CLONE_NEWTIME)` huunda time namespace mpya kwa **future children**.
- task inayoiita hubaki katika time namespace yake ya sasa.
- `/proc/<pid>/ns/time_for_children` kwa hiyo mara nyingi ni ya kuvutia zaidi kuliko `/proc/<pid>/ns/time` unapofanya debugging ya runtime setup.

Dirisha la kuandika pia ni maalum. Offsets katika `/proc/<pid>/timens_offsets` lazima ziandikwe kabla time namespace mpya haijajazwa kikamilifu na running tasks; kwa kawaida runtimes hufanya hivi wakati wa narrow setup window kati ya namespace creation na kuanzisha final payload. Mara task ikiwa tayari inaendeshwa humo, maandishi ya baadaye hushindwa kwa `EACCES`. Hii ndiyo sababu low-level runtimes hushughulikia time-namespace setup kama hatua ya mapema ya bootstrap badala ya kujaribu patch offsets kutoka ndani ya container process ambayo tayari imeanza.

### Time Offsets

Linux time namespaces huweka wazi per-namespace offsets kupitia `/proc/<pid>/timens_offsets`. Format ni seti ya clock names au IDs pamoja na second/nanosecond deltas ukilinganisha na initial time namespace.

Kwa vitendo, workflow ya kuaminika zaidi inayoonekana kwa user ni kuiacha `unshare` ikuandikie offsets hizo:
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
Jambo muhimu si sintaksia sahihi ya amri bali ni tabia: container inaweza kuona mwonekano tofauti unaofanana na uptime bila kubadilisha host wall clock.

### `unshare` Helper Flags

Matoleo ya hivi karibuni ya `util-linux` yanatoa convenience flags zinazoweka offsets kiotomatiki wakati wa kuunda namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Bendera hizi mara nyingi ni uboreshaji wa usability, lakini pia hufanya iwe rahisi zaidi kutambua feature kwenye documentation, test harnesses, na runtime wrappers.

## Runtime Usage

Time namespaces ni mpya zaidi na hazijaribiwi kwa upana kama mount au PID namespaces. OCI Runtime Specification v1.1 iliongeza explicit support kwa `time` namespace na field ya `linux.timeOffsets`, na modern runtimes zinaweza ku-map data hiyo kwenye kernel bootstrap flow. Sehemu ndogo ya OCI inaonekana hivi:
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
Ini muhimu kwa sababu inabadilisha time namespacing kutoka kuwa kernel primitive ya niche hadi kitu ambacho runtimes zinaweza kuomba kwa njia ya portably. Pia inaeleza kwa nini runtime internals zinahitaji explicit synchronization step: offset lazima iandikwe kwenye `/proc/<pid>/timens_offsets` kabla ya container payload kuingia kikamilifu kwenye namespace mpya.

Checkpoint/restore stacks kama CRIU ni moja ya sababu kuu za dunia halisi za kuwepo kwa hii kabisa. Bila time namespaces, kurejesha workload iliyosimamishwa kungesababisha monotonic na boot-time clocks kuruka kwa kiasi cha muda ambacho workload ilikaa ikiwa suspended.

## Security Impact

Kuna hadithi chache za classic breakout zinazohusiana na time namespace kuliko aina nyingine za namespace. Hatari hapa kwa kawaida si kwamba time namespace inawezesha escape moja kwa moja, bali kwamba wasomaji huiignore kabisa na hivyo kukosa kuona jinsi advanced runtimes zinavyoweza kuwa zina-shaped process behavior.

Katika mazingira maalum, views zilizobadilishwa za monotonic au boottime zinaweza kuathiri:

- timeout and retry behavior
- watchdogs na lease logic
- `timerfd`, `nanosleep`, na `clock_nanosleep` behavior
- checkpoint/restore forensics
- elapsed-time telemetry na uptime-based heuristics

Kwa hiyo ingawa mara chache hii ndiyo namespace ya kwanza unayobuse, kabisa inaweza kueleza tabia ya muda ya "haiwezekani" wakati wa assessment.

## Abuse

Kwa kawaida hakuna direct breakout primitive hapa, lakini altered clock behavior bado inaweza kuwa muhimu kwa kuelewa execution environment, kutambua advanced runtime features, na kugundua timer-based logic inayopimwa dhidi ya monotonic clocks badala ya wall clock time:
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
Ikiwa unalinganisha processes mbili, tofauti hapa zinaweza kusaidia kueleza tabia ya ajabu ya timing, checkpoint/restore artifacts, au kutolingana kwa logging maalum ya mazingira.

Mienendo ya vitendo inayohusiana na attacker:

- confuse backoff, sleep, au watchdog logic iliyotekelezwa kwa kutumia monotonic clocks
- kueleza kwa nini `/proc/uptime` na tabia inayoendeshwa na timers haitii matarajio ya host-side wall-clock
- kutambua workflows za CRIU/checkpoint-restore na other advanced runtime features
- kuona mazingira ambapo kujiunga na target time namespace kwa `nsenter -T -t <pid> -- ...` kunaweza kurudisha container-local timer behavior kwa debugging au post-exploitation

Athari:

- karibu kila wakati ni reconnaissance au kuelewa mazingira
- inafaa kwa kueleza logging, uptime, au checkpoint/restore anomalies
- inafaa kwa kuchambua monotonic-time-based sleeps, retries, na timers
- kwa kawaida si mekanizimu ya moja kwa moja ya container-escape yenyewe

Nuance muhimu ya abuse ni kwamba time namespaces hazivirtualize `CLOCK_REALTIME`, kwa hiyo hazimpi attacker uwezo wa kufalsify host wall clock au kuvunja moja kwa moja certificate-expiry checks katika mfumo mzima. Thamani yake hasa ni kuchanganya monotonic-time-based logic, kurudisha bugs maalum za mazingira, au kuelewa advanced runtime behavior.

## Checks

Hizi checks kwa kiasi kikubwa ni kuhusu kuthibitisha kama runtime inatumia private time namespace kabisa na kama kweli imeweka nonzero offsets.
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
Kinachovutia hapa ni:

- Katika mazingira mengi, thamani hizi hazitasababisha uthibitisho wa haraka wa usalama, lakini zinakuambia kama kipengele maalum cha runtime kinatumika.
- Ikiwa `time_for_children` inatofautiana na `time`, caller huenda ameandaa child-only time namespace ambayo yenyewe haijaingia.
- Ikiwa `date` inalingana na host lakini thamani za msingi za monotonic/boottime hazilingani, huenda unaangalia time namespacing badala ya wall-clock tampering.
- Ikiwa unalinganisha processes mbili, tofauti hapa zinaweza kueleza timing ya kutatanisha au checkpoint/restore behavior.

Kwa container breakouts nyingi, time namespace si control ya kwanza utakayochunguza. Hata hivyo, sehemu kamili ya container-security inapaswa kuitaja kwa sababu ni sehemu ya modern kernel model na mara chache huleta maana katika advanced runtime scenarios.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
