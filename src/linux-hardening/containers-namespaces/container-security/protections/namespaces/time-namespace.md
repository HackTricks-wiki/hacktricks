# Namespace ya Muda

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Namespace ya muda hu-virtualize saa zilizochaguliwa za aina ya monotonic badala ya saa ya ukutani ya host. Kwa vitendo, hii inamaanisha offsets binafsi za **`CLOCK_MONOTONIC`** na **`CLOCK_BOOTTIME`**, pamoja na mitazamo inayohusiana kwa karibu ya **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`**, na **`CLOCK_BOOTTIME_ALARM`**. Hai-virtualize **`CLOCK_REALTIME`**, kwa hiyo `date` na logic ya kuangalia kuisha kwa vyeti bado huona saa ya ukutani ya host isipokuwa mechanism nyingine iingilie kati.

Madhumuni makuu ni kuruhusu process kuona offsets zinazodhibitiwa za muda uliopita bila kubadilisha mwonekano wa muda wa global wa host. Hii ni muhimu kwa workflows za checkpoint/restore, testing ya deterministic, na tabia za hali ya juu za runtime. Kwa kawaida si control kuu ya isolation kwa kiwango sawa na mount au user namespaces, lakini bado husaidia kufanya mazingira ya process yajitegemee zaidi.

Kwa mtazamo wa offensive, namespace hii kwa kawaida inahusiana zaidi na **reconnaissance, timer skew, na uelewa wa runtime** kuliko breakout ya moja kwa moja. Hata hivyo, ni muhimu kwa sababu container runtimes na workflows za checkpoint/restore zaidi sasa zinaweza kuiomba explicitly.

## Lab

Ikiwa kernel ya host na userspace zina-support hii, unaweza kukagua namespace kwa kutumia:
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
Msaada hutofautiana kulingana na kernel na matoleo ya tools, kwa hivyo ukurasa huu unahusu zaidi kuelewa mechanism kuliko kutarajia ionekane katika kila lab environment. Jambo muhimu la kuzingatia ni kwamba `date` inapaswa bado kuonyesha saa ya host, huku values zinazotegemea monotonic/boottime zikiwa ndizo hubadilika wakati offsets zisizo sifuri zinapowekwa.

### Nuance ya Uundaji

Time namespaces ni za kipekee kidogo ikilinganishwa na mount, PID, au network namespaces:

- `unshare(CLONE_NEWTIME)` huunda time namespace mpya kwa **children wa baadaye**.
- Task inayoiita hubaki katika time namespace yake ya sasa.
- Kwa hivyo, `/proc/<pid>/ns/time_for_children` mara nyingi huwa muhimu zaidi kuliko `/proc/<pid>/ns/time` wakati wa kuchunguza runtime setup.

Write window pia ni maalum. Offsets katika `/proc/<pid>/timens_offsets` lazima ziandikwe kabla ya time namespace mpya kujazwa kikamilifu na tasks zinazoendesha; kwa kawaida runtimes hufanya hivyo wakati wa setup window fupi kati ya kuundwa kwa namespace na kuanzishwa kwa payload ya mwisho. Task inapokuwa tayari inaendesha humo, writes za baadaye hushindikana kwa `EACCES`. Hii ndiyo sababu low-level runtimes hushughulikia time-namespace setup kama hatua ya mapema ya bootstrap badala ya kujaribu kurekebisha offsets kutoka ndani ya container process ambayo tayari imeanzishwa.

### Offsets za Muda

Linux time namespaces huonyesha offsets za kila namespace kupitia `/proc/<pid>/timens_offsets`. Format yake ni seti ya majina au IDs za clocks pamoja na second/nanosecond deltas zinazohusiana na initial time namespace.

Kwa vitendo, workflow ya kuaminika zaidi kwa mtumiaji ni kuacha `unshare` ikuandikie offsets hizo:
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
Jambo muhimu si syntax halisi ya command, bali tabia yake: container inaweza kuona mwonekano tofauti unaofanana na uptime bila kubadilisha saa ya ukuta ya host.

### `unshare` Helper Flags

Matoleo ya hivi karibuni ya `util-linux` hutoa flags za urahisi zinazoandika offsets kiotomatiki wakati wa kuunda namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Flags hizi kwa kiasi kikubwa ni uboreshaji wa usability, lakini pia hurahisisha kutambua feature hii katika documentation, test harnesses, na runtime wrappers.

## Matumizi ya Runtime

Time namespaces ni mpya zaidi na hutumika kwa upana mdogo kuliko mount au PID namespaces. OCI Runtime Specification v1.1 iliongeza support ya moja kwa moja kwa `time` namespace na field ya `linux.timeOffsets`, na runtimes za kisasa zinaweza kuhamisha data hiyo kwenye mtiririko wa kernel bootstrap. OCI fragment ndogo inaonekana kama:
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
Hili ni muhimu kwa sababu linabadilisha time namespacing kutoka kernel primitive ya matumizi maalum kuwa kitu ambacho runtimes zinaweza kuomba kwa njia inayoweza kutumika kwa mifumo mbalimbali. Pia linaeleza kwa nini runtime internals zinahitaji hatua ya wazi ya synchronization: offset lazima iandikwe kwenye `/proc/<pid>/timens_offsets` kabla payload ya container haijaingia kikamilifu kwenye namespace mpya.

Stacks za checkpoint/restore kama vile CRIU ni mojawapo ya sababu kuu za kuwepo kwa kipengele hiki katika mazingira halisi. Bila time namespaces, kurejesha workload iliyositishwa kungesababisha monotonic na boot-time clocks kuruka kwa kiasi cha muda ambao workload ilikaa imesimamishwa.

## Security Impact

Kuna visa vichache vya classic breakout vinavyohusisha time namespace kuliko vinavyohusisha aina nyingine za namespaces. Hatari hapa kwa kawaida si kwamba time namespace inawezesha escape moja kwa moja, bali ni kwamba wasomaji huipuuza kabisa na hivyo kukosa kuelewa jinsi advanced runtimes zinavyoweza kuunda tabia ya processes.

Katika mazingira maalum, mabadiliko ya monotonic au boottime views yanaweza kuathiri:

- tabia ya timeout na retry
- watchdogs na lease logic
- tabia ya `timerfd`, `nanosleep`, na `clock_nanosleep`
- checkpoint/restore forensics
- telemetry ya muda uliopita na heuristics zinazotegemea uptime

Kwa hiyo, ingawa hii si namespace ya kwanza utakayotumia kufanya abuse, inaweza kabisa kueleza tabia ya muda "isiyowezekana" wakati wa assessment.

## Abuse

Kwa kawaida hakuna breakout primitive ya moja kwa moja hapa, lakini tabia iliyobadilishwa ya clocks bado inaweza kuwa muhimu kwa kuelewa execution environment, kutambua advanced runtime features, na kugundua timer-based logic inayopimwa dhidi ya monotonic clocks badala ya wall clock time:
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
Ikiwa unalinganisha processes mbili, tofauti hizi zinaweza kusaidia kueleza tabia zisizo za kawaida za timing, artifacts za checkpoint/restore, au mismatch za logging zinazotegemea environment.

Mielekeo muhimu kwa attacker:

- kuchanganya logic ya backoff, sleep, au watchdog inayotekelezwa kwa kutumia monotonic clocks
- kueleza kwa nini `/proc/uptime` na tabia inayoendeshwa na timers hailingani na matarajio ya wall-clock ya host
- kutambua workflows za CRIU/checkpoint-restore na vipengele vingine vya advanced runtime
- kugundua environments ambapo kujiunga na target time namespace kwa `nsenter -T -t <pid> -- ...` kunaweza kuiga tabia ya timer ya ndani ya container kwa ajili ya debugging au post-exploitation

Athari:

- karibu kila mara ni reconnaissance au kuelewa environment
- ni muhimu kueleza anomalies za logging, uptime, au checkpoint/restore
- ni muhimu kuchanganua sleeps, retries, na timers zinazotegemea monotonic time
- kwa kawaida si mechanism ya moja kwa moja ya container-escape yenyewe

Nuance muhimu ya abuse ni kwamba time namespaces hazifanyi virtualize `CLOCK_REALTIME`; kwa hiyo, zenyewe hazimruhusu attacker kughushi wall clock ya host au kuvuruga moja kwa moja ukaguzi wa certificate-expiry kwa mfumo mzima. Thamani yake iko hasa katika kuchanganya logic inayotegemea monotonic time, kuiga bugs zinazotegemea environment, au kuelewa tabia ya advanced runtime.

## Ukaguzi

Ukaguzi huu unahusu hasa kuthibitisha ikiwa runtime inatumia private time namespace kabisa na ikiwa iliweka offsets zisizo sifuri.
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
Ni nini cha kuvutia hapa:

- Katika mazingira mengi, thamani hizi hazitasababisha security finding ya haraka, lakini zinakuambia ikiwa specialized runtime feature inatumika.
- Ikiwa `time_for_children` inatofautiana na `time`, caller huenda ameandaa child-only time namespace ambayo yenyewe haijaingia.
- Ikiwa `date` inalingana na host lakini thamani zinazotegemea monotonic/boottime hazilingani, huenda unaangalia time namespacing badala ya wall-clock tampering.
- Ikiwa unalinganisha processes mbili, tofauti hizi zinaweza kueleza tabia ya muda inayochanganya au tabia ya checkpoint/restore.

Kwa container breakouts nyingi, time namespace si control ya kwanza utakayochunguza. Hata hivyo, sehemu kamili ya container-security inapaswa kuitaja kwa sababu ni sehemu ya kernel model ya kisasa na wakati mwingine huwa muhimu katika advanced runtime scenarios.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
