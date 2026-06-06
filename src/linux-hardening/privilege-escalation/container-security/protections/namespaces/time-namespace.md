# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die time namespace virtualiseer geselekteerde monotonic-style clocks in plaas van die gasheer se wall clock. In die praktyk beteken dit private offsets vir **`CLOCK_MONOTONIC`** en **`CLOCK_BOOTTIME`**, plus die nou verwante **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`**, en **`CLOCK_BOOTTIME_ALARM`** views. Dit virtualiseer **nie** **`CLOCK_REALTIME`** nie, so `date` en certificate-expiry logika neem steeds die gasheer se wall clock waar tensy een of ander ander meganisme inmeng.

Die hoofdoel is om ’n proses toe te laat om beheerde elapsed-time offsets waar te neem sonder om die gasheer se globale tydsbeeld te verander. Dit is nuttig vir checkpoint/restore workflows, deterministic testing, en advanced runtime behavior. Dit is gewoonlik nie ’n hooflyn-isolasiekontrole soos mount of user namespaces nie, maar dit dra steeds by tot ’n meer selfstandige process environment.

Van ’n offensiewe oogpunt is hierdie namespace gewoonlik meer relevant vir **reconnaissance, timer skew, en runtime understanding** as vir ’n direkte breakout. Tog maak dit saak omdat meer container runtimes en checkpoint/restore workflows dit nou eksplisiet kan aanvra.

## Lab

As die gasheer-kernel en userspace dit ondersteun, kan jy die namespace inspekteer met:
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
Ondersteuning verskil volgens kernel- en toolweergawes, so hierdie bladsy gaan meer daaroor om die meganisme te verstaan as om te verwag dat dit in elke lab-omgewing sigbaar sal wees. Die belangrike waarneming is dat `date` steeds die host wall clock moet weerspieël, terwyl monotonic/boottime-gebaseerde waardes die ones is wat verander wanneer nie-nul offsets gekonfigureer is.

### Creation Nuance

Time namespaces is effens ongewoon in vergelyking met mount, PID, of network namespaces:

- `unshare(CLONE_NEWTIME)` skep ’n nuwe time namespace vir **future children**.
- Die roepende task bly in sy huidige time namespace.
- `/proc/<pid>/ns/time_for_children` is daarom dikwels interessanter as `/proc/<pid>/ns/time` wanneer runtime setup gedebug word.

Die write window is ook spesiaal. Offsets in `/proc/<pid>/timens_offsets` moet geskryf word voordat die nuwe time namespace volledig gevul is met running tasks; in practice doen runtimes dit tydens die nou setup window tussen namespace creation en die begin van die final payload. Sodra ’n task daar al running is, misluk latere writes met `EACCES`. Dit is hoekom low-level runtimes time-namespace setup hanteer as ’n vroeë bootstrap step eerder as om offsets van binne ’n reeds-gestarte container process te probeer patch.

### Time Offsets

Linux time namespaces stel die per-namespace offsets bloot via `/proc/<pid>/timens_offsets`. Die format is ’n stel clock names of IDs plus second/nanosecond deltas relatief tot die initial time namespace.

In practice is die mees betroubare user-facing workflow om `unshare` daardie offsets vir jou te laat skryf:
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
Die belangrike punt is nie die presiese command syntax nie, maar die gedrag: ’n container kan ’n ander uptime-like view waarneem sonder om die host wall clock te verander.

### `unshare` Helper Flags

Onlangse `util-linux` versions bied convenience flags wat die offsets outomaties skryf tydens namespace creation:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Hierdie flags is meestal 'n bruikbaarheidsverbetering, maar hulle maak dit ook makliker om die feature in documentation, test harnesses, en runtime wrappers te herken.

## Runtime Usage

Time namespaces is nuwer en minder universeel gebruik as mount- of PID namespaces. OCI Runtime Specification v1.1 het eksplisiete support vir die `time` namespace en die `linux.timeOffsets` field bygevoeg, en moderne runtimes kan daardie data in die kernel bootstrap flow map. 'n Minimal OCI-fragment lyk soos:
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
Dit maak saak omdat dit time namespacing van ’n nis kernel primitive in iets verander wat runtimes draagbaar kan aanvra. Dit verduidelik ook waarom runtime internals ’n eksplisiete sinkronisasie-stap nodig het: die offset moet na `/proc/<pid>/timens_offsets` geskryf word voordat die container payload die nuwe namespace heeltemal betree.

Checkpoint/restore stacks soos CRIU is een van die hoof werklike redes waarom dit enigsins bestaan. Sonder time namespaces sou die herstel van ’n gepauzeerde workload veroorsaak dat monotonic en boot-time clocks spring met die hoeveelheid tyd wat die workload opgeskort was.

## Security Impact

Daar is minder klassieke breakout stories rondom die time namespace as rondom ander namespace tipes. Die risiko hier is gewoonlik nie dat die time namespace direk escape moontlik maak nie, maar dat lesers dit heeltemal ignoreer en dus mis hoe gevorderde runtimes process behavior kan vorm.

In gespesialiseerde omgewings kan veranderde monotonic- of boottime-aansigte beïnvloed:

- timeout en retry behavior
- watchdogs en lease logic
- `timerfd`, `nanosleep`, en `clock_nanosleep` behavior
- checkpoint/restore forensics
- elapsed-time telemetry en uptime-based heuristics

So al is dit selde die eerste namespace wat jy abuse, kan dit absoluut "impossible" timing behavior tydens ’n assessment verduidelik.

## Abuse

Daar is gewoonlik geen direkte breakout primitive hier nie, maar veranderde clock behavior kan steeds nuttig wees om die execution environment te verstaan, gevorderde runtime features te identifiseer, en timer-based logic raak te sien wat teen monotonic clocks gemeet word eerder as wall clock time:
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
As jy twee prosesse vergelyk, kan verskille hier help om vreemde tydsgedrag, checkpoint/restore-artifakte, of omgewingspesifieke logging-verskille te verduidelik.

Praktiese aanvaller-relevante hoeke:

- verwar backoff-, sleep-, of watchdog-logika wat met monotonic clocks geïmplementeer is
- verduidelik hoekom `/proc/uptime` en timer-gedrewe gedrag verskil van host-side wall-clock-verwagtinge
- herken CRIU/checkpoint-restore-workflows en ander gevorderde runtime-features
- sien omgewings waar die deelname aan ’n teiken time namespace met `nsenter -T -t <pid> -- ...` container-local timergedrag vir debugging of post-exploitation kan reproduseer

Impak:

- amper altyd reconnaissance of omgewingsbegrip
- nuttig om logging-, uptime-, of checkpoint/restore-anomalieë te verduidelik
- nuttig vir die ontleding van monotonic-time-based sleeps, retries, en timers
- gewoonlik nie self ’n direkte container-escape-meganisme nie

Die belangrike abuse-nuans is dat time namespaces nie `CLOCK_REALTIME` virtualiseer nie, so hulle laat ’n aanvaller nie op hul eie toe om die host wall clock te vervals of certificate-expiry checks stelselwyd direk te breek nie. Hulle waarde lê meestal in die verwarring van monotonic-time-based logika, die reproduseer van omgewingspesifieke bugs, of die begrip van gevorderde runtime-gedrag.

## Checks

Hierdie checks gaan meestal daaroor om te bevestig of die runtime enigsins ’n private time namespace gebruik en of dit werklik nie-nul offsets ingestel het.
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
Wat interessant hier is:

- In baie omgewings sal hierdie waardes nie tot ’n onmiddellike security finding lei nie, maar hulle sê wel vir jou of ’n gespesialiseerde runtime feature in gebruik is.
- As `time_for_children` verskil van `time`, kan die caller ’n child-only time namespace voorberei het wat dit self nog nie betree het nie.
- As `date` ooreenstem met die host maar monotonic/boottime-based waardes nie, kyk jy waarskynlik na time namespacing eerder as wall-clock tampering.
- As jy twee processes vergelyk, kan verskille hier verwarrende timing of checkpoint/restore behavior verklaar.

Vir die meeste container breakouts is die time namespace nie die eerste control wat jy sal ondersoek nie. Tog behoort ’n volledige container-security section dit te noem, omdat dit deel is van die moderne kernel model en soms saak maak in gevorderde runtime scenarios.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
