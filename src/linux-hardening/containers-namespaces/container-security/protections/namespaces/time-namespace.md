# Tyd-naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die tyd-naamruimte virtualiseer geselekteerde monotonic-styl-klokke eerder as die gasheer se stelselklok. In die praktyk beteken dit private offsets vir **`CLOCK_MONOTONIC`** en **`CLOCK_BOOTTIME`**, plus die naverwante **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** en **`CLOCK_BOOTTIME_ALARM`**-beskouings. Dit virtualiseer nie **`CLOCK_REALTIME`** nie, dus sien `date` en sertifikaat-verval-logika steeds die gasheer se stelselklok, tensy een of ander ander meganisme inmeng.<sup>[[1]](#references)</sup>

Die hoofdoel is om ’n proses beheerde offsets vir verstreke tyd te laat waarneem sonder om die gasheer se globale tydsbeskouing te verander. Dit is nuttig vir checkpoint/restore-werkvloeie, deterministiese toetsing en gevorderde runtime-gedrag. Dit is gewoonlik nie ’n prominente isolasiebeheermaatreël op dieselfde manier as mount- of user-naamruimtes nie, maar dit dra steeds daartoe by om die prosesomgewing meer selfstandig te maak.

Vanuit ’n offensiewe oogpunt is hierdie naamruimte gewoonlik meer relevant vir **reconnaissance, timer skew en runtime-begrip** as vir ’n direkte breakout. Dit is egter belangrik omdat meer container runtimes en checkpoint/restore-werkvloeie dit nou eksplisiet kan aanvra.

## Lab

As die gasheerkern en userspace dit ondersteun, kan jy die naamruimte inspekteer met:
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
Ondersteuning wissel volgens kernel- en tool-weergawes, dus gaan hierdie bladsy eerder oor die begrip van die meganisme as om te verwag dat dit in elke lab-omgewing sigbaar sal wees. Die belangrike waarneming is dat `date` steeds die host se muurklok behoort te weerspieël, terwyl waardes gebaseer op monotonic/boottime dié is wat verander wanneer nie-nul verskuiwings gekonfigureer word.

### Skeppingsnuanse

Tyd-naamruimtes is effens ongewoon in vergelyking met mount-, PID- of network-naamruimtes:<sup>[[1]](#references)</sup>

- `unshare(CLONE_NEWTIME)` skep ’n nuwe tyd-naamruimte vir **toekomstige children**.
- Die calling task bly in sy huidige tyd-naamruimte.
- `/proc/<pid>/ns/time_for_children` is dus dikwels interessanter as `/proc/<pid>/ns/time` wanneer runtime-opstelling gedebug word.

Die write window is ook spesiaal. Verskuiwings in `/proc/<pid>/timens_offsets` moet geskryf word voordat die nuwe tyd-naamruimte volledig met lopende tasks gevul is; in die praktyk doen runtimes dit gedurende die nou setup window tussen namespace-skepping en die begin van die finale payload. Sodra ’n task reeds daar loop, misluk latere writes met `EACCES`. Daarom hanteer low-level runtimes tyd-namespace-opstelling as ’n vroeë bootstrap-stap, eerder as om offsets van binne ’n reeds-beginde container-proses te probeer patch.<sup>[[1]](#references)</sup>

### Tydverskuiwings

Linux-tyd-naamruimtes stel die per-naamruimte-verskuiwings bloot deur `/proc/<pid>/timens_offsets`. Die formaat is ’n stel clock-name of -ID’s plus sekonde-/nanosekonde-deltas relatief tot die aanvanklike tyd-naamruimte.<sup>[[1]](#references)</sup>

In die praktyk is die mees betroubare user-facing workflow om `unshare` daardie offsets vir jou te laat skryf:
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
Die belangrike punt is nie die presiese command-sintaksis nie, maar die gedrag: ’n container kan ’n ander uptime-agtige aansig waarneem sonder om die host se muurklok te verander.

### `unshare`-helpervlae

Onlangse `util-linux`-weergawes verskaf geriefs-vlae wat die offsets outomaties tydens namespace-skepping skryf:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Hierdie flags is hoofsaaklik ’n bruikbaarheidsverbetering, maar dit maak dit ook makliker om die feature in dokumentasie, test harnesses en runtime wrappers te herken.

## Gebruik tydens uitvoering

Time namespaces is nuwer en word minder universeel gebruik as mount- of PID-namespaces. OCI Runtime Specification v1.1 het eksplisiete ondersteuning vir die `time` namespace en die `linux.timeOffsets`-veld bygevoeg, en moderne runtimes kan daardie data in die kernel bootstrap flow karteer. ’n Minimale OCI-fragment lyk soos volg:
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
Dit is belangrik omdat dit tydnamespasiëring van ’n niskern-primitive omskep in iets waarvoor runtimes draagbaar kan versoek. Dit verduidelik ook waarom runtime-internals ’n eksplisiete sinchronisasiestap benodig: die offset moet na `/proc/<pid>/timens_offsets` geskryf word voordat die container-payload volledig die nuwe namespace binnegaan.

Checkpoint/restore-stapels soos CRIU is een van die belangrikste praktiese redes waarom dit enigsins bestaan. Sonder time namespaces sou die herstel van ’n gepouseerde workload veroorsaak dat monotone en boottime-klokke spring met die hoeveelheid tyd wat die workload opgeskort was.<sup>[[2]](#references)</sup>

## Sekuriteitsimpak

Daar is minder klassieke breakout-verhale wat rondom die time namespace sentreer as rondom ander namespace-tipes. Die risiko is hier gewoonlik nie dat die time namespace direk escape moontlik maak nie, maar dat lesers dit heeltemal ignoreer en gevolglik mis hoe gevorderde runtimes prosestoevoer kan vorm.

In gespesialiseerde omgewings kan gewysigde monotone of boottime-aansigte die volgende beïnvloed:

- timeout- en retry-gedrag
- watchdogs en lease-logika
- `timerfd`, `nanosleep`, en `clock_nanosleep`-gedrag
- checkpoint/restore-forensika
- telemetrie oor verloopte tyd en heuristiek gebaseer op uptime

Hoewel dit dus selde die eerste namespace is wat jy abuse, kan dit absoluut "onmoontlike" tydsberekeningsgedrag tydens ’n assessering verklaar.

## Misbruik

Daar is gewoonlik geen direkte breakout-primitive hier nie, maar gewysigde klokgedrag kan steeds nuttig wees om die uitvoeringsomgewing te verstaan, gevorderde runtime-funksies te identifiseer, en timer-gebaseerde logika op te spoor wat teen monotone klokke eerder as werklike kloktyd gemeet word:
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
As jy twee prosesse vergelyk, kan verskille hier help om vreemde tydsberekeningsgedrag, checkpoint/restore-artefakte of omgewing-spesifieke logboekverskille te verduidelik.

Praktiese hoeke wat vir aanvallers relevant is:

- verwar backoff-, sleep- of watchdog-logika wat met monotone clocks geïmplementeer is
- verduidelik waarom `/proc/uptime` en timer-gedrewe gedrag nie ooreenstem met verwagtinge gebaseer op die gasheer se muurklok nie
- herken CRIU/checkpoint-restore-werkvloeie en ander gevorderde runtime-funksies
- identifiseer omgewings waar aansluiting by ’n teikentyd-namespace met `nsenter -T -t <pid> -- ...` plaaslike timer-gedrag van die container vir debugging of post-exploitation kan reproduseer

Impak:

- byna altyd reconnaissance of begrip van die omgewing
- nuttig om afwykings in logging, uptime of checkpoint/restore te verduidelik
- nuttig vir die ontleding van sleeps, retries en timers wat op monotone tyd gebaseer is
- normaalweg nie op sigself ’n direkte container-escape-meganisme nie

Die belangrike misbruiknuanse is dat time namespaces nie `CLOCK_REALTIME` virtualiseer nie. Hulle laat ’n aanvaller dus nie op sigself toe om die gasheer se muurklok te vervals of sertifikaatvervalkontroles stelselwyd direk te breek nie. Die waarde daarvan lê hoofsaaklik daarin om logika wat op monotone tyd gebaseer is te verwar, omgewingspesifieke foute te reproduseer of gevorderde runtime-gedrag te verstaan.

## Kontroles

Hierdie kontroles gaan meestal daaroor om te bevestig of die runtime hoegenaamd ’n private time namespace gebruik en of dit werklik nie-nul offsets gestel het.
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
Wat is hier interessant:

- In baie omgewings sal hierdie waardes nie tot ’n onmiddellike sekuriteitsbevinding lei nie, maar hulle wys wel of ’n gespesialiseerde runtime-funksie gebruik word.
- As `time_for_children` van `time` verskil, het die caller moontlik ’n time namespace wat slegs vir child-prosesse bedoel is, voorberei sonder om dit self binne te gaan.
- As `date` met die host ooreenstem, maar waardes gebaseer op monotonic/boottime nie, kyk jy waarskynlik na time namespacing eerder as peutery met die wall clock.
- As jy twee prosesse vergelyk, kan verskille hier verwarrende timing- of checkpoint/restore-gedrag verklaar.

Vir die meeste container-breakouts is die time namespace nie die eerste beheermeganisme wat jy sal ondersoek nie. ’n Volledige container-security-afdeling behoort dit egter te noem omdat dit deel van die moderne kernel-model is en soms in gevorderde runtime-scenario’s saak maak.

## Verwysings

- [1] [Linux `time_namespaces(7)`-handleidingsbladsy](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces: Per-Container Clock Offsets for CLOCK_MONOTONIC / CLOCK_BOOTTIME - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
