# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die time namespace virtualiseer geselekteerde monotonic-styl-klokke in plaas van die host se wall clock. In die praktyk beteken dit private offsets vir **`CLOCK_MONOTONIC`** en **`CLOCK_BOOTTIME`**, plus die nouverwante **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** en **`CLOCK_BOOTTIME_ALARM`**-aansigte. Dit virtualiseer nie **`CLOCK_REALTIME`** nie, dus neem `date` en sertifikaat-verval-logika steeds die host se wall clock waar, tensy een of ander ander meganisme inmeng.

Die hoofdoel is om ’n proses beheerde elapsed-time offsets te laat waarneem sonder om die host se globale tydsaansig te verander. Dit is nuttig vir checkpoint/restore-workflows, deterministiese toetsing en gevorderde runtime-gedrag. Dit is gewoonlik nie ’n prominente isolation control op dieselfde manier as mount- of user namespaces nie, maar dit dra steeds daartoe by om die prosesomgewing meer self-contained te maak.

Vanuit ’n offensiewe oogpunt is hierdie namespace gewoonlik meer relevant vir **reconnaissance, timer skew en runtime-begrip** as vir ’n direkte breakout. Dit is egter belangrik omdat meer container runtimes en checkpoint/restore-workflows nou in staat is om dit eksplisiet aan te vra.

## Lab

As die host-kernel en userspace dit ondersteun, kan jy die namespace met die volgende inspekteer:
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
Ondersteuning wissel volgens kernel- en tool-weergawes, dus hierdie bladsy gaan meer daaroor om die meganisme te verstaan as om te verwag dat dit in elke lab-omgewing sigbaar sal wees. Die belangrike waarneming is dat `date` steeds die host se muurklok behoort te weerspieël, terwyl waardes gebaseer op monotonic/boottime dié is wat verander wanneer nie-nul-offsets gekonfigureer word.

### Skeppingsnuanse

Time namespaces is effens ongewoon in vergelyking met mount-, PID- of network namespaces:

- `unshare(CLONE_NEWTIME)` skep ’n nuwe time namespace vir **toekomstige child-processse**.
- Die calling task bly in sy huidige time namespace.
- `/proc/<pid>/ns/time_for_children` is dus dikwels interessanter as `/proc/<pid>/ns/time` wanneer runtime-opstelling ontfout word.

Die skryfvenster is ook spesiaal. Offsets in `/proc/<pid>/timens_offsets` moet geskryf word voordat die nuwe time namespace volledig met lopende tasks bevolk is; in die praktyk doen runtimes dit gedurende die nou setup-venster tussen namespace-skepping en die begin van die finale payload. Sodra ’n task reeds daar loop, misluk latere skrywe met `EACCES`. Daarom hanteer laevlak-runtimes time-namespace-opstelling as ’n vroeë bootstrap-stap, eerder as om offsets vanuit ’n reeds-beginde container process te probeer aanpas.

### Tyd-offsets

Linux time namespaces stel die per-namespace-offsets deur `/proc/<pid>/timens_offsets` bloot. Die formaat is ’n stel klokname of -ID’s plus sekonde-/nanosekonde-deltas relatief tot die aanvanklike time namespace.

In die praktyk is die betroubaarste gebruikersgerigte workflow om `unshare` die offsets vir jou te laat skryf:
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
Die belangrike punt is nie die presiese command-sintaksis nie, maar die gedrag: ’n container kan ’n ander uptime-agtige aansig waarneem sonder om die host se wall clock te verander.

### `unshare` Helper-vlae

Onlangse `util-linux`-weergawes verskaf geriefs-vlae wat die offsets outomaties skryf tydens namespace-skepping:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Hierdie flags is meestal ’n verbetering in usability, maar dit maak dit ook makliker om die feature in dokumentasie, test harnesses en runtime wrappers te herken.

## Gebruik tydens runtime

Time namespaces is nuwer en word minder universeel gebruik as mount- of PID namespaces. OCI Runtime Specification v1.1 het eksplisiete ondersteuning vir die `time` namespace en die `linux.timeOffsets`-veld bygevoeg, en moderne runtimes kan daardie data in die kernel bootstrap flow karteer. ’n Minimale OCI-fragment lyk soos:
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
Dit is belangrik omdat dit tydnaamruimte-isolasie van ’n nis-kernelprimitief verander in iets waarvoor runtimes draagbaar kan vra. Dit verduidelik ook waarom runtime-internals ’n eksplisiete sinchronisasiestap benodig: die offset moet na `/proc/<pid>/timens_offsets` geskryf word voordat die container-payload volledig die nuwe namespace binnegaan.

Checkpoint/restore-stacks soos CRIU is een van die belangrikste praktiese redes waarom dit hoegenaamd bestaan. Sonder time namespaces sou die herstel van ’n gepouseerde workload veroorsaak dat monotone en boottime-klokke spring met die hoeveelheid tyd wat die workload opgeskort was.

## Sekuriteitsimpak

Daar is minder klassieke breakout-verhale wat op die time namespace gesentreer is as op ander namespace-tipes. Die risiko is gewoonlik nie dat die time namespace direk escape moontlik maak nie, maar dat lesers dit heeltemal ignoreer en dus nie raaksien hoe gevorderde runtimes prosesgedrag kan vorm nie.

In gespesialiseerde omgewings kan veranderde monotone of boottime-aansigte die volgende beïnvloed:

- timeout- en retry-gedrag
- watchdogs en lease-logika
- `timerfd`, `nanosleep`, en `clock_nanosleep`-gedrag
- checkpoint/restore-forensiek
- telemetrie oor verstreke tyd en heuristieke gebaseer op uptime

Hoewel dit dus selde die eerste namespace is wat jy abuse, kan dit beslis "onmoontlike" tydsberekeningsgedrag tydens ’n assessment verklaar.

## Misbruik

Daar is gewoonlik geen direkte breakout-primitief hier nie, maar veranderde klokgedrag kan steeds nuttig wees om die execution environment te verstaan, gevorderde runtime-features te identifiseer, en timer-gebaseerde logika raak te sien wat teen monotone klokke eerder as wall clock time gemeet word:
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
As jy twee prosesse vergelyk, kan verskille hier help om vreemde tydsberekeningsgedrag, checkpoint/restore-artefakte of omgewingspesifieke logboekverskille te verduidelik.

Praktiese aanvallerrelevante invalshoeke:

- verwar backoff-, sleep- of watchdog-logika wat met monotonic clocks geïmplementeer is
- verduidelik waarom `/proc/uptime` en timer-gedrewe gedrag nie ooreenstem met verwagtings oor die host se wall-clock nie
- herken CRIU/checkpoint-restore-werkvloeie en ander gevorderde runtime-features
- identifiseer omgewings waar aansluiting by ’n teiken se time namespace met `nsenter -T -t <pid> -- ...` die container-local timer-gedrag vir debugging of post-exploitation kan reproduseer

Impak:

- byna altyd reconnaissance of begrip van die omgewing
- nuttig om logboek-, uptime- of checkpoint/restore-anomalieë te verduidelik
- nuttig vir die ontleding van monotonic-time-gebaseerde sleeps, retries en timers
- gewoonlik nie op sigself ’n direkte container-escape-meganisme nie

Die belangrike misbruiknuanse is dat time namespaces nie `CLOCK_REALTIME` virtualiseer nie. Daarom laat hulle ’n aanvaller nie op sigself toe om die host se wall clock te vervals of sertifikaatvervalkontroles stelselwyd direk te omseil nie. Die waarde daarvan lê hoofsaaklik daarin om monotonic-time-gebaseerde logika te verwar, om omgewingspesifieke foute te reproduseer of om gevorderde runtime-gedrag te verstaan.

## Checks

Hierdie checks gaan meestal daaroor om te bevestig of die runtime enigsins ’n private time namespace gebruik en of dit werklik nie-nul offsets gestel het.
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
Wat hier interessant is:

- In baie omgewings sal hierdie waardes nie tot ’n onmiddellike sekuriteitsbevinding lei nie, maar hulle wys wel of ’n gespesialiseerde runtime-funksie gebruik word.
- As `time_for_children` van `time` verskil, het die caller moontlik ’n child-only time namespace voorberei wat dit self nog nie binnegegaan het nie.
- As `date` met die host ooreenstem, maar monotonic/boottime-gebaseerde waardes nie, kyk jy waarskynlik na time namespacing eerder as wall-clock-manipulasie.
- As jy twee prosesse vergelyk, kan verskille hier verwarrende timing- of checkpoint/restore-gedrag verduidelik.

Vir die meeste container breakouts is die time namespace nie die eerste beheermeganisme wat jy sal ondersoek nie. Tog behoort ’n volledige container-security-afdeling dit te noem, omdat dit deel van die moderne kernel-model is en soms in gevorderde runtime-scenario’s belangrik is.

## Verwysings

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
