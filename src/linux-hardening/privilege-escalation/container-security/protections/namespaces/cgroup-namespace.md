# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die cgroup namespace vervang nie cgroups nie en dwing op sigself geen hulpbronlimiete af nie. In plaas daarvan verander dit **hoe die cgroup-hiërargie aan die proses verskyn**. Met ander woorde virtualiseer dit die sigbare cgroup-pad-inligting sodat die werklas 'n container-afgebakende siening kry in plaas van die volledige gasheer-hiërargie.

Dit is hoofsaaklik 'n sigbaarheids- en inligtingsverkleiningsfunksie. Dit help om die omgewing self-contained te laat lyk en openbaar minder oor die gasheer se cgroup-opstelling. Dit mag eenvoudig klink, maar dit is steeds belangrik omdat onnodige sigbaarheid in die gasheerstruktuur verkenning kan vergemaklik en omgewing-afhanklike exploit chains kan vereenvoudig.

## Werking

Sonder 'n private cgroup namespace kan 'n proses host-relatiewe cgroup-paaie sien wat meer van die masjien se hiërargie openbaar as nodig. Met 'n private cgroup namespace raak `/proc/self/cgroup` en verwante waarnemings meer gelokaliseer tot die container se eie siening. Dit is veral nuttig in moderne runtime-stakke wat wil hê die werklas moet 'n netter, en minder inligting oor die gasheer openbaarende omgewing sien.

## Lab

Jy kan 'n cgroup namespace inspekteer met:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
En vergelyk die runtime-gedrag met:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Die verandering gaan hoofsaaklik oor wat die proses kan sien, nie oor of cgroup enforcement bestaan nie.

## Security Impact

Die cgroup namespace word die beste verstaan as 'n **sigbaarheidsverhardingslaag**. Op sigself gaan dit nie 'n breakout keer nie indien die container skryfbare cgroup mounts, wye capabilities, of 'n gevaarlike cgroup v1-omgewing het. As die host cgroup namespace egter gedeel is, leer die proses meer oor hoe die stelsel georganiseer is en mag dit makliker wees om host-relative cgroup paths met ander waarnemings te belyn.

Alhoewel hierdie namespace gewoonlik nie die ster van container breakout writeups is nie, dra dit steeds by tot die breër doel om host information leakage te minimaliseer.

## Abuse

Die onmiddellike abuse-waarde is hoofsaaklik reconnaissance. As die host cgroup namespace gedeel is, vergelyk die sigbare paths en soek na host-revealing hierarchy details:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
As skryfbare cgroup-paadjies ook blootgestel is, kombineer daardie sigbaarheid met 'n soektog na gevaarlike verouderde interfaces:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Die namespace self gee selde onmiddellike escape, maar dit maak dikwels die omgewing makliker om te karteer voordat cgroup-based abuse primitives getoets word.

### Volledige voorbeeld: Shared cgroup Namespace + Writable cgroup v1

Die cgroup namespace alleen is gewoonlik nie genoeg vir escape nie. Die praktiese eskalasie gebeur wanneer host-revealing cgroup paths gekombineer word met writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
As daardie lêers bereikbaar en skryfbaar is, pivot dadelik na die volledige `release_agent` exploitation flow vanaf [cgroups.md](../cgroups.md). Die impak is host code execution van binne die container.

Sonder skryfbare cgroup interfaces is die impak gewoonlik beperk tot reconnaissance.

## Kontroles

Die doel van hierdie opdragte is om te sien of die proses 'n private cgroup namespace view het of meer oor die host hiërargie leer as wat dit regtig nodig het.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Wat hier interessant is:

- As die namespace-identifiseerder ooreenstem met 'n host-proses waarna jy omgee, kan die cgroup namespace gedeel wees.
- Paadjies wat die host openbaar in `/proc/self/cgroup` is nuttige verkenning, selfs wanneer hulle nie direk uitbuitbaar is nie.
- As cgroup mounts ook skryfbaar is, word die sigbaarheidskwessie baie belangriker.

Die cgroup namespace moet as 'n sigbaarheidsverhardingslaag gesien word eerder as 'n primêre meganisme om ontsnapping te voorkom. Om die host cgroup-structuur onnodig bloot te stel verhoog die verkenningswaarde vir die aanvaller.
