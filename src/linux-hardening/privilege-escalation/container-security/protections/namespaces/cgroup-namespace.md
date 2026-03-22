# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die cgroup namespace vervang nie cgroups nie en dwing ook nie self resource-limiete af nie. In plaas daarvan verander dit **hoe die cgroup hiërargie verskyn** vir die proses. Met ander woorde virtualiseer dit die sigbare cgroup-pad-inligting sodat die workload 'n container-scoped view sien in plaas van die volle host-hiërargie.

Dit is hoofsaaklik 'n sigbaarheid- en inligtingsreduksie-funksie. Dit help om die omgewing selfstandig te laat lyk en openbaar minder oor die host se cgroup-opstelling. Dit mag eenvoudig klink, maar dit bly belangrik omdat onnodige sigbaarheid in die host-struktuur reconnaissance kan ondersteun en environment-dependent exploit chains kan vereenvoudig.

## Werking

Sonder 'n private cgroup namespace kan 'n proses host-relatiewe cgroup-paaie sien wat meer van die masjien se hiërargie blootstel as wat nodig is. Met 'n private cgroup namespace word `/proc/self/cgroup` en verwante waarnemings meer gelokaliseer tot die container se eie oogpunt. Dit is veral nuttig in moderne runtime stacks wat wil hê die workload moet 'n netter, minder host-revealing omgewing sien.

## Lab

Jy kan 'n cgroup namespace inspekteer met:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
En vergelyk runtime-gedrag met:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Die verandering gaan hoofsaaklik oor wat die proses kan sien, nie oor of cgroup enforcement bestaan nie.

## Sekuriteitsimpak

Die cgroup namespace word die beste verstaan as 'n **sigbaarheidsverhardingslaag**. Op sigself sal dit nie 'n breakout stop nie as die container writable cgroup mounts, broad capabilities, of 'n gevaarlike cgroup v1-omgewing bestaan. Echter, as die host cgroup namespace gedeel is, leer die proses meer oor hoe die stelsel georganiseer is en kan dit makliker vind om host-relatiewe cgroup-paaie met ander waarnemings te belyn.

So terwyl hierdie namespace gewoonlik nie die hoofrol in container breakout writeups speel nie, dra dit steeds by tot die breër doel om host information leakage te minimaliseer.

## Misbruik

Die onmiddellike misbruikwaarde is meestal reconnaissance. As die host cgroup namespace gedeel is, vergelyk die sigbare paaie en kyk vir host-revealing hierarchy details:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
As skryfbare cgroup paths ook blootgestel is, kombineer daardie sigbaarheid met 'n soektog na gevaarlike legacy interfaces:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Die naamruimte self gee selde onmiddellike ontsnapping, maar dit maak dikwels die omgewing makliker om te karteer voordat cgroup-gebaseerde misbruikprimitiewe getoets word.

### Volledige Voorbeeld: Gedeelde cgroup Naamruimte + Skryfbare cgroup v1

Die cgroup-naamruimte alleen is gewoonlik nie genoeg vir ontsnapping nie. Die praktiese eskalering gebeur wanneer cgroup-paaie wat die gasheer openbaar, gekombineer word met skryfbare cgroup v1-koppelvlakke:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
As daardie lêers bereikbaar en skryfbaar is, skakel onmiddellik oor na die volledige `release_agent` exploitation flow van [cgroups.md](../cgroups.md). Die impak is uitvoering van kode op die host vanaf binne die container.

Sonder skryfbare cgroup-koppelvlakke is die impak gewoonlik beperk tot verkenning.

## Checks

Die doel van hierdie opdragte is om te sien of die proses 'n privaat cgroup-namespace-uitsig het of meer oor die host-hiërargie uitvind as wat dit regtig nodig het.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
- As die namespace identifier ooreenstem met 'n host process waarin jy belangstel, kan die cgroup namespace gedeel wees.
- Host-revealing paths in `/proc/self/cgroup` is nuttige reconnaissance, selfs wanneer hulle nie direk uitgebuit kan word nie.
- As cgroup mounts ook writable is, word die visibility-vraag baie belangriker.

Die cgroup namespace moet eerder as 'n sigbaarheidsverhardingslaag behandel word in plaas van as 'n primêre ontsnappingsvoorkomingsmeganisme. Om die host cgroup structure onnodig bloot te stel, verhoog die reconnaissance-waarde vir die aanvaller.
{{#include ../../../../../banners/hacktricks-training.md}}
