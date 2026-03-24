# cgroup Naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die cgroup-naamruimte vervang nie cgroups nie en dwing self nie hulpbronbeperkings af. In plaas daarvan verander dit **hoe die cgroup-hiërargie aan die proses verskyn**. Met ander woorde virtualiseer dit die sigbare cgroup-padinligting sodat die workload ’n siening beperk tot die container kry in plaas van die volle gasheer-hiërargie.

Dit is hoofsaaklik ’n sigbaarheid- en inligtingreduksiefunksie. Dit help om die omgewing selfonderhoudend te laat lyk en openbaar minder van die gasheer se cgroup-opstelling. Dit mag beskeie klink, maar dit maak steeds saak omdat onnodige sigbaarheid van die gasheerstruktuur verkenning kan vergemaklik en omgewing-afhanklike exploit-reekse kan vereenvoudig.

## Werking

Sonder ’n privaat cgroup-naamruimte kan ’n proses gasheer-relatiewe cgroup-paaie sien wat meer van die masjien se hiërargie openbaar as wat nuttig is. Met ’n privaat cgroup-naamruimte word `/proc/self/cgroup` en verwante waarnemings meer beperk tot die container se eie siening. Dit is veral nuttig in moderne runtime-stakke wat wil hê dat die workload ’n netter, minder gasheer-onthullende omgewing moet sien.

## Laboratorium

Jy kan ’n cgroup-naamruimte inspekteer met:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
En vergelyk runtime behavior met:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Die verandering gaan hoofsaaklik oor wat die proses kan sien, nie oor of cgroup enforcement bestaan nie.

## Sekuriteitsimpak

Die cgroup namespace word die beste verstaan as 'n **sigbaarheidsverhardingslaag**. Op sigself sal dit nie 'n breakout keer as die container skryfbare cgroup mounts het, uitgebreide capabilities, of 'n gevaarlike cgroup v1-omgewing nie. As die host cgroup namespace egter gedeel word, leer die proses meer oor hoe die stelsel georganiseer is en kan dit makliker wees om host-relative cgroup paths met ander waarnemings te belyn.

Dus, hoewel hierdie namespace gewoonlik nie die hoofrol speel in container breakout-opskrywings nie, dra dit steeds by tot die breër doel om die hoeveelheid host-inligting wat bekend word, te minimaliseer.

## Misbruik

Die onmiddellike misbruikwaarde is hoofsaaklik verkenning. As die host cgroup namespace gedeel word, vergelyk die sigbare paths en kyk vir hiërargie-besonderhede wat die host openbaar:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
As skrifbare cgroup-paaie ook blootgestel is, kombineer daardie sigbaarheid met 'n soektog na gevaarlike erfenis-koppelvlakke:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Die namespace self gee selde onmiddellike escape, maar dit maak dikwels die omgewing makliker om te karteer voordat cgroup-based abuse primitives getoets word.

### Volledige voorbeeld: Gedeelde cgroup Namespace + Skryfbare cgroup v1

Die cgroup namespace op sigself is gewoonlik nie genoeg vir escape nie. Die praktiese eskalasie gebeur wanneer host-revealing cgroup paths gekombineer word met writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
As daardie lêers bereikbaar en beskryfbaar is, skuif onmiddellik oor na die volledige `release_agent` exploitation flow van [cgroups.md](../cgroups.md). Die impak is host code execution van binne die container.

Sonder beskryfbare cgroup interfaces is die impak gewoonlik beperk tot reconnaissance.

## Checks

Die doel van hierdie opdragte is om te sien of die proses 'n private cgroup namespace view het of meer oor die host hierarchy uitvind as wat dit regtig nodig het.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
- As die namespace identifier ooreenstem met 'n host process waarvoor jy belangstel, mag die cgroup namespace gedeel wees.
- Host-revealing paths in `/proc/self/cgroup` is nuttige reconnaissance, selfs wanneer dit nie direk exploitable is nie.
- As cgroup mounts ook writable is, word die visibility-vraag baie belangriker.

Die cgroup namespace moet as 'n visibility-hardening layer beskou word eerder as 'n primêre escape-prevention-meganisme. Om host cgroup structure onnodig bloot te stel voeg reconnaissance-waarde vir die aanvaller by.
{{#include ../../../../../banners/hacktricks-training.md}}
