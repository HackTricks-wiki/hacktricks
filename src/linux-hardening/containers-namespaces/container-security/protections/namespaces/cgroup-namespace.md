# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die cgroup namespace vervang nie cgroups nie en dwing ook nie self resource limits af nie. In plaas daarvan verander dit **hoe die cgroup-hiërargie** aan die proses vertoon word. Met ander woorde, dit virtualiseer die sigbare cgroup-pad-inligting sodat die workload 'n container-beperkte aansig eerder as die volledige host-hiërargie sien.

Dit is hoofsaaklik 'n sigbaarheid- en inligtingverminderingsfunksie. Dit help om die omgewing selfstandig te laat lyk en onthul minder oor die host se cgroup-uitleg. Dit mag beskeie klink, maar dit bly belangrik omdat onnodige sigbaarheid van host-struktuur reconnaissance kan vergemaklik en omgewingafhanklike exploit chains kan vereenvoudig.

## Werking

Sonder 'n private cgroup namespace kan 'n proses host-relatiewe cgroup-paaie sien wat meer van die masjien se hiërargie blootlê as wat nuttig is. Met 'n private cgroup namespace word `/proc/self/cgroup` en verwante waarnemings meer gelokaliseer tot die container se eie aansig. Dit is veral nuttig in moderne runtime stacks wat wil hê dat die workload 'n skoner omgewing moet sien wat minder oor die host onthul.

Die virtualisering beïnvloed ook `/proc/<pid>/mountinfo`, nie net `/proc/<pid>/cgroup` nie. Wanneer jy 'n ander proses vanuit 'n ander cgroup-namespace-perspektief lees, word paaie buite jou namespace-root met vooraanstaande `../`-komponente vertoon, wat 'n handige aanduiding is dat jy bo jou gedelegeerde subtree kyk. 'n Nuttige nuanse vir labs en post-exploitation is dat 'n nuutgeskepte cgroup namespace dikwels 'n **cgroupfs remount vanuit binne daardie namespace** benodig voordat `mountinfo` die nuwe root korrek weerspieël. Andersins kan jy steeds 'n mount root soos `/..` sien, wat beteken dat die geërfde mount steeds 'n ancestor-rooted aansig blootlê, selfs al het die namespace self reeds verander.<sup>[[1]](#references)</sup>

## Lab

Jy kan 'n cgroup namespace inspekteer met:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
As jy wil hê dat `mountinfo` die nuwe cgroup-namespace-root duideliker moet wys, remount die cgroup filesystem vanuit die nuwe namespace en vergelyk weer:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
En vergelyk runtime-gedrag met:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Die verandering gaan meestal oor wat die proses kan sien, nie oor of cgroup enforcement bestaan nie.

## Security Impact

Die cgroup namespace word die beste verstaan as ’n **visibility-hardening layer**. Op sy eie sal dit nie ’n breakout keer indien die container writable cgroup mounts, breë capabilities of ’n gevaarlike cgroup v1-omgewing het nie. Indien die host cgroup namespace egter gedeel word, leer die proses meer oor hoe die stelsel georganiseer is en kan dit makliker wees om host-relative cgroup paths met ander waarnemings in lyn te bring.

Op **cgroup v2** begin die namespace ’n bietjie belangriker te word omdat delegation rules strenger is. Indien die hierarchy met `nsdelegate` gemount is, behandel die kernel cgroup namespaces as delegation boundaries: ancestor control files behoort buite die delegatee se bereik te bly, en writes by die namespace root word beperk tot delegation-safe files soos `cgroup.procs`, `cgroup.threads` en `cgroup.subtree_control`.<sup>[[2]](#references)</sup> Dit maak die namespace steeds nie op sigself ’n escape primitive nie, maar dit verander wat ’n compromised workload kan inspekteer en waar dit veilig sub-cgroups kan skep.

Alhoewel hierdie namespace dus gewoonlik nie die hoofrolspeler in container breakout writeups is nie, dra dit steeds by tot die breër doel om host information leakage te beperk en cgroup delegation te beheer.

## Abuse

Die onmiddellike abuse value is meestal reconnaissance. Indien die host cgroup namespace gedeel word, vergelyk die sigbare paths en soek na host-revealing hierarchy details:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Indien skryfbare cgroup-paaie ook blootgestel word, kombineer daardie sigbaarheid met ’n soektog na gevaarlike legacy interfaces:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Die namespace self gee selde onmiddellik escape, maar dit maak dit dikwels makliker om die omgewing te karteer voordat cgroup-based abuse primitives getoets word.

’n Vinnige runtime reality check help ook om die attack path te prioritiseer. Docker stel `--cgroupns=host|private` bloot, terwyl Podman `host`, `private`, `container:<id>` en `ns:<path>` ondersteun. Spesifiek in Podman is die verstek gewoonlik **`host` op cgroup v1** en **`private` op cgroup v2**, dus vertel die identifisering van die cgroup-weergawe jou reeds watter namespace posture waarskynliker is voordat jy selfs die volledige OCI config inspekteer.

### Moderne v2 Recon: Is Dit ’n Gedelegeerde Subtree?

Op moderne hosts is die interessante vraag dikwels nie `release_agent` nie, maar of die huidige proses binne ’n gedelegeerde **cgroup v2** subtree is met genoeg visibility of write access om nested groups te bou:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Nuttige interpretasie:

- `cgroup2fs` beteken dat jy in die unified v2 hierarchy is, dus behoort klassieke v1-only `release_agent` chains nie jou eerste aanname te wees nie.
- `cgroup.controllers` wys watter controllers vanaf die ouer beskikbaar is en dus waarheen die huidige subtree moontlik na children kan uitbrei.
- `cgroup.subtree_control` wys watter controllers werklik vir descendants enabled is.
- `cgroup.events` stel `populated=0/1` bloot, wat handig is om dop te hou of ’n subtree leeg geword het, maar dit is **nie ’n host-code-execution primitive soos v1 `release_agent` nie**.

As jy reeds genoeg privilege het om ’n ander process se namespace direk te inspekteer, vergelyk views met:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Volledige voorbeeld: Gedeelde cgroup Namespace + Skryfbare cgroup v1

Die cgroup namespace alleen is gewoonlik nie genoeg vir escape nie. Die praktiese eskalasie vind plaas wanneer host-blootleggende cgroup-paaie met skryfbare cgroup v1-koppelvlakke gekombineer word:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
As daardie lêers bereikbaar en skryfbaar is, pivot onmiddellik na die volledige `release_agent`-exploitasievloei uit [cgroups.md](../cgroups.md). Die impak is host-kode-uitvoering vanuit binne die container.

Sonder skryfbare cgroup-koppelvlakke is die impak gewoonlik beperk tot reconnaissance.

## Kontroles

Die doel van hierdie opdragte is om te bepaal of die proses ’n private cgroup namespace-aansig het en of dit meer oor die host-hiërargie leer as wat dit werklik nodig het.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Wat is hier interessant:

- As die namespace identifier ooreenstem met ’n host-proses waarin jy belangstel, kan die cgroup namespace gedeel word.
- Paaie wat die host in `/proc/self/cgroup` openbaar, of ancestor-rooted entries in `mountinfo`, is nuttige reconnaissance, selfs wanneer hulle nie direk exploitable is nie.
- As `cgroup2fs` gebruik word, fokus op delegation, sigbare controllers en writable subtrees eerder as om aan te neem dat ou v1-primitives steeds bestaan.
- As cgroup mounts ook writable is, word die sigbaarheidsvraagstuk baie belangriker.

Die cgroup namespace moet as ’n visibility-hardening-laag beskou word eerder as ’n primêre escape-prevention-meganisme. Die onnodige blootstelling van die host se cgroup-struktuur voeg reconnaissance-waarde vir die aanvaller by.

## Verwysings

- [1] [cgroup_namespaces(7) — Linux manual page](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [2] [Control Group v2 — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
