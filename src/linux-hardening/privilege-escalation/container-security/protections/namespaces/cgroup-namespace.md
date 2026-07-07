# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die cgroup namespace vervang nie cgroups nie en dwing self nie hulpbronlimiete af nie. In plaas daarvan verander dit **hoe die cgroup-hiërargie vir die proses verskyn**. Met ander woorde, dit virtualiseer die sigbare cgroup-pad-inligting sodat die workload ’n container-geskepte aansig sien eerder as die volledige host-hiërargie.

Dit is hoofsaaklik ’n sigbaarheids- en inligtingsverminderingsfunksie. Dit help om die omgewing selfstandig te laat lyk en verklap minder oor die host se cgroup-uitleg. Dit klink dalk beskeie, maar dit maak steeds saak omdat onnodige sigbaarheid in die host-struktuur reconnaissance kan help en omgewing-afhanklike exploit-kettings kan vereenvoudig.

## Bedryf

Sonder ’n private cgroup namespace kan ’n proses host-verwante cgroup-paaie sien wat meer van die masjien se hiërargie blootstel as wat nuttig is. Met ’n private cgroup namespace word `/proc/self/cgroup` en verwante waarnemings meer gelokaliseer tot die container se eie aansig. Dit is veral nuttig in moderne runtime stacks wat wil hê dat die workload ’n skoner, minder host-verraaiende omgewing moet sien.

Die virtualisering beïnvloed ook `/proc/<pid>/mountinfo`, nie net `/proc/<pid>/cgroup` nie. Wanneer jy ’n ander proses vanuit ’n ander cgroup-namespace-perspektief lees, word paaie buite jou namespace-root met voorste `../`-komponente gewys, wat ’n handige leidraad is dat jy bo jou gedelegeerde subtree kyk. ’n Nuttige nuanse vir labs en post-exploitation is dat ’n pasgeskepte cgroup namespace dikwels ’n **cgroupfs remount van binne daardie namespace** benodig voordat `mountinfo` die nuwe root skoon reflekteer. Andersins kan jy steeds ’n mount root soos `/..` sien, wat beteken die geërfde mount stel steeds ’n ancestor-rooted view bloot al het die namespace self reeds verander.

## Lab

Jy kan ’n cgroup namespace inspekteer met:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
As jy wil hê `mountinfo` moet die nuwe cgroup-namespace wortel duideliker wys, remount die cgroup filesystem van binne die nuwe namespace en vergelyk weer:
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

Die cgroup namespace word die beste verstaan as 'n **visibility-hardening layer**. Op sigself sal dit nie 'n breakout stop as die container writable cgroup mounts, broad capabilities, of 'n gevaarlike cgroup v1 environment het nie. As die host cgroup namespace egter gedeel word, leer die proses meer oor hoe die stelsel georganiseer is en kan dit makliker vind om host-relative cgroup paths met ander waarnemings te koppel.

Op **cgroup v2** begin die namespace effens meer saak maak omdat delegation rules strenger is. As die hierarchy met `nsdelegate` gemount is, behandel die kernel cgroup namespaces as delegation boundaries: ancestor control files behoort buite die delegatee se bereik te bly, en writes by die namespace root is beperk tot delegation-safe files soos `cgroup.procs`, `cgroup.threads`, en `cgroup.subtree_control`. Dit maak steeds nie die namespace op sigself 'n escape primitive nie, maar dit verander wat 'n compromised workload kan inspekteer en waar dit veilig sub-cgroups kan skep.

So, hoewel hierdie namespace gewoonlik nie die ster van container breakout writeups is nie, dra dit steeds by tot die breër doel om host information leakage te minimaliseer en cgroup delegation te beperk.

## Abuse

Die onmiddellike abuse-waarde is meestal reconnaissance. As die host cgroup namespace gedeel word, vergelyk die sigbare paths en soek na hierarchy details wat die host verraai:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
As skryfbare cgroup-paaie ook blootgestel is, kombineer daardie sigbaarheid met ’n soektog vir gevaarlike legacy-interfaces:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Die namespace self gee selde onmiddelike escape, maar dit maak die omgewing dikwels makliker om te map voordat jy cgroup-gebaseerde abuse primitives toets.

’n Vinnige runtime reality check help ook om die aanvalspad te prioritiseer. Docker stel `--cgroupns=host|private` bloot, terwyl Podman `host`, `private`, `container:<id>`, en `ns:<path>` ondersteun. Op Podman spesifiek is die default gewoonlik **`host` op cgroup v1** en **`private` op cgroup v2**, so om net die cgroup version te identifiseer, vertel jou reeds watter namespace posture meer waarskynlik is nog voordat jy die volledige OCI config inspekteer.

### Modern v2 Recon: Is This A Delegated Subtree?

Op moderne hosts is die interessante vraag dikwels nie `release_agent` nie, maar of die huidige proses binne ’n gedelegeerde **cgroup v2** subtree sit met genoeg visibility of write access om nested groups te bou:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Nuttige interpretasie:

- `cgroup2fs` beteken jy is in die verenigde v2-hiërargie, so klassieke v1-alleen `release_agent`-kettings moet nie meer jou eerste raaiskoot wees nie.
- `cgroup.controllers` wys watter controllers vanaf die ouer beskikbaar is en dus waartoe die huidige subtree potensieel na kinders kan uitwaaier.
- `cgroup.subtree_control` wys watter controllers werklik vir afstammelinge geaktiveer is.
- `cgroup.events` stel `populated=0/1` bloot, wat handig is om te monitor of 'n subtree leeg geword het, maar dit is **nie** 'n host-code-execution-primatief soos v1 `release_agent` nie.

As jy reeds genoeg privilege het om 'n ander proses namespace direk te inspekteer, vergelyk aansigte met:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Volledige Voorbeeld: Gedeelde cgroup Namespace + Skribare cgroup v1

Die cgroup namespace alleen is gewoonlik nie genoeg vir escape nie. Die praktiese eskalasie gebeur wanneer host-revealing cgroup paths gekombineer word met skryfbare cgroup v1-koppelvlakke:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
As daardie lêers bereikbaar en skryfbaar is, pivot onmiddellik na die volle `release_agent`-eksploitasiestroom van [cgroups.md](../cgroups.md). Die impak is host code execution van binne die container.

Sonder skryfbare cgroup interfaces is die impak gewoonlik beperk tot reconnaissance.

## Checks

Die doel van hierdie commands is om te sien of die proses ’n private cgroup namespace view het of meer oor die host-hiërargie leer as wat dit regtig nodig het.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Wat is interessant hier:

- As die namespace-identifier ooreenstem met 'n host-proses waarvoor jy omgee, kan die cgroup namespace gedeel word.
- Host-onthullende paths in `/proc/self/cgroup` of ancestor-rooted entries in `mountinfo` is nuttige reconnaissance, selfs wanneer hulle nie direk exploiteerbaar is nie.
- As `cgroup2fs` in gebruik is, fokus op delegation, sigbare controllers, en writable subtrees eerder as om aan te neem dat ou v1 primitives nog bestaan.
- As cgroup mounts ook writable is, word die visibility-vraag baie belangriker.

Die cgroup namespace moet behandel word as 'n visibility-hardening laag eerder as as 'n primêre escape-prevention meganisme. Om host cgroup-struktuur onnodig bloot te stel, voeg reconnaissance-waarde vir die aanvaller by.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
