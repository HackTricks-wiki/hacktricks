# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die cgroup namespace vervang nie cgroups nie en dwing ook nie self hulpbronlimiete af nie. In plaas daarvan verander dit **hoe die cgroup-hiërargie** aan die proses vertoon word. Met ander woorde, dit virtualiseer die sigbare cgroup-pad-inligting sodat die werklading 'n houerbeperkte aansig eerder as die volledige gasheerhiërargie sien.

Dit is hoofsaaklik 'n sigbaarheid- en inligtingsverminderingsfunksie. Dit help om die omgewing selfstandig te laat lyk en onthul minder oor die gasheer se cgroup-uitleg. Dit mag beskeie klink, maar dit is steeds belangrik omdat onnodige sigbaarheid van die gasheer se struktuur reconnaissance kan ondersteun en omgewingafhanklike exploit chains kan vereenvoudig.

## Werking

Sonder 'n private cgroup namespace kan 'n proses gasheerrelatiewe cgroup-paaie sien wat meer van die masjien se hiërargie blootlê as wat nuttig is. Met 'n private cgroup namespace word `/proc/self/cgroup` en verwante waarnemings meer gelokaliseer tot die houer se eie aansig. Dit is veral nuttig in moderne runtime stacks wat wil hê dat die werklading 'n skoner omgewing moet sien wat minder oor die gasheer verklap.

Die virtualisering beïnvloed ook `/proc/<pid>/mountinfo`, nie net `/proc/<pid>/cgroup` nie. Wanneer jy 'n ander proses vanuit 'n ander cgroup-namespace-perspektief lees, word paaie buite jou namespace-wortel met vooraanstaande `../`-komponente vertoon. Dit is 'n nuttige aanduiding dat jy bo jou gedelegeerde subtree kyk. 'n Belangrike nuanse vir labs en post-exploitation is dat 'n nuutgeskepte cgroup namespace dikwels 'n **cgroupfs-remount vanuit binne daardie namespace** benodig voordat `mountinfo` die nuwe wortel korrek weerspieël. Andersins kan jy steeds 'n mount-wortel soos `/..` sien, wat beteken dat die geërfde mount steeds 'n voorouer-gewortelde aansig blootlê, selfs al het die namespace self reeds verander.

## Laboratorium

Jy kan 'n cgroup namespace inspekteer met:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
As jy wil hê dat `mountinfo` die nuwe cgroup-namespace-root duideliker moet wys, mount die cgroup-lêerstelsel weer vanuit binne die nuwe namespace en vergelyk weer:
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
Die verandering gaan hoofsaaklik oor wat die proses kan sien, nie oor of cgroup-enforcement bestaan nie.

## Sekuriteitsimpak

Die cgroup namespace word die beste verstaan as ’n **sigbaarheidsverhardingslaag**. Op sigself sal dit nie ’n breakout stop as die container skryfbare cgroup-mounts, breë capabilities of ’n gevaarlike cgroup v1-omgewing het nie. As die host cgroup namespace egter gedeel word, leer die proses meer oor hoe die stelsel georganiseer is en kan dit makliker wees om host-relatiewe cgroup-paaie met ander waarnemings in lyn te bring.

Op **cgroup v2** begin die namespace ’n bietjie belangriker word omdat delegation-reëls strenger is. As die hiërargie met `nsdelegate` gemount is, behandel die kernel cgroup namespaces as delegation-grense: ancestor-control-lêers behoort buite die delegatee se bereik te bly, en writes by die namespace-root word beperk tot delegation-veilige lêers soos `cgroup.procs`, `cgroup.threads` en `cgroup.subtree_control`. Dit maak die namespace steeds nie op sigself ’n escape-primitive nie, maar dit verander wat ’n gecompromitteerde workload kan inspekteer en waar dit veilig sub-cgroups kan skep.

Hoewel hierdie namespace dus gewoonlik nie die hoofrolspeler in container-breakout-writeups is nie, dra dit steeds by tot die breër doel om host-inligting-leak te minimaliseer en cgroup-delegation te beperk.

## Misbruik

Die onmiddellike misbruikwaarde is meestal reconnaissance. As die host cgroup namespace gedeel word, vergelyk die sigbare paaie en soek na hiërargie-besonderhede wat die host blootlê:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Indien skryfbare cgroup-paaie ook blootgestel is, kombineer hierdie sigbaarheid met ’n soektog na gevaarlike legacy interfaces:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Die namespace self lei selde tot ’n onmiddellike escape, maar dit maak dit dikwels makliker om die omgewing te karteer voordat cgroup-gebaseerde abuse primitives getoets word.

’n Vinnige runtime-realiteitskontrole help ook om die aanvalspad te prioritiseer. Docker stel `--cgroupns=host|private` bloot, terwyl Podman `host`, `private`, `container:<id>` en `ns:<path>` ondersteun. Spesifiek op Podman is die verstek gewoonlik **`host` op cgroup v1** en **`private` op cgroup v2**, dus vertel die identifisering van die cgroup-weergawe jou reeds watter namespace-houding meer waarskynlik is voordat jy selfs die volledige OCI-config inspekteer.

### Moderne v2 Recon: Is Dit ’n Gedelegeerde Subtree?

Op moderne hosts is die interessante vraag dikwels nie `release_agent` nie, maar of die huidige process binne ’n gedelegeerde **cgroup v2**-subtree sit met genoeg sigbaarheid of skryftoegang om geneste groepe te bou:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Nuttige interpretasie:

- `cgroup2fs` beteken dat jy in die unified v2-hiërargie is, dus behoort klassieke v1-only `release_agent`-chains nie jou eerste aanname te wees nie.
- `cgroup.controllers` wys watter controllers vanaf die ouer beskikbaar is en dus waarna die huidige subtree moontlik na children kan uitbrei.
- `cgroup.subtree_control` wys watter controllers werklik vir descendants geaktiveer is.
- `cgroup.events` stel `populated=0/1` bloot, wat nuttig is om dop te hou of ’n subtree leeg geword het, maar dit is **nie** ’n host-code-execution primitive soos v1 `release_agent` nie.

As jy reeds genoeg privilege het om ’n ander proses se namespace direk te inspekteer, vergelyk die views met:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Volledige voorbeeld: Gedeelde cgroup Namespace + Skryfbare cgroup v1

Die cgroup namespace alleen is gewoonlik nie genoeg vir escape nie. Die praktiese eskalasie vind plaas wanneer cgroup-paaie wat die host blootlê, met skryfbare cgroup v1-koppelvlakke gekombineer word:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
As daardie lêers bereikbaar en skryfbaar is, pivot onmiddellik na die volledige `release_agent`-exploitation flow from [cgroups.md](../cgroups.md). Die impak is host-kode-uitvoering van binne die container.

Sonder skryfbare cgroup interfaces is die impak gewoonlik beperk tot reconnaissance.

## Kontroles

Die doel van hierdie opdragte is om te sien of die proses ’n private cgroup namespace-aansig het, of meer oor die host-hiërargie leer as wat dit werklik nodig het.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Wat is hier interessant:

- As die namespace-identifiseerder met ’n host-proses wat vir jou van belang is ooreenstem, kan die cgroup namespace gedeel word.
- Host-onthullende paaie in `/proc/self/cgroup` of ancestor-rooted-inskrywings in `mountinfo` is nuttige verkenning, selfs wanneer hulle nie direk uitbuitbaar is nie.
- As `cgroup2fs` gebruik word, fokus op delegation, sigbare controllers en skryfbare subtrees eerder as om aan te neem dat ou v1-primitives steeds bestaan.
- As cgroup mounts ook skryfbaar is, word die sigbaarheidsvraag baie belangriker.

Die cgroup namespace moet as ’n sigbaarheid-verhardingslaag eerder as ’n primêre escape-voorkomingsmeganisme beskou word. Om host-cgroup-struktuur onnodig bloot te stel, voeg verkenningswaarde vir die aanvaller by.

## Verwysings

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
