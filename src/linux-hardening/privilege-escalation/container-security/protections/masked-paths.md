# Gemaskerde paaie

{{#include ../../../../banners/hacktricks-training.md}}

Gemaskerde paaie is runtime-beskermings wat besonders sensitiewe, na die kernel gerigte lêerstelsel-lokasies vir die container wegsteek deur daaroor te bind-mount of andersins ontoeganklik te maak. Die doel is om te verhoed dat 'n werkbelasting direk met interfaces kommunikeer wat gewone toepassings nie nodig het nie, veral binne procfs.

Dit maak saak omdat baie container escapes en host-impacting tricks begin deur spesiale lêers onder `/proc` of `/sys` te lees of te skryf. As daardie lokasies gemasker is, verloor die aanvaller direkte toegang tot 'n nuttige deel van die kernel se beheeroppervlak selfs nadat hy kode-uitvoering binne die container verkry het.

## Werking

Runtimes maskeer gewoonlik uitgesoekte paadjies soos:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Die presiese lys hang af van die runtime en host-konfigurasie. Die belangrike eienskap is dat die paadjie vanuit die container se oogpunt ontoeganklik of vervang word, selfs al bestaan dit steeds op die host.

## Lab

Inspekteer die masked-path-konfigurasie wat deur Docker blootgestel word:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Inspekteer die werklike mount-gedrag binne die workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Sekuriteitsimpak

Maskering skep nie die primêre isolasiegrens nie, maar dit verwyder verskeie hoë-waarde post-exploitation doele. Sonder maskering mag 'n gekompromitteerde container in staat wees om kernstatus te inspekteer, sensitiewe proses- of sleutelinligting te lees, of met procfs/sysfs-objekte te kommunikeer wat nooit vir die toepassing sigbaar moes wees nie.

## Miskonfigurasies

Die hooffout is om breë klasse van paaie te unmask vir gerief of foutopsporing. In Podman kan dit voorkom as `--security-opt unmask=ALL` of geteikende unmasking. In Kubernetes kan oor-breë proc-blootstelling voorkom via `procMount: Unmasked`. ’n Ander ernstige probleem is om gasheer se `/proc` of `/sys` bloot te stel deur 'n bind mount, wat die idee van 'n ingeperkte container-view heeltemal omseil.

## Misbruik

As maskering swak of afwesig is, begin deur te identifiseer watter sensitiewe procfs/sysfs-paaie direk bereikbaar is:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
As 'n verondersteld gemaskerde pad toeganklik is, ondersoek dit deeglik:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Wat hierdie opdragte kan openbaar:

- /proc/timer_list kan gasheer se timer- en skeduleerderdata openbaar. Dit is meestal 'n verkenningsprimitive, maar dit bevestig dat die container kerngerigte inligting kan lees wat gewoonlik verborgen is.
- /proc/keys is veel meer sensitief. Afhangend van die gasheerkonfigurasie kan dit keyring-inskrywings, key-beskrywings en verhoudings tussen gasheerdienste openbaar wat die kernel keyring-substelsel gebruik.
- /sys/firmware help om opstartmodus, firmware-koppelvlakke en platformbesonderhede te identifiseer wat nuttig is vir host fingerprinting en om te verstaan of die werkbelasting gasheervlaktoestand sien.
- /proc/config.gz kan die lopende kernkonfigurasie openbaar maak, wat waardevol is om dit te pas by publieke kernel exploit-voorvereistes of om te verstaan waarom 'n spesifieke funksie bereikbaar is.
- /proc/sched_debug openbaar skeduleerdertoestand en omseil dikwels die intuïtiewe verwagting dat die PID-namespace ongekoppelde prosesinligting volledig moet wegsteek.

Interessante resultate sluit direkte lees van daardie lêers in, bewyse dat die data aan die gasheer behoort eerder as aan 'n beperkte container-uitsig, of toegang tot ander procfs/sysfs-ligginge wat gewoonlik standaard gemaskeer is.

## Kontroles

Die punt van hierdie kontroles is om te bepaal watter paaie die runtime opsetlik weggesteek het en of die huidige werkbelasting steeds 'n verminderde kerngerigte lêerstelsel sien.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Wat hier interessant is:

- 'n Lang lys gemaskerde paaie is normaal in geharde runtimes.
- Ontbrekende maskering op sensitiewe procfs-inskrywings verdien noukeuriger ondersoek.
- As 'n sensitiewe pad toeganklik is en die container het ook uitgebreide bevoegdhede of breë mounts, is die blootstelling meer betekenisvol.

## Runtime-standaarde

| Runtime / platform | Standaardtoestand | Standaardgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | By verstek geaktiveer | Docker definieer 'n standaard lys van gemaskerde paaie | blootstelling van gasheer proc/sys mounts, `--privileged` |
| Podman | By verstek geaktiveer | Podman pas standaard gemaskerde paaie toe tensy dit handmatig ontmasker word | `--security-opt unmask=ALL`, geteikende ontmaskering, `--privileged` |
| Kubernetes | Erf die runtime-standaarde | Gebruik die onderliggende runtime se maskeringsgedrag tensy Pod-instellings die proc-blootstelling verswak | `procMount: Unmasked`, privileged workload patterns, breë host mounts |
| containerd / CRI-O under Kubernetes | Runtime-standaard | Pas gewoonlik OCI/runtime gemaskerde paaie toe tensy dit oorskryf word | direkte runtime-konfigurasiewijzigings, dieselfde Kubernetes-verswakkingstappe |

Gemaskerde paaie is gewoonlik standaard teenwoordig. Die hoof operasionele probleem is nie die afwesigheid in die runtime nie, maar doelbewuste ontmaskering of gasheer bind-mounts wat die beskerming ongedaan maak.
