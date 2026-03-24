# Gemaskerde Paaie

{{#include ../../../../banners/hacktricks-training.md}}

Gemaskerde paaie is runtime-beskermings wat besonders sensitiewe, na die kernel gerigte filesystem-ligginge vanaf die container verberg deur daaroor te bind-mount of dit andersins ontoeganklik te maak. Die doel is om te verhoed dat 'n workload direk met koppelvlakke omgaan wat gewone toepassings nie nodig het nie, veral binne procfs.

Dit is belangrik omdat baie container escapes en gasheer‑impakterende truuks begin deur spesiale lêers onder `/proc` of `/sys` te lees of te skryf. As daardie liggings gemasker is, verloor die aanvaller direkte toegang tot 'n nuttige deel van die kernel se beheeroppervlak selfs nadat code execution binne die container verkry is.

## Werking

Runtimes maskeer gewoonlik geselekteerde paaie soos:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Die presiese lys hang af van die runtime en die host‑konfigurasie. Die belangrike eienskap is dat die pad vanuit die container se oogpunt ontoeganklik of vervang raak, selfs al bestaan dit steeds op die host.

## Lab

Kontroleer die masked-path‑konfigurasie wat deur Docker blootgestel word:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Inspekteer die werklike mount-gedrag binne die workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Sekuriteitsimpak

Masking skep nie die hoof-isolasiegrens nie, maar dit verwyder verskeie hoë-waarde post-exploitation targets. Sonder masking kan 'n gekompromitteerde container dalk die kernelstatus inspekteer, sensitiewe proses- of sleutelinligting lees, of met procfs/sysfs-objekte interaksie hê wat nooit vir die toepassing sigbaar moes wees nie.

## Konfigurasiefoute

Die hooffout is die unmasking van wye klasse paaie vir gerief of debugging. In Podman kan dit verskyn as `--security-opt unmask=ALL` of targeted unmasking. In Kubernetes kan oormatige proc-blootstelling verskyn deur `procMount: Unmasked`. Nog 'n ernstige probleem is die blootstelling van die gasheer se `/proc` of `/sys` deur 'n bind mount, wat die idee van 'n verminderde container-uitsig heeltemal omseil.

## Misbruik

As masking swak of afwesig is, begin met die identifisering van watter sensitiewe procfs/sysfs-paaie direk bereikbaar is:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
As 'n veronderstelde gemaskerde pad toeganklik is, ondersoek dit noukeurig:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Wat hierdie opdragte kan openbaar:

- `/proc/timer_list` kan gasheer se timer- en skeduleerderdata openbaar. Dit is meestal 'n verkenningsprimitive, maar dit bevestig dat die container kerngerigte inligting kan lees wat normaalweg versteek is.
- `/proc/keys` is baie meer sensitief. Afhangend van die gasheerkonfigurasie, kan dit keyring-inskrywings, sleutelbeskrywings, en verhoudings tussen gasheerdienste wat die kernel keyring subsystem gebruik, openbaar.
- `/sys/firmware` help om opstartmodus, firmware-koppelvlakke en platformbesonderhede te identifiseer wat nuttig is vir host fingerprinting en om te bepaal of die workload gasheervlaktoestand sien.
- `/proc/config.gz` kan die lopende kernel-konfigurasie openbaar, wat waardevol is om openbare kernel exploit-voorvereistes te ooreenstem of om te verstaan waarom 'n spesifieke funksie bereikbaar is.
- `/proc/sched_debug` openbaar die skeduleerdertoestand en omseil dikwels die intuïtiewe verwagting dat die PID namespace ongerelateerde prosesinligting volledig behoort te verberg.

Interessante resultate sluit in direkte lees van daardie lêers, bewyse dat die data aan die gasheer behoort eerder as aan 'n beperkte container-uitsig, of toegang tot ander procfs/sysfs-liggings wat gewoonlik standaard gemasker is.

## Kontroles

Die doel van hierdie kontroles is om te bepaal watter paaie die runtime opsetlik verberg het en of die huidige workload steeds 'n verminderde kerngerigte lêerstelsel sien.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Wat hier interessant is:

- 'n Lang lys van gemaskeerde paaie is normaal in geharde runtimes.
- Die gebrek aan maskering van sensitiewe procfs-insette verdien nader ondersoek.
- As 'n sensitiewe pad toeganklik is en die container ook sterk capabilities of breë mounts het, is die blootstelling meer betekenisvol.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | By verstek geaktiveer | Docker definieer 'n standaard lys van gemaskeerde paaie | exposing host proc/sys mounts, `--privileged` |
| Podman | By verstek geaktiveer | Podman pas standaard gemaskeerde paaie toe tensy dit handmatig ontmasker word | `--security-opt unmask=ALL`, gerigte ontmaskering, `--privileged` |
| Kubernetes | Erf runtime-standaarde | Gebruik die onderliggende runtime se maskeringsgedrag, tensy Pod-instellings die proc-blootstelling verswak | `procMount: Unmasked`, patrone van privilegieerde werklading, breë host mounts |
| containerd / CRI-O under Kubernetes | Runtime-standaard | Gewoonlik pas OCI/runtime gemaskeerde paaie toe tensy dit oorskryf word | direkte runtime-konfigurasie-wijzigings, dieselfde Kubernetes-verswakkingspaaie |

Gemaskeerde paaie is gewoonlik standaard teenwoordig. Die primêre operasionele probleem is nie die afwesigheid in die runtime nie, maar doelbewuste ontmaskering of host bind mounts wat die beskerming tenietdoen.
{{#include ../../../../banners/hacktricks-training.md}}
