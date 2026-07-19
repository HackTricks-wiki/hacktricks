# Gemaskerde paaie

{{#include ../../../../banners/hacktricks-training.md}}

Gemaskerde paaie is runtime-beskermings wat besonder sensitiewe kernel-gerigte lêerstelsel-liggings vir die container verberg deur dit met bind-mounts te oorskryf of dit andersins ontoeganklik te maak. Die doel is om te voorkom dat 'n workload direk met koppelvlakke interaksie het wat gewone toepassings nie nodig het nie, veral binne procfs.

Dit is belangrik omdat baie container escapes en tegnieke wat die host beïnvloed, begin deur spesiale lêers onder `/proc` of `/sys` te lees of te skryf. As daardie liggings gemasker is, verloor die aanvaller direkte toegang tot 'n nuttige deel van die kernel se beheeroppervlak, selfs nadat kode-uitvoering binne die container verkry is.

## Werking

Runtimes mask algemeen geselekteerde paaie soos:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Die presiese lys hang van die runtime en host-konfigurasie af. Die belangrike eienskap is dat die pad vanuit die container se oogpunt ontoeganklik word of vervang word, selfs al bestaan dit steeds op die host.

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
## Veiligheidsimpak

Masking skep nie die hoof-isolasiegrens nie, maar dit verwyder verskeie waardevolle post-exploitation-teikens. Sonder masking kan 'n compromised container moontlik kernel state inspekteer, sensitiewe process- of sleutel-inligting lees, of met procfs/sysfs-objekte interaksie hê wat nooit aan die application sigbaar moes gewees het nie.

## Misconfigurations

Die hoofprobleem is die unmasking van breë klasse paths vir gerief of debugging. In Podman kan dit as `--security-opt unmask=ALL` of geteikende unmasking verskyn. In Kubernetes kan buitensporige proc-blootstelling deur `procMount: Unmasked` verskyn. Nog 'n ernstige probleem is om die host se `/proc` of `/sys` deur middel van 'n bind mount bloot te stel, wat die idee van 'n beperkte container view heeltemal omseil.

## Misbruik

As masking swak of afwesig is, begin deur vas te stel watter sensitiewe procfs/sysfs-paths direk bereikbaar is:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Indien ’n sogenaamd gemaskerde pad toeganklik is, inspekteer dit noukeurig:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Wat hierdie commands kan onthul:

- `/proc/timer_list` kan host-timer- en scheduler-data blootstel. Dit is hoofsaaklik 'n reconnaissance primitive, maar dit bevestig dat die container kernel-gerigte inligting kan lees wat normaalweg versteek is.
- `/proc/keys` is baie meer sensitief. Afhangend van die host-konfigurasie kan dit keyring-inskrywings, sleutelbeskrywings en verhoudings tussen host-dienste wat die kernel keyring-substelsel gebruik, onthul.
- `/sys/firmware` help om boot mode, firmware-koppelvlakke en platformbesonderhede te identifiseer wat nuttig is vir host-fingerprinting en om te verstaan of die workload host-vlaktoestand sien.
- `/proc/config.gz` kan die lopende kernel-konfigurasie onthul, wat waardevol is om publieke kernel exploit-voorvereistes te pas of te verstaan waarom 'n spesifieke feature bereikbaar is.
- `/proc/sched_debug` stel scheduler-toestand bloot en omseil dikwels die intuïtiewe verwagting dat die PID namespace onverwante prosesinligting volledig behoort te verberg.

Interessante resultate sluit direkte leesaksies vanaf daardie lêers in, bewys dat die data aan die host behoort eerder as aan 'n beperkte container-view, of toegang tot ander procfs/sysfs-liggings wat normaalweg by verstek gemasker word.

## Kontroles

Die doel van hierdie kontroles is om te bepaal watter paths die runtime doelbewus versteek het en of die huidige workload steeds 'n verminderde kernel-gerigte lêerstelsel sien.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Wat hier interessant is:

- 'n Lang masked-path-lys is normaal in hardened runtimes.
- Ontbrekende masking op sensitiewe procfs-inskrywings verdien nadere inspeksie.
- As 'n sensitiewe path toeganklik is en die container ook sterk capabilities of breë mounts het, is die blootstelling belangriker.

## Runtime-verstekke

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | By verstek geaktiveer | Docker definieer 'n verstek masked-path-lys | exposing host proc/sys mounts, `--privileged` |
| Podman | By verstek geaktiveer | Podman pas verstek masked paths toe, tensy dit handmatig unmasked word | `--security-opt unmask=ALL`, targeted unmasking, `--privileged` |
| Kubernetes | Erf runtime-verstekke | Gebruik die onderliggende runtime se masking-gedrag, tensy Pod-instellings proc-blootstelling verswak | `procMount: Unmasked`, privileged workload patterns, breë host mounts |
| containerd / CRI-O under Kubernetes | Runtime-verstek | Pas gewoonlik OCI/runtime masked paths toe, tensy dit oorskryf word | direkte runtime-configurasiestygings, dieselfde Kubernetes-verswakkingpaaie |

Masked paths is gewoonlik by verstek teenwoordig. Die belangrikste operasionele probleem is nie afwesigheid uit die runtime nie, maar doelbewuste unmasking of host bind mounts wat die beskerming neutraliseer.
{{#include ../../../../banners/hacktricks-training.md}}
