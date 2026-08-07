# Gemaskerde paaie

{{#include ../../../../banners/hacktricks-training.md}}

Gemaskerde paaie is runtime-beskermings wat besonder sensitiewe kernel-gerigte lêerstelsel-liggings vir die container verberg deur daaroor te bind-mount of dit andersins ontoeganklik te maak. Die doel is om te voorkom dat 'n workload direk met interfaces kommunikeer wat gewone toepassings nie nodig het nie, veral binne procfs.

Dit is belangrik omdat baie container escapes en host-impaktruuks begin deur spesiale lêers onder `/proc` of `/sys` te lees of te skryf. As daardie liggings gemasker is, verloor die aanvaller direkte toegang tot 'n nuttige deel van die kernel se control surface, selfs nadat code execution binne die container verkry is.

## Werking

Runtimes mask dikwels geselekteerde paaie soos:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Die presiese lys hang van die runtime en host-konfigurasie af. Die belangrike eienskap is dat die path vanuit die container se oogpunt ontoeganklik word of vervang word, selfs al bestaan dit steeds op die host.

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

Maskering skep nie die hoof-isolasiegrens nie, maar dit verwyder verskeie waardevolle post-exploitation-teikens. Sonder maskering kan 'n gekompromitteerde container moontlik kerneltoestand inspekteer, sensitiewe proses- of sleutelingsinligting lees, of met procfs/sysfs-objekte kommunikeer wat nooit aan die toepassing sigbaar moes wees nie.

## Wankonfigurasies

Die belangrikste fout is om breë klasse paaie ter wille van gerief of debugging te ontmasker. In Podman kan dit as `--security-opt unmask=ALL` of geteikende ontmaskering verskyn. In Kubernetes kan oormatig breë proc-blootstelling via `procMount: Unmasked` verskyn. Nog 'n ernstige probleem is om die host se `/proc` of `/sys` deur middel van 'n bind mount bloot te stel, wat die idee van 'n verminderde container-aansig heeltemal omseil.

## Misbruik

As maskering swak of afwesig is, begin deur te identifiseer watter sensitiewe procfs/sysfs-paaie direk bereikbaar is:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
As ’n sogenaamd gemaskerde pad toeganklik is, inspekteer dit noukeurig:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Wat hierdie opdragte kan onthul:

- `/proc/timer_list` kan data oor die host se timers en scheduler blootlê. Dit is hoofsaaklik ’n reconnaissance primitive, maar bevestig dat die container kernel-gerigte inligting kan lees wat normaalweg versteek is.
- `/proc/keys` is baie meer sensitief. Afhangend van die host se konfigurasie, kan dit keyring-inskrywings, sleutelbeskrywings en verhoudings tussen host-dienste wat die kernel keyring-substelsel gebruik, onthul.
- `/sys/firmware` help om boot mode, firmware-koppelvlakke en platformbesonderhede te identifiseer wat nuttig is vir host fingerprinting en om te verstaan of die workload host-vlaktoestand sien.
- `/proc/config.gz` kan die lopende kernel-konfigurasie onthul, wat waardevol is om vereistes vir publieke kernel exploits te evalueer of te verstaan waarom ’n spesifieke feature bereikbaar is.
- `/proc/sched_debug` stel scheduler-toestand bloot en omseil dikwels die intuïtiewe verwagting dat die PID namespace onverwante prosesinligting heeltemal behoort te versteek.

Interessante resultate sluit direkte leesbewerkings van daardie lêers in, bewyse dat die data aan die host behoort eerder as aan ’n beperkte container-aansig, of toegang tot ander procfs/sysfs-liggings wat normaalweg by verstek gemasker word.

## Kontroles

Die doel van hierdie kontroles is om te bepaal watter paaie die runtime doelbewus versteek het en of die huidige workload steeds ’n verkleinde kernel-gerigte lêerstelsel sien.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Wat hier interessant is:

- 'n Lang masked-path-lys is normaal in geharde runtimes.
- Ontbrekende masking op sensitiewe procfs-inskrywings verdien nadere ondersoek.
- As 'n sensitiewe pad toeganklik is en die container ook sterk capabilities of breë mounts het, is die blootstelling belangriker.

## Runtime-verstekke

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | By verstek geaktiveer | Docker definieer 'n verstek masked-path-lys | blootstelling van host proc/sys-mounts, `--privileged` |
| Podman | By verstek geaktiveer | Podman pas verstek masked paths toe, tensy dit handmatig unmasked word | `--security-opt unmask=ALL`, geteikende unmasking, `--privileged` |
| Kubernetes | Erf runtime-verstekke | Gebruik die onderliggende runtime se masking-gedrag, tensy Pod-instellings proc-blootstelling verswak | `procMount: Unmasked`, bevoorregte workload-patrone, breë host-mounts |
| containerd / CRI-O onder Kubernetes | Runtime-verstek | Pas gewoonlik OCI/runtime masked paths toe, tensy dit oorskryf word | direkte runtime-konfigurasieveranderings, dieselfde Kubernetes-verswakkingspaaie |

Masked paths is gewoonlik by verstek teenwoordig. Die hoofoperasionele probleem is nie die afwesigheid daarvan in die runtime nie, maar doelbewuste unmasking of host bind-mounts wat die beskerming neutraliseer.

{{#include ../../../../banners/hacktricks-training.md}}
