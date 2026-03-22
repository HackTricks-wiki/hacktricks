# Gemaskerde Paaie

{{#include ../../../../banners/hacktricks-training.md}}

Gemaskerde paaie is runtime-beskermings wat besonders sensitiewe, kernel-facing lêerstelsel-liggings vir die container verberg deur daaroor te bind-mount of dit andersins ontoeganklik te maak. Die doel is om te verhoed dat 'n workload direk met interfaces interaksie het wat gewone toepassings nie nodig het nie, veral binne procfs.

Dit is belangrik omdat baie container escapes en host-impacting tricks begin deur spesiale lêers onder `/proc` of `/sys` te lees of te skryf. As daardie liggings gemasker is, verloor die aanvaller direkte toegang tot 'n nuttige deel van die kernel control surface selfs nadat hy kode-uitvoering binne die container verkry het.

## Werking

Runtimes maskeer gewoonlik sekere paaie soos:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Die presiese lys hang af van die runtime en die host-konfigurasie. Die belangrike eienskap is dat die pad vanaf die container se hoekpunt ontoeganklik of vervang word, selfs al bestaan dit steeds op die host.

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

Maskering skep nie die hoof-isolasiegrens nie, maar dit verwyder verskeie hoëwaarde post-exploitation-teikens. Sonder maskering kan 'n gekompromitteerde container die kerneltoestand inspekteer, sensitiewe proses- of sleutelinligting lees, of met procfs/sysfs-objekte interaksie hê wat nooit vir die toepassing sigbaar moes wees nie.

## Konfigurasiefoute

Die hooffout is die ontmaskering van wye klasse paadjies vir gerief of foutsporing. In Podman kan dit verskyn as `--security-opt unmask=ALL` of geteikende ontmaskering. In Kubernetes kan te breë proc-blootstelling blyk deur `procMount: Unmasked`. Nog 'n ernstige probleem is om die host `/proc` of `/sys` deur 'n bind mount bloot te stel, wat die idee van 'n verminderde container-uitsig heeltemal omseil.

## Misbruik

As maskering swak of afwesig is, begin deur te identifiseer watter sensitiewe procfs/sysfs-paadjies direk bereikbaar is:
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
Wat hierdie opdragte kan onthul:

- `/proc/timer_list` kan gasheer se timer- en skeduleerderdata openbaar. Dit is hoofsaaklik 'n verkennings-primitive, maar dit bevestig dat die container kerngerigte inligting kan lees wat gewoonlik versteek is.
- `/proc/keys` is baie meer sensitief. Afhangend van die gasheer se konfigurasie, kan dit keyring-inskrywings, sleutelbeskrywings, en verhoudings tussen gasheerdienste wat die kernel keyring-subsisteem gebruik, openbaar.
- `/sys/firmware` help om boot-modus, firmware-koppelvlakke, en platformbesonderhede te identifiseer wat nuttig is vir gasheer-fingerafdrukke en om te verstaan of die werklading gasheervlaktoestand sien.
- `/proc/config.gz` kan die lopende kernelkonfigurasie openbaar, wat waardevol is vir die vergelyking met public kernel exploit prerequisites of om te verstaan waarom 'n spesifieke funksie bereikbaar is.
- `/proc/sched_debug` openbaar die skeduleerdertoestand en omseil dikwels die intuïtiewe verwagting dat die PID namespace ongekoppelde prosesinligting heeltemal moet verberg.

Interessante resultate sluit in direkte lees van daardie lêers, bewyse dat die data aan die gasheer behoort eerder as aan 'n beperkte container-uitsig, of toegang tot ander procfs/sysfs-ligginge wat gewoonlik standaard gemaskeer is.

## Kontroles

Die doel van hierdie kontroles is om te bepaal watter paaie die runtime doelbewus verberg het en of die huidige werkbelasting nog 'n verminderde kerngerigte lêerstelsel sien.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Wat hier interessant is:

- 'n lang masked-path list is normaal in geharde runtimes.
- Gebrek aan masking op sensitiewe procfs-inskrywings verdien nouer ondersoek.
- As 'n sensitiewe pad toeganklik is en die container ook sterk capabilities of breë mounts het, maak die blootstelling meer saak.

## Runtime-standaarde

| Runtime / platform | Standaardtoestand | Standaardgedrag | Algemene manuele verzwakking |
| --- | --- | --- | --- |
| Docker Engine | By verstek aangeskakel | Docker definieer 'n standaard masked-path list | blootstelling van host proc/sys mounts, `--privileged` |
| Podman | By verstek aangeskakel | Podman pas standaard masked paths toe tensy dit handmatig unmask gemaak word | `--security-opt unmask=ALL`, gerigte unmasking, `--privileged` |
| Kubernetes | Erf runtime-standaarde | Gebruik die onderliggende runtime se masking-gedrag tensy Pod-instellings die proc blootstelling verzwak | `procMount: Unmasked`, privileged werkbelastingpatrone, breë host mounts |
| containerd / CRI-O under Kubernetes | Runtime-standaard | Pas gewoonlik OCI/runtime masked paths toe tensy oorskryf | direkte runtime-konfigurasiewijzigings, dieselfde Kubernetes-verzwakkingspaaie |

Masked paths is gewoonlik standaard teenwoordig. Die hoof operasionele probleem is nie die afwesigheid by die runtime nie, maar doelbewuste unmasking of host bind mounts wat die beskerming ongedaan maak.
{{#include ../../../../banners/hacktricks-training.md}}
