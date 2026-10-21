# Gemaskeerde paaie

{{#include ../../../../banners/hacktricks-training.md}}

Gemaskeerde paaie is runtime-beskermingsmaatreëls wat besonder sensitiewe lêerstelsel-liggings wat met die kernel verband hou, vir die container verberg deur dit met bind-mounts te oorskryf of dit andersins ontoeganklik te maak. Die OCI runtime-spesifikasie definieer `maskedPaths` as absolute paaie wat nie binne die container leesbaar mag wees nie. <sup>[[1]](#references)</sup>

Dit is belangrik omdat baie container escapes en tegnieke wat die host raak, begin deur spesiale lêers onder `/proc` of `/sys` te lees of te skryf. As daardie liggings gemasker is, verloor die aanvaller direkte toegang tot ’n nuttige deel van die kernel se beheeroppervlak, selfs nadat hulle kode binne die container uitgevoer het.

## Werking

Runtimes masker gewoonlik geselekteerde paaie soos:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Die presiese lys hang af van die runtime en die host-konfigurasie. Die belangrike eienskap is dat die pad vanuit die container se oogpunt ontoeganklik word of vervang word, al bestaan dit steeds op die host.

## Laboratorium

Inspekteer die masked-path-konfigurasie wat deur Docker blootgestel word:

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

Ondersoek die werklike mount-gedrag binne die workload:

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

'n Gelyste pad is nie noodwendig leesbaar nie: runc kan 'n lêer met 'n `/dev/null`-bind mount maskeer en 'n gids met 'n leë, leesalleen-tmpfs. Kontroleer die presiese mountpoint, nie net of `ls` slaag nie. <sup>[[4]](#references)</sup>

## Sekuriteitsimpak

Maskering skep nie die hoof-isolasiegrens nie, maar verwyder verskeie waardevolle post-exploitation-teikens. Sonder maskering kan 'n gekompromitteerde container moontlik kerntoestand inspekteer, sensitiewe proses- of sleuteldata lees, of met procfs/sysfs-objekte kommunikeer wat nooit vir die toepassing sigbaar moes gewees het nie.

## Foutiewe konfigurasies

Die grootste fout is om breë kategorieë paaie vir gerief of ontfouting te ontmasker. In Podman kan dit voorkom as `--security-opt unmask=ALL` of geteikende ontmaskering. <sup>[[2]](#references)</sup> In Kubernetes kan buitensporig breë proc-blootstelling voorkom via `procMount: Unmasked`; huidige Kubernetes vereis `spec.hostUsers: false` ('n user namespace) vir hierdie instelling, terwyl weergawes 1.12–1.29 nie daardie vereiste afgedwing het nie. <sup>[[3]](#references)</sup> Nog 'n ernstige probleem is om die gasheer se `/proc` of `/sys` via 'n bind mount bloot te stel, wat die idee van 'n beperkte container-aansig heeltemal omseil.

## Misbruik

As maskering swak of afwesig is, begin deur vas te stel watter sensitiewe procfs/sysfs-paaie direk bereikbaar is:

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

As ’n sogenaamd gemaskerde pad toeganklik is, ondersoek dit noukeurig:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

Wat hierdie opdragte kan onthul:

- `/proc/timer_list` kan timer- en skeduleerderdata van die gasheer blootstel. Dit is meestal ’n verkenningsmiddel, maar bevestig dat die container kernvlak-inligting kan lees wat gewoonlik versteek is.
- `/proc/keys` lys slegs metadata van sleutels waarvoor die leser **view**-toestemming het, onderhewig aan LSM-kontroles. Dit kan sleutelsoorte en beskrywings onthul, maar stort nie sleutelinhoud uit nie. <sup>[[6]](#references)</sup>
- `/sys/firmware` help om opstartmodus, firmware-koppelvlakke en platformbesonderhede te identifiseer wat nuttig is om die gasheer te vingerafdruk en te verstaan of die workload gasheervlaktoestand sien.
- `/proc/config.gz` kan die konfigurasie van die lopende kernel onthul, wat waardevol is om aan die vereistes van openbare kernel-exploits te voldoen of te verstaan waarom ’n spesifieke funksie bereikbaar is.
- `/proc/sched_debug` stel skeduleerdertoestand bloot en omseil dikwels die intuïtiewe verwagting dat die PID-namespace onverwante prosesinligting heeltemal behoort te versteek.

Interessante resultate sluit in direkte lees van daardie lêers, bewyse dat die data aan die gasheer behoort eerder as aan ’n beperkte container-aansig, of toegang tot ander procfs/sysfs-liggings wat gewoonlik by verstek gemasker word.

### Wedloop in mask-bron tydens container-opstart

In kwesbare runc-implementasies hang lêermaskers af van die inode van die container se `/dev/null`. ’n Aanvaller wat gelyktydige containers met gedeelde mounts kan reël, insluitend parallelle BuildKit-stappe, kan ’n wedloop veroorsaak en `/dev/null` verwyder voordat runc dit oor gemaskerde procfs-lêers bind. Die runtime behandel dan die ontbrekende **bron** asof ’n maskerbestemming ontbreek en slaan daardie lêermaskers stilweg oor. Die mislukking hang af van ’n wedloop tydens runtime-opstelling; die verwydering van `/dev/null` ná opstart maak nie ’n reeds geïnstalleerde masker ongedaan nie. <sup>[[4]](#references)</sup>

Vergelyk ná ’n beheerde toets die aangevraagde maskerlys met die presiese mountpunte binne die nuwe container. <sup>[[4]](#references)</sup> `findmnt -M` kontroleer die benoemde mountpunt eerder as om na ’n ouermount terug te val; as `findmnt` nie beskikbaar is nie, inspekteer `/proc/self/mountinfo`. <sup>[[5]](#references)</sup> ’n Suksesvolle `ls`-opdrag of ’n leë `cat` kan nie bewys dat die masker afwesig is nie. <sup>[[4]](#references)</sup>

Gebruik die [kontroles hieronder](#checks) om die aangevraagde maskers met presiese mounts in die nuwe container te vergelyk.

’n Oorgeslane lêermasker kan procfs-data blootstel as normale toestemmings en LSM-beleid dit toelaat. Dit maak `/proc/sys` **nie** op sigself skryfbaar nie: dit is ’n afsonderlike [read-only-path](read-only-paths.md)-beheer. Die afsonderlike `/dev/null`-simboliese skakel-vervanging wat ’n bind mount na ’n skryfbare procfs-teiken kan herlei, word behandel onder die [PID-namespace-runtime-wedloop](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs). <sup>[[4]](#references)</sup>

## Checks

Die doel van hierdie kontroles is om vas te stel watter paaie die runtime doelbewus versteek het en of die huidige workload steeds ’n verminderde kernvlak-lêerstelsel sien.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

Gebruik ’n presiese mount-kontrole, want ’n gemaskerde lêer kan steeds bestaan en ’n leesaksie kan ’n leë resultaat van `/dev/null` oplewer. ’n Ontbrekende mountpoint is ’n bevinding wat ondersoek moet word, nie op sigself ’n bewys van leesbare gasheerdata nie. <sup>[[4]](#references)[[5]](#references)</sup>

Wat hier interessant is:

- ’n Lang lys gemaskerde paaie is normaal in geharde runtimes.
- Ontbrekende maskering op sensitiewe procfs-inskrywings verdien nadere ondersoek.
- As ’n sensitiewe pad toeganklik is en die container ook sterk capabilities of breë mounts het, is die blootstelling belangriker.

## Runtime-verstekke

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | By verstek geaktiveer | Docker definieer ’n versteklys van gemaskerde paaie | blootstelling van host proc/sys-mounts, `--privileged` |
| Podman | By verstek geaktiveer | Podman pas verstek-gemaskerde paaie toe, tensy dit handmatig ontmasker word | `--security-opt unmask=ALL`, geteikende ontmaskering, `--privileged` |
| Kubernetes | Erf runtime-verstekke | Gebruik die onderliggende runtime se maskeringsgedrag, tensy Pod-instellings proc-blootstelling verswak | `procMount: Unmasked` (vereis `hostUsers: false` in huidige weergawes), patrone vir bevoorregte workloads, breë host-mounts |
| containerd / CRI-O onder Kubernetes | Runtime-verstek | Pas gewoonlik OCI/runtime-gemaskerde paaie toe, tensy dit oorskryf word | direkte veranderinge aan runtime-konfigurasie, dieselfde Kubernetes-verswakkingroetes |

Gemaskerde paaie is gewoonlik by verstek teenwoordig. Die grootste operasionele probleem is nie dat hulle in die runtime ontbreek nie, maar dat hulle doelbewus ontmasker word of dat host bind mounts die beskerming ongedaan maak.

## References

- [1] [Open Container Initiative - Linux-containerkonfigurasie: Gemaskerde paaie](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Podman-dokumentasie - sekuriteitsopsies vir `podman run`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Kubernetes-dokumentasie - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [runc-advies: wedlooptoestand in die mount-bron van gemaskerde paaie](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [findmnt(8)-handleiding](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [keyrings(7)-handleiding](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}
