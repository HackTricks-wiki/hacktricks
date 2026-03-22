# नेमस्पेसेस

{{#include ../../../../../banners/hacktricks-training.md}}

नेमस्पेसेस वही kernel फीचर हैं जो किसी container को "अपनी मशीन" जैसा महसूस कराते हैं, जबकि असल में वह सिर्फ host process tree ही होता है। ये नया kernel नहीं बनाते और सब कुछ virtualize भी नहीं करते, लेकिन ये kernel को चुने हुए resources के अलग-अलग views अलग-अलग process समूहों को दिखाने की अनुमति देते हैं। यही container illusion का मूल है: workload को एक filesystem, process table, network stack, hostname, IPC resources, और user/group identity model लोकल दिखाई देते हैं, भले ही underlying सिस्टम साझा हो।

इसी कारण नेमस्पेसेस वह पहला कॉन्सेप्ट है जिससे ज्यादातर लोग containers कैसे काम करते हैं यह सीखते समय मिलते हैं। साथ ही, इन्हें अक्सर गलत समझा भी जाता है क्योंकि पाठक अक्सर मान लेते हैं कि "has namespaces" का मतलब "सुरक्षित रूप से isolated है"। वास्तविकता में, एक नेमस्पेस केवल उस विशेष संसाधन वर्ग को अलग करता है जिसके लिए वह डिजाइन किया गया था। एक process के पास private PID namespace हो सकता है और फिर भी वह खतरनाक हो सकता है क्योंकि उसके पास writable host bind mount है। उसके पास private network namespace हो सकता है और फिर भी वह खतरनाक हो सकता है क्योंकि उसने `CAP_SYS_ADMIN` रखा हुआ है और वह seccomp के बिना चल रहा है। नेमस्पेसेस आधारभूत हैं, लेकिन वे अंतिम boundary में सिर्फ एक ही परत हैं।

## नेमस्पेस प्रकार

Linux containers आमतौर पर एक साथ कई नेमस्पेस प्रकारों पर निर्भर करते हैं। **mount namespace** process को अलग mount table देता है और इसलिए एक नियंत्रित filesystem view देता है। **PID namespace** process visibility और numbering बदलता है ताकि workload अपना खुद का process tree देखे। **network namespace** interfaces, routes, sockets, और firewall state को अलग करता है। **IPC namespace** SysV IPC और POSIX message queues को अलग करता है। **UTS namespace** hostname और NIS domain name को अलग करता है। **user namespace** user और group IDs को remap करता है ताकि container के अंदर root होना जरूरी नहीं कि host पर root हो। **cgroup namespace** दिखाई देने वाली cgroup hierarchy को virtualize करता है, और नए kernels में **time namespace** चुने हुए clocks को virtualize करता है।

इनमें से हर नेमस्पेस एक अलग समस्या हल करता है। इसलिए practical container security analysis अक्सर इस पर आकर ठहरती है कि कौन से नेमस्पेसेस isolated हैं और कौन से जानबूझकर host के साथ shared किए गए हैं।

## होस्ट नेमस्पेस शेयरिंग

कई container breakouts kernel vulnerability के साथ शुरू नहीं होते। वे एक ऑपरेटर के जानबूझकर isolation model को कमजोर करने से शुरू होते हैं। उदाहरण `--pid=host`, `--network=host`, और `--userns=host` **Docker/Podman-style CLI flags** हैं जिन्हें यहाँ होस्ट नेमस्पेस शेयरिंग के ठोस उदाहरणों के रूप में उपयोग किया गया है। अन्य runtimes यही विचार अलग तरीके से व्यक्त करते हैं। Kubernetes में equivalents आमतौर पर Pod settings जैसे `hostPID: true`, `hostNetwork: true`, या `hostIPC: true` के रूप में दिखाई देते हैं। lower-level runtime stacks जैसे containerd या CRI-O में, समान व्यवहार अक्सर generated OCI runtime configuration के माध्यम से पहुँचाया जाता है बजाय किसी user-facing flag के। इन सभी मामलों में परिणाम समान होता है: workload अब default isolated namespace view प्राप्त नहीं करता।

इसीलिए नेमस्पेस समीक्षा कभी भी "process किसी नेमस्पेस में है" पर नहीं रुकनी चाहिए। महत्वपूर्ण प्रश्न यह है कि नेमस्पेस container के लिए private है, sibling containers के साथ साझा है, या सीधे host से जुड़ा हुआ है। Kubernetes में यही विचार `hostPID`, `hostNetwork`, और `hostIPC` जैसे flags के साथ दिखाई देता है। प्लेटफ़ॉर्म के बीच नाम बदलते हैं, लेकिन रिस्क पैटर्न वही रहता है: एक shared host namespace container की बची हुई privileges और accessible host state को बहुत अधिक मायने देता है।

## निरीक्षण

सबसे सरल रूपरेखा है:
```bash
ls -l /proc/self/ns
```
प्रत्येक एंट्री एक symbolic link होती है जिसमें एक inode-like identifier होता है। यदि दो processes एक ही namespace identifier की ओर इशारा करते हैं, तो वे उसी प्रकार के namespace में होते हैं। इससे `/proc` वर्तमान process की तुलना मशीन पर अन्य दिलचस्प processes से करने के लिए एक बहुत उपयोगी जगह बन जाता है।

ये quick commands अक्सर शुरू करने के लिए काफी होते हैं:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
इसके बाद, अगला कदम container process की host या पड़ोसी processes के साथ तुलना करना और यह निर्धारित करना है कि कोई namespace वास्तव में private है या नहीं।

### Host से Namespace Instances की गिनती

यदि आपके पास पहले से host access है और आप यह समझना चाहते हैं कि किसी दिए गए type के कितने distinct namespaces मौजूद हैं, तो `/proc` एक त्वरित इन्वेंटरी देता है:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
यदि आप यह पता लगाना चाहते हैं कि कौन से processes किसी विशेष namespace identifier से संबंधित हैं, तो `readlink` की बजाय `ls -l` का उपयोग करें और लक्ष्य namespace संख्या के लिए `grep` करें:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
ये कमांड उपयोगी हैं क्योंकि वे आपको यह बता सकते हैं कि कोई host एक isolated workload चला रहा है, कई isolated workloads चला रहा है, या shared और private namespace instances का मिश्रण चला रहा है।

### लक्ष्य Namespace में प्रवेश

जब caller के पास पर्याप्त privilege होता है, `nsenter` किसी अन्य process के namespace में शामिल होने का मानक तरीका है:
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
इन रूपों को एक साथ सूचीबद्ध करने का उद्देश्य यह नहीं है कि हर assessment को इन सबकी आवश्यकता हो, बल्कि namespace-specific post-exploitation अक्सर बहुत आसान हो जाता है जब operator सटीक entry syntax जानता है बजाय केवल all-namespaces फ़ॉर्म को याद रखने के।

## Pages

निम्नलिखित पृष्ठ प्रत्येक namespace को और अधिक विस्तार से समझाते हैं:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

जब आप इन्हें पढ़ें, तो दो बातें ध्यान में रखें। पहली, प्रत्येक namespace केवल एक प्रकार का view अलग करता है। दूसरी, एक private namespace तभी उपयोगी है जब privilege मॉडल का बाकी हिस्सा उस अलगाव को अभी भी meaningful बनाए रखता हो।

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | New mount, PID, network, IPC, and UTS namespaces by default; user namespaces are available but not enabled by default in standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | New namespaces by default; rootless Podman automatically uses a user namespace; cgroup namespace defaults depend on cgroup version | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Usually follow Kubernetes Pod defaults | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

मुख्य पोर्टेबिलिटी नियम सरल है: host namespace sharing की **concept** runtimes भर में सामान्य है, लेकिन **syntax** runtime-specific होता है।
{{#include ../../../../../banners/hacktricks-training.md}}
