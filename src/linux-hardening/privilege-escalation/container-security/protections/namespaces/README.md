# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces एक कर्नेल फीचर है जो कंटेनर को "अपनी मशीन" जैसा महसूस कराता है, जबकि वास्तव में यह सिर्फ एक होस्ट प्रोसेस ट्री है। ये नया कर्नेल नहीं बनाते और सब कुछ वर्चुअलाइज़ भी नहीं करते, पर ये कर्नेल को चयनित संसाधनों के अलग-अलग दृश्य अलग-अलग प्रक्रियाओं के समूहों को पेश करने की अनुमति देते हैं। यही कंटेनर भ्रम का मूल है: वर्कलोड को एक ऐसा फ़ाइलसिस्टम, process table, network stack, hostname, IPC resources, और user/group identity model दिखता है जो स्थानीय लगता है, भले ही नीचे का सिस्टम साझा किया गया हो।

इसी कारण से Namespaces वह पहला कॉन्सेप्ट है जिससे ज्यादा तर लोग कंटेनर कैसे काम करते हैं सीखते समय मिलते हैं। साथ ही, ये सबसे ज्यादा गलत समझे जाने वाले कॉन्सेप्ट्स में से भी एक हैं क्योंकि पाठक अक्सर मान लेते हैं कि "has namespaces" का मतलब है "सुरक्षित रूप से अलग किया गया है"। वास्तविकता में, एक namespace केवल उस संसाधन वर्ग को अलग करता है जिसके लिए वह डिज़ाइन किया गया है। एक प्रक्रिया के पास एक private PID namespace हो सकता है और फिर भी वह खतरनाक हो सकती है क्योंकि उसके पास एक writable host bind mount है। इसका private network namespace भी हो सकता है और फिर भी खतरा बना रहता है क्योंकि वह `CAP_SYS_ADMIN` रखती है और बिना seccomp के चलती है। Namespaces मौलिक हैं, पर ये अंतिम सीमा की सिर्फ एक परत हैं।

## Namespace Types

Linux कंटेनर आम तौर पर एक साथ कई namespace प्रकारों पर निर्भर करते हैं। The **mount namespace** प्रक्रिया को एक अलग mount table देता है और इसलिए नियंत्रित फ़ाइलसिस्टम दृश्य प्रदान करता है। The **PID namespace** प्रक्रिया दृश्यता और नंबरिंग बदलता है ताकि वर्कलोड अपनी खुद की process tree देख सके। The **network namespace** इंटरफेस, रूट, सॉकेट और फ़ायरवॉल स्थिति को पृथक करता है। The **IPC namespace** SysV IPC और POSIX message queues को पृथक करता है। The **UTS namespace** hostname और NIS domain name को पृथक करता है। The **user namespace** user और group IDs को रीमैप करता है ताकि कंटेनर के अंदर root होना जरूरी नहीं कि होस्ट पर root होना ही हो। The **cgroup namespace** दिखाई देने वाली cgroup hierarchy को वर्चुअलाइज़ करता है, और The **time namespace** नए कर्नेल्स में चयनित क्लॉक्स को वर्चुअलाइज़ करता है।

इनमें से प्रत्येक namespace अलग समस्या हल करता है। इसलिए व्यावहारिक कंटेनर सिक्योरिटी विश्लेषण अक्सर इस बात पर उतरता है कि कौन से namespaces isolated हैं और कौन से जानबूझकर होस्ट के साथ साझा किए गए हैं।

## Host Namespace Sharing

कई कंटेनर ब्रेकआउट्स कर्नेल vulnerability से शुरू नहीं होते। वे एक ऑपरेटर के द्वारा जानबूझकर isolation मॉडल कमजोर करने से शुरू होते हैं। उदाहरण `--pid=host`, `--network=host`, और `--userns=host` **Docker/Podman-style CLI flags** यहां होस्ट namespace साझा करने के ठोस उदाहरण के रूप में उपयोग किए गए हैं। अन्य runtimes यही विचार अलग तरीके से व्यक्त करते हैं। Kubernetes में equivalents आम तौर पर Pod सेटिंग्स के रूप में दिखते हैं जैसे `hostPID: true`, `hostNetwork: true`, या `hostIPC: true`। lower-level runtime stacks जैसे containerd या CRI-O में, वही व्यवहार अक्सर user-facing flag के बजाय जेनरेटेड OCI runtime configuration के माध्यम से प्राप्त किया जाता है। इन सभी मामलों में परिणाम समान होता है: वर्कलोड अब डिफ़ॉल्ट isolated namespace दृश्य प्राप्त नहीं करता।

इसलिए namespace रिव्यू कभी सिर्फ "प्रोसेस किसी namespace में है" पर ही नहीं रुकना चाहिए। महत्वपूर्ण सवाल यह है कि क्या namespace कंटेनर के लिए निजी है, sibling कंटेनरों के साथ साझा है, या सीधे होस्ट के साथ जुड़ा हुआ है। Kubernetes में यही विचार `hostPID`, `hostNetwork`, और `hostIPC` जैसे फ्लैग्स के साथ भी दिखाई देता है। प्लेटफॉर्म के बीच नाम बदल सकते हैं, लेकिन रिस्क पैटर्न एक जैसा रहता है: एक साझा होस्ट namespace कंटेनर की बाकी privileges और पहुँच में आने वाली होस्ट स्थिति को बहुत अधिक मायने रखवाती है।

## Inspection

सबसे सरल अवलोकन यह है:
```bash
ls -l /proc/self/ns
```
प्रत्येक प्रविष्टि एक symbolic link होती है जिसमें inode-जैसा identifier होता है। यदि दो processes एक ही namespace identifier की ओर संकेत करते हैं, तो वे उसी प्रकार के namespace में होते हैं। यह `/proc` को मशीन पर वर्तमान process की तुलना अन्य रुचिकर processes के साथ करने के लिए एक बहुत उपयोगी स्थान बनाता है।

These quick commands are often enough to start:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
इसके बाद अगला कदम container process की host या आसपास के processes के साथ तुलना करना और यह निर्धारित करना है कि कोई namespace वास्तव में निजी (private) है या नहीं।

### Host से Namespace Instances की गिनती

जब आपके पास पहले से host access है और आप यह जानना चाहते हैं कि किसी दिए गए प्रकार के कितने अलग-अलग namespaces मौजूद हैं, तो `/proc` एक त्वरित सूची देता है:
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
यदि आप यह पता लगाना चाहते हैं कि कौन सी प्रक्रियाएँ किसी विशिष्ट namespace पहचानकर्ता से संबंधित हैं, तो `readlink` की बजाय `ls -l` का उपयोग करें और लक्ष्य namespace संख्या के लिए `grep` करें:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
ये commands उपयोगी हैं क्योंकि ये आपको यह बताने में सक्षम बनाते हैं कि कोई host एक ही isolated workload चला रहा है, कई isolated workloads चला रहा है, या shared और private namespace instances का मिश्रण चला रहा है।

### लक्ष्य Namespace में प्रवेश

जब caller के पास पर्याप्त privilege हो, `nsenter` किसी अन्य process के namespace में जुड़ने का standard तरीका है:
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
इन रूपों को एक साथ सूचीबद्ध करने का मकसद यह नहीं है कि हर assessment को इनमें से सभी की आवश्यकता हो, बल्कि यह कि namespace-specific post-exploitation अक्सर बहुत आसान हो जाता है जब ऑपरेटर को सभी-namespace रूप केवल याद रखने की बजाय सटीक एंट्री syntax पता होता है।

## पृष्ठ

The following pages explain each namespace in more detail:

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

इन्हें पढ़ते समय, दो बातों का ध्यान रखें। सबसे पहले, प्रत्येक namespace केवल एक तरह का view अलग करता है। दूसरा, एक private namespace तब ही उपयोगी होता है जब बाकी अधिकार मॉडल उस अलगाव को सार्थक बनाते हों।

## रनटाइम डिफ़ॉल्ट

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से नए mount, PID, network, IPC, और UTS namespaces; user namespaces उपलब्ध हैं लेकिन standard rootful सेटअप में डिफ़ॉल्ट रूप से सक्षम नहीं होते | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | डिफ़ॉल्ट रूप से नए namespaces; rootless Podman स्वतः ही user namespace उपयोग करता है; cgroup namespace के डिफ़ॉल्ट cgroup वर्ज़न पर निर्भर करते हैं | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods डिफ़ॉल्ट रूप से host PID, network, या IPC साझा नहीं करते; Pod networking Pod के लिए private होता है, प्रत्येक व्यक्तिगत container के लिए नहीं; user namespaces सपोर्टेड क्लस्टरों पर `spec.hostUsers: false` के माध्यम से opt-in होते हैं | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | आमतौर पर Kubernetes Pod डिफ़ॉल्ट का पालन करते हैं | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

मुख्य पोर्टेबिलिटी नियम सरल है: host namespace sharing की **concept** रनटाइम्स में सामान्य है, लेकिन इसके **syntax** runtime-विशिष्ट होते हैं।
