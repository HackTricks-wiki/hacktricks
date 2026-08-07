# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces kernel का वह feature हैं जो container को "अपनी मशीन" जैसा महसूस कराता है, हालांकि वास्तव में वह केवल host process tree होता है। वे नया kernel create नहीं करते और न ही हर चीज़ को virtualize करते हैं, लेकिन वे kernel को अलग-अलग process groups के सामने चुने हुए resources के अलग-अलग views प्रस्तुत करने देते हैं। यही container illusion का आधार है: workload को एक filesystem, process table, network stack, hostname, IPC resources और user/group identity model स्थानीय दिखाई देते हैं, जबकि underlying system shared रहता है।

इसी कारण containers के काम करने का तरीका सीखते समय अधिकांश लोग सबसे पहले namespaces की concept से परिचित होते हैं। साथ ही, यह सबसे अधिक गलत समझी जाने वाली concepts में से एक है, क्योंकि readers अक्सर मान लेते हैं कि "has namespaces" का अर्थ "is safely isolated" है। वास्तव में, namespace केवल उसी specific class of resources को isolate करता है जिसके लिए उसे design किया गया है। किसी process के पास private PID namespace हो सकता है और फिर भी वह खतरनाक हो सकता है, क्योंकि उसके पास writable host bind mount है। उसके पास private network namespace हो सकता है और फिर भी वह खतरनाक हो सकता है, क्योंकि उसके पास `CAP_SYS_ADMIN` मौजूद है और वह seccomp के बिना चल रहा है। Namespaces foundational हैं, लेकिन final boundary में वे केवल एक layer हैं।

## Namespace Types

Linux containers आमतौर पर एक ही समय में कई namespace types पर निर्भर करते हैं। **mount namespace** process को एक अलग mount table देता है और इसलिए एक controlled filesystem view देता है। **PID namespace** process visibility और numbering को बदलता है, ताकि workload को अपना process tree दिखाई दे। **network namespace** interfaces, routes, sockets और firewall state को isolate करता है। **IPC namespace** SysV IPC और POSIX message queues को isolate करता है। **UTS namespace** hostname और NIS domain name को isolate करता है। **user namespace** user और group IDs को remap करता है, ताकि container के अंदर root का अर्थ आवश्यक रूप से host पर root न हो। **cgroup namespace** दिखाई देने वाली cgroup hierarchy को virtualize करता है, और नए kernels में **time namespace** चुनी हुई clocks को virtualize करता है।

इनमें से प्रत्येक namespace एक अलग समस्या हल करता है। इसी कारण practical container security analysis अक्सर यह जाँचने पर निर्भर करता है कि **कौन से namespaces isolated हैं** और **कौन से namespaces को जानबूझकर host के साथ shared किया गया है**।

## Host Namespace Sharing

कई container breakouts kernel vulnerability से शुरू नहीं होते। वे operator द्वारा isolation model को जानबूझकर कमजोर करने से शुरू होते हैं। `--pid=host`, `--network=host`, और `--userns=host` उदाहरण के रूप में दिए गए **Docker/Podman-style CLI flags** हैं, जो host namespace sharing को दर्शाते हैं। अन्य runtimes इसी idea को अलग तरीके से व्यक्त करते हैं। Kubernetes में इनके equivalents आमतौर पर Pod settings के रूप में दिखाई देते हैं, जैसे `hostPID: true`, `hostNetwork: true`, या `hostIPC: true`। containerd या CRI-O जैसे lower-level runtime stacks में यही behavior अक्सर user-facing flag के बजाय generated OCI runtime configuration के माध्यम से प्राप्त किया जाता है। इन सभी मामलों में result समान होता है: workload को default isolated namespace view नहीं मिलता।

इसीलिए namespace reviews को कभी भी केवल इस बात पर नहीं रुकना चाहिए कि "the process is in some namespace"। महत्वपूर्ण प्रश्न यह है कि namespace container के लिए private है, sibling containers के साथ shared है, या सीधे host से joined है। Kubernetes में यही idea `hostPID`, `hostNetwork`, और `hostIPC` जैसे flags के साथ दिखाई देता है। Platforms के बीच names बदल जाते हैं, लेकिन risk pattern समान रहता है: shared host namespace container के बचे हुए privileges और reachable host state को कहीं अधिक meaningful बना देता है।

## Inspection

सबसे सरल overview है:
```bash
ls -l /proc/self/ns
```
हर entry एक inode-जैसे identifier वाला symbolic link है। यदि दो processes एक ही namespace identifier की ओर point करते हैं, तो वे उस type के एक ही namespace में होते हैं। इससे `/proc` मशीन पर current process की तुलना अन्य interesting processes से करने के लिए एक बहुत उपयोगी स्थान बन जाता है।

शुरुआत करने के लिए ये quick commands अक्सर पर्याप्त होते हैं:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
वहां से, अगला चरण container process की तुलना host या neighboring processes से करना और यह निर्धारित करना है कि कोई namespace वास्तव में private है या नहीं।

### Host से Namespace Instances की गणना

जब आपके पास पहले से host access हो और आप यह समझना चाहते हों कि किसी दिए गए type के कितने अलग-अलग namespaces मौजूद हैं, तो `/proc` एक त्वरित inventory प्रदान करता है:
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
यदि आप यह पता लगाना चाहते हैं कि कौन-सी processes एक विशिष्ट namespace identifier से संबंधित हैं, तो `readlink` से `ls -l` पर switch करें और target namespace number के लिए grep करें:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
ये commands उपयोगी हैं क्योंकि इनके माध्यम से आप पता लगा सकते हैं कि कोई host एक isolated workload, कई isolated workloads, या shared और private namespace instances का मिश्रण चला रहा है।

### किसी Target Namespace में प्रवेश करना

जब caller के पास पर्याप्त privilege हो, तो `nsenter` किसी अन्य process के namespace में शामिल होने का standard तरीका है:
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
इन forms को एक साथ सूचीबद्ध करने का उद्देश्य यह नहीं है कि हर assessment में इन सभी की आवश्यकता होती है, बल्कि यह है कि namespace-specific post-exploitation अक्सर तब बहुत आसान हो जाता है जब operator को केवल all-namespaces form याद रखने के बजाय exact entry syntax पता हो।

## Pages

निम्नलिखित pages प्रत्येक namespace को अधिक विस्तार से समझाते हैं:

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

इन्हें पढ़ते समय दो बातों को ध्यान में रखें। पहली, प्रत्येक namespace केवल एक प्रकार के view को isolate करता है। दूसरी, private namespace तभी उपयोगी होता है जब privilege model का बाकी हिस्सा उस isolation को meaningful बनाए रखता हो।

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से नए mount, PID, network, IPC और UTS namespaces; user namespaces उपलब्ध हैं, लेकिन standard rootful setups में डिफ़ॉल्ट रूप से enabled नहीं होते | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | डिफ़ॉल्ट रूप से नए namespaces; rootless Podman अपने-आप user namespace का उपयोग करता है; cgroup namespace के defaults cgroup version पर निर्भर करते हैं | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods डिफ़ॉल्ट रूप से host PID, network या IPC share **नहीं** करते; Pod networking पूरे Pod के लिए private होती है, प्रत्येक individual container के लिए नहीं; supported clusters में `spec.hostUsers: false` के माध्यम से user namespaces opt-in किए जाते हैं | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / user-namespace opt-in को छोड़ देना, privileged workload settings |
| containerd / CRI-O under Kubernetes | आमतौर पर Kubernetes Pod defaults का पालन करते हैं | Kubernetes row के समान; direct CRI/OCI specs host namespace joins का अनुरोध भी कर सकते हैं |

मुख्य portability rule सरल है: host namespace sharing का **concept** सभी runtimes में सामान्य है, लेकिन इसका **syntax** runtime-specific होता है।

{{#include ../../../../../banners/hacktricks-training.md}}
