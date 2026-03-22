# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

PID namespace नियंत्रित करता है कि processes को कैसे नंबर दिया जाता है और कौन‑सी processes दिखाई देती हैं। यही वजह है कि एक container का अपना PID 1 हो सकता है भले ही वह असली मशीन न हो। namespace के भीतर workload को ऐसा दिखता है जैसे एक local process tree हो। namespace के बाहर host अभी भी असली host PIDs और पूरी process landscape देखता रहता है।

सुरक्षा के नजरिए से, PID namespace इसलिए महत्वपूर्ण है क्योंकि process visibility कीमती है। एक बार जब कोई workload host processes देख सकता है, तो वह service names, command-line arguments, process arguments में पास किए गए secrets, `/proc` के माध्यम से environment-derived state, और संभावित namespace-entry targets का निरीक्षण कर सकता है। अगर वह सिर्फ इन processes को देखने से आगे जाकर कुछ कर सकता है — उदाहरण के लिए सही परिस्थितियों में signals भेजना या ptrace का इस्तेमाल करना — तो समस्या कहीं अधिक गंभीर हो जाती है।

## ऑपरेशन

एक नया PID namespace अपनी आंतरिक process numbering के साथ शुरू होता है। इसमें बनाया गया पहला process namespace के नजरिए से PID 1 बन जाता है, जिसका मतलब यह भी है कि उसे अनाथ बच्चों और signal व्यवहार के लिए विशेष init-like semantics मिलते हैं। यह उन कई container अजीबताओं को समझाता है जो init processes, zombie reaping, और क्यों कभी-कभी छोटे init wrappers containers में उपयोग किए जाते हैं के आसपास हैं।

महत्वपूर्ण सुरक्षा सबक यह है कि एक process अलग दिख सकता है क्योंकि वह केवल अपनी PID tree देखता है, लेकिन वह अलगाव जानबूझकर हटाया जा सकता है। Docker इसे `--pid=host` के माध्यम से expose करता है, जबकि Kubernetes इसे `hostPID: true` के माध्यम से करता है। एक बार container host PID namespace में जुड़ गया, workload सीधे host processes देखता है, और बाद के कई attack paths कहीं अधिक वास्तविक बन जाते हैं।

## लैब

PID namespace को मैन्युअली बनाने के लिए:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Shell अब एक निजी process दृश्य देखता है। `--mount-proc` flag महत्वपूर्ण है क्योंकि यह procfs instance को mount करता है जो नए PID namespace से मेल खाता है, जिससे अंदर से process list सुसंगत रहती है।

container व्यवहार की तुलना करने के लिए:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
The difference is immediate and easy to understand, which is why this is a good first lab for readers.

## Runtime Usage

Normal containers in Docker, Podman, containerd, and CRI-O get their own PID namespace. Kubernetes Pods usually also receive an isolated PID view unless the workload explicitly asks for host PID sharing. LXC/Incus environments rely on the same kernel primitive, though system-container use cases may expose more complicated process trees and encourage more debugging shortcuts.

The same rule applies everywhere: if the runtime chose not to isolate the PID namespace, that is a deliberate reduction in the container boundary.

## Misconfigurations

The canonical misconfiguration is host PID sharing. Teams often justify it for debugging, monitoring, or service-management convenience, but it should always be treated as a meaningful security exception. Even if the container has no immediate write primitive over host processes, visibility alone can reveal a lot about the system. Once capabilities such as `CAP_SYS_PTRACE` or useful procfs access are added, the risk expands significantly.

Another mistake is assuming that because the workload cannot kill or ptrace host processes by default, host PID sharing is therefore harmless. That conclusion ignores the value of enumeration, the availability of namespace-entry targets, and the way PID visibility combines with other weakened controls.

## Abuse

If the host PID namespace is shared, an attacker may inspect host processes, harvest process arguments, identify interesting services, locate candidate PIDs for `nsenter`, or combine process visibility with ptrace-related privilege to interfere with host or neighboring workloads. In some cases, simply seeing the right long-running process is enough to reshape the rest of the attack plan.

The first practical step is always to confirm that host processes are really visible:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
एक बार host PIDs दिखाई देने पर, process arguments और namespace-entry targets अक्सर सबसे उपयोगी जानकारी का स्रोत बन जाते हैं:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
यदि `nsenter` उपलब्ध है और पर्याप्त privilege मौजूद है, तो जाँचें कि क्या किसी दिखाई देने वाले host process का उपयोग namespace bridge के रूप में किया जा सकता है:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
भले ही प्रवेश अवरुद्ध हो, होस्ट PID साझा होना पहले से ही उपयोगी होता है क्योंकि इससे सेवा का लेआउट, रनटाइम घटक और अगले लक्ष्य बनाने के लिए संभावित privileged प्रक्रियाओं का पता चलता है।

होस्ट PID की दृश्यता file-descriptor के दुरुपयोग को भी अधिक वास्तविक बनाती है। यदि किसी privileged host process या पड़ोसी workload के पास कोई संवेदनशील फ़ाइल या socket खुला है, तो हमलावर संभवतः `/proc/<pid>/fd/` का निरीक्षण कर सकता है और उस handle का पुन: उपयोग कर सकता है — यह स्वामित्व, procfs mount options, और लक्ष्य सेवा मॉडल पर निर्भर करेगा।
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
ये कमांड उपयोगी हैं क्योंकि ये बताते हैं कि `hidepid=1` या `hidepid=2` क्रॉस-प्रोसेस विज़िबिलिटी को घटा रहे हैं या नहीं, और क्या स्पष्ट रूप से दिलचस्प डिस्क्रिप्टर्स जैसे खुले secret files, logs, या Unix sockets बिल्कुल भी दिखाई दे रहे हैं।

### पूर्ण उदाहरण: host PID + `nsenter`

जब प्रक्रिया के पास host namespaces में जुड़ने के लिए पर्याप्त privileges भी होते हैं, तब Host PID sharing सीधे host escape बन जाता है:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
यदि कमांड सफल हो जाता है, तो कंटेनर प्रक्रिया अब host mount, UTS, network, IPC, और PID namespaces में चल रही होगी। प्रभाव तुरंत host compromise है।

यहां तक कि जब `nsenter` स्वयं मौजूद न भी हो, तो वही परिणाम host binary के जरिए प्राप्त किया जा सकता है यदि host filesystem माउंट है:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### हाल के रनटाइम नोट्स

कुछ PID-namespace-संबंधी हमले पारंपरिक `hostPID: true` गलत कॉन्फ़िगरेशन नहीं हैं, बल्कि container setup के दौरान procfs protections के लागू होने के तरीके से जुड़े रनटाइम इम्प्लीमेंटेशन बग हैं।

#### `maskedPaths` का host procfs पर रेस

कमजोर `runc` संस्करणों में, attackers जो container image या `runc exec` workload को नियंत्रित कर सकते हैं, masking phase में race करके container-side `/dev/null` को उस तरह के symlink से बदल सकते हैं जो किसी संवेदनशील procfs path (जैसे `/proc/sys/kernel/core_pattern`) की ओर इशारा करता हो। यदि यह race सफल हो गया, तो masked-path bind mount गलत target पर लग सकता है और host-global procfs knobs को नए container के लिए expose कर सकता है।

उपयोगी समीक्षा कमांड:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
यह महत्वपूर्ण है क्योंकि अंतिम प्रभाव सीधे procfs exposure के समान हो सकता है: writable `core_pattern` या `sysrq-trigger`, जिसके बाद host code execution या denial of service हो सकता है।

#### Namespace injection with `insject`

Namespace injection tools such as `insject` दिखाते हैं कि PID-namespace interaction के लिए हमेशा process creation से पहले target namespace में pre-enter करना आवश्यक नहीं होता। एक helper बाद में attach कर सकता है, `setns()` का उपयोग कर सकता है, और target PID space में visibility बनाए रखते हुए execute कर सकता है:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
यह प्रकार की तकनीक मुख्य रूप से advanced debugging, offensive tooling, और post-exploitation workflows के लिए महत्वपूर्ण है, जहाँ namespace context को runtime के workload को initialize करने के बाद join करना पड़ता है।

### संबंधित FD Abuse Patterns

जब host PIDs दिखाई देते हैं तो दो patterns विशेष रूप से उल्लेखनीय हैं। पहले, एक privileged process एक संवेदनशील file descriptor को `execve()` के दौरान open रख सकता है क्योंकि इसे `O_CLOEXEC` के रूप में mark नहीं किया गया था। दूसरे, services Unix sockets के माध्यम से file descriptors को `SCM_RIGHTS` के जरिए पास कर सकती हैं। दोनों मामलों में रोचक ऑब्जेक्ट अब pathname नहीं है, बल्कि वह पहले से-open handle है जिसे lower-privilege process inherit या receive कर सकता है।

यह container काम में इसलिए महत्वपूर्ण है क्योंकि handle `docker.sock`, एक privileged log, एक host secret file, या किसी अन्य high-value object की ओर इशारा कर सकता है, भले ही path स्वयं container filesystem से सीधे पहुंच योग्य न हो।

## जांच

इन commands का उद्देश्य यह निर्धारित करना है कि process के पास एक private PID view है या क्या यह पहले से ही कहीं अधिक व्यापक process landscape को enumerate कर सकता है।
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
What is interesting here:

- यदि प्रक्रिया सूची में स्पष्ट होस्ट सेवाएँ नज़र आती हैं, तो host PID sharing शायद पहले से ही प्रभाव में है।
- सिर्फ़ एक छोटा container-local tree दिखना सामान्य बेसलाइन है; `systemd`, `dockerd`, या असंबंधित daemons दिखना सामान्य नहीं है।
- एक बार host PIDs दिखाई दें, तो यहाँ तक कि read-only प्रक्रिया जानकारी भी उपयोगी सूचना-संग्रह (reconnaissance) बन जाती है।

यदि आप पता लगाते हैं कि कोई container host PID sharing के साथ चल रहा है, तो इसे केवल सौंदर्यात्मक फर्क मत समझिए। यह workload द्वारा देखे और संभावित रूप से प्रभावित किए जाने योग्य चीज़ों में एक बड़ा परिवर्तन है।
{{#include ../../../../../banners/hacktricks-training.md}}
