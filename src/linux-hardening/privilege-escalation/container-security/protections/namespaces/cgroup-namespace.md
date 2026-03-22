# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## सारांश

cgroup namespace, cgroups की जगह नहीं लेता और स्वयं संसाधन सीमाएँ लागू नहीं करता। इसके बजाय, यह **कैसे cgroup hierarchy दिखाई देती है** को बदला करता है ताकि process को दिखाई देने वाली जानकारी वर्चुअलाइज़ हो जाए। दूसरे शब्दों में, यह दिखाई देने वाली cgroup path जानकारी को वर्चुअलाइज़ करके workload को पूरा host hierarchy दिखाने के बजाय एक container-स्कोप्ड दृश्य देता है।

यह मुख्यतः एक दृश्यता और सूचना-घटाने (information-reduction) फीचर है। यह environment को self-contained दिखाने में मदद करता है और host के cgroup layout के बारे में कम जानकारी उजागर करता है। यह मामूली लग सकता है, पर यह महत्वपूर्ण है क्योंकि host संरचना में अनावश्यक दृश्यता reconnaissance में मदद कर सकती है और environment-निर्भर exploit chains को सरल बना सकती है।

## कार्यप्रणाली

यदि private cgroup namespace न हो, तो एक process host-relative cgroup paths देख सकता है जो मशीन की hierarchy का अधिक हिस्सा उजागर करते हैं जितना उपयोगी हो। एक private cgroup namespace के साथ, `/proc/self/cgroup` और संबंधित अवलोकन container के अपने दृश्य के लिए अधिक localized हो जाते हैं। यह विशेष रूप से आधुनिक runtime stacks में मददगार है जो चाहते हैं कि workload को एक साफ़, कम host-प्रकटीकरण वाला environment दिखे।

## लैब

आप निम्न के साथ cgroup namespace का निरीक्षण कर सकते हैं:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
और रनटाइम व्यवहार की तुलना करें:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
The change is mostly about what the process can see, not about whether cgroup enforcement exists.

## सुरक्षा प्रभाव

cgroup namespace को सबसे अच्छा **visibility-hardening layer** के रूप में समझा जा सकता है। यह अपने आप में breakout को तब नहीं रोकेगा जब container के पास writable cgroup mounts, broad capabilities, या एक खतरनाक cgroup v1 environment हो। हालाँकि, अगर host cgroup namespace साझा किया गया है, तो प्रक्रिया सिस्टम के संगठन के बारे में अधिक जानती है और host-relative cgroup paths को अन्य observations के साथ मिलान करना उसके लिए आसान हो सकता है।

तो जबकि यह namespace आमतौर पर container breakout writeups का मुख्य पात्र नहीं होता, फिर भी यह host information leakage को कम करने के व्यापक उद्देश्य में योगदान देता है।

## दुरुपयोग

तुरंत मिलने वाला दुरुपयोग मूल्य ज्यादातर reconnaissance है। अगर host cgroup namespace साझा है, तो दिखाई देने वाले paths की तुलना करें और host-revealing hierarchy विवरणों की तलाश करें:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
यदि writable cgroup paths भी प्रकट हैं, तो उस दृश्यता को खतरनाक legacy इंटरफेस की खोज के साथ मिलाएँ:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
namespace स्वयं अक्सर तुरंत escape नहीं देता, पर यह अक्सर cgroup-based abuse primitives का परीक्षण करने से पहले environment को map करना आसान बना देता है।

### पूर्ण उदाहरण: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace अकेला आमतौर पर escape के लिए पर्याप्त नहीं होता। व्यावहारिक escalation तब होती है जब host-revealing cgroup paths को writable cgroup v1 interfaces के साथ जोड़ा जाता है:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
यदि वे फ़ाइलें पहुँच योग्य और writable हैं, तो तुरंत [cgroups.md](../cgroups.md) से full `release_agent` exploitation flow में pivot करें। इसका प्रभाव container के अंदर से host code execution होता है।

यदि writable cgroup interfaces मौजूद नहीं हैं, तो प्रभाव आम तौर पर reconnaissance तक सीमित रहता है।

## जाँच

इन commands का उद्देश्य यह देखना है कि क्या प्रक्रिया के पास एक private cgroup namespace view है या वह host hierarchy के बारे में ज़रूरी से ज़्यादा जानकारी प्राप्त कर रही है।
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
- यदि namespace identifier उस host process से मेल खाता है जिसकी आपको परवाह है, तो cgroup namespace साझा हो सकता है।
- `/proc/self/cgroup` में host-revealing paths तब भी उपयोगी reconnaissance होते हैं जब वे सीधे exploit करने योग्य न हों।
- यदि cgroup mounts भी writable हैं, तो visibility का प्रश्न और भी अधिक महत्वपूर्ण हो जाता है।

cgroup namespace को प्राथमिक escape-prevention mechanism के बजाय एक visibility-hardening layer के रूप में माना जाना चाहिए। अनावश्यक रूप से host cgroup structure को उजागर करने से attacker के लिए reconnaissance का मूल्य बढ़ जाता है।
{{#include ../../../../../banners/hacktricks-training.md}}
