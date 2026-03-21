# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

The cgroup namespace cgroups को प्रतिस्थापित नहीं करता और स्वयं संसाधन सीमाएँ लागू नहीं करता। इसके बजाय, यह प्रक्रिया के लिए **cgroup hierarchy कैसे दिखाई देता है** बदल देता है। दूसरे शब्दों में, यह दिखाई देने वाली cgroup path जानकारी को वर्चुअलाइज़ करता है ताकि workload को पूरा host hierarchy देखने के बजाय एक container-scoped view दिखे।

यह मुख्यतः एक visibility और information-reduction फीचर है। यह environment को self-contained दिखाने में मदद करता है और host के cgroup layout के बारे में कम बताता है। यह मामूली लग सकता है, लेकिन यह मायने रखता है क्योंकि host संरचना में अनावश्यक visibility reconnaissance में मदद कर सकती है और environment-dependent exploit chains को सरल बना सकती है।

## ऑपरेशन

प्राइवेट cgroup namespace के बिना, एक प्रक्रिया host-relative cgroup paths देख सकती है जो मशीन की hierarchy का अधिक हिस्सा उजागर करते हैं जितना उपयोगी होता है। प्राइवेट cgroup namespace के साथ, `/proc/self/cgroup` और संबंधित अवलोकन container के अपने view के लिए अधिक localized हो जाते हैं। यह आधुनिक runtime stacks में विशेष रूप से मददगार है जो चाहते हैं कि workload को एक साफ़, कम host-revealing environment दिखे।

## Lab

आप cgroup namespace का निरीक्षण कर सकते हैं:
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

## Security Impact

The cgroup namespace is best understood as a **visibility-hardening layer**. By itself it will not stop a breakout if the container has writable cgroup mounts, broad capabilities, or a dangerous cgroup v1 environment. However, if the host cgroup namespace is shared, the process learns more about how the system is organized and may find it easier to line up host-relative cgroup paths with other observations.

So while this namespace is not usually the star of container breakout writeups, it still contributes to the broader goal of minimizing host information leakage.

## Abuse

The immediate abuse value is mostly reconnaissance. If the host cgroup namespace is shared, compare the visible paths and look for host-revealing hierarchy details:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
यदि writable cgroup paths भी प्रकट हैं, तो उस दृश्यता को खतरनाक पुराने इंटरफेस की खोज के साथ जोड़ें:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Namespace स्वयं आम तौर पर तुरंत escape नहीं देता, लेकिन यह अक्सर cgroup-based abuse primitives का परीक्षण करने से पहले environment को मैप करना आसान बना देता है।

### पूर्ण उदाहरण: साझा cgroup Namespace + Writable cgroup v1

cgroup namespace अकेला आम तौर पर escape के लिए पर्याप्त नहीं होता। व्यावहारिक escalation तब होती है जब host-revealing cgroup paths को writable cgroup v1 interfaces के साथ जोड़ा जाता है:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
यदि वे फ़ाइलें पहुँच योग्य और लिखने योग्य हैं, तो तुरंत [cgroups.md](../cgroups.md) में दिए गए पूरे `release_agent` exploitation flow में pivot करें। इसका प्रभाव कंटेनर के अंदर से host code execution होता है।

यदि writable cgroup interfaces न हों, तो प्रभाव सामान्यतः reconnaissance तक सीमित रहता है।

## जांच

इन कमांड्स का उद्देश्य यह देखना है कि प्रक्रिया के पास निजी cgroup namespace view है या वह host hierarchy के बारे में वास्तव में आवश्यकता से अधिक जानकारी प्राप्त कर रही है।
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
- यदि namespace identifier उस host process से मेल खाता है जिसकी आपको परवाह है, तो cgroup namespace साझा हो सकता है।
- `/proc/self/cgroup` में host-revealing paths तब भी उपयोगी reconnaissance होते हैं जब वे सीधे exploitable न हों।
- यदि cgroup mounts भी writable हैं, तो visibility का प्रश्न और भी महत्वपूर्ण हो जाता है।

cgroup namespace को visibility-hardening layer के रूप में माना जाना चाहिए बजाय इसके कि इसे प्राथमिक escape-prevention mechanism माना जाए। अनावश्यक रूप से host cgroup structure को उजागर करने से attacker के लिए reconnaissance value बढ़ जाती है।
