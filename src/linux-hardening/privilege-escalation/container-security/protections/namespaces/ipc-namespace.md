# IPC नामस्थान

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

IPC नामस्थान **System V IPC objects** और **POSIX message queues** को अलग करता है। इसमें shared memory segments, semaphores, और message queues शामिल हैं, जो अन्यथा host पर असंबंधित प्रक्रियाओं के बीच दिखाई देते। व्यवहारिक रूप से, यह एक container को अन्य workloads या host से संबंधित IPC ऑब्जेक्ट्स से सहजता से जुड़ने से रोकता है।

mount, PID, या user namespaces की तुलना में, IPC namespace अक्सर कम चर्चा में रहता है, पर इसका मतलब यह नहीं कि यह महत्वहीन है। Shared memory और संबंधित IPC mechanisms में अत्यंत उपयोगी state हो सकती है। अगर host IPC namespace एक्सपोज़ हो जाता है, तो workload ऐसे inter-process coordination objects या data में दृश्यता प्राप्त कर सकता है जिन्हें कभी container सीमा पार करने के लिए इरादा नहीं किया गया था।

## ऑपरेशन

जब runtime एक नया IPC namespace बनाता है, तो प्रक्रिया को अपने अलग IPC पहचानियों का सेट मिलता है। इसका मतलब है कि `ipcs` जैसे कमांड केवल उस namespace में उपलब्ध ऑब्जेक्ट्स ही दिखाते हैं। अगर container इसके बजाय host IPC namespace में शामिल हो जाता है, तो वे ऑब्जेक्ट्स एक साझा ग्लोबल दृश्य का हिस्सा बन जाते हैं।

यह विशेष रूप से उन वातावरणों में महत्वपूर्ण है जहाँ applications या services shared memory का भारी उपयोग करती हैं। भले ही container अकेले IPC के जरिए सीधे बाहर न निकल सके, namespace जानकारी leak कर सकता है या cross-process interference को सक्षम कर सकता है जो बाद के किसी attack में महत्वपूर्ण रूप से मदद कर सकता है।

## लैब

आप निम्नलिखित से एक private IPC namespace बना सकते हैं:
```bash
sudo unshare --ipc --fork bash
ipcs
```
और रनटाइम व्यवहार की तुलना करें:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## रनटाइम उपयोग

Docker और Podman डिफ़ॉल्ट रूप से IPC को अलग करते हैं। Kubernetes आम तौर पर Pod को उसका अपना IPC namespace देता है, जो उसी Pod के containers के बीच साझा होता है, लेकिन डिफ़ॉल्ट रूप से host के साथ साझा नहीं होता। Host IPC साझा करना संभव है, लेकिन इसे एक मामूली रनटाइम विकल्प के बजाय आइसोलेशन में एक महत्वपूर्ण कमी के रूप में माना जाना चाहिए।

## गलत कॉन्फ़िगरेशन

स्पष्ट गलती `--ipc=host` या `hostIPC: true` है। यह पुराने सॉफ़्टवेयर के साथ संगतता या सुविधा के लिए किया जा सकता है, लेकिन यह विश्वास मॉडल में काफी बदलाव कर देता है। एक और बार-बार होने वाली समस्या यह है कि IPC को अनदेखा कर दिया जाता है क्योंकि यह host PID या host networking जितना नाटकीय नहीं लगता। वास्तविकता में, अगर वर्कलोड ब्राउज़रों, डेटाबेस, वैज्ञानिक वर्कलोड्स, या अन्य ऐसे सॉफ़्टवेयर को हैंडल करता है जो shared memory का भारी उपयोग करते हैं, तो IPC सतह बहुत मायने रख सकती है।

## दुरुपयोग

जब host IPC साझा किया जाता है, तो एक हमलावर shared memory objects का निरीक्षण कर सकता है या उन पर हस्तक्षेप कर सकता है, host या पड़ोसी वर्कलोड के व्यवहार के बारे में नई जानकारी प्राप्त कर सकता है, या वहां से मिली जानकारी को process visibility और ptrace-style क्षमताओं के साथ जोड़ सकता है। IPC साझा करना अक्सर पूर्ण ब्रेकआउट पथ की बजाय एक सहायक कमजोरी होता है, लेकिन सहायक कमजोरियाँ मायने रखती हैं क्योंकि वे वास्तविक attack chains को छोटा और स्थिर करती हैं।

पहला उपयोगी कदम यह है कि यह सूचीबद्ध किया जाए कि कौन से IPC objects दिखाई देते हैं:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
यदि host IPC namespace साझा किया गया हो, तो बड़े shared-memory segments या दिलचस्प object owners तुरंत application behavior का खुलासा कर सकते हैं:
```bash
ipcs -m -p
ipcs -q -p
```
कुछ पर्यावरणों में, `/dev/shm` की सामग्री स्वयं filenames, artifacts, या tokens leak कर देती है जिन्हें जांचने लायक होता है:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC शेयरिंग आमतौर पर अपने आप तुरंत host root नहीं देती, लेकिन यह ऐसे डेटा और समन्वय चैनलों को उजागर कर सकती है जो बाद के प्रोसेस हमलों को काफी आसान बना देते हैं।

### पूर्ण उदाहरण: `/dev/shm` गुप्त पुनर्प्राप्ति

सबसे वास्तविकपूर्ण पूरा दुरुपयोग मामला सीधे escape के बजाय डेटा चोरी है। यदि host IPC या एक व्यापक shared-memory लेआउट उजागर हो, तो संवेदनशील आर्टिफैक्ट्स कभी-कभी सीधे पुनर्प्राप्त किए जा सकते हैं:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
प्रभाव:

- shared memory में छोड़ी गई गुप्त जानकारी या session सामग्री का निष्कर्षण
- host पर वर्तमान में सक्रिय applications के बारे में जानकारी
- बाद में होने वाले PID-namespace या ptrace-based attacks के लिए बेहतर targeting

IPC sharing is therefore better understood as an **हमला-बढ़ाने वाला** than as a standalone host-escape primitive.

## जाँच

ये commands यह पता लगाने के लिए हैं कि workload का private IPC view है या नहीं, क्या अर्थपूर्ण shared-memory या message objects दिखाई देते हैं, और क्या `/dev/shm` स्वयं उपयोगी artifacts उजागर करता है।
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
- यदि `ipcs -a` अप्रत्याशित उपयोगकर्ताओं या सेवाओं के स्वामित्व वाले ऑब्जेक्ट दिखाता है, तो namespace अपेक्षा के अनुसार अलग-थलग नहीं हो सकता।
- बड़े या असामान्य shared memory segments अक्सर आगे जांच के योग्य होते हैं।
- एक व्यापक `/dev/shm` mount स्वचालित रूप से बग नहीं होता, लेकिन कुछ environments में यह filenames, artifacts, और transient secrets को leak कर सकता है।

IPC को अक्सर बड़े namespace types जितना ध्यान नहीं मिलता, लेकिन उन environments में जो इसे भारी रूप से उपयोग करते हैं, host के साथ इसे साझा करना काफी हद तक एक सुरक्षा निर्णय है।
{{#include ../../../../../banners/hacktricks-training.md}}
