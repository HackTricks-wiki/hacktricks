# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

The IPC namespace isolates **System V IPC objects** and **POSIX message queues**. That includes shared memory segments, semaphores, and message queues that would otherwise be visible across unrelated processes on the होस्ट. In practical terms, this prevents a container from casually attaching to IPC objects belonging to other workloads or the होस्ट.

Compared with mount, PID, or user namespaces, the IPC namespace is often discussed less often, but that should not be confused with irrelevance. Shared memory and related IPC mechanisms can contain highly useful state. If the होस्ट IPC namespace is exposed, the workload may gain visibility into inter-process coordination objects or data that was never intended to cross the container boundary.

## संचालन

When the runtime creates a fresh IPC namespace, the process gets its own isolated set of IPC identifiers. This means commands such as `ipcs` show only the objects available in that namespace. If the container instead joins the होस्ट IPC namespace, those objects become part of a shared global view.

This matters especially in environments where applications or services use shared memory heavily. Even when the container cannot directly break out through IPC alone, the namespace may leak information or enable cross-process interference that materially helps a later attack.

## प्रयोगशाला

आप एक निजी IPC namespace बना सकते हैं:
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

Docker और Podman डिफ़ॉल्ट रूप से IPC को अलग करते हैं। Kubernetes सामान्यतः Pod को उसका अपना IPC namespace देता है, जो उसी Pod में मौजूद containers के बीच साझा होता है पर डिफ़ॉल्ट रूप से host के साथ साझा नहीं होता। Host IPC sharing संभव है, लेकिन इसे एक मामूली runtime विकल्प की बजाय अलगाव में एक महत्वपूर्ण कमी के रूप में माना जाना चाहिए।

## गलत कॉन्फ़िगरेशन

स्पष्ट गलती `--ipc=host` या `hostIPC: true` का उपयोग है। यह legacy software के साथ संगतता या सुविधा के कारण किया जा सकता है, लेकिन यह trust मॉडल को मौलिक रूप से बदल देता है। एक और बार-बार होने वाली समस्या यह है कि IPC को नजरअंदाज़ कर देना क्योंकि यह host PID या host networking जितना नाटकीय नहीं लगता। असलियत में, अगर workload browsers, databases, scientific workloads, या अन्य ऐसे software संभालता है जो shared memory का भारी उपयोग करते हैं, तो IPC surface बहुत प्रासंगिक हो सकती है।

## दुरुपयोग

जब host IPC साझा होता है, तो एक attacker shared memory objects का निरीक्षण कर सकता है या उनमें हस्तक्षेप कर सकता है, host या पड़ोसी workload के व्यवहार के बारे में नई जानकारी हासिल कर सकता है, या वहां से मिली जानकारी को process visibility और ptrace-style क्षमताओं के साथ जोड़ सकता है। IPC sharing अक्सर पूर्ण breakout मार्ग की बजाय एक सहायक कमजोरी होती है, लेकिन सहायक कमजोरियाँ मायने रखती हैं क्योंकि वे वास्तविक attack chains को छोटा और स्थिर बनाती हैं।

The first useful step is to enumerate what IPC objects are visible at all:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
अगर host IPC namespace साझा किया गया है, तो बड़े shared-memory segments या दिलचस्प object owners तुरंत application के व्यवहार को उजागर कर सकते हैं:
```bash
ipcs -m -p
ipcs -q -p
```
कुछ वातावरणों में, `/dev/shm` की सामग्री स्वयं उन filenames, artifacts, या tokens को leak कर देती है जिन्हें जाँचना चाहिए:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC साझा करना अक्सर अकेले में तुरंत host root नहीं देता, लेकिन यह डेटा और समन्वय चैनलों को उजागर कर सकता है जो बाद के process attacks को काफी आसान बना देते हैं।

### पूरा उदाहरण: `/dev/shm` गुप्त पुनर्प्राप्ति

सबसे वास्तविकपूर्ण पूरा दुरुपयोग मामिला सीधे escape के बजाय डेटा चोरी है। अगर host IPC या कोई व्यापक shared-memory लेआउट एक्सपोज़ हो, तो संवेदनशील अवशेष कभी-कभी सीधे पुनर्प्राप्त किए जा सकते हैं:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
प्रभाव:

- shared memory में छोड़ी गई secrets या session material का extraction
- host पर वर्तमान में सक्रिय applications के बारे में जानकारी
- बाद के PID-namespace या ptrace-based attacks के लिए बेहतर लक्ष्य निर्धारण

इसलिए IPC sharing को standalone host-escape primitive की तुलना में एक **attack amplifier** के रूप में समझना बेहतर है।

## जांच

ये commands यह पता लगाने के लिए हैं कि workload के पास एक private IPC view है या नहीं, क्या meaningful shared-memory या message objects दिखाई दे रहे हैं, और क्या `/dev/shm` खुद उपयोगी artifacts उजागर करता है।
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
- यदि `ipcs -a` अनपेक्षित उपयोगकर्ताओं या सेवाओं के स्वामित्व वाले ऑब्जेक्ट प्रकट करता है, तो namespace उतना अलग-थलग नहीं हो सकता जितना अपेक्षित था।
- बड़े या असामान्य shared memory segments अक्सर आगे की जाँच के योग्य होते हैं।
- एक व्यापक `/dev/shm` mount अपने आप में बग नहीं है, लेकिन कुछ environments में यह leaks filenames, artifacts, and transient secrets।

IPC को आमतौर पर बड़े namespace types जितना ध्यान नहीं मिलता, लेकिन जिन environments में इसका भारी उपयोग होता है, वहां इसे host के साथ साझा करना बहुत हद तक एक सुरक्षा निर्णय होता है।
