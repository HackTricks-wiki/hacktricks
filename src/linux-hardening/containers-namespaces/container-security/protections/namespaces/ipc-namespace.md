# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

IPC namespace **System V IPC objects** और **POSIX message queues** को isolate करता है। इसमें shared memory segments, semaphores और message queues शामिल हैं, जो अन्यथा host पर असंबंधित processes के बीच visible होते। व्यावहारिक रूप से, यह container को host या अन्य workloads से संबंधित IPC objects से अनौपचारिक रूप से जुड़ने से रोकता है।

mount, PID या user namespaces की तुलना में IPC namespace की चर्चा कम होती है, लेकिन इसे अप्रासंगिक नहीं समझना चाहिए। Shared memory और संबंधित IPC mechanisms में अत्यंत उपयोगी state हो सकती है। यदि host IPC namespace exposed है, तो workload को inter-process coordination objects या ऐसे data की visibility मिल सकती है, जिसे container boundary के बाहर जाने के लिए कभी intended नहीं किया गया था।

## संचालन

जब runtime एक नया IPC namespace बनाता है, तो process को IPC identifiers का अपना isolated set मिलता है। इसका अर्थ है कि `ipcs` जैसे commands केवल उस namespace में उपलब्ध objects दिखाते हैं। यदि container इसके बजाय host IPC namespace से जुड़ता है, तो वे objects एक shared global view का हिस्सा बन जाते हैं।

यह विशेष रूप से उन environments में महत्वपूर्ण है जहाँ applications या services shared memory का extensively उपयोग करती हैं। भले ही container केवल IPC के माध्यम से सीधे break out न कर सके, namespace information leak कर सकता है या cross-process interference सक्षम कर सकता है, जो बाद के attack में महत्वपूर्ण रूप से सहायता कर सकता है।

## Lab

आप निम्न command से एक private IPC namespace बना सकते हैं:
```bash
sudo unshare --ipc --fork bash
ipcs
```
और runtime behavior की तुलना करें:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Runtime Usage

Docker और Podman डिफ़ॉल्ट रूप से IPC को isolate करते हैं। Kubernetes आमतौर पर Pod को अपना IPC namespace देता है, जो उसी Pod के containers के बीच shared होता है, लेकिन डिफ़ॉल्ट रूप से host के साथ shared नहीं होता। Host IPC sharing संभव है, लेकिन इसे isolation में मामूली runtime option के बजाय एक महत्वपूर्ण कमी माना जाना चाहिए।

## Misconfigurations

स्पष्ट गलती `--ipc=host` या `hostIPC: true` है। ऐसा legacy software के साथ compatibility या सुविधा के लिए किया जा सकता है, लेकिन इससे trust model में काफी बदलाव आता है। एक और बार-बार होने वाली समस्या IPC को नज़रअंदाज़ करना है, क्योंकि यह host PID या host networking जितना गंभीर नहीं लगता। वास्तविकता में, यदि workload browsers, databases, scientific workloads या shared memory का अधिक उपयोग करने वाले अन्य software को संभालता है, तो IPC surface बहुत relevant हो सकता है।

## Abuse

जब host IPC shared होता है, तो attacker shared memory objects को inspect या interfere कर सकता है, host या neighboring workload के व्यवहार के बारे में नई जानकारी प्राप्त कर सकता है, या वहाँ से मिली जानकारी को process visibility और ptrace-style capabilities के साथ combine कर सकता है। IPC sharing अक्सर full breakout path के बजाय एक supporting weakness होती है, लेकिन supporting weaknesses महत्वपूर्ण होती हैं क्योंकि वे वास्तविक attack chains को छोटा और अधिक stable बनाती हैं।

पहला उपयोगी कदम यह enumerate करना है कि कौन-से IPC objects बिल्कुल visible हैं:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
यदि host IPC namespace shared है, तो बड़े shared-memory segments या दिलचस्प object owners तुरंत application behavior प्रकट कर सकते हैं:
```bash
ipcs -m -p
ipcs -q -p
```
कुछ environments में, `/dev/shm` की contents स्वयं filenames, artifacts या tokens leak कर सकती हैं, जिन्हें check करना उपयोगी है:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC sharing से अपने-आप तुरंत host root मिलना दुर्लभ है, लेकिन यह data और coordination channels को expose कर सकता है, जिससे बाद के process attacks काफी आसान हो जाते हैं।

### पूर्ण उदाहरण: `/dev/shm` Secret Recovery

सबसे वास्तविक पूर्ण abuse case direct escape के बजाय data theft है। यदि host IPC या broad shared-memory layout expose हो, तो sensitive artifacts कभी-कभी सीधे recover किए जा सकते हैं:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
प्रभाव:

- shared memory में छोड़े गए secrets या session material का extraction
- host पर वर्तमान में active applications की जानकारी
- बाद के PID-namespace या ptrace-based attacks के लिए बेहतर targeting

इसलिए IPC sharing को standalone host-escape primitive के बजाय **attack amplifier** के रूप में समझना अधिक उचित है।

## Checks

इन commands का उद्देश्य यह पता लगाना है कि workload का private IPC view है या नहीं, meaningful shared-memory या message objects दिखाई दे रहे हैं या नहीं, और क्या `/dev/shm` स्वयं उपयोगी artifacts expose करता है।
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
यहाँ क्या महत्वपूर्ण है:

- यदि `ipcs -a` से अप्रत्याशित users या services के स्वामित्व वाले objects दिखाई देते हैं, तो namespace उतना isolated नहीं हो सकता जितना अपेक्षित था।
- बड़े या असामान्य shared memory segments की आगे जाँच करना अक्सर उपयोगी होता है।
- व्यापक `/dev/shm` mount अपने-आप में bug नहीं है, लेकिन कुछ environments में यह filenames, artifacts और transient secrets को leak करता है।

IPC को बड़े namespace types जितना ध्यान शायद ही कभी मिलता है, लेकिन जो environments इसका भारी उपयोग करते हैं, उनमें इसे host के साथ share करना स्पष्ट रूप से एक security decision है।
{{#include ../../../../../banners/hacktricks-training.md}}
