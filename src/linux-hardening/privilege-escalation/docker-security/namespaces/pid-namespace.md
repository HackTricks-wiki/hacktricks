# PID Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

The PID (Process IDentifier) namespace Linux **kernel** में एक सुविधा है जो प्रक्रिया अलगाव प्रदान करती है। यह प्रक्रियाओं के एक समूह को उनके अपने अद्वितीय PIDs रखने में सक्षम बनाती है, जो अन्य namespaces के PIDs से अलग होते हैं। यह containerization में विशेष रूप से उपयोगी है, जहाँ process isolation सुरक्षा और resource management के लिए आवश्यक है।

जब एक नया PID namespace बनाया जाता है, तो उस namespace में पहली प्रक्रिया को PID 1 सौंपा जाता है। यह प्रक्रिया नए namespace की "init" process बन जाती है और namespace के भीतर अन्य प्रक्रियाओं का प्रबंधन करने के लिए जिम्मेदार होती है। namespace के भीतर बनाई गई हर अगली प्रक्रिया को उस namespace में एक अद्वितीय PID मिलेगा, और ये PIDs अन्य namespaces के PIDs से स्वतंत्र होंगे।

PID namespace के भीतर की किसी प्रक्रिया के दृष्टिकोण से, वह केवल उसी namespace की अन्य प्रक्रियाओं को देख सकती है। वह अन्य namespaces की प्रक्रियाओं से अवगत नहीं होती, और पारंपरिक प्रक्रिया प्रबंधन उपकरणों (उदा., `kill`, `wait`, आदि) का उपयोग करके उनसे इंटरैक्ट नहीं कर सकती। इससे एक स्तर का अलगाव मिलता है जो प्रक्रियाओं को एक-दूसरे में हस्तक्षेप करने से रोकने में मदद करता है।

### यह कैसे काम करता है:

1. जब एक नई प्रक्रिया बनाई जाती है (उदा., `clone()` system call का उपयोग करके), तो प्रक्रिया को एक नए या मौजूदा PID namespace में असाइन किया जा सकता है। **यदि एक नया namespace बनाया जाता है, तो प्रक्रिया उस namespace की "init" process बन जाती है**।
2. The **kernel** नए namespace के PIDs और parent namespace के संबंधित PIDs के बीच एक **मैपिंग** बनाए रखता है (यानि जिस namespace से नया namespace बनाया गया था)। यह मैपिंग आवश्यक होने पर **kernel** को PIDs का अनुवाद करने की अनुमति देती है, जैसे अलग-अलग namespaces की प्रक्रियाओं के बीच सिग्नल भेजते समय।
3. **PID namespace के भीतर की प्रक्रियाएँ केवल उसी namespace की अन्य प्रक्रियाओं को ही देख और उनके साथ इंटरैक्ट कर सकती हैं**। वे अन्य namespaces में मौजूद प्रक्रियाओं से अवगत नहीं होतीं, और उनके PIDs उनके namespace के भीतर अद्वितीय होते हैं।
4. जब एक **PID namespace** नष्ट हो जाता है (उदा., जब उस namespace की "init" process समाप्त हो जाती है), तो **उस namespace के भीतर की सभी प्रक्रियाएँ समाप्त कर दी जाती हैं**। यह सुनिश्चित करता है कि namespace से जुड़ी सभी resources ठीक से साफ़ कर दी जाएँ।

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

जब `unshare` को `-f` विकल्प के बिना चलाया जाता है, तो Linux द्वारा नए PID (Process ID) namespace को संभालने के तरीके के कारण एक त्रुटि आती है। नीचे मुख्य विवरण और समाधान दिए गए हैं:

1. **Problem Explanation**:

- Linux kernel एक प्रक्रिया को `unshare` system call के माध्यम से नए namespace बनाने की अनुमति देता है। हालाँकि, जो प्रक्रिया नए PID namespace के निर्माण की शुरुआत करती है (जिसे "unshare" process कहा जाता है) वह नए namespace में प्रवेश नहीं करती; केवल उसकी child प्रक्रियाएँ ही प्रवेश करती हैं।
- `%unshare -p /bin/bash%` चलाने पर `/bin/bash` उसी प्रक्रिया में शुरू होता है जो `unshare` है। परिणामस्वरूप, `/bin/bash` और उसकी child प्रक्रियाएँ मूल PID namespace में रहती हैं।
- नए namespace में `/bin/bash` की पहली child प्रक्रिया PID 1 बन जाती है। जब यह प्रक्रिया exit करती है, और वहाँ और कोई प्रक्रिया नहीं होती, तो यह namespace की cleanup को ट्रिगर कर देता है, क्योंकि PID 1 के पास orphan प्रक्रियाओं को अपनाने की विशेष भूमिका होती है। इसके बाद Linux kernel उस namespace में PID allocation को अक्षम कर देता है।

2. **Consequence**:

- नए namespace में PID 1 के exit होने से `PIDNS_HASH_ADDING` flag साफ़ हो जाता है। इसका परिणाम यह होता है कि नया process बनाते समय `alloc_pid` फ़ंक्शन नया PID allocate करने में असफल होता है और "Cannot allocate memory" त्रुटि उत्पन्न होती है।

3. **Solution**:
- इस समस्या को `unshare` के साथ `-f` विकल्प का उपयोग करके हल किया जा सकता है। यह विकल्प नए PID namespace बनाने के बाद `unshare` को एक नया process fork करने पर मजबूर करता है।
- `%unshare -fp /bin/bash%` चलाने से `unshare` कमांड स्वयं नए namespace में PID 1 बन जाता है। तब `/bin/bash` और उसकी child प्रक्रियाएँ सुरक्षित रूप से इस नए namespace के अंदर रहती हैं, जिससे PID 1 के जल्द exit होने से बचाव होता है और सामान्य PID allocation संभव रहता है।

यदि आप सुनिश्चित करते हैं कि `unshare` `-f` flag के साथ चले, तो नया PID namespace सही तरीके से बना रहता है और `/bin/bash` तथा उसके subprocesses बिना memory allocation त्रुटि के काम कर सकते हैं।

</details>

By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **सटीक और पृथक दृष्टि उस namespace-विशिष्ट प्रक्रिया जानकारी की**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### जांचें कि आपका process किस namespace में है
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### सभी PID namespaces खोजें
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
ध्यान दें कि प्रारम्भिक (डिफ़ॉल्ट) PID namespace से root सभी प्रक्रियाएँ देख सकता है, यहां तक कि वे जो नए PID namespaces में हैं, इसलिए हम सभी PID namespaces देख सकते हैं।

### PID namespace के अंदर प्रवेश करें
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
जब आप default namespace से किसी PID namespace के अंदर जाते हैं, तब भी आप सभी प्रोसेस देख पाएंगे। और उस PID ns का प्रोसेस उस PID ns में नए bash को देख पाएगा।

इसके अलावा, आप केवल तभी **किसी अन्य process PID namespace में प्रवेश कर सकते हैं यदि आप root हैं**। और आप **नहीं** **प्रवेश** कर सकते दूसरे namespace में **बिना किसी descriptor के** जो उस की ओर इशारा करे (जैसे `/proc/self/ns/pid`)

## हाल के Exploitation नोट्स

### CVE-2025-31133: `maskedPaths` का दुरुपयोग कर host PIDs तक पहुँचना

runc ≤1.2.7 ने उन attackers को अनुमति दी जिनके पास container images या `runc exec` workloads का नियंत्रण था कि वे container-side `/dev/null` को runtime द्वारा संवेदनशील procfs एंट्रियाँ masked करने से ठीक पहले बदल दें। जब यह race सफल हो जाता है, `/dev/null` को किसी भी host path की ओर इशारा करने वाला symlink बना दिया जा सकता है (उदाहरण के लिए `/proc/sys/kernel/core_pattern`), इसलिए नया container PID namespace अचानक host-global procfs knobs के लिए read/write पहुँच विरासत में प्राप्त कर लेता है, भले ही उसने कभी अपना namespace छोड़ा ही न हो। एक बार `core_pattern` या `/proc/sysrq-trigger` writable हो जाएँ, तो coredump जनरेट करना या SysRq ट्रिगर करना host PID namespace में code execution या denial of service दे सकता है।

व्यावहारिक कार्यप्रवाह:

1. उस OCI bundle को बनाएं जिसकी rootfs `/dev/null` को उस host path की लिंक से बदल देती है जिसे आप चाहते हैं (`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`)।
2. fix लागू होने से पहले container को स्टार्ट करें ताकि runc लिंक के ऊपर host procfs target को bind-mount कर दे।
3. container namespace के अंदर, अब-अभिव्यक्त procfs file में लिखें (उदाहरण के लिए, `core_pattern` को किसी reverse shell helper की ओर निर्देशित करें) और किसी भी process को क्रैश कर दें ताकि host kernel आपके helper को PID 1 context में execute करने के लिए मजबूर हो जाए।

आप जल्दी से audit कर सकते हैं कि कोई bundle स्टार्ट करने से पहले सही फाइलें mask कर रहा है या नहीं:
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
यदि runtime में वह masking entry मौजूद नहीं है जिसकी आप उम्मीद करते हैं (या यह छोड़ देता है क्योंकि `/dev/null` गायब हो गया), तो कंटेनर को संभावित host PID visibility वाला समझें।

### `insject` के साथ Namespace इंजेक्शन

NCC Group का `insject` LD_PRELOAD payload के रूप में लोड होता है जो target program के एक देर वाले स्टेज (default `main`) में hook करता है और `execve()` के बाद `setns()` कॉल की एक श्रृंखला इश्यू करता है। इससे आप host (या किसी अन्य container) से victim के PID namespace में attach कर सकते हैं *बाद* कि उसका runtime initialized हो चुका हो, और यह `/proc/<pid>` view को संरक्षित करता है बिना container filesystem में binaries को कॉपी किए। चूँकि `insject` PID namespace में जुड़ने को fork होने तक टाल सकता है, आप एक thread को host namespace में रख सकते हैं (with CAP_SYS_PTRACE) जबकि दूसरा thread target PID namespace में execute करता है, जिससे शक्तिशाली debugging या offensive primitives बनते हैं।

उदाहरण उपयोग:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
namespace injection के दुरुपयोग या रक्षा के समय प्रमुख बातें:

- Use `-S/--strict` to force `insject` to abort if threads already exist or namespace joins fail, otherwise you may leave partly-migrated threads straddling host and container PID spaces.
- ऐसे tools कभी attach न करें जो अभी भी writable host file descriptors होल्ड किए हुए हैं, जब तक कि आप mount namespace में भी join न कर लें—अन्यथा PID namespace के भीतर कोई भी process आपके helper को ptrace कर सकता है और उन descriptors को reuse करके host resources के साथ छेड़छाड़ कर सकता है।

## संदर्भ

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
