# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

A UTS (UNIX Time-Sharing System) namespace is a Linux kernel feature that provides i**दो सिस्टम पहचानकर्ताओं का अलगाव**: the **hostname** and the **NIS** (Network Information Service) domain name. यह अलगाव हर UTS namespace को अपना **अपना स्वतंत्र hostname और NIS domain name** रखने की अनुमति देता है, जो विशेष रूप से containerization परिदृश्यों में उपयोगी है जहाँ प्रत्येक container को अपने hostname के साथ एक अलग सिस्टम के रूप में दिखना चाहिए।

### यह कैसे काम करता है:

1. जब एक नया UTS namespace बनाया जाता है, तो यह अपने parent namespace से **hostname और NIS domain name की कॉपी** के साथ शुरू होता है। इसका मतलब यह है कि, निर्माण के समय, नया namespace s**उसके parent के समान पहचानकर्ता साझा करता है**। हालांकि, namespace के भीतर hostname या NIS domain name में बाद में किए गए किसी भी परिवर्तन का प्रभाव अन्य namespaces पर नहीं पड़ेगा।
2. UTS namespace के भीतर प्रक्रियाएँ `sethostname()` और `setdomainname()` system calls का उपयोग करके क्रमशः **hostname और NIS domain name को बदल सकती हैं**। ये परिवर्तन namespace तक सीमित होते हैं और अन्य namespaces या host system को प्रभावित नहीं करते।
3. प्रक्रियाएँ `setns()` system call का उपयोग करके namespaces के बीच जा सकती हैं या `unshare()` या `clone()` system calls के साथ `CLONE_NEWUTS` flag का उपयोग कर नए namespaces बना सकती हैं। जब एक प्रक्रिया किसी नए namespace में जाती है या नया namespace बनाती है, तो वह उस namespace से संबंधित hostname और NIS domain name का उपयोग करना शुरू कर देगी।

## Lab:

### विभिन्न Namespaces बनाएं

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new माउंट नेमस्पेस has an **सटीक और पृथक दृश्य उस नेमस्पेस के लिए प्रोसेस जानकारी का**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

जब `unshare` को `-f` विकल्प के बिना चलाया जाता है, तो Linux के नए PID (Process ID) namespaces को संभालने के तरीके के कारण एक त्रुटि आती है। मुख्य विवरण और समाधान नीचे दिए गए हैं:

1. **Problem Explanation**:

- Linux kernel किसी process को `unshare` system call का उपयोग करके नए namespaces बनाने की अनुमति देता है। हालांकि, जो process नए PID namespace के निर्माण की शुरुआत करता है (जिसे "unshare" process कहा जाता है) वह नए namespace में प्रवेश नहीं करता; केवल उसके child processes ही करते हैं।
- `%unshare -p /bin/bash%` चलाने से `/bin/bash` उसी process में शुरू होता है जो `unshare` है। परिणामस्वरूप, `/bin/bash` और उसके child processes मूल PID namespace में होते हैं।
- नए namespace में `/bin/bash` का पहला child process PID 1 बन जाता है। जब यह process exit करता है, तो यदि अन्य कोई process नहीं है तो namespace की cleanup होती है, क्योंकि PID 1 का orphan processes को adopt करने का विशेष रोल होता है। तब Linux kernel उस namespace में PID allocation को disable कर देगा।

2. **Consequence**:

- नए namespace में PID 1 के exit होने से `PIDNS_HASH_ADDING` flag साफ़ हो जाता है। इसका परिणाम यह होता है कि `alloc_pid` function नया PID allocate करने में विफल रहता है जब कोई नया process बनाया जाता है, और यह "Cannot allocate memory" त्रुटि उत्पन्न करता है।

3. **Solution**:
- इस समस्या को `unshare` के साथ `-f` विकल्प का उपयोग करके हल किया जा सकता है। यह विकल्प नए PID namespace बनाने के बाद `unshare` को एक नया process fork करने के लिए मजबूर करता है।
- `%unshare -fp /bin/bash%` चलाने से यह सुनिश्चित होता है कि `unshare` कमांड स्वयं नए namespace में PID 1 बन जाता है। तब `/bin/bash` और उसके child processes सुरक्षित रूप से इस नए namespace के भीतर रहते हैं, जिससे PID 1 के समय से पहले exit होने से रोका जाता है और सामान्य PID allocation संभव होता है।

`unshare` को `-f` फ़्लैग के साथ चलाने को सुनिश्चित करके, नया PID namespace सही तरीके से बनाए रखा जाता है, जिससे `/bin/bash` और उसके sub-processes बिना memory allocation त्रुटि का सामना किए काम कर सकें।

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### जाँचें कि आपका process किस namespace में है
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### सभी UTS namespaces खोजें
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### UTS namespace के अंदर प्रवेश करें
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## होस्ट UTS शेयरिंग का दुरुपयोग

यदि एक कंटेनर `--uts=host` के साथ शुरू किया जाता है, तो यह एक अलग UTS namespace पाने के बजाय होस्ट UTS namespace में जुड़ जाता है। `--cap-add SYS_ADMIN` जैसी क्षमताओं के साथ, कंटेनर के अंदर का कोड होस्ट का hostname/NIS नाम `sethostname()`/`setdomainname()` के माध्यम से बदल सकता है:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
host name बदलने से logs/alerts में छेड़छाड़ हो सकती है, cluster discovery भ्रमित हो सकती है या TLS/SSH configs जो hostname को पिन करती हैं, टूट सकती हैं।

### host के साथ UTS साझा करने वाले containers का पता लगाएँ
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
