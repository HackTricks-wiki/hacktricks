# UTS नेमस्पेस

{{#include ../../../../banners/hacktricks-training.md}}

## बेसिक जानकारी

A UTS (UNIX Time-Sharing System) namespace Linux kernel की एक विशेषता है जो i**दो सिस्टम पहचानकर्ताओं का अलगाव** प्रदान करती है: the **hostname** and the **NIS** (Network Information Service) domain name. यह अलगाव प्रत्येक UTS नेमस्पेस को इसका **own independent hostname and NIS domain name** रखने की अनुमति देता है, जो खासकर containerization परिदृश्यों में उपयोगी है जहाँ प्रत्येक container को एक अलग सिस्टम की तरह दिखना चाहिए और उसका अपना hostname होना चाहिए।

### यह कैसे काम करता है:

1. जब एक नया UTS नेमस्पेस बनाया जाता है, तो यह अपने parent namespace से **hostname और NIS domain name की एक copy** के साथ शुरू होता है। इसका मतलब है कि, निर्माण के समय, नया नेमस्पेस s**अपने parent के समान पहचानकर्ताओं को साझा करता है**। हालांकि, नेमस्पेस के भीतर hostname या NIS domain name में बाद में किए गए किसी भी परिवर्तन का अन्य नेमस्पेस पर प्रभाव नहीं पड़ेगा।
2. UTS नेमस्पेस के अंदर प्रक्रियाएं `sethostname()` और `setdomainname()` system calls का उपयोग करके क्रमशः **hostname और NIS domain name बदल सकती हैं**। ये परिवर्तन नेमस्पेस तक ही सीमित रहते हैं और अन्य नेमस्पेस या host system को प्रभावित नहीं करते।
3. प्रक्रियाएं `setns()` system call का उपयोग करके नेमस्पेस के बीच स्थानांतरित हो सकती हैं या `unshare()` या `clone()` system calls के साथ `CLONE_NEWUTS` flag का उपयोग करके नए नेमस्पेस बना सकती हैं। जब कोई प्रक्रिया नए नेमस्पेस में चली जाती है या नया नेमस्पेस बनाती है, तो वह उस नेमस्पेस से जुड़ा hostname और NIS domain name उपयोग करने लगेगी।

## Lab:

### विभिन्न नेमस्पेस बनाएं

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **नए namespace के लिये प्रॉसेस जानकारी का सटीक और पृथक दृश्य**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

जब `unshare` को `-f` विकल्प के बिना चलाया जाता है, तो Linux द्वारा नए PID (Process ID) namespaces को हैंडल करने के तरीके के कारण एक त्रुटि आती है। प्रमुख विवरण और समाधान नीचे दिए गए हैं:

1. **समस्या का स्पष्टीकरण**:

- Linux kernel एक प्रक्रिया को `unshare` system call का उपयोग करके नए namespaces बनाने की अनुमति देता है। हालांकि, जो प्रक्रिया नए PID namespace का निर्माण शुरू करती है (जिसे "unshare" प्रक्रिया कहा गया है) वह नए namespace में प्रवेश नहीं करती; केवल उसकी child प्रक्रियाएँ ही वहाँ प्रवेश करती हैं।
- `%unshare -p /bin/bash%` चलाने पर `/bin/bash` `unshare` के उसी प्रोसेस में शुरू होता है। परिणामस्वरूप, `/bin/bash` और इसकी child प्रक्रियाएँ मूल PID namespace में रहती हैं।
- नए namespace में `/bin/bash` का पहला child प्रोसेस PID 1 बन जाता है। जब यह प्रोसेस exit कर जाता है, तो यदि कोई अन्य प्रोसेस नहीं हैं तो namespace की cleanup ट्रिगर हो जाती है, क्योंकि PID 1 ओर्फन प्रक्रियाओं को अपनाने की विशेष भूमिका निभाता है। उसके बाद Linux kernel उस namespace में PID allocation को डिसेबल कर देगा।

2. **परिणाम**:

- नए namespace में PID 1 के exit होने से `PIDNS_HASH_ADDING` flag की cleanup होती है। इससे नया प्रोसेस बनाते समय `alloc_pid` फ़ंक्शन नया PID allocate करने में विफल हो जाता है, और "Cannot allocate memory" त्रुटि उत्पन्न होती है।

3. **समाधान**:
- इस समस्या का समाधान `unshare` के साथ `-f` विकल्प का उपयोग करना है। यह विकल्प नए PID namespace बनाने के बाद `unshare` को एक नया fork प्रोसेस बनाने के लिए कहता है।
- `%unshare -fp /bin/bash%` चलाने से यह सुनिश्चित होता है कि `unshare` स्वयं नए namespace में PID 1 बन जाता है। तब `/bin/bash` और उसकी child प्रक्रियाएँ सुरक्षित रूप से इस नए namespace के भीतर रहती हैं, PID 1 के समयपूर्व exit को रोका जाता है और सामान्य PID allocation संभव होता है।

`unshare` को `-f` फ़्लैग के साथ चलाकर आप यह सुनिश्चित करते हैं कि नया PID namespace सही ढंग से बना रहे, जिससे `/bin/bash` और उसके sub-processes बिना मेमोरी अलोकेशन त्रुटि के काम कर सकें।

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
### सभी UTS नामस्थान खोजें
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

अगर एक container को `--uts=host` के साथ शुरू किया जाता है, तो यह एक अलग UTS namespace पाने के बजाय host UTS namespace में जुड़ जाता है। `--cap-add SYS_ADMIN` जैसे capabilities के साथ, container के अंदर का code host hostname/NIS name को `sethostname()`/`setdomainname()` के माध्यम से बदल सकता है:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Host name बदलने से logs/alerts में छेड़छाड़ हो सकती है, cluster discovery को भ्रमित कर सकता है या उन TLS/SSH configs को तोड़ सकता है जो hostname को पिन करते हैं।

### Host के साथ UTS साझा कर रहे containers का पता लगाएँ
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
