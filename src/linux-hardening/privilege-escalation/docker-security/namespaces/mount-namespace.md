# Mount Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

एक माउंट नेमस्पेस एक Linux कर्नेल फीचर है जो प्रक्रियाओं के एक समूह द्वारा देखे जाने वाले फ़ाइल सिस्टम माउंट पॉइंट्स का पृथक्करण प्रदान करता है। प्रत्येक माउंट नेमस्पेस के पास अपने स्वयं के फ़ाइल सिस्टम माउंट पॉइंट्स का सेट होता है, और **एक नेमस्पेस में माउंट पॉइंट्स में परिवर्तन अन्य नेमस्पेस को प्रभावित नहीं करते**। इसका मतलब है कि विभिन्न माउंट नेमस्पेस में चलने वाली प्रक्रियाएँ फ़ाइल सिस्टम पदानुक्रम के विभिन्न दृश्य रख सकती हैं।

माउंट नेमस्पेस विशेष रूप से कंटेनरीकरण में उपयोगी होते हैं, जहाँ प्रत्येक कंटेनर को अन्य कंटेनरों और होस्ट सिस्टम से पृथक अपने स्वयं के फ़ाइल सिस्टम और कॉन्फ़िगरेशन होना चाहिए।

### How it works:

1. जब एक नया माउंट नेमस्पेस बनाया जाता है, तो इसे **अपने पैरेंट नेमस्पेस से माउंट पॉइंट्स की एक कॉपी के साथ प्रारंभ किया जाता है**। इसका मतलब है कि, निर्माण के समय, नया नेमस्पेस अपने पैरेंट के समान फ़ाइल सिस्टम का दृश्य साझा करता है। हालाँकि, नेमस्पेस के भीतर माउंट पॉइंट्स में बाद के किसी भी परिवर्तन का प्रभाव पैरेंट या अन्य नेमस्पेस पर नहीं पड़ेगा।
2. जब एक प्रक्रिया अपने नेमस्पेस के भीतर एक माउंट पॉइंट को संशोधित करती है, जैसे कि फ़ाइल सिस्टम को माउंट या अनमाउंट करना, तो **परिवर्तन उस नेमस्पेस के लिए स्थानीय होता है** और अन्य नेमस्पेस को प्रभावित नहीं करता। यह प्रत्येक नेमस्पेस को अपने स्वयं के स्वतंत्र फ़ाइल सिस्टम पदानुक्रम रखने की अनुमति देता है।
3. प्रक्रियाएँ `setns()` सिस्टम कॉल का उपयोग करके नेमस्पेस के बीच स्थानांतरित हो सकती हैं, या `unshare()` या `clone()` सिस्टम कॉल का उपयोग करके नए नेमस्पेस बना सकती हैं जिसमें `CLONE_NEWNS` फ्लैग होता है। जब एक प्रक्रिया एक नए नेमस्पेस में जाती है या एक बनाती है, तो यह उस नेमस्पेस से जुड़े माउंट पॉइंट्स का उपयोग करना शुरू कर देगी।
4. **फ़ाइल डिस्क्रिप्टर्स और इनोड्स नेमस्पेस के बीच साझा किए जाते हैं**, जिसका अर्थ है कि यदि एक नेमस्पेस में एक प्रक्रिया के पास एक फ़ाइल को इंगित करने वाला एक खुला फ़ाइल डिस्क्रिप्टर है, तो वह **उस फ़ाइल डिस्क्रिप्टर को** दूसरे नेमस्पेस में एक प्रक्रिया को पास कर सकती है, और **दोनों प्रक्रियाएँ उसी फ़ाइल तक पहुँचेंगी**। हालाँकि, फ़ाइल का पथ दोनों नेमस्पेस में माउंट पॉइंट्स में भिन्नताओं के कारण समान नहीं हो सकता है।

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
एक नए `/proc` फ़ाइल प्रणाली के उदाहरण को माउंट करके, यदि आप पैरामीटर `--mount-proc` का उपयोग करते हैं, तो आप सुनिश्चित करते हैं कि नए माउंट नामस्थान में **उस नामस्थान के लिए विशिष्ट प्रक्रिया जानकारी का सटीक और अलग दृश्य** है।

<details>

<summary>त्रुटि: bash: fork: मेमोरी आवंटित नहीं कर सकता</summary>

जब `unshare` को `-f` विकल्प के बिना निष्पादित किया जाता है, तो लिनक्स द्वारा नए PID (प्रक्रिया आईडी) नामस्थान को संभालने के तरीके के कारण एक त्रुटि उत्पन्न होती है। मुख्य विवरण और समाधान नीचे दिए गए हैं:

1. **समस्या का विवरण**:

- लिनक्स कर्नेल एक प्रक्रिया को `unshare` सिस्टम कॉल का उपयोग करके नए नामस्थान बनाने की अनुमति देता है। हालाँकि, नई PID नामस्थान बनाने की प्रक्रिया (जिसे "unshare" प्रक्रिया कहा जाता है) नए नामस्थान में प्रवेश नहीं करती है; केवल इसकी बाल प्रक्रियाएँ करती हैं।
- `%unshare -p /bin/bash%` चलाने से `/bin/bash` उसी प्रक्रिया में शुरू होता है जैसे `unshare`। परिणामस्वरूप, `/bin/bash` और इसकी बाल प्रक्रियाएँ मूल PID नामस्थान में होती हैं।
- नए नामस्थान में `/bin/bash` की पहली बाल प्रक्रिया PID 1 बन जाती है। जब यह प्रक्रिया समाप्त होती है, तो यह नामस्थान की सफाई को ट्रिगर करती है यदि कोई अन्य प्रक्रियाएँ नहीं हैं, क्योंकि PID 1 का विशेष कार्य अनाथ प्रक्रियाओं को अपनाना है। लिनक्स कर्नेल तब उस नामस्थान में PID आवंटन को अक्षम कर देगा।

2. **परिणाम**:

- नए नामस्थान में PID 1 का समाप्त होना `PIDNS_HASH_ADDING` ध्वज की सफाई की ओर ले जाता है। इसका परिणाम यह होता है कि नए प्रक्रिया बनाने के समय `alloc_pid` फ़ंक्शन नए PID को आवंटित करने में विफल रहता है, जिससे "Cannot allocate memory" त्रुटि उत्पन्न होती है।

3. **समाधान**:
- इस समस्या को `unshare` के साथ `-f` विकल्प का उपयोग करके हल किया जा सकता है। यह विकल्प `unshare` को नए PID नामस्थान बनाने के बाद एक नई प्रक्रिया बनाने के लिए फोर्क करता है।
- `%unshare -fp /bin/bash%` निष्पादित करने से यह सुनिश्चित होता है कि `unshare` कमांड स्वयं नए नामस्थान में PID 1 बन जाता है। `/bin/bash` और इसकी बाल प्रक्रियाएँ फिर इस नए नामस्थान में सुरक्षित रूप से समाहित होती हैं, PID 1 के पूर्ववर्ती समाप्त होने को रोकती हैं और सामान्य PID आवंटन की अनुमति देती हैं।

यह सुनिश्चित करके कि `unshare` `-f` ध्वज के साथ चलता है, नए PID नामस्थान को सही ढंग से बनाए रखा जाता है, जिससे `/bin/bash` और इसकी उप-प्रक्रियाएँ मेमोरी आवंटन त्रुटि का सामना किए बिना कार्य कर सकें।

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;जांचें कि आपका प्रोसेस किस नेमस्पेस में है
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### सभी माउंट नामस्थान खोजें
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

```bash
findmnt
```
### एक माउंट नेमस्पेस के अंदर प्रवेश करें
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
आप केवल **दूसरे प्रक्रिया नामस्थान में प्रवेश कर सकते हैं यदि आप रूट हैं**। और आप **दूसरे नामस्थान में प्रवेश नहीं कर सकते** **बिना एक वर्णनकर्ता** जो इसे इंगित करता है (जैसे `/proc/self/ns/mnt`)।

क्योंकि नए माउंट केवल नामस्थान के भीतर ही सुलभ होते हैं, यह संभव है कि एक नामस्थान में संवेदनशील जानकारी हो जो केवल उसी से सुलभ हो।

### कुछ माउंट करें
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```

```
# findmnt # List existing mounts
TARGET                                SOURCE                                                                                                           FSTYPE     OPTIONS
/                                     /dev/mapper/web05--vg-root

# unshare --mount  # run a shell in a new mount namespace
# mount --bind /usr/bin/ /mnt/
# ls /mnt/cp
/mnt/cp
# exit  # exit the shell, and hence the mount namespace
# ls /mnt/cp
ls: cannot access '/mnt/cp': No such file or directory

## Notice there's different files in /tmp
# ls /tmp
revshell.elf

# ls /mnt/tmp
krb5cc_75401103_X5yEyy
systemd-private-3d87c249e8a84451994ad692609cd4b6-apache2.service-77w9dT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-resolved.service-RnMUhT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-timesyncd.service-FAnDql
vmware-root_662-2689143848

```
## संदर्भ

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux](https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux)

{{#include ../../../../banners/hacktricks-training.md}}
