# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Overview

कई आर्काइव फ़ॉर्मेट (ZIP, RAR, TAR, 7-ZIP, आदि) प्रत्येक प्रविष्टि को अपना **आंतरिक पथ** ले जाने की अनुमति देते हैं। जब एक एक्सट्रैक्शन उपयोगिता उस पथ को अंधाधुंध मानती है, तो `..` या एक **पूर्ण पथ** (जैसे `C:\Windows\System32\`) वाला एक तैयार किया गया फ़ाइल नाम उपयोगकर्ता द्वारा चुने गए निर्देशिका के बाहर लिखा जाएगा। इस प्रकार की भेद्यता को *Zip-Slip* या **आर्काइव एक्सट्रैक्शन पथ ट्रैवर्सल** के रूप में जाना जाता है।

परिणामों में मनमाने फ़ाइलों को ओवरराइट करने से लेकर **रिमोट कोड निष्पादन (RCE)** को सीधे प्राप्त करने तक शामिल है, जैसे कि Windows *Startup* फ़ोल्डर में एक पेलोड डालना।

## Root Cause

1. हमलावर एक आर्काइव बनाता है जहाँ एक या एक से अधिक फ़ाइल हेडर में शामिल हैं:
* सापेक्ष ट्रैवर्सल अनुक्रम (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* पूर्ण पथ (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
2. पीड़ित एक कमजोर उपकरण के साथ आर्काइव को निकालता है जो एम्बेडेड पथ पर भरोसा करता है बजाय इसके कि उसे साफ़ करे या चुने गए निर्देशिका के नीचे निष्कर्षण को मजबूर करे।
3. फ़ाइल हमलावर-नियंत्रित स्थान में लिखी जाती है और अगली बार जब सिस्टम या उपयोगकर्ता उस पथ को ट्रिगर करता है, तो इसे निष्पादित/लोड किया जाता है।

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows के लिए WinRAR (जिसमें `rar` / `unrar` CLI, DLL और पोर्टेबल स्रोत शामिल हैं) ने निष्कर्षण के दौरान फ़ाइल नामों को मान्य करने में विफलता दिखाई। एक दुर्भावनापूर्ण RAR आर्काइव जिसमें एक प्रविष्टि शामिल है:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
**चुने गए आउटपुट निर्देशिका** के बाहर और उपयोगकर्ता के *Startup* फ़ोल्डर के अंदर समाप्त हो जाएगा। लॉगिन के बाद, Windows वहां मौजूद सभी चीज़ों को स्वचालित रूप से निष्पादित करता है, *स्थायी* RCE प्रदान करता है।

### PoC आर्काइव तैयार करना (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – फ़ाइल पथों को ठीक उसी तरह स्टोर करें जैसे दिए गए हैं (आगे के `./` को **नहीं** हटाएं)।

`evil.rar` को पीड़ित को भेजें और उन्हें इसे एक कमजोर WinRAR बिल्ड के साथ निकालने के लिए निर्देशित करें।

### Observed Exploitation in the Wild

ESET ने RomCom (Storm-0978/UNC2596) स्पीयर-फिशिंग अभियानों की रिपोर्ट की जो RAR आर्काइव को CVE-2025-8088 का दुरुपयोग करके अनुकूलित बैकडोर तैनात करने और रैनसमवेयर संचालन को सुविधाजनक बनाने के लिए संलग्न करती हैं।

## Detection Tips

* **Static inspection** – आर्काइव प्रविष्टियों की सूची बनाएं और किसी भी नाम को चिह्नित करें जिसमें `../`, `..\\`, *absolute paths* (`C:`) या गैर-मानक UTF-8/UTF-16 एन्कोडिंग शामिल हैं।
* **Sandbox extraction** – एक *safe* extractor (जैसे, Python का `patool`, 7-Zip ≥ नवीनतम, `bsdtar`) का उपयोग करके एक नष्ट करने योग्य निर्देशिका में डिकंप्रेस करें और सुनिश्चित करें कि परिणामस्वरूप पथ निर्देशिका के अंदर रहते हैं।
* **Endpoint monitoring** – WinRAR/7-Zip/etc. द्वारा एक आर्काइव खोले जाने के तुरंत बाद `Startup`/`Run` स्थानों पर लिखे गए नए निष्पादन योग्य पर अलर्ट करें।

## Mitigation & Hardening

1. **Extractor को अपडेट करें** – WinRAR 7.13 उचित पथ स्वच्छता लागू करता है। उपयोगकर्ताओं को इसे मैन्युअल रूप से डाउनलोड करना होगा क्योंकि WinRAR में ऑटो-अपडेट तंत्र की कमी है।
2. जब संभव हो, **“Ignore paths”** विकल्प (WinRAR: *Extract → "Do not extract paths"*) के साथ आर्काइव निकालें।
3. अविश्वसनीय आर्काइव को **एक सैंडबॉक्स** या VM के अंदर खोलें।
4. एप्लिकेशन व्हाइटलिस्टिंग लागू करें और उपयोगकर्ता लेखन पहुंच को ऑटो-रन निर्देशिकाओं तक सीमित करें।

## Additional Affected / Historical Cases

* 2018 – Snyk द्वारा बड़े *Zip-Slip* सलाहकार जो कई Java/Go/JS पुस्तकालयों को प्रभावित करता है।
* 2023 – 7-Zip CVE-2023-4011 के दौरान `-ao` मर्ज में समान ट्रैवर्सल।
* कोई भी कस्टम निष्कर्षण लॉजिक जो लिखने से पहले `PathCanonicalize` / `realpath` को कॉल करने में विफल रहता है।

## References

- [BleepingComputer – WinRAR zero-day exploited to plant malware on archive extraction](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [WinRAR 7.13 Changelog](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Zip Slip vulnerability write-up](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
