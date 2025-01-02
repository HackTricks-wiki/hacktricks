# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}


## यह कैसे काम करता है

**Smbexec** एक उपकरण है जो Windows सिस्टम पर दूरस्थ कमांड निष्पादन के लिए उपयोग किया जाता है, **Psexec** के समान, लेकिन यह लक्षित सिस्टम पर कोई दुर्भावनापूर्ण फ़ाइलें नहीं रखता है।

### **SMBExec** के बारे में मुख्य बिंदु

- यह लक्षित मशीन पर एक अस्थायी सेवा (उदाहरण के लिए, "BTOBTO") बनाकर cmd.exe (%COMSPEC%) के माध्यम से कमांड निष्पादित करता है, बिना किसी बाइनरी को गिराए।
- इसके छिपे हुए दृष्टिकोण के बावजूद, यह प्रत्येक निष्पादित कमांड के लिए इवेंट लॉग उत्पन्न करता है, जो एक गैर-इंटरैक्टिव "शेल" का एक रूप प्रदान करता है।
- **Smbexec** का उपयोग करके कनेक्ट करने के लिए कमांड इस प्रकार दिखता है:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### बाइनरी के बिना कमांड निष्पादित करना

- **Smbexec** सेवा binPaths के माध्यम से सीधे कमांड निष्पादन की अनुमति देता है, जिससे लक्ष्य पर भौतिक बाइनरी की आवश्यकता समाप्त हो जाती है।
- यह विधि Windows लक्ष्य पर एक बार के लिए कमांड निष्पादित करने के लिए उपयोगी है। उदाहरण के लिए, इसे Metasploit के `web_delivery` मॉड्यूल के साथ जोड़ने से PowerShell-लक्षित रिवर्स मीटरपेटर पेलोड निष्पादित किया जा सकता है।
- हमलावर की मशीन पर एक दूरस्थ सेवा बनाकर जिसमें binPath को cmd.exe के माध्यम से प्रदान किए गए कमांड को चलाने के लिए सेट किया गया है, पेलोड को सफलतापूर्वक निष्पादित करना संभव है, callback और पेलोड निष्पादन को Metasploit लिस्नर के साथ प्राप्त करना, भले ही सेवा प्रतिक्रिया त्रुटियाँ उत्पन्न हों।

### कमांड उदाहरण

सेवा बनाना और शुरू करना निम्नलिखित कमांड के साथ किया जा सकता है:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
अधिक जानकारी के लिए देखें [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## संदर्भ

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


{{#include ../../banners/hacktricks-training.md}}
