# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Si **no sabes qué son Windows Access Tokens** lee esta página antes de continuar:


{{#ref}}
access-tokens.md
{{#endref}}

**Tal vez puedas escalar privilegios abusando de los tokens que ya tienes**

### SeImpersonatePrivilege

Este privilegio, que posee cualquier proceso, permite la impersonación (pero no la creación) de cualquier token, siempre que se pueda obtener un handle del mismo. Se puede adquirir un token privilegiado desde un servicio de Windows (DCOM) induciéndolo a realizar una autenticación NTLM contra un exploit, lo que permite posteriormente la ejecución de un proceso con privilegios SYSTEM. Esta vulnerabilidad puede explotarse con varias herramientas, como [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (que requiere que winrm esté deshabilitado), [SweetPotato](https://github.com/CCob/SweetPotato) y [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Es muy similar a **SeImpersonatePrivilege**; emplea el **mismo método** para obtener un token privilegiado.\
Luego, este privilegio permite **asignar un primary token** a un proceso nuevo o suspendido. Con el privileged impersonation token puedes derivar un primary token (DuplicateTokenEx).\
Con el token, puedes crear un **nuevo proceso** con 'CreateProcessAsUser' o crear un proceso suspendido y **establecer el token** (en general, no puedes modificar el primary token de un proceso en ejecución).

### SeTcbPrivilege

Si tienes habilitado este privilegio puedes usar **KERB_S4U_LOGON** para obtener un **impersonation token** de cualquier otro usuario sin conocer las credenciales, **añadir un grupo arbitrario** (admins) al token, establecer el **integrity level** del token a "**medium**", y asignar este token al **hilo actual** (SetThreadToken).

### SeBackupPrivilege

Este privilegio provoca que el sistema conceda control de acceso de solo lectura a cualquier archivo (limitado a operaciones de lectura). Se utiliza para leer los hashes de contraseña de las cuentas de Administrator local desde el registry, tras lo cual se pueden usar herramientas como "psexec" o "wmiexec" con el hash (técnica Pass-the-Hash). Sin embargo, esta técnica falla en dos condiciones: cuando la cuenta Administrator local está deshabilitada, o cuando existe una política que elimina los derechos administrativos a los Administrators locales que se conectan de forma remota.\
Puedes **abusar de este privilegio** con:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- siguiendo a **IppSec** en [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- O como se explica en la sección **escalating privileges with Backup Operators** de:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Este privilegio otorga permiso de **escritura** sobre cualquier archivo del sistema, independientemente de la Access Control List (ACL) del archivo. Abre numerosas posibilidades para la escalada, incluyendo la capacidad de **modificar servicios**, realizar **DLL Hijacking**, y establecer **debuggers** vía Image File Execution Options, entre otras técnicas.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege es un permiso potente, especialmente útil cuando un usuario posee la capacidad de impersonate tokens, pero también en ausencia de SeImpersonatePrivilege. Esta capacidad depende de la habilidad para impersonar un token que represente al mismo usuario y cuyo integrity level no supere al del proceso actual.

**Puntos clave:**

- **Impersonación sin SeImpersonatePrivilege:** Es posible aprovechar SeCreateTokenPrivilege para EoP suplantando tokens bajo condiciones específicas.
- **Condiciones para la suplantación de tokens:** La suplantación exitosa requiere que el token objetivo pertenezca al mismo usuario y tenga un integrity level menor o igual que el integrity level del proceso que intenta suplantar.
- **Creación y modificación de impersonation tokens:** Los usuarios pueden crear un impersonation token y ampliarlo añadiendo el SID (Security Identifier) de un grupo privilegiado.

### SeLoadDriverPrivilege

Este privilegio permite **cargar y descargar device drivers** mediante la creación de una entrada en el registry con valores específicos para `ImagePath` y `Type`. Dado que el acceso de escritura directo a `HKLM` (HKEY_LOCAL_MACHINE) está restringido, debe utilizarse `HKCU` (HKEY_CURRENT_USER). Sin embargo, para que el kernel reconozca `HKCU` para la configuración del driver, debe seguirse una ruta específica.

Esta ruta es `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, donde `<RID>` es el Relative Identifier del usuario actual. Dentro de `HKCU`, se debe crear toda esta ruta y establecer dos valores:

- `ImagePath`, que es la ruta al binario que se ejecutará
- `Type`, con un valor de `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Pasos a seguir:**

1. Acceder a `HKCU` en lugar de `HKLM` debido a la restricción de escritura.
2. Crear la ruta `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dentro de `HKCU`, donde `<RID>` representa el Relative Identifier del usuario actual.
3. Establecer `ImagePath` con la ruta de ejecución del binario.
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

Esto es similar a **SeRestorePrivilege**. Su función principal permite que un proceso **asuma la propiedad de un objeto**, eludiendo el requisito de acceso discrecional explícito mediante la concesión de los derechos de acceso WRITE_OWNER. El proceso implica primero obtener la propiedad de la clave de registro objetivo con fines de escritura y, a continuación, modificar la DACL para permitir operaciones de escritura.
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

Este privilegio permite **depurar otros procesos**, incluyendo leer y escribir en la memoria. Se pueden emplear diversas estrategias de inyección de memoria, capaces de evadir la mayoría de antivirus y soluciones de prevención de intrusiones en el host, con este privilegio.

#### Volcar memoria

Puedes usar [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) de la [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **capturar la memoria de un proceso**. Específicamente, esto puede aplicarse al proceso **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, que es responsable de almacenar las credenciales de usuario una vez que un usuario ha iniciado sesión correctamente en un sistema.

Luego puedes cargar este volcado en mimikatz para obtener contraseñas:
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

Este derecho (Perform volume maintenance tasks) permite abrir raw volume device handles (por ejemplo, \\.\C:) para I/O directo de disco que elude las NTFS ACLs. Con él puedes copiar bytes de cualquier archivo en el volumen leyendo los bloques subyacentes, posibilitando la lectura arbitraria de archivos con material sensible (por ejemplo, claves privadas de la máquina en %ProgramData%\Microsoft\Crypto\, hives del registro, SAM/NTDS vía VSS). Es particularmente impactante en servidores CA donde exfiltrar la clave privada de la CA permite forjar un Golden Certificate para suplantar a cualquier entidad.

Ver técnicas detalladas y mitigaciones:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Comprobar privilegios
```
whoami /priv
```
Los **tokens que aparecen como Disabled** se pueden habilitar; de hecho puedes abusar tanto de los tokens _Enabled_ como de los _Disabled_.

### Habilitar todos los tokens

Si tienes tokens deshabilitados, puedes usar el script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para habilitar todos los tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
O el **script** incrustado en este [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabla

Hoja de referencia completa de privilegios de token en [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), el resumen a continuación solo enumerará formas directas de explotar el privilegio para obtener una sesión de admin o leer archivos sensibles.

| Privilegio                 | Impacto     | Herramienta             | Ruta de ejecución                                                                                                                                                                                                                                                                                                                                  | Observaciones                                                                                                                                                                                                                                                                                                                  |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`SeAssignPrimaryToken`** | _**Admin**_ | herramienta de terceros | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Gracias a [Aurélien Chalot](https://twitter.com/Defte_) por la actualización. Intentaré reformularlo a algo más tipo receta pronto.                                                                                                                                                                                               |
| **`SeBackup`**             | **Amenaza** | _**Built-in commands**_ | Leer archivos sensibles con `robocopy /b`                                                                                                                                                                                                                                                                                                         | <p>- Puede ser más interesante si puedes leer %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (y robocopy) no es útil cuando se trata de archivos abiertos.<br><br>- Robocopy requiere tanto SeBackup como SeRestore para funcionar con el parámetro /b.</p>                                                               |
| **`SeCreateToken`**        | _**Admin**_ | herramienta de terceros | Crear un token arbitrario incluyendo derechos de administrador local con `NtCreateToken`.                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                  |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicar el token de `lsass.exe`.                                                                                                                                                                                                                                                                                                                 | El script se encuentra en [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                       |
| **`SeLoadDriver`**         | _**Admin**_ | herramienta de terceros | <p>1. Cargar un kernel driver con errores como <code>szkg64.sys</code><br>2. Explotar la vulnerabilidad del driver<br><br>Alternativamente, el privilegio puede usarse para descargar drivers relacionados con la seguridad con el comando builtin <code>ftlMC</code>. i.e.: <code>fltMC sysmondrv</code></p>                                         | <p>1. La vulnerabilidad de <code>szkg64</code> está listada como <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. El código de exploit de <code>szkg64</code> fue creado por <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Iniciar PowerShell/ISE con el privilegio SeRestore presente.<br>2. Habilitar el privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Renombrar utilman.exe a utilman.old<br>4. Renombrar cmd.exe a utilman.exe<br>5. Bloquear la consola y presionar Win+U</p> | <p>El ataque puede ser detectado por algún software AV.</p><p>El método alternativo se basa en reemplazar binarios de servicios almacenados en "Program Files" usando el mismo privilegio</p>                                                                                         |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renombrar cmd.exe a utilman.exe<br>4. Bloquear la consola y presionar Win+U</p>                                                                                                                                 | <p>El ataque puede ser detectado por algún software AV.</p><p>El método alternativo se basa en reemplazar binarios de servicios almacenados en "Program Files" usando el mismo privilegio.</p>                                                                                                                              |
| **`SeTcb`**                | _**Admin**_ | herramienta de terceros | <p>Manipular tokens para incluir derechos de administrador local. Puede requerir SeImpersonate.</p><p>Por verificar.</p>                                                                                                                                                                                                                            |                                                                                                                                                                                                                                                                                                                                  |

## Referencia

- Echa un vistazo a esta tabla que define Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Consulta [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) sobre privesc con tokens.
- Microsoft – Realizar tareas de mantenimiento de volúmenes (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
