# Abusing Tokens

{{#include ../../../banners/hacktricks-training.md}}

## Tokens

Si **no sabes qué son los Tokens de Acceso de Windows**, lee esta página antes de continuar:

{{#ref}}
../access-tokens.md
{{#endref}}

**Quizás podrías escalar privilegios abusando de los tokens que ya tienes**

### SeImpersonatePrivilege

Este es un privilegio que posee cualquier proceso que permite la suplantación (pero no la creación) de cualquier token, siempre que se pueda obtener un identificador para él. Se puede adquirir un token privilegiado de un servicio de Windows (DCOM) induciéndolo a realizar autenticación NTLM contra un exploit, lo que permite posteriormente la ejecución de un proceso con privilegios de SYSTEM. Esta vulnerabilidad se puede explotar utilizando varias herramientas, como [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (que requiere que winrm esté deshabilitado), [SweetPotato](https://github.com/CCob/SweetPotato), [EfsPotato](https://github.com/zcgonvh/EfsPotato), [DCOMPotato](https://github.com/zcgonvh/DCOMPotato) y [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{{#ref}}
../roguepotato-and-printspoofer.md
{{#endref}}

{{#ref}}
../juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Es muy similar a **SeImpersonatePrivilege**, utilizará el **mismo método** para obtener un token privilegiado.\
Luego, este privilegio permite **asignar un token primario** a un proceso nuevo/suspendido. Con el token de suplantación privilegiado puedes derivar un token primario (DuplicateTokenEx).\
Con el token, puedes crear un **nuevo proceso** con 'CreateProcessAsUser' o crear un proceso suspendido y **establecer el token** (en general, no puedes modificar el token primario de un proceso en ejecución).

### SeTcbPrivilege

Si has habilitado este token, puedes usar **KERB_S4U_LOGON** para obtener un **token de suplantación** para cualquier otro usuario sin conocer las credenciales, **agregar un grupo arbitrario** (administradores) al token, establecer el **nivel de integridad** del token en "**medio**", y asignar este token al **hilo actual** (SetThreadToken).

### SeBackupPrivilege

El sistema se ve obligado a **otorgar todo el acceso de lectura** a cualquier archivo (limitado a operaciones de lectura) por este privilegio. Se utiliza para **leer los hashes de contraseñas de cuentas de Administrador local** desde el registro, después de lo cual, herramientas como "**psexec**" o "**wmiexec**" pueden ser utilizadas con el hash (técnica Pass-the-Hash). Sin embargo, esta técnica falla bajo dos condiciones: cuando la cuenta de Administrador local está deshabilitada, o cuando hay una política que elimina los derechos administrativos de los Administradores locales que se conectan de forma remota.\
Puedes **abusar de este privilegio** con:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- siguiendo a **IppSec** en [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- O como se explica en la sección **escalando privilegios con Operadores de Respaldo** de:

{{#ref}}
../../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Este privilegio proporciona permiso para **acceso de escritura** a cualquier archivo del sistema, independientemente de la Lista de Control de Acceso (ACL) del archivo. Abre numerosas posibilidades para la escalación, incluyendo la capacidad de **modificar servicios**, realizar DLL Hijacking, y establecer **depuradores** a través de Opciones de Ejecución de Archivos de Imagen entre varias otras técnicas.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege es un permiso poderoso, especialmente útil cuando un usuario posee la capacidad de suplantar tokens, pero también en ausencia de SeImpersonatePrivilege. Esta capacidad depende de la habilidad de suplantar un token que represente al mismo usuario y cuyo nivel de integridad no exceda el del proceso actual.

**Puntos Clave:**

- **Suplantación sin SeImpersonatePrivilege:** Es posible aprovechar SeCreateTokenPrivilege para EoP al suplantar tokens bajo condiciones específicas.
- **Condiciones para la Suplantación de Tokens:** La suplantación exitosa requiere que el token objetivo pertenezca al mismo usuario y tenga un nivel de integridad que sea menor o igual al nivel de integridad del proceso que intenta la suplantación.
- **Creación y Modificación de Tokens de Suplantación:** Los usuarios pueden crear un token de suplantación y mejorarlo agregando un SID (Identificador de Seguridad) de un grupo privilegiado.

### SeLoadDriverPrivilege

Este privilegio permite **cargar y descargar controladores de dispositivos** con la creación de una entrada en el registro con valores específicos para `ImagePath` y `Type`. Dado que el acceso de escritura directo a `HKLM` (HKEY_LOCAL_MACHINE) está restringido, se debe utilizar `HKCU` (HKEY_CURRENT_USER) en su lugar. Sin embargo, para que `HKCU` sea reconocible por el núcleo para la configuración del controlador, se debe seguir una ruta específica.

Esta ruta es `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, donde `<RID>` es el Identificador Relativo del usuario actual. Dentro de `HKCU`, se debe crear toda esta ruta y establecer dos valores:

- `ImagePath`, que es la ruta al binario que se ejecutará
- `Type`, con un valor de `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Pasos a Seguir:**

1. Accede a `HKCU` en lugar de `HKLM` debido al acceso de escritura restringido.
2. Crea la ruta `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dentro de `HKCU`, donde `<RID>` representa el Identificador Relativo del usuario actual.
3. Establece el `ImagePath` a la ruta de ejecución del binario.
4. Asigna el `Type` como `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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

Esto es similar a **SeRestorePrivilege**. Su función principal permite que un proceso **asuma la propiedad de un objeto**, eludiendo el requisito de acceso discrecional explícito a través de la provisión de derechos de acceso WRITE_OWNER. El proceso implica primero asegurar la propiedad de la clave de registro destinada para fines de escritura, y luego alterar el DACL para habilitar las operaciones de escritura.
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

Este privilegio permite **depurar otros procesos**, incluyendo leer y escribir en la memoria. Se pueden emplear varias estrategias para la inyección de memoria, capaces de evadir la mayoría de las soluciones antivirus y de prevención de intrusiones en host, con este privilegio.

#### Volcar memoria

Puedes usar [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) de la [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **capturar la memoria de un proceso**. Específicamente, esto puede aplicarse al proceso **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, que es responsable de almacenar las credenciales de usuario una vez que un usuario ha iniciado sesión con éxito en un sistema.

Luego puedes cargar este volcado en mimikatz para obtener contraseñas:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Si quieres obtener un shell de `NT SYSTEM`, podrías usar:

- \***\*[**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)\*\***
- \***\*[**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)\*\***
- \***\*[**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)\*\***
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

El `SeManageVolumePrivilege` es un derecho de usuario de Windows que permite a los usuarios gestionar volúmenes de disco, incluyendo su creación y eliminación. Aunque está destinado a administradores, si se concede a usuarios no administradores, puede ser explotado para la escalada de privilegios.

Es posible aprovechar este privilegio para manipular volúmenes, lo que lleva a un acceso completo al volumen. El [SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit) se puede utilizar para dar acceso completo a todos los usuarios para C:\

Además, el proceso descrito en [este artículo de Medium](https://medium.com/@raphaeltzy13/exploiting-semanagevolumeprivilege-with-dll-hijacking-windows-privilege-escalation-1a4f28372d37) describe el uso de DLL hijacking junto con `SeManageVolumePrivilege` para escalar privilegios. Al colocar un DLL de carga útil `C:\Windows\System32\wbem\tzres.dll` y llamar a `systeminfo`, se ejecuta el dll.

## Check privileges
```
whoami /priv
```
Los **tokens que aparecen como Deshabilitados** pueden ser habilitados, en realidad puedes abusar de los tokens _Habilitados_ y _Deshabilitados_.

### Habilitar Todos los tokens

Si tienes tokens deshabilitados, puedes usar el script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para habilitar todos los tokens:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
O el **script** incrustado en este [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabla

Hoja de trucos de privilegios de token completa en [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), el resumen a continuación solo enumerará formas directas de explotar el privilegio para obtener una sesión de administrador o leer archivos sensibles.

| Privilegio                 | Impacto     | Herramienta              | Ruta de ejecución                                                                                                                                                                                                                                                                                                                                     | Observaciones                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | herramienta de terceros   | _"Permitiría a un usuario impersonar tokens y escalar privilegios al sistema nt utilizando herramientas como potato.exe, rottenpotato.exe y juicypotato.exe"_                                                                                                                                                                                                      | Gracias [Aurélien Chalot](https://twitter.com/Defte_) por la actualización. Intentaré reformularlo a algo más parecido a una receta pronto.                                                                                                                                                                                         |
| **`SeBackup`**             | **Amenaza** | _**Comandos integrados**_ | Leer archivos sensibles con `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Puede ser más interesante si puedes leer %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (y robocopy) no son útiles cuando se trata de archivos abiertos.<br><br>- Robocopy requiere tanto SeBackup como SeRestore para trabajar con el parámetro /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | herramienta de terceros   | Crear un token arbitrario que incluya derechos de administrador local con `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicar el token de `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Script disponible en [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | herramienta de terceros   | <p>1. Cargar un controlador de kernel con errores como <code>szkg64.sys</code><br>2. Explotar la vulnerabilidad del controlador<br><br>Alternativamente, el privilegio puede usarse para descargar controladores relacionados con la seguridad con el comando integrado <code>ftlMC</code>. es decir: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. La vulnerabilidad de <code>szkg64</code> está listada como <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. El <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">código de explotación</a> fue creado por <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Iniciar PowerShell/ISE con el privilegio SeRestore presente.<br>2. Habilitar el privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Renombrar utilman.exe a utilman.old<br>4. Renombrar cmd.exe a utilman.exe<br>5. Bloquear la consola y presionar Win+U</p> | <p>El ataque puede ser detectado por algunos software antivirus.</p><p>El método alternativo se basa en reemplazar los binarios de servicio almacenados en "Program Files" utilizando el mismo privilegio</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Comandos integrados**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renombrar cmd.exe a utilman.exe<br>4. Bloquear la consola y presionar Win+U</p>                                                                                                                                       | <p>El ataque puede ser detectado por algunos software antivirus.</p><p>El método alternativo se basa en reemplazar los binarios de servicio almacenados en "Program Files" utilizando el mismo privilegio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | herramienta de terceros   | <p>Manipular tokens para incluir derechos de administrador local. Puede requerir SeImpersonate.</p><p>Por verificar.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Referencia

- Echa un vistazo a esta tabla que define los tokens de Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Echa un vistazo a [**este documento**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) sobre la escalada de privilegios con tokens.

{{#include ../../../banners/hacktricks-training.md}}
