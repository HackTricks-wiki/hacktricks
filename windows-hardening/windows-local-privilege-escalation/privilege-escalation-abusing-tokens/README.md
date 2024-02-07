# Abuso de Tokens

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Tokens

Si **no sabes qué son los Tokens de Acceso de Windows**, lee esta página antes de continuar:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Quizás puedas elevar privilegios abusando de los tokens que ya tienes**

### SeImpersonatePrivilege (3.1.1)

Cualquier proceso que tenga este privilegio puede **suplantar** (pero no crear) cualquier **token** para el cual pueda obtener un handle. Puedes obtener un **token privilegiado** de un **servicio de Windows** (DCOM) haciéndolo realizar una **autenticación NTLM** contra el exploit, luego ejecutar un proceso como **SYSTEM**. Explota esto con [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM ](https://github.com/antonioCoco/RogueWinRM)(necesita winrm deshabilitado), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer):

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege (3.1.2)

Es muy similar a **SeImpersonatePrivilege**, utilizará el **mismo método** para obtener un token privilegiado.\
Luego, este privilegio permite **asignar un token primario** a un proceso nuevo/suspendido. Con el token de suplantación privilegiado, puedes derivar un token primario (DuplicateTokenEx).\
Con el token, puedes crear un **nuevo proceso** con 'CreateProcessAsUser' o crear un proceso suspendido y **establecer el token** (en general, no puedes modificar el token primario de un proceso en ejecución).

### SeTcbPrivilege (3.1.3)

Si has habilitado este token, puedes usar **KERB\_S4U\_LOGON** para obtener un **token de suplantación** para cualquier otro usuario sin conocer las credenciales, **agregar un grupo arbitrario** (administradores) al token, establecer el **nivel de integridad** del token en "**medio**", y asignar este token al **hilo actual** (SetThreadToken).

### SeBackupPrivilege (3.1.4)

Este privilegio hace que el sistema **conceda todo el acceso de lectura** a cualquier archivo (solo lectura).\
Úsalo para **leer los hashes de contraseñas de las cuentas de Administrador local** desde el registro y luego usar "**psexec**" o "**wmicexec**" con el hash (PTH).\
Este ataque no funcionará si el Administrador Local está deshabilitado, o si está configurado para que un Admin Local no sea administrador si está conectado de forma remota.\
Puedes **abusar de este privilegio** con:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* siguiendo a **IppSec** en [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* O como se explica en la sección de **escalada de privilegios con Operadores de Respaldo** de:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege (3.1.5)

Control de **escritura** en cualquier archivo del sistema, independientemente del ACL de los archivos.\
Puedes **modificar servicios**, DLL Hijacking, establecer un **depurador** (Image File Execution Options)... Muchas opciones para escalar.

### SeCreateTokenPrivilege (3.1.6)

Este token **puede ser utilizado** como método de EoP **solo** si el usuario **puede suplantar** tokens (incluso sin SeImpersonatePrivilege).\
En un escenario posible, un usuario puede suplantar el token si es para el mismo usuario y el nivel de integridad es menor o igual al nivel de integridad del proceso actual.\
En este caso, el usuario podría **crear un token de suplantación** y agregar a él un SID de grupo privilegiado.

### SeLoadDriverPrivilege (3.1.7)

**Cargar y descargar controladores de dispositivos.**\
Debes crear una entrada en el registro con valores para ImagePath y Type.\
Como no tienes acceso para escribir en HKLM, debes **usar HKCU**. Pero HKCU no significa nada para el kernel, la forma de guiar al kernel aquí y usar la ruta esperada para una configuración de controlador es usar la ruta: "\Registry\User\S-1-5-21-582075628-3447520101-2530640108-1003\System\CurrentControlSet\Services\DriverName" (el ID es el **RID** del usuario actual).\
Por lo tanto, debes **crear toda esa ruta dentro de HKCU y establecer el ImagePath** (ruta al binario que se va a ejecutar) **y Type** (SERVICE\_KERNEL\_DRIVER 0x00000001).\

{% content-ref url="abuse-seloaddriverprivilege.md" %}
[abuse-seloaddriverprivilege.md](abuse-seloaddriverprivilege.md)
{% endcontent-ref %}

### SeTakeOwnershipPrivilege (3.1.8)

Este privilegio es muy similar a **SeRestorePrivilege**.\
Permite a un proceso “**tomar posesión de un objeto** sin que se le conceda acceso discrecional” al otorgar el derecho de acceso WRITE\_OWNER.\
Primero, debes **tomar posesión de la clave del registro** en la que vas a escribir y **modificar el DACL** para que puedas escribir en ella.
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
### SeDebugPrivilege (3.1.9)

Permite al titular **depurar otro proceso**, lo que incluye leer y **escribir** en la **memoria de ese proceso**.\
Existen diversas estrategias de **inyección de memoria** que se pueden utilizar con este privilegio y que evaden la mayoría de las soluciones de AV/HIPS.

#### Volcar memoria

Un ejemplo de **abuso de este privilegio** es ejecutar [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) de [SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **volcar la memoria de un proceso**. Por ejemplo, el proceso **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local\_Security\_Authority\_Subsystem\_Service)**)**, que almacena las credenciales de usuario después de que un usuario inicia sesión en un sistema.

Luego puedes cargar este volcado en mimikatz para obtener contraseñas:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Si deseas obtener un shell de `NT SYSTEM`, podrías usar:

- ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
- ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Verificar privilegios
```
whoami /priv
```
Los **tokens que aparecen como Deshabilitados** pueden ser habilitados, de hecho puedes abusar de los tokens _Habilitados_ y _Deshabilitados_.

### Habilitar todos los tokens

Puedes usar el script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para habilitar todos los tokens:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
O el **script** incrustado en este [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabla

Cheat sheet completo de privilegios de token en [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), el resumen a continuación solo enumerará formas directas de explotar el privilegio para obtener una sesión de administrador o leer archivos sensibles.\\

| Privilegio                 | Impacto     | Herramienta              | Ruta de ejecución                                                                                                                                                                                                                                                                                                                                  | Observaciones                                                                                                                                                                                                                                                                                                                  |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Herramienta de terceros  | _"Permitiría a un usuario suplantar tokens y escalar privilegios a nt system usando herramientas como potato.exe, rottenpotato.exe y juicypotato.exe"_                                                                                                                                                                                             | Gracias a [Aurélien Chalot](https://twitter.com/Defte\_) por la actualización. Intentaré reformularlo pronto a algo más parecido a una receta.                                                                                                                                                                                  |
| **`SeBackup`**             | **Amenaza** | _**Comandos integrados**_ | Leer archivos sensibles con `robocopy /b`                                                                                                                                                                                                                                                                                                          | <p>- Puede ser más interesante si se puede leer %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (y robocopy) no es útil cuando se trata de archivos abiertos.<br><br>- Robocopy requiere tanto SeBackup como SeRestore para funcionar con el parámetro /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Herramienta de terceros  | Crear un token arbitrario incluyendo derechos de administrador local con `NtCreateToken`.                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicar el token de `lsass.exe`.                                                                                                                                                                                                                                                                                                                | Script disponible en [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Herramienta de terceros  | <p>1. Cargar un controlador de kernel con errores como <code>szkg64.sys</code><br>2. Explotar la vulnerabilidad del controlador<br><br>Alternativamente, el privilegio puede usarse para descargar controladores relacionados con la seguridad con el comando integrado <code>ftlMC</code>. es decir: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. La vulnerabilidad de <code>szkg64</code> está listada como <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. El código de explotación de <code>szkg64</code> fue creado por <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Iniciar PowerShell/ISE con el privilegio SeRestore presente.<br>2. Habilitar el privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renombrar utilman.exe a utilman.old<br>4. Renombrar cmd.exe a utilman.exe<br>5. Bloquear la consola y presionar Win+U</p> | <p>El ataque puede ser detectado por algunos software de antivirus.</p><p>El método alternativo se basa en reemplazar los binarios de servicio almacenados en "Archivos de programa" utilizando el mismo privilegio</p>                                                                                                                |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Comandos integrados**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renombrar cmd.exe a utilman.exe<br>4. Bloquear la consola y presionar Win+U</p>                                                                                                                                       | <p>El ataque puede ser detectado por algunos software de antivirus.</p><p>El método alternativo se basa en reemplazar los binarios de servicio almacenados en "Archivos de programa" utilizando el mismo privilegio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Herramienta de terceros  | <p>Manipular tokens para incluir derechos de administrador local. Puede requerir SeImpersonate.</p><p>Por verificar.</p>                                                                                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                                |

## Referencia

* Echa un vistazo a esta tabla que define los tokens de Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Consulta [**este documento**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) sobre escalada de privilegios con tokens.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [grupo de telegram](https://t.me/peass) o **sígueme** en **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
