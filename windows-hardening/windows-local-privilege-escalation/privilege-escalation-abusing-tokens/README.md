# Abusando de Tokens

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Tokens

Si **no sabes qué son los Tokens de Acceso de Windows**, lee esta página antes de continuar:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Tal vez puedas escalar privilegios abusando de los tokens que ya tienes**

### SeImpersonatePrivilege

Este es un privilegio que posee cualquier proceso que permite la suplantación (pero no la creación) de cualquier token, siempre que se pueda obtener un identificador para él. Un token privilegiado puede ser adquirido de un servicio de Windows (DCOM) induciéndolo a realizar autenticación NTLM contra un exploit, lo que posteriormente permite la ejecución de un proceso con privilegios de SISTEMA. Esta vulnerabilidad puede ser explotada utilizando varias herramientas, como [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (que requiere que winrm esté deshabilitado), [SweetPotato](https://github.com/CCob/SweetPotato) y [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Es muy similar a **SeImpersonatePrivilege**, utilizará el **mismo método** para obtener un token privilegiado.\
Luego, este privilegio permite **asignar un token primario** a un proceso nuevo/suspendido. Con el token de suplantación privilegiado, puedes derivar un token primario (DuplicateTokenEx).\
Con el token, puedes crear un **nuevo proceso** con 'CreateProcessAsUser' o crear un proceso suspendido y **establecer el token** (en general, no puedes modificar el token primario de un proceso en ejecución).

### SeTcbPrivilege

Si has habilitado este token, puedes usar **KERB\_S4U\_LOGON** para obtener un **token de suplantación** para cualquier otro usuario sin conocer las credenciales, **agregar un grupo arbitrario** (administradores) al token, establecer el **nivel de integridad** del token en "**medio**" y asignar este token al **hilo actual** (SetThreadToken).

### SeBackupPrivilege

El sistema se ve obligado a **conceder todo el acceso de lectura** a cualquier archivo (limitado a operaciones de lectura) por este privilegio. Se utiliza para **leer los hashes de contraseñas de las cuentas de Administrador local** del registro, después de lo cual, se pueden utilizar herramientas como "**psexec**" o "**wmicexec**" con el hash (técnica Pass-the-Hash). Sin embargo, esta técnica falla bajo dos condiciones: cuando la cuenta de Administrador local está deshabilitada o cuando existe una política que elimina los derechos administrativos de los Administradores locales que se conectan de forma remota.\
Puedes **abusar de este privilegio** con:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* siguiendo a **IppSec** en [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* O como se explica en la sección de **escalada de privilegios con Operadores de Respaldo** de:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Este privilegio proporciona permiso para **acceso de escritura** a cualquier archivo del sistema, independientemente de la Lista de Control de Acceso (ACL) del archivo. Abre numerosas posibilidades de escalada, incluida la capacidad de **modificar servicios**, realizar DLL Hijacking y establecer **depuradores** a través de Opciones de Ejecución de Archivos de Imagen, entre varias técnicas.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege es un permiso poderoso, especialmente útil cuando un usuario posee la capacidad de suplantar tokens, pero también en ausencia de SeImpersonatePrivilege. Esta capacidad depende de la capacidad de suplantar un token que represente al mismo usuario y cuyo nivel de integridad no exceda el del proceso actual.

**Puntos Clave:**
- **Suplantación sin SeImpersonatePrivilege:** Es posible aprovechar SeCreateTokenPrivilege para EoP suplantando tokens bajo condiciones específicas.
- **Condiciones para la Suplantación de Tokens:** La suplantación exitosa requiere que el token objetivo pertenezca al mismo usuario y tenga un nivel de integridad que sea menor o igual al nivel de integridad del proceso que intenta la suplantación.
- **Creación y Modificación de Tokens de Suplantación:** Los usuarios pueden crear un token de suplantación y mejorarlo agregando el SID (Identificador de Seguridad) de un grupo privilegiado.

### SeLoadDriverPrivilege

Este privilegio permite **cargar y descargar controladores de dispositivos** con la creación de una entrada de registro con valores específicos para `ImagePath` y `Type`. Dado que el acceso de escritura directa a `HKLM` (HKEY_LOCAL_MACHINE) está restringido, se debe utilizar `HKCU` (HKEY_CURRENT_USER) en su lugar. Sin embargo, para que `HKCU` sea reconocible por el kernel para la configuración del controlador, se debe seguir un camino específico.

Este camino es `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, donde `<RID>` es el Identificador Relativo del usuario actual. Dentro de `HKCU`, se debe crear todo este camino y se deben establecer dos valores:
- `ImagePath`, que es la ruta al binario a ejecutar
- `Type`, con un valor de `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Pasos a Seguir:**
1. Acceder a `HKCU` en lugar de `HKLM` debido al acceso de escritura restringido.
2. Crear el camino `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dentro de `HKCU`, donde `<RID>` representa el Identificador Relativo del usuario actual.
3. Establecer `ImagePath` como la ruta de ejecución del binario.
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

Esto es similar a **SeRestorePrivilege**. Su función principal permite a un proceso **asumir la propiedad de un objeto**, evitando el requisito de acceso discrecional explícito mediante la provisión de derechos de acceso WRITE_OWNER. El proceso implica asegurar primero la propiedad de la clave de registro prevista para fines de escritura, y luego alterar el DACL para habilitar operaciones de escritura.
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

Este privilegio permite **depurar otros procesos**, incluyendo leer y escribir en la memoria. Se pueden emplear diversas estrategias de inyección de memoria capaces de evadir la mayoría de los antivirus y soluciones de prevención de intrusiones en el host con este privilegio.

#### Volcar memoria

Podrías usar [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) de la [Suite SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **capturar la memoria de un proceso**. Específicamente, esto puede aplicarse al proceso **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, que es responsable de almacenar las credenciales de usuario una vez que un usuario ha iniciado sesión correctamente en un sistema.

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
Los **tokens que aparecen como Deshabilitados** se pueden habilitar, de hecho, puedes abusar de los tokens _Habilitados_ y _Deshabilitados_.

### Habilitar todos los tokens

Si tienes tokens deshabilitados, puedes usar el script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para habilitar todos los tokens:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
O el **script** incrustado en este [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabla

Cheat sheet completo de privilegios de token en [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), el resumen a continuación solo enumerará formas directas de explotar el privilegio para obtener una sesión de administrador o leer archivos sensibles.

| Privilegio                | Impacto     | Herramienta              | Ruta de ejecución                                                                                                                                                                                                                                                                                                                                  | Observaciones                                                                                                                                                                                                                                                                                                                  |
| -------------------------  | ----------- | ------------------------  | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Herramienta de terceros   | _"Permitiría a un usuario suplantar tokens y escalar privilegios a nt system usando herramientas como potato.exe, rottenpotato.exe y juicypotato.exe"_                                                                                                                                                                                             | Gracias a [Aurélien Chalot](https://twitter.com/Defte\_) por la actualización. Intentaré reformularlo pronto de una manera más parecida a una receta.                                                                                                                                                                           |
| **`SeBackup`**             | **Amenaza** | _**Comandos integrados**_ | Leer archivos sensibles con `robocopy /b`                                                                                                                                                                                                                                                                                                        | <p>- Puede ser más interesante si se puede leer %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (y robocopy) no son útiles cuando se trata de archivos abiertos.<br><br>- Robocopy requiere tanto SeBackup como SeRestore para funcionar con el parámetro /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Herramienta de terceros   | Crear un token arbitrario incluyendo derechos de administrador local con `NtCreateToken`.                                                                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**           | Duplicar el token de `lsass.exe`.                                                                                                                                                                                                                                                                                                                | Script disponible en [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Herramienta de terceros   | <p>1. Cargar un controlador de kernel con errores como <code>szkg64.sys</code><br>2. Explotar la vulnerabilidad del controlador<br><br>Alternativamente, el privilegio puede ser utilizado para descargar controladores relacionados con la seguridad con el comando integrado <code>ftlMC</code>. es decir: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. La vulnerabilidad de <code>szkg64</code> está listada como <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. El código de explotación de <code>szkg64</code> fue creado por <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**           | <p>1. Iniciar PowerShell/ISE con el privilegio SeRestore presente.<br>2. Habilitar el privilegio con <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renombrar utilman.exe a utilman.old<br>4. Renombrar cmd.exe a utilman.exe<br>5. Bloquear la consola y presionar Win+U</p> | <p>El ataque puede ser detectado por algunos software de antivirus.</p><p>El método alternativo se basa en reemplazar los binarios de servicio almacenados en "Archivos de programa" utilizando el mismo privilegio</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Comandos integrados**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renombrar cmd.exe a utilman.exe<br>4. Bloquear la consola y presionar Win+U</p>                                                                                                                                       | <p>El ataque puede ser detectado por algunos software de antivirus.</p><p>El método alternativo se basa en reemplazar los binarios de servicio almacenados en "Archivos de programa" utilizando el mismo privilegio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Herramienta de terceros   | <p>Manipular tokens para incluir derechos de administrador local. Puede requerir SeImpersonate.</p><p>Por verificar.</p>                                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                                |

## Referencia

* Echa un vistazo a esta tabla que define los tokens de Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Consulta [**este documento**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) sobre escalada de privilegios con tokens.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
